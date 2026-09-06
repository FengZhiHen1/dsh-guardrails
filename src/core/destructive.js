// destructive — high-risk destructive command analysis for the PowerShell dialect.
//
// Boundary: pure static analysis over command fragments (nothing executed);
// depends on core/command.js (lexing/fragments) and core/path-check.js (path
// helpers for cd-chain simulation) only. The six sub-family functions mirror
// the `destructive` config leaves one-to-one (git/machine/eval/cli/bulk/target).
// Reference: docs/technical-details/命令文本分析.md; DSR-002/006.

import {
  CD_CMDS,
  DYNAMIC_PATTERN,
  applyCwdCommand,
  normalizeCommand,
  splitFragments,
  tokenizePwsh,
  unwrapFragment,
} from './command.js'
import { normCompare, resolvePath, segmentsOf } from './path-check.js'

const REMOVAL_CMDS = new Set(['removeitem', 'rm', 'ri', 'rmdir', 'del', 'erase', 'rd'])
const LIST_CMDS = new Set(['getchilditem', 'gci', 'ls', 'dir'])
const WINDOWS_FLAG_CMDS = new Set(['rd', 'del', 'erase'])
const DISK_TOOLS = new Set(['fdisk', 'parted', 'wipefs', 'format', 'diskpart'])
const DB_CLIS = new Set(['psql', 'mysql', 'mariadb', 'sqlite3', 'mongosh', 'mongo'])
// T1: machine-level commands
const MACHINE_CMDS = new Set([
  'restartcomputer', 'stopcomputer', 'cleardisk', 'initializedisk', 'formatvolume', 'removepartition',
])
// T1: remote/untrusted content execution (Invoke-Expression and friends)
const EVAL_CMDS = new Set(['iex', 'invokeexpression'])
const SHELL_PIPE_CMDS = new Set(['bash', 'sh', 'zsh', 'pwsh', 'powershell'])
const EVERYTHING_TARGETS = new Set([
  '.', './', '.\\', '*', './*', '.\\*', '$pwd', '${pwd}',
  '$pwd\\*', '$pwd/*', '${pwd}\\*', '${pwd}/*',
])
// Absolute drive roots: `C:\`, `C:/`, `C:\*` (drive root with wildcard), and
// `/` / `\` which PowerShell treats as the root of the current drive. Deleting
// any of them is machine-level destruction, independent of the workspace.
const DRIVE_ROOT_TARGET = /^[A-Za-z]:[\\/](?:\*)?$/
const CURRENT_ROOT_TARGET = /^[\\/](?:\*)?$/
// T1: whether a stop/kill targets the harness, terminal, or shell processes
const KILL_TARGET_PATTERN = /(?:^|\s)(?:node|dsh|pwsh|powershell|explorer|cmd)(?:\.exe)?(?=\s|$)/

const removalTargets = (words, windowsFlags) =>
  words.filter((w) => w !== '--' && !w.startsWith('-') && !(windowsFlags && /^\/[a-zA-Z]+$/.test(w)))
const optionLetters = (args) =>
  args
    .filter((a) => /^-[^-]/.test(a))
    .map((a) => a.slice(1))
    .join('')
const hasSequence = (lowerArgs, sequence) =>
  lowerArgs.some((_, i) => sequence.every((v, o) => lowerArgs[i + o] === v))

const DEFAULT_SUB = {
  git: true,
  machine: true,
  eval: true,
  cli: true,
  bulk: true,
  target: true,
}

/**
 * git sub-family: high-risk git subcommands (git runs identically in pwsh).
 * Covers `reset --hard`, `clean -f`, force-push, remote ref delete,
 * `branch -D`, `stash drop/clear`, and `checkout/restore .` (discards the
 * working tree).
 *
 * @returns `{ text }` or `null`.
 */
function assessGitCommand(args, lowerArgs) {
  const sub0 = lowerArgs[0]
  if (sub0 === 'reset' && lowerArgs.includes('--hard'))
    return { text: 'git reset --hard discards all uncommitted changes' }
  if (sub0 === 'clean' && (lowerArgs.includes('--force') || optionLetters(args.slice(1)).includes('f')))
    return { text: 'git clean -f permanently deletes untracked files' }
  if (sub0 === 'push') {
    const letters = optionLetters(args.slice(1))
    const forceFlags = new Set(['--force', '--force-with-lease', '--force-if-includes'])
    if (args.some((a) => forceFlags.has(a)) || letters.includes('f'))
      return { text: 'force-pushing overwrites remote git history' }
    if (
      lowerArgs.includes('--delete') ||
      letters.includes('d') ||
      args.some((a) => /^:[^:]/.test(a))
    )
      return { text: 'deleting a remote git ref cannot be undone locally' }
  }
  if (sub0 === 'branch') {
    const letters = optionLetters(args.slice(1))
    if (
      args.includes('-D') ||
      (lowerArgs.includes('--delete') && lowerArgs.includes('--force')) ||
      (letters.includes('d') && letters.includes('f'))
    )
      return { text: 'force-deleting a git branch can lose unmerged work' }
  }
  if (sub0 === 'stash' && (lowerArgs[1] === 'drop' || lowerArgs[1] === 'clear'))
    return { text: 'deleting git stash entries loses stashed work' }
  if ((sub0 === 'checkout' || sub0 === 'restore') && lowerArgs[lowerArgs.length - 1] === '.')
    return { text: 'this discards all working tree changes' }
  return null
}

/**
 * machine sub-family: machine/system-level commands — shutdown/restart, disk
 * operations, killing harness/terminal/shell processes, user creation or
 * elevation, and file emptying (Clear-Content / Set-Content `$null`).
 *
 * @returns `{ text }` or `null`.
 */
function assessMachineCommand(cmd, lowerArgs, joined) {
  if (cmd === 'shutdown' && /(?:^|\s)[-/][srp](?:\s|$)/.test(joined))
    return { text: 'shutting down or restarting the machine' }
  if (MACHINE_CMDS.has(cmd))
    return { text: 'machine/disk-level operation can destroy the system or its data' }
  if ((cmd === 'stopprocess' || cmd === 'taskkill') && KILL_TARGET_PATTERN.test(joined))
    return { text: 'killing the harness, terminal, or shell process' }
  if (cmd === 'net' && /\b(?:user|localgroup)\b/.test(joined) && lowerArgs.includes('/add'))
    return { text: 'creating a user account or elevating to the administrators group' }
  if (cmd === 'clearcontent')
    return { text: 'Clear-Content empties file contents' }
  if (cmd === 'setcontent' && /\$null\b/.test(joined))
    return { text: 'Set-Content to $null empties file contents' }
  return null
}

/**
 * eval sub-family (per-fragment half): Invoke-Expression and output piped
 * into a shell evaluator. The whole-text patterns (curl|bash, .NET data APIs)
 * run once after the fragment loop in {@link assessDestructive}.
 *
 * @returns `{ text }` or `null`.
 */
function assessEvalCommand(cmd, fragmentIndex, seps) {
  if (EVAL_CMDS.has(cmd))
    return { text: 'Invoke-Expression evaluates arbitrary code' }
  if (SHELL_PIPE_CMDS.has(cmd) && fragmentIndex > 0 && seps[fragmentIndex - 1] === '|')
    return { text: 'piping output into a shell evaluator executes remote or untrusted content' }
  return null
}

/**
 * bulk sub-family: `Get-ChildItem | ... | Remove-Item` piped bulk deletes.
 * Walks the whole pipe chain: a filter/formatting verb (Where-Object,
 * Select-Object, Sort-Object) or a `%` / ForEach-Object scriptblock in between
 * must not launder a bulk delete past an adjacency check, so any removal verb
 * anywhere in the chain (as a head or inside a scriptblock) counts.
 *
 * @returns `{ text }` or `null`.
 */
function assessBulkDelete(cmd, fragments, f, seps) {
  if (!LIST_CMDS.has(cmd) || seps[f] !== '|') return null
  for (let g = f + 1; g < fragments.length && seps[g - 1] === '|'; g += 1) {
    const next = unwrapFragment(fragments[g])
    if (next && REMOVAL_CMDS.has(next.cmd)) {
      return { text: 'Get-ChildItem piped to Remove-Item deletes matched files' }
    }
    if (fragments[g].some((w) => REMOVAL_CMDS.has(normalizeCommand(w)))) {
      return { text: 'Get-ChildItem piped to Remove-Item deletes matched files' }
    }
  }
  return null
}

/**
 * cli sub-family: data-destroying CLI tools — shred/find -delete/dd/disk
 * tools/truncate -s 0, docker system prune, terraform destroy, kubectl
 * delete, aws s3 rm --recursive, dropdb, redis flush, and destructive SQL
 * through database CLIs.
 *
 * @returns `{ text }` or `null`.
 */
function assessCliCommand(cmd, lowerArgs, joined) {
  if (cmd === 'shred')
    return { text: 'shred irreversibly overwrites and deletes files' }
  if (cmd === 'find' && lowerArgs.includes('-delete'))
    return { text: 'find -delete bulk-deletes matched files' }
  if (cmd === 'dd' && lowerArgs.some((a) => a.startsWith('of=')))
    return { text: 'dd overwrites a device or file raw' }
  if (cmd.startsWith('mkfs') || DISK_TOOLS.has(cmd))
    return { text: 'disk/filesystem tools can destroy entire volumes' }
  if (cmd === 'truncate' && /(?:^|\s)(?:-s\s*0|--size(?:=|\s+)0)(?:\s|$)/.test(joined))
    return { text: 'truncate -s 0 empties file contents' }
  if (cmd === 'docker' && hasSequence(lowerArgs, ['system', 'prune']))
    return { text: 'docker system prune deletes unused Docker data (images, containers, volumes)' }
  if (cmd === 'terraform' && lowerArgs.includes('destroy'))
    return { text: 'terraform destroy tears down managed infrastructure' }
  if (cmd === 'kubectl' && lowerArgs.includes('delete'))
    return { text: 'kubectl delete removes Kubernetes resources' }
  if (cmd === 'aws' && hasSequence(lowerArgs, ['s3', 'rm']) && lowerArgs.includes('--recursive'))
    return { text: 'aws s3 rm --recursive bulk-deletes S3 objects' }
  if (cmd === 'dropdb')
    return { text: 'dropdb drops a PostgreSQL database' }
  if (cmd === 'rediscli' && (lowerArgs.includes('flushall') || lowerArgs.includes('flushdb')))
    return { text: 'redis flush deletes database contents' }
  if (DB_CLIS.has(cmd) && /\b(?:dropdatabase|\.drop\s*\(|drop|truncate|delete\s+from)\b/.test(joined))
    return { text: 'destructive database operation through a CLI' }
  return null
}

/**
 * target sub-family: removal-command target analysis with cd-chain
 * simulation. Blocks deleting everything (`*`, `.`), a drive root, or the
 * workspace root (incl. via a cd chain); a deletion target under a
 * dynamically-computed cwd cannot be verified and is blocked conservatively.
 *
 * @param cwdState - simulated cwd `{ dir, known }` at this fragment.
 * @param rootBase - judgment base directory (resolved workspace root; DSR-007).
 * @returns `{ text }` or `null`.
 */
function assessRemovalTargets(cmd, args, cwdState, rootBase) {
  if (!REMOVAL_CMDS.has(cmd)) return null
  const windowsFlags = WINDOWS_FLAG_CMDS.has(cmd)
  for (const rawTarget of removalTargets(args, windowsFlags)) {
    const lowerTarget = rawTarget.toLowerCase()
    if (EVERYTHING_TARGETS.has(lowerTarget)) {
      if (!cwdState.known)
        return {
          text: 'the command changes to a dynamically-computed directory, so this deletion target cannot be verified; split it into separate commands or use absolute paths',
        }
      if (normCompare(cwdState.dir) === normCompare(rootBase))
        return {
          text: 'deleting the current working directory / workspace root destroys all local work, including .git metadata',
        }
      continue
    }
    if (DRIVE_ROOT_TARGET.test(rawTarget) || CURRENT_ROOT_TARGET.test(rawTarget)) {
      return {
        text: 'deleting the root of a drive destroys machine-level data (the workspace, system files, and every other project on that drive); use a precise path or delete specific files',
      }
    }
    if (DYNAMIC_PATTERN.test(rawTarget)) continue
    const base = cwdState.known ? cwdState.dir : rootBase
    if (normCompare(resolvePath(base, rawTarget)) === normCompare(rootBase)) {
      return {
        text: 'deleting the current working directory / workspace root (possibly via a cd-chained command) destroys all local work, including .git metadata; split the command or use absolute paths so the target can be verified',
      }
    }
    if (!cwdState.known && segmentsOf(rawTarget).includes('..')) {
      return {
        text: 'the command changes to a dynamically-computed directory, so this deletion target cannot be verified; split it into separate commands or use absolute paths',
      }
    }
  }
  return null
}

/**
 * High-risk destructive command analysis (PowerShell dialect, static).
 * Here-strings are blanked first; fragments run through the enabled
 * sub-families in a fixed order (git → machine → eval → bulk → cli → target),
 * then `$(...)` subexpressions recurse (subshell snapshot semantics), and the
 * eval whole-text patterns close the pass.
 *
 * @param rootBase - judgment base directory (resolved workspace root; DSR-007).
 * @param command - raw command text (already literal-reconstructed by the caller).
 * @param sub - per-sub-family leaves from the `destructive` config category.
 * @returns `{ text }` describing why the command is blocked, or `null`.
 */
export function assessDestructive(rootBase, command, sub = DEFAULT_SUB) {
  const stripped = command.replace(/@"[\s\S]*?"@|@'[\s\S]*?'@/g, ' ')
  const { tokens, nested } = tokenizePwsh(stripped)
  const { fragments, seps } = splitFragments(tokens)

  let cwdState = { dir: rootBase, known: true }
  for (let f = 0; f < fragments.length; f += 1) {
    const invocation = unwrapFragment(fragments[f])
    if (!invocation) continue
    const { cmd, args } = invocation
    const lowerArgs = args.map((a) => a.toLowerCase())
    const joined = lowerArgs.join(' ')

    if (cmd === 'popd' || CD_CMDS.has(cmd)) {
      cwdState = applyCwdCommand(cwdState, cmd, args)
      continue
    }

    const hit =
      (sub.git && cmd === 'git' && assessGitCommand(args, lowerArgs)) ||
      (sub.machine && assessMachineCommand(cmd, lowerArgs, joined)) ||
      (sub.eval && assessEvalCommand(cmd, f, seps)) ||
      (sub.bulk && assessBulkDelete(cmd, fragments, f, seps)) ||
      (sub.cli && assessCliCommand(cmd, lowerArgs, joined)) ||
      (sub.target && assessRemovalTargets(cmd, args, cwdState, rootBase))
    if (hit) return hit
  }

  // $(...) subexpressions: subshell snapshot semantics, recurse
  for (const embedded of nested) {
    const hit = assessDestructive(rootBase, embedded, sub)
    if (hit) return hit
  }

  // T1: remote download piped into an evaluator (curl | bash, iwr | iex, ...)
  if (sub.eval) {
    const text = stripped.toLowerCase()
    if (/(?:iwr|invoke-webrequest|curl|wget)\b[^;\n|&]*\|\s*(?:iex|invoke-expression|bash|sh|zsh)\b/.test(text))
      return { text: 'remote content piped into a shell evaluator executes it without review' }
    // T1: direct .NET File/Directory data APIs (bypass the sanctioned write/remove tools)
    if (/\[system\.io\.(?:file|directory)\]::(?:delete|writealltext)/.test(text))
      return { text: 'direct .NET File/Directory API call bypasses the sanctioned file tools' }
  }
  return null
}
