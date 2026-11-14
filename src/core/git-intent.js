// git-intent — pure classification of a `git` invocation's destruction risk.
// Boundary: no filesystem, process or network access; it only inspects the argv
// array that the shell analysis already produced. Counting of the actual targets
// (clean/restore/worktree evidence) belongs to the adapter, not this module.
//
// Policy (v4 catastrophe standard): only history-destroying or discard-everything
// subcommands are refused outright. Ordinary repository operations are allowed.

/**
 * @typedef {{ kind: 'allow' }} GitAllow
 * @typedef {{ kind: 'refuse', reason: string }} GitRefuse
 * @typedef {{ kind: 'clean', force: boolean, ignored: boolean, dryRun: boolean }} GitClean
 * @typedef {{ kind: 'restore', paths: string[] }} GitRestore
 * @typedef {{ kind: 'worktree-remove', path: string, force: boolean }} GitWorktreeRemove
 * @typedef {GitAllow | GitRefuse | GitClean | GitRestore | GitWorktreeRemove} GitAssessment
 */

/** Global git options that consume the following argument. */
const VALUE_GLOBAL_OPTIONS = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--super-prefix', '--config-env'])

/** Global options whose value may be attached with `=`. */
const EQUALS_GLOBAL_OPTIONS = ['--git-dir', '--work-tree', '--namespace', '--exec-path', '--super-prefix', '--config-env']

const allow = () => ({ kind: 'allow' })
const refuse = (reason) => ({ kind: 'refuse', reason })

/** True when a short option cluster (e.g. `-fdx`) contains the given letter. */
function hasShortFlag(token, letter) {
  return /^-[A-Za-z]+$/.test(token) && token.slice(1).includes(letter)
}

function pushIsDestructive(args) {
  return args.some((arg) =>
    arg === '-f' ||
    arg === '--force' ||
    arg === '--delete' ||
    arg === '-d' ||
    arg === '--mirror' ||
    arg.startsWith('--force-with-lease') ||
    arg.startsWith('--force-if-includes'))
}

function gcIsDestructive(args) {
  return args.some((arg) => arg === '--prune=now' || arg === '--prune=all')
}

function reflogIsDestructive(args) {
  // Only `reflog expire --expire=now --all` irreversibly drops recovery points.
  if (args[0] !== 'expire') return false
  const hasExpireNow = args.some((arg) => arg === '--expire=now' || arg === '--expire=all')
  const hasAll = args.includes('--all')
  return hasExpireNow && hasAll
}

/** Collect literal path arguments after `--` (or non-option words when no `--`). */
function collectPaths(args) {
  const separator = args.indexOf('--')
  const words = separator === -1 ? args.filter((arg) => !arg.startsWith('-')) : args.slice(separator + 1)
  // A `--` with nothing after it names no path.
  if (words.length === 0) return []
  return words
}

function classifyWorktree(args) {
  const sub = args[0]
  if (sub !== 'remove') return allow()
  const rest = args.slice(1)
  const force = rest.some((arg) => arg === '-f' || arg === '--force' || hasShortFlag(arg, 'f'))
  const words = rest.filter((arg) => arg !== '--' && !arg.startsWith('-'))
  if (words.length === 0) return refuse('git worktree remove names no worktree path, so the tree to delete cannot be identified.')
  return { kind: 'worktree-remove', path: words[0], force }
}

function classifyClean(args) {
  const force = args.some((arg) => arg === '--force' || hasShortFlag(arg, 'f'))
  const ignored = args.some((arg) => arg === '-x' || arg === '-X' || hasShortFlag(arg, 'x') || hasShortFlag(arg, 'X'))
  const dryRun = args.some((arg) => arg === '-n' || arg === '--dry-run' || hasShortFlag(arg, 'n'))
  // A dry run or a clean without -f removes nothing.
  if (!force || dryRun) return allow()
  return { kind: 'clean', force, ignored, dryRun: false }
}

function classifyReset(args) {
  // Only --hard/--keep/--merge touch the working tree; a soft/mixed reset keeps files.
  const touchesWorktree = args.some((arg) => arg === '--hard' || arg === '--keep' || arg === '--merge')
  if (!touchesWorktree) return allow()
  // A reset with a worktree-resetting mode is a restore ONLY when it names paths after
  // `--`. `git reset --hard <revision>` (no `--`) resets to a commit and discards every
  // uncommitted change — a history/working-tree catastrophe — even though the revision
  // word looks like a path.
  const separator = args.indexOf('--')
  if (separator === -1) {
    return refuse('git reset --hard/--keep/--merge without `--` resets to a commit and discards every uncommitted change in the repository.')
  }
  const paths = args.slice(separator + 1)
  if (paths.length === 0) {
    return refuse('git reset --hard/--keep/--merge with `--` but no path discards every uncommitted change in the repository.')
  }
  return { kind: 'restore', paths }
}

function classifyRestore(args) {
  // `--source`/`-s` can read a path from any commit, so a restore reading from a source
  // is not a plain working-tree overwrite and is refused.
  if (args.some((arg, index) =>
    arg === '-s' || arg === '--source' || arg.startsWith('--source=') ||
    (arg.startsWith('-s') && arg.length > 2))) {
    return refuse('git restore with --source/-s can read files from any commit, so its effect cannot be identified.')
  }
  // Default restore is path semantics; words after an option terminator are paths.
  const paths = collectPaths(args)
  if (paths.length === 0) return refuse('git restore names no path, so the files to overwrite cannot be identified.')
  return { kind: 'restore', paths }
}

/** A bare checkout word is unambiguously the working tree only when it is `.`, a
 * `:(...)` pathspec magic, or a Windows path with a backslash. Everything else may be
 * a branch/commit name, so it is NOT treated as a path here. */
function looksLikePathWord(word) {
  if (word === '.') return true
  if (word.startsWith(':(')) return true
  return word.includes('\\')
}

function classifyCheckout(args) {
  // A branch-creating switch never overwrites files.
  if (args.some((arg) => arg === '-b' || arg === '-B')) return allow()
  const separator = args.indexOf('--')
  if (separator !== -1) {
    const paths = args.slice(separator + 1)
    if (paths.length === 0) return refuse('git checkout -- names no path, so the files to overwrite cannot be identified.')
    return { kind: 'restore', paths }
  }
  // No `--`: only an unambiguous working-tree signal is a restore. A bare forward-slash
  // word like `feature/x` or `src/app.js` is far more likely a branch or a commit path,
  // and a slash is common in branch names, so it must not be refused as over-defence.
  //
  // KNOWN BOUNDARY: `git checkout <single-file>` (e.g. `checkout src/app.js`) is treated
  // as an allow here and is therefore NOT counted. Discarding a single file this way is a
  // narrow, non-catastrophic working-tree change; the counted path for it is
  // `git restore <path>` (see classifyRestore), which the gate does enumerate.
  const words = args.filter((arg) => arg !== '-' && !arg.startsWith('-'))
  const pathWords = words.filter((word) => looksLikePathWord(word))
  if (pathWords.length > 0) {
    return { kind: 'restore', paths: pathWords }
  }
  return allow()
}

/**
 * Classify a `git` argv array.
 *
 * @param {Array<string|null>} argv arguments after the `git` program name
 * @returns {GitAssessment}
 */
export function assessGit(argv) {
  if (!Array.isArray(argv)) return refuse('git arguments are not an array, so the subcommand cannot be identified.')
  // A dynamic word could be any subcommand or path; it cannot be proven safe.
  if (argv.some((arg) => typeof arg !== 'string')) {
    return refuse('git is invoked with a dynamic argument whose value cannot be proven, so its effect cannot be identified.')
  }

  // Skip leading global options to reach the subcommand.
  let index = 0
  while (index < argv.length) {
    const token = argv[index]
    if (token === '--') { index += 1; break }
    if (!token.startsWith('-')) break
    if (VALUE_GLOBAL_OPTIONS.has(token)) { index += 2; continue }
    if (EQUALS_GLOBAL_OPTIONS.some((name) => token.startsWith(`${name}=`))) { index += 1; continue }
    index += 1
  }

  const sub = argv[index]
  if (sub === undefined) return allow() // e.g. `git --version`, `git --help`
  const rest = argv.slice(index + 1)

  switch (sub) {
    case 'stash':
      if (rest[0] === 'clear' || rest[0] === 'drop') {
        return refuse(`git stash ${rest[0]} irreversibly discards stashed changes.`)
      }
      return allow()
    case 'gc':
      return gcIsDestructive(rest)
        ? refuse('git gc with --prune=now/--prune=all removes unreachable objects that may still be needed.')
        : allow()
    case 'filter-branch':
    case 'filter-repo':
      return refuse(`git ${sub} rewrites repository history and can destroy commits.`)
    case 'push':
      return pushIsDestructive(rest) ? refuse('git push with force/delete/mirror rewrites or deletes remote history.') : allow()
    case 'reset':
      return classifyReset(rest)
    case 'restore':
      return classifyRestore(rest)
    case 'checkout':
      return classifyCheckout(rest)
    case 'clean':
      return classifyClean(rest)
    case 'worktree':
      return classifyWorktree(rest)
    case 'reflog':
      return reflogIsDestructive(rest)
        ? refuse('git reflog expire --expire=now --all drops the recovery points that make lost commits recoverable.')
        : allow()
    default:
      return allow()
  }
}

export default assessGit
