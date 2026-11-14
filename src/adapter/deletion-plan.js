// deletion-plan — pre-execution deletion inventory and the 20-file hard gate.
// Boundary: never executes inspected text, never runs a dry-run, never reads file
// content. Only lstat/opendir metadata is observed. Any unknown, budget, permission,
// ambiguous, link-ancestor, mount-crossing, root, dotdot or non-local (e.g. WSL)
// domain refuses. All return reasons are English.
//
// Two other deletion families share this gate:
//  - `move-source` (the structured move tool): moving removes the SOURCE tree, which is
//    enumerated here exactly like a delete; >20 denies as DEL-14.
//  - the three git actions (`git-clean`, `git-restore`, `git-worktree-remove`): their
//    affected set comes from the git-evidence module (a real `git` dry-run), never from a
//    filesystem walk here. That module is loaded lazily; when it is unavailable the action
//    fails closed (`DEL-GIT-UNKNOWN`) rather than guessing "probably fine".
//
// The whitelist matcher is a real static production dependency. If the core module is
// absent the module fails to load (fail-closed); there is no silent "nothing is
// disposable" fallback. Tests inject a controlled fixture seam instead.
//
// Inspection/execution race (documented, NOT fixed here): the inventory counts the
// filesystem as observed before dispatch. A concurrent writer, or an in-command
// mutation that precedes the delete in the same invocation, can change the set after
// counting. The intent layer must surface such preceding mutations as `unknown` on the
// delete plan (which this gate denies). This module does not claim atomic <=20
// execution under concurrent filesystem mutation; wiring the deny is the Integrator's
// responsibility.

import fs from 'node:fs/promises'
import path from 'node:path'
import { classifyDisposable as defaultClassify, PROJECT_MARKERS as DEFAULT_MARKERS } from '../core/disposable.js'
import { normCompare, pathTargetsCredentials } from '../core/path-check.js'
import { isUnsupportedProviderPath } from '../core/filesystem-path.js'
import { DELETION_DOCTRINE } from '../core/deletion-intent.js'
import { createDisposableEvidence } from './disposable-evidence.js'
import { createMountBoundary } from './mount-boundary.js'

/** Hard limit: more than this many non-exempt entries in one invocation is denied. */
export const DELETION_LIMIT = 20
const MAX_OPERATIONS = 256
const MAX_SCAN_ENTRIES = 200_000
const MAX_ROOT_DEPTH = 64
const DEADLINE_MS = 5_000

/** Operations whose affected set is resolved by the git-evidence module. */
const GIT_OPERATIONS = new Set(['git-clean', 'git-restore', 'git-worktree-remove'])
/** Rule id per git action, used when the affected set exceeds the limit or is denied. */
const GIT_RULES = {
  'git-clean': 'DEL-GIT-CLEAN',
  'git-restore': 'DEL-GIT-RESTORE',
  'git-worktree-remove': 'DEL-GIT-WORKTREE',
}

/** Load the git-evidence module once. `null` means it is unavailable (not merged, or a
 *  load failure): every git action then fails closed instead of being allowed. A test may
 *  inject `_git` to exercise the wiring deterministically. */
let gitEvidenceModule
async function loadGitEvidence() {
  if (gitEvidenceModule !== undefined) return gitEvidenceModule
  try {
    gitEvidenceModule = await import('./git-evidence.js')
  } catch {
    gitEvidenceModule = null
  }
  return gitEvidenceModule
}

/** Paths named by a git operation, tolerant of `paths` or a single `path`. */
function gitPaths(operation) {
  if (Array.isArray(operation.paths)) return operation.paths.filter((entry) => typeof entry === 'string')
  if (typeof operation.path === 'string') return [operation.path]
  return []
}

/** Append the shared deletion doctrine to a one-line refusal reason exactly once. Every
 *  DEL-* denial in this module flows through `deny`, so the doctrine is attached here at a
 *  single chokepoint instead of duplicated across ~30 call sites. Idempotent: a reason that
 *  already contains the sentence is never doubled. */
function withDoctrine(reason) {
  if (typeof reason !== 'string') return reason
  return reason.includes(DELETION_DOCTRINE) ? reason : `${reason} ${DELETION_DOCTRINE}`
}

function deny(ruleId, reason, extra) {
  return { kind: 'deny', ruleId, reason: withDoctrine(reason), ...extra }
}

const isWindows = process.platform === 'win32'
const nameKey = (value) => (isWindows ? String(value).toLowerCase() : String(value))
const isDotdot = (value) => String(value).split(/[\\/]/).some((segment) => segment === '..')

/** True when a directory entry name is a representable, well-formed string. A replacement
 *  char (U+FFFD) means the OS bytes could not be decoded to the real name, and an unpaired
 *  surrogate means the JS string is not well-formed; in both cases a path built from it
 *  cannot address the actual entry, so the caller refuses rather than undercount. */
function isWellFormedName(name) {
  if (typeof name !== 'string' || name.length === 0) return false
  if (name.includes('\uFFFD')) return false
  if (typeof name.isWellFormed === 'function' ? !name.isWellFormed() : /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(name)) return false
  return true
}

/** True when the raw target requests traversal through a trailing separator or `/.`
 * (e.g. `link/` or `link/.`), which dereferences a symlink/junction on many shells. */
function hasTrailingDeref(target) {
  return /[\\/]$/.test(target) || /[\\/]\.$/.test(target)
}

/** Case-SENSITIVE dedupe key. On Windows we must NOT lowercase: NTFS can host
 * case-sensitive directories where `a` and `A` are different files. Under-counting a
 * real entry is unacceptable; re-counting on a case-insensitive volume is the safe
 * direction. Separators are normalized lexically only. */
function dedupeKey(value) {
  return path.normalize(value)
}

/** Case-sensitive filesystem-root identity (no case folding). */
function isFilesystemRoot(absolute) {
  const parsed = path.parse(absolute)
  if (parsed.root && path.normalize(absolute) === path.normalize(parsed.root)) return true
  return false
}

/** A Windows "single-rooted" path begins with `\` or `/` but no drive (e.g. `\foo`).
 * Its effective drive depends on the executing provider and can differ from Node's
 * process drive, so it cannot be mapped to a Node path safely. */
function isSingleRooted(target) {
  if (!isWindows) return false
  return /^[\\/]/.test(target) && !/^[\\/]{2}/.test(target) && !/^[a-z]:[\\/]/i.test(target)
}

function hasTildeSegment(target) {
  // PowerShell (and shells) expand a leading `~`/`~/...`/`~\...` even inside quotes, so
  // the real target is provider-dependent and cannot be proven from the raw string.
  return /^~([\\/]|$)/.test(target) || /(^|[\\/])~([\\/]|$)/.test(target)
}

function resolveCwd(operation, base) {
  const raw = operation.cwd
  if (typeof raw !== 'string' || raw.length === 0) return base
  // An unresolved `..` in the operation cwd could place the target somewhere other
  // than the lexical resolution; refuse rather than guess.
  if (isDotdot(raw)) return undefined
  if (path.isAbsolute(raw)) return raw
  return base ? path.resolve(base, raw) : null
}

function isNonliteral(target, dialect) {
  if (typeof target !== 'string' || target.length === 0 || target.length > 32768) return true
  if (target.includes('\u0000')) return true
  // `*`/`?` are glob wildcards; `[` opens a character class. The intent IR does not
  // distinguish -LiteralPath, so wildcard-bearing paths cannot be proven literal and
  // are rejected (temporarily over-conservative for bracket-named files is accepted).
  if (/[*?[]/.test(target)) return true
  // `~` (home) is expanded by the provider even when quoted; the resolved target is not
  // the literal string, so reject any tilde segment.
  if (hasTildeSegment(target)) return true
  // A backslash in a PowerShell path on a POSIX host is a provider separator but a
  // literal character to Node's POSIX path; the two namespaces disagree, so reject.
  if (dialect === 'powershell' && !isWindows && target.includes('\\')) return true
  if (target.startsWith('\\\\') || target.startsWith('//')) return true
  // Windows single-rooted `\foo` / `/foo` depends on the executing drive/provider.
  if (isSingleRooted(target)) return true
  // A URI-like scheme, a PowerShell provider form (Registry:, Variable:, FileSystem::) or a
  // bare drive-relative `C:foo` is not a local literal target. Refuse via the shared pure
  // predicate BEFORE Node resolution: ENOENT is not a provider defense (an entry can exist).
  if (isUnsupportedProviderPath(target)) return true
  return false
}

/** Walk ancestors above the final component and report the first symlink or a stopping error.
 * @returns {'ok'|'link'|'missing'|'error'}
 */
async function ancestorState(absolute) {
  const root = path.parse(absolute).root
  if (!root) return 'error'
  const parts = absolute.slice(root.length).split(path.sep).filter(Boolean)
  // The final component is the deletion target itself; only its ancestors are traversed.
  let current = root
  for (let index = 0; index < parts.length - 1; index += 1) {
    current = path.join(current, parts[index])
    let info
    try {
      info = await fs.lstat(current)
    } catch (error) {
      if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return 'missing'
      return 'error'
    }
    if (info.isSymbolicLink()) return 'link'
    if (!info.isDirectory()) return 'missing'
  }
  return 'ok'
}

async function projectRootFor(filePath, markers, ctx) {
  if (markers.size === 0) return null
  // A target outside the trusted project boundary never receives an exemption: the
  // marker climb and the evidence are both confined to the boundary. Without a boundary
  // (isolated calls) the climb is unbounded as before.
  if (ctx.boundaryAbs && !isWithinDir(ctx.boundaryAbs, filePath)) return null
  const startDir = path.dirname(filePath)
  if (ctx.rootCache.has(startDir)) return ctx.rootCache.get(startDir)
  // Probe only the fixed PROJECT_MARKERS names present at this root — never list a
  // possibly-huge directory just to look for a few marker files.
  const markerNames = [...markers]
  let dir = startDir
  let depth = 0
  while (depth < MAX_ROOT_DEPTH) {
    if (ctx.rootCache.has(dir)) {
      const cached = ctx.rootCache.get(dir)
      ctx.rootCache.set(startDir, cached)
      return cached
    }
    // Ancestor probing consumes the SAME overall scan budget as the tree walk so a
    // huge project cannot be re-probed once per file without bound.
    ctx.budget.scanned += 1
    ctx.ancestorScans += 1
    if (ctx.budget.scanned > ctx.maxScanEntries || ctx.ancestorScans > ctx.maxScanEntries
        || Date.now() - ctx.started > ctx.deadlineMs) {
      ctx.budgetExceeded = true
      return null
    }
    const present = []
    for (const name of markerNames) {
      try {
        if ((await fs.lstat(path.join(dir, name))).isFile()) present.push(name)
      } catch {
        // Missing/unreadable marker is not confirmed; ignore it.
      }
    }
    if (present.length > 0) {
      const result = { root: dir, markers: present }
      ctx.rootCache.set(dir, result)
      ctx.rootCache.set(startDir, result)
      return result
    }
    const parent = path.dirname(dir)
    if (parent === dir) break
    // Never climb to or above the trusted boundary: a project root must lie strictly
    // inside it, so an outer marker above the boundary cannot capture this file.
    if (ctx.boundaryAbs && !isWithinDir(ctx.boundaryAbs, parent)) break
    dir = parent
    depth += 1
  }
  ctx.rootCache.set(startDir, null)
  return null
}

/** True when `child` equals `parent` or lies inside it, by EXACT path-segment prefix.
 *
 * This grants/withholds a whitelist EXEMPTION, so it must be case-PRESERVING: NTFS can
 * host case-sensitive directories where `C:\repo` and `C:\REPO` are distinct entities.
 * Node's `path.relative` on Windows folds case, and lowering the strings would falsely
 * treat an outside project as inside — so we compare normalized, split segments exactly.
 * A case alias we cannot prove (without querying volume semantics) simply gets no
 * exemption (ordinary count), which is the safe direction. (The Git-tracked comparison in
 * the evidence adapter may fold case because folding only ever REVOKES an exemption.) */
function isWithinDir(parent, child) {
  const split = (value) => path.normalize(value).split(path.sep).filter(Boolean)
  const p = split(path.resolve(parent))
  const c = split(path.resolve(child))
  // Compare a common drive/root anchor first so `C:\x` is never inside `D:\x`.
  if (path.parse(path.resolve(parent)).root !== path.parse(path.resolve(child)).root) return false
  if (p.length > c.length) return false
  for (let i = 0; i < p.length; i += 1) {
    if (p[i] !== c[i]) return false // exact, case-sensitive segment equality
  }
  return true
}

function protectedByPath(absolute, rules) {
  if (rules.builtinSensitiveAsk && pathTargetsCredentials(absolute)) return true
  const normalized = normCompare(absolute)
  return rules.sensitiveFiles.some((marked) => normCompare(marked) === normalized)
}

function makeState() {
  return {
    files: 0, // non-exempt regular files
    links: 0, // deleted link entries (never followed)
    directories: 0,
    git: 0, // entries reported by git evidence for the git actions
    entries: [],
    visitedDirs: new Set(), // real-path keys of traversed directories
    entryPaths: new Set(), // normalized absolute paths of counted file/link entries (dedup, not inode)
    scanned: 0,
    truncated: false,
  }
}

async function countFile(absolute, state, ctx) {
  const key = dedupeKey(absolute)
  if (state.entryPaths.has(key)) return
  const counted = state.files + state.links
  if (counted >= DELETION_LIMIT + 1) {
    state.truncated = true
    return
  }
  state.entryPaths.add(key)
  if (protectedByPath(absolute, ctx.rules)) {
    state.files += 1
    state.entries.push({ path: absolute, type: 'file', protected: true })
    return
  }
  const root = await projectRootFor(absolute, ctx.markers, ctx)
  let disposable = false
  if (root) {
    const relative = path.relative(root.root, absolute).split(path.sep).join('/')
    let verdict = null
    try {
      verdict = ctx.classify({ relativePath: relative, projectMarkers: root.markers, isDirectory: false })
    } catch {
      verdict = null
    }
    // A shape match is NOT proof. Only a candidate the pure matcher flags disposable
    // AND where the evidence adapter proves ownership/regeneration may reduce the count.
    // Any unproven evidence (or no evidence instance) => count the file normally.
    if (verdict && verdict.disposable === true) {
      disposable = await evidenceEligible(absolute, root, verdict.ruleId, ctx)
    }
  }
  if (disposable) {
    state.entries.push({ path: absolute, type: 'file', disposable: true })
    return
  }
  state.files += 1
  state.entries.push({ path: absolute, type: 'file' })
}

/** Ask the once-per-plan evidence adapter whether a shape match may reduce the count.
 * Absent adapter (isolated calls without a boundary) never grants an exemption. */
async function evidenceEligible(absolute, root, ruleId, ctx) {
  if (!ctx.evidence) return false
  try {
    const verdict = await ctx.evidence.verify({
      absolute,
      projectRoot: root.root,
      projectMarkers: root.markers,
      ruleId,
    })
    return Boolean(verdict && verdict.eligible === true)
  } catch (error) {
    // Programming errors must surface; a runtime ambiguity from verify returns
    // eligible:false itself and never throws, so a throw here is a real fault.
    throw error
  }
}

async function countLink(absolute, state) {
  const key = dedupeKey(absolute)
  if (state.entryPaths.has(key)) return
  const counted = state.files + state.links
  if (counted >= DELETION_LIMIT + 1) {
    state.truncated = true
    return
  }
  state.entryPaths.add(key)
  state.links += 1
  state.entries.push({ path: absolute, type: 'link' })
}

/** Recursively inventory a directory subtree with mount-crossing and dedupe guards. */
async function walkDirectory(absolute, state, ctx, rootDev) {
  if (state.truncated) return
  if (ctx.signal?.aborted) throw ctx.signal.reason ?? new Error('guardrails: deletion inventory cancelled')
  if (Date.now() - ctx.started > ctx.deadlineMs || ctx.budget.scanned > ctx.maxScanEntries) {
    ctx.budgetExceeded = true
    return
  }
  let real
  try {
    real = await fs.realpath(absolute)
  } catch {
    real = absolute
  }
  const key = dedupeKey(real)
  if (state.visitedDirs.has(key)) return
  state.visitedDirs.add(key)
  state.directories += 1
  state.entries.push({ path: absolute, type: 'directory' })

  // Stream directory entries with fs.opendir so a huge directory is never fully
  // materialized into memory before the 21-entry early stop. The async iterator closes
  // the directory handle on completion, `break`, or an early `return`.
  let directory
  try {
    directory = await fs.opendir(absolute)
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return
    ctx.permission = error.code ?? error.name
    return
  }
  try {
    for await (const entry of directory) {
      if (state.truncated || ctx.budgetExceeded || ctx.permission) return
      state.scanned += 1
      ctx.budget.scanned += 1
      if (ctx.budget.scanned > ctx.maxScanEntries || state.scanned > ctx.maxScanEntries || Date.now() - ctx.started > ctx.deadlineMs) {
        ctx.budgetExceeded = true
        return
      }
      const child = path.join(absolute, entry.name)
      // Linux filesystems can hold filename bytes that are not valid UTF-8. fs.opendir
      // decodes names as UTF-8, so such a byte sequence arrives as U+FFFD or a
      // non-well-formed JS string. `path.join`/`lstat` on that mangled string will not
      // address the real entry (ENOENT => silent undercount of a file `rm` would delete).
      // We do not attempt to reconstruct raw bytes; if the name cannot be represented we
      // refuse the whole inventory. Ordinary valid Unicode (CJK, emoji) is unaffected.
      if (!isWellFormedName(entry.name)) {
        ctx.ambiguous = child
        return
      }
      // A `.git` directory (or a `.git` worktree pointer file) carries Git metadata whose
      // real common-dir body the count gate cannot prove. Never let a small tree bypass the
      // Git protections; refuse conservatively and let the Integrator prove identity if the
      // exact common-dir body is explicitly required. `nameKey` folds case only on Windows,
      // so `.GIT` on a case-insensitive NTFS volume is still caught (Linux stays exact).
      if (nameKey(entry.name) === '.git') {
        ctx.gitMetadata = child
        return
      }
      let info
      try {
        info = await fs.lstat(child)
      } catch (error) {
        if (error.code === 'ENOENT' || error.code === 'ENOTDIR') continue
        ctx.permission = error.code ?? error.name
        return
      }
      if (info.isSymbolicLink()) {
        // Removing a link entry never follows it; count once and never traverse.
        await countLink(child, state)
      } else if (info.isFile()) {
        await countFile(child, state, ctx)
      } else if (info.isDirectory()) {
        // A cross-device child is a mount crossing under st_dev. On Linux the mount
        // boundary uses /proc/self/mountinfo which ALSO catches same-device bind mounts
        // that st_dev alone misses; a non-Linux host's check() is a no-op and the st_dev
        // test still applies. Either signal is a mount crossing denial.
        if (info.dev !== rootDev) {
          ctx.mountCrossing = child
          return
        }
        const mountVerdict = await ctx.mount.check(child, ctx.boundaryAbs ?? undefined)
        if (mountVerdict.safe !== true) {
          ctx.mountCrossing = child
          ctx.mountReason = mountVerdict.reason
          return
        }
        await walkDirectory(child, state, ctx, rootDev)
      } else {
        // Sockets, FIFOs, devices and other special entries cannot be proven safe.
        ctx.ambiguous = child
        return
      }
    }
  } finally {
    // `for await` closes the handle on normal completion, `break`, or an early `return`;
    // close defensively only when iteration did not auto-close it. A double close throws
    // "Directory handle was closed", which is ignored here.
    try { await directory.close() } catch { /* already closed by the iterator */ }
  }
}

async function inspectOperation(operation, baseCwd, state, ctx) {
  // `move-source` removes the source tree, so it runs the same literal/.git/domain/path
  // checks below and is counted identically; only its >20 rule id differs. Git actions are
  // resolved by the evidence module before reaching here, so any other action is unsupported.
  if (operation.action !== 'delete' && operation.action !== 'move-source') {
    return deny('DEL-09', `Unsupported operation "${String(operation.action)}" reached the deletion gate.`)
  }
  const dialect = operation.dialect
  // On a Windows host, a bash/posix/git-bash/MSYS invocation resolves paths in a
  // different namespace than Node's Win32 path API (e.g. `/tmp` under Git Bash is not
  // `E:\tmp`). The count would be performed on the wrong filesystem view, so refuse and
  // ask for a PowerShell Remove-Item -LiteralPath command with a drive-qualified path.
  if (isWindows && (dialect === 'bash' || dialect === 'posix')) {
    return deny('DEL-03',
      'Deletion gate: a bash/posix command on a Windows host uses a provider-specific path namespace (Git Bash/MSYS/WSL), ' +
      'which does not equal Node/Win32 paths; the delete set cannot be counted on the correct filesystem. ' +
      'Reissue as a PowerShell command using Remove-Item -LiteralPath with a drive-qualified path.')
  }
  if (operation.domain !== 'host') {
    const domain = operation.domain ?? 'unknown'
    return deny('DEL-03',
      `Deletion gate: commands in the "${domain}" domain cannot be inventoried reliably from the host. ` +
      'WSL and other non-host domains are not assumed to map to /mnt or any host path. ' +
      'Reissue as an explicit, supported host command with literal paths, or delete inside that domain with its own native inventory.')
  }
  if (operation.unknown) {
    return deny('DEL-02',
      `Deletion semantics are unresolved (${String(operation.unknown)}); the file set cannot be counted before execution. ` +
      'Use explicit, literal delete commands whose target set is fixed before the call.')
  }
  if (isNonliteral(operation.path, dialect)) {
    return deny('DEL-02',
      'Deletion target is not a literal local path (dynamic, wildcard, tilde, remote, single-rooted or provider-ambiguous); ' +
      'the file set cannot be counted before execution.')
  }
  // A path that enters or addresses `.git` metadata is refused: the count gate cannot
  // prove whether this is the real shared Git common-dir body (old ABS-03 only covers an
  // exact target). This is conservative fail-closed; real identity is the Integrator's
  // decision to prove, not a pre-count exemption. `nameKey` folds case only on Windows so
  // `.GIT` on a case-insensitive volume is caught while Linux stays case-sensitive.
  if (String(operation.path).split(/[\\/]/).some((segment) => nameKey(segment) === '.git')) {
    return deny('DEL-13',
      'Deletion gate: the target addresses a ".git" metadata path. Git metadata is never part of a bounded delete; ' +
      'remove worktrees or repositories through explicit Git commands instead.')
  }
  // Reject `..` before any normalization: normalizing can silently absorb an ancestor
  // symlink, hiding an escape. The gate refuses to reason about dotdot targets.
  if (isDotdot(operation.path)) {
    return deny('DEL-08',
      'Deletion target contains a ".." segment; the resolved target set cannot be proven without following path semantics that may hide a link escape. ' +
      'Use a literal absolute or cwd-relative path with no "..".')
  }
  if (!baseCwd) {
    return deny('DEL-10', 'Deletion gate: the working directory is unresolved, so the target path cannot be located.')
  }
  const absolute = path.isAbsolute(operation.path)
    ? path.normalize(operation.path)
    : path.resolve(baseCwd, operation.path)

  if (isFilesystemRoot(absolute)) {
    return deny('DEL-12',
      'Deletion gate: the target is a filesystem root or drive root; whole-root deletion is never allowed even when the root appears empty.')
  }

  const ancestors = await ancestorState(absolute)
  if (ancestors === 'link') {
    return deny('DEL-04',
      'A parent directory of the deletion target is a symbolic link; the real target set cannot be proven. ' +
      'Delete the real path directly instead of through a link.')
  }
  if (ancestors === 'error') {
    return deny('DEL-06', 'A parent directory of the deletion target could not be inspected; deletion refused.')
  }
  if (ancestors === 'missing') {
    // A missing (or non-directory) ancestor means the target cannot exist: known zero.
    return null
  }

  let info
  try {
    info = await fs.lstat(absolute)
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return null // known zero
    return deny('DEL-06', `Deletion target could not be inspected (${error.code ?? error.name}); deletion refused.`)
  }

  const trailingDeref = hasTrailingDeref(operation.path)
  if (info.isSymbolicLink()) {
    // A recursive delete, or a trailing-separator / `/.` target, may dereference the
    // link into its target. The IR does not carry trailing-slash semantics, so the
    // target set cannot be proven; only a plain non-recursive delete removes the link.
    if (operation.recursive || trailingDeref) {
      return deny('DEL-08',
        'A delete of a symbolic link or junction is recursive or uses a trailing separator; whether it removes only the link or follows it ' +
        'into its target cannot be proven. Delete the link itself without recursion or a trailing separator.')
    }
    await countLink(absolute, state)
    return null
  }
  if (info.isFile()) {
    await countFile(absolute, state, ctx)
    return null
  }
  if (info.isDirectory()) {
    if (trailingDeref && !operation.recursive) {
      return deny('DEL-08', 'A directory target with a trailing separator but no recursion has ambiguous delete semantics; deletion refused.')
    }
    if (!operation.recursive) {
      return deny('DEL-08',
        'A non-recursive delete of a directory has ambiguous semantics (empty-vs-nonempty outcome cannot be proven); ' +
        'use an explicit recursive delete of literal paths so the count is deterministic.')
    }
    const rootDev = info.dev
    // Check the top-level recursive target itself against the mount boundary (an explicit
    // target that IS a mountpoint at/inside the deletion root must be refused on Linux).
    const topMount = await ctx.mount.check(absolute, ctx.boundaryAbs ?? undefined)
    if (topMount.safe !== true) {
      ctx.mountCrossing = absolute
      ctx.mountReason = topMount.reason
      return null
    }
    await walkDirectory(absolute, state, ctx, rootDev)
    return null
  }
  return deny('DEL-08', 'Deletion target is a special file (socket/FIFO/device) that cannot be inventoried safely.')
}

/**
 * Resolve one git action's affected set through the git-evidence module and return either
 * `{ count }` or a denial. Fail-closed by construction: a missing module, a thrown error, an
 * `unknown` verdict, or an evidence `deny` all refuse. Nothing here inspects the filesystem
 * itself, so a git command the intent layer allowed is never walked or boundary-checked.
 */
async function inspectGitOperation(operation, baseCwd, ctx, git) {
  const action = operation.action
  const ruleId = GIT_RULES[action]
  if (!git || typeof git.gitCleanTargets !== 'function') {
    return deny('DEL-GIT-UNKNOWN',
      `Deletion gate: the git evidence module is unavailable, so the set affected by "${action}" cannot be counted before execution. ` +
      'Refusing rather than guessing; retry when the git evidence capability is present.')
  }
  const opCwd = resolveCwd(operation, baseCwd)
  if (opCwd === undefined || opCwd === null) {
    return deny('DEL-GIT-UNKNOWN',
      `Deletion gate: the working directory for "${action}" is unresolved or contains a ".." segment, so the affected repository cannot be located.`)
  }
  const deadlineAt = ctx.started + ctx.deadlineMs
  let result
  try {
    if (action === 'git-clean') {
      result = await git.gitCleanTargets({ cwd: opCwd, ignored: operation.ignored === true, deadlineAt })
    } else if (action === 'git-restore') {
      const paths = gitPaths(operation)
      if (paths.length === 0) {
        return deny(ruleId, 'Deletion gate: a git restore names no paths, so the set it would overwrite cannot be counted.')
      }
      result = await git.gitRestoreTargets({ cwd: opCwd, paths, deadlineAt })
    } else {
      const target = gitPaths(operation)[0]
      if (!target) {
        return deny(ruleId, 'Deletion gate: git worktree remove names no worktree path, so the directory it would remove cannot be located.')
      }
      result = await git.gitWorktreeRemoveDecision({ cwd: opCwd, path: target, deadlineAt })
    }
  } catch {
    return deny('DEL-GIT-UNKNOWN',
      `Deletion gate: git evidence for "${action}" failed unexpectedly, so the affected set cannot be counted; invocation refused.`)
  }
  if (!result || result.kind === 'unknown') {
    return deny('DEL-GIT-UNKNOWN',
      `Deletion gate: git evidence for "${action}" could not be established (repository unreadable, git unavailable or timed out), ` +
      'so the affected set cannot be counted before execution.')
  }
  if (result.kind === 'deny') {
    return deny(ruleId, `Deletion gate: ${gitDenyReason(action, result.reason)}`, { counts: result.count })
  }
  if (result.kind === 'count' && Number.isInteger(result.count) && result.count >= 0) {
    return { count: result.count }
  }
  return deny('DEL-GIT-UNKNOWN',
    `Deletion gate: git evidence for "${action}" returned an unusable result, so the affected set cannot be counted.`)
}

/** Human reason for a git-evidence `deny` verdict. English, no repository content. */
function gitDenyReason(action, reason) {
  if (action === 'git-worktree-remove') {
    if (reason === 'detached-head') {
      return 'git worktree remove refuses a worktree whose HEAD is detached, because its commits are not reachable from a branch and removing it would destroy them.'
    }
    if (reason === 'untracked-or-modified') {
      return 'git worktree remove requires a clean worktree; it has untracked or uncommitted changes whose loss cannot be undone. Commit, stash or discard them explicitly first.'
    }
    if (reason === 'ignored-over-limit') {
      return `git worktree remove would discard more than ${DELETION_LIMIT} ignored non-rebuildable entries; verify the expected set and remove them explicitly first.`
    }
    if (reason === 'main-worktree') return 'git worktree remove refuses the main worktree of the repository.'
    if (reason === 'not-listed') return 'the target is not a registered linked worktree of this repository.'
    if (reason === 'locked') return 'the target worktree is locked and cannot be removed.'
    return `the worktree cannot be removed safely (${String(reason)}).`
  }
  return `the affected set cannot be proven safe (${String(reason)}).`
}

/**
 * Inventory every delete in one invocation and enforce the 20-file hard gate. Filesystem
 * deletes and `move-source` share the walk; the three git actions are counted by the
 * evidence module and only their totals join the same limit.
 * @param {object} options
 * @param {Array<object>} options.operations delete plans from the intent layer
 * @param {string} options.cwd actual session working directory
 * @param {object} options.rules evaluated rules (sensitiveFiles, builtinSensitiveAsk)
 * @param {AbortSignal} [options.signal]
 * @param {Function} [options.classifyDisposable] controlled test seam; defaults to the
 *   production core matcher statically imported above
 * @param {string[]} [options.projectMarkers] controlled test seam; defaults to the
 *   production core PROJECT_MARKERS
 * @param {object} [options._budget] test-only deterministic budget seam
 *   ({ maxScanEntries, deadlineMs }); production always uses the fixed constants.
 * @param {object|null} [options._git] test-only seam for the git-evidence module; when
 *   omitted the real module is loaded (and a missing module fails closed).
 * @throws {TypeError} If operations or rules are malformed.
 */
export async function planDeletions({ operations, cwd, boundary, rules, signal, classifyDisposable, projectMarkers, _budget, _evidence, _mount, _git } = {}) {
  if (!Array.isArray(operations)) throw new TypeError('guardrails: deletion plans must be an array')
  if (!rules || !Array.isArray(rules.sensitiveFiles) || typeof rules.builtinSensitiveAsk !== 'boolean') {
    throw new TypeError('guardrails: evaluated rules are required')
  }
  const maxScanEntries = Number.isInteger(_budget?.maxScanEntries) ? _budget.maxScanEntries : MAX_SCAN_ENTRIES
  const deadlineMs = Number.isFinite(_budget?.deadlineMs) ? _budget.deadlineMs : DEADLINE_MS
  if (operations.length > MAX_OPERATIONS) {
    return deny('DEL-07', `Deletion gate: ${operations.length} delete operations exceed the analysis budget of ${MAX_OPERATIONS}.`)
  }
  // Production path uses the statically-imported matcher; tests may inject a controlled
  // fixture seam. There is no silent empty fallback for a missing module.
  const classify = classifyDisposable ?? defaultClassify
  const rawMarkers = projectMarkers ?? DEFAULT_MARKERS
  if (signal?.aborted) {
    return deny('DEL-11', 'Deletion gate: invocation cancelled before its inventory completed.')
  }
  const baseCwd = typeof cwd === 'string' && path.isAbsolute(cwd) ? cwd : null
  // The trusted project boundary is a SEPARATE concept from the execution cwd: it bounds
  // where an exemption may apply. When the caller does not supply one (isolated calls) it
  // falls back to the actual cwd so behavior is unchanged; there is no bound otherwise.
  const boundaryAbs = typeof boundary === 'string' && path.isAbsolute(boundary)
    ? boundary : baseCwd
  const startedAt = Date.now()
  // ONE shared observation counter across the tree walk, ancestor probing, the evidence
  // source/Git checks and the mount snapshot. Every consumer increments the same count,
  // so the combined work cannot exceed maxScanEntries through any helper; exceeding it is
  // a hard DEL-07 budget denial (not per-helper caps).
  const budget = { scanned: 0 }
  const consume = () => {
    if (Date.now() - startedAt > deadlineMs) return false
    budget.scanned += 1
    return budget.scanned <= maxScanEntries
  }
  const evidence = _evidence ?? createDisposableEvidence({ boundary: boundaryAbs ?? undefined, signal, deadlineAt: startedAt + deadlineMs, consume })
  const mount = _mount ?? createMountBoundary({ signal, deadlineAt: startedAt + deadlineMs, consume })
  const ctx = {
    rules,
    classify,
    markers: new Set((rawMarkers ?? []).map(nameKey)),
    rootCache: new Map(),
    started: startedAt,
    signal,
    boundaryAbs,
    evidence,
    mount,
    budget,
    mountCrossing: null,
    mountReason: null,
    permission: null,
    ambiguous: null,
    budgetExceeded: false,
    gitMetadata: null,
    ancestorScans: 0,
    maxScanEntries,
    deadlineMs,
  }
  const state = makeState()

  for (const operation of operations) {
    if (state.truncated) break
    if (ctx.permission || ctx.mountCrossing || ctx.ambiguous || ctx.budgetExceeded || ctx.gitMetadata) break
    if (signal?.aborted) {
      return deny('DEL-11', 'Deletion gate: invocation cancelled before its inventory completed.')
    }
    if (!operation || typeof operation !== 'object') {
      return deny('DEL-02', 'Deletion gate: malformed delete plan.')
    }
    const operationCwd = resolveCwd(operation, baseCwd)
    // `resolveCwd` returns undefined only when the operation cwd contains `..`, whose
    // lexical resolution could place the target somewhere other than the real directory.
    if (operationCwd === undefined) {
      return deny('DEL-08',
        'Deletion gate: the operation working directory contains a ".." segment; the target cannot be located without resolving path semantics that may hide a link escape.')
    }
    // Git actions are counted by the git evidence module, never by a filesystem walk: a
    // `git status`/`add`/`commit` never reaches this gate (it emits no operation), and these
    // three never enter the generic target walk either.
    if (GIT_OPERATIONS.has(operation.action)) {
      const git = _git !== undefined ? _git : await loadGitEvidence()
      const outcome = await inspectGitOperation(operation, baseCwd, ctx, git)
      if (outcome.kind === 'deny') return outcome
      state.git += outcome.count
      state.files += outcome.count
      state.entries.push({ path: `git:${operation.action}:${gitPaths(operation).join(',')}`, type: 'git' })
      continue
    }
    // An absolute target ignores the operation cwd; a relative one needs a resolved base.
    const base = path.isAbsolute(operation.path ?? '') ? baseCwd : operationCwd
    let failure
    try {
      failure = await inspectOperation(operation, base, state, ctx)
    } catch (error) {
      if (signal?.aborted) return deny('DEL-11', 'Deletion gate: invocation cancelled before its inventory completed.')
      if (typeof error?.code !== 'string') throw error
      return deny('DEL-06', `Deletion target inspection failed (${error.code}); deletion refused.`)
    }
    if (failure) return failure
  }

  if (ctx.permission) {
    return deny('DEL-06', `Deletion gate: a target subtree could not be fully read (${ctx.permission}); the count cannot be proven.`)
  }
  if (ctx.mountCrossing) {
    // Distinguish a proven crossing from an inventory we could not verify (procfs
    // unreadable/malformed/expired). Only assert "cannot verify" — never claim a
    // crossing we did not actually observe.
    const unavailable = typeof ctx.mountReason === 'string'
      && /unavailable|malformed|budget|deadline|cancel|exhaust|poc/i.test(ctx.mountReason)
    if (unavailable) {
      return deny('DEL-05',
        'Deletion gate: the Linux mount boundary could not be verified for this target subtree ' +
        `(${ctx.mountReason}); the traversal set cannot be proven to stay within one filesystem. ` +
        'Retry when /proc/self/mountinfo is readable, or delete a smaller explicit path that stays within one mount.')
    }
    return deny('DEL-05',
      'Deletion gate: a recursive delete would cross a filesystem/mount boundary; the traversal set cannot be proven. ' +
      'Delete each mount separately with explicit literal paths.')
  }
  if (ctx.ambiguous) {
    return deny('DEL-08', 'Deletion gate: a directory subtree contains an entry whose type cannot be proven; deletion refused.')
  }
  if (ctx.gitMetadata) {
    return deny('DEL-13',
      'Deletion gate: the target tree contains a ".git" directory or worktree pointer; Git metadata cannot be safely inventoried as ' +
      'ordinary files. Remove Git worktrees or repositories through explicit Git commands instead.')
  }
  if (ctx.budgetExceeded) {
    return deny('DEL-07', 'Deletion gate: the inventory exceeded its scan budget before completing; the count cannot be proven <= 20.')
  }

  const counted = state.files + state.links
  if (state.truncated || counted > DELETION_LIMIT) {
    // The rule id names the family that overflowed: a pure git action keeps its DEL-GIT-*
    // rule, a pure source-removing move is DEL-14, and a plain delete (or a mixed call) is
    // the generic DEL-01 gate. All of them carry the shared doctrine via `deny`.
    const actions = operations.map((operation) => operation?.action)
    const onlyGit = actions.length > 0 && actions.every((action) => GIT_OPERATIONS.has(action))
    const onlyMove = actions.length > 0 && actions.every((action) => action === 'move-source')
    const gitAction = onlyGit ? actions[0] : undefined
    const ruleId = onlyGit ? GIT_RULES[gitAction] : onlyMove ? 'DEL-14' : 'DEL-01'
    const subject = onlyGit
      ? `git ${gitAction.slice(4)} would remove at least ${DELETION_LIMIT + 1} entries`
      : onlyMove
        ? `DEL-14: moving would remove at least ${DELETION_LIMIT + 1} non-whitelisted source files or links`
        : `this call would delete at least ${DELETION_LIMIT + 1} non-whitelisted files or links`
    const instruction = onlyGit
      ? `Verify the expected set first; remove at most ${DELETION_LIMIT} entries per independent call and re-issue for the rest. There is no in-call override.`
      : `Verify the expected set first; even when the extra files are expected, this call is refused — ` +
        `delete at most ${DELETION_LIMIT} entries per independent call and re-issue for any remaining files. ` +
        'Splitting the delete into separate calls is the only way to proceed; there is no in-call override.'
    return deny(ruleId,
      `Deletion gate: ${subject} (limit ${DELETION_LIMIT}). ${instruction}`,
      { counts: { files: state.files, links: state.links, directories: state.directories, atLeast: true } })
  }

  // Final re-check before granting: the last metadata/evidence await could have pushed
  // the wall clock past the deadline, or the caller could have cancelled. An allow must
  // not be returned from a stale, post-deadline observation.
  if (signal?.aborted) {
    return deny('DEL-11', 'Deletion gate: invocation cancelled before its inventory completed.')
  }
  if (Date.now() - ctx.started > ctx.deadlineMs) {
    return deny('DEL-07', 'Deletion gate: the inventory deadline elapsed before completion; the count cannot be proven <= 20.')
  }

  return {
    kind: 'allow',
    counts: { files: state.files, links: state.links, directories: state.directories, atLeast: false },
    entries: state.entries,
  }
}
