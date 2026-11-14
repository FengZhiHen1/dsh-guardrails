// git-evidence — read-only, bounded observation of what a `git clean`, `git restore`
// or `git worktree remove` command WOULD affect. The core module (src/core/git-intent.js)
// classifies the command line and emits a `git-clean` / `git-restore` /
// `git-worktree-remove` operation; this adapter turns that operation into a count or a
// decision. It never mutates a repository: every probe is a dry run (`clean -n`,
// `status --porcelain`, `worktree list`).
//
// Design rules (see tmp/guardrails-v4-contract.md §Git evidence and DSR-020):
// - Anything ambiguous is `unknown`, and the caller MUST treat `unknown` as a deny.
//   A failed, timed-out, truncated or unparseable probe never produces a count.
// - Worktree removal is the strictest check. The user's rule outranks the file-count
//   rule: ZERO tolerance for non-ignored entries (any untracked, staged or unstaged
//   change denies), and at most 20 ignored entries AFTER subtracting rebuildable build
//   output/caches. A detached HEAD, the main worktree, an unregistered path, a locked
//   worktree, or any git failure/timeout denies.
// - `git clean` counts the exact lines `git clean -n` reports as `Would remove`. A line
//   that is neither a removal nor a documented skip makes the whole probe unparseable.
// - `git restore` counts porcelain entries for the given paths; empty paths mean nothing
//   to restore (the caller guarantees it does not pass an empty list).
// - The shared plan deadline bounds every call. A past deadline is `unknown` without
//   spawning git.
//
// Testability: each entry point accepts an optional injected `run(argv)` that resolves
// `{ stdout }` (or rejects) in place of the real `git` child process, so timeout and
// unparseable-output paths are exercised without depending on a hung process. The
// default runner spawns `git` with a sanitized environment, a bounded timeout and a
// bounded output buffer.

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import fs from 'node:fs/promises'
import path from 'node:path'

const runFile = promisify(execFile)

const GIT_TIMEOUT_MS = 10_000
const GIT_MAX_BUFFER = 1 << 20 // 1 MiB of porcelain/clean output
const IGNORED_COUNT_LIMIT = 20

const isWindows = process.platform === 'win32'

/** Ignored entries that are rebuildable build output / caches: skipped from the count. */
const REBUILDABLE_SEGMENTS = Object.freeze([
  // Dependency / vendored trees.
  'node_modules',
  'vendor',
  // Python caches.
  '__pycache__',
  '.pytest_cache',
  '.mypy_cache',
  '.ruff_cache',
  '.tox',
  // General caches.
  '.cache',
  '.turbo',
  '.parcel-cache',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.angular',
  '.nyc_output',
  '.gradle',
  // Conventional build-output directories.
  'dist',
  'build',
  'out',
  'target',
  'bin',
  'obj',
  'coverage',
])

const REBUILDABLE_SEGMENT_SET = new Set(REBUILDABLE_SEGMENTS)
const REBUILDABLE_EXTENSION = /\.(?:pyc|pyo|pyd|class|o|obj|pdb|tsbuildinfo)$/i

// --- shared helpers --------------------------------------------------------

function unknown(reason) {
  return { kind: 'unknown', reason }
}

/**
 * A sanitized environment: no inherited GIT_* override may redirect the repository we
 * inspect, no terminal prompt, no lazy fetch, no system attributes. Never printed.
 */
function gitEnv() {
  const env = { ...process.env }
  for (const key of Object.keys(env)) {
    if (key.startsWith('GIT_')) delete env[key]
  }
  env.GIT_OPTIONAL_LOCKS = '0'
  env.GIT_TERMINAL_PROMPT = '0'
  env.GIT_NO_LAZY_FETCH = '1'
  env.GIT_ATTR_NOSYSTEM = '1'
  return env
}

/**
 * Per-call timeout derived from the shared plan deadline. Returns 0 when the deadline
 * has already passed (the caller reports `unknown` without spawning git).
 */
function callTimeout(deadlineAt) {
  if (typeof deadlineAt !== 'number') return GIT_TIMEOUT_MS
  const remaining = deadlineAt - Date.now()
  if (remaining <= 0) return 0
  return Math.max(1, Math.min(GIT_TIMEOUT_MS, remaining))
}

/**
 * Run one git probe. Returns `{ ok:true, stdout }` or
 * `{ ok:false, code, deadline }` where `code` is the numeric exit code (when the
 * repository answered with a non-zero status) and `deadline` marks a past deadline.
 * Injection: when `run` is a function it receives the git argv and supplies stdout.
 */
async function probe(run, argv, deadlineAt) {
  const timeout = callTimeout(deadlineAt)
  if (timeout === 0) return { ok: false, code: null, deadline: true }
  try {
    let stdout
    if (typeof run === 'function') {
      stdout = (await run(argv, { timeout })).stdout
    } else {
      ;({ stdout } = await runFile('git', argv, {
        shell: false,
        windowsHide: true,
        timeout,
        maxBuffer: GIT_MAX_BUFFER,
        env: gitEnv(),
      }))
    }
    return { ok: true, stdout: typeof stdout === 'string' ? stdout : String(stdout ?? '') }
  } catch (error) {
    const code = error && typeof error.code === 'number' ? error.code : null
    return { ok: false, code, deadline: false }
  }
}

/** Non-empty output lines, WITHOUT modifying them (porcelain prefixes are significant). */
function outputLines(stdout) {
  return String(stdout).split(/\r?\n/).filter((line) => line.trim() !== '')
}

/**
 * Canonicalize a path for identity comparison: real path when it exists (so a Windows
 * 8.3 short name and the long name compare equal), else the resolved lexical path.
 */
async function canonical(value) {
  const abs = path.resolve(value)
  try {
    return await fs.realpath(abs)
  } catch {
    return abs
  }
}

/** Normalize a canonical path to a comparison key (case-fold only on Windows). */
function comparisonKey(canonicalPath) {
  let p = String(canonicalPath).replace(/\\/g, '/')
  p = p.replace(/\/{2,}/g, '/')
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1)
  return isWindows ? p.toLowerCase() : p
}

/** True when a rebuildable build-output/cache entry may be skipped from the ignored count. */
function isRebuildableIgnored(relativePath) {
  const cleaned = String(relativePath).replace(/\/+$/, '')
  const segments = cleaned.split('/').filter(Boolean)
  if (segments.length === 0) return false
  const lower = segments.map((segment) => segment.toLowerCase())
  if (lower.some((segment) => REBUILDABLE_SEGMENT_SET.has(segment))) return true
  // A bare artifact file (compiled bytecode/object, incremental build info) is rebuildable
  // even when it is not inside one of the conventional directories.
  return REBUILDABLE_EXTENSION.test(lower[lower.length - 1])
}

/** Parse `git worktree list --porcelain`. Returns null when the shape is unparseable. */
function parseWorktreeList(stdout) {
  const entries = []
  let current = null
  for (const raw of String(stdout).split(/\r?\n/)) {
    if (raw === '') {
      if (current) {
        entries.push(current)
        current = null
      }
      continue
    }
    const space = raw.indexOf(' ')
    const key = space === -1 ? raw : raw.slice(0, space)
    const value = space === -1 ? '' : raw.slice(space + 1)
    if (key === 'worktree') {
      if (current) entries.push(current)
      current = { path: value, locked: false, bare: false, detached: false, branch: null }
      if (value === '') return null
      continue
    }
    if (!current) return null
    if (key === 'locked') current.locked = true
    else if (key === 'bare') current.bare = true
    else if (key === 'detached') current.detached = true
    else if (key === 'branch') current.branch = value
    // Other keys (HEAD, prunable, …) do not change the decision.
  }
  if (current) entries.push(current)
  return entries
}

/**
 * Count the removals reported by `git clean -n`. Anything other than a `Would remove`
 * line or a documented `Would skip repository` line makes the output unparseable (null).
 */
function countWouldRemove(stdout) {
  let count = 0
  for (const line of outputLines(stdout)) {
    if (line.startsWith('Would remove ')) {
      count += 1
      continue
    }
    if (line.startsWith('Would skip repository ')) continue
    return null
  }
  return count
}

// --- public API ------------------------------------------------------------

/**
 * Count the files `git clean -d [-x]` in `cwd` would remove.
 *
 * @param {object} input
 * @param {string} input.cwd  repository directory to inspect.
 * @param {boolean} [input.ignored]  true when the command includes `-x` (ignored files).
 * @param {number} [input.deadlineAt]  shared plan deadline (epoch ms).
 * @param {Function} [input.run]  injected probe runner (tests only).
 * @returns {Promise<{kind:'count', count:number} | {kind:'unknown', reason?:string}>}
 */
export async function gitCleanTargets({ cwd, ignored = false, deadlineAt, run } = {}) {
  if (typeof cwd !== 'string' || cwd.trim() === '') {
    throw new TypeError('guardrails: gitCleanTargets requires a cwd string')
  }
  const argv = ['-C', cwd, 'clean', '-n', '-d']
  if (ignored === true) argv.push('-x')

  const result = await probe(run, argv, deadlineAt)
  if (!result.ok) return unknown(result.deadline ? 'deadline' : 'git-clean-failed')

  const count = countWouldRemove(result.stdout)
  if (count === null) return unknown('git-clean-unparseable')
  return { kind: 'count', count }
}

/**
 * Count the porcelain entries a `git restore -- <paths>` would revert in `cwd`.
 * Empty `paths` never reaches here; it yields zero rather than a false deny.
 *
 * @param {object} input
 * @param {string} input.cwd
 * @param {string[]} input.paths  pathspecs (already literal-checked by the core).
 * @param {number} [input.deadlineAt]
 * @param {Function} [input.run]
 * @returns {Promise<{kind:'count', count:number} | {kind:'unknown', reason?:string}>}
 */
export async function gitRestoreTargets({ cwd, paths, deadlineAt, run } = {}) {
  if (typeof cwd !== 'string' || cwd.trim() === '') {
    throw new TypeError('guardrails: gitRestoreTargets requires a cwd string')
  }
  if (!Array.isArray(paths)) {
    throw new TypeError('guardrails: gitRestoreTargets requires a paths array')
  }
  if (paths.length === 0) return { kind: 'count', count: 0 }
  for (const entry of paths) {
    if (typeof entry !== 'string' || entry === '') return unknown('git-restore-bad-path')
  }

  const result = await probe(run, ['-C', cwd, 'status', '--porcelain', '-uno', '--', ...paths], deadlineAt)
  if (!result.ok) return unknown(result.deadline ? 'deadline' : 'git-restore-failed')
  return { kind: 'count', count: outputLines(result.stdout).length }
}

/**
 * Decide whether a `git worktree remove <path>` may proceed.
 *
 * Order (all failures deny; `unknown` is a deny for the caller):
 *  1. resolve the target,
 *  2. it must be a registered, non-locked linked worktree (never the current/primary one),
 *  3. a detached HEAD denies,
 *  4. any non-ignored entry (untracked/staged/unstaged) denies — zero tolerance,
 *  5. ignored entries minus rebuildable build output/caches must be ≤ 20.
 *
 * @param {object} input
 * @param {string} input.cwd  repository directory the command runs in.
 * @param {string} input.path  worktree path from the command line (relative or absolute).
 * @param {number} [input.deadlineAt]
 * @param {Function} [input.run]
 * @returns {Promise<
 *   {kind:'count', count:number} |
 *   {kind:'deny', reason:string, count?:number} |
 *   {kind:'unknown', reason?:string}>}
 */
export async function gitWorktreeRemoveDecision({ cwd, path: targetPath, deadlineAt, run } = {}) {
  if (typeof cwd !== 'string' || cwd.trim() === '') {
    throw new TypeError('guardrails: gitWorktreeRemoveDecision requires a cwd string')
  }
  if (typeof targetPath !== 'string' || targetPath.trim() === '') {
    return unknown('worktree-path-missing')
  }

  // 1. Resolve the target relative to cwd.
  let targetAbs
  try {
    targetAbs = path.resolve(cwd, targetPath)
  } catch {
    return unknown('worktree-path-unresolved')
  }
  const targetKey = comparisonKey(await canonical(targetAbs))

  // 2. It must be a registered linked worktree, not locked, not the current/primary one.
  const list = await probe(run, ['-C', cwd, 'worktree', 'list', '--porcelain'], deadlineAt)
  if (!list.ok) return unknown(list.deadline ? 'deadline' : 'worktree-list-failed')
  const entries = parseWorktreeList(list.stdout)
  if (!entries || entries.length === 0) return unknown('worktree-list-unparseable')

  const entryKeys = []
  for (const entry of entries) entryKeys.push(comparisonKey(await canonical(entry.path)))
  const index = entryKeys.indexOf(targetKey)
  if (index === -1) return unknown('worktree-not-registered')

  const entry = entries[index]
  if (entry.locked) return { kind: 'deny', reason: 'locked' }
  if (entry.bare) return unknown('worktree-bare')

  const ownTop = await probe(run, ['-C', cwd, 'rev-parse', '--show-toplevel'], deadlineAt)
  if (!ownTop.ok) return unknown(ownTop.deadline ? 'deadline' : 'worktree-toplevel-failed')
  const ownTopRaw = ownTop.stdout.trim()
  if (ownTopRaw === '') return unknown('worktree-toplevel-unavailable')
  const ownTopKey = comparisonKey(await canonical(ownTopRaw))
  // Refuse the worktree the command runs in, and refuse the primary (first) worktree.
  if (targetKey === ownTopKey) return { kind: 'deny', reason: 'main-worktree' }
  if (index === 0) return { kind: 'deny', reason: 'main-worktree' }

  // 3. A detached HEAD cannot be attributed to a branch: deny.
  const head = await probe(run, ['-C', targetAbs, 'symbolic-ref', '-q', 'HEAD'], deadlineAt)
  if (!head.ok) {
    if (head.deadline) return unknown('deadline')
    // Exit status 1 means "not a symbolic ref" (detached); anything else is unknown.
    if (head.code === 1) return { kind: 'deny', reason: 'detached-head' }
    return unknown('worktree-head-unavailable')
  }

  // 4. Zero tolerance for non-ignored entries.
  const status = await probe(run, ['-C', targetAbs, 'status', '--porcelain', '-unormal'], deadlineAt)
  if (!status.ok) return unknown(status.deadline ? 'deadline' : 'worktree-status-failed')
  const dirty = outputLines(status.stdout)
  if (dirty.some((line) => !line.startsWith('!!'))) {
    return { kind: 'deny', reason: 'untracked-or-modified' }
  }

  // 5. Ignored entries minus rebuildable build output/caches must be ≤ 20.
  const ignoredStatus = await probe(
    run,
    ['-C', targetAbs, 'status', '--porcelain', '-unormal', '--ignored=matching'],
    deadlineAt,
  )
  if (!ignoredStatus.ok) return unknown(ignoredStatus.deadline ? 'deadline' : 'worktree-status-failed')

  let count = 0
  for (const line of outputLines(ignoredStatus.stdout)) {
    if (!line.startsWith('!!')) return { kind: 'deny', reason: 'untracked-or-modified' }
    const relativePath = line.slice(2).trim()
    if (relativePath === '') return unknown('worktree-status-unparseable')
    if (isRebuildableIgnored(relativePath)) continue
    count += 1
  }
  if (count > IGNORED_COUNT_LIMIT) {
    return { kind: 'deny', reason: 'ignored-over-limit', count }
  }
  return { kind: 'count', count }
}
