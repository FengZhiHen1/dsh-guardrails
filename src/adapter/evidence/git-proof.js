// git-proof.js — bounded read-only Git probes for git-specific destructive operations.
//
// Boundary: every probe is a dry run (`clean -n -d`, `status --porcelain`, and the
// reusable worktree decision module, which itself probes `worktree list`,
// `rev-parse --show-toplevel`, `symbolic-ref -q HEAD` and `status`) or a metadata-only
// existence check (`rev-parse --absolute-git-dir` plus lstat of in-progress marker
// entries for `--abort`). No probe writes to a repository, runs hooks or filters, or
// prints repository content.
//
// Honesty rules: output is bounded; ONE unparseable line makes the WHOLE probe unknown
// (never a partial count); a probe that failed, timed out or was cancelled is unknown and
// the caller must treat it as a stage issue, not as an empty affected set.

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import fs from 'node:fs/promises'
import path from 'node:path'
import { gitWorktreeRemoveDecision } from '../git-evidence.js'

const runFile = promisify(execFile)
const GIT_TIMEOUT_MS = 10_000
const GIT_MAX_BUFFER = 1 << 20 // 1 MiB of porcelain/clean output

function gitEnvironment() {
  const env = { ...process.env }
  for (const key of Object.keys(env)) if (key.startsWith('GIT_')) delete env[key]
  // Sanitized: no inherited GIT_* override may redirect the repository we inspect; no
  // prompt, no lazy fetch, no system attributes, no hook/filter execution, and literal
  // pathspecs so a project subpath containing glob characters cannot broaden the query.
  env.GIT_OPTIONAL_LOCKS = '0'
  env.GIT_TERMINAL_PROMPT = '0'
  env.GIT_NO_LAZY_FETCH = '1'
  env.GIT_ATTR_NOSYSTEM = '1'
  env.GIT_LITERAL_PATHSPECS = '1'
  return env
}

function callTimeout(deadlineAt) {
  if (!Number.isFinite(deadlineAt)) return GIT_TIMEOUT_MS
  const remaining = deadlineAt - Date.now()
  return remaining <= 0 ? 0 : Math.max(1, Math.min(GIT_TIMEOUT_MS, remaining))
}

/**
 * Run one git probe. `run` (tests) receives the argv and supplies stdout; the default
 * runner spawns `git` with a sanitized environment, bounded timeout and bounded buffer.
 */
async function probe(argv, { deadlineAt, signal, run }) {
  const timeout = callTimeout(deadlineAt)
  if (timeout === 0) return { ok: false, deadline: true }
  try {
    let stdout
    if (typeof run === 'function') {
      stdout = (await run(argv, { timeout })).stdout
    } else {
      ;({ stdout } = await runFile('git', argv, {
        shell: false, windowsHide: true, timeout, maxBuffer: GIT_MAX_BUFFER, signal, env: gitEnvironment(),
      }))
    }
    return { ok: true, stdout: typeof stdout === 'string' ? stdout : String(stdout ?? '') }
  } catch (error) {
    if (signal?.aborted) throw signal.reason ?? error
    return { ok: false, code: typeof error?.code === 'number' ? error.code : null }
  }
}

/**
 * Parse `git clean -n -d [-x]` output into exact affected entries. Only
 * "Would remove <path>" (a trailing "/" marks a directory) and the documented
 * "Would skip repository" lines are accepted. A `-z`-quoted path or any other line makes
 * the output unparseable => unknown (never a partial count).
 */
export function parseCleanProof(stdout) {
  const entries = []
  for (const line of String(stdout).split(/\r?\n/)) {
    if (line.trim() === '') continue
    if (line.startsWith('Would skip repository ')) continue
    if (!line.startsWith('Would remove ')) return { state: 'unknown', reason: 'git-clean-unparseable' }
    const raw = line.slice('Would remove '.length)
    if (raw.startsWith('"') || raw.includes('\u0000') || raw.includes('\uFFFD')) {
      return { state: 'unknown', reason: 'git-clean-unparseable' }
    }
    entries.push({ path: raw.replace(/\/+$/, ''), isDirectory: /\/$/.test(raw) })
  }
  return { state: 'known', entries }
}

/** Probe what a real `git clean -d [-x]` in `cwd` would remove (always a dry run). */
export async function proveClean({ cwd, ignored = false, deadlineAt, signal, run } = {}) {
  const argv = ['-C', cwd, 'clean', '-n', '-d']
  if (ignored === true) argv.push('-x')
  const result = await probe(argv, { deadlineAt, signal, run })
  if (!result.ok) return { state: 'unknown', reason: result.deadline ? 'deadline' : 'git-clean-failed' }
  return parseCleanProof(result.stdout)
}

/**
 * Parse `git status --porcelain -uno -- <paths>` into affected paths. Porcelain v1:
 * "XY <path>", renames "R  old -> new" (both sides affected). C-quoted paths and
 * unrepresentable names are refused (unknown), never silently decoded.
 */
export function parseRestoreProof(stdout) {
  const paths = []
  for (const line of String(stdout).split(/\r?\n/)) {
    if (line.trim() === '') continue
    if (line.length < 4 || line.includes('"') || line.includes('\u0000') || line.includes('\uFFFD')) {
      return { state: 'unknown', reason: 'git-restore-unparseable' }
    }
    const body = line.slice(3)
    const arrow = body.indexOf(' -> ')
    if (arrow >= 0) paths.push(body.slice(0, arrow), body.slice(arrow + 4))
    else paths.push(body)
  }
  return { state: 'known', paths }
}

/**
 * Probe what a real `git restore -- <paths>` in `cwd` would overwrite. Pathspecs must
 * come after an explicit `--` separator: without it, an operand may be a tree-ish
 * (branch/tag), whose scope `status -- <operand>` cannot prove, so the caller must treat
 * the operation as ambiguous instead of counting a possibly-empty set.
 */
export async function proveRestore({ cwd, paths, deadlineAt, signal, run } = {}) {
  if (!Array.isArray(paths) || paths.length === 0) return { state: 'known', paths: [] }
  const result = await probe(['-C', cwd, 'status', '--porcelain', '-uno', '--', ...paths], { deadlineAt, signal, run })
  if (!result.ok) return { state: 'unknown', reason: result.deadline ? 'deadline' : 'git-restore-failed' }
  return parseRestoreProof(result.stdout)
}

/**
 * Worktree removal verdict. Reuses the verified decision module (registered linked
 * worktree, not locked, non-detached HEAD, clean tree, bounded ignored count); its
 * `run` injection is forwarded so tests stay deterministic. Verdicts are
 * { kind: 'count' | 'deny' | 'unknown', ... } and every failure stays fail-closed.
 */
export async function proveWorktreeRemove({ cwd, path: targetPath, deadlineAt, run } = {}) {
  // The decision module bounds every probe with deadlineAt and its own sanitized
  // environment; a past deadline yields `unknown` without spawning git.
  return gitWorktreeRemoveDecision({ cwd, path: targetPath, deadlineAt, run })
}

/**
 * In-progress state markers for `git <subcommand> --abort` (DSR-031 决定 8): the Git
 * directory entries that PROVE an operation is in progress and whose abort discards
 * uncommitted working-tree changes. `rebase-merge`/`rebase-apply` are directories; the
 * three `*_HEAD` files are sequencer state files.
 */
const ABORT_STATE_MARKERS = Object.freeze([
  Object.freeze({ name: 'rebase-merge', kind: 'directory' }),
  Object.freeze({ name: 'rebase-apply', kind: 'directory' }),
  Object.freeze({ name: 'MERGE_HEAD', kind: 'file' }),
  Object.freeze({ name: 'CHERRY_PICK_HEAD', kind: 'file' }),
  Object.freeze({ name: 'REVERT_HEAD', kind: 'file' }),
])

/**
 * Prove whether an abortable Git operation is in progress in `cwd`.
 *
 * Read-only: one `git -C <cwd> rev-parse --absolute-git-dir` and lstat-only existence
 * checks of the marker entries under that directory. Nothing is written, no repository
 * content is printed, and the probe never runs the analyzed command.
 *
 * Result shapes (the caller must map `state: 'unknown'` to a deliberate unknown, never
 * to a check failure — D1):
 * - `{ state: 'known', inProgress: true, markers, gitDir }`  proven in-progress state;
 * - `{ state: 'known', inProgress: false, gitDir }`          proven absent;
 * - `{ state: 'unknown', reason }`                           probe could not conclude.
 *
 * `consume` (shared evidence budget) is optional; each marker lstat consumes one unit.
 * The shared deadline bounds the git call AND the marker checks; cancellation rethrows.
 */
export async function proveAbortState({ cwd, deadlineAt, signal, run, consume } = {}) {
  if (typeof cwd !== 'string' || cwd === '') return { state: 'unknown', reason: 'git-cwd-unresolved' }
  if (signal?.aborted) throw signal.reason ?? new Error('guardrails: evidence cancelled')
  const directory = await probe(['-C', cwd, 'rev-parse', '--absolute-git-dir'], { deadlineAt, signal, run })
  if (!directory.ok) return { state: 'unknown', reason: directory.deadline ? 'deadline' : 'git-dir-unresolved' }
  const gitDir = String(directory.stdout).split(/\r?\n/).map((line) => line.trim()).find((line) => line !== '')
  // A NUL or replacement character cannot address a real directory reliably: stay unknown
  // instead of probing a mangled path.
  if (!gitDir || gitDir.includes('\u0000') || gitDir.includes('\uFFFD')) {
    return { state: 'unknown', reason: 'git-dir-unresolved' }
  }
  const markers = []
  for (const marker of ABORT_STATE_MARKERS) {
    if (signal?.aborted) throw signal.reason ?? new Error('guardrails: evidence cancelled')
    if (Number.isFinite(deadlineAt) && Date.now() > deadlineAt) return { state: 'unknown', reason: 'deadline' }
    if (typeof consume === 'function' && !consume()) return { state: 'unknown', reason: 'budget' }
    let info
    try {
      info = await fs.lstat(path.join(gitDir, marker.name))
    } catch (error) {
      if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') continue // proven absent
      return { state: 'unknown', reason: 'abort-state-unreadable' }
    }
    if (marker.kind === 'directory' ? info.isDirectory() : info.isFile()) markers.push(marker.name)
  }
  return { state: 'known', inProgress: markers.length > 0, markers, gitDir }
}
