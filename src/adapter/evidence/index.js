// index.js — evidence adapter entry: collectEvidence(analysis, options).
//
// Role (docs/technical-details/架构重构设计「证据适配器」): turn the unified analysis
// result (status / operations / candidates / gaps) into the observation evidence a single
// pure decision point consumes — disaster identities, one bounded deduped inventory,
// protected-path hits, rebuildable-exemption verdicts, git risk observations and stage
// issues. This module owns the orchestration and the resource envelope; it NEVER decides
// allow/confirm/deny and never produces rule verdicts beyond identity rule ids.
//
// Identity and resource boundaries:
// - Read-only: lstat/opendir/realpath, bounded /proc reads, bounded read-only git probes,
//   the read-only Windows Storage inventory, and fsProvider.stat for opaque
//   `domain: 'fs'` targets. Nothing mutates the filesystem; analyzed command text is
//   data and is never executed.
// - Domain isolation: host probes answer ONLY for `domain: 'host'` operations whose
//   declared platform matches the host. `domain: 'fs'` targets stay opaque (no host
//   probes unless a verified host mapping exists — none is wired in this slice). Other
//   domains (WSL, …) are recorded unprobed.
// - Protection matching is injected (`isProtectedPath(path, policy, platform)`); the
//   adapter never invents a protected list of its own, and a missing injection is an
//   explicit stage issue, never a silent "nothing is protected".
// - Resource envelope: one shared deadline, one shared scan budget (maxEntries) and the
//   caller's signal bound every loop. Like the verified observeTargets, the whole
//   collection settles inside a deadline race because native metadata calls cannot be
//   aborted individually; a cancelled or expired collection REJECTS so the caller can
//   apply the check-failure semantics instead of trusting a partial observation.
// - Candidates, gaps and the analysis status pass through unchanged; the analysis layer
//   owns coverage reporting, the evidence layer owns observation.

import path from 'node:path'
import fs from 'node:fs/promises'
import { createMountBoundary } from '../mount-boundary.js'
import { createDisposableEvidence } from '../disposable-evidence.js'
import { classifyDisposable, PROJECT_MARKERS } from '../../core/disposable.js'
import { comparable, absoluteCwd, hasDotDot, resolveLocal, withinExact } from './internal.js'
import {
  RULES,
  metadataProbe,
  matchSystemTree,
  observeSystemTrees,
  observeDeviceIdentity,
  observeDeviceSelectorIdentity,
  observeLinuxBlockIdentity,
  isDeviceNamespacePath,
  gitCommonDir,
} from './identity.js'
import { createInventoryState, finalizeInventory, grantDirectoryExemptions, noteUnknown, observeOperation } from './inventory.js'

const DEFAULT_LIMITS = Object.freeze({
  deadlineMs: 5_000,   // whole-collection deadline (shared with every probe and walk)
  maxEntries: 4_096,   // shared scan budget across traversal, probes and evidence checks
  maxDepth: 16,        // traversal depth for recursive trees without a declared maxDepth
  maxOperations: 256,  // observed operations per call
  threshold: 21,       // R-07 early stop: "at least 21" (the confirm boundary is 20)
})

const DESTRUCTIVE = new Set(['delete', 'move-source', 'git-clean', 'git-restore', 'git-worktree-remove'])

/**
 * Collect target evidence for one analyzed call.
 *
 * @param {object} analysis unified analysis result { status, operations, candidates, gaps }
 * @param {object} [options]
 * @param {object} [options.policy] evaluated policy handed to the injected protected matcher
 * @param {AbortSignal} [options.signal] caller cancellation
 * @param {string} [options.workspaceRoot] trusted workspace boundary for rebuildable evidence
 * @param {object} [options.limits] bounded overrides of the default resource envelope
 * @param {object} [options.fsProvider] `{ stat(target) }` for `domain: 'fs'` operations
 * @param {string} [options.platform] host platform (defaults to process.platform)
 * @param {Function} [options.isProtectedPath] `(path, policy, platform) => boolean` injection
 * @param {Function} [options.gitRun] test seam: `(argv, { timeout }) => { stdout }` git probes
 * @param {object} [options._windowsInventory] test seam: pre-observed Windows disk inventory
 * @param {object} [options._evidence] test seam: replaces the rebuildable-evidence adapter
 * @param {object} [options._mount] test seam: replaces the mount-boundary checker
 * @returns {Promise<object>} Evidence per 架构重构设计「取证结果形状」
 * @throws {TypeError|RangeError} malformed analysis or limits
 */
export async function collectEvidence(analysis, {
  policy = null, signal, workspaceRoot, limits: limitOverrides,
  fsProvider, platform = process.platform, isProtectedPath, gitRun,
  _windowsInventory, _evidence, _mount,
} = {}) {
  if (!analysis || typeof analysis !== 'object' || Array.isArray(analysis)) throw new TypeError('guardrails: analysis result object is required')
  const { status, operations, candidates, gaps } = analysis
  if (!['complete', 'partial', 'fault'].includes(status)) throw new TypeError('guardrails: analysis status must be complete, partial or fault')
  for (const member of [operations, candidates, gaps]) {
    if (!Array.isArray(member)) throw new TypeError('guardrails: analysis operations, candidates and gaps must be arrays')
  }
  const limits = { ...DEFAULT_LIMITS, ...limitOverrides }
  for (const key of Object.keys(DEFAULT_LIMITS)) {
    if (!Number.isSafeInteger(limits[key]) || limits[key] <= 0) throw new RangeError(`guardrails: invalid evidence limit ${key}`)
  }

  // Deadline race: native metadata requests cannot be aborted, so — like the verified
  // observeTargets — the whole collection settles within the budget via a rejected race.
  const controller = new AbortController()
  const merged = AbortSignal.any([controller.signal, ...(signal ? [signal] : [])])
  let settle
  const interrupted = new Promise((_, reject) => {
    settle = () => reject(merged.reason ?? new Error('guardrails: evidence collection cancelled'))
    if (merged.aborted) settle()
    else merged.addEventListener('abort', settle, { once: true })
  })
  // When the caller aborted before the race below, its early throw would leave `interrupted`
  // with no handler; mark it handled so the rejection never surfaces as unhandledRejection.
  interrupted.catch(() => {})
  const startedAt = Date.now()
  const deadlineAt = startedAt + limits.deadlineMs
  const timer = setTimeout(() => controller.abort(new Error('guardrails: evidence collection deadline')), limits.deadlineMs)
  try {
    // A caller signal that aborted BEFORE the race must reject now: Promise.race attaches
    // its reactions in array order, so a collect() that resolves in one microtask would
    // otherwise beat an already-rejected interruption and return a stale observation.
    merged.throwIfAborted()
    return await Promise.race([
      collect({
        analysis, policy, signal: merged, workspaceRoot, limits, fsProvider, platform,
        isProtectedPath, gitRun, _windowsInventory, _evidence, _mount, deadlineAt,
      }),
      interrupted,
    ])
  } finally {
    clearTimeout(timer)
    merged.removeEventListener('abort', settle)
  }
}

async function collect({
  analysis, policy, signal, workspaceRoot, limits, fsProvider, platform,
  isProtectedPath, gitRun, _windowsInventory, _evidence, _mount, deadlineAt,
}) {
  const windows = platform === 'win32'
  const identities = []
  const issues = []
  const protectedHits = []
  const protectedSeen = new Set()
  const protectedPaths = new Set()
  const state = createInventoryState()
  let gitRisk = null
  let matcherMissingNoted = false
  let scanned = 0
  let systemTreesPromise = null
  const commonDirs = new Map()

  const noteIssue = (issue) => {
    if (issues.length < limits.maxOperations) issues.push(issue)
  }

  /** Deduped protected-path matching through the INJECTED matcher only. */
  const noteProtected = (value, action) => {
    if (typeof value !== 'string' || value === '') return
    if (typeof isProtectedPath !== 'function') {
      if (!matcherMissingNoted) {
        matcherMissingNoted = true
        noteIssue({ kind: 'protected-matcher-missing', reason: 'isProtectedPath was not injected; protected matching skipped' })
      }
      return
    }
    let hit = false
    try {
      hit = isProtectedPath(value, policy, platform) === true
    } catch (error) {
      noteIssue({ kind: 'protected-matcher-failed', reason: error?.message ?? String(error), path: value })
      return
    }
    if (!hit) return
    protectedPaths.add(value)
    const key = `${action}\u0000${value}`
    if (!protectedSeen.has(key)) {
      protectedSeen.add(key)
      protectedHits.push({ path: value, action })
    }
    return true
  }

  // One shared observation counter across the walk, identity probes and evidence checks:
  // combined work cannot exceed maxEntries through any helper.
  const consume = () => {
    if (Date.now() > deadlineAt) return false
    scanned += 1
    return scanned <= limits.maxEntries
  }

  /** Shared, lazily computed host system-tree observation (one walk per call). */
  const getSystemTrees = () => {
    systemTreesPromise ??= observeSystemTrees({ signal, consume, deadlineAt })
    return systemTreesPromise
  }

  /** Shared, cached git common-dir probe (one bounded probe per distinct directory). */
  const commonDirFor = async (dir) => {
    const key = path.normalize(String(dir))
    if (commonDirs.has(key)) return commonDirs.get(key)
    const value = await gitCommonDir({ cwd: dir, signal, deadlineAt, run: gitRun })
    commonDirs.set(key, value)
    return value
  }

  const noteGitRisk = (paths, reason) => {
    if (!Array.isArray(paths) || paths.length === 0 || typeof reason !== 'string') return
    gitRisk = gitRisk
      ? { paths: [...new Set([...gitRisk.paths, ...paths])], reason: `${gitRisk.reason}; ${reason}` }
      : { paths: [...paths], reason }
  }

  // The mount snapshot (Linux only; a no-op elsewhere) and the rebuildable-evidence
  // adapter are created once per call and share this call's budget and deadline.
  const boundaryAbs = typeof workspaceRoot === 'string' && path.isAbsolute(workspaceRoot) ? workspaceRoot : null
  const ctx = {
    platform,
    windows,
    workspaceRoot: boundaryAbs,
    limits,
    deadlineAt,
    signal,
    consume,
    noteIssue,
    noteProtected,
    noteGitRisk,
    fsProvider,
    gitRun,
    windowsInventory: _windowsInventory,
    mount: _mount ?? createMountBoundary({ signal, deadlineAt, consume }),
    evidence: _evidence ?? (boundaryAbs ? createDisposableEvidence({ boundary: boundaryAbs, signal, deadlineAt, consume }) : null),
    classify: classifyDisposable,
    markers: new Set(PROJECT_MARKERS.map((name) => comparable(name, windows))),
    rootCache: new Map(),
    commonDirFor,
    getSystemTrees,
    protectedPaths,
  }

  const observed = analysis.operations.length > limits.maxOperations
    ? analysis.operations.slice(0, limits.maxOperations)
    : analysis.operations
  if (analysis.operations.length > limits.maxOperations) {
    noteIssue({ kind: 'operation-budget', reason: `${analysis.operations.length} operations exceed the evidence cap of ${limits.maxOperations}` })
  }

  // Semantic traversal order (the analysis sorts operations by execution position): a
  // known, non-preview write EARLIER in the call can create or overwrite entries that a
  // later delete would remove. The invalidation is SCOPE-SCOPED: it applies only when the
  // write's known scope can overlap the delete's known scope (exact paths, pattern bases
  // and subtree roots, containment in either direction). A write whose scope cannot be
  // resolved is real uncertainty and fails closed: it could affect the later deletion, so
  // the later inventory is marked unknown (deliberate, NOT an I/O failure) and each
  // affected operation records an issue (架构重构设计 stage 5: 记录受影响的操作和原因).
  const MUTATING = new Set(['write-content', 'truncate-content'])
  const writeScopes = []
  const knownScopeOf = (operation) => {
    const target = operation.target ?? { kind: 'unknown' }
    // An fs-domain scope is opaque host-side: whether it can overlap a later delete is
    // not provable here, so it fails closed like an unresolvable scope.
    if ((operation.context?.domain ?? 'unknown') === 'fs') return { unknown: true, paths: [], roots: [] }
    const cwd = absoluteCwd(operation.context?.cwd)
    if (target.kind === 'exact') {
      const paths = (Array.isArray(target.paths) ? target.paths : [])
        .map((value) => resolveLocal(value, cwd)).filter(Boolean)
      return paths.length ? { unknown: false, paths, roots: [] } : { unknown: true, paths: [], roots: [] }
    }
    if (target.kind === 'pattern' && typeof target.base === 'string') {
      const base = resolveLocal(target.base, cwd)
      return base ? { unknown: false, paths: [], roots: [base] } : { unknown: true, paths: [], roots: [] }
    }
    if (target.kind === 'subtree' && typeof target.root === 'string') {
      const root = resolveLocal(target.root, cwd)
      return root ? { unknown: false, paths: [], roots: [root] } : { unknown: true, paths: [], roots: [] }
    }
    return { unknown: true, paths: [], roots: [] }
  }
  const scopesOverlap = (write, del) => {
    if (write.unknown || del.unknown) return true
    // Folding case only on Windows: an alias must INvalidate (the safe direction).
    const hit = (a, b) => withinExact(a, b, ctx.windows) || withinExact(b, a, ctx.windows)
    const targets = [...del.paths, ...del.roots]
    const sources = [...write.paths, ...write.roots]
    return targets.some((t) => sources.some((s) => hit(s, t)))
  }

  for (const operation of observed) {
    signal.throwIfAborted()
    if (Date.now() > deadlineAt) {
      noteIssue({ kind: 'deadline', reason: 'deadline reached before all operations were observed' })
      break
    }
    if (!operation || typeof operation !== 'object' || typeof operation.action !== 'string') {
      noteIssue({ kind: 'malformed-operation', reason: 'operation without an action' })
      continue
    }
    const destructive = DESTRUCTIVE.has(operation.action) && operation.preview !== true
    try {
      if (destructive && writeScopes.some((write) => scopesOverlap(write, knownScopeOf(operation)))) {
        noteIssue({
          kind: 'invalidated-inventory',
          reason: 'a preceding write in the same call can change this target set before it executes',
          path: firstExactPath(operation.target ?? {}) ?? undefined,
        })
        noteUnknown(state, 'preceding-mutation')
      }
      await observeOperation(state, operation, ctx)
      await collectIdentities(operation, state, ctx, identities)
    } catch (error) {
      // Cancellation propagates (the deadline race rejects too); anything else is a stage
      // issue for THIS operation, never a silent drop of the collected evidence.
      if (signal.aborted) throw error
      noteIssue({ kind: 'inventory-failed', reason: error?.code ?? error?.message ?? String(error) })
      state.failed = true
    }
    if (MUTATING.has(operation.action) && operation.preview !== true) writeScopes.push(knownScopeOf(operation))
  }

  // An allow-grade observation must not come from a stale one: re-check cancellation
  // before handing the evidence to the caller (the deadline race covers expiry).
  signal.throwIfAborted()

  // Directory-level rebuildable evidence runs on the SAME shared state after the walk:
  // qualifying directories are reported once and cover their per-file records.
  grantDirectoryExemptions(state, ctx)

  const result = {
    analysisStatus: analysis.status,
    operations: analysis.operations,
    candidates: analysis.candidates,
    gaps: analysis.gaps,
    identities,
    inventory: finalizeInventory(state),
    protectedHits,
    exemptions: state.exemptions,
    issues,
  }
  // Host collection forwards the analysis credential flags unchanged (credential face).
  if (analysis.inlineCredential !== undefined) result.inlineCredential = analysis.inlineCredential
  if (analysis.credentialTextMention !== undefined) result.credentialTextMention = analysis.credentialTextMention
  if (gitRisk) result.gitRisk = gitRisk
  return result
}

// --- disaster identities ----------------------------------------------------

/**
 * Collect disaster identities for one operation (规则模型「规则目录」catastrophic.*).
 * Conclusions are fail-closed and PROBE-BACKED:
 * - git-history-destroy comes from the analysis-proven subcommand facts, but a PROVEN
 *   preview (`git push --dry-run`) destroys nothing and records NO identity;
 * - a declared deviceMutation is only the analysis-side fact that this operation has
 *   destructive device utility — it is NOT proof of a physical device (an ordinary image
 *   file must not be denied by the word alone). Device identity is granted ONLY by the
 *   verified read-only host probes; a probeable device that cannot be proven stays
 *   WITHOUT identity and records an explicit identity issue (关键身份取证失败 → the
 *   caller's check-failure semantics). The declared fact stays on the passthrough
 *   operation for the policy.
 * - system-tree and git-metadata identities apply to destructive non-preview operations
 *   on ordinary paths only, by realpath equality against proven host observations.
 */
async function collectIdentities(operation, state, ctx, identities) {
  const { action } = operation
  const target = operation.target ?? { kind: 'unknown' }
  const details = operation.details ?? {}
  const domain = operation.context?.domain ?? 'unknown'
  const hostProbes = domain === 'host' && (operation.context?.platform ?? ctx.platform) === ctx.platform

  // 1) Git history destruction: the identity names the repository's real common dir when
  //    a bounded read-only probe can, otherwise the probe cwd. A proven preview (e.g.
  //    `git push --dry-run`) removes nothing and records NO identity. No host probe on
  //    other domains.
  if (action === 'git-history-destroy') {
    if (operation.preview !== true) {
      identities.push({ ruleId: RULES.gitHistory, path: await gitHistoryIdentityPath(operation, ctx), action })
    }
    return
  }

  if (!hostProbes || operation.preview === true) return

  // 2) Raw storage writes can destroy a device without deleting a directory entry.
  const mayMutate = DESTRUCTIVE.has(action) || action === 'write-content' || action === 'truncate-content' || details.deviceMutation
  if (!mayMutate) return
  const selector = selectorFromDeviceMutation(details.deviceMutation)
  if (selector) {
    const identity = await observeDeviceSelectorIdentity({ selector, windowsInventory: ctx.windowsInventory, signal: ctx.signal, deadlineAt: ctx.deadlineAt })
    if (identity) identities.push({ ruleId: RULES.device, path: JSON.stringify(selector), action })
    else ctx.noteIssue({ kind: 'device-identity-unproven', reason: 'device selector could not be proven physical' })
  }
  const devicePaths = new Set()
  for (const declaredPath of deviceMutationPaths(details.deviceMutation)) {
    if (isDeviceNamespacePath(declaredPath, ctx.platform)) devicePaths.add(declaredPath)
  }
  for (const absolute of identityPaths(target, operation.context?.cwd)) {
    if (isDeviceNamespacePath(absolute, ctx.platform)) devicePaths.add(absolute)
  }
  for (const absolute of devicePaths) {
    let identity = null
    if (ctx.windows) {
      identity = await observeDeviceIdentity({ target: absolute, windowsInventory: ctx.windowsInventory, signal: ctx.signal, deadlineAt: ctx.deadlineAt })
    } else if (ctx.platform === 'linux') {
      const metadata = await metadataProbe(absolute, { signal: ctx.signal })
      if ((metadata.state === 'known' && !metadata.stat.isBlockDevice()) || metadata.code === 'ENOENT' || metadata.code === 'ENOTDIR') continue
      identity = await observeLinuxBlockIdentity({ target: absolute, systemTrees: await ctx.getSystemTrees(), signal: ctx.signal, consume: ctx.consume, deadlineAt: ctx.deadlineAt })
    }
    if (identity) identities.push({ ruleId: RULES.device, path: absolute, action })
    else ctx.noteIssue({ kind: 'device-identity-unproven', reason: 'device probe could not prove physical identity', path: absolute })
  }

  // 3) Ordinary paths: system tree and git common-dir identities, destructive only.
  if (!DESTRUCTIVE.has(action) || operation.preview === true) return
  for (const absolute of identityPaths(target, operation.context?.cwd)) {
    if (isDeviceNamespacePath(absolute, ctx.platform)) continue // handled above
    const real = await knownRealPath(state, absolute, ctx)
    if (!real) continue
    // Whole host system tree destruction — realpath EQUALITY only: deleting one file
    // inside the tree is a normal deletion, not a catastrophic identity.
    if (matchSystemTree(await ctx.getSystemTrees(), real, ctx.windows)) {
      identities.push({ ruleId: RULES.root, path: real, action })
      continue
    }
    // The real Git common-dir body (or its object store): shared across worktrees.
    const common = await ctx.commonDirFor(path.dirname(real))
    if (common && (sameRealPath(real, common, ctx.windows) || sameRealPath(real, path.join(common, 'objects'), ctx.windows))) {
      identities.push({ ruleId: RULES.gitMetadata, path: real, action })
    }
  }
}

/** Selector-shaped deviceMutation ({diskNumber}|{driveLetter}); strings are paths instead. */
function selectorFromDeviceMutation(declared) {
  if (!declared || typeof declared !== 'object' || Array.isArray(declared)) return null
  const selector = {}
  if (Number.isSafeInteger(declared.diskNumber)) selector.diskNumber = declared.diskNumber
  if (typeof declared.driveLetter === 'string') selector.driveLetter = declared.driveLetter
  return Object.keys(selector).length > 0 ? selector : null
}

/** Path-shaped deviceMutation: a string path, or an object carrying a `path` member. */
function deviceMutationPaths(declared) {
  if (typeof declared === 'string' && declared !== '') return [declared]
  if (declared && typeof declared === 'object' && !Array.isArray(declared) && typeof declared.path === 'string' && declared.path !== '') {
    return [declared.path]
  }
  return []
}

async function gitHistoryIdentityPath(operation, ctx) {
  const cwd = absoluteCwd(operation.context?.cwd)
  const common = cwd ? await ctx.commonDirFor(cwd) : null
  return common ?? cwd ?? ''
}

/** Top-level identity paths: exact target paths and subtree roots, resolved against cwd. */
function identityPaths(target, cwd) {
  const resolve = (value) => {
    if (typeof value !== 'string' || value === '' || value.includes('\u0000') || hasDotDot(value)) return null
    return path.isAbsolute(value) ? path.normalize(value) : cwd ? path.resolve(cwd, value) : null
  }
  if (target.kind === 'exact') return (Array.isArray(target.paths) ? target.paths : []).map(resolve).filter(Boolean)
  if (target.kind === 'subtree') {
    const root = resolve(target.root)
    return root ? [root] : []
  }
  return []
}

function firstExactPath(target) {
  if (target.kind === 'exact') return (Array.isArray(target.paths) ? target.paths : []).find((value) => typeof value === 'string' && value !== '') ?? null
  if (target.kind === 'subtree' && typeof target.root === 'string') return target.root
  return null
}

/**
 * Real path of a top-level identity candidate, cached from the inventory pass. A link
 * entry is cached as null: removing a link never destroys the tree behind it, so no
 * identity may be resolved THROUGH it.
 */
async function knownRealPath(state, absolute, ctx) {
  const key = path.normalize(absolute)
  if (state.realPaths.has(key)) return state.realPaths.get(key)
  try {
    const info = await fs.lstat(absolute)
    if (info.isSymbolicLink()) {
      state.realPaths.set(key, null)
      return null
    }
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') {
      state.realPaths.set(key, null)
      return null
    }
    throw error
  }
  const probe = await metadataProbe(absolute, { signal: ctx.signal })
  const real = probe.state === 'known' ? probe.path : null
  state.realPaths.set(key, real)
  return real
}

function sameRealPath(a, b, windows) {
  return comparable(a, windows) === comparable(b, windows)
}
