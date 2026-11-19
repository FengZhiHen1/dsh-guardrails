// inventory.js — bounded read-only target inventory for destructive operations.
//
// Responsibility (docs/technical-details/架构重构设计「证据适配器」): interpret one
// operation's targets INSIDE ITS OWN EXECUTION DOMAIN, observe directory entries with
// lstat/opendir/realpath, dedupe by domain-normalized path, count non-exempt regular
// files + link entries, list deduped directories separately, and record rebuildable
// candidates with their exemption verdict.
//
// Identity and resource boundaries:
// - Metadata only: lstat/opendir/realpath, or fsProvider.stat for opaque `domain: 'fs'`
//   targets. No file content is read, no analyzed command is executed, nothing mutates.
// - Every loop is bounded by the shared deadline, the shared scan budget (ctx.consume)
//   and the caller's signal; exceeding a bound marks the inventory UNKNOWN instead of
//   silently continuing — the decision point must never receive a count we cannot prove.
// - Dedupe keys are CASE-PRESERVING: NTFS can host case-sensitive directories, and
//   re-counting a case alias is the safe direction while under-counting is not.
// - Link entries are counted as removed directory entries and NEVER followed.
// - Domain isolation: host observation (fs, mount snapshot, git proofs) answers only for
//   `domain: 'host'` on the matching host platform; `domain: 'fs'` uses fsProvider.stat
//   only; any other domain (WSL, …) is recorded unprobed — no cross-domain observation.
// - Counting semantics (docs/technical-details/规则模型「删除分档细节」): regular files +
//   link entries count; directories are deduped and listed but not counted; worktree
//   removals are resolved by the git decision, not by a walk. After the threshold is
//   reached the precise count stops (`lower-bound`, "at least N") while protected-path
//   scanning and identity work continue within the remaining budget.

import fs from 'node:fs/promises'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { classifyDisposable, PROJECT_MARKERS } from '../../core/disposable.js'
import { absoluteCwd, hasDotDot, isWellFormedName, resolveLocal, withinExact } from './internal.js'
import { proveAbortState, proveClean, proveRestore, proveWorktreeRemove } from './git-proof.js'

/** R-07: >20 non-exempt entries confirms. Precise counting stops at 21 ("at least 21"). */
export const COUNT_THRESHOLD = 21

const DESTRUCTIVE = new Set(['delete', 'move-source', 'git-clean', 'git-restore', 'git-worktree-remove'])
const GIT_ACTIONS = new Set(['git-clean', 'git-restore', 'git-worktree-remove'])

export function createInventoryState() {
  return {
    files: [], links: [], directories: [], roots: [], unknown: [], exemptions: [],
    counted: 0,
    seen: new Set(),      // counted file/link entries (case-preserving absolute paths)
    dirsSeen: new Set(),  // deduped directories
    visited: new Set(),   // real paths of traversed directories
    realPaths: new Map(), // top-level target -> real path (null = link, never resolved)
    dirTree: new Map(),   // walked directory -> direct-children observation record
    exemptPaths: new Set(), // files whose rebuildable exemption concluded `established`
    seenKeys: new Set(),  // fs-domain dedupe by opaque stable target key
    fsIdentities: [],     // backend identity and content version pairs
    hostVersions: [],     // versions of protected content targets in the host filesystem
    stoppedAtThreshold: false,
    failed: false,        // scan/permission/mount/ambiguous failure observed
  }
}

/** Deduped, ordered inventory view; `kind` is honest about what was proven.
 * `kind` distinguishes deliberately unknown parts (dynamic targets, domain boundaries —
 * the observed count stays a valid exact number and `unknown` names the unenumerated
 * parts so the policy can still CONFIRM with a known range, R-09) from actual
 * observation failures (I/O, budget, ambiguity — kind 'unreliable', never a count). */
export function finalizeInventory(state) {
  const kind = state.failed ? 'unreliable'
    : state.stoppedAtThreshold ? 'lower-bound'
      : 'exact'
  const files = [...new Set(state.files)]
  const links = [...new Set(state.links)]
  const directories = [...new Set(state.directories)]
  const roots = [...new Set(state.roots)]
  const unknown = [...new Set(state.unknown)]
  const inventory = { kind, count: state.counted, files, links, directories, roots, unknown }
  // Fingerprint over the sorted observation lists: two trees with the SAME non-exempt
  // count but different contents produce different fingerprints, so a re-inventory after
  // a confirmation can prove the scope changed and not just that the count matches.
  // fs-domain entries contribute their opaque stable key + FsInfo.version pair, so a
  // version bump on an unchanged display path still changes the fingerprint.
  const fsIdentities = state.fsIdentities.map((entry) => `${entry.key}\u0000${entry.version ?? ''}`).sort()
  inventory.fingerprint = createHash('sha256')
    .update(JSON.stringify([files.sort(), links.sort(), directories.sort(), roots.sort(), unknown.sort(), fsIdentities,
      state.hostVersions.sort((left, right) => left[0].localeCompare(right[0]))]))
    .digest('hex')
  return inventory
}

const DIRECTORY_EXEMPTION_RULE = 'data.delete.rebuildable'

/**
 * Directory-level rebuildable exemption (R-14, 批量删除白名单「目录级」), narrow
 * evidence-backed positive case only:
 * - EVERY visited leaf file in the subtree is INDIVIDUALLY proven rebuildable by the
 *   file-level evidence adapter (ownership + regeneration + Git-untracked + boundary);
 * - no link entries, no protected hits, no ambiguous/unrepresentable entries, no mount
 *   crossing and no budget/deadline failure anywhere below (record.complete);
 * - the whole subtree was enumerated (never stopped at the threshold);
 * - the subtree contains at least one proven file leaf: an empty or name-only directory
 *   carries no regeneration evidence of its own and STAYS COUNTED leaf by leaf.
 *
 * Only MAXIMAL qualifying directories are reported, once each (子树覆盖：以目录为单位
 * 单列，不逐个展开); the per-file exemption records inside them are replaced by the
 * directory record through the SAME shared exemption/count state, so nothing is
 * double-reported and the count itself never changes here.
 */
export function grantDirectoryExemptions(state, ctx) {
  if (state.failed || state.stoppedAtThreshold || state.dirTree.size === 0) return
  const qualifying = new Set()
  const qualifies = (record) => {
    if (!record || record.complete !== true) return false
    if (record.links.length > 0) return false
    // Every leaf file must be individually proven rebuildable and unprotected.
    if (!record.files.every((file) => state.exemptPaths.has(path.normalize(file)) && !ctx.protectedPaths.has(path.normalize(file)))) return false
    if (record.files.length > 0) return true
    // No own files: qualify only through at least one qualifying child subtree.
    return record.dirs.some((childKey) => qualifies(state.dirTree.get(childKey)))
  }
  for (const record of state.dirTree.values()) {
    if (qualifies(record)) qualifying.add(record.key)
  }
  const maximal = [...qualifying].filter((key) => !qualifying.has(path.dirname(key)))
  if (maximal.length === 0) return
  const covered = (value) => maximal.some((dirKey) => withinExact(dirKey, path.normalize(value)))
  for (const key of maximal) {
    state.exemptions.push({
      path: state.dirTree.get(key).path,
      kind: 'directory',
      ruleId: DIRECTORY_EXEMPTION_RULE,
      conclusion: 'established',
    })
  }
  state.exemptions = state.exemptions.filter((entry) => entry.kind !== 'file' || entry.conclusion !== 'established' || !covered(entry.path))
}

/** Record a deliberately unknown part (dynamic target, domain boundary): the observed
 * entries and count stay valid; the policy confirms the unenumerated remainder with the
 * recorded known scope (R-09). This is NOT an I/O failure. */
export function noteUnknown(state, reason) {
  const value = String(reason ?? 'unknown')
  if (!state.unknown.includes(value)) state.unknown.push(value)
}

/** Record an actual observation failure (I/O, budget, ambiguity): the inventory cannot
 * be trusted as a count, so its kind becomes 'unreliable' regardless of observed entries. */
export function noteFailure(state, reason) {
  noteUnknown(state, reason)
  state.failed = true
}

const pastDeadline = (ctx) => Date.now() > ctx.deadlineAt

/** Observe one operation: protection scan for non-counting actions, inventory for destructive ones. */
export async function observeOperation(state, operation, ctx) {
  const { action } = operation
  const domain = operation.context?.domain ?? 'unknown'
  // The managed fs domain resolves EVERY content path (read/write included): a protected
  // alias may only be canonical after resolution. Counting stays destructive-only.
  if (domain === 'fs') return observeFsOperation(state, operation, ctx)
  // Content/permission actions and proven previews (real -WhatIf / --dry-run) remove
  // nothing: they still get the protected-path scan (R-04 covers reads too) and no count.
  if (!DESTRUCTIVE.has(action) || operation.preview === true) {
    await scanProtection(state, operation, ctx)
    return
  }
  if (GIT_ACTIONS.has(action)) return observeGitOperation(state, operation, ctx)
  if (domain === 'host') return observeHostOperation(state, operation, ctx)
  // WSL and other domains: no host observation is ever shared with them (not even as a
  // guess via /mnt); the analysis already kept the target expression for the policy.
  noteUnknown(state, 'domain-unprobed')
}

/** Resolve literal paths against the verified execution cwd before matching exact marks. */
async function scanProtection(state, operation, ctx) {
  if (operation.preview || operation.action === 'metadata') return
  const target = operation.target ?? { kind: 'unknown' }
  const context = operation.context ?? {}
  if (context.domain !== 'host' || (context.platform ?? ctx.platform) !== ctx.platform) return
  const cwd = absoluteCwd(context.cwd)
  if (target.kind !== 'exact') return
  for (const value of target.paths ?? []) {
    const absolute = resolveLocal(value, cwd)
    const marked = ctx.noteProtected(absolute ?? value, operation.action)
    if (!absolute) continue
    if (!ctx.consume()) { noteFailure(state, 'budget'); return }
    try {
      // Content operations follow links. Check the spelling and the resolved file.
      const resolved = await fs.realpath(absolute)
      const resolvedMarked = ctx.noteProtected(resolved, operation.action)
      if (!marked && !resolvedMarked) continue
      const info = await fs.stat(resolved, { bigint: true })
      state.hostVersions.push([absolute, resolved, String(info.dev), String(info.ino), String(info.size), String(info.mtimeNs), String(info.ctimeNs)])
    } catch (error) {
      if (error.code === 'ENOENT' || error.code === 'ENOTDIR') {
        if (marked) state.hostVersions.push([absolute, 'absent'])
        continue
      }
      ctx.noteIssue({ kind: 'protected-target-unresolved', reason: error.code ?? error.name, path: absolute })
    }
  }
}

// --- host domain -----------------------------------------------------------

async function observeHostOperation(state, operation, ctx) {
  // The host path namespace only matches the host platform: a bash/posix dialect on a
  // Windows host resolves in a different namespace, so it stays unprobed.
  if ((operation.context?.platform ?? ctx.platform) !== ctx.platform) {
    noteUnknown(state, 'domain-platform-mismatch')
    return
  }
  const cwd = absoluteCwd(operation.context?.cwd)
  const target = operation.target ?? { kind: 'unknown', reason: 'missing-target' }
  switch (target.kind) {
    case 'exact': return observeExactPaths(state, operation, target.paths, cwd, ctx)
    case 'subtree': return observeSubtree(state, operation, target.root, target.maxDepth, cwd, ctx)
    case 'pattern':
      // A pattern has a known base but was NOT enumerated by the analysis; enumerating it
      // here would claim a scope the analysis did not prove. The policy confirms with the
      // known base as the explainable range (R-09).
      ctx.noteProtected(target.base, operation.action)
      noteUnknown(state, 'pattern-unenumerated')
      return
    case 'unknown':
      noteUnknown(state, target.reason ?? 'target-unknown')
      return
    default:
      noteUnknown(state, 'unknown-target-shape')
  }
}

async function observeExactPaths(state, operation, rawPaths, cwd, ctx) {
  const paths = (Array.isArray(rawPaths) ? rawPaths : []).filter((value) => typeof value === 'string' && value !== '')
  if (paths.length === 0) { noteUnknown(state, 'empty-exact-target'); return }
  if (paths.length > 1024) { noteFailure(state, 'exact-target-budget'); return }
  for (const raw of paths) {
    ctx.noteProtected(raw, operation.action)
    if (!ctx.consume() || pastDeadline(ctx)) { noteFailure(state, 'budget'); return }
    const absolute = resolveLocal(raw, cwd)
    if (!absolute) { noteUnknown(state, 'cwd-unresolved'); continue }
    await observeEntry(state, operation, absolute, ctx, { isRoot: true })
  }
}

/** Observe one literal entry (top-level target). Deeper traversal lives in walkDirectory. */
async function observeEntry(state, operation, absolute, ctx, { isRoot = false } = {}) {
  let info
  try {
    info = await fs.lstat(absolute)
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return // known zero: nothing to count
    ctx.noteIssue({ kind: 'inventory-failed', reason: error.code ?? error.name, path: absolute })
    noteFailure(state, 'entry-unreadable')
    return
  }
  if (isRoot) await recordRealPath(state, absolute, ctx, info.isSymbolicLink())
  if (info.isSymbolicLink()) return countLink(state, absolute, operation.action, ctx)
  if (info.isFile()) return countFile(state, absolute, operation.action, ctx)
  if (info.isDirectory()) {
    if (operation.recursive !== true) {
      // A non-recursive directory delete removes the single entry (empty-dir semantics);
      // the entry is listed, not counted (directories are never part of the count).
      addDirectory(state, absolute)
      if (operation.recursive === 'unknown') noteUnknown(state, 'recursion-unproven')
      return
    }
    return observeSubtree(state, operation, absolute, undefined, null, ctx)
  }
  ctx.noteIssue({ kind: 'ambiguous-entry', reason: 'special-entry', path: absolute })
  noteFailure(state, 'ambiguous-entry')
}

async function observeSubtree(state, operation, rawRoot, maxDepthOption, cwd, ctx) {
  const root = resolveLocal(rawRoot, cwd)
  if (!root) { noteUnknown(state, 'unresolvable-target'); return }
  const maxDepth = Number.isInteger(maxDepthOption) && maxDepthOption >= 0 ? maxDepthOption : ctx.limits.maxDepth
  let info
  try {
    info = await fs.lstat(root)
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return // known zero
    ctx.noteIssue({ kind: 'inventory-failed', reason: error.code ?? error.name, path: root })
    noteFailure(state, 'entry-unreadable')
    return
  }
  ctx.noteProtected(root, operation.action)
  if (info.isSymbolicLink()) {
    // Removing the root link entry removes the link, not the tree behind it (POSIX rm -r).
    await recordRealPath(state, root, ctx, true)
    return countLink(state, root, operation.action, ctx)
  }
  if (info.isFile()) {
    await recordRealPath(state, root, ctx, false)
    return countFile(state, root, operation.action, ctx)
  }
  if (!info.isDirectory()) {
    ctx.noteIssue({ kind: 'ambiguous-entry', reason: 'special-entry', path: root })
    noteFailure(state, 'ambiguous-entry')
    return
  }
  await recordRealPath(state, root, ctx, false)
  state.roots.push(root)
  await walkDirectory(state, operation, root, info.dev, maxDepth, 0, ctx)
}

async function recordRealPath(state, absolute, ctx, isLink) {
  const key = path.normalize(absolute)
  let real = null
  if (!isLink) {
    try { real = await fs.realpath(absolute) } catch { real = null }
  }
  // A link entry is stored as null: the identity pass must never resolve THROUGH it.
  state.realPaths.set(key, real)
}

async function walkDirectory(state, operation, absolute, rootDev, maxDepth, depth, ctx) {
  if (ctx.signal?.aborted) throw ctx.signal.reason ?? new Error('guardrails: evidence cancelled')
  if (pastDeadline(ctx) || !ctx.consume()) { noteFailure(state, 'budget'); return }
  let real = absolute
  try { real = await fs.realpath(absolute) } catch { /* keep lexical */ }
  const visitedKey = path.normalize(real)
  if (state.visited.has(visitedKey)) return
  state.visited.add(visitedKey)
  addDirectory(state, absolute)
  // Per-directory observation record for the directory-level rebuildable evidence: the
  // record lists this directory's direct children and stays `complete` only when the
  // whole subtree enumeration below finished without any failure, budget stop or cap.
  const key = path.normalize(absolute)
  const record = state.dirTree.get(key) ?? { key, path: absolute, complete: true, files: [], links: [], dirs: [] }
  state.dirTree.set(key, record)
  const markIncomplete = () => { record.complete = false }
  if (depth >= maxDepth) {
    // Deeper entries are unobserved: their existence cannot be claimed either way.
    noteUnknown(state, 'depth-capped')
    markIncomplete()
    return
  }
  let directory
  try {
    directory = await fs.opendir(absolute)
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') { markIncomplete(); return }
    ctx.noteIssue({ kind: 'inventory-failed', reason: error.code ?? error.name, path: absolute })
    noteFailure(state, 'entry-unreadable')
    markIncomplete()
    return
  }
  try {
    for await (const entry of directory) {
      if (ctx.signal?.aborted) throw ctx.signal.reason ?? new Error('guardrails: evidence cancelled')
      if (pastDeadline(ctx) || !ctx.consume()) { noteFailure(state, 'budget'); markIncomplete(); return }
      const child = path.join(absolute, entry.name)
      if (!isWellFormedName(entry.name)) {
        // The mangled name cannot address the real entry (lstat would ENOENT), so the
        // removed set is not fully representable: mark unknown instead of under-counting.
        ctx.noteIssue({ kind: 'ambiguous-entry', reason: 'unrepresentable-name', path: child })
        noteFailure(state, 'unrepresentable-name')
        markIncomplete()
        return
      }
      // Git metadata inside the walked tree (worktree pointer or inner repo): its common-dir
      // body is never ordinary counted entries. Flag it and leave the inventory unproven
      // rather than silently skipping contents (under-count) or counting metadata as files.
      if (ctx.windows ? entry.name.toLowerCase() === '.git' : entry.name === '.git') {
        ctx.noteIssue({ kind: 'git-metadata-inside-tree', reason: 'git metadata inside the traversal tree', path: child })
        noteFailure(state, 'git-metadata-inside-tree')
        markIncomplete()
        return
      }
      let info
      try {
        info = await fs.lstat(child)
      } catch (error) {
        if (error.code === 'ENOENT' || error.code === 'ENOTDIR') { markIncomplete(); continue } // raced away
        ctx.noteIssue({ kind: 'inventory-failed', reason: error.code ?? error.name, path: child })
        noteFailure(state, 'entry-unreadable')
        markIncomplete()
        return
      }
      if (info.isSymbolicLink()) {
        // Links are never exempt and disqualify the containing directory.
        record.links.push(child)
        countLink(state, child, operation.action, ctx)
        continue
      }
      if (info.isFile()) {
        record.files.push(child)
        await countFile(state, child, operation.action, ctx)
        continue
      }
      if (info.isDirectory()) {
        // Same-device st_dev guard plus the Linux mount snapshot (which also catches
        // same-device bind mounts). A crossing makes the traversal set unprovable.
        if (info.dev !== rootDev) {
          ctx.noteIssue({ kind: 'mount-boundary', reason: 'cross-device-child', path: child })
          noteFailure(state, 'mount-crossing')
          markIncomplete()
          return
        }
        const verdict = await ctx.mount.check(child, ctx.workspaceRoot ?? undefined)
        if (verdict.safe !== true) {
          ctx.noteIssue({ kind: 'mount-boundary', reason: verdict.reason, path: child })
          noteFailure(state, 'mount-crossing')
          markIncomplete()
          return
        }
        record.dirs.push(path.normalize(child))
        await walkDirectory(state, operation, child, rootDev, maxDepth, depth + 1, ctx)
        continue
      }
      // Sockets, FIFOs, devices and other special entries cannot be proven safe to count.
      ctx.noteIssue({ kind: 'ambiguous-entry', reason: 'special-entry', path: child })
      noteFailure(state, 'ambiguous-entry')
      markIncomplete()
      return
    }
  } finally {
    // The async iterator closes the handle on completion/break/return; close defensively
    // only when it did not (a double close throws and is ignored here).
    try { await directory.close() } catch { /* already closed by the iterator */ }
  }
}

function addDirectory(state, absolute) {
  const key = path.normalize(absolute)
  if (state.dirsSeen.has(key)) return
  state.dirsSeen.add(key)
  state.directories.push(absolute)
}

function countLink(state, absolute, action, ctx) {
  const key = path.normalize(absolute)
  ctx.noteProtected(absolute, action)
  if (state.stoppedAtThreshold || state.seen.has(key)) return
  state.seen.add(key)
  state.links.push(absolute)
  state.counted += 1
  if (state.counted >= ctx.limits.threshold) state.stoppedAtThreshold = true
}

async function countFile(state, absolute, action, ctx) {
  const key = path.normalize(absolute)
  ctx.noteProtected(absolute, action)
  if (state.stoppedAtThreshold || state.seen.has(key)) return
  state.seen.add(key)
  // R-14 (批量删除白名单): a shape match is a CANDIDATE, never an exemption. Only the
  // ownership/regeneration evidence adapter may conclude `established`; anything unproven
  // (no trusted boundary, missing evidence, budget) stays COUNTED — the safe direction.
  const outcome = await evaluateExemption(state, absolute, ctx)
  if (outcome) {
    state.exemptions.push(outcome)
    state.exemptPaths.add(key)
    return // established: does not count toward the threshold
  }
  state.files.push(absolute)
  state.counted += 1
  if (state.counted >= ctx.limits.threshold) state.stoppedAtThreshold = true
}

const MAX_ROOT_DEPTH = 64

/** Locate the enclosing project root by fixed marker basenames (bounded climb, cached). */
async function projectRootFor(state, filePath, ctx) {
  if (ctx.markers.size === 0) return null
  const boundary = ctx.workspaceRoot
  // A target outside the trusted boundary never receives an exemption: both the marker
  // climb and the evidence stay confined to the boundary.
  if (boundary && !withinExact(boundary, filePath)) return null
  const startDir = path.dirname(filePath)
  if (ctx.rootCache.has(startDir)) return ctx.rootCache.get(startDir)
  const markerNames = [...ctx.markers]
  let dir = startDir
  for (let depth = 0; depth < MAX_ROOT_DEPTH; depth += 1) {
    if (ctx.rootCache.has(dir)) {
      const cached = ctx.rootCache.get(dir)
      ctx.rootCache.set(startDir, cached)
      return cached
    }
    if (!ctx.consume() || pastDeadline(ctx)) { noteFailure(state, 'budget'); return null }
    const present = []
    for (const name of markerNames) {
      try {
        if ((await fs.lstat(path.join(dir, name))).isFile()) present.push(name)
      } catch { /* absent marker is not a root */ }
    }
    if (present.length > 0) {
      const result = { root: dir, markers: present }
      ctx.rootCache.set(dir, result)
      ctx.rootCache.set(startDir, result)
      return result
    }
    const parent = path.dirname(dir)
    if (parent === dir) break
    // A project root must lie strictly inside the boundary; an outer marker above it
    // cannot capture this file.
    if (boundary && !withinExact(boundary, parent)) break
    dir = parent
  }
  ctx.rootCache.set(startDir, null)
  return null
}

/**
 * Rebuildable evaluation for one file. Returns the exemption record only when ownership
 * AND regeneration evidence both hold (`established`); a shape match without full
 * evidence is recorded as `unproven` and still counted by the caller. Directory-level
 * exemption evidence is not implemented in this slice: directories are listed, not
 * counted, and get no exemption records.
 */
async function evaluateExemption(state, absolute, ctx) {
  if (!ctx.classify) return null
  const root = await projectRootFor(state, absolute, ctx)
  if (!root) return null
  const relative = path.relative(root.root, absolute).split(path.sep).join('/')
  let shape = null
  try {
    shape = ctx.classify({ relativePath: relative, projectMarkers: root.markers, isDirectory: false })
  } catch { shape = null }
  if (!shape || shape.disposable !== true) return null
  const record = { path: absolute, kind: 'file', ruleId: shape.ruleId, conclusion: 'unproven' }
  if (!ctx.evidence) {
    record.reason = 'no-evidence-adapter'
    state.exemptions.push(record)
    return null
  }
  try {
    const verdict = await ctx.evidence.verify({ absolute, projectRoot: root.root, projectMarkers: root.markers, ruleId: shape.ruleId })
    if (verdict?.eligible === true) return { ...record, conclusion: 'established' }
    record.reason = verdict?.reason ?? 'evidence-unproven'
  } catch (error) {
    // verify() returns eligible:false for runtime ambiguities itself; a throw is a real
    // fault and is surfaced as a stage issue, never converted into an exemption.
    ctx.noteIssue({ kind: 'exemption-evidence-failed', reason: error?.message ?? String(error), path: absolute })
    record.reason = 'evidence-error'
  }
  state.exemptions.push(record)
  return null
}

// --- fs domain (DSH managed file service) ----------------------------------

/**
 * DSH managed file-service targets are opaque host-side: identity and rebuildability
 * probes are NOT shared across domains, so only the fs provider answers here and no host
 * path (lstat/realpath/git) is ever touched. Per the Inspect `fs` contract:
 * - `resolve(raw, {cwd, signal})` → FsTarget for EVERY content path (read/write included,
 *   because a protected alias may only be canonical after resolution);
 * - `displayPath` names the target in scope lists and protected matching;
 * - `stat(target, signal)` gives the version or absence for the approval recheck;
 * - `targetKey` is opaque. Aliases dedupe by key without treating it as a path.
 */
async function observeFsOperation(state, operation, ctx) {
  const provider = ctx.fsProvider
  if (!provider || typeof provider.resolve !== 'function' || typeof provider.stat !== 'function') {
    ctx.noteIssue({ kind: 'fs-provider-missing', reason: 'fs domain requires fsProvider.resolve and fsProvider.stat (Inspect fs contract)' })
    noteFailure(state, 'fs-provider-missing')
    return
  }
  const target = operation.target ?? { kind: 'unknown', reason: 'missing-target' }
  const counting = DESTRUCTIVE.has(operation.action) && operation.preview !== true
  if (target.kind !== 'exact') {
    // Pattern/subtree targets cannot be enumerated through resolve+stat alone.
    noteUnknown(state, target.kind === 'unknown' ? (target.reason ?? 'target-unknown') : 'fs-enumeration-unsupported')
    await protectFsScope(state, operation, ctx, target)
    return
  }
  const rawPaths = (Array.isArray(target.paths) ? target.paths : []).filter((value) => typeof value === 'string' && value !== '')
  if (rawPaths.length === 0) { noteUnknown(state, 'empty-exact-target'); return }
  for (const raw of rawPaths.slice(0, 1024)) {
    if (!ctx.consume() || pastDeadline(ctx)) { noteFailure(state, 'budget'); return }
    let resolved
    try {
      resolved = await provider.resolve(raw, { cwd: operation.context?.cwd, signal: ctx.signal })
    } catch (error) {
      ctx.noteIssue({ kind: 'inventory-failed', reason: error?.code ?? error?.name ?? String(error), path: raw })
      noteFailure(state, 'entry-unreadable')
      continue
    }
    // Protection matching uses the resolved display path: the alias may be canonical here.
    const displayPath = displayPathOf(provider, resolved, raw)
    const stableKey = stableKeyOf(resolved)
    if (!stableKey) {
      ctx.noteIssue({ kind: 'invalid-fs-target', reason: 'file provider returned no target identity', path: displayPath })
      noteFailure(state, 'invalid-fs-target')
      continue
    }
    const protectedPath = ctx.noteProtected(displayPath, operation.action)
    if (!counting && !protectedPath) continue
    let info
    try {
      info = await provider.stat(resolved, ctx.signal)
    } catch (error) {
      ctx.noteIssue({ kind: 'inventory-failed', reason: error?.code ?? error?.name ?? String(error), path: displayPath })
      noteFailure(state, 'entry-unreadable')
      continue
    }
    state.fsIdentities.push({ key: stableKey, version: fsVersionOf(info) })
    if (!counting || info === undefined || info === null) continue
    const kind = normalizeFsInfo(info)
    if (kind === 'other') {
      ctx.noteIssue({ kind: 'ambiguous-entry', reason: 'unknown-stat-shape', path: displayPath })
      noteFailure(state, 'ambiguous-entry')
      continue
    }
    // Two spellings of one target contribute a single deletion entry.
    if (state.seenKeys.has(stableKey)) continue
    state.seenKeys.add(stableKey)
    if (kind === 'link') state.links.push(displayPath)
    else if (kind === 'file') state.files.push(displayPath)
    else {
      state.directories.push(displayPath)
      if (operation.recursive === true) noteUnknown(state, 'fs-subtree-unenumerable')
    }
    if (kind !== 'directory') {
      // No rebuildable evidence is provable host-side for an opaque fs target: it counts.
      state.counted += 1
    }
    if (state.counted >= ctx.limits.threshold) state.stoppedAtThreshold = true
  }
}

/** Protection scan for fs-domain pattern/subtree scopes through the resolved display path. */
async function protectFsScope(state, operation, ctx, target) {
  const provider = ctx.fsProvider
  const raw = target.kind === 'subtree' ? target.root : target.kind === 'pattern' ? target.base : null
  if (typeof raw !== 'string' || raw === '') return
  try {
    const resolved = await provider.resolve(raw, { cwd: operation.context?.cwd, signal: ctx.signal })
    ctx.noteProtected(displayPathOf(provider, resolved, raw), operation.action)
  } catch { /* the unknown reason above already covers the unprovable scope */ }
}

function displayPathOf(provider, target, raw) {
  if (target && typeof target === 'object' && typeof target.displayPath === 'string' && target.displayPath !== '') return target.displayPath
  try {
    const shown = provider.processPath?.(target)
    if (typeof shown === 'string' && shown !== '') return shown
  } catch { /* fall through to the raw spelling */ }
  return raw
}

function stableKeyOf(target) {
  return typeof target?.targetKey === 'string' && target.targetKey !== '' ? target.targetKey : undefined
}

function fsVersionOf(info) {
  return info && typeof info === 'object' && info.version !== undefined ? String(info.version) : null
}

function normalizeFsInfo(info) {
  return info.type === 'file' || info.type === 'directory' ? info.type : 'other'
}

// --- git operations ---------------------------------------------------------

function detailArgs(operation) {
  return Array.isArray(operation.details?.args) ? operation.details.args : []
}

/** Paths for `git restore`: only pathspecs after an explicit `--` are provable. */
function restorePathsFromDetails(operation) {
  const args = detailArgs(operation)
  const marker = args.indexOf('--')
  if (marker < 0) return null // operands may include a tree-ish; scope cannot be proven
  return args.slice(marker + 1).filter((value) => typeof value === 'string' && value !== '')
}

/** First non-option operand after the `remove` token of `git worktree remove`. */
function worktreeTargetFromDetails(operation) {
  const args = detailArgs(operation)
  const marker = args.indexOf('remove')
  if (marker < 0) return null
  const rest = args.slice(marker + 1)
  const separator = rest.indexOf('--')
  const operands = separator >= 0
    ? rest.slice(separator + 1)
    : rest.filter((value) => typeof value === 'string' && !String(value).startsWith('-'))
  return operands.find((value) => typeof value === 'string' && value !== '') ?? null
}

/** `git rebase|merge|cherry-pick|revert|am --abort` reaches the evidence layer as
 * `details.command: '<subcommand>-abort'` (DSR-031 决定 8). Nothing else is probed. */
function abortCommandOf(operation) {
  if (operation.action !== 'git-restore') return null
  const command = operation.details?.command
  return typeof command === 'string' && command.endsWith('-abort') ? command : null
}

/** Append a displayable range to the EXISTING `knownScope` channel of the operation
 * target. The facts contract already supplies a per-subcommand `knownScope` (an
 * unknown target without one would be judged unscoped and denied); this only adds the
 * probe's own finding (the in-progress marker set / an unverified reason) so the
 * confirmation block names what the read-only probe actually saw. */
function noteAbortScope(operation, text) {
  const target = operation.target
  if (!target || typeof target !== 'object' || target.kind !== 'unknown') return
  const list = Array.isArray(target.knownScope) ? target.knownScope : (target.knownScope = [])
  if (!list.includes(text)) list.push(text)
}

async function observeGitOperation(state, operation, ctx) {
  if ((operation.context?.domain ?? 'unknown') !== 'host') { noteUnknown(state, 'domain-unprobed'); return }
  const action = operation.action
  const abortCommand = abortCommandOf(operation)
  const cwd = absoluteCwd(operation.context?.cwd)
  if (!cwd) {
    if (abortCommand) {
      // D1: an abort whose cwd is unresolved must stay a deliberate unknown (the policy
      // confirms with the stated range) — never a stage issue or a check failure.
      noteUnknown(state, 'git-abort-unprobed')
      noteAbortScope(operation, `${abortCommand} --abort: working tree of the analyzed call (working directory unresolved; abort state unverified)`)
      return
    }
    ctx.noteIssue({ kind: 'git-evidence', reason: 'git-cwd-unresolved' })
    noteFailure(state, 'git-cwd-unresolved')
    return
  }
  if (action === 'git-clean') {
    const ignored = detailArgs(operation).includes('-x')
    const proof = await proveClean({ cwd, ignored, deadlineAt: ctx.deadlineAt, signal: ctx.signal, run: ctx.gitRun })
    if (proof.state !== 'known') {
      ctx.noteIssue({ kind: 'git-evidence', reason: proof.reason })
      noteFailure(state, proof.reason)
      return
    }
    for (const entry of proof.entries) {
      const absolute = path.resolve(cwd, entry.path)
      ctx.noteProtected(absolute, action)
      if (entry.isDirectory) addDirectory(state, absolute) // clean -d removes untracked dirs
      else await countFile(state, absolute, action, ctx)
    }
    return
  }
  if (action === 'git-restore') {
    if (abortCommand) return observeAbortProbe(state, operation, ctx, cwd, abortCommand)
    const command = operation.details?.command
    const paths = restorePathsFromDetails(operation)
    if (command !== 'restore' && command !== 'checkout') {
      // branch -D / tag -d / forced switch / reset --merge (F-13..F-18): the scope is
      // a ref or the working-tree state named in the operation's knownScope. No host
      // probe can prove a pathset here, so record a DELIBERATE unknown — no probe, no
      // issue — so the policy confirms with the listed scope instead of failing the
      // check (D1: evidence inability must not become check-failed).
      noteUnknown(state, 'git-ref-or-state-scope')
      return
    }
    if (paths === null) {
      ctx.noteIssue({ kind: 'git-evidence', reason: 'restore-scope-ambiguous' })
      noteFailure(state, 'restore-scope-ambiguous')
      return
    }
    const proof = await proveRestore({ cwd, paths, deadlineAt: ctx.deadlineAt, signal: ctx.signal, run: ctx.gitRun })
    if (proof.state !== 'known') {
      ctx.noteIssue({ kind: 'git-evidence', reason: proof.reason })
      noteFailure(state, proof.reason)
      return
    }
    for (const value of proof.paths) {
      const absolute = path.isAbsolute(value) ? path.normalize(value) : path.resolve(cwd, value)
      ctx.noteProtected(absolute, action)
      await countFile(state, absolute, action, ctx)
    }
    return
  }
  // git-worktree-remove: the affected set comes from the decision module, never from a
  // filesystem walk. A proven-clean worktree removes tracked entries that remain
  // recoverable from the repository, so the inventory carries the root and hands the
  // verdict (clean/deny + bounded ignored count) to the policy through gitRisk.
  const targetPath = worktreeTargetFromDetails(operation)
  if (!targetPath) {
    ctx.noteIssue({ kind: 'git-evidence', reason: 'worktree-path-missing' })
    noteFailure(state, 'worktree-path-missing')
    return
  }
  const absolute = path.resolve(cwd, targetPath)
  ctx.noteProtected(absolute, action)
  const verdict = await proveWorktreeRemove({ cwd, path: targetPath, deadlineAt: ctx.deadlineAt, run: ctx.gitRun })
  if (verdict.kind === 'unknown') {
    ctx.noteIssue({ kind: 'git-evidence', reason: verdict.reason ?? 'git-unknown' })
    noteFailure(state, verdict.reason ?? 'git-unknown')
    return
  }
  if (verdict.kind === 'deny') {
    ctx.noteGitRisk([absolute], verdict.reason)
    return
  }
  state.roots.push(absolute)
}

/**
 * `git rebase|merge|cherry-pick|revert|am --abort` (DSR-031 决定 8). Confirm ONLY when a
 * read-only probe proves an in-progress operation; a proven-absent state records nothing so
 * the decision's `git-evidence` exception allows the call (D4). A probe that cannot
 * conclude records a deliberate unknown with the unverified range — never a stage issue
 * and never an inventory failure, so it can never become `execution.check-failed` (D1).
 */
async function observeAbortProbe(state, operation, ctx, cwd, abortCommand) {
  const proof = await proveAbortState({
    cwd,
    deadlineAt: ctx.deadlineAt,
    signal: ctx.signal,
    run: ctx.gitRun,
    consume: ctx.consume,
  })
  if (proof.state !== 'known') {
    noteUnknown(state, 'git-abort-unprobed')
    noteAbortScope(operation, `${abortCommand} --abort: working tree at ${cwd} (abort state unverified: ${proof.reason})`)
    return
  }
  if (proof.inProgress !== true) return
  noteUnknown(state, 'git-abort-in-progress')
  noteAbortScope(operation, `${abortCommand} --abort: working tree at ${cwd} (in-progress state: ${proof.markers.join(', ')}; uncommitted changes would be discarded)`)
}
