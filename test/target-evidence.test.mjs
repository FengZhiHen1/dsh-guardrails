// Synthetic-fixture tests for the target evidence adapter (src/adapter/evidence).
//
// Every destructive case runs against an isolated fixture directory created fresh in the
// OS temp dir (and removed afterwards): no real user path, no real repository and no
// dangerous input is ever dispatched. Git probes are injected (`gitRun`) so no child git
// process runs in the git-cases; the rebuildable-exemption case uses the real read-only
// evidence adapter because its verdict IS the behavior under test.
//
// The pure identity matcher is exercised directly so the system-tree logic is testable
// on any host; the Windows system-tree identity case is skipped on other hosts instead
// of assuming an environment that cannot exist there.

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { collectEvidence } from '../src/adapter/evidence/index.js'
import { matchSystemTree, RULES } from '../src/adapter/evidence/identity.js'

/** Create an isolated fixture directory; every entry is created by this task. */
async function makeFixture(t, { files = [], dirs = [] } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'guardrails-evidence-'))
  t.after(() => fs.rm(root, { recursive: true, force: true }))
  for (const rel of dirs) await fs.mkdir(path.join(root, rel), { recursive: true })
  for (const rel of files) {
    await fs.mkdir(path.dirname(path.join(root, rel)), { recursive: true })
    await fs.writeFile(path.join(root, rel), 'fixture')
  }
  return root
}

const hostContext = (cwd) => ({ domain: 'host', cwd, platform: process.platform })
const analysisWith = (operations, extra = {}) => ({ status: 'complete', operations, candidates: [], gaps: [], ...extra })
const deleteOp = (target, context, extra = {}) => ({
  action: 'delete', target, context, condition: 'certain', recursive: false, preview: false, ...extra,
})

// --- inventory: exact targets -------------------------------------------------

test('an exact regular-file delete inventories one counted file', async (t) => {
  const root = await makeFixture(t, { files: ['a.txt', 'keep.txt'] })
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: ['a.txt'] }, hostContext(root)),
  ]), { isProtectedPath: () => false })
  assert.equal(evidence.analysisStatus, 'complete')
  assert.equal(evidence.inventory.kind, 'exact')
  assert.equal(evidence.inventory.count, 1)
  assert.deepEqual(evidence.inventory.files, [path.join(root, 'a.txt')])
  assert.deepEqual(evidence.inventory.links, [])
  assert.deepEqual(evidence.inventory.directories, [])
  assert.deepEqual(evidence.inventory.unknown, [])
  assert.deepEqual(evidence.identities, [])
  assert.deepEqual(evidence.protectedHits, [])
  assert.deepEqual(evidence.exemptions, [])
  assert.deepEqual(evidence.issues, [])
})

test('a missing exact target is a known zero, not an unknown', async (t) => {
  const root = await makeFixture(t, {})
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: ['absent.txt'] }, hostContext(root)),
  ]), { isProtectedPath: () => false })
  assert.equal(evidence.inventory.kind, 'exact')
  assert.equal(evidence.inventory.count, 0)
})

test('a relative target without a resolvable cwd keeps a deliberate unknown', async (t) => {
  const root = await makeFixture(t, { files: ['a.txt'] })
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: ['a.txt'] }, { domain: 'host', platform: process.platform }),
  ]), { isProtectedPath: () => false })
  // Deliberate unknown: the observed count stays valid; the policy confirms dynamically.
  assert.equal(evidence.inventory.kind, 'exact')
  assert.ok(evidence.inventory.unknown.includes('cwd-unresolved'))
})

// --- inventory: trees, dedupe, fingerprints -----------------------------------

test('equal-count different trees produce different fingerprints', async (t) => {
  const treeA = await makeFixture(t, { files: ['a.txt', 'b.txt'] })
  const treeB = await makeFixture(t, { files: ['c.txt', 'd.txt'] })
  const evidenceA = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: [treeA] }, hostContext(treeA), { recursive: true }),
  ]), { isProtectedPath: () => false })
  const evidenceB = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: [treeB] }, hostContext(treeB), { recursive: true }),
  ]), { isProtectedPath: () => false })
  assert.equal(evidenceA.inventory.kind, 'exact')
  assert.equal(evidenceA.inventory.count, 2)
  assert.equal(evidenceB.inventory.count, 2)
  assert.notEqual(evidenceA.inventory.fingerprint, evidenceB.inventory.fingerprint)
  assert.ok(evidenceA.inventory.directories.includes(treeA))
})

test('precise counting stops at the threshold and reports a lower bound', async (t) => {
  const root = await makeFixture(t, { files: Array.from({ length: 25 }, (unused, index) => `f${String(index).padStart(2, '0')}.txt`) })
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: [root] }, hostContext(root), { recursive: true }),
  ]), { isProtectedPath: () => false })
  assert.equal(evidence.inventory.kind, 'lower-bound')
  assert.equal(evidence.inventory.count, 21)
  assert.equal(evidence.inventory.files.length, 21)
})

test('a pattern target stays unenumerated as a deliberate unknown', async (t) => {
  const root = await makeFixture(t, { files: ['a.log'] })
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'pattern', base: root, pattern: '*.log', dialect: 'posix' }, hostContext(root)),
  ]), { isProtectedPath: () => false })
  // The observed count (zero here) stays exact; the policy confirms the dynamic remainder.
  assert.equal(evidence.inventory.kind, 'exact')
  assert.ok(evidence.inventory.unknown.includes('pattern-unenumerated'))
  assert.equal(evidence.inventory.count, 0)
})

test('an unknown target keeps its analysis reason in the inventory', async (t) => {
  const root = await makeFixture(t, {})
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'unknown', reason: 'unresolved-target', knownScope: [root] }, hostContext(root)),
  ]), { isProtectedPath: () => false })
  assert.equal(evidence.inventory.kind, 'exact')
  assert.ok(evidence.inventory.unknown.includes('unresolved-target'))
  assert.deepEqual(evidence.inventory.roots, [])
})

test('git metadata inside a walked tree makes the inventory unproven', async (t) => {
  const root = await makeFixture(t, { files: ['keep.txt'], dirs: ['out/.git/objects'] })
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: [path.join(root, 'out')] }, hostContext(root), { recursive: true }),
  ]), { isProtectedPath: () => false })
  assert.equal(evidence.inventory.kind, 'unreliable')
  assert.ok(evidence.inventory.unknown.includes('git-metadata-inside-tree'))
  assert.ok(evidence.issues.some((issue) => issue.kind === 'git-metadata-inside-tree' && issue.path.endsWith(path.join('out', '.git'))))
})

test('a preview operation removes nothing and is not counted', async (t) => {
  const root = await makeFixture(t, { files: ['a.txt', 'b.txt'] })
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: [root] }, hostContext(root), { recursive: true, preview: true }),
  ]), { isProtectedPath: () => false })
  assert.equal(evidence.inventory.kind, 'exact')
  assert.equal(evidence.inventory.count, 0)
  assert.deepEqual(evidence.inventory.files, [])
})

test('a preceding non-preview write invalidates a later delete inventory', async (t) => {
  const root = await makeFixture(t, { files: ['a.txt'] })
  const evidence = await collectEvidence(analysisWith([
    { action: 'write-content', target: { kind: 'exact', paths: ['gen.txt'] }, context: hostContext(root), condition: 'certain', recursive: false, preview: false },
    deleteOp({ kind: 'exact', paths: [root] }, hostContext(root), { recursive: true }),
  ]), { isProtectedPath: () => false })
  // The later delete's set was observed before the write can execute; an unchanged count
  // must never read as authorization.
  assert.equal(evidence.inventory.kind, 'exact')
  assert.ok(evidence.inventory.unknown.includes('preceding-mutation'))
  assert.ok(evidence.issues.some((issue) => issue.kind === 'invalidated-inventory' && issue.path === root))
})

test('a preceding write outside the delete scope does not invalidate it', async (t) => {
  const root = await makeFixture(t, { files: ['a/keep.txt'] })
  const evidence = await collectEvidence(analysisWith([
    { action: 'write-content', target: { kind: 'exact', paths: ['other/gen.txt'] }, context: hostContext(root), condition: 'certain', recursive: false, preview: false },
    deleteOp({ kind: 'subtree', root: 'a' }, hostContext(root), { recursive: true }),
  ]), { isProtectedPath: () => false })
  assert.equal(evidence.inventory.kind, 'exact')
  assert.deepEqual(evidence.inventory.unknown, [])
  assert.deepEqual(evidence.issues.filter((issue) => issue.kind === 'invalidated-inventory'), [])
  assert.equal(evidence.inventory.count, 1)
})

test('an unresolvable write scope fails closed against a later delete', async (t) => {
  const root = await makeFixture(t, { files: ['a/keep.txt'] })
  const evidence = await collectEvidence(analysisWith([
    { action: 'write-content', target: { kind: 'unknown', reason: 'unresolved-target' }, context: hostContext(root), condition: 'certain', recursive: false, preview: false },
    deleteOp({ kind: 'subtree', root: 'a' }, hostContext(root), { recursive: true }),
  ]), { isProtectedPath: () => false })
  assert.ok(evidence.inventory.unknown.includes('preceding-mutation'))
  assert.ok(evidence.issues.some((issue) => issue.kind === 'invalidated-inventory'))
})

test('a preview write does not invalidate a later delete inventory', async (t) => {
  const root = await makeFixture(t, { files: ['a.txt'] })
  const evidence = await collectEvidence(analysisWith([
    { action: 'write-content', target: { kind: 'exact', paths: ['gen.txt'] }, context: hostContext(root), condition: 'certain', recursive: false, preview: true },
    deleteOp({ kind: 'exact', paths: ['a.txt'] }, hostContext(root)),
  ]), { isProtectedPath: () => false })
  assert.equal(evidence.inventory.kind, 'exact')
  assert.equal(evidence.inventory.count, 1)
})

// --- protected hits ------------------------------------------------------------

test('protected matching is injected and reports path plus action', async (t) => {
  const root = await makeFixture(t, { files: ['secret.env', 'plain.txt'] })
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: [root] }, hostContext(root), { recursive: true }),
    { action: 'read-content', target: { kind: 'exact', paths: [path.join(root, 'secret.env')] }, context: hostContext(root), condition: 'certain', recursive: false, preview: false },
  ]), { policy: { sensitiveFiles: [path.join(root, 'secret.env')] }, isProtectedPath: (value, policy, platform) => platform === process.platform && (policy.sensitiveFiles ?? []).includes(value) })
  assert.ok(evidence.protectedHits.some((hit) => hit.path === path.join(root, 'secret.env') && hit.action === 'delete'))
  assert.ok(evidence.protectedHits.some((hit) => hit.path === path.join(root, 'secret.env') && hit.action === 'read-content'))
  assert.equal(evidence.inventory.count, 2)
})

test('a missing protected matcher is an explicit stage issue', async (t) => {
  const root = await makeFixture(t, { files: ['a.txt'] })
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: ['a.txt'] }, hostContext(root)),
  ]), {})
  assert.ok(evidence.issues.some((issue) => issue.kind === 'protected-matcher-missing'))
  assert.deepEqual(evidence.protectedHits, [])
})

// --- rebuildable exemptions (real read-only evidence adapter) -------------------

async function makePythonProject(t) {
  return makeFixture(t, {
    files: ['pyproject.toml', 'app.py', '__pycache__/app.cpython-312.pyc'],
  })
}

test('a proven rebuildable artifact is exempt from the count', async (t) => {
  const root = await makePythonProject(t)
  // Exact named artifact: the file-level record stays visible (a fully proven enclosing
  // directory would coalesce it into a directory record instead).
  const pyc = path.join(root, '__pycache__', 'app.cpython-312.pyc')
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: [pyc] }, hostContext(root)),
  ]), { workspaceRoot: root, isProtectedPath: () => false })
  const established = evidence.exemptions.filter((entry) => entry.path === pyc)
  assert.equal(established.length, 1)
  assert.equal(established[0].conclusion, 'established')
  assert.equal(established[0].kind, 'file')
  assert.equal(established[0].ruleId, 'py-pyc-file')
  assert.equal(evidence.inventory.count, 0) // the proven artifact does not count
  assert.equal(evidence.inventory.kind, 'exact')
})

test('a shape match without a trusted boundary stays counted and unproven', async (t) => {
  const root = await makePythonProject(t)
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: [root] }, hostContext(root), { recursive: true }),
  ]), { isProtectedPath: () => false })
  const pyc = path.join(root, '__pycache__', 'app.cpython-312.pyc')
  const unproven = evidence.exemptions.filter((entry) => entry.path === pyc)
  assert.equal(unproven.length, 1)
  assert.equal(unproven[0].conclusion, 'unproven')
  assert.equal(unproven[0].ruleId, 'py-pyc-file')
  assert.equal(evidence.inventory.count, 3) // shape alone never reduces the count
})

// --- directory-level rebuildable evidence (R-14, 批量删除白名单「目录级」) ---------

test('a directory of fully proven rebuildable leaves is exempt once', async (t) => {
  const root = await makeFixture(t, {
    files: ['pyproject.toml', 'a.py', 'b.py', '__pycache__/a.cpython-312.pyc', '__pycache__/b.cpython-312.pyc'],
  })
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: [root] }, hostContext(root), { recursive: true }),
  ]), { workspaceRoot: root, isProtectedPath: () => false })
  const cache = path.join(root, '__pycache__')
  const dirRecords = evidence.exemptions.filter((entry) => entry.path === cache)
  assert.equal(dirRecords.length, 1) // the parent directory reports ONCE
  assert.equal(dirRecords[0].kind, 'directory')
  assert.equal(dirRecords[0].ruleId, 'data.delete.rebuildable')
  assert.equal(dirRecords[0].conclusion, 'established')
  // The per-file records inside the maximal directory are covered by it.
  assert.deepEqual(evidence.exemptions.filter((entry) => entry.kind === 'file' && entry.conclusion === 'established' && entry.path.startsWith(cache)), [])
  // Only the project's own files count: pyproject.toml, a.py, b.py.
  assert.equal(evidence.inventory.count, 3)
})

test('one unproven leaf keeps the whole directory counted leaf by leaf', async (t) => {
  const root = await makeFixture(t, {
    files: ['pyproject.toml', 'a.py', 'b.py', '__pycache__/a.cpython-312.pyc', '__pycache__/b.cpython-312.pyc', '__pycache__/CACHEDIR.TAG'],
  })
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: [root] }, hostContext(root), { recursive: true }),
  ]), { workspaceRoot: root, isProtectedPath: () => false })
  const cache = path.join(root, '__pycache__')
  assert.deepEqual(evidence.exemptions.filter((entry) => entry.kind === 'directory'), [])
  // File-level evidence still applies independently to each proven leaf.
  assert.equal(evidence.exemptions.filter((entry) => entry.kind === 'file' && entry.conclusion === 'established').length, 2)
  // CACHEDIR.TAG matches no rebuildable rule and is counted.
  assert.equal(evidence.inventory.count, 4)
})

test('a name-only build directory never grants an exemption', async (t) => {
  const root = await makeFixture(t, { files: ['dist/app.js', 'dist/app.js.map', 'readme.md'] })
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: [path.join(root, 'dist')] }, hostContext(root), { recursive: true }),
  ]), { workspaceRoot: root, isProtectedPath: () => false })
  assert.deepEqual(evidence.exemptions, [])
  assert.equal(evidence.inventory.count, 2) // both leaves stay counted
  assert.ok(evidence.inventory.directories.includes(path.join(root, 'dist')))
})

// --- git operations (injected probes, no real git child) -------------------------

test('git clean evidence turns Would-remove lines into counted paths', async (t) => {
  const root = await makeFixture(t, {})
  const gitRun = async () => ({ stdout: 'Would remove a.txt\nWould remove dir/\n' })
  const evidence = await collectEvidence(analysisWith([
    {
      action: 'git-clean', target: { kind: 'unknown', reason: 'git-evidence' },
      context: hostContext(root), condition: 'certain', recursive: false, preview: false,
      details: { command: 'clean', args: ['-d'], global: [] },
    },
  ]), { isProtectedPath: () => false, gitRun })
  assert.equal(evidence.inventory.kind, 'exact')
  assert.equal(evidence.inventory.count, 1)
  assert.deepEqual(evidence.inventory.files, [path.join(root, 'a.txt')])
  assert.deepEqual(evidence.inventory.directories, [path.join(root, 'dir')])
})

test('git clean evidence with unparseable output stays unknown', async (t) => {
  const root = await makeFixture(t, {})
  const gitRun = async () => ({ stdout: 'fatal: something else\n' })
  const evidence = await collectEvidence(analysisWith([
    {
      action: 'git-clean', target: { kind: 'unknown', reason: 'git-evidence' },
      context: hostContext(root), condition: 'certain', recursive: false, preview: false,
      details: { command: 'clean', args: ['-d'], global: [] },
    },
  ]), { isProtectedPath: () => false, gitRun })
  assert.equal(evidence.inventory.kind, 'unreliable')
  assert.ok(evidence.inventory.unknown.includes('git-clean-unparseable'))
  assert.ok(evidence.issues.some((issue) => issue.kind === 'git-evidence'))
})

test('a dirty worktree removal is reported as git risk, not a count', async (t) => {
  const root = await makeFixture(t, {})
  const worktree = path.join(root, 'wt')
  const gitRun = async (argv) => {
    if (argv.includes('worktree')) {
      return { stdout: `worktree ${root}\nHEAD a\nbranch refs/heads/main\n\nworktree ${worktree}\nHEAD b\nbranch refs/heads/topic\n` }
    }
    if (argv.includes('rev-parse')) return { stdout: root }
    if (argv.includes('symbolic-ref')) return { stdout: 'refs/heads/topic' }
    if (argv.includes('status')) return { stdout: ' M file.txt\n' }
    throw new Error(`unexpected probe: ${argv.join(' ')}`)
  }
  const evidence = await collectEvidence(analysisWith([
    {
      action: 'git-worktree-remove', target: { kind: 'unknown', reason: 'git-evidence' },
      context: hostContext(root), condition: 'certain', recursive: false, preview: false,
      details: { command: 'worktree', args: ['remove', 'wt'], global: [] },
    },
  ]), { isProtectedPath: () => false, gitRun })
  assert.deepEqual(evidence.gitRisk, { paths: [worktree], reason: 'untracked-or-modified' })
  assert.equal(evidence.inventory.count, 0)
})

test('restore without an explicit -- separator stays ambiguous', async (t) => {
  const root = await makeFixture(t, {})
  const gitRun = async () => { throw new Error('no probe expected without --') }
  const evidence = await collectEvidence(analysisWith([
    {
      action: 'git-restore', target: { kind: 'unknown', reason: 'git-evidence' },
      context: hostContext(root), condition: 'certain', recursive: false, preview: false,
      details: { command: 'restore', args: ['main'], global: [] },
    },
  ]), { isProtectedPath: () => false, gitRun })
  assert.ok(evidence.inventory.unknown.includes('restore-scope-ambiguous'))
  assert.equal(evidence.inventory.count, 0)
})

test('restore after -- counts the porcelain paths it would overwrite', async (t) => {
  const root = await makeFixture(t, {})
  const gitRun = async () => ({ stdout: ' M a.txt\nM  b.txt\n' })
  const evidence = await collectEvidence(analysisWith([
    {
      action: 'git-restore', target: { kind: 'unknown', reason: 'git-evidence' },
      context: hostContext(root), condition: 'certain', recursive: false, preview: false,
      details: { command: 'restore', args: ['--', '.', 'b.txt'], global: [] },
    },
  ]), { isProtectedPath: () => false, gitRun })
  assert.equal(evidence.inventory.count, 2)
  assert.ok(evidence.inventory.files.includes(path.join(root, 'a.txt')))
  assert.ok(evidence.inventory.files.includes(path.join(root, 'b.txt')))
})

// --- disaster identities ---------------------------------------------------------

test('git history destruction records the identity with the real common dir', async (t) => {
  const root = await makeFixture(t, {})
  const gitRun = async (argv) => {
    if (argv.includes('--git-common-dir')) return { stdout: root }
    throw new Error(`unexpected probe: ${argv.join(' ')}`)
  }
  const evidence = await collectEvidence(analysisWith([
    {
      action: 'git-history-destroy', target: { kind: 'unknown', reason: 'git-evidence' },
      context: hostContext(root), condition: 'certain', recursive: false, preview: false,
      details: { command: 'gc', args: ['--prune=now'], global: [] },
    },
  ]), { isProtectedPath: () => false, gitRun })
  assert.deepEqual(evidence.identities, [
    { ruleId: RULES.gitHistory, path: await fs.realpath(root), action: 'git-history-destroy' },
  ])
})

test('a declared device mutation needs a verified probe to name an identity', async (t) => {
  const root = await makeFixture(t, {})
  const devicePath = '\\\\.\\PhysicalDrive0'
  // A physical (non-virtual, online) disk proves the identity.
  const physicalInventory = { disks: [{ Number: 0, BusType: 'nvme', UniqueId: 'phys-0', IsOffline: false }], partitions: [] }
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: [devicePath] }, hostContext(root), { details: { deviceMutation: devicePath } }),
  ]), { isProtectedPath: () => false, _windowsInventory: physicalInventory })
  assert.deepEqual(evidence.identities, [
    { ruleId: RULES.device, path: devicePath, action: 'delete' },
  ])
})

test('a deviceMutation on an ordinary file never grants a device identity', async (t) => {
  const root = await makeFixture(t, { files: ['image.img'] })
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: ['image.img'] }, hostContext(root), { details: { deviceMutation: true } }),
  ]), { isProtectedPath: () => false })
  // `deviceMutation: true` is only destructive utility: no identity, no identity issue.
  assert.deepEqual(evidence.identities, [])
  assert.deepEqual(evidence.issues.filter((issue) => issue.kind === 'device-identity-unproven'), [])
  assert.equal(evidence.inventory.count, 1)
})

test('an unprovable device target records an explicit identity issue, not an identity', async (t) => {
  const root = await makeFixture(t, {})
  const devicePath = '\\\\.\\PhysicalDrive0'
  // A virtual/file-backed disk fails the physical-bus check: identity stays unproven.
  const virtualInventory = { disks: [{ Number: 0, BusType: 'file-backed', UniqueId: 'vhd', IsOffline: false }], partitions: [] }
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: [devicePath] }, hostContext(root), { details: { deviceMutation: devicePath } }),
  ]), { isProtectedPath: () => false, _windowsInventory: virtualInventory })
  assert.deepEqual(evidence.identities, [])
  assert.ok(evidence.issues.some((issue) => issue.kind === 'device-identity-unproven' && issue.path === devicePath))
})

test('a device write-content target is observed for storage identity', async (t) => {
  const root = await makeFixture(t, {})
  const devicePath = '\\\\.\\PhysicalDrive1'
  const physicalInventory = { disks: [{ Number: 1, BusType: 'usb', UniqueId: 'phys-1', IsOffline: false }], partitions: [] }
  const evidence = await collectEvidence(analysisWith([
    { action: 'write-content', target: { kind: 'exact', paths: [devicePath] }, context: hostContext(root), condition: 'certain', recursive: false, preview: false, details: { deviceMutation: devicePath } },
  ]), { isProtectedPath: () => false, _windowsInventory: physicalInventory })
  assert.deepEqual(evidence.identities, [
    { ruleId: RULES.device, path: devicePath, action: 'write-content' },
  ])
  assert.equal(evidence.inventory.count, 0) // a raw write is not a deletion
})

test('matchSystemTree matches whole-tree realpaths only (pure)', () => {
  assert.equal(matchSystemTree(['/usr', '/etc'], '/usr', false), true)
  assert.equal(matchSystemTree(['/usr', '/etc'], '/usr/share', false), false)
  assert.equal(matchSystemTree([], '/usr', false), false)
  // Case folding only where both sides are realpaths and the volume folds case.
  assert.equal(matchSystemTree(['C:\\Windows'], 'c:\\windows', true), true)
})

test('the real Windows system tree gets a root identity (Windows only)', { skip: process.platform !== 'win32' }, async (t) => {
  const systemRoot = process.env.SystemRoot
  if (!systemRoot) return t.skip('SystemRoot is unavailable')
  const root = await makeFixture(t, {})
  const real = await fs.realpath(systemRoot)
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: [systemRoot] }, hostContext(root)),
  ]), { isProtectedPath: () => false })
  assert.ok(evidence.identities.some((identity) =>
    identity.ruleId === RULES.root && identity.action === 'delete'
    && identity.path.toLowerCase() === real.toLowerCase()))
})

// --- fs domain (opaque managed targets, Inspect fs contract) ----------------------

/** Fake fs provider per the Inspect `fs` contract: resolve/processPath/stat. */
function createFsProvider(table) {
  return {
    async resolve(raw) { return { targetKey: `k:${raw}`, raw } },
    processPath(target) { return table.get(target.raw)?.displayPath ?? target.raw },
    async stat(target) {
      const item = table.get(target.raw)
      return item ? { type: item.type, version: item.version } : undefined
    },
  }
}

test('a relative host content path matches the configured absolute file', async () => {
  const cwd = path.resolve('fixture')
  const marked = path.join(cwd, 'protected.txt')
  const operation = { action: 'read-content', context: { domain: 'host', platform: process.platform, cwd },
    target: { kind: 'exact', paths: ['protected.txt'] }, recursive: false, preview: false, condition: 'certain' }
  const evidence = await collectEvidence(analysisWith([operation]), { isProtectedPath: (target) => target === marked })
  assert.deepEqual(evidence.protectedHits, [{ path: marked, action: 'read-content' }])
})

const fsContext = { domain: 'fs', platform: 'linux' }

test('fs-domain targets resolve, dedupe by key and report display paths', async (t) => {
  const table = new Map([['vault/secret.env', { type: 'file', version: 'v1', displayPath: '/ws/secret.env' }]])
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: ['vault/secret.env'] }, fsContext),
    { action: 'read-content', target: { kind: 'exact', paths: ['vault/secret.env'] }, context: fsContext, condition: 'certain', recursive: false, preview: false },
  ]), { fsProvider: createFsProvider(table), isProtectedPath: (value) => value === '/ws/secret.env' })
  // Content paths are resolved too: the protected alias only matches the display path.
  assert.ok(evidence.protectedHits.some((hit) => hit.path === '/ws/secret.env' && hit.action === 'delete'))
  assert.ok(evidence.protectedHits.some((hit) => hit.path === '/ws/secret.env' && hit.action === 'read-content'))
  assert.deepEqual(evidence.inventory.files, ['/ws/secret.env'])
  assert.equal(evidence.inventory.count, 1)
  assert.deepEqual(evidence.issues, [])
})

test('two raw spellings of one fs target count once (key dedupe)', async (t) => {
  const table = new Map([
    ['a.txt', { type: 'file', version: 'v1', displayPath: '/ws/a.txt' }],
    ['./a.txt', { type: 'file', version: 'v1', displayPath: '/ws/a.txt' }],
  ])
  const provider = createFsProvider(table)
  provider.resolve = async (raw) => ({ targetKey: 'k:same-target', raw }) // both spellings share one key
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: ['a.txt', './a.txt'] }, fsContext),
  ]), { fsProvider: provider, isProtectedPath: () => false })
  assert.equal(evidence.inventory.count, 1)
  assert.deepEqual(evidence.inventory.files, ['/ws/a.txt'])
})

test('an fs version bump changes the fingerprint on an unchanged path', async (t) => {
  const runWith = async (version) => {
    const table = new Map([['a.txt', { type: 'file', version, displayPath: '/ws/a.txt' }]])
    return collectEvidence(analysisWith([
      deleteOp({ kind: 'exact', paths: ['a.txt'] }, fsContext),
    ]), { fsProvider: createFsProvider(table), isProtectedPath: () => false })
  }
  const first = await runWith('v1')
  const second = await runWith('v2')
  assert.notEqual(first.inventory.fingerprint, second.inventory.fingerprint)
  assert.deepEqual(first.inventory.files, second.inventory.files)
})

test('fs-domain subtree targets cannot be enumerated and stay a deliberate unknown', async (t) => {
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'subtree', root: '/data/out' }, fsContext, { recursive: true }),
  ]), { fsProvider: createFsProvider(new Map()), isProtectedPath: () => false })
  assert.equal(evidence.inventory.kind, 'exact')
  assert.ok(evidence.inventory.unknown.includes('fs-enumeration-unsupported'))
})

test('a fs-domain operation without a full provider is an explicit stage issue', async (t) => {
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: ['/opaque/a.txt'] }, fsContext),
  ]), { fsProvider: { stat: async () => undefined }, isProtectedPath: () => false })
  assert.ok(evidence.issues.some((issue) => issue.kind === 'fs-provider-missing'))
  assert.equal(evidence.inventory.kind, 'unreliable')
})

// --- domain isolation and lifecycle ------------------------------------------------

test('non-host domains are recorded unprobed, never host-observed', async (t) => {
  const root = await makeFixture(t, { files: ['a.txt'] })
  const evidence = await collectEvidence(analysisWith([
    deleteOp({ kind: 'exact', paths: ['/data/a.txt'] }, { domain: 'wsl:ubuntu', platform: 'linux' }),
  ]), { isProtectedPath: () => false })
  // A deliberate domain boundary: the count stays valid (zero observed), the unknown
  // part is named, and no host I/O failure is claimed.
  assert.equal(evidence.inventory.kind, 'exact')
  assert.ok(evidence.inventory.unknown.includes('domain-unprobed'))
  assert.deepEqual(evidence.issues.filter((issue) => issue.kind === 'inventory-failed'), [])
  assert.ok(root) // fixture still created to prove no host path was touched
})

test('a pre-aborted signal rejects the whole collection', async () => {
  const controller = new AbortController()
  controller.abort(new Error('stop-capture'))
  await assert.rejects(
    collectEvidence(analysisWith([], { status: 'partial' }), { signal: controller.signal, isProtectedPath: () => false }),
    /stop-capture/,
  )
})

test('fault analysis keeps its status and passes candidates through unchanged', async (t) => {
  const root = await makeFixture(t, { files: ['a.txt'] })
  const candidate = { kind: 'unverified-effect', reason: 'Deletion options could not be interpreted', knownScope: undefined, origin: { entry: 'shell' } }
  const evidence = await collectEvidence({
    status: 'fault', candidates: [candidate], gaps: [{ kind: 'command-options', unitId: 1, origin: { entry: 'shell' } }],
    operations: [deleteOp({ kind: 'exact', paths: ['a.txt'] }, hostContext(root))],
  }, { isProtectedPath: () => false })
  assert.equal(evidence.analysisStatus, 'fault')
  assert.deepEqual(evidence.candidates, [candidate])
  assert.equal(evidence.inventory.count, 1)
})

test('an inline credential flag is forwarded unchanged', async (t) => {
  const root = await makeFixture(t, {})
  const evidence = await collectEvidence(analysisWith([], { inlineCredential: true }), { isProtectedPath: () => false })
  assert.equal(evidence.inlineCredential, true)
})
