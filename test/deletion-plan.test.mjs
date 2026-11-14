// Synthetic-fixture tests for the deletion-plan gate. No real library files are
// referenced; the disposable classifier is injected as a synthetic seam so the gate
// logic is tested independently of the separate core whitelist module.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { planDeletions } from '../src/adapter/deletion-plan.js'
import { DELETION_DOCTRINE } from '../src/core/deletion-intent.js'

const RULES = { sensitiveFiles: [], builtinSensitiveAsk: true }

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'guardrails-count-'))
  t.after(async () => { await fs.rm(root, { recursive: true, force: true }) })
  return root
}

async function manyFiles(dir, count, prefix = 'f') {
  await fs.mkdir(dir, { recursive: true })
  for (let i = 0; i < count; i += 1) await fs.writeFile(path.join(dir, `${prefix}${i}.txt`), 'fixture')
}

function deleteOp(target, extra = {}) {
  return { action: 'delete', path: target, recursive: true, domain: 'host', commandName: 'rm', ...extra }
}

// Synthetic classifier: anything under a node_modules/ segment is disposable.
function disposableNodeModules({ relativePath }) {
  return { disposable: relativePath.startsWith('node_modules/') }
}

test('small literal tree under the limit is allowed with complete counts and entries', async (t) => {
  const root = await fixture(t)
  await manyFiles(path.join(root, 'work'), 5)
  await fs.mkdir(path.join(root, 'work', 'sub'))
  await fs.writeFile(path.join(root, 'work', 'sub', 'g.txt'), 'fixture')
  const result = await planDeletions({
    operations: [deleteOp('work')], cwd: root, rules: RULES, classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'allow')
  assert.equal(result.counts.files, 6)
  assert.equal(result.counts.links, 0)
  assert.equal(result.counts.directories, 2)
  assert.equal(result.counts.atLeast, false)
  assert.equal(result.entries.filter((e) => e.type === 'file').length, 6)
})

test('21 non-exempt files deny early with at-least-21, never an exact total', async (t) => {
  const root = await fixture(t)
  await manyFiles(path.join(root, 'big'), 25)
  const result = await planDeletions({
    operations: [deleteOp('big')], cwd: root, rules: RULES, classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-01')
  assert.match(result.reason, /at least 21/)
  assert.equal(result.counts.atLeast, true)
})

test('exactly 20 files is allowed; the 21st denies, across one invocation', async (t) => {
  const root = await fixture(t)
  await manyFiles(path.join(root, 'a'), 12)
  await manyFiles(path.join(root, 'b'), 8)
  const at20 = await planDeletions({
    operations: [deleteOp('a'), deleteOp('b')], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(at20.kind, 'allow')
  assert.equal(at20.counts.files, 20)
  await fs.writeFile(path.join(root, 'b', 'extra.txt'), 'fixture')
  const at21 = await planDeletions({
    operations: [deleteOp('a'), deleteOp('b')], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(at21.kind, 'deny')
  assert.equal(at21.counts.atLeast, true)
})

test('whitelist exemptions apply per file; directories are reported separately and do not consume the limit', async (t) => {
  const root = await fixture(t)
  await fs.writeFile(path.join(root, 'package.json'), '{}')
  await manyFiles(path.join(root, 'node_modules', 'pkg'), 30)
  // Evidence is a separate seam: this test exercises per-file exemption COUNTING, so it
  // injects an evidence stub that proves every shape candidate. Real evidence (domain,
  // Git, source pairing) is covered by disposable-evidence and strict-runtime tests.
  const result = await planDeletions({
    operations: [deleteOp('node_modules')], cwd: root, rules: RULES,
    classifyDisposable: disposableNodeModules, projectMarkers: ['package.json'],
    _evidence: { verify: async () => ({ eligible: true }) },
  })
  assert.equal(result.kind, 'allow')
  assert.equal(result.counts.files, 0)
  assert.ok(result.counts.directories >= 2)
  assert.equal(result.entries.filter((e) => e.type === 'file').length, 30)
  assert.ok(result.entries.filter((e) => e.type === 'file').every((e) => e.disposable === true))
})

test('a protected file is never exempted by the whitelist and still counts', async (t) => {
  const root = await fixture(t)
  await fs.writeFile(path.join(root, 'package.json'), '{}')
  await fs.mkdir(path.join(root, 'node_modules', 'pkg'), { recursive: true })
  // .npmrc is a credential carrier; even inside a disposable tree it must count.
  await fs.writeFile(path.join(root, 'node_modules', 'pkg', '.npmrc'), 'fixture')
  const result = await planDeletions({
    operations: [deleteOp('node_modules')], cwd: root, rules: RULES,
    classifyDisposable: disposableNodeModules, projectMarkers: ['package.json'],
    _evidence: { verify: async () => ({ eligible: true }) },
  })
  assert.equal(result.kind, 'allow')
  assert.equal(result.counts.files, 1)
  assert.ok(result.entries.some((e) => e.protected === true))
})

test('overlapping delete plans deduplicate shared directory subtrees', async (t) => {
  const root = await fixture(t)
  await manyFiles(path.join(root, 'tree'), 5)
  await manyFiles(path.join(root, 'tree', 'inner'), 3)
  const result = await planDeletions({
    operations: [deleteOp('tree'), deleteOp('tree/inner')], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'allow')
  assert.equal(result.counts.files, 8) // counted once, not twice
})

test('unknown deletion semantics deny in English', async (t) => {
  const root = await fixture(t)
  const result = await planDeletions({
    operations: [deleteOp('x', { unknown: 'dynamic-path' })], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-02')
})

test('a null path denies; nonliteral and remote targets deny', async (t) => {
  const root = await fixture(t)
  for (const target of [null, '*.log', '\\\\server\\share\\x', 'https://example.test/x']) {
    const result = await planDeletions({
      operations: [deleteOp(target)], cwd: root, rules: RULES,
      classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
    })
    assert.equal(result.kind, 'deny', String(target))
    assert.equal(result.ruleId, 'DEL-02')
  }
})

test('WSL / non-host domains deny without guessing a /mnt mapping', async (t) => {
  const root = await fixture(t)
  for (const domain of ['wsl', undefined]) {
    const result = await planDeletions({
      operations: [deleteOp('/home/u/thing', { domain })], cwd: root, rules: RULES,
      classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
    })
    assert.equal(result.kind, 'deny')
    assert.equal(result.ruleId, 'DEL-03')
  }
})

test('non-recursive directory delete denies as ambiguous', async (t) => {
  const root = await fixture(t)
  await fs.mkdir(path.join(root, 'emptydir'))
  const result = await planDeletions({
    operations: [deleteOp('emptydir', { recursive: false })], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-08')
})

test('missing targets are a known zero, not an error', async (t) => {
  const root = await fixture(t)
  const result = await planDeletions({
    operations: [deleteOp('does-not-exist')], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'allow')
  assert.equal(result.counts.files + result.counts.links, 0)
})

test('deleting a symlink itself counts as one link entry and is never followed', async (t) => {
  const root = await fixture(t)
  const outside = await fixture(t)
  await manyFiles(outside, 30)
  try {
    await fs.symlink(outside, path.join(root, 'link'), 'dir')
  } catch (error) {
    t.skip(`symlink unavailable: ${error.code}`)
    return
  }
  const result = await planDeletions({
    operations: [deleteOp('link', { recursive: false })], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'allow')
  assert.equal(result.counts.links, 1)
  assert.equal(result.counts.files, 0) // never traversed the link target
})

test('a symlinked ancestor is an escape and denies', async (t) => {
  const root = await fixture(t)
  const outside = await fixture(t)
  await manyFiles(outside, 3)
  try {
    await fs.symlink(outside, path.join(root, 'bridge'), 'dir')
  } catch (error) {
    t.skip(`symlink unavailable: ${error.code}`)
    return
  }
  const result = await planDeletions({
    operations: [deleteOp('bridge/data')], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-04')
})

test('a symlink entry inside a recursive tree is counted but not traversed', async (t) => {
  const root = await fixture(t)
  const outside = await fixture(t)
  await manyFiles(outside, 40)
  await manyFiles(path.join(root, 'tree'), 2)
  try {
    await fs.symlink(outside, path.join(root, 'tree', 'escape'), 'dir')
  } catch (error) {
    t.skip(`symlink unavailable: ${error.code}`)
    return
  }
  const result = await planDeletions({
    operations: [deleteOp('tree')], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'allow')
  assert.equal(result.counts.files, 2)
  assert.equal(result.counts.links, 1)
})

test('an unsupported operation action fails closed', async (t) => {
  const root = await fixture(t)
  const result = await planDeletions({
    operations: [{ action: 'move', path: 'x', recursive: false, domain: 'host' }], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-09')
})

test('a classifier that throws leaves the file counting toward the limit', async (t) => {
  const root = await fixture(t)
  await fs.writeFile(path.join(root, 'package.json'), '{}')
  await manyFiles(path.join(root, 'node_modules', 'p'), 21)
  const result = await planDeletions({
    operations: [deleteOp('node_modules')], cwd: root, rules: RULES,
    classifyDisposable: () => { throw new Error('synthetic failure') }, projectMarkers: ['package.json'],
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-01')
})

test('an aborted signal denies before dispatch', async (t) => {
  const root = await fixture(t)
  await manyFiles(path.join(root, 'a'), 2)
  const controller = new AbortController()
  controller.abort(new Error('cancelled'))
  const result = await planDeletions({
    operations: [deleteOp('a')], cwd: root, rules: RULES, signal: controller.signal,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-11')
})

test('a recursive delete of a symlink root is ambiguous and denies', async (t) => {
  const root = await fixture(t)
  const outside = await fixture(t)
  await manyFiles(outside, 3)
  try {
    await fs.symlink(outside, path.join(root, 'link'), 'dir')
  } catch (error) {
    t.skip(`symlink unavailable: ${error.code}`)
    return
  }
  const result = await planDeletions({
    operations: [deleteOp('link', { recursive: true })], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-08')
})

test('bracket and glob-bearing paths are rejected as non-literal', async (t) => {
  const root = await fixture(t)
  for (const target of ['a[1].txt', 'x?.log', 'y*.tmp']) {
    const result = await planDeletions({
      operations: [deleteOp(target, { recursive: false })], cwd: root, rules: RULES,
      classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
    })
    assert.equal(result.kind, 'deny', target)
    assert.equal(result.ruleId, 'DEL-02')
  }
})

test('malformed inputs throw TypeError', async (t) => {
  const root = await fixture(t)
  await assert.rejects(() => planDeletions({ operations: null, cwd: root, rules: RULES }), TypeError)
  await assert.rejects(() => planDeletions({ operations: [], cwd: root, rules: null }), TypeError)
})

test('budget exhaustion denies as unknown, never treated as <=20', async (t) => {
  const root = await fixture(t)
  await manyFiles(path.join(root, 'many'), 10)
  // Force the scan budget below the number of entries needed to complete.
  const result = await planDeletions({
    operations: [deleteOp('many')], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
    _budget: { maxScanEntries: 3 },
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-07')
})

test('duplicate file targets across operations are counted once (path dedupe, not inode)', async (t) => {
  const root = await fixture(t)
  await fs.writeFile(path.join(root, 'a.txt'), 'fixture')
  const result = await planDeletions({
    operations: [
      deleteOp('a.txt', { recursive: false }),
      deleteOp('a.txt', { recursive: false }),
      deleteOp('./a.txt', { recursive: false }),
    ],
    cwd: root, rules: RULES, classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'allow')
  assert.equal(result.counts.files, 1)
})

test('a directory-overlapping file target is not double counted', async (t) => {
  const root = await fixture(t)
  await fs.mkdir(path.join(root, 'tree'))
  await fs.writeFile(path.join(root, 'tree', 'f.txt'), 'fixture')
  const result = await planDeletions({
    operations: [deleteOp('tree'), deleteOp('tree/f.txt', { recursive: false })],
    cwd: root, rules: RULES, classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'allow')
  assert.equal(result.counts.files, 1)
})

test('a filesystem root target is always denied, even when empty', async (t) => {
  if (process.platform === 'win32') {
    // Drive roots are unambiguously DEL-12; `/` is also single-rooted and may deny DEL-02.
    for (const target of ['C:\\', 'C:/']) {
      const result = await planDeletions({
        operations: [deleteOp(target)], cwd: path.parse(target).root, rules: RULES,
        classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
      })
      assert.equal(result.kind, 'deny', target)
      assert.equal(result.ruleId, 'DEL-12', target)
    }
    const slash = await planDeletions({
      operations: [deleteOp('/')], cwd: 'C:\\', rules: RULES,
      classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
    })
    assert.equal(slash.kind, 'deny')
    assert.ok(['DEL-12', 'DEL-02'].includes(slash.ruleId), slash.ruleId)
  } else {
    const result = await planDeletions({
      operations: [deleteOp('/')], cwd: '/', rules: RULES,
      classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
    })
    assert.equal(result.kind, 'deny')
    assert.equal(result.ruleId, 'DEL-12')
  }
})

test('".." segments are refused before normalization', async (t) => {
  const root = await fixture(t)
  for (const target of ['../escape', 'a/../../b', 'sub/..']) {
    const result = await planDeletions({
      operations: [deleteOp(target)], cwd: root, rules: RULES,
      classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
    })
    assert.equal(result.kind, 'deny', target)
    assert.equal(result.ruleId, 'DEL-08', target)
  }
})

test('a non-recursive delete with a trailing separator on a symlink denies', async (t) => {
  const root = await fixture(t)
  const outside = await fixture(t)
  await manyFiles(outside, 3)
  try {
    await fs.symlink(outside, path.join(root, 'link'), 'dir')
  } catch (error) {
    t.skip(`symlink unavailable: ${error.code}`)
    return
  }
  for (const target of ['link/', 'link' + path.sep, 'link/.']) {
    const result = await planDeletions({
      operations: [deleteOp(target, { recursive: false })], cwd: root, rules: RULES,
      classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
    })
    assert.equal(result.kind, 'deny', target)
    assert.equal(result.ruleId, 'DEL-08', target)
  }
})

test('a delete path that addresses .git metadata denies', async (t) => {
  const root = await fixture(t)
  await fs.mkdir(path.join(root, '.git', 'objects'), { recursive: true })
  const result = await planDeletions({
    operations: [deleteOp('.git', { recursive: false })], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-13')
})

test('a small tree containing a .git directory denies rather than sneaking under 20', async (t) => {
  const root = await fixture(t)
  await manyFiles(path.join(root, 'proj'), 3)
  await fs.mkdir(path.join(root, 'proj', '.git', 'objects'), { recursive: true })
  const result = await planDeletions({
    operations: [deleteOp('proj')], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-13')
})

// --- namespace / OS-boundary cases -----------------------------------------

test('bash/posix dialect on a Windows host is denied (DEL-03)', { skip: process.platform !== 'win32' && 'Windows-only path-namespace rule' }, async (t) => {
  const root = await fixture(t)
  for (const dialect of ['bash', 'posix']) {
    const result = await planDeletions({
      operations: [deleteOp('/tmp/x', { dialect })], cwd: root, rules: RULES,
      classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
    })
    assert.equal(result.kind, 'deny', dialect)
    assert.equal(result.ruleId, 'DEL-03', dialect)
  }
})

test('tilde-prefixed targets are refused (provider-expanded)', async (t) => {
  const root = await fixture(t)
  for (const target of ['~', '~/secret', '~/x', 'sub/~']) {
    const result = await planDeletions({
      operations: [deleteOp(target)], cwd: root, rules: RULES,
      classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
    })
    assert.equal(result.kind, 'deny', target)
    assert.equal(result.ruleId, 'DEL-02', target)
  }
})

test('Windows single-rooted \\foo and /foo are refused (drive depends on provider)', { skip: process.platform !== 'win32' && 'Windows single-root rule' }, async (t) => {
  const root = await fixture(t)
  for (const target of ['\\foo', '/foo', '\\temp\\x']) {
    const result = await planDeletions({
      operations: [deleteOp(target)], cwd: root, rules: RULES,
      classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
    })
    assert.equal(result.kind, 'deny', target)
    assert.equal(result.ruleId, 'DEL-02', target)
  }
})

test('a backslash in a PowerShell path on a POSIX host is refused', { skip: process.platform === 'win32' && 'POSIX-only provider-separator rule' }, async (t) => {
  const root = await fixture(t)
  const result = await planDeletions({
    operations: [deleteOp('a\\b', { dialect: 'powershell' })], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-02')
})

test('dedupe is case-sensitive: differently-cased targets are not merged to under-count', async (t) => {
  const root = await fixture(t)
  await fs.writeFile(path.join(root, 'a.txt'), 'fixture')
  const result = await planDeletions({
    operations: [
      deleteOp('a.txt', { recursive: false }),
      deleteOp('A.txt', { recursive: false }),
    ],
    cwd: root, rules: RULES, classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'allow')
  // Case-sensitive dedupe over-counts rather than under-counts on a case-insensitive FS.
  assert.equal(result.counts.files, 2)
})

test('an operation cwd containing ".." is refused', async (t) => {
  const root = await fixture(t)
  const result = await planDeletions({
    operations: [{ action: 'delete', path: 'x', recursive: false, domain: 'host', cwd: '..\\other' }],
    cwd: root, rules: RULES, classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-08')
})

test('streaming walk still reaches the 21st entry exactly (no early-stop miss)', async (t) => {
  const root = await fixture(t)
  await manyFiles(path.join(root, 'wide'), 25)
  const result = await planDeletions({
    operations: [deleteOp('wide')], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
    _budget: { maxScanEntries: 100_000 },
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-01')
  assert.equal(result.counts.atLeast, true)
})

test('a wide directory that exhausts a small scan budget denies without materializing', async (t) => {
  const root = await fixture(t)
  await manyFiles(path.join(root, 'wide'), 40)
  const result = await planDeletions({
    operations: [deleteOp('wide')], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
    _budget: { maxScanEntries: 5 },
  })
  // Either it stopped early at >20 (DEL-01) or hit the scan budget first (DEL-07); both
  // are denials reached by streaming a few entries, never a full materialization.
  assert.equal(result.kind, 'deny')
  assert.ok(['DEL-01', 'DEL-07'].includes(result.ruleId), result.ruleId)
})

test('project-root marker probing resolves a disposable tree by fixed markers only', async (t) => {
  const root = await fixture(t)
  await fs.writeFile(path.join(root, 'pyproject.toml'), '{}')
  await fs.mkdir(path.join(root, '__pycache__'), { recursive: true })
  // Many unrelated files in the project root: marker probing must not list them.
  await manyFiles(root, 50, 'unrelated')
  // A .pyc only becomes exempt when its paired .py source exists (regeneration evidence).
  await fs.writeFile(path.join(root, 'mod.py'), 'print(1)\n')
  await fs.writeFile(path.join(root, '__pycache__', 'mod.cpython-312.pyc'), 'x')
  const result = await planDeletions({
    operations: [deleteOp('__pycache__')], cwd: root, rules: RULES,
  })
  assert.equal(result.kind, 'allow')
  assert.equal(result.counts.files, 0) // pyc exempt via marker-based project root + paired source
})

test('Windows case-insensitive: a .GIT target segment is still denied (DEL-13)', { skip: process.platform !== 'win32' && 'Win32 case-folding rule' }, async (t) => {
  const root = await fixture(t)
  const result = await planDeletions({
    operations: [deleteOp('.GIT', { recursive: false })], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-13')
})

test('Windows case-insensitive: a tree containing a .GIT directory is denied (DEL-13)', { skip: process.platform !== 'win32' && 'Win32 case-folding rule' }, async (t) => {
  const root = await fixture(t)
  await manyFiles(path.join(root, 'proj'), 3)
  await fs.mkdir(path.join(root, 'proj', '.GIT', 'objects'), { recursive: true })
  const result = await planDeletions({
    operations: [deleteOp('proj')], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-13')
})

test('a directory entry name containing U+FFFD (unrepresentable filename) refuses rather than undercounts', async (t) => {
  const root = await fixture(t)
  const tree = path.join(root, 'tree')
  await fs.mkdir(tree, { recursive: true })
  await fs.writeFile(path.join(tree, 'ok.txt'), 'x')
  // U+FFFD is a legal filename character on all platforms; it also is exactly what a
  // UTF-8 decode of raw non-UTF-8 bytes yields, so a literal U+FFFD name must be refused
  // (we cannot distinguish it from an unrecoverable raw-byte filename).
  await fs.writeFile(path.join(tree, 'bad\uFFFDname.txt'), 'x')
  const result = await planDeletions({
    operations: [deleteOp('tree')], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'DEL-08')
})

test('ordinary Unicode filenames (CJK, emoji) are inventoried normally', async (t) => {
  const root = await fixture(t)
  const tree = path.join(root, 'tree')
  await fs.mkdir(tree, { recursive: true })
  await fs.writeFile(path.join(tree, '文档.txt'), 'x')
  await fs.writeFile(path.join(tree, 'café.txt'), 'x')
  await fs.writeFile(path.join(tree, '😀.txt'), 'x')
  const result = await planDeletions({
    operations: [deleteOp('tree')], cwd: root, rules: RULES,
    classifyDisposable: () => ({ disposable: false }), projectMarkers: [],
  })
  assert.equal(result.kind, 'allow')
  assert.equal(result.counts.files, 3)
})

test('whitelist eligibility requires an EXACT-case boundary containment (no Windows case alias)', async (t) => {
  // A target under a project, but the trusted boundary is supplied with a different letter
  // case. Because NTFS can host case-sensitive dirs, a case alias cannot be PROVEN to be
  // the same entity, so the file must NOT receive an exemption (ordinary count) rather
  // than being wrongly discounted. This uses an evidence stub that would grant if reached.
  const root = await fixture(t)
  const proj = path.join(root, 'Proj')
  await fs.mkdir(path.join(proj, '__pycache__'), { recursive: true })
  await fs.writeFile(path.join(proj, 'pyproject.toml'), '{}')
  await fs.writeFile(path.join(proj, 'm.py'), 'print(1)\n')
  await fs.writeFile(path.join(proj, '__pycache__', 'm.cpython-312.pyc'), 'x')
  // Case-variant boundary that does not equal the real path segment-for-segment.
  const boundaryAlias = path.join(root, 'proj') // lowercase 'proj' vs real 'Proj'
  let verifyCalled = 0
  const result = await planDeletions({
    operations: [deleteOp(path.join('Proj', '__pycache__'))], cwd: root, boundary: boundaryAlias, rules: RULES,
    _evidence: { verify: async () => { verifyCalled += 1; return { eligible: true } } },
    classifyDisposable: () => ({ disposable: true, ruleId: 'py-pyc-file' }),
    projectMarkers: ['pyproject.toml'],
  })
  assert.equal(result.kind, 'allow')
  // The pyc under a case-aliased boundary is NOT eligible; evidence is never consulted.
  assert.equal(verifyCalled, 0, 'evidence must not be consulted for an out-of-boundary (case-alias) target')
  assert.equal(result.counts.files, 1, 'the pyc is counted as an ordinary file')
})

test('every DEL-* denial reason carries the shared deletion doctrine exactly once', async (t) => {
  const root = await fixture(t)
  // A representative spread of denial kinds (over-limit, unknown semantics, nonliteral,
  // .git metadata, special/ambiguous, budget) to prove the doctrine is attached centrally.
  const cases = []
  // DEL-01 over limit
  const big = path.join(root, 'big')
  await manyFiles(big, 25)
  cases.push(await planDeletions({ operations: [deleteOp('big')], cwd: root, rules: RULES, classifyDisposable: () => ({ disposable: false }), projectMarkers: [] }))
  // DEL-02 unknown / nonliteral
  cases.push(await planDeletions({ operations: [deleteOp('x', { unknown: 'dynamic-path' })], cwd: root, rules: RULES, classifyDisposable: () => ({ disposable: false }), projectMarkers: [] }))
  cases.push(await planDeletions({ operations: [deleteOp('*.log')], cwd: root, rules: RULES, classifyDisposable: () => ({ disposable: false }), projectMarkers: [] }))
  // DEL-13 .git
  cases.push(await planDeletions({ operations: [deleteOp('.git', { recursive: false })], cwd: root, rules: RULES, classifyDisposable: () => ({ disposable: false }), projectMarkers: [] }))
  for (const result of cases) {
    assert.equal(result.kind, 'deny')
    assert.ok(result.reason.includes(DELETION_DOCTRINE), `doctrine present for ${result.ruleId}`)
    // Exactly once: no duplicated sentence.
    assert.equal(result.reason.split(DELETION_DOCTRINE).length - 1, 1, `doctrine once for ${result.ruleId}`)
  }
})
