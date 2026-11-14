// Tests for disposable-evidence. Synthetic fixtures are created under the OS temp
// directory and removed with t.after. No project builders/compilers are run; the only
// external program invoked is read-only `git` metadata (run by the module itself
// against fixtures). No production paths or root drive fixtures are touched.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import os from 'node:os'
import { execFileSync } from 'node:child_process'
import { createDisposableEvidence, EXCLUDED_SEGMENTS } from '../src/adapter/disposable-evidence.js'

// Fixtures live under the OS temp directory, cleaned with t.after. The worktree's own
// tmp/ sits INSIDE the containing Git repository, which would make every fixture appear
// Git-tracked-by-ancestor and defeat the non-Git cases; the OS temp dir is outside any
// repository and is not a production path. No root C:\ fixtures, no production writes.
const FIXTURE_BASE = os.tmpdir()

async function fixture(t, label) {
  await fs.mkdir(FIXTURE_BASE, { recursive: true })
  const root = await fs.mkdtemp(path.join(FIXTURE_BASE, `ev-${label}-`))
  t.after(async () => { await fs.rm(root, { recursive: true, force: true }) })
  return root
}

function makeEvidence(boundary, { budget = 100000, deadlineAt, signal } = {}) {
  let used = 0
  const consume = () => { used += 1; return used <= budget }
  return createDisposableEvidence({ boundary, signal, deadlineAt, consume })
}

async function write(root, rel, content = 'x') {
  const p = path.join(root, rel)
  await fs.mkdir(path.dirname(p), { recursive: true })
  await fs.writeFile(p, content)
  return p
}

function gitInit(root) {
  execFileSync('git', ['init', '-q', root], { stdio: 'ignore' })
  execFileSync('git', ['-C', root, 'config', 'user.email', 't@example.test'], { stdio: 'ignore' })
  execFileSync('git', ['-C', root, 'config', 'user.name', 't'], { stdio: 'ignore' })
}

test('EXCLUDED_SEGMENTS includes archive/dependency domains', () => {
  for (const seg of ['backup', 'node_modules', 'vendor', 'third_party', '.git', 'archive']) {
    assert.ok(EXCLUDED_SEGMENTS.includes(seg), seg)
  }
})

test('archive/dependency domains are never exempted (pyc with paired source inside backup/node_modules)', async (t) => {
  const root = await fixture(t, 'domain')
  const ev = makeEvidence(root)
  for (const dir of ['backup', 'node_modules/pkg', 'vendor/lib', 'third_party/x', 'snapshot']) {
    const src = await write(root, `${dir}/mod.py`)
    const pyc = await write(root, `${dir}/__pycache__/mod.cpython-312.pyc`)
    const r = await ev.verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
    assert.equal(r.eligible, false, dir)
    assert.match(r.reason, /excluded-domain/, dir)
    void src
  }
})

test('project root under an excluded boundary domain is not exempted', async (t) => {
  const boundary = await fixture(t, 'bnd')
  const proj = path.join(boundary, 'backups', 'proj')
  await fs.mkdir(proj, { recursive: true })
  await write(proj, 'mod.py')
  const pyc = await write(proj, '__pycache__/mod.cpython-312.pyc')
  const ev = makeEvidence(boundary)
  const r = await ev.verify({ absolute: pyc, projectRoot: proj, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(r.eligible, false)
  assert.match(r.reason, /excluded/)
})

test('artifact outside project / project outside boundary are not exempted', async (t) => {
  const boundary = await fixture(t, 'bnd2')
  const proj = path.join(boundary, 'proj')
  await fs.mkdir(proj, { recursive: true })
  const elsewhere = await fixture(t, 'else')
  await write(elsewhere, 'mod.py')
  const pyc = await write(elsewhere, '__pycache__/mod.cpython-312.pyc')
  const ev = makeEvidence(boundary)
  const outsideProject = await ev.verify({ absolute: pyc, projectRoot: proj, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(outsideProject.eligible, false)
  assert.match(outsideProject.reason, /outside-project/)
  const outsideBoundary = await ev.verify({ absolute: pyc, projectRoot: elsewhere, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(outsideBoundary.eligible, false)
  assert.match(outsideBoundary.reason, /outside-boundary/)
})

test('non-Git project: untracked pyc WITH paired source is eligible', async (t) => {
  const root = await fixture(t, 'nongit-src')
  await write(root, 'pkg/mod.py')
  const pyc = await write(root, 'pkg/__pycache__/mod.cpython-312.pyc')
  const ev = makeEvidence(root)
  const r = await ev.verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(r.eligible, true, JSON.stringify(r))
})

test('non-Git project: pyc WITHOUT paired source is not exempted (sourceless)', async (t) => {
  const root = await fixture(t, 'nongit-nosrc')
  const pyc = await write(root, 'pkg/__pycache__/mod.cpython-312.pyc')
  const ev = makeEvidence(root)
  const r = await ev.verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(r.eligible, false)
  assert.match(r.reason, /py-source-missing/)
})

test('Python opt-N bytecode maps to the same stem source', async (t) => {
  const root = await fixture(t, 'pyopt')
  await write(root, 'mod.py')
  const pyc = await write(root, '__pycache__/mod.cpython-312.opt-2.pyc')
  const r = await makeEvidence(root).verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(r.eligible, true)
})

test('Git-tracked pyc is NEVER exempted; after untracking it becomes eligible', async (t) => {
  const root = await fixture(t, 'git-tracked')
  gitInit(root)
  await write(root, '.gitignore', '*.pyc\n__pycache__/\n')
  await write(root, 'mod.py')
  const pycDir = path.join(root, '__pycache__')
  await fs.mkdir(pycDir, { recursive: true })
  const pyc = path.join(pycDir, 'mod.cpython-312.pyc')
  await fs.writeFile(pyc, 'x')
  // Force-add the pyc to the index despite .gitignore.
  execFileSync('git', ['-C', root, 'add', '-f', '__pycache__/mod.cpython-312.pyc'], { stdio: 'ignore' })
  const ev = makeEvidence(root)
  const tracked = await ev.verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(tracked.eligible, false)
  assert.match(tracked.reason, /git-tracked/)

  // New evidence instance so the per-plan tracked-set cache is fresh after untracking.
  execFileSync('git', ['-C', root, 'rm', '--cached', '-q', '__pycache__/mod.cpython-312.pyc'], { stdio: 'ignore' })
  const ev2 = makeEvidence(root)
  const untracked = await ev2.verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(untracked.eligible, true, JSON.stringify(untracked))
})

test('unknown Git state (unreadable repository) is never exempted', async (t) => {
  const root = await fixture(t, 'git-broken')
  await write(root, 'mod.py')
  const pyc = await write(root, '__pycache__/mod.cpython-312.pyc')
  // A `.git` entry that is a broken file pointer makes rev-parse fail => unknown.
  await fs.writeFile(path.join(root, '.git'), 'gitdir: /nonexistent/definitely-not-a-repo\n')
  const ev = makeEvidence(root)
  const r = await ev.verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(r.eligible, false)
  assert.match(r.reason, /git-unknown/)
})

test('Maven: class with corresponding standard .java source is eligible; nested $ maps to outer', async (t) => {
  const root = await fixture(t, 'maven')
  await write(root, 'src/main/java/com/acme/Widget.java')
  const outer = await write(root, 'target/classes/com/acme/Widget.class')
  const nested = await write(root, 'target/classes/com/acme/Widget$Inner.class')
  const ev = makeEvidence(root)
  assert.equal((await ev.verify({ absolute: outer, projectRoot: root, projectMarkers: ['pom.xml'], ruleId: 'maven-class-file' })).eligible, true)
  assert.equal((await ev.verify({ absolute: nested, projectRoot: root, projectMarkers: ['pom.xml'], ruleId: 'maven-class-file' })).eligible, true)
})

test('Maven: unsupported layout / wrong package path counts normally', async (t) => {
  const root = await fixture(t, 'maven-bad')
  await write(root, 'src/main/java/com/acme/Widget.java')
  // Wrong package path for the class.
  const wrong = await write(root, 'target/classes/com/other/Widget.class')
  // No source at all for a different class.
  const orphan = await write(root, 'target/classes/com/acme/Orphan.class')
  const ev = makeEvidence(root)
  assert.equal((await ev.verify({ absolute: wrong, projectRoot: root, projectMarkers: ['pom.xml'], ruleId: 'maven-class-file' })).eligible, false)
  assert.equal((await ev.verify({ absolute: orphan, projectRoot: root, projectMarkers: ['pom.xml'], ruleId: 'maven-class-file' })).eligible, false)
})

test('TS: incremental tsconfig default derivation is eligible', async (t) => {
  const root = await fixture(t, 'ts-default')
  await write(root, 'tsconfig.json', JSON.stringify({ compilerOptions: { incremental: true, outDir: './lib' } }))
  const info = await write(root, 'lib/tsconfig.tsbuildinfo')
  const ev = makeEvidence(root)
  const r = await ev.verify({ absolute: info, projectRoot: root, projectMarkers: ['tsconfig.json'], ruleId: 'ts-buildinfo-file' })
  assert.equal(r.eligible, true, JSON.stringify(r))
})

test('TS: explicit tsBuildInfoFile custom location inside project is eligible', async (t) => {
  const root = await fixture(t, 'ts-custom')
  await write(root, 'tsconfig.json', JSON.stringify({ compilerOptions: { incremental: true, tsBuildInfoFile: './cache/front-end.tsbuildinfo' } }))
  const info = await write(root, 'cache/front-end.tsbuildinfo')
  const ev = makeEvidence(root)
  // tsconfig is at project root; artifact is under cache/ (an ancestor scan reaches root).
  const r = await ev.verify({ absolute: info, projectRoot: root, projectMarkers: ['tsconfig.json'], ruleId: 'ts-buildinfo-file' })
  assert.equal(r.eligible, true, JSON.stringify(r))
})

test('TS: wrong path / non-derived suffix counts normally', async (t) => {
  const root = await fixture(t, 'ts-wrong')
  await write(root, 'tsconfig.json', JSON.stringify({ compilerOptions: { incremental: true, outDir: './lib' } }))
  const stray = await write(root, 'other/random.tsbuildinfo')
  const ev = makeEvidence(root)
  const r = await ev.verify({ absolute: stray, projectRoot: root, projectMarkers: ['tsconfig.json'], ruleId: 'ts-buildinfo-file' })
  assert.equal(r.eligible, false)
  assert.match(r.reason, /ts-config-not-derivable/)
})

test('TS: unsupported config (extends) is not exempted; JSONC rejected', async (t) => {
  const root = await fixture(t, 'ts-unsupported')
  await write(root, 'tsconfig.json', JSON.stringify({ extends: './base.json', compilerOptions: { incremental: true } }))
  const info = await write(root, 'tsconfig.tsbuildinfo')
  const ev = makeEvidence(root)
  assert.equal((await ev.verify({ absolute: info, projectRoot: root, projectMarkers: ['tsconfig.json'], ruleId: 'ts-buildinfo-file' })).eligible, false)

  const root2 = await fixture(t, 'ts-jsonc')
  await write(root2, 'tsconfig.json', '{ // comment\n "compilerOptions": { "incremental": true }\n}\n')
  const info2 = await write(root2, 'tsconfig.tsbuildinfo')
  const ev2 = makeEvidence(root2)
  assert.equal((await ev2.verify({ absolute: info2, projectRoot: root2, projectMarkers: ['tsconfig.json'], ruleId: 'ts-buildinfo-file' })).eligible, false)
})

test('TS: not incremental/composite => not derived', async (t) => {
  const root = await fixture(t, 'ts-nonincr')
  await write(root, 'tsconfig.json', JSON.stringify({ compilerOptions: {} }))
  const info = await write(root, 'tsconfig.tsbuildinfo')
  const ev = makeEvidence(root)
  assert.equal((await ev.verify({ absolute: info, projectRoot: root, projectMarkers: ['tsconfig.json'], ruleId: 'ts-buildinfo-file' })).eligible, false)
})

test('pytest/mypy cache state: eligible when not tracked and contained', async (t) => {
  const root = await fixture(t, 'cachestate')
  const nodeids = await write(root, '.pytest_cache/v/cache/nodeids')
  const mypy = await write(root, '.mypy_cache/3.12/mod.data.json')
  const ev = makeEvidence(root)
  assert.equal((await ev.verify({ absolute: nodeids, projectRoot: root, projectMarkers: ['pytest.ini'], ruleId: 'pytest-cache-file' })).eligible, true)
  assert.equal((await ev.verify({ absolute: mypy, projectRoot: root, projectMarkers: ['mypy.ini'], ruleId: 'mypy-cache-file' })).eligible, true)
})

test('unknown ruleId counts normally', async (t) => {
  const root = await fixture(t, 'unknownrule')
  const f = await write(root, 'whatever.cache')
  const ev = makeEvidence(root)
  const r = await ev.verify({ absolute: f, projectRoot: root, projectMarkers: [], ruleId: 'cargo-dep-file' })
  assert.equal(r.eligible, false)
  assert.match(r.reason, /unsupported-rule|unknown-rule/)
})

test('a symlink at the artifact path is not exempted (link escape / not regular)', async (t) => {
  const root = await fixture(t, 'link')
  const outside = await fixture(t, 'link-out')
  await write(outside, 'mod.py')
  const realPyc = await write(outside, '__pycache__/mod.cpython-312.pyc')
  const linkPath = path.join(root, '__pycache__', 'mod.cpython-312.pyc')
  await fs.mkdir(path.dirname(linkPath), { recursive: true })
  try {
    await fs.symlink(realPyc, linkPath, 'file')
  } catch (error) {
    t.skip(`symlink unavailable: ${error.code}`)
    return
  }
  const ev = makeEvidence(root)
  const r = await ev.verify({ absolute: linkPath, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(r.eligible, false)
  assert.match(r.reason, /link-escape|not-regular/)
})

test('exhausted budget never creates an exemption', async (t) => {
  const root = await fixture(t, 'budget')
  await write(root, 'mod.py')
  const pyc = await write(root, '__pycache__/mod.cpython-312.pyc')
  const ev = makeEvidence(root, { budget: 0 })
  const r = await ev.verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(r.eligible, false)
  assert.match(r.reason, /budget/)
})

test('expired deadline never creates an exemption', async (t) => {
  const root = await fixture(t, 'budget2')
  await write(root, 'mod.py')
  const pyc = await write(root, '__pycache__/mod.cpython-312.pyc')
  const ev = makeEvidence(root, { deadlineAt: Date.now() - 1000 })
  const r = await ev.verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(r.eligible, false)
  assert.match(r.reason, /budget/)
})

test('programming errors surface (missing required args throw)', async (t) => {
  const root = await fixture(t, 'args')
  assert.throws(() => createDisposableEvidence({ boundary: 'relative', consume: () => true }), TypeError)
  assert.throws(() => createDisposableEvidence({ boundary: root }), TypeError)
  const ev = makeEvidence(root)
  await assert.rejects(() => ev.verify({ projectRoot: root, ruleId: 'py-pyc-file' }), TypeError)
})

test('monorepo: subproject tracked by a PARENT repo (VCS root outside boundary) is not exempted', async (t) => {
  // parent repo (outside the project boundary) tracks a subproject under it.
  const parent = await fixture(t, 'mono')
  gitInit(parent)
  await write(parent, 'readme.txt', 'x')
  execFileSync('git', ['-C', parent, 'add', 'readme.txt'], { stdio: 'ignore' })
  const sub = path.join(parent, 'packages', 'app')
  await write(sub, 'mod.py')
  const pyc = await write(sub, '__pycache__/mod.cpython-312.pyc')
  execFileSync('git', ['-C', parent, 'add', '-f', 'packages/app/__pycache__/mod.cpython-312.pyc'], { stdio: 'ignore' })

  // Boundary is the SUBPROJECT only; its VCS root (parent) is outside the boundary.
  const ev = makeEvidence(sub)
  const tracked = await ev.verify({ absolute: pyc, projectRoot: sub, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(tracked.eligible, false, JSON.stringify(tracked))
  assert.match(tracked.reason, /git-tracked/)

  // Remove from the parent index: now untracked within a Git repo => source evidence applies.
  execFileSync('git', ['-C', parent, 'rm', '--cached', '-q', 'packages/app/__pycache__/mod.cpython-312.pyc'], { stdio: 'ignore' })
  const ev2 = makeEvidence(sub)
  const untracked = await ev2.verify({ absolute: pyc, projectRoot: sub, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(untracked.eligible, true, JSON.stringify(untracked))
})

// --- hardening fixes (git literal pathspec, casefold, maven, ts rootDir, excluded words) ---

test('git pathspec is literal: a project dir with [brackets] does not drop tracked files', async (t) => {
  // Repo root contains a subdir literally named "pkg[1]". Without --literal-pathspecs the
  // pathspec "pkg[1]" would be a glob and could return an empty tracked list, wrongly
  // reporting a tracked pyc as untracked.
  const parent = await fixture(t, 'glob')
  gitInit(parent)
  await write(parent, 'readme.txt')
  execFileSync('git', ['-C', parent, 'add', 'readme.txt'], { stdio: 'ignore' })
  const sub = path.join(parent, 'pkg[1]')
  await write(sub, 'mod.py')
  const pyc = await write(sub, '__pycache__/mod.cpython-312.pyc')
  execFileSync('git', ['-C', parent, 'add', '-f', 'pkg[1]/__pycache__/mod.cpython-312.pyc'], { stdio: 'ignore' })

  const ev = makeEvidence(sub)
  const r = await ev.verify({ absolute: pyc, projectRoot: sub, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(r.eligible, false, JSON.stringify(r))
  assert.match(r.reason, /git-tracked/)
})

test('git tracked comparison is Windows-casefolded: index casing vs disk casing still tracked', { skip: process.platform !== 'win32' && 'Windows case-fold rule' }, async (t) => {
  const root = await fixture(t, 'case')
  gitInit(root)
  await write(root, 'mod.py')
  const pyc = await write(root, '__pycache__/mod.cpython-312.pyc')
  // Add with a different component casing than the on-disk fixture path.
  execFileSync('git', ['-C', root, 'add', '-f', '__PYCACHE__/mod.cpython-312.pyc'], { stdio: 'ignore' })
  const ev = makeEvidence(root)
  const r = await ev.verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(r.eligible, false, JSON.stringify(r))
  assert.match(r.reason, /git-tracked/)
})

test('Maven default package (target/classes/App.class) maps to src/main/java/App.java', async (t) => {
  const root = await fixture(t, 'mvn-default')
  await write(root, 'src/main/java/App.java')
  const cls = await write(root, 'target/classes/App.class')
  const ev = makeEvidence(root)
  const r = await ev.verify({ absolute: cls, projectRoot: root, projectMarkers: ['pom.xml'], ruleId: 'maven-class-file' })
  assert.equal(r.eligible, true, JSON.stringify(r))
})

test('Maven bucket is strict: a classes/ artifact does not resolve to src/test/java source', async (t) => {
  const root = await fixture(t, 'mvn-strict')
  await write(root, 'src/test/java/com/acme/Widget.java') // only a TEST source exists
  const cls = await write(root, 'target/classes/com/acme/Widget.class') // main-classes artifact
  const ev = makeEvidence(root)
  const r = await ev.verify({ absolute: cls, projectRoot: root, projectMarkers: ['pom.xml'], ruleId: 'maven-class-file' })
  assert.equal(r.eligible, false, JSON.stringify(r))
})

test('Maven source dir symlinked outside the project does not qualify', async (t) => {
  const root = await fixture(t, 'mvn-link')
  const outside = await fixture(t, 'mvn-out')
  await write(outside, 'com/acme/Widget.java')
  const cls = await write(root, 'target/classes/com/acme/Widget.class')
  // src/main is a symlink to the outside dir: the standard source path escapes the project.
  await fs.mkdir(path.join(root, 'src'), { recursive: true })
  try {
    await fs.symlink(outside, path.join(root, 'src', 'main'), 'dir')
  } catch (error) {
    t.skip(`symlink unavailable: ${error.code}`)
    return
  }
  const ev = makeEvidence(root)
  const r = await ev.verify({ absolute: cls, projectRoot: root, projectMarkers: ['pom.xml'], ruleId: 'maven-class-file' })
  assert.equal(r.eligible, false, JSON.stringify(r))
})

test('TS official formula: rootDir+outDir => <outDir>/<relative config path from rootDir>/<config>.tsbuildinfo', async (t) => {
  // Official example: rootDir=src, outDir=dest, config=./tsconfig.json.
  // relative path from src/ to ./tsconfig.json is '../', so the default is
  // dest/../tsconfig.tsbuildinfo = ./tsconfig.tsbuildinfo (NOT inside dest).
  const root = await fixture(t, 'ts-rootdir-official')
  await write(root, 'tsconfig.json', JSON.stringify({ compilerOptions: { rootDir: './src', outDir: './dest', incremental: true } }))
  const correct = await write(root, 'tsconfig.tsbuildinfo') // alongside config (per formula)
  const ev = makeEvidence(root)
  assert.equal((await ev.verify({ absolute: correct, projectRoot: root, projectMarkers: ['tsconfig.json'], ruleId: 'ts-buildinfo-file' })).eligible, true)
  // The naive-but-wrong location inside dest must NOT be accepted.
  const wrong = await write(root, 'dest/tsconfig.tsbuildinfo')
  const ev2 = makeEvidence(root)
  assert.equal((await ev2.verify({ absolute: wrong, projectRoot: root, projectMarkers: ['tsconfig.json'], ruleId: 'ts-buildinfo-file' })).eligible, false)
})

test('TS: rootDir nested deeper relocates the build info under <outDir>/<rel>, not config-adjacent', async (t) => {
  // Config at project root; rootDir=./src; outDir=./dest; relative(src -> root) = '..',
  // so build info = dest/../tsconfig.tsbuildinfo = ./tsconfig.tsbuildinfo. But if config
  // lives in a subdir under rootDir, relative is a real subpath. Verify that subpath form.
  const root = await fixture(t, 'ts-rootdir-sub')
  // config at packages/app/tsconfig.json, rootDir packages (relative to config dir),
  // outDir dist => relative(packages/app? ) Let's use rootDir '..' relative to config.
  await write(root, 'packages/app/tsconfig.json', JSON.stringify({ compilerOptions: { rootDir: '..', outDir: './dist', incremental: true } }))
  // relative(rootDirAbs, configAbs): rootDir=packages, config=packages/app => rel='app'
  // build info = packages/app/dist/app/tsconfig.tsbuildinfo
  const correct = await write(root, 'packages/app/dist/app/tsconfig.tsbuildinfo')
  const ev = makeEvidence(root)
  const r = await ev.verify({ absolute: correct, projectRoot: root, projectMarkers: ['tsconfig.json'], ruleId: 'ts-buildinfo-file' })
  assert.equal(r.eligible, true, JSON.stringify(r))
})

test('TS: outFile without explicit tsBuildInfoFile is NOT exempted (both auto-candidate forms); explicit override still eligible', async (t) => {
  // The default outFile-derived name is ambiguous in official docs; we do not guess.
  const root = await fixture(t, 'ts-outfile')
  await write(root, 'tsconfig.json', JSON.stringify({ compilerOptions: { outFile: './out/bundle.js', incremental: true } }))
  for (const rel of ['out/bundle.js.tsbuildinfo', 'out/bundle.tsbuildinfo']) {
    const candidate = await write(root, rel)
    const ev = makeEvidence(root)
    assert.equal((await ev.verify({ absolute: candidate, projectRoot: root, projectMarkers: ['tsconfig.json'], ruleId: 'ts-buildinfo-file' })).eligible, false, rel)
  }
  // Explicit tsBuildInfoFile override (with outFile also set) IS supported.
  const root2 = await fixture(t, 'ts-outfile-explicit')
  await write(root2, 'tsconfig.json', JSON.stringify({ compilerOptions: { outFile: './out/bundle.js', tsBuildInfoFile: './out/custom.tsbuildinfo', incremental: true } }))
  const explicit = await write(root2, 'out/custom.tsbuildinfo')
  const ev2 = makeEvidence(root2)
  assert.equal((await ev2.verify({ absolute: explicit, projectRoot: root2, projectMarkers: ['tsconfig.json'], ruleId: 'ts-buildinfo-file' })).eligible, true)

  const root3 = await fixture(t, 'ts-badtype')
  await write(root3, 'tsconfig.json', JSON.stringify({ compilerOptions: { outDir: 123, incremental: true } }))
  const info3 = await write(root3, '123/tsconfig.tsbuildinfo')
  const ev3 = makeEvidence(root3)
  assert.equal((await ev3.verify({ absolute: info3, projectRoot: root3, projectMarkers: ['tsconfig.json'], ruleId: 'ts-buildinfo-file' })).eligible, false)
})

test('excluded words are case-insensitive on all platforms; Java package vendor/backup inside target/classes is allowed', async (t) => {
  // A pyc inside "BACKUP" (uppercase) must not be exempted even on POSIX.
  const root = await fixture(t, 'excl-case')
  await write(root, 'BACKUP/mod.py')
  const pyc = await write(root, 'BACKUP/__pycache__/mod.cpython-312.pyc')
  const ev = makeEvidence(root)
  const excluded = await ev.verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(excluded.eligible, false)
  assert.match(excluded.reason, /excluded-domain/)

  // A legitimate Java package literally named `vendor`/`backup` INSIDE target/classes is OK.
  const jroot = await fixture(t, 'java-vendor')
  await write(jroot, 'src/main/java/com/vendor/backup/Widget.java')
  const cls = await write(jroot, 'target/classes/com/vendor/backup/Widget.class')
  const jev = makeEvidence(jroot)
  const jr = await jev.verify({ absolute: cls, projectRoot: jroot, projectMarkers: ['pom.xml'], ruleId: 'maven-class-file' })
  assert.equal(jr.eligible, true, JSON.stringify(jr))
})

test('budget exhaustion during verification never creates an exemption (control: generous budget eligible)', async (t) => {
  const root = await fixture(t, 'budget-mid')
  await write(root, 'mod.py')
  const pyc = await write(root, '__pycache__/mod.cpython-312.pyc')
  // Control: with ample budget this fixture IS eligible, proving the low-budget false is
  // caused by exhaustion, not by an unrelated failure.
  const ok = await makeEvidence(root, { budget: 100000 }).verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(ok.eligible, true, JSON.stringify(ok))
  // Exhausted budget of 1 unit: cannot even complete, must not exempt.
  const exhausted = await makeEvidence(root, { budget: 1 }).verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(exhausted.eligible, false, JSON.stringify(exhausted))
})

test('a throwing consume() surfaces as a programming error (not a silent non-exemption)', async (t) => {
  const root = await fixture(t, 'throw')
  await write(root, 'mod.py')
  const pyc = await write(root, '__pycache__/mod.cpython-312.pyc')
  const ev = createDisposableEvidence({ boundary: root, consume: () => { throw new Error('boom') } })
  await assert.rejects(() => ev.verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' }), /boom/)
})

test('containment is case-sensitive: a differently-cased boundary does not grant an exemption', async (t) => {
  const root = await fixture(t, 'case-contain')
  await write(root, 'mod.py')
  const pyc = await write(root, '__pycache__/mod.cpython-312.pyc')
  // A boundary that differs ONLY in case (e.g. uppercasing a directory component) must
  // not be treated as containing the real project on a case-sensitive-NTFS assumption.
  // Build a boundary string by altering the final directory component's case.
  const parent = path.dirname(root)
  const leaf = path.basename(root)
  const upper = leaf.toUpperCase()
  if (upper === leaf) { t.skip('leaf already uppercase'); return }
  const oddBoundary = path.join(parent, upper)
  // The uppercased boundary does not exist; even if it did, containment must be exact.
  const ev = makeEvidence(oddBoundary)
  const r = await ev.verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })
  assert.equal(r.eligible, false, JSON.stringify(r))
  assert.match(r.reason, /outside-boundary/)
  // Control: the exact-case boundary (real path) IS eligible with a source file present.
  const okEv = makeEvidence(root)
  assert.equal((await okEv.verify({ absolute: pyc, projectRoot: root, projectMarkers: ['pyproject.toml'], ruleId: 'py-pyc-file' })).eligible, true)
})
