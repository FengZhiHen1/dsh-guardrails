// Unit tests for src/core/disposable.js — conservative, project-bound
// recognition of disposable build/cache FILES. Synthetic path shapes only; no
// filesystem IO. Only regular files are ever disposable: directory entries
// never reduce the deletion count.
//
// v2 hardening: archive/dependency prefixes are not exemption domains; Python
// pyc stems must be strict dotted identifiers; Cargo dependency artifacts are
// no longer auto-exempt (they now count normally).

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  classifyDisposable,
  PROJECT_MARKERS,
  EXCLUDED_DISPOSABLE_SEGMENTS,
} from '../src/core/disposable.js'

const PY = ['pyproject.toml']
const PYTEST = ['pyproject.toml', 'pytest.ini']
const MY = ['mypy.ini', 'pyproject.toml']
const MAVEN = ['pom.xml']
const TS = ['tsconfig.json']
const TS_ONLY = ['tsconfig.json']
const JS_ONLY = ['package.json']
const RUST = ['Cargo.toml']

const disposable = (relativePath, projectMarkers, isDirectory = false) =>
  classifyDisposable({ relativePath, projectMarkers, isDirectory })
const isDisposable = (relativePath, projectMarkers, isDirectory = false) =>
  classifyDisposable({ relativePath, projectMarkers, isDirectory }).disposable
const ruleOf = (relativePath, projectMarkers) =>
  classifyDisposable({ relativePath, projectMarkers }).ruleId

test('exports a plain string[] PROJECT_MARKERS list (no package.json)', () => {
  assert.ok(Array.isArray(PROJECT_MARKERS))
  assert.ok(PROJECT_MARKERS.every((m) => typeof m === 'string' && !m.includes('/')))
  for (const m of ['pyproject.toml', 'pytest.ini', 'mypy.ini', 'pom.xml', 'tsconfig.json']) {
    assert.ok(PROJECT_MARKERS.includes(m), `missing ${m}`)
  }
  assert.equal(PROJECT_MARKERS.includes('package.json'), false, 'package.json is not a marker')
  // Cargo.toml is retained as a project-BOUNDARY marker even though it gates no
  // rule this round (so nested Rust projects do not inherit outer markers).
  assert.equal(PROJECT_MARKERS.includes('Cargo.toml'), true, 'Cargo.toml is a boundary marker')
})

test('Cargo.toml marker presence never grants an exemption by itself', () => {
  // With ONLY the Cargo boundary marker present, nothing becomes disposable:
  // no pyc/pytest/mypy/maven/ts rule fires, and Cargo artifacts count normally.
  assert.equal(isDisposable('__pycache__/mod.cpython-312.pyc', RUST), false)
  assert.equal(isDisposable('.pytest_cache/v/cache/nodeids', RUST), false)
  assert.equal(isDisposable('.mypy_cache/3.12/mod.data.json', RUST), false)
  assert.equal(isDisposable('target/classes/App.class', RUST), false)
  assert.equal(isDisposable('tsconfig.tsbuildinfo', RUST), false)
  assert.equal(isDisposable('target/debug/deps/foo-deadbeef.rlib', RUST), false)
})

test('exports an immutable EXCLUDED_DISPOSABLE_SEGMENTS covering archive/dependency domains', () => {
  assert.ok(Array.isArray(EXCLUDED_DISPOSABLE_SEGMENTS))
  assert.ok(Object.isFrozen(EXCLUDED_DISPOSABLE_SEGMENTS))
  for (const s of ['backup', 'backups', 'archive', 'archives', 'snapshot', 'snapshots', 'node_modules', 'vendor', 'third_party', '.git']) {
    assert.ok(EXCLUDED_DISPOSABLE_SEGMENTS.includes(s), `missing ${s}`)
  }
  // build/dist are intentionally NOT banned (valid TS output can live there).
  assert.equal(EXCLUDED_DISPOSABLE_SEGMENTS.includes('build'), false)
  assert.equal(EXCLUDED_DISPOSABLE_SEGMENTS.includes('dist'), false)
})

test('python bytecode files are disposable, with optional PEP 488 opt tag', () => {
  assert.equal(ruleOf('__pycache__/mod.cpython-312.pyc', PY), 'py-pyc-file')
  assert.equal(ruleOf('src/pkg/__pycache__/mod.cpython-311.pyc', PY), 'py-pyc-file')
  assert.equal(ruleOf('__pycache__/mod.cpython-312.opt-1.pyc', PY), 'py-pyc-file')
  assert.equal(ruleOf('__pycache__/mod.cpython-312.opt-2.pyc', PY), 'py-pyc-file')
  // dotted module stems are fine when each segment is a Python identifier
  assert.equal(ruleOf('__pycache__/a.b.cpython-310.pyc', PY), 'py-pyc-file')
})

test('python bytecode requires a python marker and a strict stem shape', () => {
  assert.equal(isDisposable('__pycache__/mod.cpython-312.pyc', []), false)
  assert.equal(isDisposable('__pycache__/mod.cpython-312.pyc', JS_ONLY), false)
  // tag-less, non-pyc, wrong parent, outside __pycache__ are not matched
  assert.equal(isDisposable('__pycache__/mod.pyc', PY), false)
  assert.equal(isDisposable('__pycache__/notes.txt', PY), false)
  assert.equal(isDisposable('src/mod.cpython-312.pyc', PY), false)
  assert.equal(isDisposable('__pycache__/mod.opt-1.pyc', PY), false) // no cpython tag
  // v2: stem must be strict dotted identifiers — reject odd stems.
  assert.equal(isDisposable('__pycache__/mod-name.cpython-312.pyc', PY), false)
  assert.equal(isDisposable('__pycache__/mod+extra.cpython-312.pyc', PY), false)
  assert.equal(isDisposable('__pycache__/a..b.cpython-312.pyc', PY), false) // empty segment
  assert.equal(isDisposable('__pycache__/.hidden.cpython-312.pyc', PY), false) // leading empty seg
})

test('pytest cache state files under .pytest_cache/v/cache are disposable', () => {
  assert.equal(ruleOf('.pytest_cache/v/cache/nodeids', PYTEST), 'pytest-cache-file')
  assert.equal(ruleOf('.pytest_cache/v/cache/lastfailed', PYTEST), 'pytest-cache-file')
  assert.equal(ruleOf('.pytest_cache/v/cache/stepwise', PYTEST), 'pytest-cache-file')
  // other names in the cache directory (e.g. README.md, CACHEDIR.TAG) are NOT exempt
  assert.equal(isDisposable('.pytest_cache/v/cache/README.md', PYTEST), false)
  assert.equal(isDisposable('.pytest_cache/CACHEDIR.TAG', PYTEST), false)
  assert.equal(isDisposable('.pytest_cache/v/cache/random', PYTEST), false)
  // wrong depth / marker
  assert.equal(isDisposable('.pytest_cache/v/cache/nodeids', []), false)
  assert.equal(isDisposable('sub/.pytest_cache/v/cache/nodeids', PYTEST), false)
})

test('mypy cache json files under .mypy_cache/<version>/ are disposable', () => {
  assert.equal(ruleOf('.mypy_cache/3.12/mod.data.json', MY), 'mypy-cache-file')
  assert.equal(ruleOf('.mypy_cache/3.12/mod.meta.json', MY), 'mypy-cache-file')
  assert.equal(ruleOf('.mypy_cache/3.11/pkg/sub/mod.data.json', MY), 'mypy-cache-file')
  // CACHEDIR.TAG and other files are not matched
  assert.equal(isDisposable('.mypy_cache/3.12/CACHEDIR.TAG', MY), false)
  assert.equal(isDisposable('.mypy_cache/3.12/mod.txt', MY), false)
  // version dir must be <major>.<minor>; needs mypy marker
  assert.equal(isDisposable('.mypy_cache/latest/mod.data.json', MY), false)
  assert.equal(isDisposable('.mypy_cache/3.12/mod.data.json', JS_ONLY), false)
})

test('maven compiled class files under target/{classes,test-classes} are disposable', () => {
  assert.equal(ruleOf('target/classes/com/acme/App.class', MAVEN), 'maven-class-file')
  assert.equal(ruleOf('target/test-classes/com/acme/AppTest.class', MAVEN), 'maven-class-file')
  assert.equal(ruleOf('target/classes/App.class', MAVEN), 'maven-class-file')
  // v2: nested $ classes still map to outer source at adapter; matcher accepts them.
  assert.equal(ruleOf('target/classes/com/acme/Outer$Inner.class', MAVEN), 'maven-class-file')
  // non-class files, other target subdirs, missing marker
  assert.equal(isDisposable('target/classes/App.java', MAVEN), false)
  assert.equal(isDisposable('target/maven-status/foo.txt', MAVEN), false)
  assert.equal(isDisposable('target/classes/App.class', JS_ONLY), false)
  // a directory named *.class is not a file (isDirectory => false anyway)
  assert.equal(isDisposable('target/classes/App.class', MAVEN, true), false)
})

test('v2: Java package segments inside target/classes are NOT banned as archive prefixes', () => {
  // A legitimate Java package named "archive", "vendor", "backup", "snapshot"
  // below target/classes must still be exempt (not an archive/prefix directory).
  assert.equal(ruleOf('target/classes/com/archive/App.class', MAVEN), 'maven-class-file')
  assert.equal(ruleOf('target/classes/com/vendor/util/Helper.class', MAVEN), 'maven-class-file')
  assert.equal(ruleOf('target/test-classes/backup/Snapshot$1.class', MAVEN), 'maven-class-file')
})

test('v2: a path nested under an archive/dependency prefix above the artifact is NOT exempt', () => {
  // Archive/dependency domains are not exemption domains even with a marker.
  for (const prefix of ['backup', 'backups', 'archive', 'archives', 'snapshot', 'snapshots', 'node_modules', 'vendor', 'third_party', '.git']) {
    assert.equal(
      isDisposable(`${prefix}/__pycache__/mod.cpython-312.pyc`, PY),
      false,
      `${prefix}/ must block pyc`,
    )
    assert.equal(
      isDisposable(`${prefix}/.pytest_cache/v/cache/nodeids`, PYTEST),
      false,
      `${prefix}/ must block pytest cache`,
    )
    assert.equal(
      isDisposable(`${prefix}/x.tsbuildinfo`, TS),
      false,
      `${prefix}/ must block tsbuildinfo`,
    )
  }
  // case-insensitive
  assert.equal(isDisposable('Backup/__pycache__/mod.cpython-312.pyc', PY), false)
  assert.equal(isDisposable('NODE_MODULES/x.tsbuildinfo', TS), false)
  // But build/dist are allowed (valid TS output can live there).
  assert.equal(ruleOf('dist/app.tsbuildinfo', TS), 'ts-buildinfo-file')
  assert.equal(ruleOf('build/app.tsbuildinfo', TS), 'ts-buildinfo-file')
})

test('v2: Cargo dependency artifacts are NO LONGER auto-exempt (they count normally)', () => {
  // Old rules would have matched these; the Cargo rule is removed this round.
  assert.equal(isDisposable('target/debug/deps/libfoo-1a2b3c4d5e6f7a8b.rlib', RUST), false)
  assert.equal(isDisposable('target/release/deps/foo-0123456789abcdef.rmeta', RUST), false)
  assert.equal(isDisposable('target/debug/deps/foo-deadbeef.d', RUST), false)
  // Even with no Cargo marker they are ordinary files (not matched, not denied).
  assert.equal(isDisposable('target/debug/deps/foo-deadbeef.rlib', []), false)
  // The old negative assertions still hold (wrong profile/dir/ext never matched).
  assert.equal(isDisposable('target/custom/deps/foo-deadbeef.rlib', RUST), false)
  assert.equal(isDisposable('target/debug/build/foo-deadbeef.rlib', RUST), false)
  assert.equal(isDisposable('target/debug/deps/foo.rlib', RUST), false)
  assert.equal(isDisposable('target/debug/deps/foo-deadbeef.o', RUST), false)
  // Maven target/classes still works and is not confused with Cargo target/deps.
  assert.equal(ruleOf('target/classes/App.class', MAVEN), 'maven-class-file')
})

test('typescript .tsbuildinfo files are disposable with tsconfig marker', () => {
  assert.equal(ruleOf('tsconfig.tsbuildinfo', TS), 'ts-buildinfo-file')
  assert.equal(ruleOf('tsconfig.tsbuildinfo', TS_ONLY), 'ts-buildinfo-file')
  assert.equal(ruleOf('packages/app/tsconfig.app.tsbuildinfo', TS), 'ts-buildinfo-file')
  assert.equal(ruleOf('dist/tsconfig.tsbuildinfo', TS), 'ts-buildinfo-file')
  // requires a tsconfig marker; package.json alone is not enough
  assert.equal(isDisposable('tsconfig.tsbuildinfo', JS_ONLY), false)
  assert.equal(isDisposable('tsconfig.tsbuildinfo', []), false)
  assert.equal(isDisposable('src/app.ts', TS), false)
})

test('this is a FILE whitelist: directory entries are never disposable', () => {
  const all = PROJECT_MARKERS.slice()
  for (const name of ['__pycache__', '.pytest_cache', '.mypy_cache', 'target', 'target/classes', 'target/debug/deps', 'dist', 'build', 'node_modules', '.git']) {
    assert.equal(isDisposable(name, all, true), false, `dir ${name} must not be exempt`)
  }
})

test('broad trees and out-of-scope ecosystems are not exempted by name', () => {
  const all = PROJECT_MARKERS.slice()
  for (const name of ['dist', 'build', 'out', 'tmp', 'logs', 'backup', 'vendor', 'node_modules', '.git', 'coverage']) {
    assert.equal(isDisposable(`${name}/file.bin`, all, false), false, `file under ${name} must not be exempt`)
  }
  // Gradle/Go/PHP outputs are not in scope
  assert.equal(isDisposable('build/classes/Main.class', ['build.gradle'], false), false)
  assert.equal(isDisposable('bin/app', ['go.mod'], false), false)
})

test('camouflaged user files inside cache-looking paths are not exempted', () => {
  assert.equal(isDisposable('.env', PY), false)
  assert.equal(isDisposable('src/secret.py', PY), false)
  assert.equal(isDisposable('__pycache__/../../.ssh/id_rsa', PY), false)
  assert.equal(isDisposable('__pycache__/.npmrc', PY), false)
  // a user file mimicking a maven class in the wrong location
  assert.equal(isDisposable('src/App.class', MAVEN), false)
})

test('absolute paths, drive roots and traversal are rejected', () => {
  for (const bad of [
    '/etc/passwd',
    'C:/Windows/System32',
    'C:\\Windows\\System32\\x.pyc',
    '\\\\server\\share\\x.pyc',
    '../outside/x.pyc',
    'a/../../b/x.pyc',
    '__pycache__/../../evil.cpython-312.pyc',
  ]) {
    assert.equal(isDisposable(bad, PY), false, `reject ${bad}`)
  }
})

test('empty / unsafe / non-string inputs return { disposable:false } without throwing', () => {
  assert.deepEqual(classifyDisposable({}), { disposable: false })
  assert.deepEqual(classifyDisposable({ relativePath: '' }), { disposable: false })
  assert.deepEqual(classifyDisposable({ relativePath: null }), { disposable: false })
  assert.deepEqual(classifyDisposable({ relativePath: 42 }), { disposable: false })
  assert.deepEqual(classifyDisposable({ relativePath: '__pycache__\0/x.pyc', projectMarkers: PY }), {
    disposable: false,
  })
  // dot segments and repeated separators normalize.
  assert.equal(isDisposable('./__pycache__//mod.cpython-312.pyc', PY), true)
})

test('unknown / case-sensitive / path-like projectMarkers are ignored', () => {
  assert.equal(isDisposable('__pycache__/m.cpython-312.pyc', ['PYPROJECT.TOML']), false)
  assert.equal(isDisposable('__pycache__/m.cpython-312.pyc', ['../pyproject.toml']), false)
  assert.equal(isDisposable('__pycache__/m.cpython-312.pyc', ['pyproject.toml', 'random']), true)
})
