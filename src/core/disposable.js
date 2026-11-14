// disposable — conservative, project-bound recognition of tool-generated build
// output and cache FILES. Pure and synchronous: no filesystem IO, no async, no
// dependence on file content. The caller (adapter) confirms the project root and
// trusted boundary, supplies the exact marker file NAMES present at the root,
// resolves the path, rejects link/mount escapes, keeps protected-file
// exemptions, and proves source/config regeneration (see
// src/adapter/disposable-evidence.js). This module only answers "does this
// root-relative path shape match a known conventional artifact location for a
// project that declares this marker, and does it avoid archive/dependency
// prefixes?".
//
// This module returns evidence at FILE granularity. Only regular files count
// toward the caller's deletion limit, so directory-only matches are useless and
// are not produced here: a directory path always returns { disposable: false }.
//
// Design rules (see docs/technical-details/批量删除白名单.md):
// - Every rule pairs a project-marker precondition with a strict FILE shape
//   inside a conventionally documented output location. No subtree is skipped.
// - Archive/dependency prefixes are NOT exemption domains: a match whose path
//   is nested under one of EXCLUDED_DISPOSABLE_SEGMENTS (case-insensitive) is
//   refused. Legitimate Java package segments *inside* target/classes or
//   target/test-classes are exempt from that ban (they are not archive/prefix
//   directories). build/dist are NOT banned outright because valid TS output can
//   live there.
// - Cargo dependency artifacts are deliberately NOT auto-exempt this round:
//   they cannot be attributed to their dependency sources without executing or
//   fully interpreting the toolchain, so they count as ordinary files.
// - Unrecognized shapes return { disposable: false }.

/**
 * Marker file basenames the adapter may collect at a confirmed project root.
 * These serve two purposes: (a) project-boundary detection for root discovery
 * (so a nested Rust/Cargo project does not inherit an outer project's marker),
 * and (b) gating file rules below where a marker actually implies an artifact.
 * A marker being present never grants an exemption by itself — only the file
 * rules do. In particular Cargo.toml gates NO rule this round (Cargo artifacts
 * count normally); it is listed only as a boundary marker. Go/Gradle/PHP
 * toolchains are deliberately absent.
 */
export const PROJECT_MARKERS = Object.freeze([
  'pyproject.toml',
  'setup.py',
  'setup.cfg',
  'tox.ini',
  'pytest.ini',
  'mypy.ini',
  '.mypy.ini',
  'pom.xml',
  'Cargo.toml',
  'tsconfig.json',
])

/**
 * Directory segment names that are archive/dependency domains, never exemption
 * domains. Compared case-insensitively. Exported for the evidence adapter's
 * boundary/root prefix checks. Immutable.
 */
export const EXCLUDED_DISPOSABLE_SEGMENTS = Object.freeze([
  'backup',
  'backups',
  'archive',
  'archives',
  'snapshot',
  'snapshots',
  'node_modules',
  'vendor',
  'third_party',
  '.git',
])

const EXCLUDED_SET = new Set(EXCLUDED_DISPOSABLE_SEGMENTS)

// --- helpers ---------------------------------------------------------------

// CPython writes bytecode to __pycache__/ for any project with Python sources.
const PYTHON_MARKERS = ['pyproject.toml', 'setup.py', 'setup.cfg', 'tox.ini']
// pytest persists cross-run state in <rootdir>/.pytest_cache/v/cache/.
const PYTEST_MARKERS = ['pyproject.toml', 'setup.py', 'setup.cfg', 'tox.ini', 'pytest.ini']
// mypy stores its incremental cache in <project root>/.mypy_cache/<pyver>/.
const MYPY_MARKERS = ['mypy.ini', '.mypy.ini', 'setup.cfg', 'pyproject.toml']
// Maven compiles to target/{classes,test-classes} (Super POM defaults).
const MAVEN_MARKERS = ['pom.xml']
// TypeScript incremental state (<config>.tsbuildinfo) is produced by a
// tsconfig-driven build, so gate on the presence of tsconfig.json; the
// .tsbuildinfo suffix is the documented artifact.
const TS_MARKERS = ['tsconfig.json']

const hasMarker = (set, names) => names.some((name) => set.has(name))

/** CPython cache tag, e.g. cpython-312 (PEP 3147). */
const CPythonTag = /^cpython-\d{2,3}$/
/** Optimization level suffix introduced by PEP 488, e.g. opt-1 / opt-2. */
const OptTag = /^opt-[12]$/
/** A single Python identifier segment used in a module stem. */
const PyIdent = /^[A-Za-z_][A-Za-z0-9_]*$/
/** A Maven/DEX-style compiled class basename. */
const ClassName = /^[^./\\]+\.class$/
/** A mypy cache leaf, `<module>.data.json` or `<module>.meta.json`. */
const MypyJson = /\.(data|meta)\.json$/
/** A TypeScript incremental build-info filename (default <config>.tsbuildinfo). */
const TsBuildInfo = /\.tsbuildinfo$/

/**
 * Split a '/'-separated root-relative path into segments.
 * Returns null when the value is not a safe relative path (empty, absolute,
 * contains a drive/UNC root, or contains a `..` escape segment).
 */
function segments(value) {
  if (typeof value !== 'string' || value === '') return null
  if (value.includes('\0')) return null
  if (value.startsWith('/') || /^[A-Za-z]:/.test(value)) return null
  if (value.startsWith('\\\\')) return null
  const parts = value.split('/')
  if (parts.some((p) => p === '..')) return null
  const kept = parts.filter((p) => p !== '' && p !== '.')
  return kept.length ? kept : null
}

/**
 * True when a directory segment in segs[0..limit-1] is an archive/dependency
 * prefix. `limit` bounds how many leading segments are checked. For the Java
 * package tail below target/{classes,test-classes}, callers pass a larger start
 * so package names are not banned.
 */
function hasExcludedPrefix(segs, start, limit) {
  for (let i = start; i < limit; i += 1) {
    if (EXCLUDED_SET.has(segs[i].toLowerCase())) return true
  }
  return false
}

const result = (ruleId) => ({ disposable: true, ruleId })
const NONE = Object.freeze({ disposable: false })

// --- rule evaluation (files only) ------------------------------------------

/**
 * Python bytecode: __pycache__/<module stem>.cpython-<ver>[.opt-N].pyc.
 * The stem must be a strict dotted Python identifier (e.g. `a.b`), never a
 * name containing shell/path metacharacters. Source-pairing evidence is the
 * adapter's responsibility.
 */
function matchPyc(segs, markers) {
  if (segs.length < 2 || segs[segs.length - 2] !== '__pycache__') return null
  if (!hasMarker(markers, PYTHON_MARKERS)) return null
  const name = segs[segs.length - 1]
  const parts = name.split('.')
  // <stem> . cpython-<ver> [ . opt-N ] . pyc  => at least 3 parts.
  if (parts.length < 3) return null
  if (parts[parts.length - 1] !== 'pyc') return null
  let tagIndex = parts.length - 2
  if (OptTag.test(parts[tagIndex])) {
    tagIndex -= 1
    if (tagIndex < 1) return null
  }
  if (!CPythonTag.test(parts[tagIndex])) return null
  // The stem is everything before the cache tag; every dotted segment must be a
  // strict Python identifier (no '-' , '+', spaces, etc.).
  const stemParts = parts.slice(0, tagIndex)
  if (stemParts.length === 0) return null
  if (!stemParts.every((p) => PyIdent.test(p))) return null
  return result('py-pyc-file')
}

/** pytest cross-run cache state files under <rootdir>/.pytest_cache/v/cache/. */
function matchPytestCache(segs, markers) {
  if (segs.length !== 4) return null
  if (segs[0] !== '.pytest_cache' || segs[1] !== 'v' || segs[2] !== 'cache') return null
  if (!hasMarker(markers, PYTEST_MARKERS)) return null
  return ['nodeids', 'lastfailed', 'stepwise'].includes(segs[3]) ? result('pytest-cache-file') : null
}

/** mypy incremental cache: .mypy_cache/<pyver>/.../<module>.{data,meta}.json */
function matchMypyCache(segs, markers) {
  if (segs.length < 3) return null
  if (segs[0] !== '.mypy_cache') return null
  if (!/^\d+\.\d+$/.test(segs[1])) return null
  if (!hasMarker(markers, MYPY_MARKERS)) return null
  return MypyJson.test(segs[segs.length - 1]) ? result('mypy-cache-file') : null
}

/**
 * Maven compiled classes: target/classes or target/test-classes, any depth,
 * .class files. Java package segments below the anchor are legitimate even if
 * they spell an archive/prefix word, so the exclusion check starts after
 * target/<kind>. Source-pairing evidence (src/main/java|src/test/java) is the
 * adapter's responsibility.
 */
function matchMavenClass(segs, markers) {
  if (segs.length < 3) return null
  if (segs[0] !== 'target') return null
  if (segs[1] !== 'classes' && segs[1] !== 'test-classes') return null
  if (!hasMarker(markers, MAVEN_MARKERS)) return null
  if (!ClassName.test(segs[segs.length - 1])) return null
  // Only the prefix ABOVE target/ may be an archive/dependency domain; package
  // segments under target/classes are not banned.
  if (hasExcludedPrefix(segs, 0, 1)) return null
  return result('maven-class-file')
}

/** TypeScript incremental build info: <name>.tsbuildinfo */
function matchTsBuildInfo(segs, markers) {
  if (!hasMarker(markers, TS_MARKERS)) return null
  return TsBuildInfo.test(segs[segs.length - 1]) ? result('ts-buildinfo-file') : null
}

const FILE_RULES = [
  matchPyc,
  matchPytestCache,
  matchMypyCache,
  matchMavenClass,
  matchTsBuildInfo,
]

/**
 * Classify a single root-relative path as a known disposable build/cache FILE.
 * Directory entries are never disposable (they do not count toward limits).
 *
 * @param {object} input
 * @param {string} input.relativePath  '/' separated, relative to a confirmed
 *   project root (no leading slash/drive, no `..`).
 * @param {string[]} [input.projectMarkers]  exact marker file NAMES present at
 *   the confirmed root (basenames such as 'pyproject.toml', 'tsconfig.json').
 * @param {boolean} [input.isDirectory]  when true, always returns false (dirs
 *   are deduplicated and reported separately by the caller, never exempted).
 * @returns {{disposable: true, ruleId: string} | {disposable: false}}
 */
export function classifyDisposable({ relativePath, projectMarkers = [], isDirectory = false } = {}) {
  const segs = segments(relativePath)
  if (!segs) return NONE
  if (isDirectory) return NONE

  const markers = Array.isArray(projectMarkers)
    ? new Set(projectMarkers.filter((m) => typeof m === 'string'))
    : new Set()

  // Archive/dependency prefix guard for every rule EXCEPT the Java package tail
  // under target/classes (which matchMavenClass handles itself). Rules that do
  // not place an archive-named segment in a directory position are unaffected.
  const dirLimit = segs.length - 1
  const earlyExcluded = hasExcludedPrefix(segs, 0, dirLimit)

  for (const rule of FILE_RULES) {
    // Maven re-checks the prefix itself (only above target/), so it is allowed
    // to proceed even if a package segment below target/classes spells a prefix.
    if (rule === matchMavenClass) {
      const matched = matchMavenClass(segs, markers)
      if (matched) return matched
      continue
    }
    if (earlyExcluded) continue
    const matched = rule(segs, markers)
    if (matched) return matched
  }
  return NONE
}
