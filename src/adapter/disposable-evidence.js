// disposable-evidence — conditional ownership/regeneration evidence for whitelist hits.
//
// A pure core matcher (`classifyDisposable`) answers only "does this path SHAPE look
// like a known build/cache artifact?". A shape match is not proof. This adapter adds
// the missing evidence before an exemption may reduce the deletion count:
//   - the artifact must be contained between the trusted project boundary and the
//     project root, outside archive/dependency domains, reached without a link escape;
//   - it must not be a Git-tracked index entry, and its Git state must be provable;
//   - for rules that regenerate from source, the paired source/config must exist and
//     prove it (Python => paired .py; Maven => standard .java source; TS => a bounded
//     local tsconfig.json that derives exactly this build-info path).
//
// Boundary: read-only metadata/source REGULARITY checks only. This module never
// executes a project builder, compiler, Git hook, filter, plugin, or runtime import,
// never reads credentials, and never returns file contents. Unproven evidence =>
// { eligible: false } so the caller counts the file normally. An exhausted budget or
// deadline never creates an exemption. Unexpected programming errors surface; they are
// not silently converted into exemptions.

import fs from 'node:fs/promises'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const runFile = promisify(execFile)

// Archive/dependency path segments are never exemption domains (matched without case
// distinctions). Kept identical to the contract policy so the count evidence and the
// pure matcher agree. The matcher may export this list; we do not depend on it.
export const EXCLUDED_SEGMENTS = Object.freeze([
  'backup', 'backups', 'archive', 'archives', 'snapshot', 'snapshots',
  'node_modules', 'vendor', 'third_party', '.git',
])

const GIT_TIMEOUT_MS = 2_000
const GIT_MAX_BUFFER = 1 << 20 // 1 MiB of NUL-separated tracked paths
const MAX_GIT_ANCESTORS = 256 // depth cap for the ancestor `.git` search to filesystem root
const MAX_TS_CONFIG_ANCESTORS = 64
const MAX_SOURCE_BYTES = 64 * 1024 // bounded config/source existence reads are just lstat; keep a cap for content reads

const isWindows = process.platform === 'win32'

/** Case-fold only on Windows, matching NTFS semantics; POSIX stays exact. */
function foldSeg(value) {
  return isWindows ? String(value).toLowerCase() : String(value)
}

// Excluded archive/dependency words are matched case-insensitively on EVERY platform
// (the pure core does the same), independent of the OS path-case semantics.
const EXCLUDED_SET = new Set(EXCLUDED_SEGMENTS.map((seg) => seg.toLowerCase()))

/** Normalize to native absolute form for comparison. */
function normalizeAbs(value) {
  return path.resolve(value)
}

/** Key form used ONLY for Git-index eligibility on Windows: casefolded absolute path.
 * The count-side dedupe must remain case-sensitive; this is just the VCS comparison. */
function trackedKey(value) {
  const abs = path.resolve(value)
  return isWindows ? abs.toLowerCase() : abs
}

/**
 * True when `child` is `parent` or is inside `parent`, using a CONSERVATIVE,
 * CASE-SENSITIVE exact segment-prefix comparison (separators normalized). We must NOT
 * use `path.win32.relative`, which folds case on Windows: on NTFS with case-sensitive
 * directories `C:\repo` and `C:\REPO` can be different directories, so a case-folding
 * containment check could wrongly GRANT an exemption to an external project. This check
 * is used on the granting side (boundary/root containment); any case or spelling
 * mismatch simply yields "not contained" => ordinary count. (Git-index comparison still
 * folds case on Windows because it only ever REVOKES eligibility.)
 */
function isWithin(parent, child) {
  const norm = (value) => {
    let p = String(value).replace(/\\/g, '/')
    // Collapse duplicate separators and trailing slash, keep a drive root prefix intact.
    p = p.replace(/\/{2,}/g, '/')
    if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1)
    return p
  }
  const p = norm(normalizeAbs(parent))
  const c = norm(normalizeAbs(child))
  if (c === p) return true
  // Root ("/" or "C:/") already ends with '/', so guard against a missing separator.
  const withSep = p.endsWith('/') ? p : p + '/'
  return c.startsWith(withSep)
}

/** Split a native path into non-empty segments. */
function segmentsOf(value) {
  return String(value).split(/[\\/]/).filter(Boolean)
}

/**
 * True when any path segment is an excluded archive/dependency domain. Matching is
 * case-insensitive on all platforms. Note: callers pass ONLY the artifact prefix
 * (projectRoot-relative) so that a legitimate Java package segment such as
 * `.../target/classes/com/vendor/Foo.class` is judged by its real output layout, not by
 * an unrelated boundary path. `excludedWordsInSegments` is the shared predicate.
 */
function segmentsIncludeExcluded(relativePath) {
  return segmentsOf(relativePath).some((seg) => EXCLUDED_SET.has(seg.toLowerCase()))
}

/**
 * For the excluded-domain check, return only the artifact's LEADING segments that lie
 * before its rule-specific canonical output anchor. Deeper segments can be legitimate
 * package/module names (e.g. a Java package literally named `vendor`/`backup` inside
 * target/classes), which must NOT be forbidden. When no anchor applies, the whole
 * relative path is checked.
 */
function leadingSegmentsForRule(ruleId, relativePath) {
  const segs = segmentsOf(relativePath)
  const lower = segs.map((seg) => seg.toLowerCase())
  let anchor = -1
  if (ruleId === 'py-pyc-file') {
    // __pycache__/<file>.pyc — anchor at the trailing __pycache__ dir.
    if (segs.length >= 2) anchor = segs.length - 2
  } else if (ruleId === 'maven-class-file') {
    // target/{classes|test-classes}/... — anchor at `target`.
    const t = lower.indexOf('target')
    if (t >= 0) anchor = t
  } else if (ruleId === 'pytest-cache-file') {
    const p = lower.indexOf('.pytest_cache')
    if (p >= 0) anchor = p
  } else if (ruleId === 'mypy-cache-file') {
    const m = lower.indexOf('.mypy_cache')
    if (m >= 0) anchor = m
  }
  // TS build-info and anything else: no anchor => check the whole path.
  const leading = anchor >= 0 ? segs.slice(0, anchor) : segs
  return leading.join('/')
}

/**
 * Resolve a real path and assert it stays inside `root`, following no symlink out.
 * Returns the real path, or null when the path escapes / cannot be resolved.
 */
async function realWithin(root, target, signal) {
  assertNotAborted(signal)
  let realRoot
  let realTarget
  try {
    realRoot = await fs.realpath(root)
    realTarget = await fs.realpath(target)
  } catch {
    return null
  }
  return isWithin(realRoot, realTarget) ? realTarget : null
}

function assertNotAborted(signal) {
  if (signal?.aborted) throw signal.reason ?? new Error('guardrails: evidence check cancelled')
}

/** lstat; returns null on ENOENT/ENOTDIR (absent), throws otherwise. */
async function lstatOrNull(target) {
  try {
    return await fs.lstat(target)
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return null
    throw error
  }
}

/** True only for an existing regular, non-symlink file. */
async function isRegularFile(target) {
  const info = await lstatOrNull(target)
  return Boolean(info && info.isFile() && !info.isSymbolicLink())
}

export function createDisposableEvidence({ boundary, signal, deadlineAt, consume } = {}) {
  if (typeof boundary !== 'string' || !path.isAbsolute(boundary)) {
    throw new TypeError('guardrails: evidence boundary must be an absolute path')
  }
  if (typeof consume !== 'function') {
    throw new TypeError('guardrails: evidence consume() budget hook is required')
  }
  const boundaryAbs = normalizeAbs(boundary)

  // Per-plan caches: never spawn Git / re-read config per file.
  const gitCache = new Map() // projectRoot -> { kind:'non-git'|'tracked-set'|'unknown', tracked:Set }
  const tsConfigCache = new Map() // configDir|file -> derivation result

  const atDeadline = () => typeof deadlineAt === 'number' && Date.now() > deadlineAt

  /** Reserve a budget unit; returns false when exhausted (must not exempt). A throwing
   * consume() is a programming error and MUST surface, never be swallowed into "no budget". */
  function reserve() {
    if (atDeadline()) return false
    return consume() === true
  }

  // --- Git tracking evidence ------------------------------------------------
  // A sanitized environment so GIT_* path/worktree overrides cannot redirect the
  // repository we inspect. Never print environment or config.
  function gitEnv() {
    const env = { ...process.env }
    for (const key of Object.keys(env)) {
      if (key.startsWith('GIT_')) delete env[key]
    }
    env.GIT_OPTIONAL_LOCKS = '0'
    env.GIT_TERMINAL_PROMPT = '0'
    env.GIT_NO_LAZY_FETCH = '1'
    // Never run project hooks/filters for a metadata query.
    env.GIT_ATTR_NOSYSTEM = '1'
    // Treat pathspec arguments literally (never as globs), so a project subpath that
    // contains `*`, `?`, or `[...]` cannot broaden/narrow the ls-files result.
    env.GIT_LITERAL_PATHSPECS = '1'
    return env
  }

  /** Recompute a per-call git timeout from the remaining plan deadline. */
  function gitTimeoutRemaining() {
    const remaining = typeof deadlineAt === 'number' ? deadlineAt - Date.now() : GIT_TIMEOUT_MS
    return Math.max(1, Math.min(GIT_TIMEOUT_MS, remaining))
  }

  /**
   * Find the nearest existing `.git` (dir or file) by searching UP FROM `start` all the
   * way to the filesystem root. A monorepo subproject or fixture may be tracked by a
   * parent repository whose VCS root is OUTSIDE the project boundary, so the search must
   * not stop at the boundary. Only a COMPLETE walk that reaches the filesystem root
   * without finding `.git` proves a non-Git project; a depth cap, permission error, or
   * budget exhaustion is `unknown` (ordinary count), never `absent`.
   */
  async function findGitMetadata(start) {
    let dir = normalizeAbs(start)
    for (let depth = 0; depth < MAX_GIT_ANCESTORS; depth += 1) {
      if (!reserve()) return { kind: 'unknown', reason: 'budget' }
      const candidate = path.join(dir, '.git')
      let info
      try {
        info = await lstatOrNull(candidate)
      } catch {
        // Permission / IO ambiguity while probing ancestors: cannot prove non-Git.
        return { kind: 'unknown', reason: 'git-probe-error' }
      }
      if (info) return { kind: 'found', path: candidate, dir }
      const parent = path.dirname(dir)
      if (parent === dir) return { kind: 'absent' } // reached FS root: complete search
      dir = parent
    }
    // Depth cap reached before the filesystem root: not a complete search.
    return { kind: 'unknown', reason: 'git-depth-cap' }
  }

  /**
   * Load the tracked-file set for the closest Git root of `projectRoot`.
   * Returns { kind:'non-git' } | { kind:'tracked-set', tracked:Set(realpath) } |
   * { kind:'unknown', reason }. Unknown/unreadable/ambiguous must not exempt.
   */
  async function trackedSetFor(projectRoot) {
    const key = normalizeAbs(projectRoot)
    if (gitCache.has(key)) return gitCache.get(key)
    const result = await computeTracked(key)
    gitCache.set(key, result)
    return result
  }

  async function computeTracked(projectRoot) {
    const meta = await findGitMetadata(projectRoot)
    if (meta.kind === 'unknown') return meta
    if (meta.kind === 'absent') return { kind: 'non-git' }
    if (!reserve()) return { kind: 'unknown', reason: 'budget' }

    const timeout = gitTimeoutRemaining()
    let top
    try {
      const { stdout } = await runFile('git', ['-C', projectRoot, 'rev-parse', '--show-toplevel'], {
        shell: false, windowsHide: true, timeout, maxBuffer: 32768, signal, env: gitEnv(),
      })
      top = stdout.trim()
    } catch {
      // Unavailable / unreadable / not a real repository => unknown, not "non-git".
      return { kind: 'unknown', reason: 'git-toplevel-unavailable' }
    }
    const topRaw = top ? normalizeAbs(top) : null
    if (!topRaw) {
      return { kind: 'unknown', reason: 'git-toplevel-ambiguous' }
    }
    // Canonicalize both sides through realpath so a Windows 8.3 short name (e.g. from
    // os.tmpdir()) and the long name git reports compare equal.
    let topAbs
    let rootReal
    try {
      topAbs = await fs.realpath(topRaw)
      rootReal = await fs.realpath(projectRoot)
    } catch {
      return { kind: 'unknown', reason: 'git-path-canonicalize-failed' }
    }
    // The VCS top-level may live OUTSIDE the project boundary (monorepo subproject,
    // fixture nested in a parent repo). We only require that it is a real ancestor of
    // (or equal to) the project root, so tracked entries can be mapped to absolute paths
    // against the true repository root. A top-level that is NOT an ancestor of the
    // project means the repository identity is ambiguous -> ordinary count.
    if (!isWithin(topAbs, rootReal)) {
      return { kind: 'unknown', reason: 'git-toplevel-not-ancestor' }
    }
    if (!reserve()) return { kind: 'unknown', reason: 'budget' }
    // Scope the tracked listing to the project subtree (bounded, not the whole repo).
    const relProject = path.relative(topAbs, rootReal)
    const pathspec = relProject === '' ? '.' : relProject
    let list
    try {
      const { stdout } = await runFile('git', [
        '--literal-pathspecs', '-C', topAbs, 'ls-files', '-z', '--cached', '--recurse-submodules', '--', pathspec,
      ], {
        shell: false, windowsHide: true, timeout: gitTimeoutRemaining(), maxBuffer: GIT_MAX_BUFFER, signal, env: gitEnv(),
      })
      list = stdout
    } catch {
      return { kind: 'unknown', reason: 'git-tracked-unavailable' }
    }
    const tracked = new Set()
    let truncated = false
    if (list.length >= GIT_MAX_BUFFER) truncated = true // output capped: cannot prove untracked
    for (const entry of list.split('\u0000')) {
      if (!entry) continue
      // ls-files paths are relative to the repository top-level. Store a Windows-casefolded
      // absolute path ONLY for the VCS eligibility comparison (NTFS is case-insensitive and
      // the index spelling can differ from the on-disk casing); the count-side dedupe stays
      // case-sensitive. POSIX paths are stored exactly.
      const abs = path.resolve(topAbs, entry)
      tracked.add(isWindows ? abs.toLowerCase() : abs)
    }
    if (truncated) return { kind: 'unknown', reason: 'git-tracked-truncated' }
    return { kind: 'tracked-set', tracked, top: topAbs }
  }

  // --- Rule-specific source evidence ---------------------------------------

  /**
   * Confirm `candidate` is a real regular file that lives INSIDE `projectRoot` with NO
   * symlinked ancestor escaping the project: every path component from projectRoot down
   * to the file's parent is lstat'd (must be a real directory, not a link), and the
   * final realpath must stay within the project. Each IO reserves a budget unit. This
   * prevents a leaf-only lstat from accepting src/main/java -> symlink-out.
   */
  async function safeSourceFile(candidate, projectRoot, signal) {
    assertNotAborted(signal)
    const rootAbs = normalizeAbs(projectRoot)
    const candidateAbs = normalizeAbs(candidate)
    if (!isWithin(rootAbs, candidateAbs)) return false
    if (!reserve()) return false
    let info
    try {
      info = await lstatOrNull(candidateAbs)
    } catch {
      return false
    }
    if (!info || !info.isFile() || info.isSymbolicLink()) return false
    // Walk each ancestor directory from projectRoot down to the parent, rejecting links.
    const relDir = path.relative(rootAbs, path.dirname(candidateAbs))
    const parts = relDir === '' ? [] : relDir.split(path.sep).filter(Boolean)
    let current = rootAbs
    for (const part of parts) {
      current = path.join(current, part)
      if (!reserve()) return false
      let dirInfo
      try {
        dirInfo = await lstatOrNull(current)
      } catch {
        return false
      }
      if (!dirInfo || dirInfo.isSymbolicLink() || !dirInfo.isDirectory()) return false
    }
    // Final real-path proof: no component escaped the project via a link.
    const real = await realWithin(rootAbs, candidateAbs, signal)
    return real !== null
  }

  /** Python: <dir>/__pycache__/<stem>.<cpython-ver>[.opt-N].pyc => <dir>/<stem>.py */
  async function pySourceEvidence(absolute, projectRoot, signal) {
    const base = path.basename(absolute)
    if (!base.endsWith('.pyc')) return false
    let stem = base.slice(0, -'.pyc'.length)
    // Strip an optional trailing .opt-N (PEP 488).
    stem = stem.replace(/\.opt-[12]$/, '')
    // Strip the trailing .cpython-<ver> tag.
    const tagIndex = stem.lastIndexOf('.')
    if (tagIndex <= 0) return false
    const tag = stem.slice(tagIndex + 1)
    if (!/^cpython-\d{2,3}$/.test(tag)) return false
    stem = stem.slice(0, tagIndex)
    if (!stem) return false
    // The paired source lives next to the SOURCE directory, i.e. the parent of
    // __pycache__ (PEP 3147). If the artifact is not under a __pycache__ dir, fall back
    // to its own directory.
    const parentDir = path.dirname(absolute)
    const sourceDir = path.basename(parentDir) === '__pycache__' ? path.dirname(parentDir) : parentDir
    return safeSourceFile(path.join(sourceDir, stem + '.py'), projectRoot, signal)
  }

  /**
   * Maven: target/{classes|test-classes}/<pkg path>/<Name>[$Inner...].class =>
   * <projectRoot>/src/{main|test}/java/<pkg path>/<Outer>.java. Nested `$` classes map
   * to the outer class source. Bucket is strict: classes->src/main/java,
   * test-classes->src/test/java (no cross-finding). Default package (parts.length===3,
   * e.g. target/classes/App.class) is supported.
   */
  async function mavenSourceEvidence(absolute, projectRoot, signal) {
    const rel = path.relative(normalizeAbs(projectRoot), normalizeAbs(absolute))
    if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return false
    const parts = rel.split(path.sep)
    if (parts.length < 3) return false // target / (classes|test-classes) / <Name.class> is minimum
    if (foldSeg(parts[0]) !== 'target') return false
    const bucket = foldSeg(parts[1])
    if (bucket !== 'classes' && bucket !== 'test-classes') return false
    const pkgDirs = parts.slice(2, -1)
    let simple = parts[parts.length - 1]
    if (!simple.endsWith('.class')) return false
    simple = simple.slice(0, -'.class'.length)
    // Nested classes: Outer$Inner -> Outer.
    const dollar = simple.indexOf('$')
    if (dollar >= 0) simple = simple.slice(0, dollar)
    if (!simple) return false
    const sourcesRoot = bucket === 'test-classes' ? path.join('src', 'test', 'java') : path.join('src', 'main', 'java')
    const candidate = path.join(normalizeAbs(projectRoot), sourcesRoot, ...pkgDirs, simple + '.java')
    return safeSourceFile(candidate, projectRoot, signal)
  }

  /**
   * Bounded strict-JSON read of a tsconfig.json. Reads through an opened handle with a
   * FIXED 64 KiB + 1 byte cap (so a file that grows after open cannot be read without
   * bound — we never stat-then-readFile). Rejects comments/trailing-comma (strict JSON),
   * extends/references, and string substitution. Non-regular / symlink / oversize reads
   * return null (unsupported => ordinary count). Each IO reserves a budget unit.
   */
  async function readTsConfig(target, signal) {
    assertNotAborted(signal)
    if (!reserve()) return null
    let handle
    let raw
    try {
      handle = await fs.open(target, 'r')
      const buffer = Buffer.alloc(MAX_SOURCE_BYTES + 1)
      const { bytesRead } = await handle.read(buffer, 0, MAX_SOURCE_BYTES + 1, 0)
      if (bytesRead > MAX_SOURCE_BYTES) return null // grew past the fixed cap: unsupported
      raw = buffer.toString('utf8', 0, bytesRead)
    } catch {
      return null
    } finally {
      if (handle) { try { await handle.close() } catch { /* already closed */ } }
    }
    let data
    try {
      data = JSON.parse(raw) // strict JSON: comments/trailing-comma rejected
    } catch {
      return null
    }
    if (data === null || typeof data !== 'object' || Array.isArray(data)) return null
    if ('extends' in data || 'references' in data) return null
    const opts = data.compilerOptions
    if (opts !== undefined) {
      if (opts === null || typeof opts !== 'object' || Array.isArray(opts)) return null
      if ('extends' in opts) return null
      for (const value of Object.values(opts)) {
        if (typeof value === 'string' && value.includes('${')) return null
      }
    }
    return data
  }

  /**
   * Compute the tsbuildinfo path a parsed tsconfig would emit, or null if it cannot be
   * derived with certainty. Follows the documented formula:
   *   - outFile set: <outFile dir>/<outFile stem>.tsbuildinfo
   *   - else: <outDir || configDir>/<config basename>.tsbuildinfo
   *   - explicit tsBuildInfoFile overrides both (path relative to the config dir).
   * Option VALUES must have the exact documented types; a present-but-wrong-typed key is
   * rejected (return null) rather than silently treated as omitted.
   *
   * Formula (per https://www.typescriptlang.org/tsconfig/tsBuildInfoFile.html):
   *   1. explicit tsBuildInfoFile  -> resolve(relative to config dir)
   *   2. outFile set               -> <outFile>.tsbuildinfo (APPEND, keep the extension)
   *   3. rootDir AND outDir set    -> <outDir>/<relative path from rootDir to configDir>/<config name>.tsbuildinfo
   *                                   e.g. rootDir=src, outDir=dest, config=./tsconfig.json =>
   *                                   relative(src -> .) = '..' => dest/../tsconfig.tsbuildinfo
   *                                   = ./tsconfig.tsbuildinfo (NOT inside dest)
   *   4. outDir only               -> <outDir>/<config name>.tsbuildinfo
   *   5. otherwise                 -> <configDir>/<config name>.tsbuildinfo
   */
  function deriveTsBuildInfoPath(configDir, configName, data) {
    const opts = (data && data.compilerOptions) || {}
    // Strict type validation for options that influence the derivation.
    const asBool = (v) => {
      if (v === undefined) return undefined
      return typeof v === 'boolean' ? v : 'invalid'
    }
    const asStr = (v) => {
      if (v === undefined) return undefined
      if (typeof v !== 'string' || v === '') return 'invalid'
      if (v.includes('${')) return 'invalid'
      return v
    }
    const incremental = asBool(opts.incremental)
    const composite = asBool(opts.composite)
    const tsBuildInfoFile = asStr(opts.tsBuildInfoFile)
    const outFile = asStr(opts.outFile)
    const outDir = asStr(opts.outDir)
    const rootDir = asStr(opts.rootDir)
    if (incremental === 'invalid' || composite === 'invalid' || tsBuildInfoFile === 'invalid'
        || outFile === 'invalid' || outDir === 'invalid' || rootDir === 'invalid') {
      return null
    }
    if (incremental !== true && composite !== true) return null

    const configAbs = normalizeAbs(configDir)
    const base = path.basename(configName).replace(/\.json$/i, '') || 'tsconfig'

    // 1. Explicit path (relative to the config directory) always wins.
    if (typeof tsBuildInfoFile === 'string') {
      return normalizeAbs(path.resolve(configAbs, tsBuildInfoFile))
    }
    // 2. outFile WITHOUT an explicit tsBuildInfoFile: the default artifact name is
    //    ambiguous in official docs (<outFile>.tsbuildinfo shorthand vs the TS 3.4
    //    example foo.js -> foo.tsbuildinfo that strips the extension). We deliberately do
    //    NOT guess: return null so the file is counted ordinarily. An explicit
    //    tsBuildInfoFile (handled above) remains supported.
    if (typeof outFile === 'string') {
      return null
    }
    // 3./4. outDir present.
    if (typeof outDir === 'string') {
      const outAbs = normalizeAbs(path.resolve(configAbs, outDir))
      if (typeof rootDir === 'string') {
        // <outDir>/<relative path from rootDir to the config dir>/<config name>.tsbuildinfo
        const rootAbs = normalizeAbs(path.resolve(configAbs, rootDir))
        const rel = path.relative(rootAbs, configAbs)
        return normalizeAbs(path.join(outAbs, rel, base + '.tsbuildinfo'))
      }
      return path.join(outAbs, base + '.tsbuildinfo')
    }
    // 5. Otherwise: alongside the config.
    return path.join(configAbs, base + '.tsbuildinfo')
  }

  /**
   * TS: find a bounded local tsconfig.json whose derivation equals the artifact. We
   * inspect tsconfig.json files at the artifact's ancestor directories up to the
   * project root (and the project root itself). Explicit tsBuildInfoFile anywhere else
   * inside the project is conservatively counted (ordinary count).
   */
  async function tsEvidence(absolute, projectRoot, signal) {
    if (!path.basename(absolute).endsWith('.tsbuildinfo')) return false
    const rootAbs = normalizeAbs(projectRoot)
    let dir = path.dirname(normalizeAbs(absolute))
    for (let depth = 0; depth < MAX_TS_CONFIG_ANCESTORS; depth += 1) {
      if (!isWithin(rootAbs, dir)) return false
      if (!reserve()) return false
      const configPath = path.join(dir, 'tsconfig.json')
      const cached = tsConfigCache.get(configPath)
      let derived
      if (cached !== undefined) {
        derived = cached
      } else {
        const data = await readTsConfig(configPath, signal)
        derived = data ? deriveTsBuildInfoPath(dir, 'tsconfig.json', data) : null
        tsConfigCache.set(configPath, derived)
      }
      if (derived && foldSeg(derived) === foldSeg(normalizeAbs(absolute))) return true
      if (dir === rootAbs) return false
      const parent = path.dirname(dir)
      if (parent === dir) return false
      dir = parent
    }
    return false
  }

  // --- verify ---------------------------------------------------------------

  const CACHE_STATE_RULES = new Set(['pytest-cache-file', 'mypy-cache-file'])

  async function verify({ absolute, projectRoot, projectMarkers, ruleId } = {}) {
    // Unexpected programming errors surface; they are never converted into exemptions.
    return verifyInner({ absolute, projectRoot, projectMarkers, ruleId })
  }

  async function verifyInner({ absolute, projectRoot, projectMarkers, ruleId }) {
    if (typeof absolute !== 'string' || typeof projectRoot !== 'string') {
      throw new TypeError('guardrails: evidence verify requires absolute and projectRoot')
    }
    if (typeof ruleId !== 'string' || ruleId.length === 0) {
      return { eligible: false, reason: 'unknown-rule' }
    }
    if (atDeadline() || !reserve()) return { eligible: false, reason: 'budget' }

    const rootAbs = normalizeAbs(projectRoot)
    const artifactAbs = normalizeAbs(absolute)
    // Containment: boundary must contain projectRoot, and projectRoot the artifact.
    if (!isWithin(boundaryAbs, rootAbs)) return { eligible: false, reason: 'project-outside-boundary' }
    if (!isWithin(rootAbs, artifactAbs)) return { eligible: false, reason: 'artifact-outside-project' }

    // Archive/dependency domains: (a) the path from the trusted boundary to the project
    // root must not itself sit under an excluded domain; (b) the artifact's LEADING
    // segments (before its canonical output anchor) must not be an excluded domain —
    // but valid Java package names deeper inside target/classes (e.g. com/vendor/Foo)
    // must not be forbidden. `leadingSegmentsForRule` yields only the prefix to check.
    const relFromRoot = path.relative(rootAbs, artifactAbs)
    if (segmentsIncludeExcluded(leadingSegmentsForRule(ruleId, relFromRoot))) {
      return { eligible: false, reason: 'excluded-domain' }
    }
    const relBoundaryToRoot = path.relative(boundaryAbs, rootAbs)
    if (segmentsIncludeExcluded(relBoundaryToRoot)) return { eligible: false, reason: 'excluded-boundary-domain' }

    // The artifact must be a real regular file reached without a link escape. Rule math
    // below uses the lexical `artifactAbs` (it is already contained); the real path is
    // used only for the link-escape proof and Git-index comparison. On Windows a short
    // (8.3) realpath would otherwise break `path.relative` against the long projectRoot.
    const realArtifact = await realWithin(rootAbs, artifactAbs, signal)
    if (!realArtifact) return { eligible: false, reason: 'artifact-link-escape' }
    if (!(await isRegularFile(artifactAbs))) return { eligible: false, reason: 'artifact-not-regular' }

    // Git tracking: tracked or unknown Git state must never be exempted. Compare the
    // lexical path and the real path, both in the same Windows-casefolded key form the
    // tracked set uses on Windows, so short/long-name and index-casing differences still
    // match. (Count dedupe elsewhere stays case-sensitive; this is only VCS eligibility.)
    const git = await trackedSetFor(rootAbs)
    if (git.kind === 'unknown') return { eligible: false, reason: 'git-unknown' }
    if (git.kind === 'tracked-set' &&
        (git.tracked.has(trackedKey(artifactAbs)) || git.tracked.has(trackedKey(realArtifact)))) {
      return { eligible: false, reason: 'git-tracked' }
    }
    // Non-Git projects may still be exempted here; provenance is then the source/config
    // evidence below (a complete bounded search found no Git metadata).

    let proven = false
    let reason
    switch (ruleId) {
      case 'py-pyc-file':
        proven = await pySourceEvidence(artifactAbs, rootAbs, signal)
        reason = proven ? undefined : 'py-source-missing'
        break
      case 'maven-class-file':
        proven = await mavenSourceEvidence(artifactAbs, rootAbs, signal)
        reason = proven ? undefined : 'java-source-missing'
        break
      case 'ts-buildinfo-file':
        proven = await tsEvidence(artifactAbs, rootAbs, signal)
        reason = proven ? undefined : 'ts-config-not-derivable'
        break
      default:
        if (CACHE_STATE_RULES.has(ruleId)) {
          // Narrow conventional cache state already validated by the pure matcher; the
          // project/containment/tracking checks above are the required extra evidence.
          proven = true
        } else {
          proven = false
          reason = 'unsupported-rule'
        }
        break
    }
    if (!proven) return { eligible: false, reason }
    // Final gate: a proven exemption still requires remaining budget/deadline. If the
    // plan deadline passed or the shared budget is exhausted mid-verification, do not
    // exempt (ordinary count). This re-check happens after the last IO.
    if (atDeadline() || !reserve()) return { eligible: false, reason: 'budget' }
    return { eligible: true }
  }

  return { verify }
}
