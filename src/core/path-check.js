// path-check — path normalization and the path-level rule check.
//
// Boundary: pure synchronous helpers (no fs, no async); depends on
// core/rules.js for denylist data and category switches only.
// Reference: docs/technical-details/规则模型.md; DSR-005.

import {
  CRED_BASENAME_PREFIXES,
  CRED_BASENAMES,
  CRED_COMBOS,
  CRED_DIR_SEGMENTS,
  CRED_SUFFIXES,
  SYSTEM_COMBOS,
  SYSTEM_PREFIXES,
  isSensitiveEnvName,
} from './rules.js'

/** Replace backslashes with forward slashes (Windows paths accept both). */
export const slash = (p) => String(p).replace(/\\/g, '/')

/** Whether a path is absolute (`C:/x`, `C:\x`, or POSIX `/x`). */
export const isAbsolutePath = (p) => /^[A-Za-z]:[\\/]/.test(p) || p.startsWith('/')

/** Split into path segments, dropping empty and `.` components. */
export const segmentsOf = (p) => slash(p).split('/').filter((s) => s.length > 0 && s !== '.')

/**
 * Resolve `target` against `base` lexically (no fs access).
 * Absolute targets pass through (slash-normalized); `..` pops the stack.
 */
export function resolvePath(base, target) {
  if (isAbsolutePath(target)) return slash(target)
  const out = []
  for (const s of segmentsOf(base).concat(segmentsOf(target))) {
    if (s === '..') out.pop()
    else out.push(s)
  }
  return out.join('/')
}

/** Last segment of a path, or `''` for a segment-less input. */
export const baseNameOf = (p) => {
  const segs = slash(p).split('/').filter(Boolean)
  return segs.length ? segs[segs.length - 1] : ''
}

/** Lowercase slash-normalized form for case-insensitive comparison. */
export const normCompare = (p) => slash(p).toLowerCase()

/** Whether a resolved path enters a `.git` directory at any depth. */
export function entersGitDir(resolved) {
  return segmentsOf(resolved).includes('.git')
}

/**
 * Whether a resolved path targets a credential file, directory, or combo.
 * Matches basenames (incl. hive transaction-log prefixes), suffixes
 * (.pem/.key/...), credential directory segments, and username-independent
 * adjacent segment combos (browser profiles, Windows stores, system hives).
 */
export function pathTargetsCredentials(resolved) {
  const segs = segmentsOf(resolved)
  const lowerSegs = segs.map((s) => s.toLowerCase())
  const base = lowerSegs.length ? lowerSegs[lowerSegs.length - 1] : ''
  if (CRED_BASENAMES.has(base)) return true
  // Windows hive transaction logs carry the same data as the hive itself.
  for (const prefix of CRED_BASENAME_PREFIXES) {
    if (base === prefix || base.startsWith(prefix + '.')) return true
  }
  for (const suffix of CRED_SUFFIXES) {
    if (base.endsWith(suffix)) return true
  }
  for (const seg of lowerSegs) {
    if (CRED_DIR_SEGMENTS.has(seg)) return true
  }
  for (const combo of CRED_COMBOS) {
    for (let i = 0; i + combo.length <= lowerSegs.length; i += 1) {
      if (combo.every((s, j) => lowerSegs[i + j] === s)) return true
    }
  }
  return false
}

/**
 * Whether a resolved path is inside a W0 system area (DSR-001/DSR-005):
 * absolute drive prefixes (the rule model targets the C: system drive) or
 * username-independent segment combos for startup folders / PowerShell profiles.
 */
export function isSystemAreaPath(resolved) {
  const lower = slash(resolved).toLowerCase()
  if (SYSTEM_PREFIXES.some((p) => lower === p || lower.startsWith(p + '/'))) return true
  const segs = segmentsOf(resolved).map((s) => s.toLowerCase())
  for (const combo of SYSTEM_COMBOS) {
    for (let i = 0; i + combo.length <= segs.length; i += 1) {
      if (combo.every((s, j) => segs[i + j] === s)) return true
    }
  }
  return false
}

/**
 * Path-level rule check for the read/write/edit/read_image/grep/glob tools.
 * `metadataOnly` marks name-enumerating calls (glob): only pure credential
 * targets are sensitive at that level. Each category gate reads its
 * read/modify/list leaf according to this call's operation (DSR-006 leaves).
 *
 * @param base - judgment base directory (resolved workspace root; DSR-007).
 * @param raw - raw path argument from the tool call.
 * @param modifying - whether the call mutates the target.
 * @param metadataOnly - whether the call only enumerates names.
 * @param rules - op-level leaves from {@link evaluateRules}.
 * @returns `null` when allowed, else `{ category, modifying, raw }` for the
 *   caller (adapter) to render the deny message.
 */
export function checkPath(base, raw, modifying, metadataOnly = false, rules) {
  if (typeof raw !== 'string' || raw.length === 0) return null
  const resolved = resolvePath(base, raw)
  if (!metadataOnly) {
    if ((modifying ? rules.env.modify : rules.env.read) && isSensitiveEnvName(baseNameOf(resolved))) {
      return { category: 'env', modifying, raw }
    }
    if ((modifying ? rules.git.modify : rules.git.read) && entersGitDir(resolved)) {
      return { category: 'git', modifying, raw }
    }
  }
  const credentialsOn = metadataOnly
    ? rules.credentials.list
    : modifying
      ? rules.credentials.modify
      : rules.credentials.read
  if (credentialsOn && pathTargetsCredentials(resolved)) {
    return { category: 'credentials', modifying, raw }
  }
  // W0: writes into system areas only; reads and listings stay allowed (DSR-005).
  if (rules.system.write && modifying && isSystemAreaPath(resolved)) {
    return { category: 'system', modifying: true, raw }
  }
  return null
}
