// lib/path-check.js — path normalization and the path-level rule check.
// Depends on lib/rules.js for denylist data and category switches.

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

// ---------- pure path helpers (synchronous; no async fs) ----------
export const slash = (p) => String(p).replace(/\\/g, '/')
// Windows absolute paths may use either separator: C:/x or C:\x
export const isAbsolutePath = (p) => /^[A-Za-z]:[\\/]/.test(p) || p.startsWith('/')
export const segmentsOf = (p) => slash(p).split('/').filter((s) => s.length > 0 && s !== '.')

export function resolvePath(base, target) {
  if (isAbsolutePath(target)) return slash(target)
  const out = []
  for (const s of segmentsOf(base).concat(segmentsOf(target))) {
    if (s === '..') out.pop()
    else out.push(s)
  }
  return out.join('/')
}

export const baseNameOf = (p) => {
  const segs = slash(p).split('/').filter(Boolean)
  return segs.length ? segs[segs.length - 1] : ''
}

export const normCompare = (p) => slash(p).toLowerCase()

// ---------- category predicates (resolved-path level) ----------
export function entersGitDir(resolved) {
  return segmentsOf(resolved).includes('.git')
}

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

// W0 system area: absolute prefixes (drive-letter specific; the rule model
// targets the C: system drive) and username-independent segment combos for
// startup folders and PowerShell profiles.
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

// ---------- path-level check ----------
// Returns null when allowed, or { category, modifying, raw } for the caller
// (index.js) to render the deny message. metadataOnly: the call only
// enumerates names (glob / listing commands); only pure credential targets
// are sensitive at that level. `rules` carries the op-level leaves from
// evaluateRules (DSR-006): each category gate reads its read/modify/list/write
// leaf according to the operation of this call.
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
