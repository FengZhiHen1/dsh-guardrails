// path-check — path normalization and the V2 sensitive-read match.
//
// Boundary: pure synchronous helpers (no fs, no async); depends on
// core/rules.js for the target lists only.
// Reference: docs/decisions/DSR-015.

import {
  CRED_BASENAME_PREFIXES,
  CRED_BASENAMES,
  CRED_COMBOS,
  PUBLIC_KEY_SUFFIX,
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

/**
 * Whether a resolved path targets a builtin credential file.
 * Narrow V2 list: named credential basenames (incl. hive transaction-log
 * prefixes), `.pub` excluded, and the single `~/.aws/credentials` combo.
 *
 * @param resolved - slash-normalized path.
 */
export function pathTargetsCredentials(resolved) {
  const segs = segmentsOf(resolved)
  const lowerSegs = segs.map((s) => s.toLowerCase())
  const base = lowerSegs.length ? lowerSegs[lowerSegs.length - 1] : ''
  if (base.endsWith(PUBLIC_KEY_SUFFIX)) return false
  if (CRED_BASENAMES.has(base)) return true
  for (const prefix of CRED_BASENAME_PREFIXES) {
    if (base === prefix || base.startsWith(prefix + '.')) return true
  }
  for (const combo of CRED_COMBOS) {
    for (let i = 0; i + combo.length <= lowerSegs.length; i += 1) {
      if (combo.every((s, j) => lowerSegs[i + j] === s)) return true
    }
  }
  return false
}

/**
 * V2 sensitive-read match for one resolved path.
 *
 * Builtin list first (when enabled), then the user-marked list. `glob` and
 * other metadata enumeration never reach this function (the adapter only calls
 * it for content reads); writes/edits/deletes are out of V2 scope entirely.
 *
 * @param resolved - slash-normalized absolute path.
 * @param rules - `{ sensitiveFiles, credentialsReadAsk }` from {@link evaluateRules}.
 * @returns `'credentials'` | `'marked'` | `null`.
 */
export function checkSensitiveRead(resolved, rules) {
  if (rules.credentialsReadAsk && pathTargetsCredentials(resolved)) return 'credentials'
  const lower = normCompare(resolved)
  if (rules.sensitiveFiles.some((p) => normCompare(p) === lower)) return 'marked'
  return null
}
