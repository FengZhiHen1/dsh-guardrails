// path-check — lexical paths with Windows folding and POSIX case preservation.
// Filesystem identities are observed separately by the target adapter.

import path from 'node:path'
import { CRED_BASENAME_PREFIXES, CRED_BASENAMES, CRED_COMBOS, PUBLIC_KEY_SUFFIX } from './rules.js'

const windowsPath = (value) => /^[a-z]:/i.test(value) || value.startsWith('\\\\')
/** Normalize Windows separators while retaining POSIX filename semantics. */
export const slash = (value) => String(value).replace(/\\/g, '/')
/** Recognize drive, UNC and POSIX absolute paths. */
export const isAbsolutePath = (value) => path.win32.isAbsolute(value) || path.posix.isAbsolute(value)
/** Split a display path into nonempty lexical segments. */
export const segmentsOf = (value) => slash(value).split('/').filter((segment) => segment && segment !== '.')
/** Resolve dot segments using the target path's native lexical dialect. */
export function resolvePath(base, target) {
  const api = windowsPath(target) || windowsPath(base) ? path.win32 : path.posix
  const resolved = api.isAbsolute(target) ? api.normalize(target) : api.join(base, target)
  return api === path.win32 ? slash(resolved) : resolved
}
/** Return the final path segment. */
export const baseNameOf = (value) => segmentsOf(value).at(-1) ?? ''
/** Fold case only for Windows paths. */
export const normCompare = (value) => windowsPath(value) ? slash(path.win32.normalize(value)).toLowerCase() : path.posix.normalize(value)

/** Match exact credential names and trailing segment combinations. */
export function pathTargetsCredentials(resolved) {
  const segs = segmentsOf(normCompare(resolved))
  const base = segs.at(-1) ?? ''
  if (base.endsWith(PUBLIC_KEY_SUFFIX)) return false
  if (CRED_BASENAMES.has(base)) return true
  if (CRED_BASENAME_PREFIXES.some((prefix) => base.startsWith(`${prefix}.`))) return true
  return CRED_COMBOS.some((combo) => combo.length <= segs.length &&
    combo.every((part, index) => segs[segs.length - combo.length + index] === part))
}

/** Identify an exact marked or inherited credential target without filesystem IO. */
export function checkSensitiveRead(resolved, rules) {
  if (rules.builtinSensitiveAsk && pathTargetsCredentials(resolved)) return 'credentials'
  const normalized = normCompare(resolved)
  return rules.sensitiveFiles.some((marked) => normCompare(marked) === normalized) ? 'marked' : null
}
