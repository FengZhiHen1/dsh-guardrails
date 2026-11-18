// internal.js — pure helpers shared inside the evidence adapter.
// Boundary: no filesystem, process or network access; every helper only inspects its
// arguments, so each one is synchronously testable on any host.

import path from 'node:path'

/**
 * Comparison form for identity/equality checks: case-folded ONLY where the volume is
 * case-insensitive (Windows). Both sides are realpaths or proven spellings, so folding
 * can merge only spellings of the same directory, never distinct entries.
 */
export function comparable(value, windows) {
  return windows ? String(value).toLowerCase() : String(value)
}

/**
 * True when `child` equals `parent` or lies inside it, by EXACT path-segment prefix
 * after separator normalization. Used on the GRANTING side (boundary containment for
 * rebuildable exemptions), so it must stay case-PRESERVING by default: NTFS can host
 * case-sensitive directories, and Node's `path.relative` folds case on Windows — a
 * case-folded containment check could wrongly grant an exemption to an outside project.
 * A case alias we cannot prove simply yields "not contained" (the safe direction).
 */
export function withinExact(parent, child, foldCase = false) {
  const norm = (value) => {
    let p = String(value).replace(/\\/g, '/')
    p = p.replace(/\/{2,}/g, '/')
    if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1)
    return p
  }
  const fold = (value) => (foldCase ? value.toLowerCase() : value)
  const a = fold(norm(parent))
  const b = fold(norm(child))
  if (b === a) return true
  const withSep = a.endsWith('/') ? a : `${a}/`
  return b.startsWith(withSep)
}

/**
 * True when a directory entry name is a representable, well-formed string. A replacement
 * char (U+FFFD) means the OS bytes could not be decoded to the real name, and an unpaired
 * surrogate means the JS string is not well-formed; a path built from either cannot
 * address the actual entry, so the caller must not claim it was observed.
 */
export function isWellFormedName(name) {
  if (typeof name !== 'string' || name.length === 0) return false
  if (name.includes('\uFFFD')) return false
  if (typeof name.isWellFormed === 'function' ? !name.isWellFormed() : /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(name)) return false
  return true
}

/** True when any path segment is `..`: lexical resolution could hide a link escape. */
export function hasDotDot(value) {
  return String(value).split(/[\\/]/).some((segment) => segment === '..')
}

/** A usable execution cwd: absolute, no `..`, normalized. */
export function absoluteCwd(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || !path.isAbsolute(raw) || hasDotDot(raw)) return null
  return path.normalize(raw)
}

/**
 * Resolve a raw target to an absolute local path against a domain cwd. Refuses NUL and
 * `..` segments (lexical resolution could hide a link escape); returns null when the
 * relative target has no provable base.
 */
export function resolveLocal(raw, cwd) {
  if (typeof raw !== 'string' || raw === '' || raw.includes('\u0000') || hasDotDot(raw)) return null
  if (path.isAbsolute(raw)) return path.normalize(raw)
  return cwd ? path.resolve(cwd, raw) : null
}
