// filesystem-path — pure provider/path-domain predicate shared by the intent
// classifier, the target observer and the deletion planner.
// Boundary: no filesystem, platform or process access; it only inspects a string.
//
// A deletion target must designate a real local filesystem path. PowerShell lets a
// path carry a provider-qualified form (`FileSystem::C:\x`, `Registry::HKLM\...`,
// `Variable:\x`, `HKLM:\...`), a custom PSDrive (`_drive:\x`, `123:\x`, `My Drive:\x`)
// and other schemes (`http:`, `mshta:`...). Node/planner path resolution does not model
// those namespaces, so they must be refused BEFORE any resolution; relying on ENOENT is
// not a provider defense (an entry could exist).

/**
 * True when a deletion target uses an unsupported provider/scheme/PSDrive form and must
 * be rejected before Node path resolution.
 *
 * Detection uses the FIRST PATH COMPONENT (text before the first `/` or `\`), not only
 * URI syntax: any `:` inside the first component marks a provider/PSDrive/drive prefix.
 * The only accepted colon form is a single-letter drive followed immediately by a path
 * separator (`X:/...` or `X:\...`). A `::` PowerShell provider separator anywhere is
 * always refused.
 *
 * @param {unknown} value candidate target (typically a string; only strings are judged)
 * @returns {boolean} true when the value is an unsupported provider/scheme path
 */
export function isUnsupportedProviderPath(value) {
  if (typeof value !== 'string') return false
  // A PowerShell provider separator anywhere disqualifies the path (FileSystem::, etc.).
  if (value.includes('::')) return true
  // First path component = text before the first separator. Any colon there is a
  // provider / PSDrive / drive prefix (names may be `_drive`, `123`, `My Drive`).
  const firstComponent = value.split(/[\\/]/, 1)[0]
  if (!firstComponent.includes(':')) return false
  // The sole accepted prefix is a single drive letter AND a real separator follows.
  const driveQualified = /^[A-Za-z]:$/.test(firstComponent) && value.length > 2 && /[\\/]/.test(value[2])
  return !driveQualified
}

export default isUnsupportedProviderPath
