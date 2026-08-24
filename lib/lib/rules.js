// lib/rules.js — sensitive-target denylist data, text-reference regexes, and
// category switches. The single maintenance point for every denylist change;
// must stay dependency-free (no imports from other lib modules).
//
// Categories (see docs/design/dsh-guardrails/technical-details/rule-model.md):
//   env         — sensitive .env files (content access blocked, listing ok)
//   git         — .git directory internals (content access blocked, listing ok)
//   credentials — keys, cloud tokens, secret stores (read/write/list all blocked)
//   system      — Windows system areas (write blocked, read/list ok — DSR-005)
//   destructive — high-risk commands (command-text analysis only)
// `.dsh` (incl. session history) is intentionally not a category: it is a
// mixed directory with no sensitive-target semantics (see DSR-003 revisit).

export const SAFE_ENV_SUFFIXES = new Set(['example', 'sample', 'template', 'dist', 'default'])

// R0 credential targets (range B of DSR-001): private keys, package/registry
// tokens, secret stores, Windows credential stores / DPAPI / hives, browser
// profiles, memory-dump and hibernation files.
export const CRED_BASENAMES = new Set([
  'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', 'id_ed25519_sk', 'id_ecdsa_sk',
  '.npmrc', '.pypirc', '.netrc', '.pgpass', '.credentials.yaml', '.auteur-media-secret',
  '.git-credentials', 'ntuser.dat', 'usrclass.dat', 'pagefile.sys', 'hiberfil.sys',
])
// Hive basenames whose transaction logs (.LOG1/.LOG2/.regtrans-ms) carry the
// same sensitive data; matched as basename === prefix or basename startsWith
// prefix + '.'.
export const CRED_BASENAME_PREFIXES = ['ntuser.dat', 'usrclass.dat']
export const CRED_SUFFIXES = ['.pem', '.key', '.p12', '.pfx', '.ppk']
export const CRED_DIR_SEGMENTS = new Set(['.ssh', '.aws', '.azure', '.gnupg', '.kube', '.pki'])
// Adjacent segment combos (username-independent path shapes):
// cloud CLIs, container auth, browser profiles, Windows credential stores /
// DPAPI, and the system hive files.
export const CRED_COMBOS = [
  ['.config', 'gcloud'],
  ['.docker', 'config.json'],
  ['google', 'chrome', 'user data'],
  ['microsoft', 'edge', 'user data'],
  ['mozilla', 'firefox', 'profiles'],
  ['microsoft', 'credentials'],
  ['microsoft', 'protect'],
  ['system32', 'config', 'sam'],
  ['system32', 'config', 'security'],
  ['system32', 'config', 'system'],
]

// W0 system area (DSR-001/DSR-005): absolute prefixes of the Windows system
// drive (covered: Windows dir incl. System32/Tasks/hosts/drivers, Program
// Files, ProgramData incl. the certificate stores), plus username-independent
// segment combos for the user startup folder and PowerShell profiles. Reads
// and listings of these are allowed; only writes are blocked.
export const SYSTEM_PREFIXES = [
  'c:/windows',
  'c:/program files',
  'c:/program files (x86)',
  'c:/programdata',
  'c:/recovery',
]
export const SYSTEM_COMBOS = [
  ['appdata', 'roaming', 'microsoft', 'windows', 'start menu', 'programs', 'startup'],
  ['documents', 'windowspowershell'],
  ['documents', 'powershell'],
]

export function isSensitiveEnvName(name) {
  const lower = name.toLowerCase()
  if (lower === '.env') return true
  if (!lower.startsWith('.env.')) return false
  return !SAFE_ENV_SUFFIXES.has(lower.slice(5))
}

// .env reference detection; $env:NAME (PowerShell environment variable) excluded.
export const ENV_REFERENCE = /(?:^|[^A-Za-z0-9_.$-])(\.env(?:\.[A-Za-z0-9_-]+)*)(?![A-Za-z0-9_-])/gi
export const GIT_DIR_REFERENCE = /(?:^|[\s;|&'"`()\[\]{}<>=:\\/])\.git(?:$|[\/\\\s;|&'"`()\[\]{}<>])/
// Command-text references to credential files/dirs. Public keys (.pub) are
// excluded; $env:NAME is not a file path. `.dsh` (incl. session history) is
// intentionally absent: it is not a credential directory and carries no
// sensitive-target rule (see DSR-003 revisit), so its references are allowed.
// The name/dir/combo alternatives mirror the path-level lists above so the
// pwsh channel cannot bypass them (DSR-004: single maintenance point).
const CRED_NAME_PATTERN =
  '(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|\\.npmrc|\\.pypirc|\\.netrc|\\.pgpass|\\.credentials\\.yaml|\\.auteur-media-secret|\\.git-credentials|ntuser\\.dat|usrclass\\.dat|pagefile\\.sys|hiberfil\\.sys)'
const CRED_DIR_PATTERN = '(?:\\.aws|\\.ssh|\\.azure|\\.gnupg|\\.kube|\\.pki)'
const CRED_COMBO_PATTERN =
  '(?:\\.config[\\\\/]gcloud|system32[\\\\/]config[\\\\/](?:sam|security|system)|google[\\\\/]chrome[\\\\/]user data|microsoft[\\\\/]edge[\\\\/]user data|mozilla[\\\\/]firefox[\\\\/]profiles|microsoft[\\\\/]credentials|microsoft[\\\\/]protect)'
export const CRED_TEXT_REFERENCE = new RegExp(
  `(?:^|[^\\w.-])${CRED_NAME_PATTERN}(?![A-Za-z0-9_-]|\\.pub\\b)` +
    `|(?:^|[^\\w.-])${CRED_DIR_PATTERN}(?![A-Za-z0-9_.-])` +
    `|(?:^|[^\\w.-])${CRED_COMBO_PATTERN}(?![A-Za-z0-9_.-])`,
  'i',
)

export const RULE_KEYS = ['env', 'git', 'credentials', 'destructive', 'system', 'unverifiable']

// Per-category leaf keys (DSR-006): operation-level granularity. A category
// config accepts a boolean (whole category on/off) or an object of these
// leaves; subkeys default to true when absent.
export const CATEGORY_LEAF_KEYS = {
  env: ['read', 'modify'],
  git: ['read', 'modify'],
  credentials: ['read', 'modify', 'list'],
  system: ['write'],
  destructive: ['git', 'machine', 'eval', 'cli', 'bulk', 'target'],
}

const CATEGORY_KEYS = ['env', 'git', 'credentials', 'destructive', 'system']

// Evaluate one category value into its leaf object. undefined → all on;
// boolean → all equal to it; object → per-leaf, missing leaves default true.
function evaluateCategory(value, leafKeys, category) {
  if (value === undefined) return Object.fromEntries(leafKeys.map((key) => [key, true]))
  if (typeof value === 'boolean') return Object.fromEntries(leafKeys.map((key) => [key, value]))
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(
      `dsh-guardrails: config "${category}" must be a boolean or an object with keys: ${leafKeys.join(', ')}`,
    )
  }
  const unknownSub = Object.keys(value).filter((key) => !leafKeys.includes(key))
  if (unknownSub.length > 0) {
    throw new Error(
      `dsh-guardrails: unknown "${category}" config key(s): ${unknownSub.join(', ')} — valid keys: ${leafKeys.join(', ')}`,
    )
  }
  for (const key of leafKeys) {
    const v = value[key]
    if (v !== undefined && typeof v !== 'boolean') {
      throw new Error(
        `dsh-guardrails: config "${category}.${key}" must be a boolean, got ${JSON.stringify(v)}`,
      )
    }
  }
  return Object.fromEntries(leafKeys.map((key) => [key, value[key] !== false]))
}

// Evaluate the per-row config into op-level leaves; every defense layer
// defaults on. Invalid configs (unknown keys, non-boolean values, non-object
// category values) fail the mount with an actionable error instead of
// silently degrading (quality standard §7.2). v1 five-boolean categories
// remain valid (equivalent to whole category on/off).
export function evaluateRules(config = {}) {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    throw new Error(
      `dsh-guardrails: plugin config must be an object, got ${config === null ? 'null' : Array.isArray(config) ? 'array' : typeof config}`,
    )
  }
  if (config.unverifiable !== undefined && typeof config.unverifiable !== 'boolean') {
    throw new Error(
      `dsh-guardrails: config "unverifiable" must be a boolean, got ${JSON.stringify(config.unverifiable)}`,
    )
  }
  const unknown = Object.keys(config).filter((key) => !RULE_KEYS.includes(key))
  if (unknown.length > 0) {
    throw new Error(
      `dsh-guardrails: unknown config key(s): ${unknown.join(', ')} — valid keys: ${RULE_KEYS.join(', ')}`,
    )
  }
  const rules = { unverifiable: config.unverifiable !== false }
  for (const key of CATEGORY_KEYS) {
    rules[key] = evaluateCategory(config[key], CATEGORY_LEAF_KEYS[key], key)
  }
  return rules
}
