// rules — sensitive-target denylist data, text-reference regexes, category switches.
//
// Boundary: the single maintenance point for every denylist change; must stay
// dependency-free (no imports from other core modules).
// Reference: docs/technical-details/规则模型.md; DSR-001/003/004/006.

/** Safe `.env.*` suffixes: non-secret variants that stay readable. */
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
// DSR-013: named exceptions inside a credential directory. A credential dir is
// blocked as a whole because its *contents* are key material, but a routing
// table is not key material: `~/.ssh/config` maps Host aliases to host/user/key
// file and holds no secret. Blocking it made the sanctioned path
// (`ssh <alias>`) unreachable for an agent — the alias list could only come from
// the user, and `glob ~/.ssh` is blocked too, so discovery was impossible.
//
// Keyed by directory segment so the relaxation is enumerable and stays narrow:
// the file must sit DIRECTLY in that directory and be the final segment
// (`~/.ssh/sub/config` and `~/.ssh/config.bak` stay blocked), and the exception
// is per directory — `.kube/config` is a real token/certificate store and is
// deliberately NOT exempt, because the exception is a name inside one known
// directory, not the name `config` everywhere. Single maintenance point
// (DSR-004): CRED_DIR_PATTERN is derived from this map below, never hand-written.
export const SAFE_CRED_DIR_FILES = new Map([['.ssh', new Set(['config'])]])
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

/**
 * Whether a basename is a sensitive `.env` file.
 * `.env` exactly → true; `.env.<suffix>` → true unless the suffix is a known
 * non-secret variant ({@link SAFE_ENV_SUFFIXES}). Case-insensitive.
 */
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
// Derived from CRED_DIR_SEGMENTS + SAFE_CRED_DIR_FILES rather than hand-written,
// so the path channel and the command-text channel cannot drift apart (DSR-004:
// `rules.js` is the single maintenance point, and `CRED_DIR_PATTERN` mirrors the
// path-level lists so the pwsh channel cannot bypass them).
//
// A directory with named safe files carries its own exclusion lookahead. The
// exclusion applies only when the safe name is the FINAL path segment: `/config`
// followed by neither a name character nor another separator. Hence
// `~/.ssh/config` stops matching while `~/.ssh/config.bak` and
// `~/.ssh/sub/config` keep matching (the latter because the trailing `(?![\\/])`
// fails). A real filesystem cannot nest under a `config` file, but the text
// channel must not be more permissive than the path channel on principle.
const SEP = '[\\\\/]'
const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const dirAlternative = (dir, allowSafeFiles) => {
  const safeFiles = allowSafeFiles ? SAFE_CRED_DIR_FILES.get(dir) : undefined
  if (safeFiles === undefined || safeFiles.size === 0) return escapeRegex(dir)
  const names = [...safeFiles].map(escapeRegex).join('|')
  return `${escapeRegex(dir)}(?!${SEP}(?:${names})(?![A-Za-z0-9_.-])(?!${SEP}))`
}
const buildCredDirPattern = (allowSafeFiles) =>
  `(?:${[...CRED_DIR_SEGMENTS].map((dir) => dirAlternative(dir, allowSafeFiles)).join('|')})`
// Read/list form: honours the DSR-013 named exceptions.
const CRED_DIR_PATTERN = buildCredDirPattern(true)
// Modify form: no exceptions at all. The relaxation is read-only (DSR-013), and
// the two channels must agree — otherwise `Set-Content ~/.ssh/config` would slip
// through the pwsh channel while `write` is blocked on the path channel, which is
// exactly the bypass DSR-004's mirrored pattern exists to prevent.
const CRED_DIR_PATTERN_STRICT = buildCredDirPattern(false)
const CRED_COMBO_PATTERN =
  '(?:\\.config[\\\\/]gcloud|system32[\\\\/]config[\\\\/](?:sam|security|system)|google[\\\\/]chrome[\\\\/]user data|microsoft[\\\\/]edge[\\\\/]user data|mozilla[\\\\/]firefox[\\\\/]profiles|microsoft[\\\\/]credentials|microsoft[\\\\/]protect)'
const buildCredTextReference = (dirPattern) =>
  new RegExp(
    `(?:^|[^\\w.-])${CRED_NAME_PATTERN}(?![A-Za-z0-9_-]|\\.pub\\b)` +
      `|(?:^|[^\\w.-])${dirPattern}(?![A-Za-z0-9_.-])` +
      `|(?:^|[^\\w.-])${CRED_COMBO_PATTERN}(?![A-Za-z0-9_.-])`,
    'i',
  )
export const CRED_TEXT_REFERENCE = buildCredTextReference(CRED_DIR_PATTERN)
/**
 * Same reference check WITHOUT the DSR-013 named exceptions, for commands that
 * modify: a config file may be read (the alias table is not key material) but
 * never written, since rewriting it silently redirects where connections go.
 * Exported so `check-command.js` can pick the form matching the operation class;
 * both forms are built here from the shared lists (DSR-004 single source).
 */
export const CRED_TEXT_REFERENCE_STRICT = buildCredTextReference(CRED_DIR_PATTERN_STRICT)

/** Every valid top-level config key, in README order. */
export const RULE_KEYS = ['env', 'git', 'credentials', 'destructive', 'system', 'unverifiable']

// Per-category leaf keys (DSR-006): operation-level granularity. A category
// config accepts a boolean (whole category on/off) or an object of these
// leaves; subkeys default to true when absent.
export const CATEGORY_LEAF_KEYS = {
  env: ['read', 'modify'],
  git: ['read', 'modify'],
  credentials: ['read', 'modify', 'list'],
  system: ['write'],
  destructive: ['git', 'machine', 'eval', 'cli', 'bulk', 'target', 'chain', 'misuse'],
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

/**
 * Evaluate the per-row config into op-level leaves; every defense layer defaults on.
 * v1 five-boolean categories remain valid (equivalent to whole category on/off).
 *
 * @param config - raw plugin-row config (or settings-resolved value).
 * @returns `{ unverifiable, env, git, credentials, destructive, system }` leaf object.
 * @throws {Error} on unknown keys, non-boolean leaves, or non-object category
 *   values — the mount fails with an actionable error instead of silently degrading.
 */
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
