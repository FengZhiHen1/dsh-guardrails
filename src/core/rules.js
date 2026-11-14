// rules — profile-owned exact files and the inherited narrow credential list.
// Candidate credential families are not added without policy approval.

/** Inherited exact credential-carrier names; public keys remain excluded. */
export const CRED_BASENAMES = new Set([
  'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', 'id_ed25519_sk', 'id_ecdsa_sk',
  '.npmrc', '.pypirc', '.netrc', '.pgpass', '.git-credentials',
  '.credentials.yaml', '.auteur-media-secret',
  '.env', '.env.local',
  'ntuser.dat', 'usrclass.dat', 'pagefile.sys', 'hiberfil.sys',
])
/** `.env.*.local` dotenv overrides carry real secrets. Prefix+suffix string test:
 * no regex and no backtracking. `.env.example`/`.env.sample`/`.env.template` are
 * templates and are deliberately not credential carriers. */
export const ENV_LOCAL_PREFIX = '.env.'
export const ENV_LOCAL_SUFFIX = '.local'
export function isEnvLocalCredentialName(base) {
  if (typeof base !== 'string') return false
  return base.length > ENV_LOCAL_PREFIX.length + ENV_LOCAL_SUFFIX.length &&
    base.startsWith(ENV_LOCAL_PREFIX) &&
    base.endsWith(ENV_LOCAL_SUFFIX)
}
/** Exact trailing path segments, never whole credential directories. */
export const CRED_COMBOS = [
  ['.aws', 'credentials'], ['system32', 'config', 'sam'],
  ['system32', 'config', 'security'], ['system32', 'config', 'system'],
]
/** Hive transaction logs retain the inherited protection. */
export const CRED_BASENAME_PREFIXES = ['ntuser.dat', 'usrclass.dat']
/** Public key suffix excluded from credential-carrier matching. */
export const PUBLIC_KEY_SUFFIX = '.pub'
/** Supported settings. */
export const RULE_KEYS = ['sensitiveFiles', 'builtinSensitiveAsk', 'askTimeoutMs']
/** Zero is a legacy alias for the bounded default, never unlimited waiting. */
export const ASK_TIMEOUT_MIN = 0
/** One hour caps interactive waits even in unattended profiles. */
export const ASK_TIMEOUT_MAX = 3_600_000
/** Two minutes permits an interactive decision while bounding unattended calls. */
export const DEFAULT_ASK_TIMEOUT_MS = 120_000

const absolutePath = (value) => /^[A-Za-z]:[\\/]/.test(value) || value.startsWith('/') || value.startsWith('\\\\')

/** Validate configuration and produce an independent bounded snapshot.
 * @throws {Error} If any configuration key or value is unsupported.
 */
export function evaluateRules(config = {}) {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    throw new Error('dsh-guardrails: plugin config must be an object')
  }
  const unknown = Object.keys(config).filter((key) => !RULE_KEYS.includes(key))
  if (unknown.length) throw new Error(`dsh-guardrails: unknown config key(s): ${unknown.join(', ')}`)
  const { sensitiveFiles = [], builtinSensitiveAsk = true, askTimeoutMs = DEFAULT_ASK_TIMEOUT_MS } = config
  if (typeof builtinSensitiveAsk !== 'boolean') throw new Error('builtinSensitiveAsk must be a boolean')
  if (!Number.isInteger(askTimeoutMs) || askTimeoutMs < ASK_TIMEOUT_MIN || askTimeoutMs > ASK_TIMEOUT_MAX) {
    throw new Error(`askTimeoutMs must be an integer between ${ASK_TIMEOUT_MIN} and ${ASK_TIMEOUT_MAX}`)
  }
  // A finite list prevents profile mistakes from creating unbounded per-call probes.
  if (!Array.isArray(sensitiveFiles) || sensitiveFiles.length > 1024) {
    throw new Error('sensitiveFiles must be an array of at most 1024 absolute file paths')
  }
  for (const entry of sensitiveFiles) {
    if (typeof entry !== 'string' || entry.trim() === '') throw new Error('sensitiveFiles entries must be non-empty strings')
    if (entry.length > 32768 || entry.includes('\0') || !absolutePath(entry)) {
      throw new Error('sensitiveFiles only accepts bounded absolute file paths')
    }
    if (/[*?]/.test(entry)) throw new Error('sensitiveFiles does not support globs or wildcards')
  }
  return { sensitiveFiles: [...sensitiveFiles], builtinSensitiveAsk, askTimeoutMs: askTimeoutMs || DEFAULT_ASK_TIMEOUT_MS }
}
