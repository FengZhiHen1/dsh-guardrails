// rules — profile-owned exact files and the inherited narrow credential list.
// Candidate credential families are not added without policy approval.

/** Inherited exact credential-carrier names; public keys remain excluded.
 * Ordinary (unmarked) `.env` files are deliberately absent: only a Profile
 * `sensitiveFiles` mark protects them (需求 R-05, DSR-015 C+A); the template
 * names `.env.example`/`.env.sample`/`.env.template` were never carriers. */
export const CRED_BASENAMES = new Set([
  'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', 'id_ed25519_sk', 'id_ecdsa_sk',
  '.npmrc', '.pypirc', '.netrc', '.pgpass', '.git-credentials', '.my.cnf',
  '.credentials.yaml', '.auteur-media-secret',
  'ntuser.dat', 'usrclass.dat', 'pagefile.sys', 'hiberfil.sys',
])
/** Exact trailing path segments, never whole credential directories.
 * The 2026-11 additions are the confirmed core CLI/cloud credential carriers
 * (kubectl, docker, gh, gcloud, azure, MariaDB/MySQL option file); extension
 * classes (`.pem`/`.key`) and directory-level entries stay excluded (R-04). */
export const CRED_COMBOS = [
  ['.aws', 'credentials'], ['system32', 'config', 'sam'],
  ['system32', 'config', 'security'], ['system32', 'config', 'system'],
  ['.kube', 'config'], ['.docker', 'config.json'],
  ['.config', 'gh', 'hosts.yml'],
  ['.config', 'gcloud', 'application_default_credentials.json'],
  ['.config', 'gcloud', 'credentials.db'], ['.config', 'gcloud', 'access_tokens.db'],
  // `.config/gcloud/legacy_credentials` is a DIRECTORY (per-account ADC files live
  // under `<account>/adc.json`); directory-level entries stay excluded (R-04).
  // Segments compare exactly on POSIX and case-folded on Windows; the entries keep
  // the canonical spelling of the real carrier files.
  // MS Learn names the legacy ADAL cache both `accessToken.json` and
  // `accessTokens.json`; both exact spellings are kept.
  ['.azure', 'accessTokens.json'], ['.azure', 'accessToken.json'],
]
/** Hive transaction logs retain the inherited protection. */
export const CRED_BASENAME_PREFIXES = ['ntuser.dat', 'usrclass.dat']
/** Public key suffix excluded from credential-carrier matching. */
export const PUBLIC_KEY_SUFFIX = '.pub'

/** Lower-cased basenames for a case-insensitive credential-name text scan. */
const CRED_BASENAME_SET = new Set([...CRED_BASENAMES].map((name) => name.toLowerCase()))
/** A PEM/DER private-key header in free command text. */
const PRIVATE_KEY_HEADER = /-----\s*BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/i

/**
 * Static, allocation-bounded scan for a credential-carrier NAME in analyzed command,
 * terminal, or script text (规则模型「凭据防泄露」R-04). It matches whole basenames only,
 * so path prefixes do not match; ordinary unmarked `.env` names are absent from the list
 * and never match (R-05). It answers "does this text reference a credential-bearing file
 * name or a private key header?"; it can only raise a confirmation, never grant one.
 */
export function textMentionsCredential(text) {
  if (typeof text !== 'string' || text.length === 0) return false
  if (PRIVATE_KEY_HEADER.test(text)) return true
  const tokens = text.split(/[\s"'`=:;,,()\[\]{}<>|&]+/)
  for (const token of tokens) {
    if (!token) continue
    const base = token.replace(/\\/g, '/').split('/').pop()
    if (!base) continue
    if (CRED_BASENAME_SET.has(base.toLowerCase())) return true
  }
  return false
}

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
