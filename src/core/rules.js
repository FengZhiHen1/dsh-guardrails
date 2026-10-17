// rules — V2 sensitive-target model (narrow builtin list + user-marked paths)
// for the pre-execute `ask` gate.
//
// Boundary: the single maintenance point for every target-list change; must
// stay dependency-free (no imports from other core modules).
// Reference: docs/decisions/DSR-015; references/dsh-guardrails design baseline
// (B/B-2/C/A, 2026-10-16).
//
// V2 semantic shift (DSR-015): this plugin no longer DENIES anything. It asks
// for a native one-shot approval on content reads of (a) a narrow builtin list
// of well-known credential files and (b) files the user explicitly marked
// sensitive in the profile settings. Everything else — including the retired
// `.env`/`.git`/system-area/destructive-command categories — is left to DSH's
// native Auto Review.

/**
 * Builtin high-confidence credential targets (DSR-015, narrow list).
 *
 * Deliberately NARROW: only named credential FILES whose content is key
 * material. The V1 directory-segment rules (`.ssh`/`.aws`/`.kube`/…), file
 * suffixes (`.pem`/`.key`/…) and browser/DPAPI directory combos are retired —
 * they matched mixed-use and non-credential files (the known V1 false-positive
 * surface) and the whole-directory matches also blocked legal routing files.
 * Mixed-use carriers that *can* hold tokens (`.kube/config`, `.config/gcloud/…`,
 * browser profiles) are NOT builtin: the user marks them explicitly via
 * `sensitiveFiles` when their own workflow needs the extra approval.
 */
export const CRED_BASENAMES = new Set([
  'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', 'id_ed25519_sk', 'id_ecdsa_sk',
  '.npmrc', '.pypirc', '.netrc', '.pgpass', '.git-credentials',
  '.credentials.yaml', '.auteur-media-secret',
  'ntuser.dat', 'usrclass.dat', 'pagefile.sys', 'hiberfil.sys',
])

/**
 * Adjacent-segment combos kept in V2: the AWS shared-credentials file (not
 * named `credentials` — it is `<dir>/credentials` inside `~/.aws`) and the
 * three Windows system hives (SAM/SECURITY/SYSTEM under system32\config).
 * Everything else from V1 — cloud CLIs, container auth, browser profiles,
 * DPAPI stores — is retired: mixed-use or high-false-positive; the user marks
 * individual files via `sensitiveFiles` when needed.
 */
export const CRED_COMBOS = [
  ['.aws', 'credentials'],
  ['system32', 'config', 'sam'],
  ['system32', 'config', 'security'],
  ['system32', 'config', 'system'],
]

// Windows hive transaction logs (.LOG1/.LOG2/.regtrans-ms) carry the same data
// as the hive itself: matched as basename === prefix or basename startsWith
// prefix + '.'.
export const CRED_BASENAME_PREFIXES = ['ntuser.dat', 'usrclass.dat']

/** Filename `.pub` stays free (public half of a key pair). */
export const PUBLIC_KEY_SUFFIX = '.pub'

// ---------- V2 config evaluation ----------

/** Every valid top-level config key. */
export const RULE_KEYS = ['sensitiveFiles', 'credentialsReadAsk', 'askTimeoutMs']

/** Bounds of `askTimeoutMs` (milliseconds). `0` disables the plugin-owned
 * bound and leaves the ask to DSH's native (unbounded) approval wait. */
export const ASK_TIMEOUT_MIN = 0
export const ASK_TIMEOUT_MAX = 3_600_000

/** Whether a path is absolute (`C:/x`, `C:\x`, or POSIX `/x`). Local copy:
 * rules.js stays dependency-free (no imports from other core modules). */
const absolutePath = (p) => /^[A-Za-z]:[\\/]/.test(p) || p.startsWith('/')

/**
 * Evaluate the per-row config into plain data.
 *
 * @param config - raw plugin-row config (or settings-resolved value).
 * @returns `{ sensitiveFiles: string[], credentialsReadAsk: boolean, askTimeoutMs: number }`.
 * @throws {Error} on unknown keys or malformed values — the mount fails with
 *   an actionable error instead of silently degrading.
 */
export function evaluateRules(config = {}) {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    throw new Error(
      `dsh-guardrails: plugin config must be an object, got ${config === null ? 'null' : Array.isArray(config) ? 'array' : typeof config}`,
    )
  }
  const unknown = Object.keys(config).filter((key) => !RULE_KEYS.includes(key))
  if (unknown.length > 0) {
    throw new Error(
      `dsh-guardrails: unknown config key(s): ${unknown.join(', ')} — valid keys: ${RULE_KEYS.join(', ')}`,
    )
  }
  const { sensitiveFiles, credentialsReadAsk, askTimeoutMs } = config
  if (credentialsReadAsk !== undefined && typeof credentialsReadAsk !== 'boolean') {
    throw new Error(
      `dsh-guardrails: config "credentialsReadAsk" must be a boolean, got ${JSON.stringify(credentialsReadAsk)}`,
    )
  }
  if (askTimeoutMs !== undefined) {
    if (
      typeof askTimeoutMs !== 'number' ||
      !Number.isInteger(askTimeoutMs) ||
      askTimeoutMs < ASK_TIMEOUT_MIN ||
      askTimeoutMs > ASK_TIMEOUT_MAX
    ) {
      throw new Error(
        `dsh-guardrails: config "askTimeoutMs" must be an integer between ${ASK_TIMEOUT_MIN} and ${ASK_TIMEOUT_MAX} (milliseconds; 0 disables), got ${JSON.stringify(askTimeoutMs)}`,
      )
    }
  }
  if (sensitiveFiles !== undefined) {
    if (!Array.isArray(sensitiveFiles)) {
      throw new Error(
        `dsh-guardrails: config "sensitiveFiles" must be an array of absolute file paths, got ${JSON.stringify(sensitiveFiles)}`,
      )
    }
    for (const entry of sensitiveFiles) {
      if (typeof entry !== 'string' || entry.trim() === '') {
        throw new Error(
          `dsh-guardrails: config "sensitiveFiles" entries must be non-empty strings, got ${JSON.stringify(entry)}`,
        )
      }
      if (!absolutePath(entry)) {
        throw new Error(
          `dsh-guardrails: config "sensitiveFiles" only accepts absolute file paths (no recursion), got ${JSON.stringify(entry)}`,
        )
      }
      if (/[*?]/.test(entry)) {
        throw new Error(
          `dsh-guardrails: config "sensitiveFiles" does not support globs or wildcards (exact file paths only), got ${JSON.stringify(entry)}`,
        )
      }
    }
  }
  return {
    sensitiveFiles: sensitiveFiles ?? [],
    credentialsReadAsk: credentialsReadAsk !== false,
    askTimeoutMs: askTimeoutMs ?? 0,
  }
}
