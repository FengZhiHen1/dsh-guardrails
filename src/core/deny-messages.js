// deny-messages — deny-message rendering and op-level leaf gating.
//
// Boundary: pure string templates and leaf predicates; no imports. Every deny
// message follows the same shape: what was detected and why it is sensitive,
// the legitimate alternative when one exists, NO_BYPASS_GUIDANCE (the same
// intent through another tool/path/command is also blocked and logged), and
// the sanctioned escalation path (only the user can lift a block — the guard
// is a hard block with no runtime approval channel).
// Reference: docs/technical-details/规则模型.md; DSR-006.

const NO_BYPASS_GUIDANCE =
  'Do not try to circumvent this block (a different tool, path tricks, command obfuscation, or subagent delegation): the same intent through another channel is also blocked and logged.'

/** Sanctioned escalation path for a blocked rule: ask the user, never bypass. */
const escalateFor = (rule) =>
  `If this access is genuinely necessary, explain to the user what you need and why, and ask them to run it manually or to relax the "${rule}" rule in the dsh-guardrails plugin config for this profile — only the user can lift a block.`

const envReadReason = (p) =>
  `[guardrails] Blocked: "${p}" is a sensitive .env file. .env files typically hold secrets (API keys, tokens, passwords); reading them risks credential leakage. Safe alternative: read a non-secret variant (.env.example / .env.sample / .env.template) or ask the user to provide the needed values in redacted form. ${NO_BYPASS_GUIDANCE} ${escalateFor('env')}`
const envModifyReason = (p) =>
  `[guardrails] Blocked: "${p}" is a sensitive .env file. Modifying it can overwrite or rotate secrets the user relies on, silently changing their environment or breaking authentication. Safe alternative: write the configuration to a non-sensitive file (e.g. .env.example) or ask the user to update .env manually. ${NO_BYPASS_GUIDANCE} ${escalateFor('env')}`
const envBashReason = () =>
  `[guardrails] Blocked: this shell command references a sensitive .env file. .env files typically hold secrets (API keys, tokens, passwords); direct access risks credential leakage. Safe alternative: read a non-secret variant (.env.example / .env.sample / .env.template) or ask the user to provide the needed values in redacted form. ${NO_BYPASS_GUIDANCE} ${escalateFor('env')}`
const gitReadReason = (p) =>
  `[guardrails] Blocked: "${p}" is inside the .git directory. .git internals (object database, refs, hooks, config) can expose unreferenced or sensitive data, and direct reads are never required for normal work. Safe alternative: use git commands (git status / git log / git diff / git config). ${NO_BYPASS_GUIDANCE} ${escalateFor('git')}`
const gitModifyReason = (p) =>
  `[guardrails] Blocked: "${p}" is inside the .git directory. Hand-editing .git internals (objects, refs, hooks, config) can corrupt the repository beyond repair. Safe alternative: use git commands (git add / git commit / git reset / git branch / git config) instead of touching .git files. ${NO_BYPASS_GUIDANCE} ${escalateFor('git')}`
const gitBashReason = () =>
  `[guardrails] Blocked: this shell command references the .git directory. Direct access to .git internals risks repository corruption and can expose unreferenced data. Safe alternative: use git commands (git status / git log / git diff / git config). ${NO_BYPASS_GUIDANCE} ${escalateFor('git')}`
const CRED_READ_GUIDANCE =
  "Ask the user to handle credential files manually; never read, copy, or modify them on the user's behalf."
const credReadReason = (p) =>
  `[guardrails] Blocked: "${p}" is a credential file (private key, cloud/registry token, or secret store). Reading it can expose secrets that grant impersonation or data access — treated as credential-theft risk. ${CRED_READ_GUIDANCE} ${NO_BYPASS_GUIDANCE} ${escalateFor('credentials')}`
const credModifyReason = (p) =>
  `[guardrails] Blocked: "${p}" is a credential file. Modifying it can break the user's authentication or, done maliciously, hijack their access. ${CRED_READ_GUIDANCE} ${NO_BYPASS_GUIDANCE} ${escalateFor('credentials')}`
const credBashReason = () =>
  `[guardrails] Blocked: this shell command references a credential file or credential directory (private keys, cloud/registry tokens, secret stores) — treated as credential-theft risk. ${CRED_READ_GUIDANCE} ${NO_BYPASS_GUIDANCE} ${escalateFor('credentials')}`

/** Deny message for a destructive-command hit, with a single-line command preview. */
const destructiveReason = (text, command) => {
  const preview = command.trim().replace(/\s+/g, ' ').slice(0, 200)
  return (
    `[guardrails] Blocked: ${text}. Command: ${preview}\n` +
    `This is a hard block: rephrasing the command, aliasing it, or running the same destructive intent through another tool is also blocked. ` +
    `${escalateFor('destructive')}`
  )
}

/** Deny message for the unverifiable-target fail-safe, with a command preview. */
const unverifiableReason = (text, command) => {
  const preview = command.trim().replace(/\s+/g, ' ').slice(0, 200)
  return (
    `[guardrails] Blocked: ${text}. Command: ${preview}\n` +
    `Rewrite the command with literal paths so its target can be verified statically; a dynamically computed target can never be verified. ` +
    `${NO_BYPASS_GUIDANCE} If this access is genuinely necessary, explain to the user what you need and why, and ask them to run it manually.`
  )
}
const systemWriteReason = (p) =>
  `[guardrails] Blocked: "${p}" is inside a Windows system area (Windows / Program Files / ProgramData / Recovery, or the startup / PowerShell-profile locations). Writing or deleting system files can break the operating system or installed applications, and planting files in startup locations or PowerShell profiles is a persistence vector. Safe alternative: keep all writes inside the workspace; if a system setting genuinely needs changing, explain to the user and let them run it manually. ${NO_BYPASS_GUIDANCE} ${escalateFor('system')}`
const systemBashReason = (p) =>
  `[guardrails] Blocked: this shell command writes into a Windows system area ("${p}"). Writing or deleting system files can break the operating system or installed applications, and planting files in startup locations or PowerShell profiles is a persistence vector. Safe alternative: keep all writes inside the workspace; if a system setting genuinely needs changing, explain to the user and let them run it manually. ${NO_BYPASS_GUIDANCE} ${escalateFor('system')}`

/** Render the deny message for a path-level {@link checkPath} hit. */
export const PATH_REASON_BY_CATEGORY = {
  env: (hit) => (hit.modifying ? envModifyReason(hit.raw) : envReadReason(hit.raw)),
  git: (hit) => (hit.modifying ? gitModifyReason(hit.raw) : gitReadReason(hit.raw)),
  credentials: (hit) =>
    hit.modifying ? credModifyReason(hit.raw) : credReadReason(hit.raw),
  system: (hit) => systemWriteReason(hit.raw),
}

/** Deny message for a pwsh content-sensitive reference (`env` | `'git'`). */
export const COMMAND_REFERENCE_REASON = { env: envBashReason, git: gitBashReason }

/** Deny message for a pwsh credential text reference. */
export const credentialBashReason = credBashReason

/** Re-export the command-level reason renderers under the adapter's names. */
export { destructiveReason, systemBashReason, unverifiableReason }

/**
 * Op-level leaf gate (DSR-006): a command classified as read/modify/list
 * consults the matching leaf; the `'unknown'` class is fail-closed — any
 * enabled leaf in the category blocks (full-rules semantics).
 */
export const leafEnabled = (leaf, cls) => {
  if (cls === 'read') return leaf.read
  if (cls === 'modify') return leaf.modify
  if (cls === 'list') return leaf.list
  return Boolean(leaf.read || leaf.modify || leaf.list)
}
