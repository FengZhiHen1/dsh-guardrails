// dsh-guardrails — DSH permission protection layer (thin entry).
//
// Hard-blocks (no confirmation prompt) AI-initiated tool calls that:
//   1. access sensitive .env files          (read/write/edit/grep/pwsh)
//   2. access .git directory internals      (read/write/edit/grep/glob/pwsh)
//   3. access credential files              (ssh keys, cloud/registry tokens, secret stores)
//   4. write into Windows system areas      (W0: write-only ban; reads/listings allowed)
//   5. run high-risk destructive commands   (pwsh, PowerShell dialect)
//
// Scope notes:
// - Guarded tool names are exactly: read / write / edit / read_image / grep /
//   glob / pwsh. Other tools are not covered by this plugin's rules (the
//   harness's own permission pipeline still applies to them).
// - Only AI tool calls pass through the tools pipeline; the user's own
//   commands are not intercepted.
// - Ordinary file deletion is allowed; only devastating operations are blocked.
// - Pure static analysis: no process is spawned and no fs service is touched.
// - Access is classified by operation: content reads/writes hit the full
//   rules; metadata listing (Get-ChildItem/Test-Path/... or glob) only hits
//   pure credential targets — `.dsh` (incl. session history) carries no
//   sensitive-target rule at all (see DSR-003 revisit), so `.dsh` paths are
//   not intercepted. Unrecognized commands stay conservative (full rules).
// - pwsh text is literally reconstructed first: evaluable $(...) splicing
//   (`$('nv')`) and same-command variable assignments (`$p='.env'`) are
//   resolved to their values, so hidden sensitive names stay visible to the
//   text rules. A remaining dynamic $(...) target on a content/removal verb
//   is unverifiable and blocked as a category-independent fail-safe.
// - Defense layers are configurable through the plugin row config (DSR-006):
//   each category accepts a boolean (whole category on/off) or an object of
//   op-level leaves — env/git: { read, modify }, credentials: { read,
//   modify, list }, system: { write }, destructive: { git, machine, eval,
//   cli, bulk, target } — plus the category-independent `unverifiable`
//   fail-safe (default on). Leaves default on; invalid configs (unknown
//   keys, non-boolean values, non-object category values) fail the mount
//   with an actionable error instead of silently degrading.
//
// Module layout (see docs/design/dsh-guardrails/technical-details/engineering.md):
//   lib/rules.js        — denylist data + text-reference regexes + switches
//   lib/path-check.js   — path normalization + checkPath + system-area test
//   lib/command.js      — command lexing, verbs, listing mode, text refs,
//                         cd-chain state, system-write (W0) detection
//   lib/destructive.js  — destructive command analysis
// This file owns config evaluation, deny-message rendering, and the guard hook.
//
// Source of truth: E:\Project\DSH_Plugins\plugins\dsh-guardrails (this repo).
// Distributed as a DSH bundle: package.json declares dsh.bundle.patch, the
// install row ships in cordis.patch.yml, and profiles enable it by listing
// this package in dsh.profile.bundles (via `dsh plugin --profile <name> add`).
// The test profile mounts it from source; the web profile takes it as a github
// git dependency (lockfile-pinned) until the package is published. Both
// profiles must pass the test smoke gate before any web/release install.
// Override the row config by id in a profile's own cordis.patch.yml.

import z from '@deepseek-ai/schemastery'
import {
  CATEGORY_LEAF_KEYS,
  CRED_TEXT_REFERENCE,
  evaluateRules,
} from './lib/rules.js'
import { checkPath, resolvePath } from './lib/path-check.js'
import {
  assessContentClass,
  assessSystemWrite,
  assessUnverifiable,
  detectContentSensitiveRef,
  isListingOnly,
  resolveCommandLiterals,
} from './lib/command.js'
import { assessDestructive } from './lib/destructive.js'

// ---------- deny messages ----------
// Every deny message follows the same shape:
//   1. what was detected and why it is sensitive (specific to category/op)
//   2. the legitimate alternative, when one exists
//   3. NO_BYPASS_GUIDANCE — the agent must not try to circumvent the block;
//      the guard statically analyzes every tool call, so the same intent
//      expressed through another tool/path/command still hits it (and is logged)
//   4. escalateFor(rule) — the sanctioned escalation path: the agent explains
//      the need to the user and asks them to run the operation manually or to
//      relax the named rule in the plugin config. The guard is a hard block
//      with no runtime approval channel, so only the user can lift it.
const NO_BYPASS_GUIDANCE =
  'Do not try to circumvent this block (a different tool, path tricks, command obfuscation, or subagent delegation): the same intent through another channel is also blocked and logged.'
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
const destructiveReason = (text, command) => {
  const preview = command.trim().replace(/\s+/g, ' ').slice(0, 200)
  return (
    `[guardrails] Blocked: ${text}. Command: ${preview}\n` +
    `This is a hard block: rephrasing the command, aliasing it, or running the same destructive intent through another tool is also blocked. ` +
    `${escalateFor('destructive')}`
  )
}
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

const PATH_REASON_BY_CATEGORY = {
  env: (hit) => (hit.modifying ? envModifyReason(hit.raw) : envReadReason(hit.raw)),
  git: (hit) => (hit.modifying ? gitModifyReason(hit.raw) : gitReadReason(hit.raw)),
  credentials: (hit) =>
    hit.modifying ? credModifyReason(hit.raw) : credReadReason(hit.raw),
  system: (hit) => systemWriteReason(hit.raw),
}

// Op-level leaf gate (DSR-006): a command classified as read/modify/list
// consults the matching leaf; the 'unknown' class is fail-closed — any
// enabled leaf in the category blocks (full-rules semantics).
const leafEnabled = (leaf, cls) => {
  if (cls === 'read') return leaf.read
  if (cls === 'modify') return leaf.modify
  if (cls === 'list') return leaf.list
  return Boolean(leaf.read || leaf.modify || leaf.list)
}

// ---------- config schema (official DSH config boundary) ----------
// Every cordis config entry may carry a `config` block; the plugin declares a
// Schemastery schema that the loader validates BEFORE apply and fills in with
// defaults (cordis-tutorial §5): `apply` always receives a complete validated
// config, and a wrong config fails the mount with the loader's actionable
// ValidationError (fiber FAILED) — no hand-rolled silent degradation.
// Category keys accept a boolean (whole category on/off, v1-compatible) or an
// object of op-level leaves; `evaluateRules` then normalizes to leaves.
const leafObject = (keys) =>
  z.object(Object.fromEntries(keys.map((key) => [key, z.boolean().default(true)])))
const categorySchema = (keys) => z.union([z.boolean(), leafObject(keys)]).default(true)

export const Config = z.object({
  env: categorySchema(CATEGORY_LEAF_KEYS.env),
  git: categorySchema(CATEGORY_LEAF_KEYS.git),
  credentials: categorySchema(CATEGORY_LEAF_KEYS.credentials),
  system: categorySchema(CATEGORY_LEAF_KEYS.system),
  destructive: categorySchema(CATEGORY_LEAF_KEYS.destructive),
  unverifiable: z.boolean().default(true),
})

export const name = 'dsh-guardrails'
export const inject = ['tools']

/**
 * Settings namespace this plugin owns — the official settings-seam pairing
 * key: Host registers it, the browser card in `settings.plugin.item` is keyed
 * by the same value, and the "插件配置" tab pairs the two (DSH cookbook
 * "adding a settings card").
 */
export const SETTINGS_NS = 'dsh-guardrails'

export function apply(ctx, config = {}) {
  // The composition entry is the `base` of the settings section: the user
  // document overrides it, and when no settings service mounts the plugin
  // keeps working exactly as composed (official `installSettingsSection`
  // semantics, replicated against the raw service so this package depends on
  // nothing beyond schemastery).
  const entryRules = evaluateRules(config)
  let source = () => entryRules
  let rules = source()
  const rebuild = () => {
    rules = evaluateRules(source())
  }
  ctx.inject(['settings'], (sctx) => {
    const scope = sctx.settings.register(SETTINGS_NS, Config, { base: entryRules })
    source = () => scope.get()
    sctx.effect(() => () => {
      // Settings provider detaching (or this fiber unloading): fall back to
      // the composition entry and re-judge what the guard derived.
      source = () => entryRules
      rebuild()
    })
    rebuild()
    scope.watch(() => rebuild())
  })

  const sandboxPolicy = ctx.get('sandboxPolicy')
    const workspaceRoot =
      sandboxPolicy && typeof sandboxPolicy.workspaceRoot === 'string'
        ? sandboxPolicy.workspaceRoot
        : ''

    function checkCommand(base, command) {
      // Literal reconstruction first: evaluable $(...) splicing and
      // same-command variable assignments are rewritten to their values so
      // every downstream check sees the real command. Each pwsh call runs in
      // a fresh process, so no variable can persist across calls.
      const resolved = resolveCommandLiterals(command)
      const listingOnly = isListingOnly(resolved)
      const contentClass = assessContentClass(resolved)
      if (!listingOnly) {
        const category = detectContentSensitiveRef(resolved)
        if (category === 'env' && leafEnabled(rules.env, contentClass)) return envBashReason()
        if (category === 'git' && leafEnabled(rules.git, contentClass)) return gitBashReason()
      }
      if (leafEnabled(rules.credentials, contentClass) && CRED_TEXT_REFERENCE.test(resolved))
        return credBashReason()
      if (!listingOnly) {
        // W0 system-area writes (write verbs / redirects / cd chains).
        if (rules.system.write) {
          const systemHit = assessSystemWrite(base, resolved)
          if (systemHit) return systemBashReason(systemHit.path)
        }
        // Unverifiable-target gate (category-independent fail-safe): after
        // reconstruction, a remaining $(...) as the command itself or in a
        // content/removal verb argument means the target is computed at run
        // time — it cannot be verified, so block conservatively. Controlled
        // by the `unverifiable` config leaf (DSR-006), default on.
        if (rules.unverifiable) {
          const hit = assessUnverifiable(resolved)
          if (hit) return unverifiableReason(hit.text, command)
        }
      }
      const hit = assessDestructive(base, resolved, rules.destructive)
      if (hit) return destructiveReason(hit.text, command)
      return undefined
    }

    // ---------- global monotonic guard ----------
    ctx.effect(() =>
      ctx.tools.guard((execution) => {
        try {
          if (!execution || typeof execution.name !== 'string' || !execution.arguments)
            return undefined
          const agent = execution.agent
          const cwd =
            agent && agent.session && agent.session.meta ? agent.session.meta.cwd : undefined
          const base = typeof cwd === 'string' && cwd ? cwd : workspaceRoot
          const name = execution.name
          const args = execution.arguments
          let reason
          if (name === 'read' || name === 'write' || name === 'edit' || name === 'read_image') {
            const hit = checkPath(
              base,
              args.file_path,
              name === 'write' || name === 'edit',
              false,
              rules,
            )
            if (hit) reason = PATH_REASON_BY_CATEGORY[hit.category](hit)
          } else if (name === 'grep' || name === 'glob') {
            // grep reads content; glob only enumerates names.
            const hit = checkPath(base, args.path, false, name === 'glob', rules)
            if (hit) reason = PATH_REASON_BY_CATEGORY[hit.category](hit)
          } else if (name === 'pwsh') {
            const command = args.command
            if (typeof command === 'string' && command) {
              const workdir =
                typeof args.workdir === 'string' && args.workdir ? args.workdir : undefined
              reason = checkCommand(workdir ? resolvePath(base, workdir) : base, command)
            }
          }
          if (reason) console.log(`[guardrails] denied ${name}: ${reason.slice(0, 140)}`)
          return reason
        } catch (error) {
          // Fail-open with a loud log: a guard bug must not deadlock the session.
          console.error(
            '[guardrails] internal error (fail-open):',
            error && error.message ? error.message : String(error),
          )
          return undefined
        }
      }),
    )
}
