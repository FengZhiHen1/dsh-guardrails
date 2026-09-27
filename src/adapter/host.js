// host — DSH adapter entry (Host plane): Config schema, settings page policy,
// base-directory resolution, and the tools.guard hook.
//
// Boundary: only DSH wiring lives here (schemastery schema, settings.configure,
// sandboxPolicy, tools.guard); all judgment logic is in src/core/ (testable
// under bare node). The guard is a hard block with no runtime approval
// channel; the decision layer is fail-closed, the hook layer is fail-open.
// Reference: docs/decisions/DSR-006/DSR-007; README「已知限制与边界」.
//
// v0.1.7 settings model (knowledge `host/07` §1-§3): the configuration truth is
// this entry's Cordis Config. `settings.yaml`, the settings-file provider and
// `settings.installSection` no longer exist — a field is editable only when its
// schema node is `.volatile()`, the settings service merely enumerates and
// generates forms, and a profile-patch edit commits into the live Config. The
// guard therefore reads the volatile refs AT OPERATION TIME instead of caching
// a snapshot pushed by a settings callback: no remount, no onChange wiring.

import z from '@deepseek-ai/schemastery'
import { CATEGORY_LEAF_KEYS, evaluateRules } from '../core/rules.js'
import { checkPath, resolvePath } from '../core/path-check.js'
import { checkCommand } from '../core/check-command.js'
import { PATH_REASON_BY_CATEGORY } from '../core/deny-messages.js'

// ---------- config schema (official DSH config boundary) ----------
// Every cordis config entry may carry a `config` block; the plugin declares a
// Schemastery schema that the loader validates BEFORE apply and fills in with
// defaults: `apply` always receives a complete validated config, and a wrong
// config fails the mount with the loader's actionable ValidationError (fiber
// FAILED) — no hand-rolled silent degradation. Category keys accept a boolean
// (whole category on/off, v1-compatible) or an object of op-level leaves;
// `evaluateRules` then normalizes to leaves.
//
// Every field carries `.volatile()`: that marker is what makes the field (a)
// writable through the settings page and (b) committed into the RUNNING fiber
// without a remount (knowledge `host/07` §2 — a non-volatile path throws
// `Config field "x" is not volatile` on write and never reaches a settings
// page). The settings service's `volatileForm()` walk keeps only volatile
// subtrees, so a field without the marker silently disappears from the page.
const leafObject = (keys) =>
  z.object(Object.fromEntries(keys.map((key) => [key, z.boolean().default(true)])))
const categorySchema = (keys) =>
  z.union([z.boolean(), leafObject(keys)]).default(true).volatile()

export const Config = z.object({
  env: categorySchema(CATEGORY_LEAF_KEYS.env),
  git: categorySchema(CATEGORY_LEAF_KEYS.git),
  credentials: categorySchema(CATEGORY_LEAF_KEYS.credentials),
  system: categorySchema(CATEGORY_LEAF_KEYS.system),
  destructive: categorySchema(CATEGORY_LEAF_KEYS.destructive),
  unverifiable: z.boolean().default(true).volatile(),
})

export const name = 'dsh-guardrails'
export const inject = ['tools']

/**
 * Settings namespace this plugin owns. ⚠ v0.1.7 semantics: a namespace IS the
 * local loader entry id of the plugin row (`host/07` §1 — the old
 * `NAMESPACE_PATTERN` and the plugin-chosen kebab-case name are gone). The
 * bundle patch inserts the row as `id: guardrails`, so the browser card must
 * bind THIS value, not the package name `dsh-guardrails`. Renaming the row in a
 * profile patch moves the namespace and detaches the card.
 */
export const SETTINGS_NS = 'guardrails'

/** Whether a value is a cordis volatile config reference (duck-typed: the
 * `Volatile<T>` protocol is `Symbol.for`-based, so no import is needed and a
 * plain value from a test or a hand-written row stays valid). */
const isVolatileRef = (value) =>
  typeof value === 'object' && value !== null && typeof value.get === 'function'

/**
 * Read the entry's current configuration as plain data.
 *
 * The loader commits a volatile edit by replacing the reference's snapshot, so
 * `ref.get()` always answers with the live value; a non-object config is handed
 * through untouched so `evaluateRules` can report its own actionable error
 * instead of a property-access TypeError.
 */
function readConfig(config) {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) return config
  return Object.fromEntries(
    Object.entries(config).map(([key, value]) => [key, isVolatileRef(value) ? value.get() : value]),
  )
}

/**
 * Judge one tool execution against the guard rules.
 * The base directory comes from `sandboxPolicy.resolve({ session })` — the
 * same identity the official tool chain enforces against (DSR-007); without
 * the sandbox-policy service the base is `''` (defensive degradation: only
 * absolute-prefix rules can still match).
 *
 * @returns the deny reason (a string is a monotonic refusal), or `undefined`.
 *   A guard bug must not deadlock the session: internal errors are logged
 *   loud and the call is allowed (fail-open hook layer).
 */
function judgeExecution(execution, rawConfig, sandboxPolicy) {
  try {
    if (!execution || typeof execution.name !== 'string' || !execution.arguments) {
      return undefined
    }
    // Live read: a settings-page edit lands in the volatile refs, so the next
    // judgment already sees it — no rebuild hook, no stale snapshot window.
    const rules = evaluateRules(readConfig(rawConfig))
    const session = execution.agent?.session
    const base = sandboxPolicy?.resolve(session ? { session } : {}).workspaceRoot ?? ''
    const toolName = execution.name
    const args = execution.arguments
    let reason
    if (toolName === 'read' || toolName === 'write' || toolName === 'edit' || toolName === 'read_image') {
      const hit = checkPath(
        base,
        args.file_path,
        toolName === 'write' || toolName === 'edit',
        false,
        rules,
      )
      if (hit) reason = PATH_REASON_BY_CATEGORY[hit.category](hit)
    } else if (toolName === 'grep' || toolName === 'glob') {
      // grep reads content; glob only enumerates names.
      const hit = checkPath(base, args.path, false, toolName === 'glob', rules)
      if (hit) reason = PATH_REASON_BY_CATEGORY[hit.category](hit)
    } else if (toolName === 'pwsh') {
      const command = args.command
      if (typeof command === 'string' && command) {
        const workdir =
          typeof args.workdir === 'string' && args.workdir ? args.workdir : undefined
        reason = checkCommand(workdir ? resolvePath(base, workdir) : base, command, rules)
      }
    }
    if (reason) console.log(`[guardrails] denied ${toolName}: ${reason.slice(0, 140)}`)
    return reason
  } catch (error) {
    // Fail-open with a loud log: a guard bug must not deadlock the session.
    console.error(
      '[guardrails] internal error (fail-open):',
      error && error.message ? error.message : String(error),
    )
    return undefined
  }
}

/**
 * Plugin entry: declare the configuration page policy and install the global
 * monotonic guard. The guard stays active even with no settings service — the
 * source then reads the composition entry exactly as composed.
 */
export function apply(ctx, config = {}) {
  // Mount-time validation. The loader already validated the row's config, but
  // this keeps an invalid hand-written or test config failing LOUDLY at mount
  // (fiber FAILED) rather than degrading at the first tool call.
  evaluateRules(readConfig(config))

  // Self-drawn page: the browser half renders this entry's form, so the
  // schema-generated page is switched off to avoid a second, duplicate page
  // once a client auto-generates from `autoGenerate` (knowledge `host/07` §3).
  ctx.inject(['settings'], (sctx) => {
    sctx.effect(() => sctx.settings.configure({ auto: false }, ctx.fiber))
  })

  const sandboxPolicy = ctx.get('sandboxPolicy')
  ctx.effect(() => ctx.tools.guard((execution) => judgeExecution(execution, config, sandboxPolicy)))
}
