// host — DSH adapter entry (Host plane): Config schema, settings wiring,
// base-directory resolution, and the tools.guard hook.
//
// Boundary: only DSH wiring lives here (schemastery schema, installSection,
// sandboxPolicy, tools.guard); all judgment logic is in src/core/ (testable
// under bare node). The guard is a hard block with no runtime approval
// channel; the decision layer is fail-closed, the hook layer is fail-open.
// Reference: docs/decisions/DSR-006/DSR-007; README「已知限制与边界」.

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
 * by the same value, and the "插件配置" tab pairs the two.
 */
export const SETTINGS_NS = 'dsh-guardrails'

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
function judgeExecution(execution, rules, sandboxPolicy) {
  try {
    if (!execution || typeof execution.name !== 'string' || !execution.arguments) {
      return undefined
    }
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
 * Plugin entry: register the settings section (composition entry as the base
 * layer, live rebuild on commit, fallback to the entry when the provider
 * detaches — the official `installSection` semantics) and install the global
 * monotonic guard. The guard stays active even with no settings service:
 * the source then reads the composition entry exactly as composed.
 */
export function apply(ctx, config = {}) {
  const entryRules = evaluateRules(config)
  let source = () => entryRules
  let rules = source()
  const rebuild = () => {
    rules = evaluateRules(source())
  }
  ctx.inject(['settings'], (sctx) => {
    sctx.settings.installSection(ctx, SETTINGS_NS, Config, config, {
      setSource: (current) => {
        source = current
      },
      onChange: rebuild,
    })
  })

  const sandboxPolicy = ctx.get('sandboxPolicy')
  ctx.effect(() => ctx.tools.guard((execution) => judgeExecution(execution, rules, sandboxPolicy)))
}
