// host — DSH adapter entry (Host plane): Config schema, settings page policy,
// base-directory resolution, and the tools/pre-execute `ask` gate.
//
// Boundary: only DSH wiring lives here (schemastery schema, settings.configure,
// pre-execute listener); all judgment logic is in src/core/ (testable under
// bare node). V2 (DSR-015): the listener never denies — it returns
// `{ kind: 'ask' }` on sensitive content reads so DSH's native one-shot
// approval channel decides; every other decision is passed through untouched.
// The listener is fail-open: an internal error logs loud and returns undefined
// (no decision), never breaking the waterfall.
//
// Reference: knowledge v0.2.0-rc.2 `host/07` §1-§3 (settings model unchanged
// from v0.1.7) and `host/09` §2 (PreToolDecision ask / ctx.approval bridge);
// docs/decisions/DSR-015.
//
// Why pre-execute and not ctx.tools.guard: the guard is a monotonic
// post-review refusal with no approval channel — a user-approved ask would
// still die at the guard. `ask` composes with native Auto Review (which
// registers `{ prepend: true }` and re-emits its own ask ahead of us) and
// degrades to a denial when no approval service is composed (fail-closed).

import z from '@deepseek-ai/schemastery'
import { ASK_TIMEOUT_MAX, evaluateRules } from '../core/rules.js'
import { checkSensitiveRead, resolvePath } from '../core/path-check.js'
import { askMessage } from '../core/ask-messages.js'
import { decideFromOutcome } from '../core/ask-decision.js'

/**
 * Render one audit line, bounded. Only the first line of a reason is logged;
 * the full text still reaches the model through the ask reason.
 */
const auditLine = (reason, max = 300) => {
  const line = reason.split('\n', 1)[0].trim()
  return line.length > max ? `${line.slice(0, max)}…` : line
}

// ---------- config schema (official DSH config boundary) ----------
// Every field carries `.volatile()`: that marker is what makes the field (a)
// writable through the settings page and (b) committed into the RUNNING fiber
// without a remount (knowledge `host/07` §2 — a non-volatile path throws
// `Config field "x" is not volatile` on write).
export const Config = z.object({
  // Explicitly marked sensitive files: exact absolute file paths, one per
  // entry. A mark means "reads of this file ask for approval" — it is NOT a
  // pre-approval. No globs, no recursion, no directory inheritance (DSR-015).
  sensitiveFiles: z.array(z.string()).default([]).volatile(),
  // Builtin narrow credential list (SSH key files, registry tokens, hive and
  // dump files — see core/rules.js). Off only to hand the whole category to
  // Auto Review.
  credentialsReadAsk: z.boolean().default(true).volatile(),
  // Plugin-owned upper bound on the approval wait (DSR-016). `0` (default)
  // keeps DSH's native unbounded wait; a positive value aborts this plugin's
  // own ask when nobody answers, which the approval service reports as
  // `cancelled` and we turn into an explicit automatic refusal.
  askTimeoutMs: z.number().min(0).max(ASK_TIMEOUT_MAX).default(0).volatile(),
})

export const name = 'dsh-guardrails'
export const inject = ['tools']

/**
 * Settings namespace this plugin owns. ⚠ semantics (v0.1.7+, unchanged in
 * 0.2.0): a namespace IS the local loader entry id of the plugin row
 * (`host/07` §1). The bundle patch inserts the row as `id: guardrails`, so the
 * browser card must bind THIS value, not the package name. Renaming the row in
 * a profile patch moves the namespace and detaches the card.
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
 * The content-read tools V2 covers, and where their target path lives.
 * `grep` is judged through exact-path equality like the other tools: its
 * `path` only asks when it names the sensitive file itself, so a directory or
 * workspace search never matches a marked FILE path — wide searches stay with
 * Auto Review by construction (DSR-015).
 */
const READ_TOOLS = new Set(['read', 'read_image', 'grep'])

/**
 * Judge one tool execution for a sensitive content read.
 *
 * @returns `{ hit, reason, timeoutMs }` on a hit, `undefined` otherwise. The
 *   decision shape (ask vs. plugin-owned request) belongs to the listener so
 *   this stays a pure judgment; `timeoutMs` is the live `askTimeoutMs` value.
 *   An internal error must not deadlock the tool waterfall: it is logged loud
 *   and swallowed (fail-open listener layer).
 */
function judgeExecution(execution, rawConfig, sandboxPolicy) {
  try {
    if (!execution || typeof execution.name !== 'string' || !execution.arguments) return undefined
    if (!READ_TOOLS.has(execution.name)) return undefined
    const args = execution.arguments
    const raw = args.file_path ?? args.path
    if (typeof raw !== 'string' || raw.length === 0) return undefined
    const rules = evaluateRules(readConfig(rawConfig))
    const session = execution.agent?.session
    const base = sandboxPolicy?.resolve(session ? { session } : {}).workspaceRoot ?? ''
    const hit = checkSensitiveRead(resolvePath(base, raw), rules)
    if (hit === null) return undefined
    return { hit, reason: askMessage(hit, raw, execution.name), timeoutMs: rules.askTimeoutMs }
  } catch (error) {
    // Fail-open with a loud log: a listener bug must not wedge the waterfall.
    console.error(
      '[guardrails] internal error (fail-open):',
      error && error.message ? error.message : String(error),
    )
    return undefined
  }
}

/**
 * Run one plugin-owned approval request with an upper bound on the wait
 * (DSR-016).
 *
 * Why the plugin issues the request itself: a `{ kind: 'ask' }` decision is
 * resolved by `tools/serviceAsk`, which borrows `exec.signal` and waits
 * forever — the approval chain has no timeout at all. Passing our own merged
 * signal is the only seam that both bounds the wait and tells the UI to dismiss
 * its pending prompt (`dsh-client-ui-approval` aborts the presentation on
 * `request.signal`). Policy (`never`) and the answerer waterfall stay inside
 * the service, so neither is bypassed.
 *
 * Failure direction: once a target is judged sensitive, a broken approval path
 * must NOT read it — every error here denies. (The judgment layer above keeps
 * its fail-open behavior for its own bugs.)
 */
async function askWithTimeout(ctx, execution, judged) {
  const toolName = execution.name
  const approval = ctx.get('approval')
  if (approval === undefined) {
    return { kind: 'deny', reason: `tool "${toolName}" requires approval, but no approval channel is available` }
  }
  if (execution.agent === undefined) {
    return { kind: 'deny', reason: `tool "${toolName}" requires approval, but the call has no agent to route it through` }
  }

  const controller = new AbortController()
  const timer = setTimeout(() => {
    controller.abort(new Error(`dsh-guardrails: ask timeout after ${judged.timeoutMs}ms`))
  }, judged.timeoutMs)
  // Keep a caller-side cancel intact: aborting the turn must still end the wait
  // (and must be told apart from our own timeout below).
  const signal = execution.signal === undefined
    ? controller.signal
    : AbortSignal.any([execution.signal, controller.signal])

  let outcome
  try {
    outcome = await approval.request({
      agent: execution.agent,
      toolName,
      callId: execution.callId,
      reason: judged.reason,
      signal,
    })
  } catch (error) {
    console.error(
      '[guardrails] approval request failed (fail-closed):',
      error && error.message ? error.message : String(error),
    )
    return { kind: 'deny', reason: `tool "${toolName}" requires approval, but the approval request failed` }
  } finally {
    clearTimeout(timer)
  }

  const timedOut = controller.signal.aborted
  if (timedOut) {
    // One bounded audit line: the approval pair itself records `cancelled`,
    // which cannot distinguish "timeout" from "user cancelled the turn".
    console.error(`[guardrails] ask timed out after ${judged.timeoutMs}ms: ${toolName}`)
  }
  return decideFromOutcome(outcome, {
    toolName,
    hit: judged.hit,
    timeoutMs: judged.timeoutMs,
    timedOut,
  })
}

/**
 * Plugin entry: declare the configuration page policy and install the
 * pre-execute ask gate. The gate stays active even with no settings service —
 * the source then reads the composition entry exactly as composed.
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
  ctx.effect(() =>
    ctx.on('tools/pre-execute', async (execution, next) => {
      const judged = judgeExecution(execution, config, sandboxPolicy)
      if (judged === undefined) return next()
      // `askTimeoutMs = 0` keeps the native unbounded ask (a plain decision);
      // a positive bound owns the request so it can be aborted.
      if (judged.timeoutMs <= 0) return { kind: 'ask', reason: judged.reason }
      return await askWithTimeout(ctx, execution, judged)
    }),
  )
}
