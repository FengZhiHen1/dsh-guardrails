// ask-decision — map one native approval outcome onto a pre-execute decision.
//
// Boundary: pure data mapping, no imports beyond the message templates in
// ./ask-messages.js (no DSH, no cordis, no fs). Host wiring lives in
// src/adapter/host.js; the outcome vocabulary is owned by
// @deepseek-ai/dsh-user-approval (`allowed-once` / `rejected` / `cancelled` /
// `unavailable`) and is CLOSED — an unknown value must never be read as a grant.
//
// Reference: docs/decisions/DSR-015 (ask semantics), DSR-016 (plugin-owned
// ask timeout).

import { timeoutMessage } from './ask-messages.js'

/**
 * The only grant the approval service issues.
 */
export const GRANT = 'allowed-once'

/**
 * Translate an approval outcome into a `PreToolDecision`.
 *
 * @param outcome - closed approval outcome (unknown values fail closed).
 * @param detail - `{ toolName, hit, timeoutMs, timedOut }`; `timedOut` is true
 *   only when the plugin's own timer aborted the request, which the approval
 *   service reports as `cancelled` exactly like a caller-side cancel.
 * @returns `{ kind: 'allow' }` for a grant, `{ kind: 'cancel' }` for a
 *   caller-side cancellation (native "aborted before dispatch"), and
 *   `{ kind: 'deny', reason }` for everything else.
 */
export function decideFromOutcome(outcome, { toolName, hit, timeoutMs = 0, timedOut = false }) {
  if (outcome === GRANT) return { kind: 'allow' }
  switch (outcome) {
    case 'rejected':
      return { kind: 'deny', reason: `the user rejected tool "${toolName}"` }
    case 'cancelled':
      // A plugin-owned timeout also surfaces as `cancelled`; report it as the
      // automatic refusal it is, and let a genuine caller cancel keep the
      // native "aborted" shape.
      return timedOut
        ? { kind: 'deny', reason: timeoutMessage(toolName, timeoutMs, hit) }
        : { kind: 'cancel' }
    case 'unavailable':
      return {
        kind: 'deny',
        reason: `tool "${toolName}" requires approval, but no approval channel is available`,
      }
    default:
      // Fail closed: a value outside the closed vocabulary is not a grant.
      return {
        kind: 'deny',
        reason: `tool "${toolName}" requires approval, but the approval outcome was unrecognized (${String(outcome)})`,
      }
  }
}
