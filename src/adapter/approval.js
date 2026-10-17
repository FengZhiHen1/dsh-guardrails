// approval — bounded, execution-local approval requests.
// Only an on-time allowed-once outcome grants this invocation.

import { DEFAULT_ASK_TIMEOUT_MS } from '../core/rules.js'

/** Share the configuration boundary's finite default. */
export { DEFAULT_ASK_TIMEOUT_MS }

/** Request one grant and stop waiting on timeout, caller cancel, or unload. */
export async function requestApproval(ctx, execution, reason, timeoutMs, lifetime) {
  const approval = ctx.get('approval')
  if (!approval || !execution.agent) {
    return { kind: 'deny', reason: '[APPROVAL_UNAVAILABLE] No approval channel or requesting agent.' }
  }
  const controller = new AbortController()
  const signals = [controller.signal, lifetime, execution.signal].filter(Boolean)
  const signal = AbortSignal.any(signals)
  const bound = timeoutMs > 0 ? timeoutMs : DEFAULT_ASK_TIMEOUT_MS
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, bound)
  let stop
  const cancelled = new Promise((resolve) => {
    stop = () => resolve('cancelled')
    if (signal.aborted) stop()
    else signal.addEventListener('abort', stop, { once: true })
  })
  try {
    if (signal.aborted) return { kind: 'cancel' }
    const outcome = await Promise.race([
      approval.request({ agent: execution.agent, toolName: execution.name,
        callId: execution.callId, reason, signal }),
      cancelled,
    ])
    if (timedOut) return { kind: 'deny', reason: `[APPROVAL_TIMEOUT] No grant within ${bound}ms; invocation refused.` }
    if (signal.aborted) return { kind: 'cancel' }
    if (outcome === 'allowed-once') return { kind: 'allow' }
    return { kind: 'deny', reason: `[APPROVAL_${String(outcome).toUpperCase()}] This invocation has no one-time grant.` }
  } catch {
    return { kind: 'deny', reason: '[APPROVAL_FAILED] Approval could not be recorded; invocation refused.' }
  } finally {
    clearTimeout(timer)
    signal.removeEventListener('abort', stop)
  }
}
