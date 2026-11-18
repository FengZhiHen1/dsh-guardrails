// dsh-gate — the execution-local guard: async pre-execute analysis pipeline,
// bounded plugin-owned approval, and the final monotonic WeakMap guard.
//
// Wiring contract (official, verified against DSH 0.2.2-rc.2):
//   - `tools/pre-execute` waterfall computes the full evidence chain and decision
//     for one ToolExecution and binds the result to it; `ctx.tools.guard` (sync,
//     monotonic) only consumes the completed result and never runs analysis.
//   - PreToolDecision: allow | deny{reason} | cancel | ask{reason?, displayReason?}.
//     We resolve our own asks plugin-side (DSR-016/023): only an on-time
//     `allowed-once` outcome grants; rejected/cancelled/unavailable/timeout and
//     any unknown outcome deny (closed union, never read unknown as grant).
//   - Analysis signals link the plugin lifetime with the caller's cancellation
//     via AbortSignal.any; approval waits add a self-owned timer controller.
//   - Every context effect registers a disposer (ctx.effect(() => () => teardown))
//     so plugin unload removes hooks, aborts in-flight analysis, and disposes
//     the analyzer exactly once.
//
// Failure stance:
//   - A required execution (command face / structured target / HTTP face)
//     without a completed analysis is a bounded fault at the final guard → deny.
//   - A design skip (everything DSR-022 leaves alone) passes without analysis.
//   - Every gate fault renders one stable, sanitized diagnostic; raw command
//     text and arguments never enter reasons.
//
// Post-approval revisit (需求 R-09): a grant only releases the CURRENT call.
// The wait is unbounded from the target's point of view — command text may read
// script files whose contents change, and a patch manifest's targets sit on a
// filesystem that can change while the user decides. After `allowed-once` the
// gate therefore reruns the FULL pipeline against the live state: fresh
// planning (re-reads any manifest), fresh analysis (re-reads script sources),
// a freshly read live policy (volatile values), fresh evidence, and a fresh
// verdict. Operation/target semantics, evidence versions
// (inventory.fingerprint, else the decision scope), and the decision itself
// must still agree; a deny, a changed scope, or a degraded analysis refuses
// dispatch, and a NEW confirmation is re-asked only within the budget that
// remains of the total configured wait.

import { DEFAULT_ASK_TIMEOUT_MS, ASK_TIMEOUT_MAX } from '../core/rules.js'
import { CHECK_FAILED_RULE } from '../core/decision.js'
import {
  planExecution,
  requiresAnalysis,
  workspaceRootOf,
} from './dsh-input.js'

/**
 * Install the gate on one plugin context.
 *
 * @param {object} ctx - Cordis plugin context (owns `tools`, events, effects).
 * @param {object} deps - injected pipeline members (lead-owned contracts):
 *   - analyzer: object with analyze(unit, {signal}) → analysis and dispose()
 *   - collectEvidence(analysis, {policy, signal, workspaceRoot, fsProvider, isProtectedPath}) → evidence
 *   - decide(evidence, policy) → { kind:'allow'|'confirm'|'deny', ruleId?, ruleIds?, reason?, scope?, gaps? }
 *   - renderDecision(verdict) → string (sanitized fixed-block text)
 *   - readPolicy() → live normalized policy snapshot (synchronous read, no mutation)
 *   - isProtectedPath(path) → boolean
 *   - parsePatch? (patch: string) → operations[] | Promise<operations[]> — official-style
 *     parser injection; awaited, failures degrade to explicit fault analyses
 *   - diagnose? (gaps: array) → string|undefined — sanitized diagnostic renderer for
 *     gap lists; when absent (or empty-handed) the built-in stable text is used
 */
export function installGate(ctx, deps) {
  if (!deps || typeof deps !== 'object') {
    throw new TypeError('guardrails: installGate requires a dependency object')
  }
  for (const key of ['collectEvidence', 'decide', 'renderDecision', 'readPolicy', 'isProtectedPath']) {
    if (typeof deps[key] !== 'function') {
      throw new TypeError(`guardrails: installGate dependency "${key}" must be a function`)
    }
  }
  // The analyzer is an object with two separate members; validate them apart.
  if (!deps.analyzer || typeof deps.analyzer !== 'object' || Array.isArray(deps.analyzer)) {
    throw new TypeError('guardrails: installGate dependency "analyzer" must be an object')
  }
  if (typeof deps.analyzer.analyze !== 'function') {
    throw new TypeError('guardrails: installGate dependency "analyzer.analyze" must be a function')
  }
  if (typeof deps.analyzer.dispose !== 'function') {
    throw new TypeError('guardrails: installGate dependency "analyzer.dispose" must be a function')
  }
  const { analyzer, collectEvidence, decide, renderDecision, readPolicy, isProtectedPath } = deps
  const parsePatch = typeof deps.parsePatch === 'function' ? deps.parsePatch : undefined
  const diagnose = typeof deps.diagnose === 'function' ? deps.diagnose : undefined

  /** Completed decisions for exactly this invocation; the final guard's only source. */
  const completed = new WeakMap()
  const lifetime = new AbortController()
  ctx.effect(() => () => {
    lifetime.abort(new Error('guardrails: plugin unloaded'))
    try {
      analyzer.dispose()
    } catch (error) {
      ctx.logger?.warn?.(`guardrails: analyzer disposal failed: ${safeMessage(error)}`)
    }
  })

  /**
   * Stable fault verdict under the single closed-failure rule id
   * `execution.check-failed` (规则模型 rule catalog): gate faults are never
   * catalog rule ids themselves. The concrete fault code and stage stay in the
   * reason text so the denial remains diagnosable; raw command text and
   * arguments never enter reasons. The optional diagnose member receives the
   * gap list and may refine the reason.
   */
  function fault(code, detail, gaps = [{ code }]) {
    const builtin = `execution.check-failed (stage ${code}): ${detail}`
    let rendered
    try {
      rendered = diagnose?.(Array.isArray(gaps) ? gaps : [{ code }])
    } catch {
      rendered = undefined
    }
    const body = typeof rendered === 'string' && rendered.length > 0 ? rendered : detail
    return {
      kind: 'deny',
      ruleId: CHECK_FAILED_RULE,
      reason: `execution.check-failed (stage ${code}): ${body}`,
    }
  }

  /** Closed-union normalization of an injected verdict. */
  function normalizeVerdict(candidate) {
    if (!candidate || typeof candidate !== 'object') {
      return fault('GUARD_DECISION_INVALID', 'the policy decision was not a verdict object; invocation refused.')
    }
    if (candidate.kind === 'allow') return candidate
    if (candidate.kind === 'confirm') {
      // A confirmation without any scope is unqualified (需求 R-09): refuse rather
      // than ask the user to approve an unlisted range.
      if (candidate.scope === undefined) {
        return fault('GUARD_CONFIRM_UNSCOPED', 'a confirmation arrived without a concrete scope; invocation refused.')
      }
      return candidate
    }
    if (candidate.kind === 'deny') return candidate
    return fault('GUARD_DECISION_INVALID', 'the policy decision used an unknown kind; invocation refused.')
  }

  /** Render one verdict once into sanitized text; failure is a bounded fault. */
  function renderVerdict(verdict) {
    let reason
    try {
      reason = renderDecision(verdict)
    } catch {
      reason = undefined
    }
    if (typeof reason !== 'string' || reason.length === 0) {
      return fault('GUARD_RENDER_FAILED', 'the decision renderer failed; invocation refused.')
    }
    return { ...verdict, reason }
  }

  /** Deterministic key for comparisons; unserializable values compare unequal. */
  function stableKey(value, seen = new WeakSet()) {
    if (value === undefined) return 'undefined'
    if (value === null || typeof value !== 'object') {
      try {
        return JSON.stringify(value) ?? String(value)
      } catch {
        return 'unserializable'
      }
    }
    if (seen.has(value)) return '[circular]'
    seen.add(value)
    try {
      if (Array.isArray(value)) return `[${value.map((entry) => stableKey(entry, seen)).join(',')}]`
      const entries = Object.keys(value).sort()
        .map((key) => `${stableKey(key, seen)}:${stableKey(value[key], seen)}`)
      return `{${entries.join(',')}}`
    } catch {
      return 'unserializable'
    } finally {
      seen.delete(value)
    }
  }

  /**
   * Semantic identity of one analysis: its status plus every operation and
   * target. Two analyses agree when actions, target paths, context (domain and
   * cwd), recursion, preview and condition all match.
   */
  function analysisSemantics(analysis) {
    if (!analysis || typeof analysis !== 'object') return 'missing'
    const operations = Array.isArray(analysis.operations) ? analysis.operations : []
    return stableKey({
      status: analysis.status,
      operations: operations.map((operation) => ({
        action: operation?.action,
        context: operation?.context,
        target: operation?.target,
        recursive: operation?.recursive,
        preview: operation?.preview,
        condition: operation?.condition,
      })),
    })
  }

  /**
   * Comparable scope/target versions. A non-empty inventory fingerprint is the
   * authoritative version on each side; an empty or missing fingerprint never
   * counts as a stable version (no false authorize for protected paths), so
   * the decision scope compares only between two confirmations. A kind change
   * (confirm → allow) with no fingerprint to compare is not a scope change.
   */
  function scopeChanged(beforeVerdict, afterVerdict, beforeEvidence, afterEvidence) {
    const fingerprintBefore = beforeEvidence?.inventory?.fingerprint
    const fingerprintAfter = afterEvidence?.inventory?.fingerprint
    const versionedBefore = typeof fingerprintBefore === 'string' && fingerprintBefore.length > 0
    const versionedAfter = typeof fingerprintAfter === 'string' && fingerprintAfter.length > 0
    if (versionedBefore !== versionedAfter ||
      (versionedBefore && fingerprintBefore !== fingerprintAfter)) return true
    if (beforeVerdict?.kind === 'confirm' && afterVerdict?.kind === 'confirm' &&
      ruleSignature(beforeVerdict) === ruleSignature(afterVerdict)) {
      return stableKey(beforeVerdict.scope) !== stableKey(afterVerdict.scope)
    }
    return false
  }

  function ruleSignature(verdict) {
    const ids = Array.isArray(verdict?.ruleIds) ? [...verdict.ruleIds].map(String).sort() : []
    return `${typeof verdict?.ruleId === 'string' ? verdict.ruleId : ''}|${ids.join(',')}`
  }

  /** Bounded ask budget: finite, capped; legacy 0 selects the bounded default. */
  function askBudget(policy) {
    const value = policy?.askTimeoutMs
    if (Number.isFinite(value) && value > 0) {
      return Math.min(Math.floor(value), ASK_TIMEOUT_MAX)
    }
    return DEFAULT_ASK_TIMEOUT_MS
  }

  /** Stable, sanitized denial texts for the closed approval-outcome union. The
   * outcome code stays in the reason text; it is not a catalog rule id. */
  const APPROVAL_DENIALS = {
    timeout: 'APPROVAL_TIMEOUT: No grant within the configured wait; this is an automatic refusal, not a user rejection. Do not retry with the same parameters; re-issue with a narrower, enumerable scope if the operation is still needed.',
    rejected: 'APPROVAL_REJECTED: The user rejected this invocation. Do not retry with the same parameters.',
    cancelled: 'APPROVAL_CANCELLED: The confirmation was cancelled before a decision; invocation refused.',
    unavailable: 'APPROVAL_UNAVAILABLE: No approval channel or requesting agent is available for this confirmation; invocation refused.',
    failed: 'APPROVAL_FAILED: The approval request could not be recorded; invocation refused.',
    budget: 'APPROVAL_TIMEOUT: The bounded wait budget was already spent on the first confirmation; invocation refused. Re-issue the call to start a new bounded confirmation.',
  }

  /**
   * One plugin-owned bounded ask (DSR-016): waits at most `waitMs`, links the
   * caller signal, the plugin lifetime, and a self-owned timer; maps the
   * official outcome word list one-to-one and treats every non-grant as deny.
   */
  async function askOnce(execution, reason, waitMs, baseSignals) {
    const approval = ctx.get('approval')
    if (!approval || typeof approval.request !== 'function' || !execution.agent) {
      return { granted: false, reason: APPROVAL_DENIALS.unavailable }
    }
    const controller = new AbortController()
    const signal = AbortSignal.any([controller.signal, ...baseSignals.filter(Boolean)])
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      controller.abort()
    }, Math.max(1, waitMs))
    let stop
    const cancelled = new Promise((resolve) => {
      stop = () => resolve('cancelled')
      if (signal.aborted) stop()
      else signal.addEventListener('abort', stop, { once: true })
    })
    try {
      const outcome = await Promise.race([
        approval.request({
          agent: execution.agent,
          toolName: execution.name,
          callId: execution.callId,
          reason,
          signal,
        }),
        cancelled,
      ])
      if (timedOut) return { granted: false, reason: APPROVAL_DENIALS.timeout }
      if (outcome === 'allowed-once') return { granted: true }
      if (outcome === 'rejected') return { granted: false, reason: APPROVAL_DENIALS.rejected }
      if (outcome === 'cancelled') return { granted: false, reason: APPROVAL_DENIALS.cancelled }
      if (outcome === 'unavailable') return { granted: false, reason: APPROVAL_DENIALS.unavailable }
      // Closed word list: an unknown outcome never reads as a grant.
      return { granted: false, reason: APPROVAL_DENIALS.failed }
    } catch {
      return { granted: false, reason: APPROVAL_DENIALS.failed }
    } finally {
      clearTimeout(timer)
      signal.removeEventListener('abort', stop)
    }
  }

  /**
   * The evidence member receives the actual mounted FsProvider (ctx.get('fs'))
   * and calls its official methods directly: resolve(raw, { cwd, signal }),
   * stat(target, signal), displayPath/targetKey. The gate passes it through
   * unchanged; no wrapper sits between the evidence member and the provider.
   */

  /** Surface gap diagnostics of partial/fault analyses through the lead decoder. */
  function noteAnalysisGaps(analysis) {
    if (!analysis || typeof analysis !== 'object') return
    if (analysis.status !== 'partial' && analysis.status !== 'fault') return
    if (!diagnose) return
    try {
      const text = diagnose(Array.isArray(analysis.gaps) ? analysis.gaps : [])
      if (typeof text === 'string' && text.length > 0) {
        ctx.logger?.warn?.(`guardrails: ${text}`)
      }
    } catch {
      // Diagnostics never influence the verdict's direction.
    }
  }

  /** Run one analysis stage for a plan against one signal and policy. */
  async function analyzePlan(execution, plan, { signal, policy }) {
    const analysis = plan.kind === 'command'
      ? await analyzer.analyze(plan.unit, { signal })
      : plan.analysis
    noteAnalysisGaps(analysis)
    const evidence = await collectEvidence(analysis, {
      policy,
      signal,
      workspaceRoot: workspaceRootOf(ctx, execution),
      fsProvider: ctx.get('fs'),
      isProtectedPath,
    })
    return { analysis, evidence }
  }

  /**
   * Run one full pipeline for a required execution: analyze → evidence →
   * decide, then the bounded approval and the mandatory full revisit. Never
   * throws; returns { kind:'allow' } or { kind:'deny', decision }.
   */
  async function analyzeRequired(execution, firstPlan) {
    const policy = readPolicy()
    const signal = AbortSignal.any([lifetime.signal, execution.signal].filter(Boolean))
    let first
    try {
      first = await analyzePlan(execution, firstPlan, { signal, policy })
    } catch {
      return { kind: 'deny', decision: fault('ANALYSIS_UNAVAILABLE', 'official syntax or target analysis failed; invocation refused. Check parser availability and valid syntax.') }
    }
    const verdict = normalizeVerdict(decide(first.evidence, policy))
    if (verdict.kind === 'deny') return { kind: 'deny', decision: renderVerdict(verdict) }
    if (verdict.kind === 'allow') return { kind: 'allow' }

    // Confirmation: plugin-owned bounded ask, then the mandatory full revisit.
    const askReason = renderVerdict(verdict)
    if (askReason.kind === 'deny') return { kind: 'deny', decision: askReason }
    const budget = askBudget(policy)
    const startedAt = Date.now()
    const grant = await askOnce(execution, askReason.reason, budget, [lifetime.signal, execution.signal])
    if (!grant.granted) return { kind: 'deny', decision: renderVerdict({ ...verdict, kind: 'deny', reason: grant.reason }) }
    if (signal.aborted || lifetime.signal.aborted) {
      return { kind: 'deny', decision: fault('ANALYSIS_CANCELLED', 'invocation cancelled before dispatch.') }
    }

    // Post-approval full revisit: fresh planning (re-reads manifests), fresh
    // analysis (re-reads script sources the command may consume), a freshly
    // read live policy, fresh evidence, fresh verdict. Every stage failure is
    // a bounded refusal, never a silent continuation.
    async function revisitOnce() {
      const revisitPolicy = readPolicy()
      const revisitSignal = AbortSignal.any([lifetime.signal, execution.signal].filter(Boolean))
      if (revisitSignal.aborted) {
        return { aborted: true }
      }
      const revisitPlan = await planExecution(ctx, execution, { parsePatch })
      if (revisitPlan.kind === 'skip') return { changed: true }
      if (revisitPlan.kind === 'fault') return { faulted: true }
      const stage = await analyzePlan(execution, revisitPlan, { signal: revisitSignal, policy: revisitPolicy })
      return { ...stage, verdict: normalizeVerdict(decide(stage.evidence, revisitPolicy)) }
    }

    function denyCancel() {
      return { kind: 'deny', decision: fault('ANALYSIS_CANCELLED', 'invocation cancelled before dispatch.') }
    }
    function denyScopeChanged() {
      return { kind: 'deny', decision: fault('GUARD_SCOPE_CHANGED', 'the confirmed scope, analyzed operations, or target set changed between approval and dispatch (script contents or manifest may have changed); invocation refused. Re-issue a fresh invocation with the current, verified scope.') }
    }

    let previous = { analysis: first.analysis, evidence: first.evidence, verdict }
    for (let round = 1; round <= 2; round += 1) {
      let revisit
      try {
        revisit = await revisitOnce()
      } catch {
        return { kind: 'deny', decision: fault('GUARD_RECHECK_FAILED', 'the post-approval re-check failed; invocation refused.') }
      }
      if (revisit.aborted) return denyCancel()
      if (revisit.changed) return denyScopeChanged()
      if (revisit.faulted) {
        return { kind: 'deny', decision: fault('GUARD_RECHECK_FAILED', 'the re-check could not plan the invocation anymore; invocation refused.') }
      }
      if (revisit.verdict.kind === 'deny') return { kind: 'deny', decision: renderVerdict(revisit.verdict) }
      if (analysisSemantics(previous.analysis) !== analysisSemantics(revisit.analysis)) return denyScopeChanged()
      if (scopeChanged(previous.verdict, revisit.verdict, previous.evidence, revisit.evidence)) return denyScopeChanged()
      if (revisit.verdict.kind === 'allow') return { kind: 'allow' }
      // Still a confirmation: an already-granted identical scope proceeds; a
      // NEW requirement is re-asked strictly inside the remaining total wait,
      // and after that second grant the check runs once more above (round 2).
      if (ruleSignature(previous.verdict) === ruleSignature(revisit.verdict)) {
        return { kind: 'allow' }
      }
      if (round === 2) {
        return { kind: 'deny', decision: fault('GUARD_REAPPROVAL_UNRESOLVED', 'a further changed confirmation appeared after the bounded re-approval; invocation refused. Re-issue a fresh invocation to confirm the current scope.') }
      }
      const remaining = budget - (Date.now() - startedAt)
      if (remaining <= 0) {
        return { kind: 'deny', decision: renderVerdict({ ...revisit.verdict, kind: 'deny', reason: APPROVAL_DENIALS.budget }) }
      }
      const reAsk = renderVerdict(revisit.verdict)
      if (reAsk.kind === 'deny') return { kind: 'deny', decision: reAsk }
      const reGrant = await askOnce(execution, reAsk.reason, remaining, [lifetime.signal, execution.signal])
      if (!reGrant.granted) return { kind: 'deny', decision: renderVerdict({ ...revisit.verdict, kind: 'deny', reason: reGrant.reason }) }
      if (lifetime.signal.aborted || execution.signal?.aborted) return denyCancel()
      previous = revisit
    }
    return { kind: 'allow' }
  }

  ctx.effect(() => ctx.on('tools/pre-execute', async (execution, next) => {
    let required
    try {
      required = requiresAnalysis(ctx, execution)
    } catch {
      required = true
    }
    if (!required) return next()
    let decision
    try {
      const plan = await planExecution(ctx, execution, { parsePatch })
      decision = plan.kind === 'skip'
        ? { kind: 'allow' }
        : plan.kind === 'fault'
          ? { kind: 'deny', decision: fault(plan.code, plainFaultDetail(plan.code, plan.reason)) }
          : await analyzeRequired(execution, plan)
    } catch {
      // Parser/evidence diagnostics may embed source text; report only the category.
      decision = { kind: 'deny', decision: fault('ANALYSIS_UNAVAILABLE', 'official syntax or target analysis failed; invocation refused. Check parser availability and valid syntax.') }
    }
    if (decision.kind !== 'allow') {
      const denial = decision.decision ?? fault('ANALYSIS_UNAVAILABLE', 'analysis failed; invocation refused.')
      completed.set(execution, { kind: 'deny', reason: denial.reason })
      return { kind: 'deny', reason: denial.reason }
    }
    if (lifetime.signal.aborted) {
      const denial = fault('ANALYSIS_DISPOSED', 'guardrails was unloaded during analysis.')
      completed.set(execution, { kind: 'deny', reason: denial.reason })
      return { kind: 'deny', reason: denial.reason }
    }
    if (execution.signal?.aborted) {
      const denial = fault('ANALYSIS_CANCELLED', 'invocation cancelled before dispatch.')
      completed.set(execution, { kind: 'deny', reason: denial.reason })
      return { kind: 'deny', reason: denial.reason }
    }
    completed.set(execution, { kind: 'allow' })
    return next()
  }))

  ctx.effect(() => ctx.tools.guard((execution) => {
    let required
    try {
      required = requiresAnalysis(ctx, execution)
    } catch {
      return { reason: fault('ANALYSIS_UNAVAILABLE', 'front-door classification failed at the final guard; invocation refused.').reason }
    }
    // Design skips carry no analyzed capability and pass untouched; a required
    // execution without a completed analysis is a bounded fault (an early skip
    // of a required analysis can never grant dispatch).
    if (!required) return undefined
    if (lifetime.signal.aborted) {
      return { reason: fault('ANALYSIS_DISPOSED', 'guardrails was unloaded during analysis.').reason }
    }
    if (execution.signal?.aborted) {
      return { reason: fault('ANALYSIS_CANCELLED', 'invocation cancelled.').reason }
    }
    // A completed decision is consumed exactly once: reading removes the
    // entry, so the same execution can never reuse an earlier verdict on a
    // second dispatch attempt (a second attempt hits the bounded fault below).
    const result = completed.get(execution)
    completed.delete(execution)
    if (!result) {
      return { reason: fault('ANALYSIS_MISSING', 'guardrails has no completed analysis for this exact invocation; dispatch refused.').reason }
    }
    if (result.kind === 'allow') return undefined
    return { reason: result.reason ?? fault('APPROVAL_CANCELLED', 'no one-time authorization.').reason }
  }))

  return { completed, lifetime }
}

/** Strip a synthesized fault's code prefix so the stable text stays single-sourced. */
function plainFaultDetail(code, reason) {
  const prefix = `${code}: `
  return typeof reason === 'string' && reason.startsWith(prefix) ? reason.slice(prefix.length) : reason
}

/** Bounded, non-throwing message extraction for teardown logging. */
function safeMessage(error) {
  try {
    return error instanceof Error ? error.message : String(error)
  } catch {
    return 'unprintable error'
  }
}
