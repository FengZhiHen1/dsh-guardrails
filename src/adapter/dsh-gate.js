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
import { confirmSummary } from './confirm-text.js'
import { randomUUID } from 'node:crypto'
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
  /**
   * Confirmed-grant records for the post-execute notice, keyed by the same
   * execution object. `completed` cannot hold this because the final guard
   * consumes and removes its entry before dispatch.
   */
  const confirmationRecords = new WeakMap()
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
    policyNever: 'APPROVAL_POLICY_NEVER: The session approval policy is "never" and no interactive answerer accepted this confirmation; the operation was refused without a user decision.',
    delegated: 'APPROVAL_DELEGATED: This operation runs in a delegated subagent session, which cannot ask the user; invocation refused. Re-run it from the parent session.',
  }

  /** Sentinel distinguishing "the wait was cancelled" from a channel result. */
  const CANCELLED = Symbol('guardrails-ask-cancelled')

  /**
   * Effective host approval policy for one invocation, read fail-closed: an
   * unreadable policy counts as `never`, so the gate can never silently grant.
   * Precedence matches the official seam: session override, then config default.
   */
  function readApprovalState(execution) {
    let approval
    try { approval = ctx.get('approval') } catch { approval = undefined }
    let policyName = 'never'
    try {
      const session = execution?.agent?.session
      const override = approval && typeof approval.overrideOf === 'function'
        ? approval.overrideOf(session)
        : undefined
      const configured = approval?.config?.policy
      policyName = (override ?? configured ?? 'ask') === 'never' ? 'never' : 'ask'
    } catch {
      policyName = 'never'
    }
    // A missing seam has no approval channel at all; record it as "never".
    if (!approval) policyName = 'never'
    return { approval, policyName }
  }

  /** Fetch an optional service without letting a provider lookup throw. */
  function optionalService(key) {
    try { return ctx.get(key) } catch { return undefined }
  }

  /** Selected labels for the guardrails question from one answer batch. Only an
   * entry whose id matches exactly counts; anything else is treated as no answer. */
  function selectedLabels(answer, id) {
    const answers = answer?.answers
    if (!Array.isArray(answers)) return []
    const item = answers.find((entry) => entry && entry.id === id)
    const selected = item?.selected
    return Array.isArray(selected) ? selected.filter((label) => typeof label === 'string') : []
  }

  /** Map one question-channel exception onto the closed denial codes. */
  function questionFailureReason(error) {
    const code = error && typeof error === 'object' ? error.code : undefined
    if (code === 'DELEGATED_CALLER') return APPROVAL_DENIALS.delegated
    if (code === 'NO_PROVIDER' || code === 'CALLER_NOT_LIVE') return APPROVAL_DENIALS.policyNever
    if (code === 'ASK_ABORTED') return APPROVAL_DENIALS.cancelled
    return APPROVAL_DENIALS.failed
  }

  /**
   * Shared bounded wait: links `baseSignals`, a self-owned timer and a cancel
   * sentinel; `run(signal)` performs the channel call. The timer wins over a
   * concurrent abort so a budget expiry is reported as a timeout. Channel
   * exceptions are rethrown to the caller, which owns the code mapping.
   */
  async function runBoundedAsk(run, waitMs, baseSignals) {
    const controller = new AbortController()
    const signal = AbortSignal.any([controller.signal, ...baseSignals.filter(Boolean)])
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      controller.abort()
    }, Math.max(1, waitMs))
    let stop
    const cancelled = new Promise((resolve) => {
      stop = () => resolve(CANCELLED)
      if (signal.aborted) stop()
      else signal.addEventListener('abort', stop, { once: true })
    })
    try {
      const result = await Promise.race([run(signal), cancelled])
      if (timedOut) return { granted: false, reason: APPROVAL_DENIALS.timeout }
      if (result === CANCELLED) return { granted: false, reason: APPROVAL_DENIALS.cancelled }
      return result
    } catch (error) {
      if (timedOut) return { granted: false, reason: APPROVAL_DENIALS.timeout }
      throw error
    } finally {
      clearTimeout(timer)
      signal.removeEventListener('abort', stop)
    }
  }

  /** Existing official approval.request path (mapping unchanged). */
  async function askViaApproval(execution, reason, waitMs, baseSignals, approval, confirmInfo) {
    if (typeof approval.request !== 'function' || !execution.agent) {
      return { granted: false, reason: APPROVAL_DENIALS.unavailable }
    }
    // The host card gets the same human single-paragraph copy as the question
    // channel; `reason` stays the audit/model-facing fixed block.
    const displayReason = displayReasonOf(confirmInfo)
    try {
      const result = await runBoundedAsk(async (signal) => {
        const outcome = await approval.request({
          agent: execution.agent,
          toolName: execution.name,
          callId: execution.callId,
          reason,
          ...(displayReason ? { displayReason } : {}),
          signal,
        })
        if (outcome === 'allowed-once') return { granted: true }
        if (outcome === 'rejected') return { granted: false, reason: APPROVAL_DENIALS.rejected }
        if (outcome === 'cancelled') return { granted: false, reason: APPROVAL_DENIALS.cancelled }
        if (outcome === 'unavailable') return { granted: false, reason: APPROVAL_DENIALS.unavailable }
        // Closed word list: an unknown outcome never reads as a grant.
        return { granted: false, reason: APPROVAL_DENIALS.failed }
      }, waitMs, baseSignals)
      return result.granted ? { ...result, channel: 'approval', policy: 'ask' } : result
    } catch {
      return { granted: false, reason: APPROVAL_DENIALS.failed }
    }
  }

  /** Independent interactive question channel: one approval-shaped question. */
  async function askViaQuestions(execution, reason, waitMs, baseSignals, userQuestions, confirmInfo, policyName) {
    const approveLabel = 'Allow once'
    const rejectLabel = 'Reject'
    const id = 'guardrails-confirm'
    const ruleIds = Array.isArray(confirmInfo?.ruleIds) ? confirmInfo.ruleIds : []
    const scopeText = typeof confirmInfo?.scopeText === 'string' ? confirmInfo.scopeText : ''
    const summary = confirmSummary(scopeText, ruleIds)
    try {
      const result = await runBoundedAsk(async (signal) => {
        const answer = await userQuestions.ask({
          questions: [{
            id,
            question: 'Allow this operation once?',
            // Top-level detail is the single-paragraph English fallback for
            // clients that do not read intent.display.
            detail: summary.en,
            options: [{ label: approveLabel }, { label: rejectLabel }],
            intent: {
              kind: 'approval',
              approve: approveLabel,
              reject: rejectLabel,
              display: {
                question: { en: 'Allow this operation once?', zh: '是否允许本次操作？（仅本次）' },
                detail: { en: summary.en, zh: summary.zh },
                approve: { en: approveLabel, zh: '允许一次' },
              },
            },
          }],
          agent: execution.agent,
          signal,
        })
        if (selectedLabels(answer, id).includes(approveLabel)) return { granted: true }
        // Reject, empty or malformed answers are all a real refusal, never a grant.
        return { granted: false, reason: APPROVAL_DENIALS.rejected }
      }, waitMs, baseSignals)
      return result.granted ? { ...result, channel: 'question', policy: policyName } : result
    } catch (error) {
      return { granted: false, reason: questionFailureReason(error) }
    }
  }

  /**
   * One plugin-owned bounded ask (DSR-016): choose the channel, then wait at most
   * `waitMs` with the approval budget, caller signal and lifetime linked. The
   * budget, closed "never grant on unknown" mapping and one-time semantics are
   * identical on both channels.
   */
  async function askOnce(execution, reason, waitMs, baseSignals, policy, confirmInfo) {
    const { approval, policyName } = readApprovalState(execution)
    // The official approval seam owns the decision whenever its policy allows asking.
    if (approval && policyName !== 'never') {
      return askViaApproval(execution, reason, waitMs, baseSignals, approval, confirmInfo)
    }
    // Policy "never" (or a missing approval seam): ask through the independent
    // interactive question channel when enabled; otherwise refuse with the accurate
    // "no answerer accepted" code (never the "user rejected" text).
    const userQuestions = optionalService('userQuestions')
    if (policy?.alwaysAsk === true && userQuestions && typeof userQuestions.ask === 'function' && execution.agent) {
      return askViaQuestions(execution, reason, waitMs, baseSignals, userQuestions, confirmInfo, policyName)
    }
    return { granted: false, reason: APPROVAL_DENIALS.policyNever }
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
    const firstConfirm = { ruleIds: ruleIdsOf(verdict), scopeText: scopeTextOf(verdict, askReason.reason) }
    const budget = askBudget(policy)
    const startedAt = Date.now()
    // Set when a grant is granted; only a final allow turns it into a post-execute
    // confirmation record (a later deny must never leave a stale record behind).
    let confirmedGrant = null
    const finishAllow = () => {
      if (confirmedGrant) confirmationRecords.set(execution, confirmedGrant)
      return { kind: 'allow' }
    }
    const grant = await askOnce(execution, askReason.reason, budget, [lifetime.signal, execution.signal], policy, firstConfirm)
    if (!grant.granted) return { kind: 'deny', decision: renderVerdict({ ...verdict, kind: 'deny', reason: grant.reason }) }
    confirmedGrant = { ruleIds: firstConfirm.ruleIds, scope: firstConfirm.scopeText, channel: grant.channel, policy: grant.policy }
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
      if (revisit.verdict.kind === 'allow') return finishAllow()
      // Still a confirmation: an already-granted identical scope proceeds; a
      // NEW requirement is re-asked strictly inside the remaining total wait,
      // and after that second grant the check runs once more above (round 2).
      if (ruleSignature(previous.verdict) === ruleSignature(revisit.verdict)) {
        return finishAllow()
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
      const reConfirm = { ruleIds: ruleIdsOf(revisit.verdict), scopeText: scopeTextOf(revisit.verdict, reAsk.reason) }
      const reGrant = await askOnce(execution, reAsk.reason, remaining, [lifetime.signal, execution.signal], policy, reConfirm)
      if (!reGrant.granted) return { kind: 'deny', decision: renderVerdict({ ...revisit.verdict, kind: 'deny', reason: reGrant.reason }) }
      confirmedGrant = { ruleIds: reConfirm.ruleIds, scope: reConfirm.scopeText, channel: reGrant.channel, policy: reGrant.policy }
      if (lifetime.signal.aborted || execution.signal?.aborted) return denyCancel()
      previous = revisit
    }
    return finishAllow()
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

  /**
   * Post-execute structured notice: one human confirmation of a guarded call is
   * surfaced to the model as an additional user message. Only an accepted result
   * for an execution that actually carried a recorded confirmation gets the
   * notice; an ordinary allow never does. A read removes the record so the same
   * execution cannot inject the notice twice.
   */
  ctx.effect(() => ctx.on('tools/post-execute', async (execution, result, next) => {
    const downstream = await next()
    const record = confirmationRecords.get(execution)
    if (!record) return downstream
    confirmationRecords.delete(execution)
    // Only a real, accepted dispatch gets the notice: a downstream block or an
    // error result (for example a later policy denial) must not claim "allowed ONCE".
    if (!downstream || downstream.kind !== 'accept' || result?.isError === true) return downstream
    const notice = confirmationNotice(record)
    const contexts = Array.isArray(downstream.additionalContexts) ? downstream.additionalContexts : []
    return { ...downstream, additionalContexts: [notice, ...contexts] }
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

/** Confirmed rule ids of one verdict, primary first, de-duplicated. */
function ruleIdsOf(verdict) {
  const ids = Array.isArray(verdict?.ruleIds) ? verdict.ruleIds.map(String) : []
  if (ids.length === 0 && typeof verdict?.ruleId === 'string' && verdict.ruleId) ids.push(verdict.ruleId)
  return [...new Set(ids)]
}

/** Scope text for the question/notice: prefer an explicit non-empty string scope,
 * falling back to the Scope line of the already-rendered fixed block. */
function scopeTextOf(verdict, renderedReason) {
  const scope = verdict?.scope
  if (typeof scope === 'string' && scope.trim() !== '') return scope
  return scopeTextFromReason(renderedReason)
}

/** The Scope line of an already-rendered fixed block, so the question shows the
 * exact same scope text as the English CONFIRM block (fallback only). */
function scopeTextFromReason(reason) {
  if (typeof reason !== 'string') return ''
  const match = /^Scope:[ \t]*(.*)$/m.exec(reason)
  return match ? match[1].trim() : ''
}

/** Localized `displayReason` for the approval card. Returns undefined (and never
 * throws) when the confirmation info is missing or the summary would be empty,
 * so the caller simply omits the field and the raw `reason` remains authoritative. */
export function displayReasonOf(confirmInfo) {
  if (!confirmInfo || typeof confirmInfo !== 'object') return undefined
  if (!Array.isArray(confirmInfo.ruleIds) || typeof confirmInfo.scopeText !== 'string') return undefined
  try {
    const summary = confirmSummary(confirmInfo.scopeText, confirmInfo.ruleIds)
    if (!summary || typeof summary.en !== 'string' || summary.en === '' ||
      typeof summary.zh !== 'string' || summary.zh === '') return undefined
    return { en: summary.en, zh: summary.zh }
  } catch {
    return undefined
  }
}

/** The structured user message that carries the confirmation notice to the model. */
function confirmationNotice(record) {
  const ruleIds = Array.isArray(record?.ruleIds) ? record.ruleIds : []
  const text = [
    '[Guardrails] Approval granted ONCE for this call.',
    `rule=${ruleIds.join(',')}`,
    `scope=${typeof record?.scope === 'string' ? record.scope : ''}`,
    `channel=${record?.channel ?? 'unknown'}`,
    `policy=${record?.policy ?? 'unknown'}`,
    'reusable=no',
  ].join('\n')
  return {
    id: randomUUID(),
    role: 'user',
    content: [{ type: 'text', text }],
    source: { kind: 'dsh-guardrails', form: 'notice', summary: 'Guardrails confirmation' },
  }
}

/** Bounded, non-throwing message extraction for teardown logging. */
function safeMessage(error) {
  try {
    return error instanceof Error ? error.message : String(error)
  } catch {
    return 'unprintable error'
  }
}
