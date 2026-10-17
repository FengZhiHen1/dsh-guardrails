// host — execution-local analysis, bounded approval, and final monotonic guard.
// Official parser failures refuse dispatch; dynamic semantic unknowns stay explicit.

import z from '@deepseek-ai/schemastery'
import { ASK_TIMEOUT_MAX, evaluateRules } from '../core/rules.js'
import { evaluatePolicy, structuredCommands } from '../core/policy.js'
import { observeTargets } from './targets.js'
import { createShellParsers } from './parsers/index.mjs'
import { requestApproval, DEFAULT_ASK_TIMEOUT_MS } from './approval.js'
import { installRedaction } from './redaction.js'
import { inlineCredentialDecision } from '../core/redaction.js'

/** Live profile settings; zero from legacy configs now selects the bounded default. */
export const Config = z.object({
  sensitiveFiles: z.array(z.string()).default([]).volatile(),
  builtinSensitiveAsk: z.boolean().default(true).volatile(),
  askTimeoutMs: z.number().min(0).max(ASK_TIMEOUT_MAX).default(DEFAULT_ASK_TIMEOUT_MS).volatile(),
})
/** Host plugin identity. */
export const name = 'dsh-guardrails'
/** Required monotonic tool gate. */
export const inject = ['tools']
/** Loader row namespace retained across configuration migration. */
export const SETTINGS_NS = 'guardrails'

function readConfig(config) {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) return config
  return Object.fromEntries(Object.entries(config).map(([key, value]) =>
    [key, value !== null && typeof value === 'object' && typeof value.get === 'function' ? value.get() : value]))
}

function dialectOf(execution) {
  if (execution.name === 'pwsh') return 'powershell'
  if (execution.name === 'bash') return 'bash'
  return undefined
}

const FILE_TOOLS = new Set(['read', 'read_image', 'write', 'edit', 'grep', 'glob', 'delete', 'move'])
function requiresAnalysis(execution) {
  return Boolean(dialectOf(execution)) || FILE_TOOLS.has(execution.name) || execution.name === 'web_fetch'
}

/** Mount the gate; every resource belongs to this plugin fiber.
 * @throws {Error} If the composed configuration is invalid.
 */
export function apply(ctx, config = {}) {
  evaluateRules(readConfig(config))
  const completed = new WeakMap()
  const lifetime = new AbortController()
  const parsers = createShellParsers()
  ctx.effect(() => () => {
    lifetime.abort()
    return parsers.dispose()
  })
  ctx.inject(['settings'], (sctx) => {
    sctx.effect(() => sctx.settings.configure({ auto: false }, ctx.fiber))
  })
  installRedaction(ctx)
  ctx.effect(() => ctx.tools.guard((execution) => {
    if (!requiresAnalysis(execution)) return undefined
    const result = completed.get(execution)
    if (!result) return '[ANALYSIS_MISSING] Guardrails has no completed analysis for this exact execution; dispatch refused.'
    if (lifetime.signal.aborted) return '[ANALYSIS_DISPOSED] Guardrails was unloaded during analysis.'
    if (execution.signal?.aborted) return '[ANALYSIS_CANCELLED] Invocation cancelled.'
    return result.kind === 'allow' ? undefined : result.reason ?? '[APPROVAL_CANCELLED] No one-time authorization.'
  }))
  ctx.effect(() => ctx.on('tools/pre-execute', async (execution, next) => {
    if (!requiresAnalysis(execution)) return next()
    let decision
    let unknown = []
    try {
      const rules = evaluateRules(readConfig(config))
      const signal = AbortSignal.any([lifetime.signal, execution.signal].filter(Boolean))
      const dialect = dialectOf(execution)
      const args = execution.arguments
      let commands
      if (dialect) {
        if (!args || typeof args.command !== 'string') throw new Error('invalid shell input')
        const parsed = await parsers.parse(dialect, args.command, { signal })
        commands = parsed.commands
        unknown = parsed.unknown
      } else if (execution.name === 'web_fetch') {
        commands = typeof args?.url === 'string' ? [{ name: 'Invoke-WebRequest', args: [args.url] }] : []
      } else commands = structuredCommands(execution.name, args)
      const session = execution.agent?.session
      const cwd = args?.workdir ?? ctx.get('sandboxPolicy')?.resolve(session ? { session } : {}).workspaceRoot
        ?? session?.header?.cwd ?? process.cwd()
      const targets = await observeTargets({ commands, cwd, rules, signal })
      unknown = [...unknown, ...(targets.unknown ?? []), ...targets.operations.flatMap(operation => [operation.unknown, operation.scanUnknown].filter(Boolean))]
      decision = evaluatePolicy({ commands, targets })
      const inline = inlineCredentialDecision(commands)
      if (decision.kind !== 'deny' && inline) decision = inline
      if (decision.kind === 'ask') {
        decision = await requestApproval(ctx, execution, decision.reason, rules.askTimeoutMs, lifetime.signal)
      }
      if (signal.aborted) decision = { kind: 'deny', reason: '[ANALYSIS_CANCELLED] Invocation cancelled before dispatch.' }
    } catch {
      // Parser diagnostics may contain script source; report only a safe category.
      decision = { kind: 'deny', reason: '[ANALYSIS_UNAVAILABLE] Official syntax or target analysis failed; invocation refused. Check parser availability and valid syntax.' }
    }
    // Unknown diagnostics belong to this invocation; they never create permission.
    completed.set(execution, { ...decision, unknown })
    if (decision.kind !== 'allow') return decision
    return next()
  }))
}
