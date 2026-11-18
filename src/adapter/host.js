import z from '@deepseek-ai/schemastery'
import { parsePatch } from '@deepseek-ai/dsh-fs-patch'
import { decide, isProtectedPath, normalizePolicy, renderDecision } from '../core/decision.js'
import { createExecutionAnalyzer } from './analysis/index.js'
import { installGate } from './dsh-gate.js'
import { collectEvidence } from './evidence/index.js'
import { installRedaction } from './redaction.js'

export const name = 'dsh-guardrails'
export const inject = ['tools']
export const SETTINGS_NS = 'guardrails'

// Keep volatile fields at fixed object paths. Loose validation uses the protective
// default for malformed fields before the per-call policy validates the snapshot.
export const Config = z.object({
  sensitiveFiles: z.array(z.string()).default([]).loose().volatile(),
  builtinSensitiveAsk: z.boolean().default(true).loose().volatile(),
  askTimeoutMs: z.natural().max(3_600_000).default(120_000).loose().volatile(),
  rules: z.dict(z.object({ enabled: z.boolean(), allowlist: z.array(z.string()) })).default({}).loose().volatile(),
  tightenOnly: z.const(true).default(true).loose().volatile(),
}).default({}).loose()

function snapshotConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) return config
  return Object.fromEntries(Object.entries(config).map(([key, value]) => [key,
    value && typeof value.get === 'function' ? value.get() : value]))
}

export function apply(ctx, config = {}) {
  const logger = ctx.logger?.('guardrails')
  const analyzer = createExecutionAnalyzer()
  installGate(ctx, {
    analyzer,
    collectEvidence,
    decide,
    isProtectedPath,
    parsePatch,
    renderDecision,
    readPolicy() {
      const policy = snapshotConfig(config)
      // An invocation grant comes from ApprovalService. Reading one from a persistent
      // profile on every call would make that grant reusable.
      if (policy && typeof policy === 'object') delete policy.allowOnce
      return normalizePolicy(policy)
    },
    diagnose(gaps) {
      // Logs identify the missing capability without repeating submitted source or paths.
      const kinds = [...new Set(gaps.map((gap) => gap.kind ?? gap.code).filter(Boolean))]
      if (kinds.length) logger?.debug('Execution analysis coverage: %s', kinds.join(', '))
    },
  })
  installRedaction(ctx)
  ctx.inject(['settings'], (settingsCtx) => {
    settingsCtx.effect(() => settingsCtx.settings.configure({ auto: false }, ctx.fiber))
  })
}
