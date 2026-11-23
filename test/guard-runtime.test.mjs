// Real ToolRuntime and ApprovalService integration with synthetic session storage.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { realpathSync } from 'node:fs'
import { resolve, extname } from 'node:path'
import { pathToFileURL } from 'node:url'
import { apply } from '../src/adapter/host.js'
import { installGate } from '../src/adapter/dsh-gate.js'
import { normalizePolicy, renderDecision } from '../src/core/decision.js'

const anchor = process.env.DSH_RUNTIME_PATH
const resolver = anchor ? createRequire(realpathSync(extname(anchor) ? resolve(anchor) : resolve(anchor, 'package.json'))) : createRequire(import.meta.url)
let runtime
try {
  const load = async name => import(pathToFileURL(resolver.resolve(name)).href)
  const [cordis, tools, prompt, approval, native, session, projections] = await Promise.all(['@deepseek-ai/cordis', '@deepseek-ai/dsh-tools', '@deepseek-ai/dsh-system-prompt', '@deepseek-ai/dsh-user-approval', '@deepseek-ai/dsh-tool-executor-native', '@deepseek-ai/dsh-session', '@deepseek-ai/dsh-session-projection'].map(load))
  runtime = { cordis, tools, prompt, approval, native, session, projections }
} catch (error) { if (anchor || error.code !== 'MODULE_NOT_FOUND') throw error }

async function setup(t, policy = 'never') {
  const ctx = new runtime.cordis.Context()
  t.after(() => ctx.fiber.dispose())
  await ctx.plugin(runtime.prompt.default)
  await ctx.plugin(runtime.tools.default)
  // 0.2.2 executes through a mounted executor (not a tools-service `mode`).
  await ctx.plugin(runtime.native)
  // 0.2.2 ApprovalService injects `sessionProjections` for its durable audit projection.
  await ctx.plugin(runtime.projections.default)
  await ctx.plugin(runtime.approval.default, { policy })
  return ctx
}

const call = (ctx, name, id, args, signal) => ctx.tools.execute({
  signal,
  calls: [{ type: 'tool-call', id, name, arguments: JSON.stringify(args) }],
})

/** Real session with one open turn, for the never-policy audit assertion. */
function realSession(id) {
  const session = runtime.session.Session.create(id)
  session.append('turn/start', { turn: 1 })
  return session
}

test('real ToolRuntime final guard rejects short-circuited pre-analysis', { skip: !runtime && 'Set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t)
  await ctx.plugin({ name: 'guardrails-test-mount', inject: ['tools'], apply })
  let calls = 0
  ctx.tools.register({ name: 'pwsh', description: 'Synthetic parser fixture.', parameters: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    execute: async () => { calls++; return 'safe' } })
  const signal = new AbortController().signal
  const accepted = (await call(ctx, 'pwsh', 'allowed', { command: "Write-Output 'safe'" }, signal)).results[0].result
  assert.equal(accepted.isError, false)
  assert.equal(calls, 1)
  const dispose = ctx.on('tools/pre-execute', async () => ({ kind: 'allow' }), { prepend: true })
  const denied = (await call(ctx, 'pwsh', 'short-circuit', { command: "Write-Output 'safe'" }, signal)).results[0].result
  assert.equal(denied.isError, true)
  // The final-guard fault uses the stable closed-failure rule id; the concrete
  // stage code stays in the reason for diagnosability.
  assert.match(denied.error.message, /execution\.check-failed/)
  assert.match(denied.error.message, /ANALYSIS_MISSING/)
  assert.equal(calls, 1)
  dispose()
})

test('never policy without a question provider says UNAVAILABLE and writes no approval audit', { skip: !runtime && 'Set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t, 'never')
  await ctx.plugin({
    name: 'guardrails-never-audit-mount',
    inject: ['tools'],
    apply(inner) {
      installGate(inner, {
        analyzer: { async analyze() { return { status: 'complete', operations: [] } }, dispose() {} },
        collectEvidence: (analysis) => ({ analysis, inventory: { fingerprint: 'cov-1' } }),
        decide: () => ({ kind: 'confirm', ruleId: 'data.delete.bulk', scope: { entries: ['./x'] } }),
        renderDecision,
        readPolicy: () => normalizePolicy({ askTimeoutMs: 500 }),
        isProtectedPath: () => false,
      })
    },
  })
  ctx.tools.register({
    name: 'bash',
    description: 'Synthetic never-audit fixture.',
    parameters: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    execute: async () => 'noop',
  })
  const session = realSession('guardrails-never-audit')
  const response = await ctx.tools.execute({
    signal: new AbortController().signal,
    agent: { session, ctx },
    calls: [{ type: 'tool-call', id: 'never-1', name: 'bash', arguments: JSON.stringify({ command: 'rm -rf ./x' }) }],
  })
  const result = response.results[0].result
  assert.equal(result.isError, true)
  assert.match(result.error.message, /APPROVAL_UNAVAILABLE: No confirmation UI is available/)
  const types = session.snapshotEvents().map(event => event.type)
  assert.ok(!types.includes('approval/asked'), 'the never policy bypasses the approval seam (no ask)')
  assert.ok(!types.includes('approval/decided'), 'the never policy bypasses the approval seam (no decision)')
})
