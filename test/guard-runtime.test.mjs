// Real ToolRuntime and ApprovalService integration with synthetic session storage.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { realpathSync } from 'node:fs'
import { resolve, extname } from 'node:path'
import { pathToFileURL } from 'node:url'
import { requestApproval } from '../src/adapter/approval.js'
import { apply } from '../src/adapter/host.js'

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

/** A minimal real Session with one open turn (approval requests must be turn-enclosed). */
function openSession(id = 'guardrails-runtime') {
  const session = runtime.session.Session.create(id)
  session.append('turn/start', { turn: 1 })
  return session
}
function session() {
  const events = [{ type: 'turn/start', data: { turn: 1 } }]
  return { get seq() { return events.length }, eventAt: index => events[index],
    append: (type, data) => events.push({ type, data }), events }
}

test('real ApprovalService never cannot be overridden by a prepended answerer', { skip: !runtime && 'Set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t)
  let asked = 0
  ctx.on('approval/request', async () => { asked++; return 'allowed-once' }, { prepend: true })
  const log = openSession()
  const execution = { name: 'read', callId: 'synthetic', agent: { session: log }, signal: new AbortController().signal }
  const result = await requestApproval(ctx, execution, 'Synthetic fixture', 1000, new AbortController().signal)
  assert.equal(result.kind, 'deny')
  assert.equal(asked, 0, 'the never policy resolves before any answerer runs')
  const types = log.snapshotEvents().map(event => event.type)
  assert.ok(types.includes('approval/asked'), 'the ask was audited')
  assert.ok(types.includes('approval/decided'), 'the decision was audited')
  const decided = log.snapshotEvents().find(event => event.type === 'approval/decided')
  assert.equal(decided.data.outcome, 'rejected')
})

const call = (ctx, name, id, args, signal) => ctx.tools.execute({
  signal,
  calls: [{ type: 'tool-call', id, name, arguments: JSON.stringify(args) }],
})

test('real ToolRuntime final guard rejects short-circuited pre-analysis', { skip: !runtime && 'Set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t)
  await ctx.plugin({ name: 'guardrails-test-mount', inject: ['tools'], apply })
  let calls = 0
  ctx.tools.register({ name: 'pwsh', description: 'Synthetic parser fixture.', parameters: { type: 'object' },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    execute: async () => { calls++; return 'safe' } })
  const signal = new AbortController().signal
  const accepted = (await call(ctx, 'pwsh', 'allowed', { command: "Write-Output 'safe'" }, signal)).results[0].result
  assert.equal(accepted.isError, false)
  assert.equal(calls, 1)
  const dispose = ctx.on('tools/pre-execute', async () => ({ kind: 'allow' }), { prepend: true })
  const denied = (await call(ctx, 'pwsh', 'short-circuit', { command: "Write-Output 'safe'" }, signal)).results[0].result
  assert.equal(denied.isError, true)
  assert.match(denied.error.message, /ANALYSIS_MISSING/)
  assert.equal(calls, 1)
  dispose()
})
