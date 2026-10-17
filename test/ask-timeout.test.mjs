// Bounded approval lifecycle, driven through the real Host pre-execute and guard.
// Approval is a virtual service; this suite does not exercise runtime approval UI.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdir, mkdtemp, writeFile, rm } from 'node:fs/promises'
import path from 'node:path'
import * as guardrails from '../index.js'

async function makeGate(t, config = {}, options = {}) {
  const root = await mkdtemp(path.resolve('tmp/approval-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const target = path.join(root, 'synthetic-sensitive.txt')
  await writeFile(target, 'synthetic fixture only')
  const listeners = new Map()
  const disposers = []
  const requests = []
  let answer
  let started
  const ready = new Promise(resolve => { started = resolve })
  const ctx = {
    tools: { guard(fn) { ctx.gate = fn; return () => { ctx.gate = undefined } } },
    get(key) {
      if (key === 'approval' && options.service !== false) return {
        request(req) {
          requests.push(req)
          started()
          if (options.throw) throw new Error('synthetic approval failure')
          if (options.pending) return new Promise(resolve => { answer = resolve })
          return Promise.resolve(options.outcome ?? 'allowed-once')
        },
      }
    },
    effect(fn) { const off = fn(); if (typeof off === 'function') disposers.push(off) },
    inject() {},
    on(event, fn) { listeners.set(event, fn); return () => listeners.delete(event) },
  }
  guardrails.apply(ctx, { sensitiveFiles: [target], ...config })
  const dispose = async () => { while (disposers.length) await disposers.pop()() }
  t.after(dispose)
  const execution = { name: 'read', arguments: { file_path: target }, callId: 'synthetic-call', agent: { session: { header: { cwd: root } } }, ...options.execution }
  let dispatches = 0
  return {
    execution, requests, ready, dispose,
    guard: () => ctx.gate(execution),
    answer: value => answer(value),
    dispatches: () => dispatches,
    run: () => listeners.get('tools/pre-execute')(execution, async () => { dispatches++; return { kind: 'allow' } }),
  }
}

await mkdir(path.resolve('tmp'), { recursive: true })

for (const config of [{}, { askTimeoutMs: 0 }]) {
  test(`default and legacy zero own a bounded 120000ms request: ${JSON.stringify(config)}`, async t => {
    const gate = await makeGate(t, config, { pending: true })
    t.mock.timers.enable({ apis: ['setTimeout'] })
    const pending = gate.run()
    await gate.ready
    t.mock.timers.tick(119999)
    assert.equal(gate.requests[0].signal.aborted, false)
    t.mock.timers.tick(1)
    const result = await pending
    assert.equal(result.kind, 'deny')
    assert.match(result.reason, /APPROVAL_TIMEOUT.*120000ms/)
    assert.equal(gate.requests[0].signal.aborted, true)
    assert.equal(gate.dispatches(), 0)
    assert.match(gate.guard(), /APPROVAL_TIMEOUT/)
  })
}

test('one timely grant dispatches once and clears its timer', async t => {
  const gate = await makeGate(t, { askTimeoutMs: 5000 })
  t.mock.timers.enable({ apis: ['setTimeout'] })
  assert.deepEqual(await gate.run(), { kind: 'allow' })
  assert.equal(gate.dispatches(), 1)
  assert.equal(gate.guard(), undefined)
  const request = gate.requests[0]
  assert.equal(request.toolName, 'read')
  assert.equal(request.callId, gate.execution.callId)
  assert.equal(request.agent, gate.execution.agent)
  assert.match(request.reason, /S-F1/)
  assert.ok(request.reason.length < 600)
  t.mock.timers.tick(60000)
  assert.equal(request.signal.aborted, false)
})

for (const outcome of ['rejected', 'unavailable', 'cancelled', 'maybe']) {
  test(`non-grant approval outcome ${outcome} refuses dispatch`, async t => {
    const gate = await makeGate(t, {}, { outcome })
    const result = await gate.run()
    assert.equal(result.kind, 'deny')
    assert.match(result.reason, /APPROVAL_/)
    assert.equal(gate.dispatches(), 0)
    assert.equal(gate.guard(), result.reason)
  })
}

for (const options of [{ service: false }, { throw: true }, { execution: { agent: undefined } }]) {
  test(`unavailable or failing approval refuses dispatch: ${JSON.stringify(options)}`, async t => {
    const gate = await makeGate(t, {}, options)
    const result = await gate.run()
    assert.equal(result.kind, 'deny')
    assert.match(result.reason, /APPROVAL_(UNAVAILABLE|FAILED)/)
    assert.equal(gate.dispatches(), 0)
  })
}

test('caller cancellation aborts an uncooperative approval service and blocks late grant', async t => {
  const controller = new AbortController()
  const gate = await makeGate(t, {}, { pending: true, execution: { signal: controller.signal } })
  const pending = gate.run()
  await gate.ready
  controller.abort()
  assert.equal((await pending).kind, 'deny')
  assert.equal(gate.requests[0].signal.aborted, true)
  gate.answer('allowed-once')
  await Promise.resolve()
  assert.match(gate.guard(), /CANCELLED/)
  assert.equal(gate.dispatches(), 0)
})

test('timeout ignores a late grant even when the service ignores its abort signal', async t => {
  const gate = await makeGate(t, { askTimeoutMs: 1000 }, { pending: true })
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const pending = gate.run()
  await gate.ready
  t.mock.timers.tick(1000)
  assert.match((await pending).reason, /APPROVAL_TIMEOUT/)
  gate.answer('allowed-once')
  await Promise.resolve()
  assert.match(gate.guard(), /APPROVAL_TIMEOUT/)
  assert.equal(gate.dispatches(), 0)
})

test('unload cancels pending approval without waiting for the service', async t => {
  const gate = await makeGate(t, {}, { pending: true })
  const pending = gate.run()
  await gate.ready
  await gate.dispose()
  assert.equal((await pending).kind, 'deny')
  assert.equal(gate.requests[0].signal.aborted, true)
  gate.answer('allowed-once')
  await Promise.resolve()
  assert.equal(gate.dispatches(), 0)
})

test('mount validation rejects malformed timeout bounds', async t => {
  for (const bad of [-1, 1.5, '3000', 3600001]) {
    await assert.rejects(makeGate(t, { askTimeoutMs: bad }), /askTimeoutMs/)
  }
})
