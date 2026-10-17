// Fiber effects own every guard/listener/settings registration and pending invocation.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as guardrails from '../index.js'

function makeLifecycleCtx() {
  const listeners = []
  const guards = []
  const disposers = []
  const policies = []
  const fiber = { name: 'synthetic-guardrails' }
  const ctx = {
    fiber,
    tools: { guard(handler) {
      guards.push(handler)
      return () => { guards.splice(guards.indexOf(handler), 1) }
    } },
    get: () => undefined,
    on(event, handler) {
      const item = { event, handler }
      listeners.push(item)
      return () => { listeners.splice(listeners.indexOf(item), 1) }
    },
    effect(fn) { const off = fn(); if (typeof off === 'function') disposers.push(off) },
    inject(dependencies, consumer) {
      assert.deepEqual(dependencies, ['settings'])
      consumer({ ...ctx, settings: { configure(presentation, owner) {
        const item = { presentation, owner }
        policies.push(item)
        return () => { policies.splice(policies.indexOf(item), 1) }
      } } })
    },
  }
  return { ctx, listeners, guards, policies,
    pre: () => listeners.filter(item => item.event === 'tools/pre-execute'),
    async dispose() { while (disposers.length) await disposers.pop()() },
  }
}

const exec = () => ({ name: 'web_fetch', arguments: { url: 'https://example.invalid' } })
const next = async () => ({ kind: 'allow' })

test('mount owns one guard, one pre listener, and the generated settings policy', async () => {
  const h = makeLifecycleCtx()
  guardrails.apply(h.ctx)
  assert.equal(h.guards.length, 1)
  assert.equal(h.pre().length, 1)
  assert.deepEqual(h.policies, [{ presentation: { auto: true }, owner: h.ctx.fiber }])
  assert.ok(h.listeners.length >= 1)
  await h.dispose()
  assert.equal(h.guards.length, 0)
  assert.equal(h.listeners.length, 0)
  assert.equal(h.policies.length, 0)
})

test('20 mount-dispose cycles release every registration', async () => {
  const h = makeLifecycleCtx()
  for (let i = 0; i < 20; i++) {
    guardrails.apply(h.ctx)
    assert.equal(h.pre().length, 1)
    assert.equal(h.guards.length, 1)
    const execution = exec()
    assert.equal((await h.pre()[0].handler(execution, next)).kind, 'allow')
    assert.equal(h.guards[0](execution), undefined)
    await h.dispose()
    assert.equal(h.listeners.length, 0, `cycle ${i}`)
    assert.equal(h.guards.length, 0, `cycle ${i}`)
    assert.equal(h.policies.length, 0, `cycle ${i}`)
  }
})

test('HMR remount cannot inherit an old execution authorization', async () => {
  const h = makeLifecycleCtx()
  guardrails.apply(h.ctx)
  const execution = exec()
  await h.pre()[0].handler(execution, next)
  const oldGuard = h.guards[0]
  await h.dispose()
  assert.match(oldGuard(execution), /ANALYSIS_DISPOSED/)
  guardrails.apply(h.ctx)
  assert.match(h.guards[0](execution), /ANALYSIS_MISSING/)
  await h.pre()[0].handler(execution, next)
  assert.equal(h.guards[0](execution), undefined)
  await h.dispose()
})

test('duplicate mounts remain distinct fibers of registrations until disposal', async () => {
  const h = makeLifecycleCtx()
  guardrails.apply(h.ctx)
  guardrails.apply(h.ctx)
  assert.equal(h.pre().length, 2)
  assert.equal(h.guards.length, 2)
  assert.equal(h.policies.length, 2)
  await h.dispose()
  assert.equal(h.listeners.length, 0)
  assert.equal(h.guards.length, 0)
})

test('invalid config fails before any effect registration', () => {
  for (const config of [{ credentialsReadAsk: 'no' }, { bogusKey: true }, null, { sensitiveFiles: ['relative/path'] }]) {
    const h = makeLifecycleCtx()
    assert.throws(() => guardrails.apply(h.ctx, config))
    assert.equal(h.listeners.length, 0)
    assert.equal(h.guards.length, 0)
    assert.equal(h.policies.length, 0)
  }
})

test('disposal is idempotent and remount remains possible', async () => {
  const h = makeLifecycleCtx()
  guardrails.apply(h.ctx)
  await h.dispose()
  await h.dispose()
  guardrails.apply(h.ctx)
  assert.equal(h.guards.length, 1)
  await h.dispose()
})
