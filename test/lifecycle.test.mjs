// Lifecycle tests: mount → dispose → remount cycles, HMR re-apply,
// duplicate-mount non-masking, and load-time config failure. The mock ctx
// records listener disposers exactly like Cordis does: the plugin returns the
// pre-execute listener's disposer from the effect callback, so unmount
// unregisters it. No filesystem, no network.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as guardrails from '../index.js'

function makeLifecycleCtx() {
  const listeners = []
  const disposers = []
  const ctx = {
    get: () => undefined,
    on: (event, handler) => {
      listeners.push({ event, handler })
      return () => {
        const i = listeners.findIndex((l) => l.handler === handler)
        if (i >= 0) listeners.splice(i, 1)
      }
    },
    effect: (fn) => {
      const result = fn()
      if (typeof result === 'function') disposers.push(result)
    },
    inject: (name, consumer) => {
      if (name === 'settings' && ctx.$$settings !== undefined) consumer({ ...ctx, settings: ctx.$$settings })
    },
  }
  return {
    ctx,
    listeners,
    preExecute: () => listeners.filter((l) => l.event === 'tools/pre-execute'),
    dispose: () => {
      while (disposers.length) disposers.pop()()
    },
  }
}

const exec = (name, args) => ({
  name,
  arguments: args,
  agent: { session: { header: { cwd: 'E:/p' } } },
})
const next = async () => ({ kind: 'allow' })
const asks = (decision) => decision !== undefined && decision.kind === 'ask'

test('mount registers exactly one pre-execute listener; dispose unregisters it', () => {
  const { ctx, preExecute, dispose } = makeLifecycleCtx()
  guardrails.apply(ctx)
  assert.equal(preExecute().length, 1)
  dispose()
  assert.equal(preExecute().length, 0)
})

test('20 mount→dispose cycles keep exactly one registration and a working gate', async () => {
  const { ctx, preExecute, dispose } = makeLifecycleCtx()
  for (let i = 0; i < 20; i += 1) {
    guardrails.apply(ctx)
    assert.equal(preExecute().length, 1, `cycle ${i}`)
    assert.equal(asks(await preExecute()[0].handler(exec('read', { file_path: 'C:/u/.ssh/id_rsa' }), next)), true, `cycle ${i}`)
    dispose()
    assert.equal(preExecute().length, 0, `cycle ${i}`)
  }
})

test('HMR re-apply: old instance disposed, new config takes effect', async () => {
  const { ctx, preExecute, dispose } = makeLifecycleCtx()
  guardrails.apply(ctx, { sensitiveFiles: ['E:/p/secret'] })
  assert.equal(asks(await preExecute()[0].handler(exec('read', { file_path: 'E:/p/secret' }), next)), true)
  dispose() // HMR: Cordis disposes the old effect before re-applying
  guardrails.apply(ctx, { sensitiveFiles: [] })
  assert.equal(preExecute().length, 1)
  assert.equal(asks(await preExecute()[0].handler(exec('read', { file_path: 'E:/p/secret' }), next)), false) // mark removed
})

test('double mount without dispose registers two listeners (no silent dedup)', () => {
  const { ctx, preExecute } = makeLifecycleCtx()
  guardrails.apply(ctx)
  guardrails.apply(ctx)
  assert.equal(preExecute().length, 2) // duplicate-row detection stays Cordis's job
})

test('invalid config fails the mount instead of silently degrading', () => {
  const { ctx } = makeLifecycleCtx()
  assert.throws(() => guardrails.apply(ctx, { credentialsReadAsk: 'no' }), /must be a boolean/)
  assert.throws(() => guardrails.apply(ctx, { bogusKey: true }), /unknown config key/)
  assert.throws(() => guardrails.apply(ctx, null), /must be an object/)
  assert.throws(() => guardrails.apply(ctx, { sensitiveFiles: ['relative/path'] }), /absolute file paths/)
})

test('dispose is idempotent and repeatable', () => {
  const { ctx, preExecute, dispose } = makeLifecycleCtx()
  guardrails.apply(ctx)
  dispose()
  dispose()
  assert.equal(preExecute().length, 0)
  guardrails.apply(ctx) // remount after double dispose still works
  assert.equal(preExecute().length, 1)
})
