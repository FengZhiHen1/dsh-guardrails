// Lifecycle tests (quality standard §3/§8.1): mount → dispose → remount
// cycles, HMR re-apply, duplicate-mount non-masking, and load-time config
// failure. The mock ctx records effect disposers exactly like Cordis does:
// the plugin returns the guard unregister disposer from the effect callback,
// so unmount unregisters the guard. No filesystem, no network.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as guardrails from '../index.js'

function makeLifecycleCtx() {
  const guards = []
  const disposers = []
  const ctx = {
    get: () => undefined,
    effect: (fn) => {
      const result = fn()
      if (typeof result === 'function') disposers.push(result)
    },
    inject: (name, consumer) => {
      if (name === 'settings' && ctx.$$settings !== undefined) consumer({ ...ctx, settings: ctx.$$settings })
    },
    tools: {
      guard: (handler) => {
        guards.push(handler)
        return () => {
          const i = guards.indexOf(handler)
          if (i >= 0) guards.splice(i, 1)
        }
      },
    },
  }
  return {
    ctx,
    guards,
    dispose: () => {
      while (disposers.length) disposers.pop()()
    },
  }
}

const blocked = (r) => typeof r === 'string' && r.startsWith('[guardrails] Blocked')
const exec = (name, file_path) => ({
  name,
  arguments: { file_path },
  agent: { session: { meta: { cwd: 'E:/p' } } },
})

test('mount registers exactly one guard; dispose unregisters it', () => {
  const { ctx, guards, dispose } = makeLifecycleCtx()
  guardrails.apply(ctx)
  assert.equal(guards.length, 1)
  dispose()
  assert.equal(guards.length, 0)
})

test('20 mount→dispose cycles keep exactly one registration and a working guard', () => {
  const { ctx, guards, dispose } = makeLifecycleCtx()
  for (let i = 0; i < 20; i += 1) {
    guardrails.apply(ctx)
    assert.equal(guards.length, 1, `cycle ${i}`)
    assert.equal(blocked(guards[0](exec('read', '.env'))), true, `cycle ${i}`)
    assert.equal(blocked(guards[0](exec('read', '.env.example'))), false, `cycle ${i}`)
    dispose()
    assert.equal(guards.length, 0, `cycle ${i}`)
  }
})

test('HMR re-apply: old instance disposed, new config takes effect', () => {
  const { ctx, guards, dispose } = makeLifecycleCtx()
  guardrails.apply(ctx, { env: true })
  const first = guards[0]
  dispose() // HMR: Cordis disposes the old effect before re-applying
  guardrails.apply(ctx, { env: false })
  assert.equal(guards.length, 1)
  assert.notEqual(guards[0], first) // old handler is gone
  assert.equal(blocked(guards[0](exec('read', 'E:/p/.env'))), false) // env off
  assert.equal(blocked(guards[0](exec('read', 'E:/p/.dsh/sessions/x'))), false) // .dsh never intercepted
})

test('double mount without dispose registers two guards (no silent dedup)', () => {
  const { ctx, guards } = makeLifecycleCtx()
  guardrails.apply(ctx)
  guardrails.apply(ctx)
  assert.equal(guards.length, 2) // duplicate-row detection stays Cordis's job
})

test('invalid config fails the mount instead of silently degrading', () => {
  const { ctx } = makeLifecycleCtx()
  assert.throws(() => guardrails.apply(ctx, { env: 'no' }), /must be a boolean/)
  assert.throws(() => guardrails.apply(ctx, { bogusKey: true }), /unknown config key/)
  assert.throws(() => guardrails.apply(ctx, null), /must be an object/)
  // DSR-006 leaf-level validation
  assert.throws(() => guardrails.apply(ctx, { env: { bogus: true } }), /unknown "env" config key/)
  assert.throws(() => guardrails.apply(ctx, { destructive: { cli: 1 } }), /must be a boolean/)
})

test('dispose is idempotent and repeatable', () => {
  const { ctx, guards, dispose } = makeLifecycleCtx()
  guardrails.apply(ctx)
  dispose()
  dispose()
  assert.equal(guards.length, 0)
  guardrails.apply(ctx) // remount after double dispose still works
  assert.equal(guards.length, 1)
})
