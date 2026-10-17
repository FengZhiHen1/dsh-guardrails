// Native configuration slot and Host presentation belong to the plugin lifetime.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import * as guardrails from '../index.js'

const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
const patch = readFileSync(new URL('../cordis.patch.yml', import.meta.url), 'utf8')

test('package declares the native configuration-slot client and its provider dependencies', () => {
  assert.equal(manifest.dsh.client.platform, 'web')
  assert.equal(manifest.exports['./client'], './src/client/settings.js')
  assert.equal(manifest.exports['.'].default, './index.js')
})

test('bundle retains the guardrails row identity for existing settings', () => {
  assert.equal(guardrails.SETTINGS_NS, 'guardrails')
  assert.match(patch, /\bid:\s*guardrails\b/)
  assert.match(patch, /\bname:\s*dsh-guardrails\b/)
})

test('Host disables duplicate generation without asking for client services', async () => {
  const effects = []
  const configurations = []
  const ctx = {
    fiber: { name: 'synthetic-settings-owner' },
    tools: { guard: () => () => {} },
    get: () => undefined,
    effect(fn) { const off = fn(); if (typeof off === 'function') effects.push(off) },
    on: () => () => {},
    inject(deps, consumer) {
      assert.deepEqual(deps, ['settings'])
      consumer({ ...ctx, settings: { configure(presentation, owner) {
        configurations.push({ presentation, owner })
        return () => { configurations.pop() }
      } } })
    },
  }
  guardrails.apply(ctx)
  try {
    assert.deepEqual(configurations, [{ presentation: { auto: false }, owner: ctx.fiber }])
    assert.deepEqual(Object.keys(guardrails.Config.dict).sort(), ['askTimeoutMs', 'builtinSensitiveAsk', 'sensitiveFiles'])
    for (const value of Object.values(guardrails.Config({}))) assert.equal(typeof value.get, 'function')
  } finally {
    while (effects.length) await effects.pop()()
  }
  assert.deepEqual(configurations, [])
})
