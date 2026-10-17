// Client retirement contract: the loader uses the official schema-generated settings page.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import * as guardrails from '../index.js'

const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
const patch = readFileSync(new URL('../cordis.patch.yml', import.meta.url), 'utf8')

test('package no longer advertises or exports a custom client settings bundle', () => {
  assert.equal(Object.hasOwn(manifest.dsh, 'client'), false)
  assert.equal(Object.hasOwn(manifest.exports, './client'), false)
  assert.equal(manifest.exports['.'].default, './index.js')
})

test('bundle retains the guardrails row identity for existing settings', () => {
  assert.equal(guardrails.SETTINGS_NS, 'guardrails')
  assert.match(patch, /\bid:\s*guardrails\b/)
  assert.match(patch, /\bname:\s*dsh-guardrails\b/)
})

test('Host configures the generated page without asking for client services', async () => {
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
    assert.deepEqual(configurations, [{ presentation: { auto: true }, owner: ctx.fiber }])
    assert.deepEqual(Object.keys(guardrails.Config.dict).sort(), ['askTimeoutMs', 'credentialsReadAsk', 'sensitiveFiles'])
    for (const value of Object.values(guardrails.Config({}))) assert.equal(typeof value.get, 'function')
  } finally {
    while (effects.length) await effects.pop()()
  }
  assert.deepEqual(configurations, [])
})
