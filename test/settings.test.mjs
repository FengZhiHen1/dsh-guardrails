// Generated settings policy and live volatile values are independent of settings availability.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdir, mkdtemp, writeFile, rm } from 'node:fs/promises'
import path from 'node:path'
import * as guardrails from '../index.js'

function volatile(value) {
  let current = value
  return Object.freeze({ get: () => current, commit(next) { current = next } })
}

async function harness(t, { withSettings = true, plain = false } = {}) {
  await mkdir(path.resolve('tmp'), { recursive: true })
  const root = await mkdtemp(path.resolve('tmp/settings-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const marked = path.join(root, 'marked.txt')
  const builtin = path.join(root, 'id_rsa')
  for (const file of [marked, builtin]) await writeFile(file, 'synthetic fixture only')
  const entry = Object.fromEntries(Object.entries({ sensitiveFiles: [], credentialsReadAsk: true, askTimeoutMs: 120000 })
    .map(([key, value]) => [key, plain ? value : volatile(value)]))
  const effects = []
  const settingsEffects = []
  const listeners = new Map()
  const requests = []
  let configured
  const ctx = {
    fiber: { name: 'synthetic-guardrails' },
    tools: { guard: () => () => {} },
    get: key => key === 'approval' ? { request: async req => { requests.push(req); return 'allowed-once' } } : undefined,
    effect(fn) { const off = fn(); if (typeof off === 'function') effects.push(off) },
    on(event, handler) { listeners.set(event, handler); return () => listeners.delete(event) },
    inject(deps, consumer) {
      assert.deepEqual(deps, ['settings'])
      if (withSettings) consumer({ ...ctx,
        effect(fn) { const off = fn(); if (typeof off === 'function') settingsEffects.push(off) },
        settings: { configure(presentation, owner) {
          configured = { presentation, owner }
          return () => { configured = undefined }
        } },
      })
    },
  }
  guardrails.apply(ctx, entry)
  const detachSettings = () => { while (settingsEffects.length) settingsEffects.pop()() }
  t.after(async () => { detachSettings(); while (effects.length) await effects.pop()() })
  return { ctx, entry, marked, builtin, requests, detachSettings, configured: () => configured,
    async read(file_path) {
      return listeners.get('tools/pre-execute')({ name: 'read', arguments: { file_path }, agent: { session: { header: { cwd: root } } } }, async () => ({ kind: 'allow' }))
    },
  }
}

test('settings selects the native slot editor owned by the plugin fiber', async t => {
  const h = await harness(t)
  assert.deepEqual(h.configured(), { presentation: { auto: false }, owner: h.ctx.fiber })
  assert.equal(guardrails.SETTINGS_NS, 'guardrails')
})

test('live marked-file and builtin toggles change analysis without remount', async t => {
  const h = await harness(t)
  await h.read(h.marked)
  assert.equal(h.requests.length, 0)
  h.entry.sensitiveFiles.commit([h.marked])
  await h.read(h.marked)
  assert.equal(h.requests.length, 1)
  await h.read(h.builtin)
  assert.equal(h.requests.length, 2)
  h.entry.credentialsReadAsk.commit(false)
  await h.read(h.builtin)
  assert.equal(h.requests.length, 2)
  await h.read(h.marked)
  assert.equal(h.requests.length, 3, 'changing builtin toggle must retain explicit marks')
})

test('invalid live values fail closed for that invocation', async t => {
  const h = await harness(t)
  h.entry.askTimeoutMs.commit(-1)
  assert.match((await h.read(h.marked)).reason, /ANALYSIS_UNAVAILABLE/)
  h.entry.askTimeoutMs.commit(120000)
  assert.equal((await h.read(h.marked)).kind, 'allow')
})

for (const withSettings of [true, false]) {
  test(`live config remains authoritative with settings available=${withSettings}`, async t => {
    const h = await harness(t, { withSettings })
    h.entry.sensitiveFiles.commit([h.marked])
    h.detachSettings()
    assert.equal(h.configured(), undefined)
    await h.read(h.marked)
    assert.equal(h.requests.length, 1)
    h.entry.sensitiveFiles.commit([])
    await h.read(h.marked)
    assert.equal(h.requests.length, 1)
  })
}

test('plain composed values work for bare Node callers', async t => {
  const h = await harness(t, { plain: true })
  h.entry.sensitiveFiles.push(h.marked)
  assert.equal((await h.read(h.marked)).kind, 'allow')
  assert.equal(h.requests.length, 1)
})
