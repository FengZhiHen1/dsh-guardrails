// Settings-seam tests (v0.1.7+ "profile entry Config + volatile + live commit"
// model, unchanged in 0.2.0 — knowledge `host/07`): there is no settings
// namespace registration any more. The row's Cordis Config IS the configuration
// truth, every field is a `Volatile<T>` reference, and a settings-page edit
// commits a new value into the RUNNING fiber — so the gate re-reads those
// references at operation time and picks the change up with no remount and no
// onChange callback.
//
// What these tests pin:
//   1. the plugin declares its page policy through `settings.configure` and
//      does not depend on the settings service existing;
//   2. the gate reads the LIVE value behind each reference, so replacing a
//      reference's snapshot (what the loader does on commit) changes judgment
//      immediately;
//   3. the composition entry is what a profile falls back to when no settings
//      service is mounted at all.
//
// The mock ctx mirrors the cordis surface the adapter actually uses
// (`inject(['settings'], cb)`, `effect`, `settings.configure`, `ctx.on`).
// `makeVolatile` reproduces the cosmokit `Volatile<T>` protocol (a frozen
// `{ get }` over a mutable cell) so a commit can be simulated exactly like the
// loader performs it. No filesystem, no network.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as guardrails from '../index.js'
import { SETTINGS_NS } from '../index.js'

/** The cosmokit volatile protocol: a stable reference over a mutable cell. */
function makeVolatile(value) {
  let current = value
  return Object.freeze({
    get: () => current,
    // Not part of the public protocol: the test plays the loader committing a
    // settings edit (which calls the internal write symbol).
    commit: (next) => { current = next },
  })
}

/** A full entry config with every field volatile, as the loader resolves it. */
function makeEntryConfig(overrides = {}) {
  return {
    sensitiveFiles: overrides.sensitiveFiles !== undefined
      ? makeVolatile(overrides.sensitiveFiles)
      : makeVolatile([]),
    credentialsReadAsk: overrides.credentialsReadAsk !== undefined
      ? makeVolatile(overrides.credentialsReadAsk)
      : makeVolatile(true),
  }
}

function makeHarness({ entry = makeEntryConfig(), withSettings = true } = {}) {
  let listener
  let configured = null
  const disposers = []
  // Settings-page disposers are tracked apart from the plugin's own effects:
  // "the settings provider detaches" must not be simulated by disposing the
  // gate as well, or the test would prove nothing about the settings seam.
  const settingsDisposers = []
  const settings = {
    // SettingsForms.configure(presentation, owner) — declares the page policy
    // (auto: false because the browser half draws its own form) and returns
    // its own disposer.
    configure(presentation, owner) {
      configured = { presentation, owner }
      const off = () => { configured = null }
      settingsDisposers.push(off)
      return off
    },
  }
  const ctx = {
    get: () => undefined,
    fiber: { name: 'dsh-guardrails' },
    effect: (fn) => {
      const result = fn()
      if (typeof result === 'function') disposers.push(result)
    },
    on: (event, handler) => {
      listener = handler
      return () => { listener = undefined }
    },
    inject: (name, consumer) => {
      const deps = Array.isArray(name) ? name : [name]
      // `inject` only runs the consumer once the service is available; with no
      // settings service mounted the callback never fires (that is the
      // documented "plugin runs from the composition entry" branch).
      if (deps.includes('settings') && withSettings) consumer({ ...ctx, settings })
    },
  }
  const call = (name, args) =>
    listener(
      { name, arguments: args, agent: { session: { header: { cwd: 'E:/Project/DSH_Plugins' } } } },
      async () => ({ kind: 'allow' }),
    )
  return {
    ctx, call, entry,
    configured: () => configured,
    /** Simulate the settings provider unmounting: only the page policy goes. */
    detachSettings: () => { while (settingsDisposers.length) settingsDisposers.pop()() },
    dispose: () => { while (disposers.length) disposers.pop()() },
  }
}

const isAsk = (r) => r !== undefined && r.kind === 'ask'
const passes = (r) => r !== undefined && r.kind === 'allow'

test('', async () => {
  const h = makeHarness()
  guardrails.apply(h.ctx, h.entry)
  const c = h.configured()
  assert.notEqual(c, null, 'settings.configure was not called')
  // The browser half draws its own form, so the schema-generated page is off.
  assert.deepEqual(c.presentation, { auto: false })
  // The owner is the plugin's own fiber (the presenting instance).
  assert.equal(c.owner, h.ctx.fiber)
  // The namespace is the loader ENTRY ID, not a plugin-chosen name — the
  // bundle patch inserts `id: guardrails` and the card binds the same value.
  assert.equal(SETTINGS_NS, 'guardrails')
})

test('', async () => {
  const h = makeHarness({ entry: makeEntryConfig({ sensitiveFiles: ['E:/x/secret'] }) })
  guardrails.apply(h.ctx, h.entry)
  assert.equal(isAsk(await h.call('read', { file_path: 'E:/x/secret' })), true)
  assert.equal(isAsk(await h.call('read', { file_path: 'C:/u/.ssh/id_rsa' })), true, 'builtin list stays on')
  assert.equal(passes(await h.call('read', { file_path: '.env' })), true)
})

test('', async () => {
  const h = makeHarness()
  guardrails.apply(h.ctx, h.entry)
  assert.equal(passes(await h.call('read', { file_path: 'E:/app/.env.production' })), true)
  // The loader commits a settings-page edit by replacing the reference's
  // snapshot — no remount, no callback.
  h.entry.sensitiveFiles.commit(['E:/app/.env.production'])
  assert.equal(isAsk(await h.call('read', { file_path: 'E:/app/.env.production' })), true)
  // Committing one field must not disturb another.
  h.entry.credentialsReadAsk.commit(false)
  assert.equal(passes(await h.call('read', { file_path: 'C:/u/.ssh/id_rsa' })), true, 'builtin list off')
  assert.equal(isAsk(await h.call('read', { file_path: 'E:/app/.env.production' })), true, 'the mark edit still stands')
})

test('', async () => {
  const h = makeHarness({ withSettings: false })
  guardrails.apply(h.ctx, h.entry)
  assert.equal(h.configured(), null, 'no settings service means no page policy')
  assert.equal(isAsk(await h.call('read', { file_path: 'C:/u/.ssh/id_rsa' })), true)
  // Live reads work with or without the settings service.
  h.entry.sensitiveFiles.commit(['E:/x/secret'])
  assert.equal(isAsk(await h.call('read', { file_path: 'E:/x/secret' })), true)
})

test('', async () => {
  const h = makeHarness()
  guardrails.apply(h.ctx, h.entry)
  h.entry.sensitiveFiles.commit(['E:/x/secret'])
  assert.equal(isAsk(await h.call('read', { file_path: 'E:/x/secret' })), true)
  h.detachSettings() // settings provider unmounts; the gate is a separate effect
  assert.equal(h.configured(), null, 'page policy was released')
  // No fallback copy is kept: the refs are the single source, so the last
  // committed value still stands rather than snapping back to the row config.
  assert.equal(isAsk(await h.call('read', { file_path: 'E:/x/secret' })), true)
})

test('', async () => {
  // Defensive: a row composed without volatile refs (or a bare-node caller)
  // must keep judging by the composed values instead of throwing.
  const h = makeHarness({ entry: { sensitiveFiles: ['E:/x/secret'], credentialsReadAsk: false } })
  guardrails.apply(h.ctx, h.entry)
  assert.equal(isAsk(await h.call('read', { file_path: 'E:/x/secret' })), true)
  assert.equal(passes(await h.call('read', { file_path: 'C:/u/.ssh/id_rsa' })), true)
})
