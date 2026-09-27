// Settings-seam tests (v0.1.7 "profile entry Config + volatile + live commit"
// model): there is no settings namespace registration any more. The row's
// Cordis Config IS the configuration truth, every field is a `Volatile<T>`
// reference, and a settings-page edit commits a new value into the RUNNING
// fiber — so the guard re-reads those references at operation time and picks
// the change up with no remount and no onChange callback.
//
// What these tests pin:
//   1. the plugin declares its page policy through `settings.configure` and
//      does not depend on the settings service existing;
//   2. the guard reads the LIVE value behind each reference, so replacing a
//      reference's snapshot (what the loader does on commit) changes judgment
//      immediately;
//   3. the composition entry is what a profile falls back to when no settings
//      service is mounted at all.
//
// The mock ctx mirrors the cordis surface the adapter actually uses
// (`inject(['settings'], cb)`, `effect`, `settings.configure`, `tools.guard`).
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
  const refs = {}
  for (const field of ['env', 'git', 'credentials', 'system', 'destructive', 'unverifiable']) {
    refs[field] = makeVolatile(overrides[field] ?? true)
  }
  return refs
}

function makeHarness({ entry = makeEntryConfig(), withSettings = true } = {}) {
  let handler
  let configured = null
  const disposers = []
  // Settings-page disposers are tracked apart from the plugin's own effects:
  // "the settings provider detaches" must not be simulated by disposing the
  // guard as well, or the test would prove nothing about the settings seam.
  const settingsDisposers = []
  const settings = {
    // v0.1.7 SettingsForms.configure(presentation, owner) — declares the page
    // policy (auto: false because the browser half draws its own form) and
    // returns its own disposer.
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
    inject: (name, consumer) => {
      const deps = Array.isArray(name) ? name : [name]
      // `inject` only runs the consumer once the service is available; with no
      // settings service mounted the callback never fires (that is the
      // documented "plugin runs from the composition entry" branch).
      if (deps.includes('settings') && withSettings) consumer({ ...ctx, settings })
    },
    tools: {
      guard: (h) => { handler = h; return () => { handler = undefined } },
    },
  }
  const call = (name, args) =>
    handler({ name, arguments: args, agent: { session: { header: { cwd: 'E:/Project/DSH_Plugins' } } } })
  return {
    ctx, call, entry,
    configured: () => configured,
    /** Simulate the settings provider unmounting: only the page policy goes. */
    detachSettings: () => { while (settingsDisposers.length) settingsDisposers.pop()() },
    dispose: () => { while (disposers.length) disposers.pop()() },
  }
}

const blocked = (r) => typeof r === 'string' && r.startsWith('[guardrails] Blocked')

test('declares the page policy (auto: false) without owning a settings namespace', () => {
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

test('entry config drives judgment (all defaults on, row config honored)', () => {
  const h = makeHarness({ entry: makeEntryConfig({ destructive: { cli: false } }) })
  guardrails.apply(h.ctx, h.entry)
  // entry config honored: the cli subfamily is off
  assert.equal(blocked(h.call('pwsh', { command: 'kubectl delete ns prod' })), false)
  // unmentioned layers stay on
  assert.equal(blocked(h.call('pwsh', { command: 'rm -rf .' })), true)
})

test('a committed settings edit takes effect immediately (live volatile read)', () => {
  const h = makeHarness()
  guardrails.apply(h.ctx, h.entry)
  assert.equal(blocked(h.call('read', { file_path: '.env' })), true)
  // The loader commits a settings-page edit by replacing the reference's
  // snapshot — no remount, no callback.
  h.entry.env.commit({ read: false, modify: true })
  assert.equal(blocked(h.call('read', { file_path: '.env' })), false)
  assert.equal(blocked(h.call('write', { file_path: '.env' })), true)
  // Boolean category form (v1) is normalized too.
  h.entry.destructive.commit(false)
  assert.equal(blocked(h.call('pwsh', { command: 'rm -rf .' })), false)
  // Committing one field must not disturb another: the env edit still stands.
  assert.equal(blocked(h.call('read', { file_path: '.env' })), false)
  assert.equal(blocked(h.call('write', { file_path: '.env' })), true)
})

test('the fail-safe toggle is read live as well', () => {
  const h = makeHarness()
  guardrails.apply(h.ctx, h.entry)
  // A command whose only remaining target is a dynamic $() substitution is
  // blocked by the fail-safe; turning it off must also be live.
  const dynamic = { command: 'Remove-Item -Recurse -Force $(Resolve-Path ./build)' }
  assert.equal(blocked(h.call('pwsh', dynamic)), true)
  h.entry.unverifiable.commit(false)
  assert.equal(blocked(h.call('pwsh', dynamic)), false)
})

test('no settings service mounted: plugin runs from the composition entry', () => {
  const h = makeHarness({ withSettings: false })
  guardrails.apply(h.ctx, h.entry)
  assert.equal(h.configured(), null, 'no settings service means no page policy')
  assert.equal(blocked(h.call('read', { file_path: '.env' })), true)
  // Live reads work with or without the settings service.
  h.entry.env.commit({ read: false, modify: true })
  assert.equal(blocked(h.call('read', { file_path: '.env' })), false)
})

test('detaching the settings service leaves the guard reading the same refs', () => {
  const h = makeHarness()
  guardrails.apply(h.ctx, h.entry)
  h.entry.env.commit(false)
  assert.equal(blocked(h.call('read', { file_path: '.env' })), false)
  h.detachSettings() // settings provider unmounts; the guard is a separate effect
  assert.equal(h.configured(), null, 'page policy was released')
  // No fallback copy is kept: the refs are the single source, so the last
  // committed value still stands rather than snapping back to the row config.
  assert.equal(blocked(h.call('read', { file_path: '.env' })), false)
})

test('a plain (non-volatile) config still works: hand-written rows and tests', () => {
  // Defensive: a row composed without volatile refs (or a bare-node caller)
  // must keep judging by the composed values instead of throwing.
  const h = makeHarness({ entry: { env: { read: false, modify: true }, destructive: true, unverifiable: true } })
  guardrails.apply(h.ctx, h.entry)
  assert.equal(blocked(h.call('read', { file_path: '.env' })), false)
  assert.equal(blocked(h.call('write', { file_path: '.env' })), true)
})
