// Settings-seam tests (official "adding a settings card" pattern): the plugin
// registers its own settings namespace with the composition entry as `base`,
// the user document overrides it, and committed changes rebuild the guard
// rules live; provider detach falls back to the entry. The mock settings
// service records the registration and lets the test drive `scope.get()` and
// the watcher. No filesystem, no network.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as guardrails from '../index.js'
import { SETTINGS_NS } from '../index.js'

function makeHarness(settingsValue) {
  let handler
  let watcher
  const disposers = []
  let current = settingsValue
  let base
  const registered = []
  const settings = {
    register(ns, schema, options) {
      registered.push({ ns, schema, base: options.base })
      base = options.base
      return {
        // Resolved section: the user document overlays the entry base; a
        // null mock value means "absent user section" → the base.
        get: () => (current === null ? base : current),
        watch: (callback) => {
          watcher = callback
          return () => { watcher = undefined }
        },
      }
    },
  }
  const ctx = {
    get: () => undefined,
    effect: (fn) => {
      const result = fn()
      if (typeof result === 'function') disposers.push(result)
      return result
    },
    // cordis 4.x inject() takes an array (or object) of dependency names;
    // keep accepting the legacy bare-string form so the mock mirrors both.
    inject: (name, consumer) => {
      const deps = Array.isArray(name) ? name : [name]
      if (deps.includes('settings')) consumer({ ...ctx, settings })
    },
    tools: {
      guard: (h) => { handler = h },
    },
  }
  const call = (name, args) =>
    handler({ name, arguments: args, agent: { session: { meta: { cwd: 'E:/Project/DSH_Plugins' } } } })
  return {
    ctx, call, registered, disposers,
    setValue: (value) => { current = value },
    commit: () => { if (watcher) watcher() },
    dispose: () => { while (disposers.length) disposers.pop()() },
  }
}

const blocked = (r) => typeof r === 'string' && r.startsWith('[guardrails] Blocked')

test('registers the settings namespace with the entry config as base', () => {
  const h = makeHarness(null)
  guardrails.apply(h.ctx, { destructive: { cli: false } })
  assert.equal(h.registered.length, 1)
  assert.equal(h.registered[0].ns, SETTINGS_NS)
  assert.deepEqual(h.registered[0].base.destructive, {
    git: true, machine: true, eval: true, cli: false, bulk: true, target: true,
  })
  // entry config honored when the setting document is empty
  assert.equal(blocked(h.call('pwsh', { command: 'kubectl delete ns prod' })), false)
  assert.equal(blocked(h.call('pwsh', { command: 'rm -rf .' })), true)
})

test('user settings override the entry and rebuild rules live on commit', () => {
  const h = makeHarness(null)
  guardrails.apply(h.ctx, {})
  const full = h.registered[0].base
  assert.equal(blocked(h.call('read', { file_path: '.env' })), true)
  // a committed change lands through scope.get() → watcher → rules rebuild
  h.setValue({ ...full, env: { read: false, modify: true } })
  h.commit()
  assert.equal(blocked(h.call('read', { file_path: '.env' })), false)
  assert.equal(blocked(h.call('write', { file_path: '.env' })), true)
  // boolean category form (v1) is normalized too
  h.setValue({ ...full, destructive: false })
  h.commit()
  assert.equal(blocked(h.call('pwsh', { command: 'rm -rf .' })), false)
  assert.equal(blocked(h.call('pwsh', { command: 'shutdown -s -t 0' })), false)
})

test('settings provider detach falls back to the composition entry', () => {
  const h = makeHarness(null)
  guardrails.apply(h.ctx, {})
  const full = h.registered[0].base
  h.setValue({ ...full, env: { read: false, modify: false } })
  h.commit()
  assert.equal(blocked(h.call('read', { file_path: '.env' })), false)
  h.dispose() // detach: source falls back to the entry (all on)
  assert.equal(blocked(h.call('read', { file_path: '.env' })), true)
})

test('no settings service mounted: plugin runs from the composition entry', () => {
  let handler
  const ctx = {
    get: () => undefined,
    effect: (fn) => fn(),
    inject: () => {},
    tools: { guard: (h) => { handler = h } },
  }
  guardrails.apply(ctx, {})
  const r = handler({ name: 'read', arguments: { file_path: '.env' }, agent: { session: { meta: { cwd: 'E:/p' } } } })
  assert.equal(blocked(r), true)
})
