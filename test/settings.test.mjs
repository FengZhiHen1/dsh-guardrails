// Settings-seam tests (official installSection pattern): the plugin registers
// its own settings namespace with the composition entry as `base`, the user
// document overrides it, and committed changes rebuild the guard rules live;
// provider detach falls back to the entry. The mock settings service mirrors
// @deepseek-ai/dsh-settings installSection (setSource → detach fallback →
// onChange → watch) and lets the test drive the resolved value and the change
// notification. No filesystem, no network.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as guardrails from '../index.js'
import { SETTINGS_NS } from '../index.js'

function makeHarness(settingsValue) {
  let handler
  let onChange
  const detachers = []
  let current = settingsValue
  let entry
  const registered = []
  const settings = {
    // installSection(owner, ns, schema, entry, hooks): entry is the base
    // layer verbatim; the source reads the resolved section (null mock value
    // = absent user section → the entry); detach falls back to the entry.
    installSection(owner, ns, schema, entryConfig, hooks) {
      registered.push({ ns, schema, base: entryConfig })
      entry = entryConfig
      hooks.setSource(() => (current === null ? entry : current))
      onChange = hooks.onChange
      detachers.push(() => {
        hooks.setSource(() => entry)
        hooks.onChange()
      })
      hooks.onChange()
    },
  }
  const ctx = {
    get: () => undefined,
    effect: (fn) => fn(),
    // cordis inject() takes an array (or object) of dependency names; keep
    // accepting the legacy bare-string form so the mock mirrors both.
    inject: (name, consumer) => {
      const deps = Array.isArray(name) ? name : [name]
      if (deps.includes('settings')) consumer({ ...ctx, settings })
    },
    tools: {
      guard: (h) => { handler = h },
    },
  }
  const call = (name, args) =>
    handler({ name, arguments: args, agent: { session: { header: { cwd: 'E:/Project/DSH_Plugins' } } } })
  return {
    ctx, call, registered,
    setValue: (value) => { current = value },
    commit: () => { if (onChange) onChange() },
    detach: () => { while (detachers.length) detachers.pop()() },
  }
}

const blocked = (r) => typeof r === 'string' && r.startsWith('[guardrails] Blocked')

test('registers the settings namespace with the entry config as base', () => {
  const h = makeHarness(null)
  guardrails.apply(h.ctx, { destructive: { cli: false } })
  assert.equal(h.registered.length, 1)
  assert.equal(h.registered[0].ns, SETTINGS_NS)
  // installSection registers the entry verbatim as the base layer.
  assert.deepEqual(h.registered[0].base, { destructive: { cli: false } })
  // entry config honored when the setting document is empty
  assert.equal(blocked(h.call('pwsh', { command: 'kubectl delete ns prod' })), false)
  assert.equal(blocked(h.call('pwsh', { command: 'rm -rf .' })), true)
})

test('user settings override the entry and rebuild rules live on commit', () => {
  const h = makeHarness(null)
  guardrails.apply(h.ctx, {})
  // a committed change lands through the resolved value → onChange → rebuild
  h.setValue({ env: { read: false, modify: true } })
  h.commit()
  assert.equal(blocked(h.call('read', { file_path: '.env' })), false)
  assert.equal(blocked(h.call('write', { file_path: '.env' })), true)
  // boolean category form (v1) is normalized too; unmentioned categories
  // default to all-on
  h.setValue({ destructive: false })
  h.commit()
  assert.equal(blocked(h.call('pwsh', { command: 'rm -rf .' })), false)
  assert.equal(blocked(h.call('pwsh', { command: 'shutdown -s -t 0' })), false)
  assert.equal(blocked(h.call('read', { file_path: '.env' })), true)
})

test('settings provider detach falls back to the composition entry', () => {
  const h = makeHarness(null)
  guardrails.apply(h.ctx, {})
  h.setValue({ env: { read: false, modify: false } })
  h.commit()
  assert.equal(blocked(h.call('read', { file_path: '.env' })), false)
  h.detach() // provider detach: source falls back to the entry (all on)
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
  const r = handler({ name: 'read', arguments: { file_path: '.env' }, agent: { session: { header: { cwd: 'E:/p' } } } })
  assert.equal(blocked(r), true)
})
