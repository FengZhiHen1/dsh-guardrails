// The browser entry is loaded in a VM; no browser, profile write or shell dispatch occurs.
import test from 'node:test'
import assert from 'node:assert/strict'
import vm from 'node:vm'
import { readFile } from 'node:fs/promises'
const source = await readFile(new URL('../src/client/settings.js', import.meta.url), 'utf8')
let plugin
vm.runInNewContext(source, { window: { __ModuleLoader__: { load(entry) {
  plugin = entry.factory(name => {
    assert.equal(name, 'react')
    return { createElement() {} }
  })
} } } })
const plain = value => JSON.parse(JSON.stringify(value))

test('settings converts seconds to milliseconds without losing legacy values or exact path spaces', () => {
  const draft = plugin.toDraft({ sensitiveFiles: ['E:/a b/x', '/tmp/with trailing space '], credentialsReadAsk: false, askTimeoutMs: 1501 })
  assert.equal(draft.seconds, '1.501')
  assert.deepEqual(plain(plugin.parseDraft(draft).value), { sensitiveFiles: ['E:/a b/x', '/tmp/with trailing space '], credentialsReadAsk: false, askTimeoutMs: 1501 })
  assert.equal(plugin.toDraft({ sensitiveFiles: [], credentialsReadAsk: true, askTimeoutMs: 0 }).seconds, '120')
})

test('settings rejects invalid drafts before any Host mutation', () => {
  const draft = { files: '', builtin: true, seconds: '120' }
  for (const seconds of ['', '-1', '0', '3601', '0.0001', 'NaN']) assert.equal(plugin.parseDraft({ ...draft, seconds }).error, 'timeoutError')
  for (const files of ['relative/x', 'C:/x/*.txt', '/a\0b', Array(1025).fill('/file').join('\n')]) assert.equal(plugin.parseDraft({ ...draft, files }).error, 'pathError')
  assert.deepEqual(plain(plugin.parseDraft(draft).value.sensitiveFiles), [])
})

test('settings copies the native settings form and disables save until dirty', () => {
  assert.doesNotMatch(source, /require\('@deepseek-ai\//)
  assert.match(source, /h\(SaveButton, \{ type: 'submit', disabled: locked \|\| !dirty \|\| Boolean\(parsed\.error\)/)
  assert.match(source, /if \(busy\.current \|\| !dirty \|\| parsed\.error \|\| !snapshot\.writable/)
  assert.match(source, /\.gr-settings \.gr-field \+ \.gr-field\{/)
  assert.match(source, /\.gr-settings \.gr-save\{/)
  assert.match(source, /--dsw-alias-label-primary/)
  assert.match(source, /save: '保存', saving: '保存中…'/)
  assert.doesNotMatch(source, /保存设置|Save settings/)
  assert.doesNotMatch(source, /#[0-9a-fA-F]{3,8}\b/)
  assert.doesNotMatch(source, /(?:rgba?|hsla?)\(/)
})

test('settings derives safe drafts from partial or stale served sections', () => {
  assert.deepEqual(plain(plugin.toDraft({})), { files: '', builtin: true, seconds: '120' })
  assert.deepEqual(plain(plugin.toDraft({ sensitiveFiles: [1, '/ok'], credentialsReadAsk: 'no', askTimeoutMs: -5 })), { files: '/ok', builtin: true, seconds: '120' })
})

test('settings owns bilingual dictionary and row slot resources for unload', () => {
  const disposers = []
  const registrations = []
  const keys = []
  const form = { getSnapshot: () => ({ status: 'loading' }), subscribe: () => () => {} }
  const ctx = {
    effect(callback) { disposers.push(callback()) },
    locale: { register(ns, language, dictionary) { keys.push(Object.keys(dictionary).sort()); registrations.push(language); return () => registrations.pop() } },
    configForms: { get(namespace) { assert.equal(namespace, 'guardrails'); return form } },
    slots: { inject(name, callback) { assert.equal(name, 'plugins.row.config'); disposers.push(callback()) }, register(options) {
      assert.equal(options.key, 'dsh-guardrails#guardrails')
      assert.equal(options.locale, 'guardrails-settings')
      assert.equal(options.inject().settingsForm, form)
      return () => registrations.push('slot-disposed')
    } },
  }
  plugin.apply(ctx)
  assert.deepEqual(keys[0], keys[1])
  assert.deepEqual(registrations, ['zh', 'en'])
  while (disposers.length) disposers.pop()()
  assert.equal(disposers.length, 0)
})
