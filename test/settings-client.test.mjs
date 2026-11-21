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
    return { createElement(type, props) { return { type, props } } }
  })
} } } })
const plain = value => JSON.parse(JSON.stringify(value))

test('settings converts seconds to milliseconds without losing legacy values or exact path spaces', () => {
  const draft = plugin.toDraft({ sensitiveFiles: ['E:/a b/x', '/tmp/with trailing space '], builtinSensitiveAsk: false, askTimeoutMs: 1501 })
  assert.equal(draft.seconds, '1.501')
  assert.deepEqual(plain(plugin.parseDraft(draft).value), { sensitiveFiles: ['E:/a b/x', '/tmp/with trailing space '], builtinSensitiveAsk: false, alwaysAsk: true, askTimeoutMs: 1501 })
  assert.equal(plugin.toDraft({ sensitiveFiles: [], builtinSensitiveAsk: true, askTimeoutMs: 0 }).seconds, '120')
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
  assert.match(source, /\.gr-settings\{[^}]*width:100%/)
  assert.doesNotMatch(source, /\.gr-settings\{[^}]*max-width/)
  assert.match(source, /\.gr-settings \.gr-save\{/)
  assert.match(source, /--dsw-alias-label-primary/)
  assert.match(source, /save: '保存', saving: '保存中…'/)
  assert.doesNotMatch(source, /保存设置|Save settings/)
  assert.doesNotMatch(source, /#[0-9a-fA-F]{3,8}\b/)
  assert.doesNotMatch(source, /(?:rgba?|hsla?)\(/)
})

test('settings puts long explanations behind the info disclosure', () => {
  assert.match(source, /className: 'gr-help-button'/)
  assert.match(source, /'aria-expanded': openHelp === key/)
  assert.match(source, /'aria-controls': helpId\(key\)/)
  assert.match(source, /role: 'region'/)
  assert.match(source, /helpRegion\('files'\)/)
  assert.match(source, /helpRegion\('builtin'\)/)
  assert.match(source, /helpRegion\('alwaysAsk'\)/)
  assert.match(source, /helpRegion\('timeout'\)/)
  assert.match(source, /helpRegion\('scope'\)/)
  assert.match(source, /filesHelpLabel/)
  assert.match(source, /alwaysAskHelpLabel/)
  assert.match(source, /scopeHelpLabel/)
})

test('settings derives safe drafts from partial or stale served sections', () => {
  assert.deepEqual(plain(plugin.toDraft({})), { files: '', builtin: true, alwaysAsk: true, seconds: '120' })
  assert.deepEqual(plain(plugin.toDraft({ sensitiveFiles: [1, '/ok'], builtinSensitiveAsk: 'no', askTimeoutMs: -5 })), { files: '/ok', builtin: true, alwaysAsk: true, seconds: '120' })
})

test('settings round-trips alwaysAsk so the toggle saves and reads back', () => {
  const draft = plugin.toDraft({ sensitiveFiles: [], builtinSensitiveAsk: true, alwaysAsk: false, askTimeoutMs: 120000 })
  assert.equal(draft.alwaysAsk, false)
  const parsed = plain(plugin.parseDraft(draft).value)
  assert.equal(parsed.alwaysAsk, false)
  // A legacy draft without the key keeps the protective default (true).
  assert.equal(plain(plugin.parseDraft({ files: '', builtin: true, seconds: '120' }).value).alwaysAsk, true)
})

test('settings explains subagent refusals and non-enumerable approvals in both languages', () => {
  const copy = [
    '没有客户端应答的无人值守会话，以及委派给子代理的会话，仍会拒绝（子代理无法询问用户，请回到父会话执行）',
    'Headless sessions without a client, and delegated subagent sessions, still refuse (a child cannot ask you; run it from the parent session)',
    '此外，无法准确枚举的删除、移动来源、Git 清理/恢复/工作树移除，以及无法静态解析的执行，也会请求一次确认',
    'Deletions that cannot be enumerated, move sources, Git clean/restore, worktree removal, and executions that cannot be statically resolved also request one-time approval',
    '必须是绝对路径（不支持相对路径）',
    'Paths must be absolute; relative paths are not supported.',
    '（仅查看元数据不触发）',
    '(metadata-only inspection does not prompt)',
  ]
  for (const text of copy) assert.ok(source.includes(text), text)
})

test('settings owns bilingual dictionary and row slot resources for unload', () => {
  const disposers = []
  const registrations = []
  const keys = []
  const form = { state: { status: 'loading' } }
  const ctx = {
    effect(callback) { disposers.push(callback()) },
    locale: { register(ns, language, dictionary) { keys.push(Object.keys(dictionary).sort()); registrations.push(language); return () => registrations.pop() } },
    slots: {
      inject(name, callback) {
        assert.ok(name === 'plugins.row.config' || name === 'conversation.composer', name)
        disposers.push(callback())
      },
      register(options, render) {
        assert.equal(options.locale, 'guardrails-settings')
        if (options.name === 'plugins.row.config') {
          assert.equal(options.key, 'dsh-guardrails#guardrails')
          assert.equal(render({ view: 'page', form, t: String }).props.form, form)
        } else {
          assert.equal(options.name, 'conversation.composer')
          assert.equal(options.priority, -1)
        }
        return () => registrations.push('slot-disposed')
      },
    },
  }
  plugin.apply(ctx)
  assert.deepEqual(keys[0], keys[1])
  assert.deepEqual(registrations, ['zh', 'en'])
  while (disposers.length) disposers.pop()()
  assert.equal(disposers.length, 0)
})
