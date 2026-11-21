// The browser entry is loaded in a VM; no browser, profile write or shell dispatch occurs.
import test from 'node:test'
import assert from 'node:assert/strict'
import vm from 'node:vm'
import { readFile } from 'node:fs/promises'

const source = await readFile(new URL('../src/client/settings.js', import.meta.url), 'utf8')
const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))
let plugin
vm.runInNewContext(source, { window: { __ModuleLoader__: { load(entry) {
  plugin = entry.factory(name => {
    assert.equal(name, 'react')
    return { createElement(type, props, ...children) { return { type, props: props ?? {}, children } } }
  })
} } } })

const display = {
  question: { en: 'Allow this guarded operation once?', zh: '是否允许本次受保护操作？（仅本次）' },
  detail: { en: 'Read the protected file', zh: '读取受保护文件' },
  approve: { en: 'Allow once', zh: '允许一次' },
}
const questionItem = () => ({
  id: 'guardrails-confirm',
  question: 'Allow this guarded operation once?',
  detail: 'Read the protected file',
  options: [{ label: 'Allow once' }, { label: 'Reject' }],
  intent: { kind: 'approval', approve: 'Allow once', reject: 'Reject', display },
})
function pendingQuestion(overrides = {}) {
  const answers = []
  const value = {
    kind: 'question',
    key: 'question:1',
    questions: [questionItem()],
    answer: async answer => { answers.push(answer) },
    snapshot: () => ({ channel: 'waterfall', closed: false }),
    ...overrides,
  }
  return { value, answers }
}
// Apply against a synthetic context so the assertions exercise the real registration.
function mount() {
  const entries = []
  plugin.apply({
    effect(callback) { callback() },
    locale: {
      register() { return () => {} },
      resolveText: text => text.zh,
    },
    slots: {
      inject(name, callback) { callback() },
      register(options, render) { entries.push({ options, render }) },
    },
  })
  const entry = entries.find(candidate => candidate.options.name === 'conversation.composer')
  assert.ok(entry, 'composer registration is missing')
  return entry
}
function mountShared() {
  const entry = mount()
  const calls = []
  const render = (matched, extra = {}) => entry.render({
    matched,
    resolveText: entry.options.inject().resolveText,
    renderFactorySlot: (name, props, options) => { calls.push({ name, props, options }); return { type: 'approval-card', props, options } },
    t: key => `t:${key}`,
    ...extra,
  })
  return { entry, calls, render }
}
const nodes = (node, found = []) => {
  if (node === null || typeof node !== 'object') return found
  found.push(node)
  for (const child of node.children ?? []) nodes(child, found)
  return found
}
const buttons = element => nodes(element).filter(node => node.type === 'button')
// Answer batches are created inside the VM realm; compare their data, not their prototypes.
const plain = value => JSON.parse(JSON.stringify(value))

test('selector narrows only the guardrails approval question', () => {
  const { value } = pendingQuestion()
  const matched = plugin.selectGuardrailsApproval(value)
  assert.equal(matched.pending, value)
  assert.equal(matched.item, value.questions[0])
  assert.equal(matched.intent, value.questions[0].intent)
  const rejected = [
    undefined,
    { kind: 'approval' },
    { kind: 'question' },
    { kind: 'question', questions: [] },
    { kind: 'question', questions: [questionItem(), questionItem()] },
    { kind: 'question', questions: [{ ...questionItem(), id: 'cua-app-access' }] },
    { kind: 'question', questions: [{ ...questionItem(), intent: { kind: 'plan-review', approve: 'Allow once' } }] },
    { kind: 'question', questions: [{ ...questionItem(), intent: undefined }] },
  ]
  for (const candidate of rejected) assert.equal(plugin.selectGuardrailsApproval(candidate), null)
})

test('approval renders the shared decision card with localized copy and original labels', async () => {
  const { entry, calls, render } = mountShared()
  const { value, answers } = pendingQuestion()
  const matched = entry.options.select({ pendingInteraction: value })
  const element = render(matched)
  assert.equal(calls.length, 1)
  assert.equal(calls[0].name, 'conversation.approval.card')
  // The framework always injects the factory, so the miss must render our card, not a blank slot.
  assert.ok(calls[0].options, 'renderFactorySlot must receive the fallback options')
  assert.equal(buttons(calls[0].options.fallback).length, 2)
  const props = calls[0].props
  assert.equal(props.requestKey, 'question:1')
  assert.equal(props.title, display.question.zh)
  assert.equal(props.description, display.detail.zh)
  assert.equal(props.allowLabel, display.approve.zh)
  assert.equal(props.canAnswer(), true)
  assert.equal(element.type, 'approval-card')
  await props.onAllow()
  await props.onReject()
  assert.deepEqual(plain(answers), [
    { answers: [{ id: 'guardrails-confirm', selected: ['Allow once'] }] },
    { answers: [{ id: 'guardrails-confirm', selected: ['Reject'] }] },
  ])
})

test('approval refuses answers once the pending channel closes or disappears', () => {
  const { entry, calls, render } = mountShared()
  for (const snapshot of [() => ({ channel: 'none', closed: false }), () => ({ channel: 'waterfall', closed: true }), undefined]) {
    const { value } = pendingQuestion({ snapshot })
    render(entry.options.select({ pendingInteraction: value }))
    assert.equal(calls.at(-1).props.canAnswer(), false)
  }
})

test('approval falls back to a native card with the bilingual action labels', async () => {
  const entry = mount()
  const t = key => ({ approvalAllow: '允许一次', approvalReject: '拒绝' })[key]
  const { value, answers } = pendingQuestion()
  const element = entry.render({
    matched: entry.options.select({ pendingInteraction: value }),
    resolveText: entry.options.inject().resolveText,
    t,
  })
  assert.ok(element)
  const actions = buttons(element)
  assert.equal(actions.length, 2)
  assert.deepEqual(actions.map(button => button.children[0]), ['拒绝', '允许一次'])
  assert.equal(actions.some(button => button.props.disabled), false)
  assert.match(nodes(element).find(node => node.type === 'p' && node.props.className === 'gr-approval-title').children[0], /是否允许本次受保护操作/)
  await actions[0].props.onClick()
  await actions[1].props.onClick()
  assert.deepEqual(plain(answers), [
    { answers: [{ id: 'guardrails-confirm', selected: ['Reject'] }] },
    { answers: [{ id: 'guardrails-confirm', selected: ['Allow once'] }] },
  ])
})

test('fallback actions stay disabled without an answer channel', () => {
  const entry = mount()
  const { value } = pendingQuestion({ snapshot: undefined })
  const element = entry.render({ matched: entry.options.select({ pendingInteraction: value }), t: String })
  const actions = buttons(element)
  assert.equal(actions.length, 2)
  assert.deepEqual(actions.map(button => button.props.disabled), [true, true])
})

test('fallback labels use the original option text when the locale seat returns nothing', () => {
  const entry = mount()
  const { value } = pendingQuestion()
  const element = entry.render({ matched: entry.options.select({ pendingInteraction: value }), t: () => undefined })
  assert.deepEqual(buttons(element).map(button => button.children[0]), ['Reject', 'Allow once'])
})

test('a closed-channel rejection never escapes as an unhandled rejection', async () => {
  const entry = mount()
  const { value } = pendingQuestion({ answer: () => Promise.reject(new Error('channel closed')) })
  const element = entry.render({ matched: entry.options.select({ pendingInteraction: value }), resolveText: entry.options.inject().resolveText, t: String })
  const seen = []
  const onRejection = reason => seen.push(reason)
  process.on('unhandledRejection', onRejection)
  try {
    await buttons(element)[0].props.onClick()
    await new Promise(resolve => setImmediate(resolve))
    assert.deepEqual(seen, [])
  } finally {
    process.off('unhandledRejection', onRejection)
  }
})

test('a synchronous answer failure is swallowed and both actions stay clickable', () => {
  const entry = mount()
  const { value } = pendingQuestion({ answer: () => { throw new Error('already settled') } })
  const element = entry.render({ matched: entry.options.select({ pendingInteraction: value }), resolveText: entry.options.inject().resolveText, t: String })
  const actions = buttons(element)
  assert.doesNotThrow(() => actions[0].props.onClick())
  assert.doesNotThrow(() => actions[1].props.onClick())
})

test('the client half never requires a Harness Client package and keeps token-only styles', () => {
  assert.doesNotMatch(source, /require\('@deepseek-ai\//)
  assert.doesNotMatch(source, /from '@deepseek-ai\//)
  assert.doesNotMatch(source, /#[0-9a-fA-F]{3,8}\b/)
  assert.doesNotMatch(source, /(?:rgba?|hsla?)\(/)
  // The shared factory renders the supplied fallback when the card factory is absent.
  assert.match(source, /'conversation\.approval\.card', \{[\s\S]*?\}, \{ fallback: renderMinimalCard\(\) \}\)/)
  assert.match(source, /return renderMinimalCard\(\)/)
  assert.match(source, /settled\.catch\(\(\) => \{\}\)/)
})

test('the client activation order covers the shared approval card providers', () => {
  assert.deepEqual(manifest.dsh.client.inject, [
    '@deepseek-ai/dsh-client-ui-plugin-manager',
    '@deepseek-ai/dsh-client-locale',
    '@deepseek-ai/dsh-client-ui-user-questions',
    '@deepseek-ai/dsh-client-ui-approval',
    '@deepseek-ai/dsh-client-ui-conversation',
  ])
})
