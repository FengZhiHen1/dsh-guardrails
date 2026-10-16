// Config-page field specs: the parity guard between the browser page and the
// Host Config schema.
//
// Why this exists: the card declares — in the browser-only bundle — which
// fields it edits, and mirrors the Host's validation shape for the path list.
// Both facts are duplicated across the plane boundary (a browser bundle cannot
// import src/core/rules.js without pulling Node-only module code in), so they
// can drift silently:
//   - a field the page renders but the Host does not accept → the save is
//     refused at the Host, and the page shows only "保存未生效";
//   - a field the Host accepts but the page omits → it can never be edited
//     from the UI at all, which looks like "the setting does nothing".
// Neither is visible to the Host's own unit suite. This file closes the gap by
// evaluating the shipped bundle and comparing its declarations against the real
// `src/core/rules.js` and the real Config schema.
//
// It also pins the spec round-trip: the official form model decides "is this
// dirty?" by comparing draft text against formatted text, so a spec whose
// format()/parse() are not inverse would report phantom edits — or, worse,
// silently drop a real one.
//
// No browser, no network, no DSH process.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { RULE_KEYS, evaluateRules } from '../src/core/rules.js'
import { Config } from '../src/adapter/host.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const CARD = join(HERE, '..', 'src', 'client', 'card.js')
const SOURCE = readFileSync(CARD, 'utf8')

/**
 * Evaluate the shipped bundle and return the spec list the card hands to the
 * official form model. Captures the specs through a fake `SettingsFormModel`,
 * exactly as the real one receives them.
 */
function captureSpecs() {
  let registration
  new Function('window', `${SOURCE}\n;return window.__ModuleLoader__;`)({
    __ModuleLoader__: { load: (entry) => { registration = entry } },
  })
  assert.ok(registration, 'bundle did not call __ModuleLoader__.load')
  let specs
  const fakeModel = class {
    constructor(scope, list) { specs = list }
    shell() { return {} }
    field() { return { text: '', overridden: false, invalid: false } }
    bind() { return { getSnapshot: () => ({}), subscribe: () => () => {} } }
    actions() { return { edit() {}, resetField() {}, save() {}, discard() {} } }
    dispose() {}
  }
  const primitives = {
    SettingsFormModel: fakeModel,
    SettingsForm: 'SettingsForm',
    Checkbox: (props) => ({ type: 'Checkbox', props }),
    Tag: (props) => ({ type: 'Tag', props }),
  }
  const exported = registration.factory((name) => {
    if (name === 'react') return { createElement: () => ({}), useState: () => [undefined, () => {}], useEffect() {}, useRef: () => ({}) }
    if (name === '@deepseek-ai/dsh-client-ui-primitives') return primitives
    throw new Error(`unexpected require(${name})`)
  })
  exported.apply({
    configForms: {
      get: () => ({ getSnapshot: () => ({ status: 'ready', writable: true, value: {}, user: {} }), subscribe: () => () => {}, mutate: async () => true }),
      whileServed: (_ns, register) => register(new Set()),
    },
    slots: { inject: (_n, factory) => factory(), register: () => () => {} },
    effect: (fn) => fn(),
  })
  assert.ok(Array.isArray(specs), 'the card never constructed a SettingsFormModel with specs')
  return specs
}

const SPECS = captureSpecs()
const FIELDS = SPECS.map((spec) => spec.field)

test('the page edits exactly the two top-level Config keys (no more, no fewer)', () => {
  assert.deepEqual([...FIELDS].sort(), [...RULE_KEYS].sort(),
    'page fields must match RULE_KEYS from src/core/rules.js')
  // And the Host schema must have them all, volatile — a non-volatile field
  // never reaches a settings page and cannot be written.
  const dict = Config.dict
  for (const field of FIELDS) {
    assert.ok(dict[field] !== undefined, `Config has no field ${field}`)
  }
})

test('path-list spec round-trips (format ∘ parse is stable and marks stay exact)', () => {
  const spec = SPECS.find((s) => s.field === 'sensitiveFiles')
  assert.ok(spec, 'the page must expose a sensitiveFiles spec')
  // Round-trip: format → parse → format is the identity.
  for (const value of [[], ['E:/p/.env.production'], ['E:/a b/x.env', 'C:/y/z']]) {
    const text = spec.format(value)
    const write = spec.parse(text)
    assert.notEqual(write, undefined, `format(${JSON.stringify(value)}) → unparseable text ${JSON.stringify(text)}`)
    assert.equal(write.kind, 'set')
    assert.deepEqual(write.value, value.map((p) => p.trim()))
    assert.equal(spec.format(write.value), text, 'format/parse are not inverse')
  }
  // Blank lines and whitespace are tolerated input, normalized on parse.
  assert.deepEqual(spec.parse('  E:/a\n\nE:/b  \n').value, ['E:/a', 'E:/b'])
})

test('path-list spec refuses drafts the Host would refuse', () => {
  const spec = SPECS.find((s) => s.field === 'sensitiveFiles')
  // Relative paths and globs/wildcards are rejected HERE (invalid blocks the
  // save) rather than shipped to the Host as a guaranteed refusal. Note: a
  // bare absolute directory string is syntactically valid to the Host (it
  // cannot tell a directory from a file without fs access), so it is accepted
  // at the spec layer too — a marked directory simply never matches a file read.
  for (const bad of ['.env', 'src/**', 'E:/x/*.env', 'C:/y?', 'not-a-path']) {
    assert.equal(spec.parse(bad), undefined, `sensitiveFiles spec must reject ${JSON.stringify(bad)}`)
  }
  assert.notEqual(spec.parse('E:/some/absolute/path'), undefined,
    'an absolute path is syntactically valid; file-vs-directory is not statically knowable')
})

test('boolean spec round-trips and refuses non-boolean texts', () => {
  const spec = SPECS.find((s) => s.field === 'credentialsReadAsk')
  assert.ok(spec, 'the page must expose a credentialsReadAsk spec')
  for (const value of [true, false]) {
    const text = spec.format(value)
    const write = spec.parse(text)
    assert.equal(write.kind, 'set')
    assert.equal(write.value, value)
    assert.equal(spec.format(write.value), text)
  }
  for (const bad of ['yes', '1', 'on', '']) {
    assert.equal(spec.parse(bad), undefined, `credentialsReadAsk spec must reject ${JSON.stringify(bad)}`)
  }
  // The spec's acceptance mirrors the Host's evaluator.
  assert.deepEqual(
    evaluateRules({ credentialsReadAsk: spec.parse('false').value }).credentialsReadAsk,
    false,
  )
})
