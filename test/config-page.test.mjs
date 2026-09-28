// Config-page field specs: the parity guard between the browser page and the
// Host Config schema (DSR-011).
//
// Why this exists: the card declares — in the browser-only bundle — which
// fields it edits, and mirrors CATEGORY_LEAF_KEYS so each category's toggle
// grid matches the leaves the Host accepts. Both facts are duplicated across
// the plane boundary (a browser bundle cannot import src/core/rules.js without
// pulling Node-only module code in), so they can drift silently:
//   - a leaf the page renders but the Host does not accept → the save is
//     refused at the Host, and the page shows only "保存未生效";
//   - a leaf the Host accepts but the page omits → that operation can never be
//     toggled from the UI at all, which looks like "the setting does nothing".
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
import { CATEGORY_LEAF_KEYS, RULE_KEYS, evaluateRules } from '../src/core/rules.js'
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

test('the page edits exactly the six top-level Config keys (no more, no fewer)', () => {
  assert.deepEqual([...FIELDS].sort(), [...RULE_KEYS].sort(),
    'page fields must match RULE_KEYS from src/core/rules.js')
  // And the Host schema must have them all, volatile — a non-volatile field
  // never reaches a settings page and cannot be written.
  const dict = Config.dict
  for (const field of FIELDS) {
    assert.ok(dict[field] !== undefined, `Config has no field ${field}`)
  }
})

test('every category leaf the page renders is one the Host accepts', () => {
  // The card's own CATEGORIES is closure-scoped (deliberately not exported), but
  // its SPECS expose the same fact through behavior: `parse` accepts exactly the
  // declared keys, so probing one candidate key at a time recovers the set.
  // This is drift of the silent kind — an extra leaf makes every save fail, a
  // missing one makes an operation untoggleable from the UI.
  const spec = (field) => SPECS.find((s) => s.field === field)
  const allCandidateKeys = [...new Set(Object.values(CATEGORY_LEAF_KEYS).flat())]
  const observed = {}
  for (const cat of Object.keys(CATEGORY_LEAF_KEYS)) {
    observed[cat] = allCandidateKeys.filter((key) => spec(cat).parse(JSON.stringify({ [key]: true })) !== undefined)
  }
  assert.deepEqual(Object.keys(observed).sort(), Object.keys(CATEGORY_LEAF_KEYS).sort(),
    'category names must match the Host rule model')
  for (const [cat, keys] of Object.entries(CATEGORY_LEAF_KEYS)) {
    assert.deepEqual([...observed[cat]].sort(), [...keys].sort(),
      `category "${cat}" leaves drifted from src/core/rules.js`)
  }
})

test('category spec round-trips every accepted shape (format ∘ parse is stable)', () => {
  const spec = (field) => SPECS.find((s) => s.field === field)
  const roundTrip = (field, value) => {
    const text = spec(field).format(value)
    const write = spec(field).parse(text)
    assert.notEqual(write, undefined, `${field}: format(${JSON.stringify(value)}) → unparseable text ${JSON.stringify(text)}`)
    assert.equal(write.kind, 'set', `${field}: a boolean/leaf value must write, not clear`)
    // Re-formatting the parsed value must reproduce the same text, or the form
    // model reports a phantom dirty state.
    assert.equal(spec(field).format(write.value), text, `${field}: format/parse are not inverse for ${JSON.stringify(value)}`)
    return write.value
  }
  /**
   * Compare through the HOST's own normalizer, not by shape. A uniform leaf set
   * deliberately collapses to the boolean form (that is the v1-compatible
   * canonicalization, and for a single-leaf category like `system` it is the
   * only sensible storage) — so equality of intent, not of JSON shape, is what
   * the page must preserve.
   */
  const sameRules = (field, a, b) => assert.deepEqual(
    evaluateRules({ [field]: a })[field],
    evaluateRules({ [field]: b })[field],
    `${field}: ${JSON.stringify(a)} and ${JSON.stringify(b)} must judge identically`,
  )
  for (const cat of Object.keys(CATEGORY_LEAF_KEYS)) {
    assert.equal(roundTrip(cat, undefined), true, `${cat}: absent ⇒ all on ⇒ written as true`)
    assert.equal(roundTrip(cat, true), true)
    assert.equal(roundTrip(cat, false), false)
    const leaves = Object.fromEntries(CATEGORY_LEAF_KEYS[cat].map((k, i) => [k, i % 2 === 0]))
    const parsed = roundTrip(cat, leaves)
    // Whatever shape comes back, it must judge the same as the mixed leaf set.
    sameRules(cat, parsed, leaves)
    // A mixed set can never collapse to a bare boolean.
    if (new Set(Object.values(leaves)).size > 1) {
      assert.equal(typeof parsed, 'object', `${cat}: a mixed leaf set must stay an object`)
      assert.deepEqual(Object.keys(parsed).sort(), [...CATEGORY_LEAF_KEYS[cat]].sort())
    }
  }
  assert.equal(roundTrip('unverifiable', true), true)
  assert.equal(roundTrip('unverifiable', false), false)
})

test('category spec refuses drafts the Host would refuse', () => {
  const spec = SPECS.find((s) => s.field === 'env')
  // Unknown leaf, non-boolean leaf, a bare boolean-like string, and JSON that is
  // not an object all have to be rejected HERE (invalid blocks the save) rather
  // than shipped to the Host as a guaranteed refusal.
  for (const bad of ['nonsense', '{"nope":true}', '{"read":"yes"}', '["read"]', '1', '']) {
    assert.equal(spec.parse(bad), undefined, `env spec must reject ${JSON.stringify(bad)}`)
  }
  // An all-on/all-off leaf object normalizes to the boolean form, so a grid that
  // happens to end uniform stores the same value a v1 boolean row would.
  assert.deepEqual(spec.parse('{"read":true,"modify":true}'), { kind: 'set', value: true })
  assert.deepEqual(spec.parse('{"read":false,"modify":false}'), { kind: 'set', value: false })
  assert.deepEqual(spec.parse('{"read":false,"modify":true}'), { kind: 'set', value: { read: false, modify: true } })
})

/**
 * The card's leaf spec must also be TOTAL: a candidate key that is not declared
 * must be refused, which is what the probing loop above relies on. This pins
 * that assumption so the parity test above cannot pass vacuously.
 */
test('a category spec refuses keys outside its own declaration', () => {
  const spec = SPECS.find((s) => s.field === 'system') // system declares exactly ['write']
  assert.deepEqual(spec.parse('{"write":false}'), { kind: 'set', value: false })
  assert.equal(spec.parse('{"read":false}'), undefined, 'system must not accept the env leaf "read"')
  assert.equal(spec.parse('{"write":false,"extra":true}'), undefined, 'unknown keys must be refused')
})
