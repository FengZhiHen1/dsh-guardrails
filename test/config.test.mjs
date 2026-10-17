// Official DSH config boundary: the plugin exports its Schemastery `Config`
// schema; the loader validates the row's config block and fills defaults
// BEFORE apply — a wrong config fails the mount with a ValidationError instead
// of being hand-checked inside apply. Unknown keys are rejected by
// evaluateRules (schema objects pass unknown keys through), so both layers are
// covered by the suites.
//
// Contract (knowledge `host/07` §2): every field carries `.volatile()`, so
// resolution returns a Volatile<T> REFERENCE rather than a plain value. The
// reference is what makes a field (a) writable through the settings page and
// (b) committed into the running fiber without a remount. These tests
// therefore assert both the values AND the volatility marker — a field that
// lost `.volatile()` would silently vanish from the settings page and throw on
// write.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Config } from '../index.js'
import { evaluateRules } from '../src/core/rules.js'

/** Unwrap the resolved config: volatile refs expose `.get()`, plain values pass through. */
const plain = (value) =>
  value !== null && typeof value === 'object' && typeof value.get === 'function' ? value.get() : value

/** Every field of a resolved config, unwrapped and keyed as the schema declares. */
const resolved = (input) =>
  Object.fromEntries(Object.entries(Config(input)).map(([key, value]) => [key, plain(value)]))

/** Top-level field names whose resolved value is a volatile reference. */
const volatileKeys = (input) =>
  Object.entries(Config(input)).filter(([, value]) => typeof value?.get === 'function').map(([key]) => key)

const ALL_FIELDS = ['sensitiveFiles', 'credentialsReadAsk', 'askTimeoutMs']

test('Config schema: empty config validates to all-defaults', () => {
  assert.deepEqual(resolved({}), {
    sensitiveFiles: [],
    credentialsReadAsk: true,
    askTimeoutMs: 120_000,
  })
})

test('Config schema: every top-level field is volatile (writable + live-committed)', () => {
  // The whole field set must be volatile: `volatileForm()` keeps only volatile
  // subtrees, so a non-volatile field never reaches the settings page, and a
  // write to it throws `Config field "x" is not volatile`.
  assert.deepEqual(volatileKeys({}).sort(), [...ALL_FIELDS].sort())
  // Still volatile when a non-default value is supplied (the marker rides the
  // schema, not the value that happens to resolve).
  assert.deepEqual(
    volatileKeys({ sensitiveFiles: ['E:/x'], credentialsReadAsk: false }).sort(),
    [...ALL_FIELDS].sort(),
  )
})

test('Config schema: resolved references expose get() and reflect the stored value', () => {
  const out = Config({ sensitiveFiles: ['E:/x/secret'] })
  assert.equal(typeof out.sensitiveFiles.get, 'function')
  assert.deepEqual(out.sensitiveFiles.get(), ['E:/x/secret'])
  // get() returns the same snapshot reference until the owning runtime replaces it.
  assert.equal(out.sensitiveFiles.get(), out.sensitiveFiles.get())
})

test('Config schema: invalid values fail validation (loader ValidationError)', () => {
  // Type-level errors are the schema's job (they fail the mount before apply).
  assert.throws(() => Config({ credentialsReadAsk: 'yes' }))
  assert.throws(() => Config({ sensitiveFiles: 'E:/x' }))
  assert.throws(() => Config({ sensitiveFiles: [42] }))
  // Semantic errors (relative paths, unknown keys) pass the schema by design
  // (schemastery objects do not prune/validate beyond the declared types) and
  // are rejected by evaluateRules at apply time — the mount fails loudly there.
  assert.doesNotThrow(() => Config({ sensitiveFiles: ['relative/path'] }))
  assert.throws(() => evaluateRules({ sensitiveFiles: ['relative/path'] }), /absolute file paths/)
  assert.throws(() => evaluateRules({ bogus: true }), /unknown config key/)
  // The timeout bound is type-checked by the schema and integer/bounds-checked
  // by the evaluator (schemastery allows a float; the evaluator does not).
  assert.throws(() => Config({ askTimeoutMs: -1 }))
  assert.doesNotThrow(() => Config({ askTimeoutMs: 1.5 }))
  assert.throws(() => evaluateRules({ askTimeoutMs: 1.5 }), /askTimeoutMs/)
  assert.throws(() => evaluateRules({ askTimeoutMs: 3_600_001 }), /askTimeoutMs/)
  assert.equal(evaluateRules({}).askTimeoutMs, 120_000)
  assert.equal(evaluateRules({ askTimeoutMs: 0 }).askTimeoutMs, 120_000,
    'legacy zero selects the bounded default')
  assert.equal(evaluateRules({ askTimeoutMs: 5000 }).askTimeoutMs, 5000)
})
