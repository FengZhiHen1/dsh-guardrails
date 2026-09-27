// Official DSH config boundary: the plugin exports its Schemastery `Config`
// schema; the loader validates the row's config block and fills defaults
// BEFORE apply (cordis-tutorial §5) — a wrong config fails the mount with a
// ValidationError instead of being hand-checked inside apply. Unknown keys /
// unknown sub-keys are rejected by evaluateRules (schema objects pass unknown
// keys through), so both layers are covered by the suites.
//
// v0.1.7 contract (knowledge `host/07` §2): every field carries `.volatile()`,
// so resolution returns a Volatile<T> REFERENCE rather than a plain value. The
// reference is what makes a field (a) writable through the settings page and
// (b) committed into the running fiber without a remount. These tests therefore
// assert both the values AND the volatility marker — a field that lost
// `.volatile()` would silently vanish from the settings page and throw on write.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Config } from '../index.js'

/** Unwrap the resolved config: volatile refs expose `.get()`, plain values pass through. */
const plain = (value) =>
  value !== null && typeof value === 'object' && typeof value.get === 'function' ? value.get() : value

/** Every field of a resolved config, unwrapped and keyed as the schema declares. */
const resolved = (input) =>
  Object.fromEntries(Object.entries(Config(input)).map(([key, value]) => [key, plain(value)]))

/** Top-level field names whose resolved value is a volatile reference. */
const volatileKeys = (input) =>
  Object.entries(Config(input)).filter(([, value]) => typeof value?.get === 'function').map(([key]) => key)

const ALL_FIELDS = ['env', 'git', 'credentials', 'system', 'destructive', 'unverifiable']

test('Config schema: empty config validates to all-defaults (boolean form)', () => {
  assert.deepEqual(resolved({}), {
    env: true,
    git: true,
    credentials: true,
    system: true,
    destructive: true,
    unverifiable: true,
  })
})

test('Config schema: object form fills missing leaves with true', () => {
  const out = resolved({ env: { read: false }, destructive: { cli: false } })
  assert.deepEqual(out.env, { read: false, modify: true })
  assert.deepEqual(out.destructive, {
    git: true, machine: true, eval: true, cli: false, bulk: true, target: true, chain: true, misuse: true,
  })
  assert.equal(out.unverifiable, true)
  assert.equal(out.credentials, true) // untouched categories stay boolean
})

test('Config schema: every top-level field is volatile (writable + live-committed)', () => {
  // The whole field set must be volatile: `volatileForm()` keeps only volatile
  // subtrees, so a non-volatile field never reaches the settings page, and a
  // write to it throws `Config field "x" is not volatile`.
  assert.deepEqual(volatileKeys({}).sort(), [...ALL_FIELDS].sort())
  // Still volatile when a non-default value is supplied (the marker rides the
  // schema, not the value that happens to resolve).
  assert.deepEqual(volatileKeys({ env: false, unverifiable: false }).sort(), [...ALL_FIELDS].sort())
})

test('Config schema: resolved references expose get() and reflect the stored value', () => {
  const out = Config({ env: { read: false } })
  assert.equal(typeof out.env.get, 'function')
  assert.deepEqual(out.env.get(), { read: false, modify: true })
  // get() returns the same snapshot reference until the owning runtime replaces it.
  assert.equal(out.env.get(), out.env.get())
})

test('Config schema: invalid values fail validation (loader ValidationError)', () => {
  assert.throws(() => Config({ env: 'no' }))
  assert.throws(() => Config({ env: { read: 'false' } }))
  assert.throws(() => Config({ credentials: [] }))
  assert.throws(() => Config({ destructive: { cli: 1 } }))
  assert.throws(() => Config({ unverifiable: 'yes' }))
})
