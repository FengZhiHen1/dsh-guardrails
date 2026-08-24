// Official DSH config boundary: the plugin exports its Schemastery `Config`
// schema; the loader validates the row's config block and fills defaults
// BEFORE apply (cordis-tutorial §5) — a wrong config fails the mount with a
// ValidationError instead of being hand-checked inside apply. Unknown keys /
// unknown sub-keys are rejected by evaluateRules (schema objects pass unknown
// keys through), so both layers are covered by the suites.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Config } from '../index.js'

test('Config schema: empty config validates to all-defaults (boolean form)', () => {
  assert.deepEqual(Config({}), {
    env: true,
    git: true,
    credentials: true,
    system: true,
    destructive: true,
    unverifiable: true,
  })
})

test('Config schema: object form fills missing leaves with true', () => {
  const out = Config({ env: { read: false }, destructive: { cli: false } })
  assert.deepEqual(out.env, { read: false, modify: true })
  assert.deepEqual(out.destructive, {
    git: true, machine: true, eval: true, cli: false, bulk: true, target: true,
  })
  assert.equal(out.unverifiable, true)
  assert.equal(out.credentials, true) // untouched categories stay boolean
})

test('Config schema: invalid values fail validation (loader ValidationError)', () => {
  assert.throws(() => Config({ env: 'no' }))
  assert.throws(() => Config({ env: { read: 'false' } }))
  assert.throws(() => Config({ credentials: [] }))
  assert.throws(() => Config({ destructive: { cli: 1 } }))
  assert.throws(() => Config({ unverifiable: 'yes' }))
})
