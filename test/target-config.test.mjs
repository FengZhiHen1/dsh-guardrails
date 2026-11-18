import assert from 'node:assert/strict'
import test from 'node:test'
import { Config } from '../index.js'
import { normalizePolicy } from '../src/core/decision.js'

function effective(raw) {
  const parsed = Config(raw)
  return normalizePolicy(Object.fromEntries(Object.entries(parsed).map(([key, value]) =>
    [key, typeof value?.get === 'function' ? value.get() : value])))
}

test('invalid input falls back to protective defaults without making the bundle fail to load', () => {
  const config = effective({ sensitiveFiles: 'not a list', builtinSensitiveAsk: 0, askTimeoutMs: -1, tightenOnly: false })
  assert.deepEqual(config.sensitiveFiles, [])
  assert.equal(config.builtinSensitiveAsk, true)
  assert.equal(config.askTimeoutMs, 120_000)
  // An explicit false cannot relax protected items; the exported boundary keeps true.
  assert.equal(config.tightenOnly, true)
})

test('a valid custom file and short confirmation time pass the exported Config boundary', () => {
  const config = effective({ sensitiveFiles: ['/home/fixture/protected.txt'], askTimeoutMs: 250 })
  assert.deepEqual(config.sensitiveFiles, ['/home/fixture/protected.txt'])
  assert.equal(config.askTimeoutMs, 250)
})
