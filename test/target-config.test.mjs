import assert from 'node:assert/strict'
import test from 'node:test'
import { Config } from '../index.js'
import { createConfigIssueWarner } from '../src/adapter/host.js'
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

test('config issue warnings print deduplicated codes once and never the raw values', () => {
  const warnings = []
  const warn = createConfigIssueWarner({ warn: (...args) => warnings.push(args.join(' ')) })
  const policy = {
    configIssues: [
      { code: 'unknown-config-key', detail: 'secret-value', count: 1 },
      { code: 'always-ask-invalid', count: 1 },
    ],
  }
  warn(policy)
  warn(policy)
  warn({ configIssues: policy.configIssues.map((issue) => ({ ...issue })) })
  assert.equal(warnings.length, 1, 'the same code signature warns exactly once')
  assert.match(warnings[0], /always-ask-invalid/)
  assert.match(warnings[0], /unknown-config-key/)
  assert.doesNotMatch(warnings[0], /secret-value/, 'raw config values never reach the log')

  warn({ configIssues: [{ code: 'ask-timeout-invalid', count: 1 }] })
  assert.equal(warnings.length, 2, 'a changed signature warns again')

  warn({ configIssues: [] })
  warn(policy)
  assert.equal(warnings.length, 3, 'an empty set resets the signature so a later recurrence warns')
})
