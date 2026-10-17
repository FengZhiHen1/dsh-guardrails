// The official generated settings page consumes the Host schema directly.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Config } from '../src/adapter/host.js'
import { RULE_KEYS, evaluateRules, ASK_TIMEOUT_MAX } from '../src/core/rules.js'

const plain = input => Object.fromEntries(Object.entries(Config(input)).map(([key, value]) => [key, value.get()]))

test('generated settings exposes exactly the policy keys as volatile schema fields', () => {
  assert.deepEqual(Object.keys(Config.dict).sort(), [...RULE_KEYS].sort())
  const resolved = Config({})
  for (const key of RULE_KEYS) assert.equal(typeof resolved[key].get, 'function', key)
})

test('generated path-list values retain exact files including spaces and empty lists', () => {
  for (const value of [[], ['E:/synthetic/marked.txt'], ['E:/synthetic directory/a.txt', 'C:/synthetic/b.txt']]) {
    const resolved = plain({ sensitiveFiles: value })
    assert.deepEqual(resolved.sensitiveFiles, value)
    assert.deepEqual(evaluateRules(resolved).sensitiveFiles, value)
  }
})

test('generated boolean values remain booleans and reject text drafts at schema boundary', () => {
  for (const value of [true, false]) assert.equal(plain({ credentialsReadAsk: value }).credentialsReadAsk, value)
  for (const value of ['yes', 'true', '1', 1]) assert.throws(() => Config({ credentialsReadAsk: value }))
  assert.equal(plain({ credentialsReadAsk: null }).credentialsReadAsk, true, 'schema treats null as the default')
})

test('schema and runtime jointly reject invalid marked-file settings', () => {
  for (const sensitiveFiles of ['E:/synthetic/a', [42]]) assert.throws(() => Config({ sensitiveFiles }))
  for (const sensitiveFiles of [[null], ['relative/file'], ['E:/synthetic/*.txt'], ['C:/synthetic/?'], ['']]) {
    assert.throws(() => evaluateRules(plain({ sensitiveFiles })), /sensitiveFiles/)
  }
})

test('generated timeout field preserves bounded values and migrates legacy zero at runtime', () => {
  assert.equal(plain({}).askTimeoutMs, 120000)
  for (const value of [0, 1000, ASK_TIMEOUT_MAX]) {
    const config = plain({ askTimeoutMs: value })
    assert.equal(config.askTimeoutMs, value)
    assert.equal(evaluateRules(config).askTimeoutMs, value || 120000)
  }
  for (const value of [-1, ASK_TIMEOUT_MAX + 1, '3000']) assert.throws(() => Config({ askTimeoutMs: value }))
  assert.throws(() => evaluateRules(plain({ askTimeoutMs: 1.5 })), /askTimeoutMs/)
})
