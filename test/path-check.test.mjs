// Path-level rule unit tests for src/core/path-check.js (V2 sensitive-read
// matching: builtin credential list + user-marked exact paths).

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  baseNameOf,
  checkSensitiveRead,
  isAbsolutePath,
  normCompare,
  resolvePath,
  segmentsOf,
  slash,
} from '../src/core/path-check.js'
import { evaluateRules } from '../src/core/rules.js'

const RULES = evaluateRules({})
const MARKED = evaluateRules({
  sensitiveFiles: ['E:/Project/app/.env.production', 'C:/Users/me/.kube/config'],
})
const BASE = 'E:/Project/DSH_Plugins'

test('resolvePath: absolute, relative, dot-dot folding, separators', () => {
  assert.equal(resolvePath(BASE, 'C:/abs/path'), 'C:/abs/path')
  assert.equal(resolvePath(BASE, 'C:\\abs\\path'), 'C:/abs/path') // backslash form
  assert.equal(resolvePath(BASE, '/abs/path'), '/abs/path')
  assert.equal(resolvePath(BASE, 'sub/file.txt'), 'E:/Project/DSH_Plugins/sub/file.txt')
  assert.equal(resolvePath(BASE, '../other'), 'E:/Project/other')
  assert.equal(resolvePath(BASE, './x/./y'), 'E:/Project/DSH_Plugins/x/y')
  assert.equal(resolvePath('', 'x'), 'x')
  assert.equal(resolvePath('/workspace/app', '../secret'), '/workspace/secret')
  assert.equal(resolvePath('/workspace', '/a/../b'), '/b')
})

test('segmentsOf / baseNameOf / normCompare / slash basics', () => {
  assert.deepEqual(segmentsOf('a/b/c'), ['a', 'b', 'c'])
  assert.deepEqual(segmentsOf('a\\b\\c'), ['a', 'b', 'c'])
  assert.deepEqual(segmentsOf('./a/'), ['a'])
  assert.equal(baseNameOf('a/b/c.txt'), 'c.txt')
  assert.equal(normCompare('A:\\B'), 'a:/b')
  assert.equal(slash('a\\b'), 'a/b')
  assert.equal(isAbsolutePath('C:/x'), true)
  assert.equal(isAbsolutePath('/x'), true)
  assert.equal(isAbsolutePath('x/y'), false)
})

test('POSIX comparisons preserve case and credential combos require the exact file', () => {
  const rules = evaluateRules({ sensitiveFiles: ['/workspace/Secret'] })
  assert.equal(checkSensitiveRead('/workspace/Secret', rules), 'marked')
  assert.equal(checkSensitiveRead('/workspace/secret', rules), null)
  assert.equal(checkSensitiveRead('/home/me/.SSH/ID_RSA', rules), null)
  assert.equal(checkSensitiveRead('/home/me/.aws/credentials/other', rules), null)
})

test('checkSensitiveRead: builtin credential hits', () => {
  assert.equal(checkSensitiveRead(resolvePath(BASE, 'C:/Users/me/.ssh/id_rsa'), RULES), 'credentials')
  assert.equal(checkSensitiveRead(resolvePath(BASE, 'C:/Users/me/.npmrc'), RULES), 'credentials')
  assert.equal(checkSensitiveRead(resolvePath(BASE, 'C:/Users/me/.aws/credentials'), RULES), 'credentials')
})

test('checkSensitiveRead: user-marked exact paths (case-insensitive, separator-insensitive)', () => {
  assert.equal(
    checkSensitiveRead(resolvePath('E:/Project/app', '.env.production'), MARKED),
    'marked',
  )
  assert.equal(checkSensitiveRead('e:/project/app/.env.production', MARKED), 'marked')
  assert.equal(checkSensitiveRead('E:\\Project\\app\\.env.production', MARKED), 'marked')
  assert.equal(checkSensitiveRead('c:/users/ME/.KUBE/config', MARKED), 'marked')
  // A sibling or subpath is NOT the marked file.
  assert.equal(checkSensitiveRead('E:/Project/app/.env', MARKED), null)
  assert.equal(checkSensitiveRead('E:/Project/app/.env.production.bak', MARKED), null)
  assert.equal(checkSensitiveRead('E:/Project/app/sub/.env.production', MARKED), null)
})

test('checkSensitiveRead: ordinary files and unmarked .env stay free', () => {
  assert.equal(checkSensitiveRead(resolvePath(BASE, 'src/core/rules.js'), RULES), null)
  assert.equal(checkSensitiveRead(resolvePath(BASE, '.env'), RULES), null, 'plain .env is Auto-Review territory')
  assert.equal(checkSensitiveRead(resolvePath(BASE, '.env.example'), RULES), null)
  assert.equal(checkSensitiveRead(resolvePath(BASE, '.git/config'), RULES), null)
  assert.equal(checkSensitiveRead(resolvePath(BASE, 'C:/Windows/System32/drivers/etc/hosts'), RULES), null)
})

test('checkSensitiveRead: builtin toggle off removes only the builtin channel', () => {
  const off = { ...RULES, builtinSensitiveAsk: false }
  assert.equal(checkSensitiveRead('C:/Users/me/.ssh/id_rsa', off), null)
  assert.equal(checkSensitiveRead('E:/Project/app/.env.production', { ...off, sensitiveFiles: MARKED.sensitiveFiles }), 'marked')
})

test('checkSensitiveRead: marked beats nothing but credentials wins ties', () => {
  // A marked file that also matches the builtin list reports 'credentials'.
  const both = evaluateRules({ sensitiveFiles: ['C:/Users/me/.ssh/id_rsa'] })
  assert.equal(checkSensitiveRead('C:/Users/me/.ssh/id_rsa', both), 'credentials')
})
