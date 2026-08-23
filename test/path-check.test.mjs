// Path-level rule unit tests for lib/path-check.js.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  baseNameOf,
  checkPath,
  entersGitDir,
  isSystemAreaPath,
  normCompare,
  resolvePath,
  segmentsOf,
} from '../lib/path-check.js'
import { evaluateRules } from '../lib/rules.js'

const RULES = evaluateRules({})
const BASE = 'E:/Project/DSH_Plugins'

test('resolvePath: absolute, relative, dot-dot folding, separators', () => {
  assert.equal(resolvePath(BASE, 'C:/abs/path'), 'C:/abs/path')
  assert.equal(resolvePath(BASE, 'C:\\abs\\path'), 'C:/abs/path') // backslash form
  assert.equal(resolvePath(BASE, '/abs/path'), '/abs/path')
  assert.equal(resolvePath(BASE, 'sub/file.txt'), 'E:/Project/DSH_Plugins/sub/file.txt')
  assert.equal(resolvePath(BASE, '../other'), 'E:/Project/other')
  assert.equal(resolvePath(BASE, './x/./y'), 'E:/Project/DSH_Plugins/x/y')
  assert.equal(resolvePath('', 'x'), 'x')
})

test('segmentsOf / baseNameOf / normCompare basics', () => {
  assert.deepEqual(segmentsOf('a/b/c'), ['a', 'b', 'c'])
  assert.deepEqual(segmentsOf('a\\b\\c'), ['a', 'b', 'c'])
  assert.deepEqual(segmentsOf('./a/'), ['a'])
  assert.equal(baseNameOf('a/b/c.txt'), 'c.txt')
  assert.equal(normCompare('A:\\B'), 'a:/b')
})

test('category predicates', () => {
  assert.equal(entersGitDir('E:/repo/.git/config'), true)
  assert.equal(entersGitDir('E:/repo/.gitignore'), false)
})

test('isSystemAreaPath: absolute prefixes, case/separator tolerant', () => {
  for (const p of [
    'C:/Windows',
    'C:/windows/system32/drivers/etc/hosts',
    'C:/Windows/System32/Tasks/x',
    'C:/Program Files/Common Files/x',
    'C:/Program Files (x86)/x',
    'C:/ProgramData/Microsoft/Certificate/x',
    'C:/Recovery/x',
  ]) {
    assert.equal(isSystemAreaPath(p), true, p)
  }
  assert.equal(isSystemAreaPath('C:/Windows.old/x'), false) // prefix, not substring
  assert.equal(isSystemAreaPath('D:/Windows/x'), false) // non-C drive is user data
  assert.equal(isSystemAreaPath('E:/repo/windows/x'), false)
  assert.equal(isSystemAreaPath('C:/Users/me/x'), false)
})

test('isSystemAreaPath: username-independent startup/profile combos', () => {
  assert.equal(isSystemAreaPath('C:/Users/me/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/x.ps1'), true)
  assert.equal(isSystemAreaPath('C:/Users/me/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1'), true)
  assert.equal(isSystemAreaPath('C:/Users/me/Documents/PowerShell/Microsoft.PowerShell_profile.ps1'), true)
  assert.equal(isSystemAreaPath('C:/Users/me/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Other/x.lnk'), false)
  assert.equal(isSystemAreaPath('E:/repo/docs/powershell/script.ps1'), false) // 'docs' is not the profile dir shape
  assert.equal(isSystemAreaPath('E:/repo/documents/powershell/x.ps1'), true) // combo is username-independent (accepted rare FP)
})

test('checkPath: env category, read vs modify, metadata mode', () => {
  assert.deepEqual(checkPath(BASE, '.env', false, false, RULES), { category: 'env', modifying: false, raw: '.env' })
  assert.deepEqual(checkPath(BASE, '.env', true, false, RULES), { category: 'env', modifying: true, raw: '.env' })
  assert.equal(checkPath(BASE, '.env.example', false, false, RULES), null)
  // listing (.env) is allowed: metadataOnly skips env
  assert.equal(checkPath(BASE, '.env', false, true, RULES), null)
})

test('checkPath: git category only in content mode', () => {
  assert.deepEqual(checkPath(BASE, '.git/config', false, false, RULES), { category: 'git', modifying: false, raw: '.git/config' })
  assert.equal(checkPath(BASE, '.git/config', false, true, RULES), null)
})

test('checkPath: .dsh paths are not intercepted (sessions rule removed)', () => {
  assert.equal(checkPath(BASE, '.dsh/sessions/x.jsonl', false, false, RULES), null)
  assert.equal(checkPath(BASE, '.dsh/sessions/x.jsonl', true, false, RULES), null)
  assert.equal(checkPath(BASE, '.dsh/sessions', false, true, RULES), null)
  assert.equal(checkPath(BASE, '.dsh/skills/SKILL.md', false, false, RULES), null)
})

test('checkPath: credentials category in every mode', () => {
  assert.deepEqual(checkPath(BASE, '.ssh/anything', false, false, RULES), { category: 'credentials', modifying: false, raw: '.ssh/anything' })
  assert.deepEqual(checkPath(BASE, '.ssh/**', false, true, RULES), { category: 'credentials', modifying: false, raw: '.ssh/**' })
  assert.equal(checkPath(BASE, '.dsh/skills/SKILL.md', false, false, RULES), null)
})

test('checkPath: range-B credential targets (hive files, browser/DPAPI paths)', () => {
  assert.equal(checkPath(BASE, 'C:/Users/me/.git-credentials', false, false, RULES)?.category, 'credentials')
  assert.equal(checkPath(BASE, 'C:/Users/me/ntuser.dat.LOG1', false, false, RULES)?.category, 'credentials')
  assert.equal(checkPath(BASE, 'C:/Windows/System32/config/SAM', false, false, RULES)?.category, 'credentials')
  assert.equal(checkPath(BASE, 'C:/Users/me/AppData/Local/Google/Chrome/User Data/Default/Cookies', false, false, RULES)?.category, 'credentials')
  assert.equal(checkPath(BASE, 'C:/Users/me/AppData/Local/Microsoft/Credentials/a', true, false, RULES)?.category, 'credentials')
  assert.equal(checkPath(BASE, 'C:/Users/me/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/cookies.sqlite', false, false, RULES)?.category, 'credentials')
})

test('checkPath: system category blocks writes only (W0)', () => {
  assert.deepEqual(checkPath(BASE, 'C:/Windows/System32/drivers/etc/hosts', true, false, RULES), { category: 'system', modifying: true, raw: 'C:/Windows/System32/drivers/etc/hosts' })
  assert.equal(checkPath(BASE, 'C:/Windows/System32/drivers/etc/hosts', false, false, RULES), null)
  assert.equal(checkPath(BASE, 'C:/Windows/**', false, true, RULES), null)
  assert.equal(checkPath(BASE, 'C:/Program Files (x86)/x', true, false, RULES)?.category, 'system')
  assert.equal(checkPath(BASE, 'C:/Users/me/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/x.ps1', true, false, RULES)?.category, 'system')
  assert.equal(checkPath(BASE, 'C:/Users/me/Documents/PowerShell/Microsoft.PowerShell_profile.ps1', true, false, RULES)?.category, 'system')
  assert.equal(checkPath(BASE, 'E:/repo/docs/powershell/x.ps1', true, false, RULES), null)
})

test('checkPath: system switch disables the check', () => {
  const off = evaluateRules({ system: false })
  assert.equal(checkPath(BASE, 'C:/Windows/x', true, false, off), null)
  assert.equal(checkPath(BASE, 'C:/Users/me/ntuser.dat', false, false, off)?.category, 'credentials') // credentials unaffected
})

test('checkPath: category switches disable checks', () => {
  const off = evaluateRules({ env: false })
  assert.equal(checkPath(BASE, '.env', false, false, off), null)
  assert.equal(checkPath(BASE, '.dsh/sessions/x', false, false, off), null)
  assert.deepEqual(checkPath(BASE, '.ssh/id_rsa', false, false, off), { category: 'credentials', modifying: false, raw: '.ssh/id_rsa' })
})

test('checkPath: empty or non-string raw is allowed', () => {
  assert.equal(checkPath(BASE, '', false, false, RULES), null)
  assert.equal(checkPath(BASE, undefined, false, false, RULES), null)
})
