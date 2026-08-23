// Command-text unit tests for lib/command.js: lexing, fragment unwrapping,
// listing-mode detection, and content-sensitive reference detection.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  applyCwdCommand,
  assessContentClass,
  assessSystemWrite,
  classifyVerb,
  detectContentSensitiveRef,
  isListingOnly,
  tokenizePwsh,
  unwrapFragment,
} from '../lib/command.js'
import { LISTING_SAMPLES, NON_LISTING_SAMPLES } from './fixtures/command-samples.mjs'

test('tokenizePwsh: words, quotes, backticks, separators, subexpressions', () => {
  const { tokens, nested } = tokenizePwsh('Get-Content "a b" \'c`d\' $var; echo $(Get-Content .env) | cat')
  const words = tokens.filter((t) => t.kind === 'word').map((t) => t.value)
  // Backtick inside single quotes is treated as an escape (existing lexer
  // approximation; preserved as-is by the refactor).
  assert.deepEqual(words, ['Get-Content', 'a b', 'cd', '$var', 'echo', '$(x)', 'cat'])
  assert.deepEqual(nested, ['Get-Content .env'])
  const seps = tokens.filter((t) => t.kind === 'sep').map((t) => t.value)
  assert.deepEqual(seps, [';', '|'])
})

test('tokenizePwsh: && and || merge into one separator', () => {
  const { tokens } = tokenizePwsh('a && b || c')
  assert.deepEqual(tokens.filter((t) => t.kind === 'sep').map((t) => t.value), ['&', '|'])
})

test('unwrapFragment: skips $var / & / . prefixes, normalizes dashes', () => {
  assert.deepEqual(unwrapFragment(['$x', 'Get-ChildItem', '.dsh']), { cmd: 'getchilditem', args: ['.dsh'] })
  assert.deepEqual(unwrapFragment(['&', 'Remove-Item', 'x']), { cmd: 'removeitem', args: ['x'] })
  assert.equal(unwrapFragment(['$x']), undefined)
})

test('isListingOnly: pure metadata commands are listing', () => {
  for (const cmd of LISTING_SAMPLES) {
    assert.equal(isListingOnly(cmd), true, cmd)
  }
})

test('isListingOnly: content, redirect, subexpression, mixed, unknown break listing', () => {
  for (const cmd of NON_LISTING_SAMPLES) {
    assert.equal(isListingOnly(cmd), false, cmd)
  }
})

test('detectContentSensitiveRef: env → git order, null otherwise', () => {
  assert.equal(detectContentSensitiveRef('Get-Content .env'), 'env')
  // Safe suffix: text-level match is filtered by isSensitiveEnvName upstream
  assert.equal(detectContentSensitiveRef('Get-Content .env.example'), null)
  assert.equal(detectContentSensitiveRef('cat .git/config'), 'git')
  assert.equal(detectContentSensitiveRef('Get-Content .dsh/sessions/x'), null) // .dsh has no rule
  assert.equal(detectContentSensitiveRef('Get-ChildItem .ssh'), null) // credentials not here
  assert.equal(detectContentSensitiveRef('git status'), null)
  assert.equal(detectContentSensitiveRef('Get-ChildItem .dsh'), null)
})

const SYS_BASE = 'E:/Project/DSH_Plugins'

test('applyCwdCommand: cd tracking matches destructive-analysis semantics', () => {
  let state = { dir: SYS_BASE, known: true }
  state = applyCwdCommand(state, 'cd', ['C:/Windows'])
  assert.deepEqual(state, { dir: 'C:/Windows', known: true })
  state = applyCwdCommand(state, 'cd', ['..'])
  assert.deepEqual(state, { dir: 'C:', known: true })
  state = applyCwdCommand(state, 'cd', ['$x'])
  assert.equal(state.known, false)
  state = applyCwdCommand(state, 'popd', [])
  assert.equal(state.known, false)
  assert.deepEqual(applyCwdCommand(state, 'echo', ['x']), state) // non-cd command is a no-op
})

test('classifyVerb: read / modify / list / unknown (normalized names)', () => {
  assert.equal(classifyVerb('getcontent'), 'read')
  assert.equal(classifyVerb('gc'), 'read')
  assert.equal(classifyVerb('selectstring'), 'read')
  assert.equal(classifyVerb('setcontent'), 'modify')
  assert.equal(classifyVerb('removeitem'), 'modify')
  assert.equal(classifyVerb('copyitem'), 'modify')
  assert.equal(classifyVerb('newitem'), 'modify')
  assert.equal(classifyVerb('getchilditem'), 'list')
  assert.equal(classifyVerb('selectobject'), 'list')
  assert.equal(classifyVerb('git'), undefined)
  assert.equal(classifyVerb('cd'), undefined)
})

test('assessContentClass: modify wins, redirect is modify, unknown is fail-closed', () => {
  assert.equal(assessContentClass('Get-Content .env'), 'read')
  assert.equal(assessContentClass('Select-String .env -Pattern x'), 'read')
  assert.equal(assessContentClass('Get-Content .env | Set-Content x'), 'modify')
  assert.equal(assessContentClass('Set-Content .env x'), 'modify')
  assert.equal(assessContentClass('Get-ChildItem x > .env'), 'modify')
  assert.equal(assessContentClass('Get-ChildItem .dsh'), 'list')
  assert.equal(assessContentClass('cd x; Get-Content .env'), 'unknown')
  assert.equal(assessContentClass('Get-ChildItem $(echo .env)'), 'unknown')
  assert.equal(assessContentClass('git status'), 'unknown')
})

test('assessSystemWrite: write verbs and redirects into system prefixes', () => {
  for (const cmd of [
    'Set-Content C:\\Windows\\x y',
    'Set-Content "C:/Program Files/x" y',
    'Remove-Item C:\\Windows\\x -Recurse',
    'Remove-Item C:/ProgramData/x',
    'Copy-Item a.txt C:\\Windows\\x',
    'Copy-Item a.txt -Destination C:\\Windows\\x',
    'Move-Item a.txt "C:/Program Files (x86)/x"',
    'New-Item C:\\Windows\\x',
    'Out-File C:\\Windows\\x',
    'Clear-Content C:\\Windows\\x',
    'echo x > C:\\Windows\\foo.txt',
    'echo x >> C:/Windows/foo.txt',
    'cmd /c echo x 2>C:\\Windows\\err.txt',
  ]) {
    assert.notEqual(assessSystemWrite(SYS_BASE, cmd), null, cmd)
  }
  // reads and listings stay allowed (DSR-005)
  assert.equal(assessSystemWrite(SYS_BASE, 'Get-Content C:\\Windows\\win.ini'), null)
  assert.equal(assessSystemWrite(SYS_BASE, 'Get-ChildItem C:\\Windows'), null)
  assert.equal(assessSystemWrite(SYS_BASE, 'Copy-Item C:\\Windows\\x .'), null) // copy FROM system area
  // non-system writes stay allowed
  assert.equal(assessSystemWrite(SYS_BASE, 'Set-Content README.md x'), null)
  assert.equal(assessSystemWrite(SYS_BASE, 'Remove-Item tmp/x'), null)
  assert.equal(assessSystemWrite(SYS_BASE, 'echo x > out.txt'), null)
})

test('assessSystemWrite: cd chains cannot hide a system write', () => {
  assert.notEqual(assessSystemWrite(SYS_BASE, 'cd C:\\Windows; Set-Content x y'), null)
  assert.notEqual(assessSystemWrite(SYS_BASE, 'Set-Location "C:/Program Files"; Remove-Item x'), null)
  assert.notEqual(assessSystemWrite(SYS_BASE, 'cd $unknown; Set-Content C:\\Windows\\x y'), null) // absolute still caught
  assert.equal(assessSystemWrite(SYS_BASE, 'cd C:\\Windows; Get-Content x'), null) // read in system dir ok
})

test('assessSystemWrite: startup folder and PowerShell profiles', () => {
  assert.notEqual(
    assessSystemWrite(SYS_BASE, 'Set-Content "C:/Users/me/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/x.ps1" y'),
    null,
  )
  assert.notEqual(
    assessSystemWrite(SYS_BASE, 'Set-Content "C:/Users/me/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1" y'),
    null,
  )
  assert.notEqual(
    assessSystemWrite(SYS_BASE, 'Set-Content "C:/Users/me/Documents/PowerShell/Microsoft.PowerShell_profile.ps1" y'),
    null,
  )
})
