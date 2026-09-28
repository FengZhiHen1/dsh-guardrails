// Command-text unit tests for src/core/command.js: lexing, fragment
// unwrapping, listing-mode detection, and content-sensitive reference detection.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  applyCwdCommand,
  assessContentClass,
  assessSystemWrite,
  classifyVerb,
  detectContentSensitiveRef,
  isListingOnly,
  maskTextSpans,
  tokenizePwsh,
  unwrapFragment,
} from '../src/core/command.js'
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

test('tokenizePwsh: && and || keep their two-char values (error-gate fidelity)', () => {
  const { tokens } = tokenizePwsh('a && b || c')
  assert.deepEqual(tokens.filter((t) => t.kind === 'sep').map((t) => t.value), ['&&', '||'])
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

test('maskTextSpans: prose in a quoted span is a citation, not a path (DSR-010)', () => {
  // The 2026-09-27 false positive: a commit message quoting this guard's own
  // deny text was judged as a path reference into .git.
  assert.equal(
    maskTextSpans('git commit -m "docs: references the .git directory"').includes('.git'),
    false,
  )
  assert.equal(maskTextSpans('Write-Output "see .git for history"').includes('.git'), false)
  assert.equal(maskTextSpans('git commit -m "keep .ssh out of the repo"').includes('.ssh'), false)
})

test('maskTextSpans: path-shaped spans keep their separators under full rules', () => {
  // A span with whitespace but no separator cannot name the .git directory, so
  // it is blanked; anything carrying a separator stays visible to the checks.
  for (const cmd of [
    'Get-Content ".git/config"',
    "Get-Content '.git/config'",
    'Get-Content "C:\\Program Files\\repo\\.git\\config"',
    'Get-Content ".git"',
    'Get-Content .git',
  ]) {
    assert.equal(maskTextSpans(cmd).includes('.git'), true, cmd)
  }
})

test('maskTextSpans: text/pattern parameter values are citations', () => {
  assert.equal(maskTextSpans("$n -notmatch '\\.git'").includes('.git'), false)
  assert.equal(maskTextSpans('git commit --message "the .git dir"').includes('.git'), false)
  assert.equal(maskTextSpans('git commit -Message:"the .git dir"').includes('.git'), false)
})

test('maskTextSpans: path-capable parameters are never exempted', () => {
  // -Filter / -Pattern / -Include / -Exclude really do select filesystem names.
  assert.equal(maskTextSpans('Get-ChildItem -Filter ".git"').includes('.git'), true)
  assert.equal(maskTextSpans('Select-String -Pattern "\\.git" x').includes('.git'), true)
  assert.equal(maskTextSpans('Get-ChildItem -Include ".git"').includes('.git'), true)
  assert.equal(maskTextSpans('Get-Content -LiteralPath ".git"').includes('.git'), true)
  // a text parameter's citation is blanked, but the immediately following
  // positional path is untouched
  const mixed = maskTextSpans('git commit -m "see .git" .env')
  assert.equal(mixed.includes('.git'), false)
  assert.equal(mixed.includes('.env'), true)
})

test('maskTextSpans: blanking preserves length and every non-cited character', () => {
  const cmd = 'git commit -m "see .git" x'
  const masked = maskTextSpans(cmd)
  assert.equal(masked.length, cmd.length)
  // The cited span includes its quotes, so compare the text on either side of it.
  assert.equal(masked.slice(0, 14), cmd.slice(0, 14)) // 'git commit -m '
  assert.equal(masked.slice(-2), cmd.slice(-2)) // ' x'
  assert.equal(masked.slice(14, 24), ' '.repeat(10))
  assert.equal(maskTextSpans('git status'), 'git status')
})

test('maskTextSpans: masking is what keeps citations from reading as references', () => {
  const cited = 'git commit -m "references the .git directory"'
  assert.equal(detectContentSensitiveRef(cited), 'git') // unmasked: reads as a reference
  assert.equal(detectContentSensitiveRef(maskTextSpans(cited)), null) // masked: a citation
})

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
