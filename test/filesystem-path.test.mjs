// Tests for the pure filesystem provider-path predicate shared by intent/plan/targets.
import test from 'node:test'
import assert from 'node:assert/strict'
import { isUnsupportedProviderPath } from '../src/core/filesystem-path.js'

test('drive-qualified absolute paths are supported', () => {
  for (const p of ['C:\\Users\\x', 'D:/data/file.txt', 'c:\\a', 'Z:/']) {
    assert.equal(isUnsupportedProviderPath(p), false, p)
  }
})

test('ordinary literal and relative paths are supported', () => {
  for (const p of ['file.txt', 'sub/dir/x', './a', '../up/a', '/home/user/x', 'a b/c', '']) {
    assert.equal(isUnsupportedProviderPath(p), false, JSON.stringify(p))
  }
})

test('PowerShell provider separator (::) is rejected anywhere', () => {
  for (const p of ['FileSystem::C:\\x', 'Microsoft.PowerShell.Core\\FileSystem::C:\\x', 'C:\\a::b', '::relative']) {
    assert.equal(isUnsupportedProviderPath(p), true, p)
  }
})

test('non-filesystem provider / scheme prefixes are rejected', () => {
  for (const p of [
    'Registry::HKLM\\Software',
    'HKCU:\\Software',
    'HKLM:\\Software',
    'Variable:\\env:PATH',
    'Variable:foo',
    'Env:PATH',
    'Function:prompt',
    'Alias:ls',
    'Cert:\\LocalMachine\\My',
    'http://example/x',
    'https://example/x',
    'mshta:foo',
    'file:///etc/passwd',
    'wsman:localhost',
  ]) {
    assert.equal(isUnsupportedProviderPath(p), true, p)
  }
})

test('PowerShell custom PSDrive / arbitrary first-component prefixes are rejected', () => {
  // Detection is by the FIRST path component's colon, not URI grammar, so a PSDrive
  // name that is not a single letter (`_drive`, `123`, `My Drive`) is refused.
  for (const p of ['_drive:\\x', '123:\\x', 'My Drive:\\x', 'a b:/x', 'MyDrive:x', 'foo_bar:\\x']) {
    assert.equal(isUnsupportedProviderPath(p), true, p)
  }
})

test('a bare drive prefix without a separator is drive-relative and rejected', () => {
  assert.equal(isUnsupportedProviderPath('C:foo'), true)
  assert.equal(isUnsupportedProviderPath('C:'), true)
})

test('non-string inputs are not judged as provider paths', () => {
  for (const v of [null, undefined, 42, {}, []]) assert.equal(isUnsupportedProviderPath(v), false)
})
