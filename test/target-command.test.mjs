import assert from 'node:assert/strict'
import test from 'node:test'
import { resolveCommand } from '../src/adapter/analysis/commands.js'

function command(executable, args, unit = {}) {
  const operations = []
  const children = []
  const candidates = []
  const gaps = []
  resolveCommand(executable, args, {
    context: { domain: 'host', platform: 'linux', cwd: '/fixture' }, origin: { entry: 'fixture' }, ...unit,
  }, {
    operation(action, target, options) { operations.push({ action, target, ...options }) },
    child(input) { children.push(input) },
    candidate(kind, reason) { candidates.push({ kind, reason }) },
    gap(kind) { gaps.push(kind) },
  })
  return { operations, children, candidates, gaps }
}

test('recursive deletion identifies the subtree, including a bounded wildcard base', () => {
  const direct = command('rm', ['-r', '--', 'build'])
  assert.deepEqual(direct.operations[0].target, { kind: 'subtree', root: 'build' })
  const pattern = command('rm', ['-r', '--', 'build/*.txt'], { patterns: [false, false, true] })
  assert.deepEqual(pattern.operations[0].target, { kind: 'pattern', base: '/fixture/build', pattern: '*.txt', dialect: 'posix' })
})

test('PowerShell separates a literal operand, pattern and preview', () => {
  const literal = command('Remove-Item', ['-LiteralPath', '*.txt', '-WhatIf:$false'], { powershell: true })
  assert.deepEqual(literal.operations[0].target, { kind: 'exact', paths: ['*.txt'] })
  assert.equal(literal.operations[0].preview, false)
  const preview = command('Remove-Item', ['-Path', '*.txt', '-WhatIf'], { powershell: true })
  assert.equal(preview.operations[0].preview, true)
  assert.equal(preview.operations[0].target.kind, 'pattern')
})

test('storage cmdlets report selectors as evidence requests and honor preview', () => {
  const unit = { powershell: true, context: { domain: 'host', platform: 'win32', cwd: 'C:\\fixture' } }
  const operation = command('Clear-Disk', ['-Number', '0'], unit).operations[0]
  assert.deepEqual(operation.details, { deviceMutation: { diskNumber: 0 } })
  assert.equal(command('Format-Volume', ['-DriveLetter', 'C', '-WhatIf'], unit).operations.length, 0)
  assert.equal(command('Clear-Disk', ['-Number', null], unit).candidates[0].kind, 'unverified-effect')
})

test('Git preview only follows a recognized option before the terminator', () => {
  const preview = command('git', ['clean', '-ndx'])
  assert.equal(preview.operations[0].preview, true)
  const ordinary = command('git', ['clean', '-fd', '--', '-n'])
  assert.equal(ordinary.operations[0].preview, false)
  assert.equal(command('git', ['push', '--dry-run', '--force']).operations[0].preview, true)
  assert.equal(command('git', ['push', 'origin', 'HEAD:main']).operations.length, 0)
  assert.equal(command('git', ['push', 'origin', ':obsolete']).operations[0].action, 'git-history-destroy')
})

test('cat line-number switch does not consume the file operand', () => {
  const result = command('cat', ['-n', 'fixture.txt'])
  assert.deepEqual(result.operations[0].target, { kind: 'exact', paths: ['fixture.txt'] })
})

test('raw output commands emit write intent only for the destination', () => {
  const write = command('dd', ['if=source.img', 'of=destination.img']).operations[0]
  assert.equal(write.action, 'write-content')
  assert.deepEqual(write.target.paths, ['destination.img'])
  const truncate = command('truncate', ['--size', '0', '--', 'fixture.txt']).operations[0]
  assert.equal(truncate.action, 'truncate-content')
  assert.deepEqual(truncate.target.paths, ['fixture.txt'])
})

test('WSL retains explicit distribution, user and cwd without inheriting host paths', () => {
  const result = command('wsl.exe', ['-d', 'Fixture', '-u', 'runner', '--cd', '/fixture', '--exec', 'bash', 'example.sh'], {
    context: { domain: 'host', platform: 'win32', cwd: 'C:\\fixture' },
  })
  assert.deepEqual(result.children[0].context, { domain: 'wsl', platform: 'linux', cwd: '/fixture', user: 'runner', distribution: 'Fixture' })
  assert.deepEqual(result.children[0].source, { kind: 'argv', executable: 'bash', args: ['example.sh'] })
})
