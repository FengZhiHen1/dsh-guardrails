import test from 'node:test'
import assert from 'node:assert/strict'
import { evaluatePolicy, extractOperations, structuredCommands } from '../src/core/policy.js'

const decide = (...operations) => evaluatePolicy({ targets: { operations } })

test('confirmed absolute categories need actual identity plus destructive effect', () => {
  for (const [operation, ruleId] of [
    [{ action: 'device-destroy', identity: 'host-physical-device' }, 'ABS-01'],
    [{ action: 'delete', recursive: true, identity: 'host-system-tree' }, 'ABS-02'],
    [{ action: 'delete', recursive: true, gitSharedBody: true }, 'ABS-03'],
  ]) assert.equal(decide(operation).ruleId, ruleId)
  for (const operation of [
    { action: 'device-destroy', path: '/dev/sda' },
    { action: 'delete', path: '/.git', recursive: true },
    { action: 'read', identity: 'host-system-tree' },
    { action: 'worktree-remove', recursive: true, gitSharedBody: true },
    { action: 'delete', identity: 'host-system-tree', recursive: false },
  ]) assert.equal(decide(operation).kind, 'allow')
})

test('S-F1/S-F2 require observed protected files and deny wins aggregation', () => {
  assert.equal(decide({ action: 'read', protected: true }).ruleId, 'S-F1')
  assert.equal(decide({ action: 'worktree-remove', containsProtected: true }).ruleId, 'S-F2')
  assert.equal(decide({ action: 'worktree-remove', containsProtected: false }).kind, 'allow')
  assert.equal(decide({ action: 'metadata', protected: true }).kind, 'allow')
  assert.equal(decide({ action: 'read', protected: true }, { action: 'delete', recursive: true, gitSharedBody: true }).kind, 'deny')
})

test('semantic extraction ignores arguments in unrelated commands and unknown values', () => {
  const commands = [
    { name: 'echo', args: ['rm', '-rf', '/', '.npmrc'] },
    { name: null, args: ['.npmrc'] },
    { name: 'terraform', args: ['destroy'] },
    { name: 'git', args: ['reset', '--hard'] },
    { name: 'git', args: ['clean', '-fdx'] },
    { name: 'rm', args: [null] },
  ]
  assert.deepEqual(extractOperations(commands), [])
  assert.equal(extractOperations([{ name: 'Remove-Item', args: ['-LiteralPath', 'build', '-Recurse'] }])[0].recursive, true)
  assert.equal(extractOperations([{ name: 'Remove-Item', args: ['secret', '-WhatIf'] }]).length, 0)
})

test('redirects and native worktree removal preserve explicit target semantics', () => {
  const operations = extractOperations([
    { name: 'echo', args: ['hello'], redirects: [{ operator: '>', target: '.npmrc' }] },
    { name: 'git', args: ['-C', 'repo', 'worktree', 'remove', '--', '../wt'] },
    { name: 'grep', args: ['.npmrc', 'README.md'] },
  ])
  assert.deepEqual(operations.map(({ action, path }) => [action, path]), [['write', '.npmrc'], ['worktree-remove', '../wt'], ['read', 'README.md']])
  assert.equal(operations[1].cwd, 'repo')
  assert.deepEqual(structuredCommands('read', { file_path: 'secret' }), [{ name: 'read', args: ['secret'], structured: true }])
})

test('Unix options are command-specific and never consume targets for cat -n or rm -f', () => {
  for (const [name, args] of [['cat', ['-n', 'secret']], ['less', ['-N', 'secret']], ['rm', ['-f', 'secret']], ['head', ['-c', '10', 'secret']]]) {
    assert.deepEqual(extractOperations([{ name, args }]).map(operation => operation.path), ['secret']);
  }
});

test('preview and help operands do not manufacture destructive effects; redirects remain writes', () => {
  for (const command of [
    { name: 'Set-Content', args: ['-LiteralPath', 'secret', '-Value', 'text', '-WhatIf'] },
    { name: 'wipefs', args: ['--no-act', '/dev/sda'] },
    { name: 'mkfs.ext4', args: ['-n', '/dev/sda'] },
    { name: 'rm', args: ['-rf', '/', '--help'] },
  ]) assert.deepEqual(extractOperations([command]), []);
  assert.equal(extractOperations([{ name: 'Remove-Item', args: ['/etc', '-Recurse:$false'] }])[0].recursive, false);
  assert.equal(extractOperations([{ name: 'rm', args: ['--help'], redirects: [{ operator: '>', target: 'secret' }] }])[0].action, 'write');
});

test('malformed IR fails explicitly instead of masquerading as unknown semantics', () => {
  assert.throws(() => extractOperations([{ name: 'rm', args: [5] }]), /argument/)
  assert.throws(() => evaluatePolicy({}), /observations/)
})
