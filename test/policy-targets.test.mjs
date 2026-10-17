import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import os from 'node:os'
import { execFileSync } from 'node:child_process'
import { observeTargets } from '../src/adapter/targets.js'
import { evaluatePolicy, structuredCommands } from '../src/core/policy.js'
import { evaluateRules } from '../src/core/rules.js'

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'guardrails-policy-'))
  // Only this test-created isolated fixture is removed.
  t.after(async () => { await fs.rm(root, { recursive: true, force: true }) })
  return root
}

async function judge(root, commands, config = {}) {
  const targets = await observeTargets({ commands, cwd: root, rules: evaluateRules(config) })
  return { targets, decision: evaluatePolicy({ commands, targets }) }
}

test('actual exact files ask for direct reads/writes/deletion; unmarked env and metadata allow', async (t) => {
  const root = await fixture(t)
  await fs.writeFile(path.join(root, 'secret.env'), 'synthetic fixture')
  await fs.writeFile(path.join(root, '.env'), 'ordinary fixture')
  const config = { sensitiveFiles: [path.join(root, 'secret.env')] }
  for (const name of ['read', 'write', 'edit', 'delete', 'copy', 'move']) {
    assert.equal((await judge(root, structuredCommands(name, { file_path: 'secret.env' }), config)).decision.kind, 'ask', name)
  }
  for (const name of ['read', 'glob']) {
    assert.equal((await judge(root, structuredCommands(name, { file_path: '.env' }), config)).decision.kind, 'allow')
  }
  const missingConfig = { sensitiveFiles: [path.join(root, 'missing')] }
  assert.equal((await judge(root, structuredCommands('read', { file_path: 'missing' }), missingConfig)).decision.kind, 'allow')
  assert.equal((await judge(root, structuredCommands('write', { file_path: 'missing' }), missingConfig)).decision.ruleId, 'S-F1')
  assert.equal((await judge(root, structuredCommands('edit', { file_path: 'missing' }), missingConfig)).decision.ruleId, 'S-F1')
})

test('directory operations and worktree remove ask only on actual protected files', async (t) => {
  const root = await fixture(t)
  await fs.mkdir(path.join(root, 'wt'))
  await fs.writeFile(path.join(root, 'wt', '.env'), 'fixture')
  const command = [{ name: 'git', args: ['worktree', 'remove', 'wt'] }]
  assert.equal((await judge(root, command)).decision.kind, 'allow')
  await fs.writeFile(path.join(root, 'wt', 'secret.env'), 'fixture')
  const config = { sensitiveFiles: [path.join(root, 'wt', 'secret.env')] }
  assert.equal((await judge(root, command, config)).decision.ruleId, 'S-F2')
  assert.equal((await judge(root, [{ name: 'rm', args: ['-rf', 'wt'] }], config)).decision.ruleId, 'S-F1')
  assert.equal((await judge(root, structuredCommands('grep', { path: 'wt' }), config)).decision.ruleId, 'S-F1')
})

test('worktree builtin discovery uses metadata; ordinary cleanup does not scan builtin files', async (t) => {
  const root = await fixture(t)
  await fs.mkdir(path.join(root, 'build'))
  await fs.mkdir(path.join(root, 'build', 'id_rsa'))
  assert.equal((await judge(root, [{ name: 'rm', args: ['-rf', 'build'] }])).decision.kind, 'allow')
  await fs.writeFile(path.join(root, 'build', '.npmrc'), 'synthetic fixture')
  assert.equal((await judge(root, [{ name: 'rm', args: ['-rf', 'build'] }])).decision.kind, 'allow')
  assert.equal((await judge(root, [{ name: 'git', args: ['worktree', 'remove', 'build'] }])).decision.kind, 'ask')
  assert.equal((await judge(root, [{ name: 'git', args: ['worktree', 'remove', 'build'] }], { builtinSensitiveAsk: false })).decision.kind, 'allow')
})

test('real git common-dir differs from linked .git pointer and local cleanup', async (t) => {
  const root = await fixture(t)
  execFileSync('git', ['init', root], { stdio: 'ignore' })
  assert.equal((await judge(root, [{ name: 'rm', args: ['-rf', '.git'] }])).decision.ruleId, 'ABS-03')
  assert.equal((await judge(root, [{ name: 'rm', args: ['-rf', '.git/objects'] }])).decision.ruleId, 'ABS-03')
  assert.equal((await judge(root, [{ name: 'rm', args: ['-rf', '.git/hooks'] }])).decision.kind, 'allow')
  assert.equal((await judge(root, [{ name: 'rm', args: ['-rf', '.'] }])).decision.kind, 'allow')
  assert.equal((await judge(root, [{ name: 'mv', args: ['.git', 'git-backup'] }])).decision.kind, 'allow')
  const linked = path.join(root, 'linked')
  await fs.mkdir(linked)
  await fs.writeFile(path.join(linked, '.git'), 'gitdir: ../.git/worktrees/linked')
  assert.equal((await judge(root, [{ name: 'rm', args: ['-rf', 'linked/.git'] }])).decision.kind, 'allow')
})

test('ordinary image files and nonexistent device-like names never prove host disks', async (t) => {
  const root = await fixture(t)
  await fs.writeFile(path.join(root, 'disk.img'), 'fixture')
  for (const target of ['disk.img', '/dev/guardrails-missing-device']) {
    const result = await judge(root, [{ name: 'mkfs.ext4', args: [target] }])
    assert.equal(result.decision.kind, 'allow')
    assert.notEqual(result.targets.operations[0].identity, 'host-physical-device')
  }
})

test('realpath aliases match marked files and Linux case stays significant', async (t) => {
  const root = await fixture(t)
  await fs.writeFile(path.join(root, 'Secret'), 'fixture')
  const config = { sensitiveFiles: [path.join(root, 'Secret')] }
  if (process.platform !== 'win32') {
    await fs.writeFile(path.join(root, 'secret'), 'fixture')
    assert.equal((await judge(root, structuredCommands('read', { file_path: 'secret' }), config)).decision.kind, 'allow')
    await fs.symlink(path.join(root, 'Secret'), path.join(root, 'alias'))
    assert.equal((await judge(root, structuredCommands('read', { file_path: 'alias' }), config)).decision.kind, 'ask')
  }
})
