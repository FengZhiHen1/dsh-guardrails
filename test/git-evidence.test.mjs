// Tests for git-evidence. Every case builds a REAL temporary git repository under the
// OS temp directory (os.tmpdir()) with local user config, then removes it with t.after.
// No project source is touched, no network, no push/merge. The only external program is
// read-only `git` (dry-run probes). Timeout/unparseable paths inject a fake `run`.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import os from 'node:os'
import { execFileSync } from 'node:child_process'
import {
  gitCleanTargets,
  gitRestoreTargets,
  gitWorktreeRemoveDecision,
} from '../src/adapter/git-evidence.js'

const FIXTURE_BASE = os.tmpdir()

async function fixture(t, label) {
  await fs.mkdir(FIXTURE_BASE, { recursive: true })
  const root = await fs.mkdtemp(path.join(FIXTURE_BASE, `git-ev-${label}-`))
  t.after(async () => {
    await fs.rm(root, { recursive: true, force: true, maxRetries: 3 })
  })
  return root
}

function git(cwd, args) {
  return execFileSync('git', ['-C', cwd, '-c', 'user.email=t@example.com', '-c', 'user.name=t', ...args], {
    stdio: 'ignore',
  })
}

function gitOut(cwd, args) {
  return execFileSync('git', ['-C', cwd, '-c', 'user.email=t@example.com', '-c', 'user.name=t', ...args], {
    encoding: 'utf8',
  })
}

async function write(root, relative, content = 'x\n') {
  const target = path.join(root, ...relative.split('/'))
  await fs.mkdir(path.dirname(target), { recursive: true })
  await fs.writeFile(target, content)
  return target
}

/** Create a repository with one commit and a .gitignore. */
async function repo(t, label, gitignoreLines = []) {
  const root = await fixture(t, label)
  git(root, ['init', '-q'])
  git(root, ['config', 'user.email', 't@example.com'])
  git(root, ['config', 'user.name', 't'])
  if (gitignoreLines.length > 0) {
    await write(root, '.gitignore', gitignoreLines.join('\n') + '\n')
  }
  await write(root, 'tracked.txt', 'original\n')
  git(root, ['add', '-A'])
  git(root, ['commit', '-q', '-m', 'init'])
  return root
}

/** Main repository plus one linked worktree. Returns { main, worktree }. */
async function worktreeFixture(t, label, gitignoreLines = ['*.env', 'node_modules/', 'dist/']) {
  const main = await repo(t, label, gitignoreLines)
  const worktree = path.join(path.dirname(main), `${path.basename(main)}-wt`)
  t.after(async () => {
    await fs.rm(worktree, { recursive: true, force: true, maxRetries: 3 })
  })
  git(main, ['worktree', 'add', '-q', worktree, '-b', `wt-${path.basename(main)}`])
  return { main, worktree }
}

// --- git clean -------------------------------------------------------------

test('gitCleanTargets counts the untracked files a dry-run clean would remove', async (t) => {
  const root = await repo(t, 'clean-basic')
  await write(root, 'a.txt')
  await write(root, 'b.txt')
  await write(root, 'sub/c.txt')

  const result = await gitCleanTargets({ cwd: root })
  assert.equal(result.kind, 'count', JSON.stringify(result))
  assert.equal(result.count, 3)
})

test('gitCleanTargets includes ignored files only when -x is requested', async (t) => {
  const root = await repo(t, 'clean-ignored', ['*.log'])
  await write(root, 'untracked.txt')
  await write(root, 'noise.log')

  const withoutIgnored = await gitCleanTargets({ cwd: root })
  assert.equal(withoutIgnored.kind, 'count')
  assert.equal(withoutIgnored.count, 1)

  const withIgnored = await gitCleanTargets({ cwd: root, ignored: true })
  assert.equal(withIgnored.kind, 'count')
  assert.equal(withIgnored.count, 2)
})

test('gitCleanTargets is unknown on unparseable output', async (t) => {
  const root = await repo(t, 'clean-garbage')
  const result = await gitCleanTargets({ cwd: root, run: async () => ({ stdout: 'fatal: nonsense\n' }) })
  assert.equal(result.kind, 'unknown')
})

test('gitCleanTargets is unknown when git fails or the deadline passed', async (t) => {
  const root = await repo(t, 'clean-fail')
  const failed = await gitCleanTargets({ cwd: root, run: async () => { throw new Error('boom') } })
  assert.equal(failed.kind, 'unknown')

  const expired = await gitCleanTargets({ cwd: root, deadlineAt: Date.now() - 1000 })
  assert.equal(expired.kind, 'unknown')
  assert.equal(expired.reason, 'deadline')
})

// --- git restore -----------------------------------------------------------

test('gitRestoreTargets counts modified tracked paths', async (t) => {
  const root = await repo(t, 'restore')
  await write(root, 'a.txt', 'changed-a\n')
  await write(root, 'b.txt', 'changed-b\n')
  await write(root, 'c.txt', 'changed-c\n')
  git(root, ['add', 'a.txt', 'b.txt', 'c.txt'])
  git(root, ['commit', '-q', '-m', 'add files'])
  await write(root, 'a.txt', 'dirty-a\n')
  await write(root, 'b.txt', 'dirty-b\n')

  const all = await gitRestoreTargets({ cwd: root, paths: ['a.txt', 'b.txt', 'c.txt'] })
  assert.equal(all.kind, 'count')
  assert.equal(all.count, 2)

  const one = await gitRestoreTargets({ cwd: root, paths: ['a.txt'] })
  assert.equal(one.kind, 'count')
  assert.equal(one.count, 1)

  const none = await gitRestoreTargets({ cwd: root, paths: [] })
  assert.equal(none.kind, 'count')
  assert.equal(none.count, 0)
})

test('gitRestoreTargets is unknown when git fails', async (t) => {
  const root = await repo(t, 'restore-fail')
  const result = await gitRestoreTargets({
    cwd: root,
    paths: ['a.txt'],
    run: async () => { throw Object.assign(new Error('killed'), { code: 128 }) },
  })
  assert.equal(result.kind, 'unknown')
})

// --- worktree remove -------------------------------------------------------

test('worktree remove: a clean linked worktree is allowed with count 0', async (t) => {
  const { main, worktree } = await worktreeFixture(t, 'wt-clean')
  const result = await gitWorktreeRemoveDecision({ cwd: main, path: worktree })
  assert.equal(result.kind, 'count', JSON.stringify(result))
  assert.equal(result.count, 0)
})

test('worktree remove: any untracked file denies (zero tolerance)', async (t) => {
  const { main, worktree } = await worktreeFixture(t, 'wt-untracked')
  await write(worktree, 'surprise.txt')
  const result = await gitWorktreeRemoveDecision({ cwd: main, path: worktree })
  assert.equal(result.kind, 'deny', JSON.stringify(result))
  assert.equal(result.reason, 'untracked-or-modified')
})

test('worktree remove: a staged or unstaged modification denies (zero tolerance)', async (t) => {
  const { main, worktree } = await worktreeFixture(t, 'wt-modified')
  await write(worktree, 'tracked.txt', 'locally modified\n')
  const unstaged = await gitWorktreeRemoveDecision({ cwd: main, path: worktree })
  assert.equal(unstaged.kind, 'deny', JSON.stringify(unstaged))
  assert.equal(unstaged.reason, 'untracked-or-modified')

  git(worktree, ['add', 'tracked.txt'])
  const staged = await gitWorktreeRemoveDecision({ cwd: main, path: worktree })
  assert.equal(staged.kind, 'deny', JSON.stringify(staged))
  assert.equal(staged.reason, 'untracked-or-modified')
})

test('worktree remove: a detached HEAD denies', async (t) => {
  const { main, worktree } = await worktreeFixture(t, 'wt-detached')
  git(worktree, ['checkout', '-q', '--detach'])
  const result = await gitWorktreeRemoveDecision({ cwd: main, path: worktree })
  assert.equal(result.kind, 'deny', JSON.stringify(result))
  assert.equal(result.reason, 'detached-head')
})

test('worktree remove: 21 non-rebuildable ignored files deny, 20 are allowed', async (t) => {
  const over = await worktreeFixture(t, 'wt-ignored-21')
  for (let i = 1; i <= 21; i += 1) await write(over.worktree, `secret-${String(i).padStart(2, '0')}.env`)
  const denied = await gitWorktreeRemoveDecision({ cwd: over.main, path: over.worktree })
  assert.equal(denied.kind, 'deny', JSON.stringify(denied))
  assert.equal(denied.reason, 'ignored-over-limit')
  assert.equal(denied.count, 21)

  const within = await worktreeFixture(t, 'wt-ignored-20')
  for (let i = 1; i <= 20; i += 1) await write(within.worktree, `secret-${String(i).padStart(2, '0')}.env`)
  const allowed = await gitWorktreeRemoveDecision({ cwd: within.main, path: within.worktree })
  assert.equal(allowed.kind, 'count', JSON.stringify(allowed))
  assert.equal(allowed.count, 20)
})

test('worktree remove: rebuildable IGNORED entries do not count, but un-ignored ones still deny', async (t) => {
  // Zero-tolerance rule takes precedence: a rebuildable directory that is NOT ignored is
  // an untracked entry and still denies.
  const loose = await worktreeFixture(t, 'wt-rebuildable-loose')
  await write(loose.worktree, '__pycache__/mod.cpython-312.pyc', 'bytecode')
  const looseDecision = await gitWorktreeRemoveDecision({ cwd: loose.main, path: loose.worktree })
  assert.equal(looseDecision.kind, 'deny', JSON.stringify(looseDecision))
  assert.equal(looseDecision.reason, 'untracked-or-modified')

  // When they ARE ignored, rebuildable build output/caches are skipped from the count.
  const { main, worktree } = await worktreeFixture(t, 'wt-rebuildable', [
    '*.env', 'node_modules/', 'dist/', '__pycache__/', '*.pyc',
  ])
  await write(worktree, 'node_modules/pkg/index.js')
  await write(worktree, 'dist/app.js')
  await write(worktree, '__pycache__/mod.cpython-312.pyc', 'bytecode')
  const result = await gitWorktreeRemoveDecision({ cwd: main, path: worktree })
  assert.equal(result.kind, 'count', JSON.stringify(result))
  assert.equal(result.count, 0)
})

test('worktree remove: the main/current worktree is denied', async (t) => {
  const { main, worktree } = await worktreeFixture(t, 'wt-main')
  // Removing the primary worktree.
  const primary = await gitWorktreeRemoveDecision({ cwd: main, path: main })
  assert.equal(primary.kind, 'deny', JSON.stringify(primary))
  assert.equal(primary.reason, 'main-worktree')

  // Removing the worktree the command runs in.
  const own = await gitWorktreeRemoveDecision({ cwd: worktree, path: worktree })
  assert.equal(own.kind, 'deny', JSON.stringify(own))
  assert.equal(own.reason, 'main-worktree')
})

test('worktree remove: a locked worktree denies', async (t) => {
  const { main, worktree } = await worktreeFixture(t, 'wt-locked')
  git(main, ['worktree', 'lock', worktree])
  const result = await gitWorktreeRemoveDecision({ cwd: main, path: worktree })
  assert.equal(result.kind, 'deny', JSON.stringify(result))
  assert.equal(result.reason, 'locked')
})

test('worktree remove: an unregistered or missing path is unknown', async (t) => {
  const { main } = await worktreeFixture(t, 'wt-missing')
  const absent = await gitWorktreeRemoveDecision({ cwd: main, path: path.join(path.dirname(main), 'never-created') })
  assert.equal(absent.kind, 'unknown', JSON.stringify(absent))

  const empty = await gitWorktreeRemoveDecision({ cwd: main, path: '' })
  assert.equal(empty.kind, 'unknown', JSON.stringify(empty))
})

test('worktree remove: any git failure or timeout is unknown', async (t) => {
  const { main, worktree } = await worktreeFixture(t, 'wt-timeout')
  const timeout = await gitWorktreeRemoveDecision({
    cwd: main,
    path: worktree,
    run: async () => { throw Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }) },
  })
  assert.equal(timeout.kind, 'unknown', JSON.stringify(timeout))

  const expired = await gitWorktreeRemoveDecision({ cwd: main, path: worktree, deadlineAt: Date.now() - 1000 })
  assert.equal(expired.kind, 'unknown', JSON.stringify(expired))
  assert.equal(expired.reason, 'deadline')
})

test('worktree remove: unparseable worktree list is unknown', async (t) => {
  const { main, worktree } = await worktreeFixture(t, 'wt-garbage')
  const result = await gitWorktreeRemoveDecision({
    cwd: main,
    path: worktree,
    run: async () => ({ stdout: 'not a porcelain listing\n' }),
  })
  assert.equal(result.kind, 'unknown', JSON.stringify(result))
})
