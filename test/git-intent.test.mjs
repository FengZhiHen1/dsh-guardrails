// Tests for the pure git subcommand classifier (v4 catastrophe standard).
import test from 'node:test'
import assert from 'node:assert/strict'
import { assessGit } from '../src/core/git-intent.js'

test('ordinary repository operations are allowed', () => {
  for (const argv of [
    ['status'], ['status', '--short'], ['diff'], ['log', '--oneline'], ['show', 'HEAD'],
    ['add', '.'], ['commit', '-m', 'x'], ['branch'], ['branch', '-D', 'old'],
    ['switch', 'main'], ['merge', 'x'], ['rebase', 'main'], ['fetch'], ['pull'],
    ['reflog'], ['rev-parse', 'HEAD'], ['tag', '-d', 'v1'],
    ['worktree', 'add', '../wt'], ['worktree', 'list'], ['worktree', 'prune'],
    ['gc'], ['gc', '--prune=2.weeks.ago'],
    ['update-ref', '-d', 'refs/heads/x'],
  ]) {
    assert.deepEqual(assessGit(argv), { kind: 'allow' }, JSON.stringify(argv))
  }
})

test('empty argv (e.g. git --version) is allowed', () => {
  assert.deepEqual(assessGit([]), { kind: 'allow' })
  assert.deepEqual(assessGit(['--version']), { kind: 'allow' })
  assert.deepEqual(assessGit(['--help']), { kind: 'allow' })
})

test('leading global options are skipped to reach the subcommand', () => {
  assert.equal(assessGit(['-C', 'repo', 'clean', '-fdx']).kind, 'clean')
  assert.equal(assessGit(['-c', 'user.email=t@example.test', 'reset', '--hard']).kind, 'refuse')
  assert.equal(assessGit(['--git-dir=/repo/.git', 'clean', '-f']).kind, 'clean')
  assert.equal(assessGit(['--git-dir', '/repo/.git', '--no-pager', 'log']).kind, 'allow')
  assert.equal(assessGit(['--no-pager', 'status']).kind, 'allow')
})

test('history-destroying subcommands refuse', () => {
  for (const argv of [
    ['stash', 'clear'],
    ['stash', 'drop'],
    ['gc', '--prune=now'],
    ['gc', '--prune=all'],
    ['filter-branch', '--', '--all'],
    ['filter-repo', '--force'],
    ['push', '--force'],
    ['push', '-f'],
    ['push', '--force-with-lease'],
    ['push', '--force-with-lease=main:abc'],
    ['push', '--delete', 'origin', 'x'],
    ['push', '--mirror'],
    ['reset', '--hard'],
    ['reflog', 'expire', '--expire=now', '--all'],
  ]) {
    const r = assessGit(argv)
    assert.equal(r.kind, 'refuse', JSON.stringify(argv))
    assert.equal(typeof r.reason, 'string')
    assert.ok(r.reason.length > 0)
  }
})

test('non-destructive variants of the same subcommands stay allowed', () => {
  for (const argv of [
    ['stash'], ['stash', 'list'], ['stash', 'push'],
    ['push'], ['push', 'origin', 'main'],
    ['reset'], ['reset', '--soft', 'HEAD~1'],
    ['reflog', 'expire', '--expire=now'],
    ['reflog', 'expire', '--all'],
    ['reflog', 'delete', 'HEAD@{0}'],
    ['gc', '--auto'],
    ['clean'], ['clean', '-n'], ['clean', '--dry-run'], ['clean', '-f', '-n'],
  ]) {
    assert.equal(assessGit(argv).kind, 'allow', JSON.stringify(argv))
  }
})

test('clean with force is graded and reports ignored/dryRun flags', () => {
  assert.deepEqual(assessGit(['clean', '-f']), { kind: 'clean', force: true, ignored: false, dryRun: false })
  assert.deepEqual(assessGit(['clean', '-fdx']), { kind: 'clean', force: true, ignored: true, dryRun: false })
  assert.deepEqual(assessGit(['clean', '-fdX']), { kind: 'clean', force: true, ignored: true, dryRun: false })
  assert.deepEqual(assessGit(['clean', '--force']), { kind: 'clean', force: true, ignored: false, dryRun: false })
  assert.deepEqual(assessGit(['clean', '--force', '-x']), { kind: 'clean', force: true, ignored: true, dryRun: false })
})

test('restore/checkout/reset --hard with paths yield restore paths', () => {
  assert.deepEqual(assessGit(['restore', 'a.txt']), { kind: 'restore', paths: ['a.txt'] })
  assert.deepEqual(assessGit(['restore', '--', 'a', 'b']), { kind: 'restore', paths: ['a', 'b'] })
  assert.deepEqual(assessGit(['restore', '--staged', 'a.txt']), { kind: 'restore', paths: ['a.txt'] })
  assert.deepEqual(assessGit(['checkout', '--', 'a.txt']), { kind: 'restore', paths: ['a.txt'] })
  assert.deepEqual(assessGit(['checkout', '.' ]), { kind: 'restore', paths: ['.'] })
  assert.deepEqual(assessGit(['reset', '--hard', '--', 'a', 'b']), { kind: 'restore', paths: ['a', 'b'] })
})

test('reset --hard without a `--` pathspec is an L1 refusal (revision is not a path)', () => {
  // `git reset --hard <rev>` discards every uncommitted change; the rev word must not be
  // counted as a single path and allowed.
  for (const args of [['--hard'], ['--hard', 'HEAD~1'], ['--hard', 'origin/main'], ['--hard', 'HEAD'], ['--keep', 'HEAD~1'], ['--merge', 'main'], ['--hard', '--']]) {
    assert.equal(assessGit(['reset', ...args]).kind, 'refuse', JSON.stringify(args))
  }
  // Only a real `-- <paths>` form is a restore.
  assert.deepEqual(assessGit(['reset', '--hard', '--', 'a.txt']), { kind: 'restore', paths: ['a.txt'] })
  // A soft/mixed reset keeps the working tree.
  assert.equal(assessGit(['reset', '--soft', 'HEAD~1']).kind, 'allow')
  assert.equal(assessGit(['reset', 'HEAD~1']).kind, 'allow')
})

test('restore reading from a source commit refuses (path could come from any commit)', () => {
  assert.equal(assessGit(['restore', '--source=HEAD~1', 'a.txt']).kind, 'refuse')
  assert.equal(assessGit(['restore', '--source', 'HEAD~1', 'a.txt']).kind, 'refuse')
  assert.equal(assessGit(['restore', '-s', 'HEAD~1', 'a.txt']).kind, 'refuse')
  assert.equal(assessGit(['restore', '-sHEAD~1', 'a.txt']).kind, 'refuse')
  // Plain restore keeps path semantics.
  assert.deepEqual(assessGit(['restore', 'a.txt']), { kind: 'restore', paths: ['a.txt'] })
})

test('checkout distinguishes a working-tree path from a branch switch', () => {
  // Restore-like: `.`, a `:(...)` pathspec, or a Windows backslash path.
  for (const word of ['.', 'dir\\file', ':([0-9])']) {
    assert.deepEqual(assessGit(['checkout', word]), { kind: 'restore', paths: [word] }, word)
  }
  // Everything else is a branch/commit switch (a forward slash is common in branch names).
  for (const args of [['feature/x'], ['src/app.js'], ['main'], ['HEAD'], ['ab12cd3'], ['-b', 'feat'], ['-B', 'feat']]) {
    assert.equal(assessGit(['checkout', ...args]).kind, 'allow', JSON.stringify(args))
  }
  // KNOWN BOUNDARY: `checkout <single-file>` is an allow (not counted); use the counted
  // `git restore <path>` to discard a single file.
  assert.equal(assessGit(['checkout', 'src/app.js']).kind, 'allow')
  assert.deepEqual(assessGit(['restore', 'src/app.js']), { kind: 'restore', paths: ['src/app.js'] })
})

test('restore/checkout with no path refuses (empty target set is not silently allowed)', () => {
  assert.equal(assessGit(['restore']).kind, 'refuse')
  assert.equal(assessGit(['restore', '--']).kind, 'refuse')
  assert.equal(assessGit(['checkout', '--']).kind, 'refuse')
})

test('branch switching is not a restore (checkout without -- is allowed)', () => {
  assert.equal(assessGit(['checkout', 'main']).kind, 'allow')
  assert.equal(assessGit(['checkout', '-b', 'new']).kind, 'allow')
})

test('worktree remove yields path/force; missing path refuses', () => {
  assert.deepEqual(assessGit(['worktree', 'remove', '../wt']), { kind: 'worktree-remove', path: '../wt', force: false })
  assert.deepEqual(assessGit(['worktree', 'remove', '-f', '../wt']), { kind: 'worktree-remove', path: '../wt', force: true })
  assert.deepEqual(assessGit(['worktree', 'remove', '--force', '../wt']), { kind: 'worktree-remove', path: '../wt', force: true })
  assert.deepEqual(assessGit(['worktree', 'remove', '--', '../wt']), { kind: 'worktree-remove', path: '../wt', force: false })
  assert.equal(assessGit(['worktree', 'remove']).kind, 'refuse')
})

test('dynamic (non-literal) arguments refuse rather than guess', () => {
  assert.equal(assessGit(['clean', null]).kind, 'refuse')
  assert.equal(assessGit([null]).kind, 'refuse')
  assert.equal(assessGit(['restore', null]).kind, 'refuse')
  assert.equal(assessGit('not-an-array').kind, 'refuse')
})

test('reasons are English ASCII', () => {
  const reasons = [
    assessGit(['reset', '--hard']).reason,
    assessGit(['push', '--force']).reason,
    assessGit(['worktree', 'remove']).reason,
    assessGit(['clean', null]).reason,
  ]
  for (const reason of reasons) assert.match(reason, /^[\x20-\x7e]+$/)
})
