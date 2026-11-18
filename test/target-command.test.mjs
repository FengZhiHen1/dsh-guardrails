import assert from 'node:assert/strict'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { resolveCommand } from '../src/adapter/analysis/commands.js'
import { collectEvidence } from '../src/adapter/evidence/index.js'
import { decide } from '../src/core/decision.js'

function command(executable, args, unit = {}) {
  const operations = []
  const children = []
  const candidates = []
  const gaps = []
  const commands = []
  const base = { context: { domain: 'host', platform: 'linux', cwd: '/fixture' }, origin: { entry: 'fixture' }, ...unit }
  const env = {
    operation(action, target, options) { operations.push({ action, target, ...options }) },
    child(input) { children.push(input) },
    candidate(kind, reason) { candidates.push({ kind, reason }) },
    gap(kind) { gaps.push(kind) },
    // Mirrors the pipeline env.command: nested command facts re-enter the catalog.
    command(name, commandArgs, opts = {}) { resolveCommand(name, commandArgs, { ...base, ...opts }, env) },
    step() {},
  }
  resolveCommand(executable, args, base, env)
  return { operations, children, candidates, gaps, commands }
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

// --- coverage additions: find (F-01/F-02) -------------------------------------

test('find -delete scopes the matched pattern to the find root', () => {
  const direct = command('find', ['.', '-name', '*.log', '-delete'])
  assert.equal(direct.operations[0].action, 'delete')
  assert.deepEqual(direct.operations[0].target, { kind: 'pattern', base: '/fixture', pattern: '*.log', dialect: 'posix' })
  assert.equal(direct.operations[0].recursive, true)
  const absolute = command('find', ['/var/log', '-maxdepth', '2', '-name', '*.tmp', '-delete'])
  assert.deepEqual(absolute.operations[0].target, { kind: 'pattern', base: '/var/log', pattern: '*.tmp', dialect: 'posix' })
})

test('find delete with an unresolvable root keeps knownScope', () => {
  const result = command('find', ['relative-dir', '-delete'], { context: { domain: 'host', platform: 'linux' } })
  assert.deepEqual(result.operations[0].target, { kind: 'unknown', reason: 'find-base-unresolved', knownScope: ['relative-dir'] })
})

test('find without a destructive action stays untouched', () => {
  for (const args of [['.', '-name', '*.ts'], ['/tmp', '-maxdepth', '1', '-type', 'd'], ['.', '-name', '*.log', '-print']]) {
    const result = command('find', args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
})

test('find -exec rm becomes a dynamic deletion with the find root as scope', () => {
  const plus = command('find', ['.', '-exec', 'rm', '-rf', '{}', '+'])
  assert.equal(plus.operations[0].action, 'delete')
  assert.deepEqual(plus.operations[0].target, { kind: 'unknown', reason: 'find-exec-targets', knownScope: ['/fixture'] })
  const escaped = command('find', ['.', '-name', '*.tmp', '-exec', 'rm', '-f', '{}', null])
  assert.deepEqual(escaped.operations[0].target, { kind: 'unknown', reason: 'find-exec-targets', knownScope: ['/fixture'] })
  assert.deepEqual(escaped.gaps, [])
})

test('find -exec of other programs or prompts never deletes', () => {
  const listing = command('find', ['.', '-exec', 'ls', '{}', '+'])
  assert.deepEqual(listing.operations, [])
  assert.ok(listing.gaps.includes('unmodeled-command'))
  assert.deepEqual(command('find', ['.', '-exec', 'echo', '{}', ';']).operations, [])
  const interactive = command('find', ['.', '-exec', 'rm', '-i', '{}', ';'])
  assert.deepEqual(interactive.operations, [])
  assert.ok(interactive.gaps.includes('command-options'))
})

/** Decision-level check over harness operations: run the evidence adapter and the
 * pure decision point without touching the fixture filesystem. */
async function decideOperations(operations, candidates = []) {
  const evidence = await collectEvidence(
    { status: 'complete', operations, candidates, gaps: [] },
    { isProtectedPath: () => false },
  )
  return decide(evidence, {})
}

test('find with a dynamic predicate keeps the start scope and confirms dynamically', async () => {
  const result = command('find', ['.', '-name', null, '-delete'])
  assert.equal(result.operations[0].action, 'delete')
  assert.deepEqual(result.operations[0].target, { kind: 'unknown', reason: 'find-predicate-unresolved', knownScope: ['/fixture'] })
  assert.equal(result.operations[0].recursive, true)
  assert.deepEqual(result.candidates, [])
  const decision = await decideOperations(result.operations)
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'data.delete.dynamic')
})

test('find with a dynamic start point becomes an unverified-effect candidate', async () => {
  const result = command('find', [null, '-name', '*.log', '-delete'])
  assert.deepEqual(result.operations, [])
  assert.equal(result.candidates[0]?.kind, 'unverified-effect')
  assert.equal(result.candidates[0]?.knownScope, undefined)
  const decision = await decideOperations(result.operations, result.candidates)
  assert.equal(decision.kind, 'deny')
  assert.equal(decision.ruleId, 'execution.unverified-effect')
})

test('find deletion tiers survive the scope fallback (regression)', async () => {
  const pattern = command('find', ['.', '-name', '*.log', '-delete'])
  assert.deepEqual(pattern.operations[0].target, { kind: 'pattern', base: '/fixture', pattern: '*.log', dialect: 'posix' })
  const decision = await decideOperations(pattern.operations)
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'data.delete.dynamic')
  const plain = command('find', ['.', '-name', '*.ts'])
  assert.deepEqual(plain.operations, [])
  assert.deepEqual(plain.candidates, [])
})

// --- coverage additions: xargs / parallel (F-03, D5) ---------------------------

test('xargs and parallel with a literal destructive argv keep the stream scope', () => {
  const piped = command('xargs', ['rm', '-rf'])
  assert.equal(piped.operations[0].action, 'delete')
  assert.deepEqual(piped.operations[0].target, { kind: 'unknown', reason: 'stream-fed-targets', knownScope: ['stdin stream', 'rm -rf'] })
  const parallel = command('parallel', ['rm', '-rf', ':::', 'a', 'b'])
  assert.deepEqual(parallel.operations[0].target, { kind: 'unknown', reason: 'stream-fed-targets', knownScope: ['stdin stream', 'rm -rf'] })
  const forced = command('xargs', ['-0', 'rm', '-f'])
  assert.deepEqual(forced.operations[0].target.knownScope, ['stdin stream', 'rm -f'])
})

test('xargs and parallel never treat dynamic or read-only inner commands as deletions', () => {
  for (const [name, args] of [['xargs', ['echo']], ['xargs', ['wc', '-l']], ['parallel', ['ls', ':::', 'a', 'b']]]) {
    const result = command(name, args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
  const dynamic = command('xargs', [null, '-rf'])
  assert.deepEqual(dynamic.operations, [])
  assert.deepEqual(dynamic.candidates, [])
  assert.ok(dynamic.gaps.includes('unmodeled-command'))
})

// --- coverage additions: shred (F-04, lead ruling) ------------------------------

test('shred always tiers as a deletion and lookup forms stay untouched', () => {
  assert.deepEqual(command('shred', ['-u', 'secret.txt']).operations[0].target, { kind: 'exact', paths: ['secret.txt'] })
  assert.deepEqual(command('shred', ['-fzu', 'note.md']).operations[0].target, { kind: 'exact', paths: ['note.md'] })
  assert.deepEqual(command('shred', ['-n', '1', 'file']).operations[0].target, { kind: 'exact', paths: ['file'] })
  assert.deepEqual(command('shred', ['--help']).operations, [])
  assert.deepEqual(command('shred', ['--help']).gaps, [])
  assert.deepEqual(command('shred', ['-n', '1']).gaps, ['command-options'])
  assert.deepEqual(command('shred', []).gaps, ['command-options'])
})

// --- coverage additions: rsync (F-05) -------------------------------------------

test('rsync --delete models the destination tree and honors -n', () => {
  const direct = command('rsync', ['-a', '--delete', 'src/', 'dst/'])
  assert.equal(direct.operations[0].action, 'delete')
  assert.deepEqual(direct.operations[0].target, { kind: 'subtree', root: 'dst/' })
  assert.equal(direct.operations[0].recursive, true)
  assert.deepEqual(direct.operations[0].details, { rsyncDelete: true })
  assert.deepEqual(command('rsync', ['--delete-during', 'src/', 'dst/']).operations[0].target, { kind: 'subtree', root: 'dst/' })
  assert.equal(command('rsync', ['-n', '--delete', 'src/', 'dst/']).operations[0].preview, true)
})

test('rsync without a delete flag or help output never deletes', () => {
  const plain = command('rsync', ['-a', 'src/', 'dst/'])
  assert.deepEqual(plain.operations, [])
  assert.deepEqual(plain.candidates, [])
  const help = command('rsync', ['--help'])
  assert.deepEqual(help.operations, [])
  assert.deepEqual(help.gaps, [])
})

// --- coverage additions: transparent wrappers (F-06, D5) ------------------------

test('transparent wrappers unwrap to the inner command without extra candidates', () => {
  for (const argv of [
    ['sudo', 'rm', '-rf', 'X'],
    ['timeout', '5', 'rm', '-rf', 'X'],
    ['nohup', 'rm', '-rf', 'X'],
    ['env', 'FOO=1', 'rm', '-rf', 'X'],
    ['command', 'rm', '-rf', 'X'],
    ['exec', 'rm', '-rf', 'X'],
    ['nice', '-n', '1', 'rm', '-rf', 'X'],
    ['stdbuf', '-oL', 'rm', '-rf', 'X'],
    ['sudo', 'env', 'FOO=1', 'timeout', '5', 'rm', '-rf', 'X'],
  ]) {
    const result = command(argv[0], argv.slice(1))
    assert.equal(result.operations[0]?.action, 'delete', JSON.stringify(argv))
    assert.deepEqual(result.operations[0]?.target, { kind: 'subtree', root: 'X' }, JSON.stringify(argv))
    assert.deepEqual(result.candidates, [], JSON.stringify(argv))
  }
})

test('wrapper chains with a dynamic inner program stay a gap without candidates', () => {
  const dynamic = command('sudo', [null, 'rm', '-rf', 'X'])
  assert.deepEqual(dynamic.operations, [])
  assert.deepEqual(dynamic.candidates, [])
  assert.ok(dynamic.gaps.includes('unmodeled-command'))
  const lookup = command('command', ['-v', 'rm'])
  assert.deepEqual(lookup.operations, [])
  assert.deepEqual(lookup.gaps, [])
})

test('non-destructive wrapper usage never produces operations or candidates', () => {
  for (const [name, args] of [['sudo', ['ls']], ['timeout', ['5', 'sleep', '1']], ['env', ['FOO=1', 'make']], ['command', ['echo', 'hi']]]) {
    const result = command(name, args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
})

// --- coverage additions: cmd inline (F-09..F-11) ---------------------------------

test('cmd inline delete family is modeled with cmd semantics', () => {
  const rmdir = command('cmd', ['/c', 'rmdir', '/s', '/q', 'build'])
  assert.equal(rmdir.operations[0].action, 'delete')
  assert.deepEqual(rmdir.operations[0].target, { kind: 'subtree', root: 'build' })
  assert.equal(rmdir.operations[0].recursive, true)
  assert.deepEqual(command('cmd', ['/c', 'rd', '/s', '/q', 'C:\\tmp\\x']).operations[0].target, { kind: 'subtree', root: 'C:\\tmp\\x' })
  assert.deepEqual(command('cmd', ['/c', 'rmdir', '/s', '/q', 'C:\\']).operations[0].target, { kind: 'subtree', root: 'C:\\' })
  assert.deepEqual(command('cmd', ['/c', 'del', '/f', '/q', 'a.txt']).operations[0].target, { kind: 'exact', paths: ['a.txt'] })
  const recursive = command('cmd', ['/c', 'del', '/s', '/q', '*.log'])
  assert.equal(recursive.operations[0].target.kind, 'unknown')
  assert.deepEqual(recursive.operations[0].target.knownScope, ['files matching *.log in the working directory tree (del /s)'])
  assert.deepEqual(command('cmd', ['/c', 'del', 'a.txt']).operations[0].target, { kind: 'exact', paths: ['a.txt'] })
  const segments = command('cmd', ['/c', 'del a.txt & del b.txt'])
  assert.deepEqual(segments.operations.map((op) => op.target.paths[0]), ['a.txt', 'b.txt'])
})

test('unmodeled cmd text stays a gap and never deletes', () => {
  for (const args of [['/c', 'echo', 'hi'], ['/c', 'dir', 'C:\\'], ['/c', 'ver'], ['/k', 'rmdir', '/s', '/q', 'X'], []]) {
    const result = command('cmd', args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
    assert.ok(result.gaps.includes('cmd-inline'), JSON.stringify(args))
  }
  const help = command('cmd', ['/c', 'del', '/?'])
  assert.deepEqual(help.operations, [])
  assert.ok(help.gaps.includes('command-options'))
})

// --- coverage additions: git subcommands (F-12..F-18) ----------------------------

test('git rm without --cached deletes worktree paths', () => {
  const recursive = command('git', ['rm', '-r', 'src/legacy'])
  assert.deepEqual(recursive.operations[0].target, { kind: 'subtree', root: 'src/legacy' })
  assert.equal(recursive.operations[0].recursive, true)
  assert.deepEqual(command('git', ['rm', 'a.txt', 'b.txt']).operations[0].target, { kind: 'exact', paths: ['a.txt', 'b.txt'] })
  assert.equal(command('git', ['rm', '-r', '--cached', '.']).operations.length, 0)
  assert.equal(command('git', ['rm', '-n', 'src/legacy']).operations.length, 0)
  assert.equal(command('git', ['rm']).operations.length, 0)
})

test('git branch -D and tag -d report the ref scope', () => {
  const branch = command('git', ['branch', '-D', 'feature'])
  assert.equal(branch.operations[0].action, 'git-restore')
  assert.deepEqual(branch.operations[0].target, { kind: 'unknown', reason: 'git-ref-scope', knownScope: ['refs/heads/feature'] })
  assert.equal(branch.operations[0].details.command, 'branch')
  const tag = command('git', ['tag', '--delete', 'v1'])
  assert.deepEqual(tag.operations[0].target, { kind: 'unknown', reason: 'git-ref-scope', knownScope: ['refs/tags/v1'] })
  assert.equal(tag.operations[0].details.command, 'tag')
  for (const args of [['branch', '-d', 'merged-branch'], ['branch', 'newfeat'], ['branch'], ['branch', '-a'],
    ['tag', 'v1.2.0'], ['tag'], ['tag', '-l']]) {
    assert.deepEqual(command('git', args).operations, [], JSON.stringify(args))
  }
})

test('git checkout discards are scoped by pathspec or state', () => {
  assert.deepEqual(command('git', ['checkout', '--', 'src/a.js']).operations[0].target, { kind: 'exact', paths: ['src/a.js'] })
  assert.deepEqual(command('git', ['checkout', 'HEAD', '--', 'src/app.ts']).operations[0].target, { kind: 'exact', paths: ['src/app.ts'] })
  const force = command('git', ['checkout', '--force', 'other-branch'])
  assert.equal(force.operations[0].action, 'git-restore')
  assert.deepEqual(force.operations[0].target, {
    kind: 'unknown', reason: 'git-state-scope',
    knownScope: ['working tree (branch switch discards local changes)'],
  })
  assert.equal(command('git', ['checkout', '-f', 'main']).operations.length, 1)
  for (const args of [['checkout', 'main'], ['checkout', '-b', 'newfeat'], ['checkout', '--orphan', 'x'],
    ['checkout', '--force', '--merge', 'main'], ['switch', 'main'], ['switch', '-c', 'feat'],
    ['reset'], ['reset', '--soft', 'HEAD~1']]) {
    assert.deepEqual(command('git', args).operations, [], JSON.stringify(args))
  }
})

test('git switch --discard-changes and reset --merge report the state scope', () => {
  const sw = command('git', ['switch', '--discard-changes', 'main'])
  assert.deepEqual(sw.operations[0].target, {
    kind: 'unknown', reason: 'git-state-scope',
    knownScope: ['working tree (branch switch discards local changes)'],
  })
  assert.equal(sw.operations[0].details.command, 'switch')
  assert.deepEqual(command('git', ['switch', '--force', 'main']).operations[0].target.reason, 'git-state-scope')
  const reset = command('git', ['reset', '--merge', 'HEAD~1'])
  assert.deepEqual(reset.operations[0].target, { kind: 'unknown', reason: 'git-state-scope', knownScope: ['merge state / uncommitted changes'] })
  assert.equal(reset.operations[0].details.command, 'reset')
  assert.equal(command('git', ['reset', '--merge']).operations.length, 1)
  // Existing behavior regression guards (D6).
  assert.equal(command('git', ['merge', '--ff-only', 'main']).operations.length, 0)
  assert.equal(command('git', ['reflog']).operations.length, 0)
  assert.equal(command('git', ['status']).operations.length, 0)
  assert.equal(command('git', ['reset', '--hard']).operations[0].action, 'git-history-destroy')
})

// --- coverage additions: tilde (F-24) ---------------------------------------------

test('tilde operands expand to the host home directory', () => {
  const home = os.homedir()
  const win = { context: { domain: 'host', platform: 'win32', cwd: 'C:\\fixture' } }
  const remove = command('rm', ['-rf', '~/proj'], win)
  assert.deepEqual(remove.operations[0].target, { kind: 'subtree', root: path.win32.join(home, 'proj') })
  const read = command('Get-Content', ['~/.aws/credentials'], { ...win, powershell: true })
  assert.equal(read.operations[0].action, 'read-content')
  assert.deepEqual(read.operations[0].target, { kind: 'exact', paths: [path.win32.join(home, '.aws', 'credentials')] })
  const posix = command('cat', ['~/.aws/credentials'])
  assert.deepEqual(posix.operations[0].target, { kind: 'exact', paths: [path.posix.join(home, '.aws', 'credentials')] })
})

test('tilde-user forms and a quoted tilde never expand to the home directory', () => {
  const user = command('rm', ['-rf', '~bob/x'])
  assert.ok(user.gaps.includes('tilde-user'))
  assert.equal(user.operations[0].target.kind, 'unknown')
  const quoted = command('cat', ['~/.aws/credentials'], {
    context: { domain: 'host', platform: 'linux', cwd: '/fixture' },
    literalOperands: [true],
  })
  assert.deepEqual(quoted.operations[0].target, { kind: 'exact', paths: ['~/.aws/credentials'] })
})

// --- coverage additions: non-host domain (F-33, D2) -------------------------------

test('non-host domain deletions avoid host targets and list the domain scope', () => {
  const wsl = command('rm', ['-rf', '/tmp/x'], { context: { domain: 'wsl', platform: 'linux', cwd: '/tmp' } })
  assert.deepEqual(wsl.operations[0].target, { kind: 'unknown', reason: 'non-host-domain', knownScope: ['wsl: /tmp/x (recursive)'] })
  const exact = command('rm', ['a.txt', 'b.txt'], { context: { domain: 'wsl', platform: 'linux', cwd: '/tmp' } })
  assert.deepEqual(exact.operations[0].target, { kind: 'unknown', reason: 'non-host-domain', knownScope: ['wsl: a.txt', 'wsl: b.txt'] })
  const bare = command('rm', ['-rf'], { context: { domain: 'wsl', platform: 'linux', cwd: '/tmp' } })
  assert.deepEqual(bare.operations, [])
  assert.ok(bare.gaps.includes('command-options'))
  assert.deepEqual(command('rm', ['-rf', '/tmp/x']).operations[0].target, { kind: 'subtree', root: '/tmp/x' })
})
