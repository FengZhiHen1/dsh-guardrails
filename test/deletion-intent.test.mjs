// Tests for the pure deletion-intent classifier.
// These assert real fail-closed behavior, including counterexamples that would
// otherwise slip through a name/keyword-only checker.

import test from 'node:test';
import assert from 'node:assert/strict';
import { assessCommands, DELETION_DOCTRINE } from '../src/core/deletion-intent.js';

/** Helper: build a parsed command IR entry. */
const cmd = (name, args, extra = {}) => ({ name, args, redirects: [], scope: 'script', ...extra });

test('POSIX rm yields a single non-recursive delete plan', () => {
  const { operations, denial } = assessCommands([cmd('rm', ['file.txt'], { dialect: 'bash', domain: 'host' })]);
  assert.equal(denial, undefined);
  assert.deepEqual(operations, [
    { action: 'delete', path: 'file.txt', recursive: false, domain: 'host', commandName: 'rm', dialect: 'bash' },
  ]);
});

test('POSIX rm -rf is recursive and keeps every operand', () => {
  const { operations, denial } = assessCommands([cmd('rm', ['-rf', 'a', 'b'], { dialect: 'bash' })]);
  assert.equal(denial, undefined);
  assert.equal(operations.length, 2);
  assert.ok(operations.every((op) => op.recursive === true && op.action === 'delete'));
  assert.deepEqual(operations.map((op) => op.path), ['a', 'b']);
});

test('POSIX rm with a dynamic target survives as path:null + unknown, and denies', () => {
  const { operations, denial } = assessCommands([cmd('rm', [null], { dialect: 'bash' })]);
  // Intent is preserved as a null-path delete plan, but a dynamic target denies.
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-DYNAMIC-ARGUMENT');
  assert.equal(operations.length, 1);
  assert.equal(operations[0].path, null);
  assert.equal(operations[0].unknown, 'dynamic-path');
  assert.equal(operations[0].action, 'delete');
});

test('rmdir and unlink (POSIX) yield delete plans', () => {
  const a = assessCommands([cmd('rmdir', ['empty-dir'], { dialect: 'bash' })]);
  const b = assessCommands([cmd('unlink', ['link'], { dialect: 'bash' })]);
  assert.equal(a.operations[0].path, 'empty-dir');
  assert.equal(a.operations[0].commandName, 'rmdir');
  assert.equal(b.operations[0].path, 'link');
});

test('PowerShell Remove-Item / ri / del / erase / rd use PS grammar under powershell dialect', () => {
  for (const name of ['Remove-Item', 'ri', 'del', 'erase', 'rd']) {
    const { operations, denial } = assessCommands([cmd(name, ['-LiteralPath', 'x', '-Recurse'], { dialect: 'powershell' })]);
    assert.equal(denial, undefined, `${name} should classify`);
    assert.equal(operations.length, 1);
    assert.equal(operations[0].path, 'x');
    assert.equal(operations[0].recursive, true);
    assert.equal(operations[0].commandName, name.toLowerCase());
  }
});

test('PowerShell Remove-Item positional path with -Confirm only still yields intent', () => {
  const { operations, denial } = assessCommands([cmd('Remove-Item', ['target', '-Confirm'], { dialect: 'powershell' })]);
  assert.equal(denial, undefined);
  assert.equal(operations[0].path, 'target');
});

test('PowerShell rm is Remove-Item, not GNU rm: -Recurse works, GNU-only -rf is refused', () => {
  const ok = assessCommands([cmd('rm', ['-Recurse', 'dir'], { dialect: 'powershell' })]);
  assert.equal(ok.denial, undefined);
  assert.equal(ok.operations[0].recursive, true);
  // -rf is not a PowerShell switch; refusing it proves we are NOT treating PS rm as GNU rm.
  const bad = assessCommands([cmd('rm', ['-rf', 'dir'], { dialect: 'powershell' })]);
  assert.equal(bad.denial?.kind, 'deny');
  assert.equal(bad.denial?.ruleId, 'DI-UNSUPPORTED-OPTION');
});

test('PowerShell parameter abbreviation is refused (cannot prove unique)', () => {
  const { denial } = assessCommands([cmd('Remove-Item', ['-Rec', 'x'], { dialect: 'powershell' })]);
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-UNSUPPORTED-OPTION');
});

test('dialect-ambiguous alias without a dialect denies', () => {
  const { denial } = assessCommands([cmd('rm', ['x'])]);
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-AMBIGUOUS-DIALECT');
});

test('rm without any operand denies (no provable target)', () => {
  const { denial } = assessCommands([cmd('rm', ['-rf'], { dialect: 'bash' })]);
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-NO-TARGET');
});

test('unknown POSIX rm option is refused', () => {
  const { denial } = assessCommands([cmd('rm', ['--one-file-system', 'x'], { dialect: 'bash' })]);
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-UNSUPPORTED-OPTION');
});

test('rm --no-preserve-root is refused (safety-lowering switch)', () => {
  const { denial } = assessCommands([cmd('rm', ['--no-preserve-root', '-rf', '/'], { dialect: 'bash' })]);
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-UNSUPPORTED-OPTION');
});

test('custom path reusing a familiar basename is not trusted', () => {
  for (const name of ['/tmp/evil/rm', 'C:\\Temp\\rm.exe', './rm', 'bin/rm']) {
    const { denial } = assessCommands([cmd(name, ['-rf', '/'], { dialect: 'bash' })]);
    assert.equal(denial?.kind, 'deny', `${name} must deny`);
    assert.equal(denial?.ruleId, 'DI-UNTRUSTED-PATH');
  }
});

test('unknown program name is L3 allowed (v4), and still yields no operations', () => {
  // The catastrophe standard only gates recognisable deletion and execution channels;
  // an unmodelled program name passes through, but the gate records no delete evidence.
  for (const [name, args] of [['myCustomCleaner', ['--purge', 'x']], ['Test-Path', ['x']], ['Copy-Item', ['a', 'b']], ['whoami', []]]) {
    const r = assessCommands([cmd(name, args)]);
    assert.equal(r.denial, undefined, name);
    assert.deepEqual(r.operations, []);
  }
});

test('sync/copy deletion families are refused explicitly', () => {
  for (const [name, args] of [
    ['rsync', ['-a', '--delete', 'src/', 'dst/']],
    ['robocopy', ['src', 'dst', '/MIR']],
    ['xcopy', ['src', 'dst', '/s']],
  ]) {
    const { denial } = assessCommands([cmd(name, args)]);
    assert.equal(denial?.kind, 'deny', `${name} must deny`);
    assert.equal(denial?.ruleId, 'DI-UNSUPPORTED-COMMAND');
    assert.match(denial.reason, /cannot be proven|cannot clear/);
  }
});

test('git is graded, not refused: status/ordinary commands allow, destructive ones classify', () => {
  // v4: ordinary git operations are L3 allow — no denial, no operations.
  for (const args of [['status'], ['log', '--oneline'], ['add', '.'], ['commit', '-m', 'x']]) {
    const r = assessCommands([cmd('git', args)]);
    assert.equal(r.denial, undefined, JSON.stringify(args));
    assert.deepEqual(r.operations, []);
  }
  // History-destroying subcommands deny immediately with DI-GIT-REFUSE + doctrine.
  for (const args of [['reset', '--hard'], ['push', '--force'], ['stash', 'clear'], ['gc', '--prune=now'], ['clean', null]]) {
    const r = assessCommands([cmd('git', args)]);
    assert.equal(r.denial?.ruleId, 'DI-GIT-REFUSE', JSON.stringify(args));
    assert.ok(r.denial.reason.endsWith(DELETION_DOCTRINE));
  }
  // clean -f becomes a count-later operation, never an immediate refusal.
  const clean = assessCommands([cmd('git', ['clean', '-fdx'])]);
  assert.equal(clean.denial, undefined);
  assert.equal(clean.operations.length, 1);
  assert.equal(clean.operations[0].action, 'git-clean');
  assert.equal(clean.operations[0].ignored, true);
  // restore with paths becomes a count-later operation.
  const restore = assessCommands([cmd('git', ['restore', '--', 'a.txt'])]);
  assert.equal(restore.denial, undefined);
  assert.deepEqual(restore.operations[0].paths, ['a.txt']);
  assert.equal(restore.operations[0].action, 'git-restore');
  // worktree remove becomes a count-later operation with its path.
  const wt = assessCommands([cmd('git', ['worktree', 'remove', '-f', '../wt'])]);
  assert.equal(wt.denial, undefined);
  assert.equal(wt.operations[0].action, 'git-worktree-remove');
  assert.equal(wt.operations[0].path, '../wt');
  assert.equal(wt.operations[0].force, true);
});

test('find -delete / -exec and fd -x are refused', () => {
  for (const [name, args] of [['find', ['.', '-name', '*.tmp', '-delete']], ['find', ['.', '-exec', 'rm', '{}', ';']], ['fd', ['-x', 'rm', '{}']]]) {
    const { denial } = assessCommands([cmd(name, args)]);
    assert.equal(denial?.kind, 'deny');
    assert.equal(denial?.ruleId, 'DI-UNSUPPORTED-COMMAND');
  }
});

test('shell hosts (sh/bash/pwsh/cmd) still refused at core; language runtimes allow scripts but inline code denies', () => {
  // Shell interpreters remain refused at the core layer (the adapter analyzes a literal
  // script file before this layer; a bare host or unproven script still denies here).
  for (const [name, args] of [
    ['sh', ['-c', 'rm -rf x']],
    ['bash', ['-c', 'rm -rf x']],
    ['pwsh', ['-Command', 'Remove-Item -Recurse x']],
    ['cmd', ['/c', 'del /s x']],
  ]) {
    const { denial } = assessCommands([cmd(name, args)]);
    assert.equal(denial?.kind, 'deny', `${name} must deny`);
    assert.equal(denial?.ruleId, 'DI-UNSUPPORTED-COMMAND', name);
  }
  // Language runtimes with inline code still deny as inline code, not as an opaque host.
  for (const [name, args] of [
    ['node', ['-e', 'require("fs").rmSync("x",{recursive:true})']],
    ['python', ['-c', 'import shutil; shutil.rmtree("x")']],
  ]) {
    const { denial } = assessCommands([cmd(name, args)]);
    assert.equal(denial?.kind, 'deny', `${name} must deny`);
    assert.equal(denial?.ruleId, 'DI-INLINE-CODE', name);
  }
});

test('command lookup/replace wrappers are refused (env/xargs/sudo/timeout/start)', () => {
  for (const [name, args] of [['env', ['rm', '-rf', 'x']], ['xargs', ['rm']], ['sudo', ['rm', '-rf', 'x']], ['timeout', ['5', 'rm', 'x']], ['start', ['evil.exe']]]) {
    const { denial } = assessCommands([cmd(name, args)]);
    assert.equal(denial?.kind, 'deny');
    assert.equal(denial?.ruleId, 'DI-UNSUPPORTED-COMMAND');
  }
});

test('startup/source and Invoke-Expression are refused', () => {
  for (const [name, args] of [['source', ['setup.sh']], ['.', ['x.sh']], ['Invoke-Expression', ['Remove-Item x']], ['iex', ['rm x']]]) {
    const { denial } = assessCommands([cmd(name, args)]);
    assert.equal(denial?.kind, 'deny');
    assert.equal(denial?.ruleId, 'DI-UNSUPPORTED-COMMAND');
  }
});

test('disk destruction tools are refused', () => {
  for (const [name, args] of [['dd', ['if=/dev/zero', 'of=/dev/sda']], ['mkfs.ext4', ['/dev/sda1']], ['wipefs', ['-a', '/dev/sda']], ['shred', ['-u', 'x']], ['Format-Volume', ['-DriveLetter', 'D']]]) {
    const { denial } = assessCommands([cmd(name, args)]);
    assert.equal(denial?.kind, 'deny');
    assert.equal(denial?.ruleId, 'DI-UNSUPPORTED-COMMAND');
  }
});

test('parser-level unknown denies, but a known-delete plan is kept', () => {
  const { operations, denial } = assessCommands([cmd('rm', ['a.txt'], { dialect: 'bash' })], { unknown: ['Dynamic command or argument'] });
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-UNKNOWN-SEMANTICS');
  // Evidence is not swallowed: the delete intent survives.
  assert.equal(operations.length, 1);
  assert.equal(operations[0].action, 'delete');
  assert.equal(operations[0].path, 'a.txt');
});

test('control-flow unknown on an otherwise neutral command still denies', () => {
  const { denial } = assessCommands([cmd('echo', ['hi'], { dialect: 'bash' })], { unknown: ['Invocation of locally defined Bash function'] });
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-UNKNOWN-SEMANTICS');
});

test('neutral read-only commands pass with no operations', () => {
  for (const [name, args, dialect] of [
    ['echo', ['hello'], 'bash'],
    ['pwd', [], 'bash'],
    ['ls', ['-la'], 'bash'],
    ['cat', ['file.txt'], 'bash'],
    ['Write-Output', ['hi'], 'powershell'],
    ['Get-Location', [], 'powershell'],
    ['Get-ChildItem', ['-Recurse', '-File'], 'powershell'],
    ['Get-Content', ['-Raw', 'file.txt'], 'powershell'],
  ]) {
    const { operations, denial } = assessCommands([cmd(name, args, { dialect })]);
    assert.equal(denial, undefined, `${name} should pass: ${denial?.reason}`);
    assert.deepEqual(operations, []);
  }
});

test('printf is always allowed (v4 A3: it writes stdout, not files)', () => {
  for (const args of [['%s\n', 'x'], ['-v', 'var', 'x'], ['%n', 'a[$(rm -rf ~/victim) ]']]) {
    const r = assessCommands([cmd('printf', args, { dialect: 'bash' })]);
    assert.equal(r.denial, undefined, JSON.stringify(args));
    assert.deepEqual(r.operations, []);
  }
});

test('read-tool families are graded by their exact argv (v4 A3)', () => {
  // grep is always allowed, whatever its options.
  for (const args of [['-f', 'patterns', 'x'], ['-l', 'x']]) {
    assert.equal(assessCommands([cmd('grep', args)]).denial, undefined, JSON.stringify(args));
  }
  // rg refuses only --pre/--pre-glob.
  assert.equal(assessCommands([cmd('rg', ['--pre', 'evil', 'x'])]).denial?.ruleId, 'DI-UNSUPPORTED-COMMAND');
  assert.equal(assessCommands([cmd('rg', ['--pre=evil', 'x'])]).denial?.ruleId, 'DI-UNSUPPORTED-COMMAND');
  assert.equal(assessCommands([cmd('rg', ['--pre-glob', '*.py', 'x'])]).denial?.ruleId, 'DI-UNSUPPORTED-COMMAND');
  for (const args of [['pattern', 'x'], ['--hidden', 'x'], ['--preattach', 'x']]) {
    assert.equal(assessCommands([cmd('rg', args)]).denial, undefined, JSON.stringify(args));
  }
  // fd refuses only -x/-X/--exec/--exec-batch.
  for (const args of [['-x', 'rm', '{}'], ['-X', 'rm', '{}'], ['--exec', 'rm', '{}'], ['--exec-batch', 'rm', '{}']]) {
    assert.equal(assessCommands([cmd('fd', args)]).denial?.ruleId, 'DI-UNSUPPORTED-COMMAND', JSON.stringify(args));
  }
  assert.equal(assessCommands([cmd('fd', ['-e', 'py', 'x'])]).denial, undefined);
  // find refuses only -delete/-exec*/-ok*.
  for (const args of [['.', '-delete'], ['.', '-exec', 'rm', '{}', ';'], ['.', '-execdir', 'rm', '{}', ';'], ['.', '-ok', 'rm', '{}', ';'], ['.', '-okdir', 'rm', '{}', ';']]) {
    assert.equal(assessCommands([cmd('find', args)]).denial?.ruleId, 'DI-UNSUPPORTED-COMMAND', JSON.stringify(args));
  }
  for (const args of [['.', '-name', '*.tmp'], ['.', '-type', 'f'], ['-maxdepth', '2']]) {
    assert.equal(assessCommands([cmd('find', args)]).denial, undefined, JSON.stringify(args));
  }
});

test('a write redirection on a delete command denies, but keeps the delete evidence op', () => {
  for (const operator of ['>', '>>', '<>', '2>']) {
    for (const [name, args, dialect] of [
      ['rm', ['file'], 'bash'],
      ['Remove-Item', ['file'], 'powershell'],
    ]) {
      const { operations, denial } = assessCommands([cmd(name, args, { dialect, redirects: [{ operator, target: 'valuable' }] })]);
      assert.equal(denial?.kind, 'deny', `${name} ${operator}`);
      assert.equal(denial?.ruleId, 'DI-REDIRECTION', `${name} ${operator}`);
      // The known delete intent is still surfaced as evidence.
      assert.equal(operations.length, 1, `${name} ${operator}`);
      assert.equal(operations[0].action, 'delete');
    }
  }
});

test('neutral command contrast: same command passes without redirection, denies with one', () => {
  assert.equal(assessCommands([cmd('echo', ['hi'], { dialect: 'bash' })]).denial, undefined);
  assert.equal(
    assessCommands([cmd('echo', ['hi'], { dialect: 'bash', redirects: [{ operator: '>', target: 'x' }] })]).denial?.ruleId,
    'DI-REDIRECTION',
  );
});

test('a neutral value-option with a dynamic (null) value denies', () => {
  // Get-Content -Path <dynamic> cannot be proven; null must not silently pass.
  assert.equal(
    assessCommands([cmd('Get-Content', ['-Path', null], { dialect: 'powershell' })]).denial?.ruleId,
    'DI-DYNAMIC-ARGUMENT',
  );
});

test('Write-Output -NoEnumerate passes; a bogus -NoNewline for Write-Output denies', () => {
  assert.equal(assessCommands([cmd('Write-Output', ['-NoEnumerate', 'x'], { dialect: 'powershell' })]).denial, undefined);
  assert.equal(assessCommands([cmd('Write-Output', ['-NoNewline', 'x'], { dialect: 'powershell' })]).denial?.ruleId, 'DI-UNSUPPORTED-OPTION');
});

test('unmodelled PowerShell aliases are L3 allow (no deletion evidence)', () => {
  // v4: a read-only unmodelled alias name is allowed rather than refused. It still
  // produces no delete operations, so the gate never mistakes it for a deletion.
  for (const [name, args] of [['ls', ['-la']], ['cat', ['-n', 'x']]]) {
    const r = assessCommands([cmd(name, args, { dialect: 'powershell' })]);
    assert.equal(r.denial, undefined, name);
    assert.deepEqual(r.operations, []);
  }
});

test('POSIX names are case-sensitive: RM is not rm', () => {
  const upper = assessCommands([cmd('RM', ['-rf', 'x'], { dialect: 'bash' })]);
  // v4: an unmodelled program name is L3 allow, but it must NOT be read as `rm`,
  // so it yields no delete operation and no target.
  assert.equal(upper.denial, undefined);
  assert.deepEqual(upper.operations, []);
  // PowerShell names are case-insensitive aliases.
  const ps = assessCommands([cmd('REMOVE-ITEM', ['-Recurse', 'x'], { dialect: 'powershell' })]);
  assert.equal(ps.denial, undefined);
  assert.equal(ps.operations.length, 1);
});

test('PowerShell -Stream (ADS delete) and other unmodeled switches deny', () => {
  for (const opt of ['-Stream', '-Filter', '-Include', '-Exclude', '-Credential', '-Attributes']) {
    const { denial } = assessCommands([cmd('Remove-Item', ['-Path', 'x', opt, 'v'], { dialect: 'powershell' })]);
    assert.equal(denial?.kind, 'deny', `${opt} must deny`);
    assert.equal(denial?.ruleId, 'DI-UNSUPPORTED-OPTION', opt);
  }
});

test('PowerShell --% stop-parsing denies', () => {
  const { denial } = assessCommands([cmd('Remove-Item', ['--%', 'x'], { dialect: 'powershell' })]);
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-STOP-PARSING');
});

test('PowerShell -Recurse:$true denies (not silently a path)', () => {
  const { denial } = assessCommands([cmd('Remove-Item', ['-Recurse:$true', 'x'], { dialect: 'powershell' })]);
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-UNSUPPORTED-OPTION');
});

test('rmdir -p (parent removal) denies rather than simulating a recursive subtree', () => {
  const { denial } = assessCommands([cmd('rmdir', ['-p', 'a/b/c'], { dialect: 'bash' })]);
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-UNSUPPORTED-OPTION');
});

test('read-write open and clobber redirections deny', () => {
  for (const operator of ['<>', '>|', '&>', '2>&1', '>*']) {
    const command = cmd('pwd', [], { dialect: 'bash', redirects: [{ operator, target: 'f' }] });
    assert.equal(assessCommands([command]).denial?.ruleId, 'DI-REDIRECTION', operator);
  }
});

test('input-only redirection does not by itself deny a neutral command', () => {
  const command = cmd('cat', ['-u'], { dialect: 'bash', redirects: [{ operator: '<', target: 'in.txt' }] });
  assert.equal(assessCommands([command]).denial, undefined);
});

test('neutral command with a dynamic (null) operand denies', () => {
  const { denial } = assessCommands([cmd('echo', [null], { dialect: 'bash' })]);
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-DYNAMIC-ARGUMENT');
});

test('write redirection denies even on a neutral command', () => {
  const command = cmd('echo', ['x'], { dialect: 'bash', redirects: [{ operator: '>', target: 'out.txt' }] });
  const { denial } = assessCommands([command]);
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-REDIRECTION');
});

test('append and stderr redirection also deny', () => {
  for (const operator of ['>>', '2>', '&>']) {
    const command = cmd('pwd', [], { dialect: 'bash', redirects: [{ operator, target: 'log' }] });
    assert.equal(assessCommands([command]).denial?.ruleId, 'DI-REDIRECTION', operator);
  }
});

test('delete inside a non-script scope preserves intent but denies', () => {
  const { operations, denial } = assessCommands([cmd('rm', ['a.txt'], { dialect: 'bash', scope: 'CmdSubst' })]);
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-NONSCRIPT-SCOPE');
  assert.equal(operations.length, 1);
  assert.equal(operations[0].action, 'delete');
  assert.equal(operations[0].path, 'a.txt');
});

test('dynamic command name (null) denies', () => {  const { denial } = assessCommands([{ name: null, args: [], redirects: [], scope: 'script', dialect: 'bash' }]);
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-DYNAMIC-COMMAND');
});

test('WSL domain is carried onto operations', () => {
  const { operations } = assessCommands([cmd('rm', ['/home/u/x'], { dialect: 'bash', domain: 'wsl', distribution: 'Ubuntu', user: 'root' })]);
  assert.equal(operations[0].domain, 'wsl');
  assert.equal(operations[0].distribution, 'Ubuntu');
  assert.equal(operations[0].user, 'root');
});

test('cwd is carried onto operations', () => {
  const { operations } = assessCommands([cmd('rm', ['sub/x'], { dialect: 'bash', cwd: '/repo' })]);
  assert.equal(operations[0].cwd, '/repo');
});

test('mixed batch: a known delete plus a refusing command denies and keeps the plan as evidence', () => {
  const { operations, denial } = assessCommands([
    cmd('rm', ['a.txt'], { dialect: 'bash' }),
    cmd('find', ['.', '-delete']),
  ]);
  assert.equal(denial?.kind, 'deny');
  assert.equal(denial?.ruleId, 'DI-UNSUPPORTED-COMMAND');
  assert.equal(operations.length, 1);
  assert.equal(operations[0].path, 'a.txt');
});

test('mixed batch: a known delete plus an allowed unknown program keeps the plan and does not deny', () => {
  const { operations, denial } = assessCommands([
    cmd('rm', ['a.txt'], { dialect: 'bash' }),
    cmd('someOpaqueTool', ['whatever']),
  ]);
  assert.equal(denial, undefined);
  assert.equal(operations.length, 1);
  assert.equal(operations[0].path, 'a.txt');
});

test('empty command list is a pass with no operations', () => {
  assert.deepEqual(assessCommands([]), { operations: [] });
});

test('malformed input types throw (programming error, not a silent allow)', () => {
  assert.throws(() => assessCommands('nope'), TypeError);
  assert.throws(() => assessCommands([{ name: 'rm', args: 'nope' }]), TypeError);
  assert.throws(() => assessCommands([], { unknown: 'not-array' }), TypeError);
});

test('native program suffixes are never exempted as cmdlets/aliases', () => {
  for (const name of ['Remove-Item.exe', 'Write-Output.exe', 'rm.exe', 'rmdir.exe', 'GET-CONTENT.EXE', 'cleanup.com', 'wipe.cmd', 'run.bat']) {
    for (const dialect of ['powershell', 'bash', undefined]) {
      const { denial } = assessCommands([cmd(name, ['x'], { dialect })]);
      assert.equal(denial?.kind, 'deny', `${name} (${dialect}) must deny`);
      assert.equal(denial?.ruleId, 'DI-NATIVE-PROGRAM', `${name} (${dialect})`);
    }
  }
});

test('every deletion-related denial ends with the universal DELETION_DOCTRINE', () => {
  const cases = [
    assessCommands([cmd('rm', ['-x', 'y'], { dialect: 'bash' })]).denial,        // DI-UNSUPPORTED-OPTION on delete
    assessCommands([cmd('git', ['reset', '--hard'], { dialect: 'bash' })]).denial, // DI-GIT-REFUSE
    assessCommands([cmd('npx', ['x'], { dialect: 'bash' })]).denial,               // DI-UNSUPPORTED-COMMAND family
    assessCommands([cmd('rm', [], { dialect: 'bash' })]).denial,                // DI-NO-TARGET
    assessCommands([cmd('node', ['-e', 'x'])] ).denial,                         // DI-INLINE-CODE
    assessCommands([cmd('rm', ['x'], { dialect: 'bash' })], { unknown: ['dyn'] }).denial, // DI-UNKNOWN-SEMANTICS
  ];
  for (const denial of cases) {
    assert.match(denial.reason, /Use a clearer, supported command with explicit literal paths and supported options\./);
    assert.ok(denial.reason.endsWith(DELETION_DOCTRINE), `doctrine must be the final sentence: ${denial.reason}`);
    // Exactly once, no duplication.
    assert.equal(denial.reason.split(DELETION_DOCTRINE).length - 1, 1);
  }
});

test('returned reasons are English ASCII (tool-facing contract)', () => {
  const results = [
    assessCommands([cmd('git', ['reset', '--hard'])]),
    assessCommands([cmd('rm', ['-x', 'y'], { dialect: 'bash' })]),
    assessCommands([cmd('echo', ['x'], { dialect: 'bash' })], { unknown: ['dynamic'] }),
  ];
  for (const result of results) {
    if (result.denial) {
      assert.equal(result.denial.kind, 'deny');
      assert.match(result.denial.reason, /^[\x20-\x7e]+$/);
      assert.equal(typeof result.denial.ruleId, 'string');
    }
  }
});

// --- v2: pure -WhatIf preview semantics and provider-path rejection ---

test('a real Remove-Item -WhatIf is preview: ops preview:true + previewCommandIndexes, no denial', () => {
  const { operations, denial, previewCommandIndexes } = assessCommands([
    cmd('Remove-Item', ['-LiteralPath', 'x.txt', '-WhatIf'], { dialect: 'powershell' }),
  ]);
  assert.equal(denial, undefined);
  assert.equal(operations.length, 1);
  assert.equal(operations[0].preview, true);
  assert.equal(operations[0].path, 'x.txt');
  assert.deepEqual(previewCommandIndexes, [0]);
});

test('-WhatIf:$true is preview; -WhatIf:$false is not preview (still a real delete)', () => {
  const on = assessCommands([cmd('Remove-Item', ['x', '-WhatIf:$true'], { dialect: 'powershell' })]);
  assert.equal(on.operations[0].preview, true);
  assert.deepEqual(on.previewCommandIndexes, [0]);
  const off = assessCommands([cmd('Remove-Item', ['x', '-WhatIf:$false'], { dialect: 'powershell' })]);
  assert.equal(off.operations[0].preview, undefined);
  assert.equal(off.previewCommandIndexes, undefined);
});

test('-Confirm is NOT preview (a real deletion)', () => {
  for (const args of [['x', '-Confirm'], ['x', '-Confirm:$false'], ['-LiteralPath', 'x', '-Confirm:$true']]) {
    const { operations, previewCommandIndexes } = assessCommands([cmd('Remove-Item', args, { dialect: 'powershell' })]);
    assert.equal(operations[0].preview, undefined, JSON.stringify(args));
    assert.equal(previewCommandIndexes, undefined);
  }
});

test('a positional filename that is the literal string -WhatIf is a value, not a switch', () => {
  // As the value of -LiteralPath it is a filename, so this is a REAL delete, not preview.
  const literalValue = assessCommands([cmd('Remove-Item', ['-LiteralPath', '-WhatIf'], { dialect: 'powershell' })]);
  assert.equal(literalValue.operations[0].path, '-WhatIf');
  assert.equal(literalValue.operations[0].preview, undefined);
  assert.equal(literalValue.previewCommandIndexes, undefined);
  // As a positional operand after a path it is treated as a target name, still real.
  const positional = assessCommands([cmd('Remove-Item', ['x', '-WhatIf'], { dialect: 'powershell' })]);
  // Here -WhatIf is a genuine switch token, so this one IS preview; contrast with the value form.
  assert.equal(positional.operations.find(o => o.path === 'x').preview, true);
});

test('mixed real + preview: every op keeps evidence, only the preview index is listed', () => {
  const result = assessCommands([
    cmd('Remove-Item', ['real.txt'], { dialect: 'powershell' }),
    cmd('Remove-Item', ['preview.txt', '-WhatIf'], { dialect: 'powershell' }),
    cmd('Remove-Item', ['-LiteralPath', 'real2.txt'], { dialect: 'powershell' }),
  ]);
  assert.equal(result.denial, undefined);
  assert.equal(result.operations.length, 3);
  assert.deepEqual(result.previewCommandIndexes, [1]);
  const previewOp = result.operations.find(o => o.path === 'preview.txt');
  assert.equal(previewOp.preview, true);
  assert.equal(result.operations.find(o => o.path === 'real.txt').preview, undefined);
});

test('results without any preview do not gain a previewCommandIndexes field', () => {
  const result = assessCommands([cmd('Remove-Item', ['x'], { dialect: 'powershell' })]);
  assert.equal(Object.hasOwn(result, 'previewCommandIndexes'), false);
  assert.equal(result.operations[0].preview, undefined);
});

test('provider/scheme delete targets are rejected, including under -WhatIf preview', () => {
  for (const target of ['Registry::HKLM\\Software', 'HKLM:\\Soft', 'FileSystem::C:\\x', 'Variable:foo', 'C:rel']) {
    // real
    const real = assessCommands([cmd('Remove-Item', ['-LiteralPath', target], { dialect: 'powershell' })]);
    assert.equal(real.denial?.kind, 'deny', target);
    assert.equal(real.denial?.ruleId, 'DI-PROVIDER-PATH', target);
    // preview must still validate the provider path
    const preview = assessCommands([cmd('Remove-Item', ['-LiteralPath', target, '-WhatIf'], { dialect: 'powershell' })]);
    assert.equal(preview.denial?.ruleId, 'DI-PROVIDER-PATH', target);
  }
  // A provider path on a POSIX rm is also refused.
  assert.equal(
    assessCommands([cmd('rm', ['F::x'], { dialect: 'bash' })]).denial?.ruleId,
    'DI-PROVIDER-PATH',
  );
});

test('ordinary drive and relative delete targets remain allowed (control)', () => {
  for (const target of ['C:\\tmp\\x', 'D:/data/y', 'sub/file', 'file.txt']) {
    const r = assessCommands([cmd('Remove-Item', ['-LiteralPath', target], { dialect: 'powershell' })]);
    assert.equal(r.denial, undefined, target);
    assert.equal(r.operations[0].path, target);
  }
});

test('preview must be a certain literal host path: WSL/UNC/dynamic/tilde/wildcard deny', () => {
  // Non-host (wsl) preview denies (domain cannot be inventoried from here).
  assert.equal(
    assessCommands([cmd('Remove-Item', ['-LiteralPath', '/home/u/x', '-WhatIf'], { dialect: 'powershell', domain: 'wsl' })]).denial?.ruleId,
    'DI-PREVIEW-DOMAIN',
  );
  // UNC/network preview cannot be verified locally.
  for (const p of ['\\\\server\\share\\x', '//server/share/x']) {
    assert.equal(assessCommands([cmd('Remove-Item', ['-LiteralPath', p, '-WhatIf'], { dialect: 'powershell' })]).denial?.ruleId, 'DI-PREVIEW-UNPROVEN', p);
  }
  // Dynamic (null) preview target.
  assert.equal(assessCommands([cmd('Remove-Item', ['-LiteralPath', null, '-WhatIf'], { dialect: 'powershell' })]).denial?.ruleId, 'DI-PREVIEW-UNPROVEN');
  // Tilde-expanded and wildcard preview targets are not certain.
  assert.equal(assessCommands([cmd('Remove-Item', ['~/x', '-WhatIf'], { dialect: 'powershell' })]).denial?.ruleId, 'DI-PREVIEW-UNPROVEN');
  assert.equal(assessCommands([cmd('Remove-Item', ['C:\\d\\*.txt', '-WhatIf'], { dialect: 'powershell' })]).denial?.ruleId, 'DI-PREVIEW-UNPROVEN');
  // Provider path under preview is still the provider rule (checked first).
  assert.equal(assessCommands([cmd('Remove-Item', ['Registry::HKLM\\X', '-WhatIf'], { dialect: 'powershell' })]).denial?.ruleId, 'DI-PROVIDER-PATH');
});

test('a certain literal host-path preview is accepted as preview (control)', () => {
  for (const p of ['C:\\data\\x.txt', 'sub/file.txt']) {
    const r = assessCommands([cmd('Remove-Item', ['-LiteralPath', p, '-WhatIf'], { dialect: 'powershell', domain: 'host' })]);
    assert.equal(r.denial, undefined, p);
    assert.equal(r.operations[0].preview, true);
    assert.deepEqual(r.previewCommandIndexes, [0]);
  }
});

test('a real (non-preview) UNC/dynamic delete is NOT rejected by the preview rule (plan layer owns it)', () => {
  // Without -WhatIf these are real deletes: intent keeps the op; plan/host decide. Not preview-denied here.
  const unc = assessCommands([cmd('Remove-Item', ['-LiteralPath', '\\\\server\\share\\x'], { dialect: 'powershell' })]);
  assert.equal(unc.denial, undefined);
  assert.equal(unc.operations[0].path, '\\\\server\\share\\x');
  assert.equal(unc.operations[0].preview, undefined);
});

// --- v3: language runtimes allowed; inline code denied ---

test('language runtimes with a script argument are allowed (no operations, no counting)', () => {
  const allowed = [
    ['node', ['script.mjs']],
    ['nodejs', ['build.js']],
    ['python', ['main.py']],
    ['python3', ['-m', 'pytest']],
    ['py', ['tool.py']],
    ['perl', ['run.pl']],
    ['ruby', ['app.rb']],
    ['php', ['index.php']],
    ['deno', ['run', 'main.ts']],
    ['bun', ['run', 'x.ts']],
    ['uv', ['run', 'x.py']],
  ];
  for (const [name, args] of allowed) {
    const r = assessCommands([cmd(name, args)]);
    assert.equal(r.denial, undefined, `${name} ${JSON.stringify(args)} should pass: ${r.denial?.reason}`);
    assert.deepEqual(r.operations, []);
  }
});

test('node --version and python -V pass (not inline)', () => {
  assert.equal(assessCommands([cmd('node', ['--version'])]).denial, undefined);
  assert.equal(assessCommands([cmd('python', ['-V'])]).denial, undefined);
});

test('inline-code switches deny with DI-INLINE-CODE for the matching runtimes', () => {
  const cases = [
    ['node', ['-e', 'x']],
    ['node', ['--eval', 'x']],
    ['node', ['-p', '1']],
    ['node', ['--print', '1']],
    ['node', ['-i']],
    ['node', ['--interactive']],
    ['python', ['-c', 'x']],
    ['perl', ['-e', 'x']],
    ['perl', ['-E', 'x']],
    ['ruby', ['-e', 'x']],
    ['php', ['-r', 'x']],
    ['node', ['-']], // read program from stdin
    ['python', ['-']],
  ];
  for (const [name, args] of cases) {
    const { denial } = assessCommands([cmd(name, args)]);
    assert.equal(denial?.kind, 'deny', `${name} ${JSON.stringify(args)}`);
    assert.equal(denial?.ruleId, 'DI-INLINE-CODE', `${name} ${JSON.stringify(args)}`);
    assert.ok(denial.reason.includes(DELETION_DOCTRINE));
  }
});

test('posix name case: uppercase NODE is not the allowed node runtime', () => {
  // `NODE` is not the `node` runtime, so it is not analysed as one: it must not deny as
  // inline code (which proves it was not recognised) and must yield no delete evidence.
  const upper = assessCommands([cmd('NODE', ['-e', 'x'], { dialect: 'bash' })]);
  assert.equal(upper.denial, undefined);
  assert.deepEqual(upper.operations, []);
  // The real runtime still refuses the same inline code.
  assert.equal(assessCommands([cmd('node', ['-e', 'x'], { dialect: 'bash' })]).denial?.ruleId, 'DI-INLINE-CODE');
});

test('path-qualified and native runtimes are still refused', () => {
  for (const name of ['C:\\\\tools\\\\node.exe', './node', '../node', 'bin/python']) {
    const r = assessCommands([cmd(name, ['script.mjs'], { dialect: 'bash' })]);
    assert.equal(r.denial?.kind, 'deny', name);
    assert.equal(r.denial?.ruleId, 'DI-UNTRUSTED-PATH', name);
  }
  // .exe native form is refused as a native program even for an allowed runtime name.
  assert.equal(assessCommands([cmd('node.exe', ['script.mjs'])]).denial?.ruleId, 'DI-NATIVE-PROGRAM');
});

test('npx remains refused; bash script file remains denied at the core layer', () => {
  assert.equal(assessCommands([cmd('npx', ['some-pkg'])]).denial?.ruleId, 'DI-UNSUPPORTED-COMMAND');
  const bash = assessCommands([cmd('bash', ['script.sh'], { dialect: 'bash' })]);
  assert.equal(bash.denial?.kind, 'deny');
  assert.equal(bash.denial?.ruleId, 'DI-UNSUPPORTED-COMMAND');
  assert.ok(bash.denial.reason.includes(DELETION_DOCTRINE));
});

// --- v4: move source deletion is counted (L2), copy stays allow (v28) ---

test('Move-Item sources become move-source operations (counted, not allowed)', () => {
  const single = assessCommands([cmd('Move-Item', ['-LiteralPath', 'a.txt', '-Destination', 'b.txt'], { dialect: 'powershell' })]);
  assert.equal(single.denial, undefined);
  assert.equal(single.operations.length, 1);
  assert.deepEqual({ action: single.operations[0].action, path: single.operations[0].path, recursive: single.operations[0].recursive },
    { action: 'move-source', path: 'a.txt', recursive: true });

  // 21 Move-Item commands (the live defect) => 21 move-source operations, no allow.
  const commands = [];
  for (let i = 0; i < 21; i += 1) commands.push(cmd('Move-Item', ['-LiteralPath', `f${i}.txt`, '-Destination', `d${i}.txt`], { dialect: 'powershell' }));
  const many = assessCommands(commands);
  assert.equal(many.denial, undefined);
  assert.equal(many.operations.length, 21);
  assert.ok(many.operations.every((op) => op.action === 'move-source'));
});

test('Move-Item aliases move/mi and positional/destination-order variants classify the source', () => {
  for (const name of ['Move-Item', 'move', 'mi']) {
    // Positional operands are all sources (PowerShell requires -Destination for the target).
    const positional = assessCommands([cmd(name, ['a.txt'], { dialect: 'powershell' })]);
    assert.deepEqual(positional.operations.map((op) => op.path), ['a.txt'], name);
    // -Destination before the source still identifies only the source.
    const destFirst = assessCommands([cmd(name, ['-Destination', 'b.txt', '-Path', 'a.txt'], { dialect: 'powershell' })]);
    assert.deepEqual(destFirst.operations.map((op) => op.path), ['a.txt'], `${name} dest-first`);
  }
});

test('Move-Item wildcard or dynamic source refuses (source set not enumerable)', () => {
  assert.equal(assessCommands([cmd('Move-Item', ['*.txt', '-Destination', 'dir'], { dialect: 'powershell' })]).denial?.ruleId, 'DI-UNSUPPORTED-COMMAND');
  assert.equal(assessCommands([cmd('Move-Item', ['-LiteralPath', null, '-Destination', 'x'], { dialect: 'powershell' })]).denial?.ruleId, 'DI-DYNAMIC-ARGUMENT');
  // Doctrine is attached to the refusal.
  assert.ok(assessCommands([cmd('Move-Item', ['*.txt', '-Destination', 'dir'], { dialect: 'powershell' })]).denial.reason.includes(DELETION_DOCTRINE));
});

test('mv sources become move-source operations (last operand is the destination)', () => {
  const one = assessCommands([cmd('mv', ['a', 'b'], { dialect: 'bash' })]);
  assert.deepEqual(one.operations.map((op) => op.path), ['a']);
  assert.equal(one.operations[0].action, 'move-source');
  // Multiple sources into a directory => one operation per source.
  const many = assessCommands([cmd('mv', ['a', 'b', 'c', 'dir/'], { dialect: 'bash' })]);
  assert.deepEqual(many.operations.map((op) => op.path), ['a', 'b', 'c']);
  // -t/--target-directory: every operand is a source.
  const t = assessCommands([cmd('mv', ['-t', 'dir', 'a', 'b'], { dialect: 'bash' })]);
  assert.deepEqual(t.operations.map((op) => op.path), ['a', 'b']);
  // `--` separates options; sources are words after it.
  const sep = assessCommands([cmd('mv', ['--', '-weird', 'dir'], { dialect: 'bash' })]);
  assert.deepEqual(sep.operations.map((op) => op.path), ['-weird']);
});

test('mv with a wildcard source refuses; mv is never treated as an unknown allow', () => {
  assert.equal(assessCommands([cmd('mv', ['*.txt', 'dir'], { dialect: 'bash' })]).denial?.ruleId, 'DI-UNSUPPORTED-COMMAND');
  // No-dialect mv must still be graded (not the L3 unknown allow): it yields move-source.
  const noDialect = assessCommands([cmd('mv', ['a', 'b'])]);
  assert.equal(noDialect.operations.length, 1);
  assert.equal(noDialect.operations[0].action, 'move-source');
});

test('copy / cp / Copy-Item keep their source and stay allow (no operation)', () => {
  for (const [name, args, dialect] of [
    ['cp', ['-r', 'a', 'b'], 'bash'],
    ['cp', ['a', 'b', 'dir/'], 'bash'],
    ['Copy-Item', ['-Path', 'a.txt', '-Destination', 'b.txt'], 'powershell'],
    ['copy', ['a', 'b'], 'powershell'],
  ]) {
    const r = assessCommands([cmd(name, args, { dialect })]);
    assert.equal(r.denial, undefined, `${name} ${JSON.stringify(args)}`);
    assert.deepEqual(r.operations, [], `${name} must not emit a move/delete operation`);
  }
});
