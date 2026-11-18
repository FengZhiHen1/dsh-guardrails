// target-shell — behavior tests for the routed shell analysis unit
// (src/adapter/analysis/shell.js + shell/*).
//
// Real trusted parsers (vendored shfmt 3.12.0, real pwsh helper) exercise the
// official-AST path; injected fake parser pools exercise budget, failure and
// lifecycle paths. Nothing here is executed: the analyzed text is data only.
// All filesystem targets are synthetic per-test temporary directories.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createShellAnalyzer } from '../src/adapter/analysis/shell.js';
import { resolveCommand } from '../src/adapter/analysis/commands.js';
import { createShellParsers } from '../src/adapter/parsers/index.mjs';

/** Create an analyzer plus an emitter recorder for one test. The analyzer's
 * parser pool is disposed when the test finishes so no helper process or stdio
 * handle outlives the test file (otherwise `node --test` never sees the child
 * test process exit). */
function harness(t, options = {}) {
  const calls = { command: [], operation: [], child: [], gap: [], candidate: [], steps: 0, order: [] };
  const env = {
    command: (executable, args, opts) => { calls.command.push({ executable, args, opts }); calls.order.push('command'); },
    operation: (action, target, opts) => { calls.operation.push({ action, target, opts }); calls.order.push('operation'); },
    child: (unit) => { calls.child.push(unit); calls.order.push('child'); },
    gap: (kind, origin) => calls.gap.push({ kind, origin }),
    candidate: (kind, reason, knownScope, origin) => calls.candidate.push({ kind, reason, knownScope, origin }),
    step: (count = 1) => { calls.steps += count; },
  };
  const analyzer = createShellAnalyzer(options);
  t.after(() => analyzer.dispose());
  return { analyzer, calls, env };
}

function shellUnit(text, overrides = {}) {
  return {
    unitId: 'u1',
    source: { kind: 'inline', text },
    language: 'bash',
    context: { domain: 'host' },
    origin: { tool: 'bash' },
    ...overrides,
  };
}

function gapKinds(calls) {
  return calls.gap.map((entry) => entry.kind);
}

function commandNamed(calls, name) {
  return calls.command.find((entry) => entry.executable === name);
}

/** Per-test temporary directory, resolved against 8.3 short-name quirks. */
async function tmpDir(t) {
  const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'gr-target-shell-')));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  return dir;
}

/** Spell a path with `/` separators so a POSIX-shell source keeps it literal. */
function shellPath(file) {
  return file.split(path.sep).join('/');
}

test('bash delete command is emitted as a typed command fact', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('rm -rf /srv/x'), env);
  const fact = commandNamed(calls, 'rm');
  assert.ok(fact, `expected rm fact, got ${JSON.stringify(calls.command)}`);
  assert.deepEqual(fact.args, ['-rf', '/srv/x']);
  assert.equal(fact.opts.condition, 'certain');
  assert.deepEqual(fact.opts.patterns, [false, false]);
  assert.deepEqual(fact.opts.dataArgs, [false, false]);
  assert.deepEqual(fact.opts.literalOperands, [false, false]);
  assert.equal(fact.opts.context.dialect, 'bash');
  assert.equal(fact.opts.context.domain, 'host');
  assert.deepEqual(fact.opts.origin, { tool: 'bash', commandIndex: 0, commandName: 'rm' });
  assert.deepEqual(gapKinds(calls), []);
  assert.deepEqual(calls.child, []);
});

test('bash -c inline script becomes a nested child unit and consumes the wrapper', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`bash -c 'rm -rf /srv/x'`), env);
  assert.deepEqual(gapKinds(calls), []);
  assert.deepEqual(calls.command, [], 'wrapper must be consumed, no duplicate fact');
  assert.equal(calls.child.length, 1);
  const child = calls.child[0];
  assert.equal(child.unitId, 'u1/0');
  assert.equal(child.source.kind, 'inline');
  assert.equal(child.source.text, 'rm -rf /srv/x');
  assert.equal(child.language, 'bash');
  assert.deepEqual(child.origin, { tool: 'bash', commandIndex: 0, commandName: 'bash' });
});

test('sh -c child uses the posix dialect', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`sh -c 'rm -f /srv/x'`), env);
  assert.equal(calls.child.length, 1);
  assert.equal(calls.child[0].language, 'posix');
});

test('wrapper redirect is emitted by the outer shell alongside the child unit', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`bash -c 'rm -f /srv/x' > /srv/log.txt`), env);
  assert.equal(calls.child.length, 1);
  assert.equal(calls.operation.length, 1);
  const op = calls.operation[0];
  assert.equal(op.action, 'truncate-content');
  assert.deepEqual(op.target, { kind: 'exact', paths: ['/srv/log.txt'] });
  assert.equal(op.opts.details.operator, '>');
  assert.deepEqual(op.opts.origin, { tool: 'bash', commandIndex: 0, commandName: 'bash' });
});

test('append and read redirections are typed; heredoc delimiters are not file targets', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('printf x >> /srv/app.log\ncat < /srv/in.txt\ncat <<EOF\nhello\nEOF'), env);
  const actions = calls.operation.map((entry) => entry.action);
  assert.ok(actions.includes('write-content'), `expected write-content, got ${JSON.stringify(actions)}`);
  assert.ok(actions.includes('read-content'), `expected read-content, got ${JSON.stringify(actions)}`);
  assert.ok(!calls.operation.some((entry) => entry.target?.paths?.[0] === 'EOF' || entry.target?.paths?.[0] === 'hello'), 'heredoc delimiter/body must not become a file target');
});

test('dynamic redirect target is an unknown target object', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('rm -f /srv/x > "$OUT"'), env);
  const op = calls.operation.find((entry) => entry.action !== 'read-content');
  assert.ok(op, `expected a write operation, got ${JSON.stringify(calls.operation)}`);
  assert.equal(op.target.kind, 'unknown');
  assert.ok(op.target.reason.length > 0);
  assert.ok(!op.target.reason.includes('$OUT'), 'reason must not echo raw source');
});

test('redirections are modeled before their owning invocation', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('rm -f /srv/x > /srv/log'), env);
  assert.deepEqual(calls.order, ['operation', 'command']);
});

test('PowerShell data text never reads as parameters or delete targets', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`Write-Output '--- label ---'`, { language: 'powershell' }), env);
  const fact = commandNamed(calls, 'Write-Output');
  assert.ok(fact, `expected Write-Output fact, got ${JSON.stringify(calls.command)}`);
  assert.deepEqual(fact.args, ['--- label ---']);
  assert.equal(fact.opts.powershell, true);
  assert.deepEqual(fact.opts.dataArgs, [true]);
  assert.equal(fact.opts.literalOperands, undefined, 'literalOperands is POSIX-only');
  assert.equal(fact.opts.condition, 'certain');
  assert.deepEqual(gapKinds(calls), []);
});

test('PowerShell delete with redirect emits command and truncate-content operation', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('Remove-Item C:/x -Recurse > C:/log.txt', { language: 'powershell' }), env);
  const fact = commandNamed(calls, 'Remove-Item');
  assert.ok(fact);
  assert.deepEqual(fact.args, ['C:/x', '-Recurse']);
  const op = calls.operation.find((entry) => entry.action === 'truncate-content');
  assert.ok(op, `expected truncate-content, got ${JSON.stringify(calls.operation)}`);
  assert.deepEqual(op.target, { kind: 'exact', paths: ['C:/log.txt'] });
});

test('PowerShell wildcard operand carries glob metadata', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`Get-ChildItem C:/ -Include '*.txt'`, { language: 'powershell' }), env);
  const fact = commandNamed(calls, 'Get-ChildItem');
  assert.ok(fact);
  assert.deepEqual(fact.args, ['C:/', '-Include', '*.txt']);
  assert.deepEqual(fact.opts.patterns, [false, false, true]);
});

test('unquoted POSIX glob is a pattern word; quoted glob stays literal', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('rm -rf *.txt\nrm -rf "*.txt"'), env);
  const facts = calls.command.filter((entry) => entry.executable === 'rm');
  assert.equal(facts.length, 2);
  assert.deepEqual(facts[0].args, ['-rf', '*.txt']);
  assert.deepEqual(facts[0].opts.patterns, [false, true]);
  assert.deepEqual(facts[1].args, ['-rf', '*.txt']);
  assert.deepEqual(facts[1].opts.patterns, [false, false], 'quoted glob is literal data in POSIX shells');
});

test('quoted hyphen value is marked as a literal operand', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`grep -- '-label' /srv/x`), env);
  const fact = commandNamed(calls, 'grep');
  assert.ok(fact);
  assert.deepEqual(fact.args, ['--', '-label', '/srv/x']);
  assert.deepEqual(fact.opts.literalOperands, [false, true, false]);
});

test('data positions are marked for echo, git -m and grep -e', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`git commit -m 'rm -rf /'\ngrep -e 'rm -rf' /srv/x\necho rm -rf /srv/x`), env);
  const git = commandNamed(calls, 'git');
  assert.deepEqual(git.opts.dataArgs, [false, false, true]);
  const grep = commandNamed(calls, 'grep');
  assert.deepEqual(grep.opts.dataArgs, [false, true, false]);
  const echo = commandNamed(calls, 'echo');
  assert.deepEqual(echo.opts.dataArgs, [true, true, true]);
});

test('loop body commands are condition "possible" and the control flow is a gap', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('for f in a b; do rm -rf "$f"; done'), env);
  const fact = commandNamed(calls, 'rm');
  assert.ok(fact);
  assert.equal(fact.opts.condition, 'possible');
  assert.ok(gapKinds(calls).includes('control-flow'));
});

test('PowerShell gated top-level scope is condition "unknown" with a control-flow gap', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('if ($true) { Remove-Item C:/x }', { language: 'powershell' }), env);
  const fact = commandNamed(calls, 'Remove-Item');
  assert.ok(fact);
  assert.equal(fact.opts.condition, 'unknown');
  assert.ok(gapKinds(calls).includes('control-flow'));
});

test('PowerShell invoked scriptblock scope is condition "possible"', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('& { Remove-Item C:/x }', { language: 'powershell' }), env);
  const fact = commandNamed(calls, 'Remove-Item');
  assert.ok(fact);
  assert.equal(fact.opts.condition, 'possible');
});

test('literal cd into a verified directory refines context.cwd for later commands', async (t) => {
  const { analyzer, calls, env } = harness(t);
  const dir = await tmpDir(t);
  const sub = path.join(dir, 'sub');
  await fs.mkdir(sub);
  await analyzer.analyze(shellUnit('cd sub\nrm -rf x', { context: { domain: 'host', cwd: dir } }), env);
  const fact = commandNamed(calls, 'rm');
  assert.ok(fact);
  assert.equal(fact.opts.context.cwd, sub);
  assert.deepEqual(gapKinds(calls), []);
});

test('WSL-routed units keep POSIX cwd semantics and preserve distribution/user', async (t) => {
  const { analyzer, calls, env } = harness(t);
  const unit = shellUnit('rm -rf /srv/x', {
    context: { domain: 'wsl', cwd: '/srv/app', platform: 'linux', distribution: 'Ubuntu', user: 'dev' },
  });
  await analyzer.analyze(unit, env);
  const fact = commandNamed(calls, 'rm');
  assert.ok(fact);
  assert.equal(fact.opts.context.cwd, '/srv/app', 'a POSIX absolute cwd stays provable on a Windows host');
  assert.equal(fact.opts.context.platform, 'linux');
  assert.equal(fact.opts.context.distribution, 'Ubuntu');
  assert.equal(fact.opts.context.user, 'dev');
  assert.deepEqual(gapKinds(calls), []);
});

test('an unprovable cd removes the provable cwd from later facts', async (t) => {
  const { analyzer, calls, env } = harness(t);
  const dir = await tmpDir(t);
  await analyzer.analyze(shellUnit('cd missing_dir\nrm -rf x', { context: { domain: 'host', cwd: dir } }), env);
  const fact = commandNamed(calls, 'rm');
  assert.ok(fact);
  assert.equal(fact.opts.context.cwd, undefined, 'cwd must not be retained after an unprovable cd');
  assert.ok(gapKinds(calls).includes('state-mutation'));
});

test('a subshell cd does not propagate into the parent and is not a gap', async (t) => {
  const { analyzer, calls, env } = harness(t);
  const dir = await tmpDir(t);
  await analyzer.analyze(shellUnit('(cd sub)\nrm -rf x', { context: { domain: 'host', cwd: dir } }), env);
  const fact = commandNamed(calls, 'rm');
  assert.ok(fact);
  assert.equal(fact.opts.context.cwd, dir, 'parent cwd stays provable');
  assert.deepEqual(gapKinds(calls), []);
});

test('commands inside a subshell have no provable cwd', async (t) => {
  const { analyzer, calls, env } = harness(t);
  const dir = await tmpDir(t);
  await analyzer.analyze(shellUnit('(cd sub; rm -rf x)', { context: { domain: 'host', cwd: dir } }), env);
  const fact = commandNamed(calls, 'rm');
  assert.ok(fact);
  assert.equal(fact.opts.context.cwd, undefined, 'subshell cwd is untracked');
  assert.deepEqual(gapKinds(calls), []);
});

test('state-mutating commands are visible facts with a state-mutation gap', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`source ./env.sh\nrm -f /srv/x`), env);
  assert.ok(commandNamed(calls, 'source'), 'source must stay visible');
  assert.ok(commandNamed(calls, 'rm'));
  assert.ok(gapKinds(calls).includes('state-mutation'));
});

test('pwsh -NoProfile -Command becomes a powershell child with no gaps', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`pwsh -NoProfile -Command 'Remove-Item /srv/x'`), env);
  assert.deepEqual(calls.command, [], 'wrapper consumed');
  assert.equal(calls.child.length, 1);
  assert.equal(calls.child[0].language, 'powershell');
  assert.equal(calls.child[0].source.text, 'Remove-Item /srv/x');
  assert.deepEqual(gapKinds(calls), []);
});

test('nested pwsh without -NoProfile still extracts the child and flags the profile', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`pwsh -Command 'Remove-Item /srv/x'`), env);
  assert.equal(calls.child.length, 1);
  assert.ok(gapKinds(calls).includes('pwsh-profile'));
});

test('pwsh -File stays a direct command fact for the shared catalog', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('pwsh -NoProfile -File C:/x/clean.ps1'), env);
  const fact = commandNamed(calls, 'pwsh');
  assert.ok(fact);
  assert.deepEqual(fact.args, ['-NoProfile', '-File', 'C:/x/clean.ps1']);
  assert.deepEqual(calls.child, [], 'script files are routed by main, not by shell');
  assert.deepEqual(gapKinds(calls), []);
});

test('encoded commands are surfaced as a gap', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('pwsh -NoProfile -EncodedCommand QQBBAA=='), env);
  assert.ok(commandNamed(calls, 'pwsh'));
  assert.ok(gapKinds(calls).includes('encoded-command'));
  assert.deepEqual(calls.child, []);
});

test('dynamic inline script keeps the wrapper fact and reports a dynamic-script gap', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`bash -c "$CMD"`), env);
  const fact = commandNamed(calls, 'bash');
  assert.ok(fact);
  assert.deepEqual(fact.args, ['-c', null]);
  assert.ok(gapKinds(calls).includes('dynamic-script'));
  assert.deepEqual(calls.child, []);
});

test('unsupported inline interpreters stay direct facts with a gap', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`zsh -c 'rm -rf /srv/x'`), env);
  assert.ok(commandNamed(calls, 'zsh'));
  assert.ok(gapKinds(calls).includes('unsupported-interpreter'));
  assert.deepEqual(calls.child, []);
});

test('cmd /c stays a direct fact and cannot be parsed', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('cmd /c del C:\\x'), env);
  assert.ok(commandNamed(calls, 'cmd'));
  assert.ok(gapKinds(calls).includes('cmd-inline'));
});

test('path-qualified interpreter names are never consumed', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`/tmp/bash -c 'rm -rf /srv/x'`), env);
  const fact = commandNamed(calls, '/tmp/bash');
  assert.ok(fact);
  assert.ok(gapKinds(calls).includes('untrusted-interpreter-path'));
  assert.deepEqual(calls.child, []);
});

test('POSIX near-miss interpreter names stay opaque', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`BASH -c 'echo safe'`), env);
  assert.ok(commandNamed(calls, 'BASH'));
  assert.ok(gapKinds(calls).includes('opaque-interpreter'));
  assert.ok(!calls.command.some((entry) => entry.executable === 'echo'), 'must not unwrap');
});

test('WSL invocations are direct command facts for the shared catalog', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('wsl --exec rm -rf /data'), env);
  const fact = commandNamed(calls, 'wsl');
  assert.ok(fact);
  assert.deepEqual(fact.args, ['--exec', 'rm', '-rf', '/data']);
  assert.deepEqual(gapKinds(calls), []);
  assert.deepEqual(calls.child, []);
});

test('dynamic command name becomes a dynamic-execution candidate', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('& $cmd', { language: 'powershell' }), env);
  assert.equal(calls.candidate.length, 1);
  const signal = calls.candidate[0];
  assert.equal(signal.kind, 'dynamic-execution');
  assert.ok(signal.reason.length > 0);
  assert.ok(!signal.reason.includes('$cmd'), 'reason must not echo raw source');
  assert.deepEqual(signal.origin, { tool: 'bash', commandIndex: 0, commandName: null });
  assert.deepEqual(calls.command, [], 'a dynamic-name command has no executable fact');
});

test('bash dynamic variable command name is a dynamic-execution candidate', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('$cmd -rf /srv/x'), env);
  assert.equal(calls.candidate.length, 1);
  assert.equal(calls.candidate[0].kind, 'dynamic-execution');
});

test('parser syntax failure is a parse-error gap, not a throw', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('if'), env);
  assert.deepEqual(gapKinds(calls), ['parse-error']);
  assert.deepEqual(calls.command, []);
});

test('PowerShell syntax failure is a parse-error gap', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('if ($true', { language: 'powershell' }), env);
  assert.deepEqual(gapKinds(calls), ['parse-error']);
});

test('PowerShell startup surfaces (#requires, using) are gaps', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('#requires -Modules EvilModule\nWrite-Output safe', { language: 'powershell' }), env);
  assert.ok(gapKinds(calls).includes('startup-code'));
  assert.ok(commandNamed(calls, 'Write-Output'));
});

test('unsupported language routes to a gap without parsing', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('rm(x)', { language: 'python' }), env);
  assert.deepEqual(gapKinds(calls), ['unsupported-language']);
  assert.deepEqual(calls.command, []);
});

test('malformed unit or env fails fast with TypeError', async (t) => {
  const { analyzer, env } = harness(t);
  await assert.rejects(
    analyzer.analyze({ unitId: 'u1', source: { kind: 'file', path: 'x' }, language: 'bash' }, env),
    TypeError,
  );
  await assert.rejects(
    analyzer.analyze({ unitId: '', source: { kind: 'inline', text: '' }, language: 'bash' }, env),
    TypeError,
  );
  await assert.rejects(analyzer.analyze(shellUnit('rm x'), null), TypeError);
});

test('abort signal cancels parsing', async (t) => {
  const controller = new AbortController();
  controller.abort();
  const { analyzer, env } = harness(t);
  await assert.rejects(
    analyzer.analyze(shellUnit('rm x', { source: { kind: 'inline', text: 'rm x' } }), { ...env, signal: controller.signal }),
    (error) => error?.code === 'CANCELLED',
  );
});

test('command budget bounds emitted facts and reports a gap', async (t) => {
  const commands = Array.from({ length: 20 }, (_, i) => ({ name: `c${i}`, args: [], redirects: [], scope: 'script' }));
  // The injected pool serves the PowerShell dialect; mock tests route through it.
  const { analyzer, calls, env } = harness(t, { parsers: { parse: async () => ({ commands, unknown: [] }) }, limits: { maxCommands: 5 } });
  await analyzer.analyze(shellUnit('ignored', { language: 'powershell' }), env);
  assert.equal(calls.command.length, 5);
  assert.deepEqual(gapKinds(calls), ['budget-commands']);
  assert.ok(calls.steps >= 6);
});

test('child budget keeps the wrapper fact and reports a gap', async (t) => {
  const commands = Array.from({ length: 6 }, () => ({ name: 'bash', args: ['-c', 'rm -f /srv/x'], redirects: [], scope: 'script' }));
  const { analyzer, calls, env } = harness(t, { parsers: { parse: async () => ({ commands, unknown: [] }) }, limits: { maxChildren: 2 } });
  await analyzer.analyze(shellUnit('ignored', { language: 'powershell' }), env);
  assert.equal(calls.child.length, 2);
  assert.equal(calls.command.length, 4, 'unroutable wrappers stay visible');
  assert.deepEqual(gapKinds(calls), ['budget-children']);
});

test('injected parser pool is not disposed by analyzer.dispose', async (t) => {
  let disposed = 0;
  const fake = { parse: async () => ({ commands: [], unknown: [] }), dispose: () => { disposed += 1; } };
  const { analyzer, env } = harness(t, { parsers: fake });
  await analyzer.analyze(shellUnit('true', { language: 'powershell' }), env);
  await analyzer.dispose();
  assert.equal(disposed, 0, 'an injected pool is owned by main');
});

test('owned parser pool disposes cleanly', async (t) => {
  const { analyzer } = harness(t);
  await analyzer.dispose();
});

test('step accounting covers parse, facts, operations and children', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`bash -c 'rm -f /srv/x' > /srv/log`), env);
  // 1 parse + 1 child + 1 operation
  assert.equal(calls.steps, 3);
});

test('DSR-024 reproduced false positives emit no gap and no candidate', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`git clone $REPO`), env);
  const clone = commandNamed(calls, 'git');
  assert.ok(clone);
  assert.deepEqual(clone.args, ['clone', null]);
  assert.deepEqual(gapKinds(calls), [], 'dynamic operand is a fact, not a gap');
  assert.deepEqual(calls.candidate, []);
  const { analyzer: a2, calls: c2, env: e2 } = harness(t);
  await a2.analyze(shellUnit(`Get-ChildItem C:/ -Include`, { language: 'powershell' }), e2);
  assert.deepEqual(gapKinds(c2), [], 'known command with a bare option must not fail the unit');
});

test('the analyzed text is never executed', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`echo SOURCE_MUST_NOT_RUN; rm -f /srv/x`), env);
  assert.ok(commandNamed(calls, 'echo'));
  assert.ok(commandNamed(calls, 'rm'));
});

/** Feed one emitted command fact through the shared catalog and collect operations. */
function resolveFact(fact, context = { domain: 'host', platform: process.platform, cwd: os.tmpdir() }) {
  const operations = [];
  const gaps = [];
  const candidates = [];
  // The fact's own context (dialect provenance) must not shadow the fixture cwd.
  resolveCommand(fact.executable, fact.args, {
    ...fact.opts, context, origin: { tool: 'fixture' },
  }, {
    operation: (action, target, opts) => operations.push({ action, target, ...opts }),
    gap: (kind) => gaps.push(kind),
    candidate: (kind) => candidates.push(kind),
    command: () => {},
    step: () => {},
  });
  return { operations, gaps, candidates };
}

test('unquoted leading tilde words stay literal text and expand through the catalog', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('rm -rf ~/proj', { context: { domain: 'host', platform: process.platform } }), env);
  const fact = commandNamed(calls, 'rm');
  assert.ok(fact, `expected rm fact, got ${JSON.stringify(calls.command)}`);
  assert.deepEqual(fact.args, ['-rf', '~/proj'], 'the tilde word arrives as literal text');
  assert.deepEqual(gapKinds(calls), []);
  const result = resolveFact(fact);
  assert.equal(result.operations[0].action, 'delete');
  assert.equal(result.operations[0].target.kind, 'subtree');
  assert.equal(result.operations[0].target.root, path.join(os.homedir(), 'proj'));
});

test('a tilde credential read expands to the protected home path', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('cat ~/.aws/credentials', { context: { domain: 'host', platform: process.platform } }), env);
  const fact = commandNamed(calls, 'cat');
  assert.ok(fact);
  assert.deepEqual(fact.args, ['~/.aws/credentials']);
  const result = resolveFact(fact);
  assert.equal(result.operations[0].action, 'read-content');
  assert.deepEqual(result.operations[0].target, { kind: 'exact', paths: [path.join(os.homedir(), '.aws', 'credentials')] });
});

test('a quoted tilde word is marked as a literal operand, never an expansion', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit(`cat '~/.aws/credentials'`), env);
  const fact = commandNamed(calls, 'cat');
  assert.ok(fact);
  assert.deepEqual(fact.opts.literalOperands, [true]);
  const result = resolveFact(fact);
  assert.deepEqual(result.operations[0].target, { kind: 'exact', paths: ['~/.aws/credentials'] });
});

test('brace expansion and variable words keep their dynamic facts', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('echo {a,b}'), env);
  const braces = commandNamed(calls, 'echo');
  assert.deepEqual(braces.args, [null], 'brace expansion stays an unprovable dynamic word');
  const second = harness(t);
  await second.analyzer.analyze(shellUnit('rm -rf $X', { context: { domain: 'host', platform: process.platform } }), second.env);
  const fact = commandNamed(second.calls, 'rm');
  assert.deepEqual(fact.args, ['-rf', null], 'variable operands stay dynamic');
  const result = resolveFact(fact);
  assert.equal(result.operations[0].action, 'delete');
  assert.equal(result.operations[0].target.kind, 'unknown');
});

test('transparent `command` executes without a state-mutation gap', async (t) => {
  const { analyzer, calls, env } = harness(t);
  await analyzer.analyze(shellUnit('command rm -rf /srv/x'), env);
  const fact = commandNamed(calls, 'command');
  assert.ok(fact, `expected command fact, got ${JSON.stringify(calls.command)}`);
  assert.deepEqual(fact.args, ['rm', '-rf', '/srv/x']);
  assert.deepEqual(gapKinds(calls), []);
  const result = resolveFact(fact, { domain: 'host', platform: 'linux', cwd: '/srv' });
  assert.equal(result.operations[0].action, 'delete');
  assert.deepEqual(result.operations[0].target, { kind: 'subtree', root: '/srv/x' });
  assert.deepEqual(result.candidates, []);
});
