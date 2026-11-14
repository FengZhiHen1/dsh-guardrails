import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { analyzeShell, ShellAbortError } from '../src/adapter/shell-analysis.mjs';
import { createShellParsers } from '../src/adapter/parsers/index.mjs';

// All targets are synthetic; nothing here is executed. The analysis only re-parses text.

function names(result) {
  return result.commands.map(c => c.name);
}

/** Create a per-test temporary directory that is removed afterwards. */
async function tmpDir(t) {
  // Resolve the real path so a Windows 8.3 short name (e.g. `FENGZH~1`) does not linger:
  // a `~` inside a POSIX-shell word would make the parser treat the path as dynamic.
  const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'gr-shell-')));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  return dir;
}

/** Write a synthetic script file and return its absolute path. */
async function writeScript(dir, name, content) {
  const file = path.join(dir, name);
  await fs.writeFile(file, content);
  return file;
}

/**
 * Spell a filesystem path so that a POSIX-shell source keeps it literal: a backslash is an
 * escape inside bash/sh/dash/zsh text, so a Windows path must use `/` separators there.
 */
function shellPath(file) {
  return file.split(path.sep).join('/');
}

test('wsl + bash -lc unwraps to inner command with wsl domain, distribution and user', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const source = `wsl -d Ubuntu -u dev --cd /srv/app bash -lc 'rsync -a --delete ./dist/ "$dst/"'`;
  const result = await analyzeShell({ dialect: 'bash', source, parsers });
  const rsync = result.commands.find(c => c.name === 'rsync');
  assert.ok(rsync, `expected inner rsync, got ${JSON.stringify(names(result))}`);
  assert.equal(rsync.domain, 'wsl');
  assert.equal(rsync.distribution, 'Ubuntu');
  assert.equal(rsync.user, 'dev');
  assert.equal(rsync.cwd, '/srv/app');
  assert.equal(rsync.dialect, 'bash');
  // The literal source/dest are retained; "$dst/" is dynamic -> null.
  assert.deepEqual(rsync.args, ['-a', '--delete', './dist/', null]);
  // The wrapper call must not remain as a separate command.
  assert.ok(!result.commands.some(c => c.name === 'wsl'));
});

test('wsl --exec passes argv directly without login-shell re-splitting', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const source = `wsl --exec rm -rf /srv/tmp/x`;
  const result = await analyzeShell({ dialect: 'bash', source, parsers });
  const rm = result.commands.find(c => c.name === 'rm');
  assert.ok(rm);
  assert.equal(rm.domain, 'wsl');
  assert.deepEqual(rm.args, ['-rf', '/srv/tmp/x']);
});

test('nested wsl -> bash -> pwsh keeps dialects and domains correct', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  // Outer bash calls wsl, whose Linux program is pwsh running -Command with a Remove-Item.
  const source = `wsl -d U pwsh -NoProfile -Command 'Remove-Item /srv/tmp/y -Recurse'`;
  const result = await analyzeShell({ dialect: 'bash', source, parsers });
  const rm = result.commands.find(c => c.name && c.name.toLowerCase() === 'remove-item');
  assert.ok(rm, `expected Remove-Item, got ${JSON.stringify(names(result))}`);
  assert.equal(rm.domain, 'wsl');
  assert.equal(rm.dialect, 'powershell');
});

test('dynamic inner script is not parsed and stays visible with unknown', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const source = `bash -c "$CMD"`;
  const result = await analyzeShell({ dialect: 'bash', source, parsers });
  // Wrapper retained (dynamic script cannot be safely re-parsed).
  assert.ok(result.commands.some(c => c.name === 'bash'));
  assert.ok(result.unknown.some(u => /dynamic|unprovable/i.test(u)));
});

test('unprovable external script file is surfaced as unknown, not silently dropped', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  // No provable cwd here, so the relative script path cannot be located: the wrapper must
  // stay visible and carry an explicit unknown (never silently dropped, never allowed).
  const source = `bash ./deploy.sh --go`;
  const result = await analyzeShell({ dialect: 'bash', source, parsers });
  assert.ok(result.commands.some(c => c.name === 'bash'));
  assert.ok(result.unknown.some(u => /script file/i.test(u)));
});

test('non-bash POSIX shells are not parsed as bash; surfaced as unknown', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const source = `zsh -c 'rm -rf /srv/tmp/x'`;
  const result = await analyzeShell({ dialect: 'bash', source, parsers });
  // The zsh wrapper is retained; we must not pretend the inner is bash.
  assert.ok(result.commands.some(c => c.name === 'zsh'));
  assert.ok(result.unknown.some(u => /Unsupported shell interpreter 'zsh'/i.test(u)));
});

test('cmd inline command is surfaced as unknown (no official parser)', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const source = `cmd /c "del /s /q C:\\synthetic\\x"`;
  const result = await analyzeShell({ dialect: 'bash', source, parsers });
  assert.ok(result.commands.some(c => c.name === 'cmd'));
  assert.ok(result.unknown.some(u => /cmd inline command/i.test(u)));
});

test('unknown wsl option prevents misclassification and stays visible', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const source = `wsl --unmodeled-flag bash -lc 'rm -rf /srv/tmp/x'`;
  const result = await analyzeShell({ dialect: 'bash', source, parsers });
  assert.ok(result.commands.some(c => c.name === 'wsl'));
  assert.ok(result.unknown.some(u => /not modeled/i.test(u)));
});

test('plain non-wrapper commands pass through with dialect/domain enriched', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const source = `git status --short`;
  const result = await analyzeShell({ dialect: 'bash', source, parsers, cwd: '/srv/app' });
  const git = result.commands.find(c => c.name === 'git');
  assert.ok(git);
  assert.equal(git.dialect, 'bash');
  assert.equal(git.domain, 'host');
  assert.equal(git.cwd, '/srv/app');
});

test('control-flow preserved from parser remains visible as unknown', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const source = `for f in *; do rm -rf "$f"; done`;
  const result = await analyzeShell({ dialect: 'bash', source, parsers });
  // rm must be visible (loop body executes) and the dynamic target stays null.
  const rm = result.commands.find(c => c.name === 'rm');
  assert.ok(rm);
  assert.equal(rm.args[1], null);
});

test('parser failure propagates (fail-closed downstream)', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  await assert.rejects(analyzeShell({ dialect: 'bash', source: 'if', parsers }), { code: 'SYNTAX' });
});

test('abort signal stops analysis', async () => {
  const controller = new AbortController();
  controller.abort();
  const parsers = { parse: async () => ({ commands: [], unknown: [] }) };
  await assert.rejects(
    analyzeShell({ dialect: 'bash', source: 'echo hi', parsers, signal: controller.signal }),
    (err) => err instanceof ShellAbortError || err.code === 'CANCELLED',
  );
});

test('depth budget bounds deeply nested wrappers without executing', async () => {
  // Stub parser that always returns a nested `bash -lc '<inner>'` until source bottoms out.
  let calls = 0;
  const parsers = {
    parse: async (dialect, src) => {
      calls += 1;
      const m = /^L(\d+)$/.exec(src);
      const level = m ? Number(m[1]) : 0;
      if (level >= 20) return { commands: [{ name: 'rm', args: ['-rf', '/srv/x'], redirects: [] }], unknown: [] };
      // Emit a wrapper whose inline script is L(level+1).
      return { commands: [{ name: 'bash', args: ['-c', `L${level + 1}`], redirects: [] }], unknown: [] };
    },
  };
  const result = await analyzeShell({ dialect: 'bash', source: 'L0', parsers });
  // Depth budget (8) stops recursion; a bounded number of parses happened, no infinite loop.
  assert.ok(calls <= 24, `parse calls ${calls} exceeded budget`);
  assert.ok(result.unknown.some(u => /budget|depth/i.test(u)));
});

test('source text is never executed (echoed marker must not run)', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const result = await analyzeShell({ dialect: 'bash', source: `wsl -d U bash -lc 'echo SOURCE_MUST_NOT_RUN; rm -rf /srv/tmp/x'`, parsers });
  // Both commands are visible as facts, but nothing was executed by this module.
  assert.ok(result.commands.some(c => c.name === 'echo'));
  assert.ok(result.commands.some(c => c.name === 'rm'));
});

test('state-changing commands are always surfaced as explicit unknown', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  // Command-visible mutators must carry the explicit state-invalidation label. A LITERAL cd
  // is now tracked (see the cd-tracking tests); a dynamic cd, pushd and alias/source stay
  // explicit unknown.
  for (const src of ['cd "$DIR" && rm -rf build', 'pushd /srv && rm -rf build', "alias rm='rm -rf'; rm /x", 'source ./env.sh']) {
    const result = await analyzeShell({ dialect: 'bash', source: src, parsers });
    assert.ok(result.unknown.some(u => /State-changing command/i.test(u)), `missing state unknown for: ${src}`);
  }
  // Assignment (DeclClause) yields no command; the parser still reports it as unknown, so
  // the invocation cannot silently lose the fact.
  const assign = await analyzeShell({ dialect: 'bash', source: 'export X=/y; rm -rf build', parsers });
  assert.ok(assign.unknown.length > 0, 'assignment must surface an unknown');
});

test("PowerShell 'rm' alias is retained by name but tagged powershell dialect", async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const result = await analyzeShell({ dialect: 'powershell', source: 'rm build -Recurse', parsers });
  const rm = result.commands.find(c => c.name === 'rm');
  assert.ok(rm);
  assert.equal(rm.dialect, 'powershell');
  assert.deepEqual(rm.args, ['build', '-Recurse']);
});

// ---- Review regressions: path-qualified wrapper spoofing ----
test('path-qualified wrapper is NOT consumed (spoofing prevention)', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const cases = [
    ['bash', `/tmp/bash -c 'rm -rf /srv/x'`],
    ['bash', `./pwsh -Command 'rm x'`],
    ['powershell', `C:\\evil\\bash -c 'rm -rf /srv/x'`],
    ['powershell', `C:\\evil\\pwsh.exe -Command 'rm x'`],
  ];
  for (const [dialect, src] of cases) {
    const result = await analyzeShell({ dialect, source: src, parsers });
    assert.ok(result.commands.length >= 1, `wrapper should remain for: ${src}`);
    assert.ok(result.unknown.some(u => /Path-qualified interpreter/i.test(u)), `missing path-qualified unknown for: ${src}`);
  }
});

// ---- Review regressions: bare interactive shell must not disappear ----
test('bare interactive shell is kept and flagged, never silently dropped', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  for (const [dialect, src] of [['bash', 'bash'], ['powershell', 'pwsh']]) {
    const result = await analyzeShell({ dialect, source: src, parsers });
    assert.ok(result.commands.some(c => c.name && c.name.toLowerCase().includes(dialect === 'bash' ? 'bash' : 'pwsh')), `shell should remain: ${src}`);
    assert.ok(result.unknown.some(u => /interactive|startup|profile|no inline script/i.test(u)), `missing unknown for: ${src}`);
  }
});

// ---- Review regressions: startup/profile options must be unknown ----
test('startup/profile flags are surfaced as unknown', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const cases = [
    `bash -l -c 'rm -rf /srv/x'`,
    `bash -i -c 'rm -rf /srv/x'`,
    `bash --rcfile /tmp/evil -c 'rm -rf /srv/x'`,
    `bash --init-file /tmp/evil -c 'rm -rf /srv/x'`,
    `bash -l`,
  ];
  for (const src of cases) {
    const result = await analyzeShell({ dialect: 'bash', source: src, parsers });
    assert.ok(result.unknown.some(u => /startup|profile|Interactive|not modeled|load/i.test(u)), `missing startup unknown for: ${src}`);
  }
});

test('nested PowerShell without -NoProfile is surfaced as unknown', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const result = await analyzeShell({ dialect: 'bash', source: `pwsh -Command 'Remove-Item /srv/x -Recurse'`, parsers });
  assert.ok(result.unknown.some(u => /NoProfile/i.test(u)), 'expected missing -NoProfile unknown');
});

// ---- Review regressions: -Command trailing args must not be silently dropped ----
test('PowerShell -Command with trailing args is rejected as unknown, not truncated', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const result = await analyzeShell({ dialect: 'bash', source: `pwsh -NoProfile -Command 'Remove-Item /srv/x' -Extra junk`, parsers });
  assert.ok(result.unknown.some(u => /extra arguments|not provable/i.test(u)), 'expected trailing-args unknown');
  assert.ok(result.commands.some(c => c.name && c.name.toLowerCase() === 'pwsh'), 'wrapper should remain');
});

// ---- Review regressions: sh is parsed as posix, not bash ----
test('sh inner script is parsed with posix dialect, not bash', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const result = await analyzeShell({ dialect: 'bash', source: `sh -c 'rm -rf /srv/x'`, parsers });
  const rm = result.commands.find(c => c.name === 'rm');
  assert.ok(rm, `expected rm from posix parse, got ${JSON.stringify(names(result))}`);
  assert.equal(rm.dialect, 'posix');
});

// ---- Review regressions: wrapper redirects must be preserved ----
test('wrapper redirects are preserved on inner commands', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const result = await analyzeShell({ dialect: 'bash', source: `bash -c 'rm -rf /srv/x' > /srv/log.txt`, parsers });
  const rm = result.commands.find(c => c.name === 'rm');
  assert.ok(rm, 'inner rm should be visible');
  assert.ok(Array.isArray(rm.redirects) && rm.redirects.some(r => r && r.target === '/srv/log.txt' && r.operator === '>'), 'wrapper redirect must be preserved on inner command');
});

// ---- Review regressions: AST-level state gaps (assignment / loops / controls) ----
test('PowerShell env/variable assignment is explicit unknown even with no delete command', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const envAssign = await analyzeShell({ dialect: 'powershell', source: `$env:FOO = 'x'`, parsers });
  assert.ok(envAssign.unknown.some(u => /environment variable assignment/i.test(u)), 'env assignment must be unknown');
  const varAssign = await analyzeShell({ dialect: 'powershell', source: `$x = 'C:/synthetic'`, parsers });
  assert.ok(varAssign.unknown.some(u => /variable assignment/i.test(u)), 'variable assignment must be unknown');
});

test('PowerShell loops/conditionals are explicit unknown even with literal targets', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  for (const src of ['while ($true) { Get-ChildItem C:/synthetic }', 'for ($i=0;$i -lt 3;$i++) { Get-ChildItem C:/synthetic }', 'try { Get-ChildItem C:/synthetic } finally {}']) {
    const r = await analyzeShell({ dialect: 'powershell', source: src, parsers });
    assert.ok(r.unknown.some(u => /loop|conditional|try\/catch|switch/i.test(u)), `missing control-flow unknown for: ${src}`);
  }
});

test('bash assignment and loops are explicit unknown', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const assign = await analyzeShell({ dialect: 'bash', source: `x=/srv; echo ok`, parsers });
  assert.ok(assign.unknown.some(u => /assignment changes state/i.test(u)), 'bash assignment must be unknown');
  const loop = await analyzeShell({ dialect: 'bash', source: `for f in a b; do echo "$f"; done`, parsers });
  assert.ok(loop.unknown.some(u => /loop repeats execution/i.test(u)), 'bash loop must be unknown');
});

// ---- Reviewer ds-delete regressions ----
test('PowerShell value-taking interpreter options consume their value, payload extracted', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const src = `pwsh -WorkingDirectory C:\\somewhere -Command "Remove-Item C:\\x -Recurse -Force"`;
  const result = await analyzeShell({ dialect: 'powershell', source: src, parsers });
  const rm = result.commands.find(c => c && c.name && c.name.toLowerCase() === 'remove-item');
  assert.ok(rm, `payload must be extracted, got ${JSON.stringify(names(result))}`);
  assert.deepEqual(rm.args, ['C:\\x', '-Recurse', '-Force']);
  // The option value must NOT be mistaken for a program.
  assert.ok(!result.commands.some(c => c.name === 'C:\\somewhere'));
});

test('POSIX near-miss interpreter names (case/.exe) are opaque, never unwrapped', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  for (const src of [`BASH -c 'echo safe'`, `bash.exe -c 'echo safe'`, `BaSh -c 'echo safe'`]) {
    const result = await analyzeShell({ dialect: 'bash', source: src, parsers });
    // Must remain the original command name (NOT unwrapped to echo) and be flagged opaque.
    assert.ok(!result.commands.some(c => c.name === 'echo'), `must not unwrap: ${src}`);
    assert.ok(result.commands.some(c => c.name && c.name.toLowerCase().includes('bash')), `command kept: ${src}`);
    assert.ok(result.unknown.some(u => /resembles an interpreter|opaque/i.test(u)), `opaque unknown: ${src}`);
  }
});

test('exact lowercase bash is still unwrapped (opaque rule does not overreach)', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const result = await analyzeShell({ dialect: 'bash', source: `bash -c 'echo safe'`, parsers });
  assert.ok(result.commands.some(c => c.name === 'echo'));
});

test('bash +c is not treated as an inline-command flag', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const result = await analyzeShell({ dialect: 'bash', source: `bash +c 'echo safe'`, parsers });
  assert.ok(!result.commands.some(c => c.name === 'echo'), '+c must not unwrap to echo');
  assert.ok(result.unknown.some(u => /option-disabling|\+c|not proven/i.test(u)), 'must flag +c');
});

test('wsl without --exec flags default-shell expansion; --exec does not', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const plain = await analyzeShell({ dialect: 'bash', source: `wsl -d Ubuntu rm -rf /data`, parsers });
  assert.ok(plain.commands.some(c => c.name === 'rm' && c.domain === 'wsl'));
  assert.ok(plain.unknown.some(u => /default WSL shell/i.test(u)), 'non --exec must flag default shell');
  const exec = await analyzeShell({ dialect: 'bash', source: `wsl --exec rm -rf /data`, parsers });
  assert.ok(exec.commands.some(c => c.name === 'rm' && c.domain === 'wsl'));
  assert.ok(!exec.unknown.some(u => /default WSL shell/i.test(u)), '--exec must not flag default shell');
});

// ---- Lead semantic fix: context-changing PS options are NOT safe even when consumed ----
test('-WorkingDirectory relative delete is flagged unknown while the literal target is extracted', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const src = `pwsh -NoProfile -WorkingDirectory C:/actual -Command 'Remove-Item victims -Recurse'`;
  const result = await analyzeShell({ dialect: 'powershell', source: src, parsers });
  const rm = result.commands.find(c => c && c.name && c.name.toLowerCase() === 'remove-item');
  assert.ok(rm, 'delete payload must be extracted for facts');
  assert.deepEqual(rm.args, ['victims', '-Recurse']);
  // The relative 'victims' target cannot be trusted because -WorkingDirectory changed cwd.
  assert.ok(result.unknown.some(u => /WorkingDirectory|execution context/i.test(u)), 'must flag context change');
});

test('true-safe PS startup flags are not flagged', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const src = `pwsh -NoProfile -NoLogo -NonInteractive -Command 'Remove-Item victims -Recurse'`;
  const result = await analyzeShell({ dialect: 'powershell', source: src, parsers });
  const rm = result.commands.find(c => c && c.name && c.name.toLowerCase() === 'remove-item');
  assert.ok(rm);
  assert.equal(result.unknown.length, 0, `expected no unknown, got ${JSON.stringify(result.unknown)}`);
});

test('PS -ConfigurationName/-PSConsoleFile/-NoExit are unknown even though consumed', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  for (const src of [
    `pwsh -NoProfile -ConfigurationName evil -Command 'Remove-Item victims'`,
    `pwsh -NoProfile -PSConsoleFile x.psc1 -Command 'Remove-Item victims'`,
    `pwsh -NoProfile -NoExit -Command 'Remove-Item victims'`,
  ]) {
    const r = await analyzeShell({ dialect: 'powershell', source: src, parsers });
    assert.ok(r.commands.some(c => c.name && c.name.toLowerCase() === 'remove-item'), `payload extracted: ${src}`);
    assert.ok(r.unknown.length > 0, `must flag: ${src}`);
  }
});

test('bash combined -c clusters and -o are unknown but still extract the script', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const exact = await analyzeShell({ dialect: 'bash', source: `bash -c 'rm -rf /data'`, parsers });
  assert.equal(exact.unknown.length, 0, 'exact -c must be silent');
  for (const src of [`bash -xec 'rm -rf /data'`, `bash -o pipefail -c 'rm -rf /data'`]) {
    const r = await analyzeShell({ dialect: 'bash', source: src, parsers });
    assert.ok(r.commands.some(c => c.name === 'rm'), `script extracted: ${src}`);
    assert.ok(r.unknown.length > 0, `must flag: ${src}`);
  }
});

// ---- Implicit PowerShell startup / executable constructs (no CommandAst) ----
test('#requires -Modules auto-import is surfaced as unknown', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const result = await analyzeShell({ dialect: 'powershell', source: '#requires -Modules EvilModule\nWrite-Output safe', parsers });
  assert.ok(result.unknown.some(u => /#requires -Modules/i.test(u)), 'module auto-import must be unknown');
});

test('#requires -Version is benign (no unknown)', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const result = await analyzeShell({ dialect: 'powershell', source: '#requires -Version 7.0\nWrite-Output safe', parsers });
  assert.equal(result.unknown.length, 0, `version gate should not flag, got ${JSON.stringify(result.unknown)}`);
});

test('using module/assembly and dynamicparam are fail-closed at parse', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  for (const src of ['using module EvilModule\nWrite-Output safe', 'using assembly Evil.dll\nWrite-Output safe', 'dynamicparam { }\nWrite-Output safe']) {
    await assert.rejects(analyzeShell({ dialect: 'powershell', source: src, parsers }), (e) => e.code === 'SYNTAX' || /rejected/i.test(e.message), `expected syntax reject: ${src}`);
  }
});

test('executable non-command constructs (class/attribute/data/typeconstraint) are unknown', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  for (const src of [
    '[SomeAttribute()] param()\nWrite-Output safe',
    'class C { [void] M() {} }\nWrite-Output safe',
    'data { }\nWrite-Output safe',
    'param([ValidateScript({Invoke-Evil})]$x)\nWrite-Output safe',
  ]) {
    const r = await analyzeShell({ dialect: 'powershell', source: src, parsers });
    assert.ok(r.unknown.some(u => /construct can execute or load code/i.test(u)), `must flag executable construct: ${src}`);
  }
});

test('using namespace is also flagged for consistency (unnamed startup resolution)', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const ns = await analyzeShell({ dialect: 'powershell', source: 'using namespace System.Text\nWrite-Output safe', parsers });
  assert.ok(ns.unknown.some(u => /using statement/i.test(u)), 'using namespace must be flagged');
  const plain = await analyzeShell({ dialect: 'powershell', source: 'Write-Output safe', parsers });
  assert.equal(plain.unknown.length, 0, 'plain command has no unknown');
});

// ---- v3: external script-file AST analysis ---------------------------------
// A script file named on the command line is read (bounded) and re-parsed as its shell
// dialect, so the inner commands are analyzed instead of being an opaque blob.

test('bash <script file> is analyzed: the inner rm is visible with literal args', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const dir = await tmpDir(t);
  const file = await writeScript(dir, 'deploy.sh', 'rm -f a.txt\n');
  const result = await analyzeShell({ dialect: 'bash', source: `bash ${shellPath(file)}`, parsers, cwd: dir });
  const rm = result.commands.find(c => c.name === 'rm');
  assert.ok(rm, `expected inner rm, got ${JSON.stringify(names(result))}`);
  assert.deepEqual(rm.args, ['-f', 'a.txt']);
  assert.equal(rm.dialect, 'bash');
  assert.equal(rm.domain, 'host');
  assert.deepEqual(result.unknown, [], 'a clean script must not produce unknown');
  // The wrapper itself must be consumed, not left as a separate command.
  assert.ok(!result.commands.some(c => c && c.name === 'bash'));
});

test('sh/dash script files are parsed with the posix dialect, zsh with bash', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const dir = await tmpDir(t);
  const file = await writeScript(dir, 'clean.sh', 'rm -f a.txt\n');
  for (const [shell, expected] of [['sh', 'posix'], ['dash', 'posix'], ['zsh', 'bash']]) {
    const result = await analyzeShell({ dialect: 'bash', source: `${shell} ${shellPath(file)}`, parsers, cwd: dir });
    const rm = result.commands.find(c => c.name === 'rm');
    assert.ok(rm, `expected inner rm for ${shell}, got ${JSON.stringify(names(result))}`);
    assert.equal(rm.dialect, expected, `${shell} script must use the ${expected} grammar`);
    assert.deepEqual(result.unknown, [], `${shell} clean script must not produce unknown`);
  }
});

test('pwsh -NoProfile -File <script.ps1> is analyzed with the PowerShell parser', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const dir = await tmpDir(t);
  const file = await writeScript(dir, 'clean.ps1', 'Remove-Item a.txt -Recurse\n');
  const result = await analyzeShell({ dialect: 'powershell', source: `pwsh -NoProfile -File ${file}`, parsers, cwd: dir });
  const rm = result.commands.find(c => c && c.name && c.name.toLowerCase() === 'remove-item');
  assert.ok(rm, `expected inner Remove-Item, got ${JSON.stringify(names(result))}`);
  assert.equal(rm.dialect, 'powershell');
  assert.deepEqual(result.unknown, [], 'clean -NoProfile -File script must not produce unknown');
});

test('pwsh -File without -NoProfile stays unknown (profile may redefine commands)', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const dir = await tmpDir(t);
  const file = await writeScript(dir, 'clean.ps1', 'Remove-Item a.txt -Recurse\n');
  const result = await analyzeShell({ dialect: 'powershell', source: `pwsh -File ${file}`, parsers, cwd: dir });
  assert.ok(result.unknown.some(u => /NoProfile/i.test(u)), 'missing -NoProfile must be flagged');
});

test('a relative script path is analyzable only with a provable working directory', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const dir = await tmpDir(t);
  await writeScript(dir, 'clean.sh', 'rm -f a.txt\n');
  const withCwd = await analyzeShell({ dialect: 'bash', source: 'bash ./clean.sh', parsers, cwd: dir });
  assert.ok(withCwd.commands.some(c => c.name === 'rm'), 'relative path with cwd must be analyzed');
  assert.deepEqual(withCwd.unknown, [], 'no unknown when the file is provable');
  const withoutCwd = await analyzeShell({ dialect: 'bash', source: 'bash ./clean.sh', parsers });
  assert.ok(withoutCwd.unknown.some(u => /working directory/i.test(u)), 'relative path without cwd must be unknown');
  assert.ok(withoutCwd.commands.some(c => c.name === 'bash'), 'wrapper must stay visible');
});

test('a source/eval construct inside the script is explicit unknown', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const dir = await tmpDir(t);
  const file = await writeScript(dir, 'sourced.sh', 'source ./env.sh\nrm -f a.txt\n');
  const result = await analyzeShell({ dialect: 'bash', source: `bash ${shellPath(file)}`, parsers, cwd: dir });
  assert.ok(result.unknown.some(u => /State-changing command 'source'/i.test(u)), 'source must be flagged');
  assert.ok(result.commands.some(c => c.name === 'rm'), 'the literal rm is still a visible fact');
});

test('script files that cannot be proven are unknown: missing / directory / symlink', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const dir = await tmpDir(t);
  const missing = path.join(dir, 'nope.sh');
  const missingResult = await analyzeShell({ dialect: 'bash', source: `bash ${shellPath(missing)}`, parsers, cwd: dir });
  assert.ok(missingResult.unknown.some(u => /could not be inspected/i.test(u)), 'missing file must be unknown');

  const dirResult = await analyzeShell({ dialect: 'bash', source: `bash ${shellPath(dir)}`, parsers, cwd: dir });
  assert.ok(dirResult.unknown.some(u => /not a regular file/i.test(u)), 'directory must be unknown');

  const target = await writeScript(dir, 'target.sh', 'rm -f a.txt\n');
  const link = path.join(dir, 'link.sh');
  try {
    await fs.symlink(target, link, 'file');
  } catch (error) {
    t.diagnostic(`symlink unavailable on this host (${error.code}); skipping symlink assertion`);
    return;
  }
  const linkResult = await analyzeShell({ dialect: 'bash', source: `bash ${shellPath(link)}`, parsers, cwd: dir });
  assert.ok(linkResult.unknown.some(u => /symbolic link/i.test(u)), 'symlink must be unknown');
});

test('oversize and undecodable script files are unknown', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const dir = await tmpDir(t);
  const big = path.join(dir, 'big.sh');
  await fs.writeFile(big, Buffer.alloc((1 << 20) + 1, 0x23)); // 1 MiB + 1 of '#'
  const bigResult = await analyzeShell({ dialect: 'bash', source: `bash ${shellPath(big)}`, parsers, cwd: dir });
  assert.ok(bigResult.unknown.some(u => /exceeds the 1048576-byte/i.test(u)), 'oversize file must be unknown');

  const bad = path.join(dir, 'bad.sh');
  await fs.writeFile(bad, Buffer.from([0x72, 0x6d, 0x20, 0x80, 0x0a])); // "rm \x80\n": invalid UTF-8
  const badResult = await analyzeShell({ dialect: 'bash', source: `bash ${shellPath(bad)}`, parsers, cwd: dir });
  assert.ok(badResult.unknown.some(u => /not valid UTF-8/i.test(u)), 'invalid UTF-8 must be unknown');
});

test('decidable BOM encodings (UTF-8 BOM, UTF-16LE BOM) are analyzed', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const dir = await tmpDir(t);

  const utf8bom = path.join(dir, 'utf8bom.sh');
  await fs.writeFile(utf8bom, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('rm -f a.txt\n', 'utf8')]));
  const utf8Result = await analyzeShell({ dialect: 'bash', source: `bash ${shellPath(utf8bom)}`, parsers, cwd: dir });
  assert.ok(utf8Result.commands.some(c => c.name === 'rm'), 'UTF-8 BOM script must be analyzed');
  assert.deepEqual(utf8Result.unknown, [], 'UTF-8 BOM must not add unknown');

  const utf16 = path.join(dir, 'utf16le.sh');
  await fs.writeFile(utf16, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('rm -f a.txt\n', 'utf16le')]));
  const utf16Result = await analyzeShell({ dialect: 'bash', source: `bash ${shellPath(utf16)}`, parsers, cwd: dir });
  const rm = utf16Result.commands.find(c => c.name === 'rm');
  assert.ok(rm, 'UTF-16LE BOM script must be analyzed');
  assert.deepEqual(rm.args, ['-f', 'a.txt']);
  assert.deepEqual(utf16Result.unknown, [], 'UTF-16LE BOM must not add unknown');
});

test('a script file that the parser rejects is unknown, never a silent allow', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const dir = await tmpDir(t);
  const file = await writeScript(dir, 'broken.sh', 'if\n');
  const result = await analyzeShell({ dialect: 'bash', source: `bash ${shellPath(file)}`, parsers, cwd: dir });
  assert.ok(result.unknown.some(u => /could not be parsed/i.test(u)), 'parse failure inside the file must be unknown');
  assert.ok(result.commands.some(c => c.name === 'bash'), 'wrapper must stay visible');
});

test('path-qualified executables and cmd batch files are NOT analyzed', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const dir = await tmpDir(t);
  await writeScript(dir, 'x.sh', 'rm -f a.txt\n');
  // A path-qualified program is not a trusted interpreter: never consumed as one.
  const direct = await analyzeShell({ dialect: 'bash', source: './x.sh --go', parsers, cwd: dir });
  assert.ok(direct.unknown.some(u => /Path-qualified interpreter/i.test(u)), './x.sh must stay unknown');
  assert.ok(!direct.commands.some(c => c.name === 'rm'), './x.sh must not be expanded');
  // cmd batch files are still not analyzed (no official parser).
  const cmd = await analyzeShell({ dialect: 'bash', source: `cmd /c ${path.join(dir, 'x.bat')}`, parsers, cwd: dir });
  assert.ok(cmd.unknown.some(u => /cmd inline command/i.test(u)), 'cmd /c must stay unknown');
});

test('a script file in a non-host (wsl) domain is unknown, not read from the host', async t => {
  const parsers = createShellParsers();
  t.after(() => parsers.dispose());
  const dir = await tmpDir(t);
  const file = await writeScript(dir, 'linux.sh', 'rm -f a.txt\n');
  const result = await analyzeShell({ dialect: 'bash', source: `wsl --exec bash ${shellPath(file)}`, parsers, cwd: dir });
  assert.ok(result.unknown.some(u => /external script file|contents not analyzed/i.test(u)), 'wsl script file contents must not be read from the host');
});
