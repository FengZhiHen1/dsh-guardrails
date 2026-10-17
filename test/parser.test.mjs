import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { createShellParsers } from '../src/adapter/parsers/index.mjs';

test('all shipped platforms match official release SHA256 checksums', async () => {
  const root = new URL('../vendor/shfmt/', import.meta.url);
  const manifest = JSON.parse(await readFile(new URL('manifest.json', root), 'utf8'));
  const checksums = await readFile(new URL('sha256sums.txt', root), 'utf8');
  assert.equal(manifest.version, 'v3.12.0');
  assert.deepEqual(Object.keys(manifest.binaries).sort(), ['linux-arm64', 'linux-x64', 'win32-x64']);
  for (const entry of Object.values(manifest.binaries)) {
    assert.ok(checksums.includes(`${entry.sha256}  ${entry.file}`));
    const bytes = await readFile(new URL(entry.file, root));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256);
  }
});

for (const dialect of ['powershell', 'bash']) {
  test(`official ${dialect} parser literals, dynamics, definitions and substitutions`, async t => {
    const parser = createShellParsers();
    t.after(() => parser.dispose());
    const source = dialect === 'bash'
      ? `f() { rm hidden; }; echo 'a b' "$variable" $(touch nested) >output`
      : `function f { Remove-Item hidden }; Write-Output 'a b' "$variable" $(New-Item nested) >output`;
    const result = await parser.parse(dialect, source);
    const outer = result.commands.find(c => c.name === (dialect === 'bash' ? 'echo' : 'Write-Output'));
    assert.deepEqual(outer.args, ['a b', null, null]);
    assert.equal(outer.redirects[0].target, 'output');
    assert.equal(outer.redirects[0].operator, '>');
    assert.ok(result.commands.some(c => c.name === (dialect === 'bash' ? 'touch' : 'New-Item')));
    assert.ok(!result.commands.some(c => ['rm', 'Remove-Item'].includes(c.name)));
    assert.deepEqual((await parser.parse(dialect, '')).commands, []);
    await assert.rejects(parser.parse(dialect, dialect === 'bash' ? 'if' : 'function {'), { code: 'SYNTAX' });
    assert.ok((await parser.parse(dialect, dialect === 'bash' ? 'echo recovered' : 'Write-Output recovered')).commands.length);
  });
}

test('PowerShell persistent helper handles concurrent callers without executing stdin', async t => {
  const parser = createShellParsers();
  t.after(() => parser.dispose());
  const results = await Promise.all(Array.from({ length: 8 }, (_, i) => parser.parse('pwsh', `Write-Output '${i}'; throw 'SOURCE MUST NOT RUN'`)));
  results.forEach((r, i) => assert.equal(r.commands[0].args[0], String(i)));
});

test('Bash scans heredocs, process substitution, pipelines, assignment substitutions', async t => {
  const parser = createShellParsers();
  t.after(() => parser.dispose());
  const result = await parser.parse('bash', 'x=$(touch a); cat <(touch b) | tee c\ncat <<EOF\n$(touch d)\nEOF');
  for (const arg of ['a', 'b', 'd']) assert.ok(result.commands.some(c => c.name === 'touch' && c.args[0] === arg));
});

test('bounded input, queue, cancellation, timeout, disposal and missing helper fail explicitly', async () => {
  const parser = createShellParsers({ maxInputBytes: 10 });
  await assert.rejects(parser.parse('bash', 'x'.repeat(11)), { code: 'INPUT_LIMIT' });
  await assert.rejects(parser.parse('other', ''), { code: 'DIALECT' });
  await assert.rejects(parser.parse('bash', '', { signal: AbortSignal.abort() }), { code: 'CANCELLED' });
  parser.dispose();
  parser.dispose();
  await assert.rejects(parser.parse('bash', ''), { code: 'DISPOSED' });
  const missing = createShellParsers({ pwshPath: 'guardrails-nonexistent-pwsh' });
  await assert.rejects(missing.parse('powershell', ''), { code: 'UNAVAILABLE' });
  missing.dispose();
  const slow = createShellParsers({ timeoutMs: 1 });
  await assert.rejects(slow.parse('powershell', 'echo x'), { code: 'TIMEOUT' });
  slow.dispose();
  const bounded = createShellParsers({ maxConcurrent: 1, maxQueue: 1 });
  const first = bounded.parse('powershell', 'echo 1');
  const second = bounded.parse('powershell', 'echo 2');
  await assert.rejects(bounded.parse('powershell', 'echo 3'), { code: 'BUSY' });
  bounded.dispose();
  await assert.rejects(first, { code: 'DISPOSED' });
  await assert.rejects(second, { code: 'DISPOSED' });
});

test('execution scope excludes definitions and reports unknown local functions and member evaluation', async t => {
  const parser = createShellParsers();
  t.after(() => parser.dispose());
  for (const [dialect, source] of [['powershell', 'function f { Remove-Item x }; f'], ['bash', 'f() { rm x; }; f']]) {
    const result = await parser.parse(dialect, source);
    assert.equal(result.commands.length, 1);
    assert.equal(result.commands[0].name, 'f');
    assert.ok(result.unknown.some(reason => /function/.test(reason)));
  }
  assert.ok((await parser.parse('powershell', '[IO.File]::Delete("x")')).unknown.length);
  const redirect = await parser.parse('powershell', "'text' > output");
  assert.equal(redirect.commands[0].redirects[0].target, 'output');
  const quoted = await parser.parse('bash', "echo '$(rm literal)' \"*.txt\" *.txt $'escape\\n'");
  assert.deepEqual(quoted.commands[0].args, ['$(rm literal)', '*.txt', null, null]);
  assert.equal(quoted.commands.length, 1);
});

test('PowerShell stored scriptblocks stay inert while invoked blocks and literal arrays retain facts', async t => {
  const parser = createShellParsers();
  t.after(() => parser.dispose());
  const inert = await parser.parse('powershell', "$saved = { Remove-Item C:/Windows -Recurse }; Write-Output $saved");
  assert.ok(!inert.commands.some(command => command.name === 'Remove-Item'));
  const invoked = await parser.parse('powershell', '& { Get-Content -LiteralPath a,b }; 1 | ForEach-Object { Get-Content c }');
  assert.deepEqual(invoked.commands.find(command => command.name === 'Get-Content').args, ['-LiteralPath', 'a', 'b']);
  assert.equal(invoked.commands.filter(command => command.name === 'Get-Content').length, 2);
  const switches = await parser.parse('powershell', 'Remove-Item /etc -Recurse:$false -WhatIf:$true');
  assert.deepEqual(switches.commands[0].args, ['/etc', '-Recurse:$false', '-WhatIf:$true']);
});

test('protocol request IDs reject mismatches and stale child output cannot authorize a new request', async t => {
  const children = [];
  const requests = [];
  const parser = createShellParsers({ spawnProcess: () => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.stdin = new Writable({ write(chunk, _encoding, callback) {
      requests.push(JSON.parse(chunk.toString())); callback();
    } });
    child.kill = () => { queueMicrotask(() => child.emit('close', 0)); return true; };
    children.push(child); return child;
  } });
  t.after(() => parser.dispose());
  const first = parser.parse('pwsh', 'echo one');
  children[0].stdout.write(JSON.stringify({ reqId: requests[0].reqId + 1, commands: [], unknown: [] }) + '\n');
  await assert.rejects(first, { code: 'PROTOCOL' });
  const second = parser.parse('pwsh', 'echo two');
  await Promise.resolve();
  children[0].stdout.write(JSON.stringify({ reqId: requests[0].reqId, commands: [{ name: 'wrong', args: [] }], unknown: [] }) + '\n');
  const latest = requests.at(-1);
  children.at(-1).stdout.write(JSON.stringify({ reqId: latest.reqId, commands: [{ name: 'echo', args: ['two'] }], unknown: [] }) + '\n');
  assert.equal((await second).commands[0].args[0], 'two');
});

test('bounded output and in-flight abort close helpers', async () => {
  const small = createShellParsers({ maxOutputBytes: 10 });
  await assert.rejects(small.parse('powershell', 'echo hello'), { code: 'OUTPUT_LIMIT' });
  await assert.rejects(small.parse('bash', 'echo hello'), { code: 'OUTPUT_LIMIT' });
  small.dispose();
  const parser = createShellParsers();
  const abort = new AbortController();
  const pending = parser.parse('powershell', 'echo hi', { signal: abort.signal });
  abort.abort();
  await assert.rejects(pending, { code: 'CANCELLED' });
  assert.equal((await parser.parse('powershell', 'echo recovered')).commands[0].args[0], 'recovered');
  parser.dispose();
});
