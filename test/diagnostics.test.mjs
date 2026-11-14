// A: structured tool-return messages, and B: trigger narrowing regressions.
// All paths are synthetic fixtures created under tmp/; no real user path is referenced.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdir, mkdtemp, writeFile, rm } from 'node:fs/promises'
import path from 'node:path'
import * as guardrails from '../index.js'
import { renderGuardrailMessage, classifyUnknown } from '../src/core/diagnostics.js'
import { textMentionsCredential } from '../src/core/rules.js'
import { DELETION_DOCTRINE } from '../src/core/deletion-intent.js'

// ---- A. pure renderer ------------------------------------------------------

test('A: a deletion denial renders the fixed block and ends with the doctrine', () => {
  const message = renderGuardrailMessage({
    kind: 'deny',
    ruleId: 'DEL-01',
    reason: 'Deletion gate: this call would delete at least 21 non-whitelisted files or links (limit 20). Delete at most 20 per call.',
    unknown: [],
    execution: { name: 'pwsh', arguments: { command: "Remove-Item -LiteralPath 'a.txt','b.txt' -Force" } },
  })
  assert.match(message, /^\[GUARDRAILS\] DENY DEL-01 \(L2\)/)
  assert.match(message, /\nWhy: /)
  assert.match(message, /\nTrigger: pwsh command=Remove-Item/)
  assert.match(message, /\nEffect: /)
  assert.match(message, /\nNext: /)
  assert.ok(message.endsWith(DELETION_DOCTRINE), 'doctrine is the final line')
})

test('A: unresolved semantics carries the concrete expression into Why and Trigger', () => {
  const message = renderGuardrailMessage({
    kind: 'deny',
    ruleId: 'DI-UNKNOWN-SEMANTICS',
    reason: 'Shell analysis reported unresolved semantics (Interpreter piece: inner script dynamic), so deletion intent cannot be ruled out.',
    unknown: ['Interpreter piece: inner script dynamic or unprovable'],
    execution: { name: 'pwsh', arguments: { command: 'pwsh -Command $scriptText' } },
  })
  assert.match(message, /^\[GUARDRAILS\] DENY DI-UNKNOWN-SEMANTICS \(Analysis\)/)
  assert.match(message, /Why: .*inner script dynamic/)
  assert.match(message, /Trigger: .*unresolved: .*inner script dynamic/)
  assert.ok(message.includes(DELETION_DOCTRINE))
})

test('A: an ASK uses the same block', () => {
  const message = renderGuardrailMessage({
    kind: 'ask',
    ruleId: 'S-F1',
    reason: `S-F1: this deletion would remove a protected file. ${DELETION_DOCTRINE}`,
    unknown: [],
    execution: { name: 'delete', arguments: { file_path: 'C:\\synthetic\\id_rsa' } },
  })
  assert.match(message, /^\[GUARDRAILS\] ASK S-F1 \(Approval\)/)
  assert.match(message, /Trigger: delete file_path=C:\\synthetic\\id_rsa/)
  assert.ok(message.endsWith(DELETION_DOCTRINE))
})

test('A: a non-deletion rule has no doctrine line', () => {
  const message = renderGuardrailMessage({
    kind: 'deny',
    ruleId: 'UNKNOWN_TOOL',
    reason: '[UNKNOWN_TOOL] This tool is not a recognized, analysed capability.',
    execution: { name: 'cleanup_cache', arguments: {} },
  })
  assert.match(message, /^\[GUARDRAILS\] DENY UNKNOWN_TOOL \(Analysis\)/)
  assert.ok(!message.includes(DELETION_DOCTRINE))
})

test('A: a credential in the trigger is masked', () => {
  const secret = 'sk-proj-' + 'a'.repeat(40)
  const message = renderGuardrailMessage({
    kind: 'deny',
    ruleId: 'DI-UNKNOWN-SEMANTICS',
    reason: 'Shell analysis reported unresolved semantics (x)',
    unknown: [],
    execution: { name: 'pwsh', arguments: { command: `Invoke-WebRequest $env:URL -Headers @{Authorization='${secret}'}` } },
  })
  assert.ok(!message.includes(secret), 'the raw secret must not appear')
  assert.ok(message.includes('[REDACTED]'), 'the redactor marker is present')
})

test('classifyUnknown roughly separates noise from analysis limits', () => {
  assert.equal(classifyUnknown('ENOENT'), 'errno')
  assert.equal(classifyUnknown("State-changing command 'cd' invalidates a fixed target set"), 'state-changing')
  assert.equal(classifyUnknown('PowerShell environment variable assignment changes state: $env:X=1'), 'assignment')
  assert.equal(classifyUnknown('Dynamic command or argument'), 'dynamic-argument')
  assert.equal(classifyUnknown('PowerShell member/type expression: $s.Replace(...)'), 'member-expression')
  assert.equal(classifyUnknown('Wrapper nesting depth budget exceeded'), 'budget')
})

test('textMentionsCredential matches carriers, not templates or path fragments', () => {
  assert.equal(textMentionsCredential('Get-Content .env'), true)
  assert.equal(textMentionsCredential('type C:\\synthetic\\.env.local'), true)
  assert.equal(textMentionsCredential('copy id_rsa somewhere'), true)
  assert.equal(textMentionsCredential('notify -----BEGIN RSA PRIVATE KEY-----'), true)
  assert.equal(textMentionsCredential('read .env.example'), false)
  assert.equal(textMentionsCredential('read .env.sample'), false)
  assert.equal(textMentionsCredential('read myid_rsa_backup'), false)
  assert.equal(textMentionsCredential('Get-ChildItem materials\\library'), false)
})

// ---- host integration ------------------------------------------------------

async function fixture(t, config = {}, options = {}) {
  await mkdir(path.resolve('tmp'), { recursive: true })
  const root = await mkdtemp(path.resolve('tmp/diag-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const listeners = new Map()
  const disposers = []
  const requests = []
  let guard
  const ctx = {
    tools: { guard(fn) { guard = fn; return () => { guard = undefined } } },
    get(key) {
      if (key === 'sandboxPolicy') return { resolve: () => ({ workspaceRoot: root }) }
      if (key === 'workingDirectory') return undefined
      if (key === 'approval') return { request: async req => { requests.push(req); return options.outcome ?? 'allowed-once' } }
    },
    effect(fn) { const off = fn(); if (typeof off === 'function') disposers.push(off) },
    on(event, fn) { listeners.set(event, fn); return () => listeners.delete(event) },
    inject() {},
  }
  guardrails.apply(ctx, { sensitiveFiles: [], ...config })
  t.after(async () => { while (disposers.length) await disposers.pop()() })
  const execution = (name, args) => ({ name, arguments: args, agent: { session: { header: { cwd: root } } } })
  let dispatches = 0
  return {
    root, requests, execution,
    guard: exec => guard(exec),
    dispatches: () => dispatches,
    pre: exec => listeners.get('tools/pre-execute')(exec, async () => { dispatches++; return { kind: 'allow' } }),
  }
}

test('B: the six read-only session shapes are allowed', async t => {
  const h = await fixture(t)
  const commands = [
    // seq 2405: read-only pipeline with a ForEach-Object scriptblock
    "Get-ChildItem . | ForEach-Object { $_.Line; $_.Context.PostContext } | Select-Object -First 60",
    // seq 2430 / 2440: environment assignment then an opaque language runtime
    "$env:PYTHONIOENCODING='utf-8'; uv run probe.py inspect synthetic",
    "$env:PYTHONIOENCODING='utf-8'; uv run probe.py materialize --plan 2>&1 | Out-String -Stream | Select-Object -First 60",
    // seq 2459: literal variable + dynamic-looking -LiteralPath resolves to the literal
    "$p = 'synthetic-library'; Get-ChildItem -LiteralPath $p -Force | Select-Object Name,@{n='T';e={$_.Target}} | Format-Table",
    // seq 2478: scriptblock + property access only
    "uv run probe.py validate 2>&1 | Select-String -Pattern 'status' | Select-Object -First 10 | ForEach-Object { $_.Line }; (uv run probe.py validate 2>&1 | Measure-Object -Line).Lines",
    // seq 2496: assignment then property/index access
    "$c = Get-Content synthetic.json; $c.Count; $c[-12..-1]",
  ]
  for (const command of commands) {
    const exec = h.execution('pwsh', { command })
    const result = await h.pre(exec)
    assert.equal(result.kind, 'allow', `expected allow: ${command}\n${result.reason ?? ''}`)
    assert.equal(h.guard(exec), undefined, command)
  }
  assert.equal(h.dispatches(), commands.length)
  assert.equal(h.requests.length, 0)
})

test('B: a dynamic-target deletion still denies, in the structured block', async t => {
  const h = await fixture(t)
  const exec = h.execution('pwsh', { command: "$p = Get-ChildItem .; Remove-Item -LiteralPath $p -Recurse -Force" })
  const result = await h.pre(exec)
  assert.equal(result.kind, 'deny', result.reason)
  assert.match(result.reason, /^\[GUARDRAILS\] DENY DI-DYNAMIC-ARGUMENT \(Analysis\)/)
  assert.match(result.reason, /\nWhy: /)
  assert.match(result.reason, /\nTrigger: pwsh command=.*Remove-Item/)
  assert.match(result.reason, /\nNext: /)
  assert.ok(result.reason.includes(DELETION_DOCTRINE))
  assert.equal(h.dispatches(), 0)
})

test('B: 21 literal delete targets still deny as DEL-01', async t => {
  const h = await fixture(t)
  const names = Array.from({ length: 21 }, (_, i) => `f${i}.txt`)
  for (const name of names) await writeFile(path.join(h.root, name), 'synthetic')
  const list = names.map(name => `'${name}'`).join(',')
  const exec = h.execution('pwsh', { command: `Remove-Item -LiteralPath ${list} -Force` })
  const result = await h.pre(exec)
  assert.equal(result.kind, 'deny', result.reason)
  assert.match(result.reason, /^\[GUARDRAILS\] DENY DEL-01 \(L2\)/)
  assert.match(result.reason, /at least 21/)
  assert.equal(h.dispatches(), 0)
})

test('B: git push --force is still refused (DI-GIT-REFUSE)', async t => {
  const h = await fixture(t)
  const exec = h.execution('pwsh', { command: 'git push --force origin main' })
  const result = await h.pre(exec)
  assert.equal(result.kind, 'deny', result.reason)
  assert.match(result.reason, /^\[GUARDRAILS\] DENY DI-GIT-REFUSE \(Analysis\)/)
  assert.equal(h.dispatches(), 0)
})

test('B: a literal credential path resolved by constant propagation still asks S-F1', async t => {
  const h = await fixture(t, {}, { outcome: 'rejected' })
  const npmrc = path.join(h.root, '.npmrc')
  await writeFile(npmrc, 'synthetic fixture only')
  const exec = h.execution('pwsh', { command: `$p = '${npmrc}'; Get-Content -LiteralPath $p` })
  const result = await h.pre(exec)
  assert.equal(result.kind, 'deny', 'a rejected approval ends as deny')
  assert.equal(h.requests.length, 1)
  assert.match(h.requests[0].reason, /^\[GUARDRAILS\] ASK S-F1 \(Approval\)/)
})

test('B: an unresolved-at-parse-time read path is allowed (path-check cannot see it)', async t => {
  const h = await fixture(t)
  await writeFile(path.join(h.root, 'x'), 'synthetic fixture only')
  const exec = h.execution('pwsh', { command: `$p = (Get-Item '${path.join(h.root, 'x')}').FullName; Get-Content -LiteralPath $p` })
  const result = await h.pre(exec)
  assert.equal(result.kind, 'allow', result.reason)
  assert.equal(h.requests.length, 0)
})

test('B: the narrowed text scan still asks when a read target stays unresolved', async t => {
  const h = await fixture(t, {}, { outcome: 'rejected' })
  await writeFile(path.join(h.root, 'x'), 'synthetic fixture only')
  const exec = h.execution('pwsh', { command: `$p = (Get-Item '${path.join(h.root, 'x')}').FullName; Get-Content -LiteralPath $p; Write-Output '.npmrc'` })
  const result = await h.pre(exec)
  assert.equal(result.kind, 'deny')
  assert.equal(h.requests.length, 1)
  assert.match(h.requests[0].reason, /^\[GUARDRAILS\] ASK S-F1 \(Approval\)/)
})

test('B: a commit message mentioning .npmrc is allowed (no dynamic operand)', async t => {
  const h = await fixture(t)
  const exec = h.execution('pwsh', { command: 'git commit -m "remove .npmrc from docs"' })
  const result = await h.pre(exec)
  assert.equal(result.kind, 'allow', result.reason)
  assert.equal(h.requests.length, 0)
})

test('B: a search pattern mentioning .npmrc is allowed (no dynamic operand)', async t => {
  const h = await fixture(t)
  const notes = path.join(h.root, 'notes.txt')
  await writeFile(notes, 'synthetic fixture only')
  const exec = h.execution('pwsh', { command: `Select-String -Pattern '.npmrc' '${notes}'` })
  const result = await h.pre(exec)
  assert.equal(result.kind, 'allow', result.reason)
  assert.equal(h.requests.length, 0)
})

test('B: a literal cd is tracked so a later literal relative delete is counted and allowed', async t => {
  const h = await fixture(t)
  const sub = path.join(h.root, 'work')
  await mkdir(sub, { recursive: true })
  for (const name of ['f0.txt', 'f1.txt', 'f2.txt']) await writeFile(path.join(sub, name), 'synthetic')
  const exec = h.execution('pwsh', { command: `cd '${sub}'; Remove-Item -LiteralPath 'f0.txt','f1.txt','f2.txt' -Force` })
  const result = await h.pre(exec)
  assert.equal(result.kind, 'allow', result.reason)
  assert.equal(h.dispatches(), 1)
})

test('B: a dynamic cd keeps a later delete denied (state stays unprovable)', async t => {
  const h = await fixture(t)
  const exec = h.execution('pwsh', { command: "cd $env:TEMP; Remove-Item -LiteralPath 'f0.txt' -Force" })
  const result = await h.pre(exec)
  assert.equal(result.kind, 'deny', result.reason)
  assert.match(result.reason, /^\[GUARDRAILS\] DENY /)
  assert.equal(h.dispatches(), 0)
})

