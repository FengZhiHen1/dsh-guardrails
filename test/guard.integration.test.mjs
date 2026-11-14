// Host integration: real isolated file identities and execution-local guard decisions.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdir, mkdtemp, writeFile, rm } from 'node:fs/promises'
import path from 'node:path'
import * as guardrails from '../index.js'

async function fixture(t, config = {}, options = {}) {
  await mkdir(path.resolve('tmp'), { recursive: true })
  const root = await mkdtemp(path.resolve('tmp/host-'))
  const marked = path.join(root, 'marked.txt')
  const ordinary = path.join(root, 'ordinary.txt')
  const builtin = path.join(root, 'id_rsa')
  for (const file of [marked, ordinary, builtin]) await writeFile(file, 'synthetic fixture only')
  t.after(() => rm(root, { recursive: true, force: true }))
  const listeners = new Map()
  const disposers = []
  const requests = []
  let guard
  const ctx = {
    tools: { guard(fn) { guard = fn; return () => { guard = undefined } } },
    get(key) {
      if (key === 'sandboxPolicy') return { resolve: () => { if (options.brokenSandbox) throw new Error('synthetic failure'); return { workspaceRoot: root } } }
      if (key === 'workingDirectory') return options.workingDirectory ? { get: () => root } : undefined
      if (key === 'approval') return { request: async req => { requests.push(req); return options.outcome ?? 'allowed-once' } }
    },
    effect(fn) { const off = fn(); if (typeof off === 'function') disposers.push(off) },
    on(event, fn) { listeners.set(event, fn); return () => listeners.delete(event) },
    inject() {},
  }
  guardrails.apply(ctx, { sensitiveFiles: [marked], ...config })
  t.after(async () => { while (disposers.length) await disposers.pop()() })
  const execution = (name, args) => ({ name, arguments: args, agent: { session: { header: { cwd: root } } } })
  let dispatches = 0
  return {
    root, marked, ordinary, builtin, requests, execution,
    guard: exec => guard(exec),
    dispatches: () => dispatches,
    pre: exec => listeners.get('tools/pre-execute')(exec, async () => { dispatches++; return { kind: 'allow' } }),
  }
}

test('tools is required and each protected execution needs completed analysis', async t => {
  assert.deepEqual(guardrails.inject, ['tools'])
  const h = await fixture(t)
  const exec = h.execution('read', { file_path: h.ordinary })
  assert.match(h.guard(exec), /ANALYSIS_MISSING/)
  assert.equal((await h.pre(exec)).kind, 'allow')
  assert.equal(h.guard(exec), undefined)
  assert.match(h.guard({ ...exec }), /ANALYSIS_MISSING/, 'a clone cannot reuse another execution analysis')
  // Unknown tools are default-denied: a custom destructive tool must not pass by name.
  assert.match(h.guard(h.execution('cleanup_cache', {})), /UNKNOWN_TOOL/)
  // Reviewed framework tools (no deletion capability) pass untouched.
  assert.equal(h.guard(h.execution('todo_write', {})), undefined)
  assert.equal((await h.pre(h.execution('skill', { name: 'x' }))).kind, 'allow')
})

test('guard refuses dispatch while asynchronous analysis is pending', async t => {
  const h = await fixture(t)
  const exec = h.execution('read', { file_path: h.marked })
  const pending = h.pre(exec)
  assert.match(h.guard(exec), /ANALYSIS_MISSING/)
  await pending
  assert.equal(h.guard(exec), undefined)
  assert.equal(h.requests.length, 1)
})

test('structured content operations on actual marked files require a grant', async t => {
  const h = await fixture(t, {}, { outcome: 'rejected' })
  // write/edit name one target; move names a destination. read/read_image/grep read it.
  for (const name of ['read', 'read_image', 'grep', 'write', 'edit']) {
    const exec = h.execution(name, { file_path: h.marked, destination: h.ordinary })
    const result = await h.pre(exec)
    assert.equal(result.kind, 'deny', name)
    assert.match(h.guard(exec), /APPROVAL_REJECTED/, name)
  }
  // The delete tool takes a single literal target; give it only the protected path.
  const del = h.execution('delete', { file_path: h.marked })
  const delResult = await h.pre(del)
  assert.equal(delResult.kind, 'deny', 'delete')
  assert.match(h.guard(del), /APPROVAL_REJECTED/, 'delete')
  // move removes the SOURCE (an L2 deletion, counted), and copy overwrites the destination
  // (a protected target → approval). A move with the marked file as its SOURCE is a delete of
  // the protected file → approval; a copy whose DESTINATION is the marked file → approval.
  const mv = h.execution('move', { file_path: h.ordinary, destination: h.marked })
  assert.equal((await h.pre(mv)).kind, 'deny', 'move-onto-protected-destination')
  assert.match(h.guard(mv), /APPROVAL_REJECTED/, 'move')
  const cp = h.execution('copy', { file_path: h.ordinary, destination: h.marked })
  assert.equal((await h.pre(cp)).kind, 'deny', 'copy-onto-protected-destination')
  assert.match(h.guard(cp), /APPROVAL_REJECTED/, 'copy')
  assert.equal(h.dispatches(), 0)
  assert.equal(h.requests.length, 8)
})

test('move counts its source removal (L2) and refuses above 20; copy is allowed', async t => {
  const h = await fixture(t)
  // A move whose SOURCE subtree has 21 files: the source removal is counted and refused.
  const big = path.join(h.root, 'movesrc')
  await mkdir(big, { recursive: true })
  for (let i = 0; i < 21; i += 1) await writeFile(path.join(big, `f${i}.txt`), 'x')
  const mvBig = h.execution('move', { file_path: big, destination: path.join(h.root, 'movedest') })
  const denied = await h.pre(mvBig)
  assert.equal(denied.kind, 'deny', denied.reason)
  assert.match(denied.reason, /DEL-14/, 'a move source over 20 is DEL-14')
  assert.match(denied.reason, /Deletion is irreversible/, 'the doctrine sentence is present')
  // A small move source passes.
  const small = path.join(h.root, 'movesmall')
  await mkdir(small, { recursive: true })
  for (let i = 0; i < 3; i += 1) await writeFile(path.join(small, `g${i}.txt`), 'x')
  const mvSmall = h.execution('move', { file_path: small, destination: path.join(h.root, 'movedest2') })
  assert.equal((await h.pre(mvSmall)).kind, 'allow', 'a small move source is allowed')
  // copy never enters the deletion gate, even for a large source (source is not removed).
  const cpBig = h.execution('copy', { file_path: big, destination: path.join(h.root, 'copydest') })
  assert.equal((await h.pre(cpBig)).kind, 'allow', 'copy is allowed regardless of source size')
})

test('ordinary and missing targets pass without approval; glob does not read content', async t => {
  const h = await fixture(t)
  for (const [name, args] of [
    ['read', { file_path: h.ordinary }],
    ['read', { file_path: path.join(h.root, 'missing', 'id_rsa') }],
    ['glob', { path: h.root, pattern: '**/*' }],
    ['read', { file_path: `${h.marked}.bak` }],
  ]) {
    const exec = h.execution(name, args)
    assert.equal((await h.pre(exec)).kind, 'allow')
    assert.equal(h.guard(exec), undefined)
  }
  assert.equal(h.requests.length, 0)
})

test('builtin toggle leaves explicit marks active', async t => {
  const h = await fixture(t, { builtinSensitiveAsk: false })
  await h.pre(h.execution('read', { file_path: h.builtin }))
  assert.equal(h.requests.length, 0)
  await h.pre(h.execution('read', { file_path: h.marked }))
  assert.equal(h.requests.length, 1)
})

test('relative targets resolve against the actual session working directory service', async t => {
  // The workingDirectory service is the authoritative actual cwd; a stale header cwd
  // must NOT be used when the service answers. mark.txt lives at the served cwd (root).
  const h = await fixture(t, {}, { workingDirectory: true })
  const exec = h.execution('read', { file_path: 'marked.txt' })
  exec.agent.session.header.cwd = path.join(h.root, 'a-stale-header-directory')
  await h.pre(exec)
  assert.equal(h.requests.length, 1)
  assert.equal(h.guard(exec), undefined)
})

test('cwd resolution failure refuses dispatch with safe diagnostics', async t => {
  // No session workingDirectory and no header cwd: the only cwd source is the sandbox
  // policy, which throws. A throwing cwd resolution must fail closed, not guess a dir.
  const h = await fixture(t, {}, { brokenSandbox: true })
  const exec = { name: 'read', arguments: { file_path: 'marked.txt' }, agent: { session: {} } }
  const result = await h.pre(exec)
  assert.equal(result.kind, 'deny')
  assert.match(result.reason, /ANALYSIS_UNAVAILABLE/)
  assert.equal(result.reason.includes(h.marked), false)
  assert.equal(h.guard(exec), result.reason)
  assert.equal(h.dispatches(), 0)
})

test('framework coordination tools pass; terminal_send analysed in place; run_code denied; unknown tools denied', async t => {
  const h = await fixture(t)
  // Reviewed coordination / terminal-control / orchestration / workspace+profile management
  // tools with no filesystem-deletion capability pass untouched (guard) and via pre-execute.
  for (const name of ['todo_write', 'skill', 'team_task_list', 'send_message', 'job_output', 'working_directory',
    'terminal_list', 'terminal_signal', 'terminal_close', 'workflow', 'create_worktree', 'terminal_open',
    'plugin_manager']) {
    const exec = h.execution(name, {})
    assert.equal(h.guard(exec), undefined, `${name} guard passes`)
    assert.equal((await h.pre(exec)).kind, 'allow', `${name} pre allows`)
  }
  // plugin_manager now allows EVERY action (install/enable/disable/remove included).
  for (const action of ['list_plugins', 'install_bundle', 'remove_bundle', 'set_plugin', 'set_bundle']) {
    assert.equal((await h.pre(h.execution('plugin_manager', { action, target: 'x' }))).kind, 'allow', `plugin_manager ${action}`)
  }
  // terminal_send is analysed in place: a non-deleting command is allowed, and a command the
  // analyser cannot prove (dynamic/diagnostic) is refused.
  assert.equal((await h.pre(h.execution('terminal_send', { sessionId: 't', text: 'Get-Location' }))).kind, 'allow', 'terminal_send ordinary command')
  assert.equal((await h.pre(h.execution('terminal_send', { sessionId: 't', text: 42 }))).kind, 'deny', 'terminal_send non-string text denied')
  // run_code is denied outright: its payload is a program, not a command line.
  const code = await h.pre(h.execution('run_code', { code: "await tools.pwsh({command:'x'})" }))
  assert.equal(code.kind, 'deny')
  assert.match(code.reason, /OPAQUE_CODE/)
  // A genuinely unknown tool is still default-denied.
  assert.match(h.guard(h.execution('mystery_tool', {})), /UNKNOWN_TOOL/)
})

test('malformed shell input fails closed without dispatching source', async t => {
  const h = await fixture(t)
  for (const name of ['pwsh', 'bash']) {
    const exec = h.execution(name, { command: null })
    assert.match((await h.pre(exec)).reason, /ANALYSIS_UNAVAILABLE/)
    assert.match(h.guard(exec), /ANALYSIS_UNAVAILABLE/)
  }
  assert.equal(h.dispatches(), 0)
})

test('an allowed analysis cannot override later invocation cancellation', async t => {
  const h = await fixture(t)
  const controller = new AbortController()
  const exec = { ...h.execution('read', { file_path: h.ordinary }), signal: controller.signal }
  await h.pre(exec)
  controller.abort()
  assert.match(h.guard(exec), /ANALYSIS_CANCELLED/)
})

test('a real -WhatIf preview is excluded from the delete inventory, not treated as a deletion', async t => {
  const h = await fixture(t)
  // 25 files targeted only by a -WhatIf preview: a preview removes nothing, so it must NOT
  // be counted as a >20 deletion. A separate real single-file delete still inventories normally.
  const { mkdir, writeFile } = await import('node:fs/promises')
  const big = path.join(h.root, 'big')
  await mkdir(big, { recursive: true })
  for (let i = 0; i < 25; i += 1) await writeFile(path.join(big, `f${i}.txt`), 'x')
  const single = path.join(h.root, 'single.txt')
  await writeFile(single, 'x')
  const psBig = big.replace(/'/g, "''")
  const psSingle = single.replace(/'/g, "''")
  const command = `Remove-Item -LiteralPath '${psBig}' -Recurse -Force -WhatIf; Remove-Item -LiteralPath '${psSingle}' -Force`
  const exec = h.execution('pwsh', { command })
  const decision = await h.pre(exec)
  assert.equal(decision.kind, 'allow', decision.reason)
  assert.equal(h.guard(exec), undefined)
})

test('a mixed invocation still denies when the REAL (non-preview) part exceeds the limit', async t => {
  const h = await fixture(t)
  const { mkdir, writeFile } = await import('node:fs/promises')
  const big = path.join(h.root, 'bigreal')
  await mkdir(big, { recursive: true })
  for (let i = 0; i < 25; i += 1) await writeFile(path.join(big, `f${i}.txt`), 'x')
  const prev = path.join(h.root, 'prev')
  await mkdir(prev, { recursive: true })
  await writeFile(path.join(prev, 'p.txt'), 'x')
  const psBig = big.replace(/'/g, "''")
  const psPrev = prev.replace(/'/g, "''")
  // A -WhatIf preview of a small tree must not mask the REAL 25-file delete.
  const command = `Remove-Item -LiteralPath '${psPrev}' -Recurse -Force -WhatIf; Remove-Item -LiteralPath '${psBig}' -Recurse -Force`
  const decision = await h.pre(h.execution('pwsh', { command }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /DEL-01|21|20/)
})

test('a >20 delete denial carries the shared DELETION_DOCTRINE (plan-layer, via pre-execute)', async t => {
  const h = await fixture(t)
  const { mkdir, writeFile } = await import('node:fs/promises')
  const dir = path.join(h.root, 'big')
  await mkdir(dir, { recursive: true })
  for (let i = 0; i < 25; i += 1) await writeFile(path.join(dir, `f${i}.txt`), 'x')
  const psDir = dir.replace(/'/g, "''")
  const decision = await h.pre(h.execution('pwsh', { command: `Remove-Item -LiteralPath '${psDir}' -Recurse -Force` }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /Deletion is irreversible/, 'the doctrine sentence is appended to DEL-* denials')
  // Exactly once (no duplicated sentence).
  const sentence = 'Deletion is irreversible.'
  assert.equal(decision.reason.split(sentence).length - 1, 1)
})

test('L3 over-defence fix: create/write/copy/rename to a not-yet-existing path is allowed (no real delete)', async t => {
  const h = await fixture(t)
  const { writeFile } = await import('node:fs/promises')
  await writeFile(path.join(h.root, 'a.txt'), 'x')
  // Each of these names a path that does not exist yet, which observation reports as a bare
  // ENOENT (or shell analysis flags as state-changing). With no delete in the call, that must
  // not deny — the operation is L3 (allow) and dispatches.
  const cases = [
    'Copy-Item -LiteralPath a.txt -Destination new.txt',
    'New-Item -ItemType File -Path new-file.txt -Value hello',
    'Move-Item -LiteralPath a.txt -Destination new-name.txt',
  ]
  for (const command of cases) {
    const exec = h.execution('pwsh', { command })
    const decision = await h.pre(exec)
    assert.equal(decision.kind, 'allow', `${command} should be L3-allowed: ${decision.reason}`)
    assert.equal(h.guard(exec), undefined, `${command} guard passes`)
  }
})

test('L3 over-defence fix does NOT relax a call that also deletes: create + delete still gates', async t => {
  const h = await fixture(t)
  const { mkdir, writeFile } = await import('node:fs/promises')
  const dir = path.join(h.root, 'victims')
  await mkdir(dir, { recursive: true })
  for (let i = 0; i < 25; i += 1) await writeFile(path.join(dir, `f${i}.txt`), 'x')
  const psDir = dir.replace(/'/g, "''")
  // A new-file creation mixed with a real delete: the call must still be refused. Because a
  // state-changing command makes the fixed delete set untrustworthy, it denies (fail-closed);
  // the exact rule may be DEL-01 or DI-UNKNOWN-SEMANTICS — either is a refusal.
  const command = `New-Item -ItemType File -Path new-file.txt -Value hello; Remove-Item -LiteralPath '${psDir}' -Recurse -Force`
  const decision = await h.pre(h.execution('pwsh', { command }))
  assert.equal(decision.kind, 'deny', decision.reason)
})

test('command-form Move-Item counts source removal (L2): 21 sources → DEL-14, single move allowed', async t => {
  const h = await fixture(t)
  const { mkdir, writeFile } = await import('node:fs/promises')
  // Build 21 source files; a Move-Item script moving all of them removes 21 sources.
  const srcDir = path.join(h.root, 'mvsrc')
  await mkdir(srcDir, { recursive: true })
  const destDir = path.join(h.root, 'mvdst')
  await mkdir(destDir, { recursive: true })
  const lines = []
  for (let i = 0; i < 21; i += 1) {
    await writeFile(path.join(srcDir, `f${i}.txt`), 'x')
    lines.push(`Move-Item -LiteralPath '${path.join(srcDir, `f${i}.txt`).replace(/'/g, "''")}' -Destination '${path.join(destDir, `f${i}.txt`).replace(/'/g, "''")}'`)
  }
  const denied = await h.pre(h.execution('pwsh', { command: lines.join('; ') }))
  assert.equal(denied.kind, 'deny', denied.reason)
  assert.match(denied.reason, /DEL-14|21|20/)
  assert.match(denied.reason, /Deletion is irreversible/)
  // Single Move-Item (one source) is L2-counted (1 ≤ 20) and allowed.
  const one = h.execution('pwsh', { command: `Move-Item -LiteralPath '${path.join(srcDir, 'f0.txt').replace(/'/g, "''")}' -Destination '${path.join(destDir, 'renamed.txt').replace(/'/g, "''")}'` })
  assert.equal((await h.pre(one)).kind, 'allow', 'single move is allowed')
})
