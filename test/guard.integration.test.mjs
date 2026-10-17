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
  assert.equal(h.guard(h.execution('unrelated-tool', {})), undefined)
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
  for (const name of ['read', 'read_image', 'grep', 'write', 'edit', 'delete', 'move']) {
    const exec = h.execution(name, { file_path: h.marked, destination: h.ordinary })
    const result = await h.pre(exec)
    assert.equal(result.kind, 'deny', name)
    assert.match(h.guard(exec), /APPROVAL_REJECTED/, name)
  }
  assert.equal(h.dispatches(), 0)
  assert.equal(h.requests.length, 7)
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

test('relative targets use the sandbox workspace root', async t => {
  const h = await fixture(t)
  const exec = h.execution('read', { file_path: 'marked.txt' })
  exec.agent.session.header.cwd = path.join(h.root, 'different-session-directory')
  await h.pre(exec)
  assert.equal(h.requests.length, 1)
  assert.equal(h.guard(exec), undefined)
})

test('analysis failures refuse dispatch with safe diagnostics', async t => {
  const h = await fixture(t, {}, { brokenSandbox: true })
  const exec = h.execution('read', { file_path: h.marked })
  const result = await h.pre(exec)
  assert.equal(result.kind, 'deny')
  assert.match(result.reason, /ANALYSIS_UNAVAILABLE/)
  assert.equal(result.reason.includes(h.marked), false)
  assert.equal(h.guard(exec), result.reason)
  assert.equal(h.dispatches(), 0)
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
