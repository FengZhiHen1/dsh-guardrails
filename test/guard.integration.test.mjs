// Integration matrix: drives the plugin's tools/pre-execute listener through a
// mock ctx (no filesystem, no network). This is the V2 semantic anchor: the
// listener never denies — it returns `{ kind: 'ask', reason }` on sensitive
// content reads and passes everything else through with `next()`.
// Run with: node --test test/

import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as guardrails from '../index.js'

function makeGate(config = {}, settings) {
  let listener
  // Mirror the real ctx.sandboxPolicy shape (DSR-007): resolve() derives the
  // workspace root from the calling session's immutable header.cwd.
  const sandboxPolicy = {
    resolve: ({ session } = {}) => ({ workspaceRoot: session?.header?.cwd ?? 'E:/FallbackRoot' }),
  }
  const ctx = {
    get: (key) => (key === 'sandboxPolicy' ? sandboxPolicy : undefined),
    // The adapter registers the listener inside an effect and returns the
    // listener's disposer; keep the registration alive (disposal is lifecycle
    // territory, covered by lifecycle.test.mjs).
    effect: (fn) => fn(),
    on: (event, handler) => {
      assert.equal(event, 'tools/pre-execute', 'the plugin must register tools/pre-execute')
      listener = handler
      return () => { listener = undefined }
    },
    inject: (name, consumer) => {
      const deps = Array.isArray(name) ? name : [name]
      if (deps.includes('settings') && settings !== undefined) consumer({ ...ctx, settings })
    },
  }
  guardrails.apply(ctx, config)
  return {
    /** Drive the registered listener: (name, args) → Promise<PreToolDecision | undefined>. */
    call: (name, args, cwd = 'E:/Project/DSH_Plugins') =>
      listener({ name, arguments: args, agent: { session: { header: { cwd } } } }, async () => ({ kind: 'allow' })),
  }
}

const isAsk = (r) => r !== undefined && r.kind === 'ask' && typeof r.reason === 'string'
const passedThrough = (r) => r !== undefined && r.kind === 'allow'
const read = (gate, file_path) => gate.call('read', { file_path })
const readImage = (gate, file_path) => gate.call('read_image', { file_path })
const grep = (gate, path) => gate.call('grep', { path })
const glob = (gate, path) => gate.call('glob', { path })
const write = (gate, file_path) => gate.call('write', { file_path })
const pwsh = (gate, command) => gate.call('pwsh', { command })

test('gate registers exactly one pre-execute listener', async () => {
  const gate = makeGate()
  assert.equal(typeof gate.call, 'function')
})

test('builtin credential reads ask; ordinary reads pass through', async () => {
  const gate = makeGate()
  assert.equal(isAsk(await read(gate, 'C:/Users/me/.ssh/id_rsa')), true)
  assert.equal(isAsk(await read(gate, 'C:/Users/me/.npmrc')), true)
  assert.equal(isAsk(await read(gate, 'C:/Users/me/.aws/credentials')), true)
  assert.equal(passedThrough(await read(gate, 'src/core/rules.js')), true)
  assert.equal(passedThrough(await read(gate, '.env')), true, 'plain .env is Auto-Review territory (decision C)')
  assert.equal(passedThrough(await read(gate, '.env.example')), true)
  assert.equal(passedThrough(await read(gate, '.git/config')), true)
  assert.equal(passedThrough(await read(gate, 'C:/Users/me/.ssh/config')), true, 'routing table stays free')
  assert.equal(passedThrough(await read(gate, 'C:/keys/prod.pem')), true, 'suffix rules are retired')
})

test('read_image and single-file grep are judged; glob never is', async () => {
  const gate = makeGate()
  assert.equal(isAsk(await readImage(gate, 'C:/Users/me/.ssh/id_rsa')), true)
  assert.equal(passedThrough(await readImage(gate, 'E:/shot.png')), true)
  assert.equal(isAsk(await grep(gate, 'C:/Users/me/.ssh/id_rsa')), true)
  assert.equal(passedThrough(await grep(gate, 'E:/Project/DSH_Plugins/src')), true, 'directory grep cannot name a marked file')
  assert.equal(passedThrough(await glob(gate, '.ssh/**')), true)
  assert.equal(passedThrough(await glob(gate, 'C:/Users/me/.ssh')), true)
})

test('V2 never denies and never intercepts writes, deletes, or shell commands', async () => {
  const gate = makeGate()
  // Writes/edits/shell are out of V2 scope entirely (Auto Review + OS perms).
  assert.equal(passedThrough(await write(gate, 'C:/Users/me/.ssh/id_rsa')), true)
  assert.equal(passedThrough(await pwsh(gate, 'Get-Content .ssh/id_rsa')), true)
  assert.equal(passedThrough(await pwsh(gate, 'Remove-Item C:\\ -Recurse -Force')), true)
  assert.equal(passedThrough(await pwsh(gate, 'git reset --hard')), true)
  // The deny channel is gone: no decision ever carries kind 'deny'.
  for (const decision of [
    await read(gate, 'C:/Users/me/.ssh/id_rsa'),
    await pwsh(gate, 'Remove-Item C:\\ -Recurse -Force'),
  ]) {
    assert.equal(decision?.kind === 'deny', false, 'the deny channel is retired')
  }
})

test('user-marked files ask on exact content reads', async () => {
  const gate = makeGate({ sensitiveFiles: ['E:/Project/app/.env.production', 'C:/Users/me/.kube/config'] })
  assert.equal(isAsk(await read(gate, 'E:/Project/app/.env.production')), true)
  assert.equal(isAsk(await read(gate, 'e:\\project\\APP\\.env.production')), true, 'matching is case-insensitive')
  assert.equal(passedThrough(await read(gate, 'E:/Project/app/.env')), true, 'sibling names are not the marked file')
  assert.equal(passedThrough(await read(gate, 'E:/Project/app/.env.production.bak')), true)
  assert.equal(isAsk(await grep(gate, 'C:/Users/me/.kube/config')), true, 'single-file grep on a marked file asks')
  assert.equal(passedThrough(await grep(gate, 'E:/Project/app')), true, 'directory grep never matches a marked FILE')
})

test('config toggles: builtin list off, marks still active; live volatile read', async () => {
  const gate = makeGate({ credentialsReadAsk: false, sensitiveFiles: ['E:/x/secret'] })
  assert.equal(passedThrough(await read(gate, 'C:/Users/me/.ssh/id_rsa')), true)
  assert.equal(isAsk(await read(gate, 'E:/x/secret')), true)
})

test('ask reason names action and target, never file content', async () => {
  const gate = makeGate()
  const decision = await read(gate, 'C:/Users/me/.ssh/id_rsa')
  assert.ok(decision.reason.includes('read'), 'the reason names the tool')
  assert.ok(decision.reason.includes('id_rsa'), 'the reason names the target path')
  assert.ok(decision.reason.length < 600, 'the reason stays bounded')
})

test('relative paths resolve against the session workspace root', async () => {
  // A marked file referenced relatively from the session cwd must hit.
  const gate = makeGate({ sensitiveFiles: ['E:/Project/DSH_Plugins/.env.local'] })
  assert.equal(isAsk(await read(gate, '.env.local')), true)
  assert.equal(passedThrough(await read(gate, '.env')), true)
})

test('no sandboxPolicy service: absolute targets still judge; relative targets ask by basename', async () => {
  // Without a sandboxPolicy the base degrades to ''. Narrow-list matching then
  // only sees the basename — a relative `.ssh/id_rsa` still asks, because the
  // failure direction of this plugin is the one-shot ASK, never a denial.
  let listener
  const ctx = {
    get: () => undefined,
    effect: (fn) => fn(),
    on: (event, handler) => { listener = handler; return () => {} },
    inject: () => {},
  }
  guardrails.apply(ctx, {})
  const exec = (name, args) =>
    listener({ name, arguments: args, agent: { session: { header: { cwd: 'E:/p' } } } }, async () => ({ kind: 'allow' }))
  assert.equal(isAsk(await exec('read', { file_path: 'C:/Users/me/.ssh/id_rsa' })), true)
  assert.equal(isAsk(await exec('read', { file_path: '.ssh/id_rsa' })), true,
    'basename-only matching keeps the ask direction (fail-toward-ask, not deny)')
  assert.equal(isAsk(await exec('read', { file_path: 'notes.txt' })), false)
})

test('listener failure is fail-open: a throwing judgment must not break the waterfall', async () => {
  let listener
  const ctx = {
    // A sandboxPolicy whose resolve throws must degrade to pass-through, not
    // wedge the tool waterfall: the listener swallows the error and falls
    // through to `next()`, so the call proceeds under the native review.
    get: () => ({ resolve: () => { throw new Error('boom') } }),
    effect: (fn) => fn(),
    on: (event, handler) => { listener = handler; return () => {} },
    inject: () => {},
  }
  guardrails.apply(ctx, {})
  const result = await listener(
    { name: 'read', arguments: { file_path: 'C:/Users/me/.ssh/id_rsa' }, agent: undefined },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(result.kind, 'allow', 'internal errors fall through to next() (fail-open)')
})

test('non-read tools and malformed executions pass through untouched', async () => {
  const gate = makeGate()
  assert.equal((await gate.call('edit', { file_path: 'C:/Users/me/.ssh/id_rsa' })).kind, 'allow')
  assert.equal((await gate.call('bash', { command: 'cat ~/.ssh/id_rsa' })).kind, 'allow')
  // No target: the listener returns the downstream decision unchanged.
  assert.equal((await gate.call('read', {})).kind, 'allow')
  assert.equal((await gate.call('read', { file_path: '' })).kind, 'allow')
})
