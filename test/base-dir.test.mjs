// DSR-007 tests: the judgment base directory comes from
// sandboxPolicy.resolve({ session }).workspaceRoot — the same identity the
// official tool chain enforces against. The rule model judges targets by
// their own shape, so these tests lock the CALLING convention rather than a
// verdict difference: the session is forwarded to resolve(), the agentless
// call falls back to the deployment root, and a missing sandbox-policy
// service degrades to base '' without failing closed.
// Run with: node --test test/

import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as guardrails from '../index.js'

function makeHarness({ sandboxPolicy } = {}) {
  let handler
  const resolveCalls = []
  const policy = sandboxPolicy === undefined
    ? {
        resolve: (request) => {
          resolveCalls.push(request)
          return { workspaceRoot: request?.session?.header?.cwd ?? 'C:/Deployment/Fallback' }
        },
      }
    : sandboxPolicy
  const ctx = {
    get: (key) => (key === 'sandboxPolicy' ? policy : undefined),
    effect: (fn) => fn(),
    inject: () => {},
    tools: { guard: (h) => { handler = h } },
  }
  guardrails.apply(ctx, {})
  return { handler, resolveCalls }
}

const blocked = (r) => typeof r === 'string' && r.startsWith('[guardrails] Blocked')

test('base comes from sandboxPolicy.resolve with the calling session forwarded', () => {
  const { handler, resolveCalls } = makeHarness()
  const session = { header: { cwd: 'C:/Work' } }
  const r = handler({ name: 'pwsh', arguments: { command: 'Remove-Item .' }, agent: { session } })
  assert.equal(blocked(r), true) // cwdState.dir === base (session cwd) → workspace-root delete
  assert.equal(resolveCalls.length, 1)
  assert.equal(resolveCalls[0].session, session) // the live Session object, not a copy
})

test('agentless execution resolves the deployment fallback root', () => {
  const { handler, resolveCalls } = makeHarness()
  const r = handler({ name: 'pwsh', arguments: { command: 'Remove-Item .' }, agent: undefined })
  assert.equal(blocked(r), true) // base = fallback root; `Remove-Item .` still hits it
  assert.equal(resolveCalls.length, 1)
  assert.deepEqual(resolveCalls[0], {}) // no session forwarded
})

test('relative workdir resolves against the resolved base', () => {
  const { handler } = makeHarness()
  // base = 'C:/Work' (session cwd); workdir 'sub' → C:/Work/sub — a plain
  // write there must pass (proves resolvePath consumed the resolved base
  // without throwing; a broken base chain would fail open the same way, so
  // pair it with the workspace-root assertion below).
  const session = { header: { cwd: 'C:/Work' } }
  const ok = handler(
    { name: 'pwsh', arguments: { command: 'Set-Content x.txt y', workdir: 'sub' }, agent: { session } },
  )
  assert.equal(ok, undefined)
  const denied = handler(
    { name: 'pwsh', arguments: { command: 'Remove-Item .', workdir: '.' }, agent: { session } },
  )
  assert.equal(blocked(denied), true) // workdir '.' resolves back to the base itself
})

test('without sandboxPolicy the guard degrades to base "" and still judges', () => {
  const { handler } = makeHarness({ sandboxPolicy: undefined })
  // get() returns undefined for every service: base = ''.
  assert.equal(blocked(handler({ name: 'read', arguments: { file_path: '.env' } })), true)
  assert.equal(
    blocked(handler({ name: 'pwsh', arguments: { command: 'Remove-Item .' }, agent: undefined })),
    true,
  )
  assert.equal(handler({ name: 'read', arguments: { file_path: 'src/index.js' } }), undefined)
})

test('a throwing sandboxPolicy.resolve fails open (hook layer) with a loud log', () => {
  const { handler } = makeHarness({
    sandboxPolicy: {
      resolve: () => {
        throw new Error('boom')
      },
    },
  })
  const r = handler({ name: 'read', arguments: { file_path: '.env' }, agent: undefined })
  assert.equal(r, undefined) // fail-open: a guard bug must not deadlock the session
})
