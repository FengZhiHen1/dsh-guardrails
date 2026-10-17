// Plugin-owned ask timeout (DSR-016).
//
// Drives the real tools/pre-execute listener through a mock ctx whose approval
// service mimics @deepseek-ai/dsh-user-approval: `request()` settles with a
// closed outcome and reports `cancelled` when the request signal aborts. Timers
// are mocked, so nothing here waits in real time.
//
// Run with: node --test test/

import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as guardrails from '../index.js'

const CWD = 'E:/Project/DSH_Plugins'
const TARGET = 'C:/Users/me/.ssh/id_rsa'

/**
 * Build a gate over a fake approval service.
 *
 * @param config - plugin row config.
 * @param answer - outcome the service returns when it is not aborted.
 * @param opts - `{ service: false }` omits the approval service entirely.
 */
function makeGate(config = {}, answer = 'allowed-once', opts = {}) {
  let listener
  const requests = []
  const approval = {
    request: (req) => {
      if (opts.throw === true) throw new Error('approval seam exploded')
      requests.push(req)
      return new Promise((resolve) => {
        const settle = () => resolve(answer)
        if (req.signal === undefined) {
          settle()
          return
        }
        if (req.signal.aborted) {
          resolve('cancelled')
          return
        }
        req.signal.addEventListener('abort', () => resolve('cancelled'), { once: true })
        if (opts.pending === true) return
        // An answerer that decides before any timeout.
        queueMicrotask(() => {
          if (!req.signal.aborted) settle()
        })
      })
    },
  }
  const sandboxPolicy = { resolve: ({ session } = {}) => ({ workspaceRoot: session?.header?.cwd ?? CWD }) }
  const ctx = {
    get: (key) => {
      if (key === 'sandboxPolicy') return sandboxPolicy
      if (key === 'approval') return opts.service === false ? undefined : approval
      return undefined
    },
    effect: (fn) => fn(),
    on: (event, handler) => {
      if (event === 'tools/pre-execute') listener = handler
      return () => { listener = undefined }
    },
    inject: () => {},
  }
  guardrails.apply(ctx, config)
  return {
    requests,
    call: (name, args, exec = {}) =>
      listener(
        { name, arguments: args, agent: { session: { header: { cwd: CWD } } }, ...exec },
        async () => ({ kind: 'allow' }),
      ),
    read: (file_path, exec) => listener(
      { name: 'read', arguments: { file_path }, agent: { session: { header: { cwd: CWD } } }, ...exec },
      async () => ({ kind: 'allow' }),
    ),
  }
}

const isTimeoutDeny = (r) => r !== undefined && r.kind === 'deny' && /审批在 .* 内无人处理，已自动拒绝/.test(r.reason)

test('askTimeoutMs = 0 (default) keeps the native ask and issues no request', async () => {
  const gate = makeGate()
  const decision = await gate.read(TARGET)
  assert.equal(decision.kind, 'ask')
  assert.equal(gate.requests.length, 0, 'a disabled bound must not own the request')
})

test('a bound owns the request and maps a grant to allow', async () => {
  const gate = makeGate({ askTimeoutMs: 5000 })
  const decision = await gate.read(TARGET)
  assert.equal(decision.kind, 'allow')
  assert.equal(gate.requests.length, 1)
  const req = gate.requests[0]
  assert.equal(req.toolName, 'read')
  assert.ok(typeof req.reason === 'string' && req.reason.includes('id_rsa'))
  assert.ok(req.signal !== undefined, 'the request must carry a signal so the UI can dismiss on timeout')
})

test('a grant clears the timer: aborting later must not touch the request signal', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const gate = makeGate({ askTimeoutMs: 5000 })
  assert.equal((await gate.read(TARGET)).kind, 'allow')
  const signal = gate.requests[0].signal
  t.mock.timers.tick(60_000)
  assert.equal(signal.aborted, false, 'the timeout timer must be cleared once the ask settles')
})

test('a user rejection keeps the native wording', async () => {
  const gate = makeGate({ askTimeoutMs: 5000 }, 'rejected')
  const decision = await gate.read(TARGET)
  assert.equal(decision.kind, 'deny')
  assert.equal(decision.reason, 'the user rejected tool "read"')
})

test('an unavailable channel denies with the native wording', async () => {
  const gate = makeGate({ askTimeoutMs: 5000 }, 'unavailable')
  const decision = await gate.read(TARGET)
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /no approval channel is available/)
})

test('no approval service at all denies instead of reading', async () => {
  const gate = makeGate({ askTimeoutMs: 5000 }, 'allowed-once', { service: false })
  const decision = await gate.read(TARGET)
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /no approval channel is available/)
})

test('a caller-side cancel keeps the native cancel shape', async () => {
  const gate = makeGate({ askTimeoutMs: 60_000 }, 'allowed-once', { pending: true })
  const controller = new AbortController()
  const pending = gate.read(TARGET, { signal: controller.signal })
  controller.abort(new Error('turn cancelled'))
  assert.deepEqual(await pending, { kind: 'cancel' })
})

test('the bound fires: nobody answers → explicit automatic refusal', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const gate = makeGate({ askTimeoutMs: 3000 }, 'allowed-once', { pending: true })
  const pending = gate.read(TARGET)
  // Let the listener reach the await, then let the timer elapse.
  await Promise.resolve()
  assert.equal(gate.requests.length, 1, 'the request must be pending before the timeout')
  t.mock.timers.tick(3000)
  const decision = await pending
  assert.equal(decision.kind, 'deny')
  assert.equal(isTimeoutDeny(decision), true, `unexpected reason: ${decision.reason}`)
  assert.match(decision.reason, /3s/, 'the reason states the bound')
  assert.match(decision.reason, /自动拒绝/, 'the reason distinguishes timeout from a human rejection')
})

test('the timeout never grants and never leaves the call running', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const gate = makeGate({ askTimeoutMs: 1000 }, 'allowed-once', { pending: true })
  const pending = gate.read(TARGET)
  await Promise.resolve()
  t.mock.timers.tick(5000)
  const decision = await pending
  assert.equal(decision.kind, 'deny')
  assert.equal(gate.requests[0].signal.aborted, true)
})

test('a throwing approval request fails closed instead of reading', async () => {
  const gate = makeGate({ askTimeoutMs: 5000 }, 'allowed-once', { throw: true })
  const decision = await gate.read(TARGET)
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /approval request failed/)
})

test('a timeout leaves one bounded audit line (the approval pair cannot say timeout)', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const lines = []
  const original = console.error
  console.error = (...args) => { lines.push(args.join(' ')) }
  try {
    const gate = makeGate({ askTimeoutMs: 2000 }, 'allowed-once', { pending: true })
    const pending = gate.read(TARGET)
    await Promise.resolve()
    t.mock.timers.tick(2000)
    await pending
  } finally {
    console.error = original
  }
  assert.equal(lines.length, 1, `expected exactly one audit line, got ${JSON.stringify(lines)}`)
  assert.match(lines[0], /\[guardrails\] ask timed out after 2000ms/)
})

test('an unknown outcome fails closed', async () => {
  const gate = makeGate({ askTimeoutMs: 5000 }, 'maybe')
  const decision = await gate.read(TARGET)
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /unrecognized/)
})

test('non-sensitive reads never touch the approval service, even with a bound', async () => {
  const gate = makeGate({ askTimeoutMs: 5000 })
  assert.equal((await gate.read('src/core/rules.js')).kind, 'allow')
  assert.equal(gate.requests.length, 0)
})

test('mount-time validation rejects a malformed bound loudly', () => {
  for (const bad of [-1, 1.5, '3000', 3_600_001]) {
    assert.throws(() => makeGate({ askTimeoutMs: bad }), /askTimeoutMs/)
  }
})
