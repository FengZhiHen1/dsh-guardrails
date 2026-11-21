import assert from 'node:assert/strict'
import test from 'node:test'
import { redactText, redactContent, inlineCredentialDecision } from '../src/core/redaction.js'
import { installRedaction } from '../src/adapter/redaction.js'

const token = `sk-${'Ab7Q'.repeat(12)}`
const bearer = `Bearer ${'Aa91'.repeat(10)}`
const jwt = [Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url'), Buffer.from(JSON.stringify({ sub: 'fixture' })).toString('base64url'), 'signature'.repeat(4)].join('.')
// quality-floor: ignore hardcoded-secret Generated base64 test prose is synthetic and contains no private key.
const pem = ['-----BEGIN PRIVATE KEY-----', Buffer.from('synthetic fixture only '.repeat(4)).toString('base64'), '-----END PRIVATE KEY-----'].join('\n')

test('recognized credentials are completely masked with their kind and no retained token edges', () => {
  const cases = [
    [token, 'provider'],
    [bearer, 'bearer'],
    [jwt, 'jwt'],
    [pem, 'pem'],
    [`ghp_${'Az19'.repeat(10)}`, 'provider'],
  ]
  for (const [secret, kind] of cases) {
    const masked = redactText(`before ${secret} after`)
    assert.equal(masked.changed, true)
    assert.equal(masked.text, `before ${kind === 'bearer' ? 'Bearer ' : ''}[REDACTED:${kind}] after`)
    assert.deepEqual(masked.kinds, [kind])
    assert.equal(redactText(masked.text).changed, false)
  }
})

test('variables, documentation placeholders, public material, and entropy survive', () => {
  for (const text of [`sk-${'x'.repeat(48)}`, `sk-example${'A'.repeat(40)}`, '$env:API_KEY', '${TOKEN}', 'Bearer YOUR_API_TOKEN', 'Bearer ${TOKEN}', 'sk-your_api_key_here', 'a9Q3'.repeat(100), '-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----', 'eyJbroken.payload.signaturelongenough']) {
    assert.equal(redactText(text).text, text)
  }
})

test('mask all matches and preserve binary blocks and block annotations', () => {
  const image = { type: 'image', data: token }
  const result = redactContent([{ type: 'text', text: `${token} ${token}`, annotation: 'kept' }, image])
  assert.equal(result[0].text, '[REDACTED:provider] [REDACTED:provider]')
  assert.equal(result[0].annotation, 'kept')
  assert.equal(result[1], image)
})

test('inline literal transmission is corrective deny; echo docs and dynamic tokens survive', () => {
  const decision = inlineCredentialDecision([{ name: 'curl', args: ['-H', `Authorization: ${bearer}`, 'https://example.org'] }])
  assert.equal(decision.kind, 'deny')
  assert.equal(decision.ruleId, 'credential.inline')
  assert.match(decision.reason, /^\[guardrails:credential\.inline\] /)
  assert.ok(!decision.reason.includes(bearer))
  for (const command of [{ name: 'echo', args: [token] }, { name: 'curl', args: ['-H', 'Authorization: Bearer ${TOKEN}', null] }]) {
    assert.equal(inlineCredentialDecision([command]), undefined)
  }
})

function harness() {
  const events = new Map()
  const ctx = {
    effect: factory => factory(),
    tools: { executable: () => ({ output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] } }) },
    on: (name, callback) => { events.set(name, callback); return () => events.delete(name) },
  }
  return { ctx, events }
}

test('post calls next once and preserves block/context and replacement decisions', async () => {
  const { ctx, events } = harness()
  const dispose = installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const result = { isError: false, value: token, content: [{ type: 'text', text: token }] }
  let called = 0
  const contexts = [{ role: 'user', content: [] }]
  const decision = await post({ name: 'echo', arguments: {} }, result, async () => { called++; return { kind: 'accept', additionalContexts: contexts } })
  assert.equal(called, 1)
  assert.equal(decision.value, '[REDACTED:provider]')
  assert.ok(!Object.hasOwn(decision, 'content'))
  assert.equal(decision.additionalContexts, contexts)
  const block = await post({}, result, async () => ({ kind: 'block', feedback: result.content, additionalContexts: contexts }))
  assert.equal(block.kind, 'block')
  assert.equal(block.feedback[0].text, '[REDACTED:provider]')
  assert.equal(block.additionalContexts, contexts)
  const replacement = await post({}, result, async () => ({ kind: 'accept', content: [{ type: 'text', text: 'other policy' }] }))
  assert.equal(replacement.content[0].text, 'other policy')
  assert.ok(!Object.hasOwn(replacement, 'value'))
  dispose()
  assert.equal(events.size, 0)
})

test('unknown schema and failures mask content without inventing value or altering errors', async () => {
  const { ctx, events } = harness()
  ctx.tools.get = () => ({ output: { schema: { type: 'string', enum: [token] } } })
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const result = { isError: true, error: { message: token }, content: [{ type: 'text', text: token }] }
  const decision = await post({}, result, async () => ({ kind: 'accept' }))
  assert.equal(decision.content[0].text, '[REDACTED:provider]')
  assert.ok(!Object.hasOwn(decision, 'value'))
  assert.equal(result.error.message, token)
  const log = await events.get('tools/ptc-dispatch-log')({}, async () => result.content)
  assert.equal(log[0].text, '[REDACTED:provider]')
})

test('object replacement values that cannot be masked are withheld without echoing them', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const contexts = [{ role: 'user', content: [] }]
  const value = { token, nested: { list: [token, 'plain'] }, count: 3, ok: true }
  const decision = await post({ name: 'object_tool', arguments: {} }, { isError: false, value, content: [] }, async () => ({ kind: 'accept', value, additionalContexts: contexts }))
  assert.equal(decision.kind, 'block')
  assert.match(decision.feedback[0].text, /withheld/)
  assert.ok(!JSON.stringify(decision).includes(token))
  assert.equal(value.token, token)
})

test('result values that cannot be masked are withheld instead of being passed through', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const value = { token }
  const decision = await post({ name: 'object_tool', arguments: {} }, { isError: false, value, content: [{ type: 'text', text: 'visible' }] }, async () => ({ kind: 'accept' }))
  assert.equal(decision.kind, 'block')
  assert.ok(!JSON.stringify(decision).includes(token))
})

test('a replacement string on a plain string schema is masked in place', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const decision = await post({ name: 'plain_tool', arguments: {} }, { isError: false, value: token, content: [] }, async () => ({ kind: 'accept', value: token }))
  assert.equal(decision.kind, 'accept')
  assert.equal(decision.value, '[REDACTED:provider]')
  assert.ok(!Object.hasOwn(decision, 'content'))
})

test('replacement strings on constrained or non-plain schemas are withheld', async () => {
  const projectors = [
    () => ({ output: { schema: { type: 'string', enum: [token] }, render: (_args, value) => [{ type: 'text', text: value }] } }),
    () => ({ projectContent: () => [{ type: 'text', text: token }], output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] } }),
  ]
  for (const projector of projectors) {
    const { ctx, events } = harness()
    ctx.tools.executable = projector
    installRedaction(ctx)
    const post = events.get('tools/post-execute')
    const decision = await post({ name: 'constrained_tool', arguments: {} }, { isError: false, value: token }, async () => ({ kind: 'accept', value: token }))
    assert.equal(decision.kind, 'block')
    assert.match(decision.feedback[0].text, /withheld/)
    assert.ok(!JSON.stringify(decision).includes(token))
  }
})

test('cyclic and deeply nested values terminate within the traversal bounds', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const cyclic = { token, nested: {} }
  cyclic.nested.self = cyclic
  const withheld = await post({ name: 'cyclic', arguments: {} }, { isError: false, value: cyclic, content: [] }, async () => ({ kind: 'accept', value: cyclic }))
  assert.equal(withheld.kind, 'block')
  assert.ok(!JSON.stringify(withheld).includes(token))
  const quiet = { nested: {} }
  quiet.nested.self = quiet
  const unchanged = await post({ name: 'quiet', arguments: {} }, { isError: false, value: quiet, content: [] }, async () => ({ kind: 'accept', value: quiet }))
  assert.equal(unchanged.kind, 'accept')
  assert.equal(unchanged.value, quiet)
  let deep = { token }
  const leaf = deep
  for (let level = 0; level < 50; level++) deep = { next: deep }
  const bounded = await post({ name: 'deep', arguments: {} }, { isError: false, value: deep, content: [] }, async () => ({ kind: 'accept', value: deep }))
  // Beyond the traversal bound the value is not scanned and is retained as-is.
  assert.equal(bounded.kind, 'accept')
  assert.equal(bounded.value, deep)
  assert.equal(leaf.token, token)
})

test('an unchanged replacement value never gains a competing content field', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const result = { isError: false, value: 'safe replacement', content: [{ type: 'text', text: token }] }
  const decision = await post({ name: 'echo', arguments: {} }, result, async () => ({ kind: 'accept', value: 'safe replacement' }))
  assert.equal(decision.value, 'safe replacement')
  assert.ok(!Object.hasOwn(decision, 'content'))
})

test('failed calls keep their current value contract (known residual)', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const result = { isError: true, value: token, content: [{ type: 'text', text: token }] }
  const decision = await post({ name: 'failure', arguments: {} }, result, async () => ({ kind: 'accept', value: token }))
  assert.equal(decision.value, token)
  assert.ok(!Object.hasOwn(decision, 'content'))
})
