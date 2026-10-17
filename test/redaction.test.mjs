import assert from 'node:assert/strict'
import test from 'node:test'
import { redactText, redactContent, inlineCredentialDecision } from '../src/core/redaction.js'
import { installRedaction } from '../src/adapter/redaction.js'

const token = `sk-${'Ab7Q'.repeat(12)}`
const bearer = `Bearer ${'Aa91'.repeat(10)}`
const jwt = [Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url'), Buffer.from(JSON.stringify({ sub: 'fixture' })).toString('base64url'), 'signature'.repeat(4)].join('.')
// quality-floor: ignore hardcoded-secret Generated base64 test prose is synthetic and contains no private key.
const pem = ['-----BEGIN PRIVATE KEY-----', Buffer.from('synthetic fixture only '.repeat(4)).toString('base64'), '-----END PRIVATE KEY-----'].join('\n')

test('recognized credentials are completely masked without retained token edges', () => {
  for (const secret of [token, bearer, jwt, pem, `ghp_${'Az19'.repeat(10)}`]) {
    const masked = redactText(`before ${secret} after`)
    assert.equal(masked.changed, true)
    assert.equal(masked.text, `before ${secret === bearer ? 'Bearer ' : ''}[REDACTED] after`)
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
  assert.equal(result[0].text, '[REDACTED] [REDACTED]')
  assert.equal(result[0].annotation, 'kept')
  assert.equal(result[1], image)
})

test('inline literal transmission is corrective deny; echo docs and dynamic tokens survive', () => {
  const decision = inlineCredentialDecision([{ name: 'curl', args: ['-H', `Authorization: ${bearer}`, 'https://example.org'] }])
  assert.equal(decision.kind, 'deny')
  assert.equal(decision.ruleId, 'R-M2')
  assert.ok(!decision.reason.includes(bearer))
  for (const command of [{ name: 'echo', args: [token] }, { name: 'curl', args: ['-H', 'Authorization: Bearer ${TOKEN}', null] }]) {
    assert.equal(inlineCredentialDecision([command]), undefined)
  }
})

function harness() {
  const events = new Map()
  const ctx = {
    effect: factory => factory(),
    tools: { get: () => ({ output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] } }) },
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
  assert.equal(decision.value, '[REDACTED]')
  assert.ok(!Object.hasOwn(decision, 'content'))
  assert.equal(decision.additionalContexts, contexts)
  const block = await post({}, result, async () => ({ kind: 'block', feedback: result.content, additionalContexts: contexts }))
  assert.equal(block.kind, 'block')
  assert.equal(block.feedback[0].text, '[REDACTED]')
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
  assert.equal(decision.content[0].text, '[REDACTED]')
  assert.ok(!Object.hasOwn(decision, 'value'))
  assert.equal(result.error.message, token)
  const log = await events.get('tools/ptc-dispatch-log')({}, async () => result.content)
  assert.equal(log[0].text, '[REDACTED]')
})
