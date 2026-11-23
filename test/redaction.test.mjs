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

test('inline literal transmission is detected; echo docs and dynamic tokens survive', () => {
  assert.equal(inlineCredentialDecision([{ name: 'curl', args: ['-H', `Authorization: ${bearer}`, 'https://example.org'] }]), true)
  for (const command of [{ name: 'echo', args: [token] }, { name: 'curl', args: ['-H', 'Authorization: Bearer ${TOKEN}', null] }]) {
    assert.equal(inlineCredentialDecision([command]), false)
  }
  assert.equal(inlineCredentialDecision('not commands'), false)
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
  const replacement = await post({}, { isError: false, value: 'safe', content: result.content }, async () => ({ kind: 'accept', content: [{ type: 'text', text: 'other policy' }] }))
  assert.equal(replacement.content[0].text, 'other policy')
  assert.ok(!Object.hasOwn(replacement, 'value'))
  dispose()
  assert.equal(events.size, 0)
})

test('error text containing a credential withholds the whole failed result', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const result = { isError: true, error: { message: token, info: { name: 'Fixture', code: 'E1' } }, content: [{ type: 'text', text: token }] }
  const decision = await post({}, result, async () => ({ kind: 'accept' }))
  assert.equal(decision.kind, 'block')
  assert.match(decision.feedback[0].text, /withheld/)
  assert.ok(!JSON.stringify(decision).includes(token))
  // The raw result is not mutated; masking applies to the returned decision.
  assert.equal(result.error.message, token)
  const log = await events.get('tools/ptc-dispatch-log')({}, async () => result.content)
  assert.equal(log[0].text, '[REDACTED:provider]')
})

test('error info, meta, and unprovable error text also withhold the failed result', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const clean = { isError: true, error: { message: 'boom' }, content: [{ type: 'text', text: 'visible' }] }
  const unchanged = await post({}, clean, async () => ({ kind: 'accept' }))
  assert.equal(unchanged.kind, 'accept')
  const infoHit = await post({}, { isError: true, error: { message: 'boom', info: { name: 'Fixture', code: 'E1', reason: token } }, content: [] }, async () => ({ kind: 'accept' }))
  assert.equal(infoHit.kind, 'block')
  assert.ok(!JSON.stringify(infoHit).includes(token))
  const unknownText = await post({}, { isError: true, error: { message: 'x'.repeat(8 * 1024 * 1024 + 1) }, content: [] }, async () => ({ kind: 'accept' }))
  assert.equal(unknownText.kind, 'block')
  const metaHit = await post({}, { isError: true, error: { message: 'boom' }, content: [], meta: { token } }, async () => ({ kind: 'accept' }))
  assert.equal(metaHit.kind, 'block')
  assert.ok(!JSON.stringify(metaHit).includes(token))
})

test('unsafe block info is replaced with a fixed error identity', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const result = { isError: false, value: 'ok', content: [] }
  const hit = await post({}, result, async () => ({ kind: 'block', feedback: [{ type: 'text', text: 'policy' }], info: { name: 'Fixture', code: 'E1', reason: token } }))
  assert.deepEqual(hit.info, { name: 'Guardrails', code: 'REDACTED' })
  assert.ok(!JSON.stringify(hit).includes(token))
  const clean = await post({}, result, async () => ({ kind: 'block', feedback: [{ type: 'text', text: 'policy' }], info: { name: 'Fixture', code: 'E1' } }))
  assert.deepEqual(clean.info, { name: 'Fixture', code: 'E1' })
  const unknown = await post({}, result, async () => ({ kind: 'block', feedback: [], info: { name: 'Fixture', code: 'E1', reason: 'x'.repeat(8 * 1024 * 1024 + 1) } }))
  assert.deepEqual(unknown.info, { name: 'Guardrails', code: 'REDACTED' })
})

test('meta that cannot be proven clean withholds the result', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const hit = await post({}, { isError: false, value: 'ok', content: [], meta: { token } }, async () => ({ kind: 'accept' }))
  assert.equal(hit.kind, 'block')
  assert.ok(!JSON.stringify(hit).includes(token))
  const clean = await post({}, { isError: false, value: 'ok', content: [], meta: { label: 'public' } }, async () => ({ kind: 'accept' }))
  assert.equal(clean.kind, 'accept')
  const unknown = await post({}, { isError: false, value: 'ok', content: [], meta: { blob: 'x'.repeat(8 * 1024 * 1024 + 1) } }, async () => ({ kind: 'accept' }))
  assert.equal(unknown.kind, 'block')
})

test('a replacement whose candidate meta is unsafe is withheld', async () => {
  const { ctx, events } = harness()
  ctx.tools.executable = () => ({
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }], presentationMeta: () => ({ token }) },
  })
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const decision = await post({ name: 'meta_tool', arguments: {} }, { isError: false, value: token, content: [] }, async () => ({ kind: 'accept', value: token }))
  assert.equal(decision.kind, 'block')
  assert.ok(!JSON.stringify(decision).includes(token))
})

test('an unchanged replacement value still withholds an unsafe candidate meta', async () => {
  const { ctx, events } = harness()
  ctx.tools.executable = () => ({
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }], presentationMeta: () => ({ token }) },
  })
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const decision = await post({ name: 'meta_tool', arguments: {} }, { isError: false, value: 'safe text', content: [] }, async () => ({ kind: 'accept', value: 'safe text' }))
  assert.equal(decision.kind, 'block')
  assert.ok(!JSON.stringify(decision).includes(token))
})

test('a content replacement withholds an unsafe underlying value', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const replacement = [{ type: 'text', text: 'replacement' }]
  const hit = await post({}, { isError: false, value: { token }, content: [] }, async () => ({ kind: 'accept', content: replacement }))
  assert.equal(hit.kind, 'block')
  assert.ok(!JSON.stringify(hit).includes(token))
  const clean = await post({}, { isError: false, value: { count: 2 }, content: [] }, async () => ({ kind: 'accept', content: replacement }))
  assert.equal(clean.kind, 'accept')
  assert.equal(clean.content[0].text, 'replacement')
  let deep = { token }
  for (let level = 0; level < 50; level++) deep = { next: deep }
  const unknown = await post({}, { isError: false, value: deep, content: [] }, async () => ({ kind: 'accept', content: replacement }))
  assert.equal(unknown.kind, 'block')
  const withValue = await post({}, { isError: false, value: { token }, content: [] }, async () => ({ kind: 'accept', content: replacement, value: { token } }))
  assert.equal(withValue.kind, 'block')
})

test('decision contexts are kept only when the whole message is proven clean', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const clean = { role: 'user', content: [{ type: 'text', text: 'plain' }] }
  const image = { role: 'user', content: [{ type: 'image', attachment: { name: 'shot.png' } }] }
  const sourced = { role: 'user', content: [{ type: 'text', text: 'ok' }], source: { summary: token } }
  const contexts = [{ role: 'user', content: [{ type: 'text', text: token }] }, clean, image, sourced]
  const decision = await post({}, { isError: false, value: 'ok', content: [] }, async () => ({ kind: 'accept', additionalContexts: contexts }))
  assert.equal(decision.additionalContexts.length, 2)
  assert.equal(decision.additionalContexts[0], clean)
  assert.equal(decision.additionalContexts[1], image)
  assert.ok(!JSON.stringify(decision).includes(token))
  const broken = await post({}, { isError: false, value: 'ok', content: [] }, async () => ({ kind: 'accept', additionalContexts: 'nope' }))
  assert.deepEqual(broken.additionalContexts, [])
  const same = await post({}, { isError: false, value: 'ok', content: [] }, async () => ({ kind: 'accept', additionalContexts: [clean] }))
  assert.equal(same.additionalContexts[0], clean)
})

test('content redaction covers text-bearing, executable, and name fields only', () => {
  const image = { type: 'image', attachment: { name: `file ${token}`, id: 'attach' } }
  const call = { type: 'tool-call', id: 'call', name: token, arguments: token }
  const reasoning = { type: 'reasoning', text: `thinking ${token}`, signature: 'kept' }
  const addition = { type: 'tool-addition', toolName: token }
  const result = redactContent([image, call, reasoning, addition])
  assert.equal(result[0].attachment.name, 'file [REDACTED:provider]')
  assert.equal(result[0].attachment.id, 'attach')
  assert.equal(result[1].name, '[REDACTED:provider]')
  assert.equal(result[1].arguments, '[REDACTED:provider]')
  assert.equal(result[1].id, 'call')
  assert.equal(result[2].text, 'thinking [REDACTED:provider]')
  assert.equal(result[2].signature, 'kept')
  assert.equal(result[3].toolName, '[REDACTED:provider]')
})

test('reasoning and tool-call content are masked; unknown blocks are withheld only when unprovable', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const reasoning = await post({}, { isError: false, value: 'ok', content: [{ type: 'reasoning', text: `thinking ${token}` }] }, async () => ({ kind: 'accept' }))
  assert.equal(reasoning.kind, 'accept')
  assert.equal(reasoning.content[0].text, 'thinking [REDACTED:provider]')
  const call = await post({}, { isError: false, value: 'ok', content: [{ type: 'tool-call', id: 'c1', name: 'echo', arguments: `{"token":"${token}"}` }] }, async () => ({ kind: 'accept' }))
  assert.equal(call.kind, 'accept')
  assert.equal(call.content[0].arguments, '{"token":"[REDACTED:provider]"}')
  const unknownHit = await post({}, { isError: false, value: 'ok', content: [{ type: 'custom-block', payload: token }] }, async () => ({ kind: 'accept' }))
  assert.equal(unknownHit.kind, 'block')
  assert.ok(!JSON.stringify(unknownHit).includes(token))
  const unknownClean = await post({}, { isError: false, value: 'ok', content: [{ type: 'custom-block', payload: 'plain' }] }, async () => ({ kind: 'accept' }))
  assert.equal(unknownClean.kind, 'accept')
})

test('a safe string replacement projects presentationMeta once and clean results not at all', async () => {
  const { ctx, events } = harness()
  let calls = 0
  ctx.tools.executable = () => ({
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }], presentationMeta: () => { calls++; return { label: 'public' } } },
  })
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const decision = await post({ name: 'plain_tool', arguments: {} }, { isError: false, value: token, content: [] }, async () => ({ kind: 'accept', value: token }))
  assert.equal(decision.kind, 'accept')
  assert.equal(decision.value, '[REDACTED:provider]')
  assert.equal(calls, 1)
  calls = 0
  const clean = await post({ name: 'plain_tool', arguments: {} }, { isError: false, value: 'ok', content: [] }, async () => ({ kind: 'accept' }))
  assert.equal(clean.kind, 'accept')
  assert.equal(calls, 0)
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

test('traversal bounds admit real tool shapes and withhold only unprovable ones', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const accept = value => post({ name: 'tool', arguments: {} }, { isError: false, value, content: [] }, async () => ({ kind: 'accept', value }))
  const cyclic = { token, nested: {} }
  cyclic.nested.self = cyclic
  const withheld = await accept(cyclic)
  assert.equal(withheld.kind, 'block')
  assert.ok(!JSON.stringify(withheld).includes(token))
  const quiet = { nested: {} }
  quiet.nested.self = quiet
  assert.equal((await accept(quiet)).kind, 'accept')
  assert.equal((await accept({ a: { b: { c: 'plain' } } })).kind, 'accept')
  // Real reachable shapes stay inside the raised bounds.
  assert.equal((await accept(Array.from({ length: 2000 }, () => 'plain'))).kind, 'accept')
  assert.equal((await accept(Object.fromEntries(Array.from({ length: 1100 }, (_, index) => [`k${index}`, 'plain'])))).kind, 'accept')
  let ten = { leaf: 'plain' }
  for (let level = 0; level < 10; level++) ten = { next: ten }
  assert.equal((await accept(ten)).kind, 'accept')
  // Sharing a reference is not re-flagged when reached shallow first.
  const shared = { value: 'plain' }
  let tail = shared
  for (let level = 0; level < 5; level++) tail = { next: tail }
  assert.equal((await accept({ shallow: shared, chain: tail })).kind, 'accept')
  // Beyond the bounds the value cannot be proven clean, so it is withheld.
  let deep = { token }
  const leaf = deep
  for (let level = 0; level < 40; level++) deep = { next: deep }
  const bounded = await accept(deep)
  assert.equal(bounded.kind, 'block')
  assert.ok(!JSON.stringify(bounded).includes(token))
  assert.equal(leaf.token, token)
  for (const value of [
    Array.from({ length: 65537 }, () => 'plain'),
    Object.fromEntries(Array.from({ length: 65537 }, (_, index) => [`k${index}`, 'plain'])),
    { blob: 'x'.repeat(8 * 1024 * 1024 + 1) },
    { when: new Date(0) },
    { map: new Map([['k', 'v']]) },
  ]) {
    assert.equal((await accept(value)).kind, 'block')
  }
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

test('tool-supplied result contexts are scanned as whole messages', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const run = (additionalContexts, value = 'ok') => post({ name: 'tool', arguments: {} }, { isError: false, value, content: [], additionalContexts }, async () => ({ kind: 'accept' }))
  const hit = await run([{ role: 'user', content: [{ type: 'text', text: token }] }])
  assert.equal(hit.kind, 'block')
  assert.ok(!JSON.stringify(hit).includes(token))
  const sourced = await run([{ role: 'user', content: [{ type: 'text', text: 'ok' }], source: { summary: token } }])
  assert.equal(sourced.kind, 'block')
  assert.ok(!JSON.stringify(sourced).includes(token))
  const clean = await run([{ role: 'user', content: [{ type: 'text', text: 'plain' }] }])
  assert.equal(clean.kind, 'accept')
  // A non-text context is allowed when every field is provably clean.
  const image = await run([{ role: 'user', content: [{ type: 'image', attachment: { name: 'shot.png' } }] }])
  assert.equal(image.kind, 'accept')
  const imageHit = await run([{ role: 'user', content: [{ type: 'image', attachment: { name: `shot ${token}.png` } }] }])
  assert.equal(imageHit.kind, 'block')
  assert.ok(!JSON.stringify(imageHit).includes(token))
  const unknown = await run([{ role: 'user', content: [{ type: 'text', text: 'x'.repeat(8 * 1024 * 1024 + 1) }] }])
  assert.equal(unknown.kind, 'block')
  const absent = await run(undefined)
  assert.equal(absent.kind, 'accept')
  const malformed = await run('not messages')
  assert.equal(malformed.kind, 'block')
  const failed = await post({ name: 'tool', arguments: {} }, { isError: true, error: { message: 'boom' }, content: [], additionalContexts: [{ role: 'user', content: [{ type: 'text', text: 'plain' }] }] }, async () => ({ kind: 'accept' }))
  assert.equal(failed.kind, 'accept')
  const failedHit = await post({ name: 'tool', arguments: {} }, { isError: true, error: { message: 'boom' }, content: [], additionalContexts: [{ role: 'user', content: [{ type: 'text', text: token }] }] }, async () => ({ kind: 'accept' }))
  assert.equal(failedHit.kind, 'block')
  assert.ok(!JSON.stringify(failedHit).includes(token))
})

test('PTC dispatch log deep-masks every string and withholds unprovable blocks', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const log = events.get('tools/ptc-dispatch-log')
  const callLog = content => log({}, async () => content)
  const mixed = [
    { type: 'text', text: `before ${token}` },
    { type: 'tool-call', id: 'call-1', name: 'echo', arguments: `{"t":"${token}"}` },
    { type: 'custom-block', payload: token },
    { type: 'text', text: 'plain', extra: { nested: token } },
  ]
  const masked = await callLog(mixed)
  assert.equal(masked.length, 4)
  assert.equal(masked[0].text, 'before [REDACTED:provider]')
  assert.equal(masked[1].arguments, '{"t":"[REDACTED:provider]"}')
  assert.equal(masked[1].id, 'call-1')
  assert.deepEqual(masked[2], { type: 'text', text: '[Guardrails] log content withheld' })
  assert.equal(masked[3].text, 'plain')
  assert.equal(masked[3].extra.nested, '[REDACTED:provider]')
  assert.ok(!JSON.stringify(masked).includes(token))
  const clean = [{ type: 'text', text: 'plain' }]
  const unchanged = await callLog(clean)
  assert.deepEqual(unchanged, clean)
  assert.equal(unchanged[0], clean[0])
  const withheld = { type: 'text', text: '[Guardrails] log content withheld' }
  const oversized = await callLog([{ type: 'text', text: 'x'.repeat(8 * 1024 * 1024 + 1) }])
  assert.deepEqual(oversized, [withheld])
  const cyclic = { type: 'text', text: 'ok' }
  cyclic.self = cyclic
  assert.deepEqual(await callLog([cyclic]), [withheld])
  assert.deepEqual(await callLog([{ type: 'text', text: 'ok', fn: () => 'x' }]), [withheld])
  assert.deepEqual(await callLog([{ type: 'text', text: 'ok', when: new Date(0) }]), [withheld])
  const unknown = await callLog([{ type: 'custom', payload: token }])
  assert.deepEqual(unknown, [withheld])
  assert.ok(!JSON.stringify(unknown).includes(token))
  const whole = await callLog({ not: 'blocks', token })
  assert.deepEqual(whole, [withheld])
  assert.ok(!JSON.stringify(whole).includes(token))
  assert.deepEqual(await log({}, async () => { throw new Error(token) }), [withheld])
})

test('a failed result carrying a credential-bearing value is withheld by defense in depth', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  for (const value of [{ token }, token]) {
    const result = { isError: true, value, content: [{ type: 'text', text: token }] }
    const decision = await post({ name: 'failure', arguments: {} }, result, async () => ({ kind: 'accept' }))
    assert.equal(decision.kind, 'block')
    assert.match(decision.feedback[0].text, /withheld/)
    assert.ok(!JSON.stringify(decision).includes(token))
  }
  // An upstream hook injecting a replacement value on a failure is covered too.
  const injected = await post({ name: 'failure', arguments: {} }, { isError: true, content: [] }, async () => ({ kind: 'accept', value: token }))
  assert.equal(injected.kind, 'block')
  assert.ok(!JSON.stringify(injected).includes(token))
})

test('a failed result with a clean value keeps its usual error handling', async () => {
  const { ctx, events } = harness()
  installRedaction(ctx)
  const post = events.get('tools/post-execute')
  const clean = { isError: true, value: { label: 'ok' }, content: [{ type: 'text', text: 'visible' }] }
  const decision = await post({ name: 'failure', arguments: {} }, clean, async () => ({ kind: 'accept' }))
  assert.equal(decision.kind, 'accept')
  assert.ok(!Object.hasOwn(decision, 'content'))
  const masked = await post({ name: 'failure', arguments: {} }, { isError: true, value: { label: 'ok' }, content: [{ type: 'text', text: token }] }, async () => ({ kind: 'accept' }))
  assert.equal(masked.content[0].text, '[REDACTED:provider]')
})
