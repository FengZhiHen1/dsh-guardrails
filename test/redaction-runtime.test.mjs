// Set DSH_RUNTIME_PATH to a runtime package directory, package.json, or DSH bin.
// Otherwise resolve installed runtime dependencies from this project.
import assert from 'node:assert/strict'
import test from 'node:test'
import { createRequire } from 'node:module'
import { realpathSync } from 'node:fs'
import { resolve, extname } from 'node:path'
import { pathToFileURL } from 'node:url'
import { installRedaction } from '../src/adapter/redaction.js'

const anchor = process.env.DSH_RUNTIME_PATH
const runtimeRequire = anchor ? createRequire(realpathSync(extname(anchor) ? resolve(anchor) : resolve(anchor, 'package.json'))) : createRequire(import.meta.url)
let runtime
try {
  const load = async name => import(pathToFileURL(runtimeRequire.resolve(name)).href)
  // 0.2.2: the tools service no longer takes a `mode`; native and PTC execution are
  // separate executor plugins mounted into the composition.
  const [cordis, tools, prompt, ptc, native] = await Promise.all(['@deepseek-ai/cordis', '@deepseek-ai/dsh-tools', '@deepseek-ai/dsh-system-prompt', '@deepseek-ai/dsh-ptc-runtime', '@deepseek-ai/dsh-tool-executor-native'].map(load))
  runtime = { cordis, tools, prompt, ptc, native }
} catch (error) {
  if (anchor || error.code !== 'MODULE_NOT_FOUND') throw error
}

const secret = `sk-${'Az78'.repeat(12)}`
const signal = new AbortController().signal

async function setup(t, { ptc = false } = {}) {
  const ctx = new runtime.cordis.Context()
  t.after(() => ctx.fiber.dispose())
  await ctx.plugin(runtime.prompt.default)
  await ctx.plugin(runtime.tools.default)
  // 0.2.2 selects execution through a mounted executor, not a tools-service `mode`.
  // The executor package's module namespace itself is the Cordis plugin (exports apply).
  // Only ONE executor may be registered per scope, so mount exactly the one under test.
  if (ptc) {
    const ptcExecutor = await import(pathToFileURL(runtimeRequire.resolve('@deepseek-ai/dsh-tool-executor-ptc')).href)
    await ctx.plugin(ptcExecutor)
  } else {
    await ctx.plugin(runtime.native)
  }
  // Resolve the Agent working directory and confined PTC authority from services.
  ctx.provide('workingDirectory', { ensure: async () => process.cwd() })
  ctx.provide('sandboxPolicy', { resolve: () => ({ mode: 'workspace-write', workspaceRoot: process.cwd() }) })
  installRedaction(ctx)
  return ctx
}
function register(ctx, name, value, schema = { type: 'string' }, extras = {}) {
  ctx.tools.register({
    name, description: 'Synthetic redaction boundary fixture.', parameters: { type: 'object', properties: {}, additionalProperties: false },
    output: { schema, render: (_args, val) => [{ type: 'text', text: typeof val === 'string' ? val : JSON.stringify(val) }] },
    execute: async () => value, ...extras,
  })
}
const execute = async (ctx, name, extra = {}) => {
  const { arguments: args = {}, ...rest } = extra
  const settled = await ctx.tools.execute({
    signal,
    calls: [{ type: 'tool-call', id: `redaction-${name}`, name, arguments: JSON.stringify(args) }],
    ...rest,
  })
  return settled.results[0].result
}

test('real ToolRuntime Native masks plain strings and withholds values it cannot mask', { skip: !runtime && 'Install runtime dependencies or set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t)
  register(ctx, 'string_result', secret)
  const clean = await execute(ctx, 'string_result')
  assert.equal(clean.isError, false)
  assert.equal(clean.value, '[REDACTED:provider]')
  assert.equal(clean.content[0].text, '[REDACTED:provider]')
  register(ctx, 'object_result', { token: secret }, { type: 'object', properties: { token: { type: 'string' } }, required: ['token'], additionalProperties: false })
  const object = await execute(ctx, 'object_result')
  assert.equal(object.isError, true)
  assert.ok(!Object.hasOwn(object, 'value'))
  assert.match(object.content[0].text, /withheld/)
  assert.ok(!JSON.stringify(object).includes(secret))
  register(ctx, 'enum_result', secret, { type: 'string', enum: [secret] })
  const constrained = await execute(ctx, 'enum_result')
  assert.equal(constrained.isError, true)
  assert.match(constrained.content[0].text, /withheld/)
  assert.doesNotMatch(constrained.error.message, /invalid output/)
  assert.ok(!JSON.stringify(constrained).includes(secret))
  register(ctx, 'meta_result', { token: secret }, { type: 'object' }, { output: { schema: { type: 'object' }, render: () => [{ type: 'text', text: secret }], presentationMeta: () => ({ token: secret }) } })
  const meta = await execute(ctx, 'meta_result')
  assert.equal(meta.isError, true)
  assert.match(meta.content[0].text, /withheld/)
  assert.ok(!JSON.stringify(meta).includes(secret))
  register(ctx, 'failure', null, { type: 'null' }, { execute: async () => { throw new Error(secret) } })
  const failed = await execute(ctx, 'failure')
  assert.equal(failed.isError, true)
  assert.match(failed.content[0].text, /This error result was withheld/)
  assert.match(failed.error.message, /This error result was withheld/)
  assert.ok(!JSON.stringify(failed).includes(secret))
  assert.ok(!Object.hasOwn(failed, 'value'))
})

test('real ToolRuntime composition withholds replacement values it cannot mask', { skip: !runtime && 'Install runtime dependencies or set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t)
  // Redaction wraps later handlers, so an inner hook supplies the replacement under test.
  ctx.on('tools/post-execute', async (exec, _result, next) => {
    const decision = await next()
    return { ...decision, value: exec.name === 'enum_result' ? secret : { token: secret, kept: 'unchanged' } }
  })
  register(ctx, 'object_result', { token: secret }, { type: 'object' })
  const object = await execute(ctx, 'object_result')
  assert.equal(object.isError, true)
  assert.match(object.content[0].text, /withheld/)
  assert.ok(!JSON.stringify(object).includes(secret))
  // A constrained string replacement is withheld before the runtime can echo an
  // invalid-output validation error containing the raw value.
  register(ctx, 'enum_result', secret, { type: 'string', enum: [secret] })
  const constrained = await execute(ctx, 'enum_result')
  assert.equal(constrained.isError, true)
  assert.match(constrained.content[0].text, /withheld/)
  assert.doesNotMatch(constrained.error.message, /invalid output/)
  assert.ok(!JSON.stringify(constrained).includes(secret))
})

test('real ToolRuntime withholds unsafe error results', { skip: !runtime && 'Install runtime dependencies or set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t)
  register(ctx, 'error_hit', null, { type: 'null' }, { execute: async () => { throw new Error(secret) } })
  const hit = await execute(ctx, 'error_hit')
  assert.equal(hit.isError, true)
  assert.match(hit.content[0].text, /This error result was withheld/)
  assert.match(hit.error.message, /This error result was withheld/)
  assert.ok(!JSON.stringify(hit).includes(secret))
  register(ctx, 'error_clean', null, { type: 'null' }, { execute: async () => { throw new Error('boom') } })
  const clean = await execute(ctx, 'error_clean')
  assert.equal(clean.isError, true)
  assert.equal(clean.error.message, 'boom')
  assert.equal(clean.content[0].text, 'Error: boom')
  register(ctx, 'error_unknown', null, { type: 'null' }, { execute: async () => { throw new Error('x'.repeat(8 * 1024 * 1024 + 1)) } })
  const unknown = await execute(ctx, 'error_unknown')
  assert.equal(unknown.isError, true)
  assert.match(unknown.content[0].text, /This error result was withheld/)
  assert.ok(!JSON.stringify(unknown).includes('x'.repeat(1000)))
})

test('real ToolRuntime replaces unsafe block info with a fixed identity', { skip: !runtime && 'Install runtime dependencies or set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t)
  ctx.on('tools/post-execute', async (exec, _result, next) => {
    const decision = await next()
    if (exec.name === 'info_hit') return { kind: 'block', feedback: [{ type: 'text', text: 'policy' }], info: { name: 'Fixture', code: 'E1', reason: secret } }
    if (exec.name === 'info_clean') return { kind: 'block', feedback: [{ type: 'text', text: 'policy' }], info: { name: 'Fixture', code: 'E1' } }
    if (exec.name === 'info_unknown') return { kind: 'block', feedback: [{ type: 'text', text: 'policy' }], info: { name: 'Fixture', code: 'E1', reason: 'x'.repeat(8 * 1024 * 1024 + 1) } }
    return decision
  })
  register(ctx, 'info_hit', 'ok')
  const hit = await execute(ctx, 'info_hit')
  assert.equal(hit.isError, true)
  assert.deepEqual(hit.error.info, { name: 'Guardrails', code: 'REDACTED' })
  assert.ok(!JSON.stringify(hit).includes(secret))
  register(ctx, 'info_clean', 'ok')
  const clean = await execute(ctx, 'info_clean')
  assert.equal(clean.isError, true)
  assert.deepEqual(clean.error.info, { name: 'Fixture', code: 'E1' })
  register(ctx, 'info_unknown', 'ok')
  const unknown = await execute(ctx, 'info_unknown')
  assert.equal(unknown.isError, true)
  assert.deepEqual(unknown.error.info, { name: 'Guardrails', code: 'REDACTED' })
})

test('real ToolRuntime withholds unsafe meta', { skip: !runtime && 'Install runtime dependencies or set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t)
  register(ctx, 'meta_hit', 'ok', { type: 'string' }, { output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }], presentationMeta: () => ({ token: secret }) } })
  const hit = await execute(ctx, 'meta_hit')
  assert.equal(hit.isError, true)
  assert.match(hit.content[0].text, /withheld/)
  assert.ok(!JSON.stringify(hit).includes(secret))
  register(ctx, 'meta_clean', 'ok', { type: 'string' }, { output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }], presentationMeta: () => ({ label: 'public' }) } })
  const clean = await execute(ctx, 'meta_clean')
  assert.equal(clean.isError, false)
  assert.deepEqual(clean.meta, { label: 'public' })
  assert.equal(clean.content[0].text, 'ok')
  let nested = { value: 'plain' }
  for (let level = 0; level < 40; level++) nested = { next: nested }
  register(ctx, 'meta_unknown', 'ok', { type: 'string' }, { output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }], presentationMeta: () => nested } })
  const unknown = await execute(ctx, 'meta_unknown')
  assert.equal(unknown.isError, true)
  assert.match(unknown.content[0].text, /withheld/)
})

test('real ToolRuntime withholds content replacements over unsafe values and sanitizes contexts', { skip: !runtime && 'Install runtime dependencies or set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t)
  ctx.on('tools/post-execute', async (exec, _result, next) => {
    const decision = await next()
    if (exec.name.startsWith('content_')) return { ...decision, content: [{ type: 'text', text: 'replacement' }] }
    if (exec.name === 'context_tool') {
      return {
        ...decision,
        additionalContexts: [
          { role: 'user', content: [{ type: 'text', text: secret }] },
          { role: 'user', content: [{ type: 'image', data: 'binary' }] },
          { role: 'user', content: [{ type: 'text', text: 'plain' }] },
        ],
      }
    }
    return decision
  })
  register(ctx, 'content_hit', { token: secret }, { type: 'object' })
  const hit = await execute(ctx, 'content_hit')
  assert.equal(hit.isError, true)
  assert.match(hit.content[0].text, /withheld/)
  assert.ok(!JSON.stringify(hit).includes(secret))
  register(ctx, 'content_clean', { count: 1 }, { type: 'object' })
  const clean = await execute(ctx, 'content_clean')
  assert.equal(clean.isError, false)
  assert.equal(clean.content[0].text, 'replacement')
  assert.deepEqual(clean.value, { count: 1 })
  let deep = { token: 'plain' }
  for (let level = 0; level < 40; level++) deep = { next: deep }
  register(ctx, 'content_unknown', deep, { type: 'object' })
  const unknown = await execute(ctx, 'content_unknown')
  assert.equal(unknown.isError, true)
  assert.match(unknown.content[0].text, /withheld/)
  register(ctx, 'context_tool', 'ok')
  const contexts = await execute(ctx, 'context_tool')
  assert.equal(contexts.isError, false)
  // The unsafe message is dropped; the clean image and text messages are kept.
  assert.equal(contexts.additionalContexts.length, 2)
  assert.equal(contexts.additionalContexts[0].content[0].type, 'image')
  assert.equal(contexts.additionalContexts[1].content[0].text, 'plain')
  assert.ok(!JSON.stringify(contexts).includes(secret))
})

test('real ToolRuntime ends with no value when a hook replaces a failed result value', { skip: !runtime && 'Install runtime dependencies or set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t)
  // Another hook tries to attach a replacement value. Either this hook's
  // defense-in-depth or the runtime's own rejection must leave no value behind.
  ctx.on('tools/post-execute', async (exec, _result, next) => {
    const decision = await next()
    if (exec.name === 'failure_value') return { ...decision, value: 'rejected' }
    if (exec.name === 'failure_secret_value') return { ...decision, value: secret }
    return decision
  })
  register(ctx, 'failure_value', null, { type: 'null' }, { execute: async () => { throw new Error('boom') } })
  const result = await execute(ctx, 'failure_value')
  assert.equal(result.isError, true)
  assert.match(result.error.message, /cannot replace the value of a failed result/)
  assert.ok(!Object.hasOwn(result, 'value'))
  assert.ok(!JSON.stringify(result).includes(secret))
  register(ctx, 'failure_secret_value', null, { type: 'null' }, { execute: async () => { throw new Error('boom') } })
  const defended = await execute(ctx, 'failure_secret_value')
  assert.equal(defended.isError, true)
  assert.match(defended.content[0].text, /This error result was withheld/)
  assert.ok(!Object.hasOwn(defended, 'value'))
  assert.ok(!JSON.stringify(defended).includes(secret))
})

test('real ToolRuntime withholds unsafe tool-supplied contexts', { skip: !runtime && 'Install runtime dependencies or set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t)
  // An around-dispatch wrapper is the real way a tool result gains additionalContexts.
  ctx.on('tools/execute', async (exec, next) => {
    const result = await next()
    const message = exec.name === 'contexts_secret' ? { role: 'user', content: [{ type: 'text', text: secret }] }
      : exec.name === 'contexts_clean' ? { role: 'user', content: [{ type: 'text', text: 'plain' }] }
      : exec.name === 'contexts_image' ? { role: 'user', content: [{ type: 'image', attachment: { name: 'shot.png' } }] }
      : exec.name === 'contexts_image_hit' ? { role: 'user', content: [{ type: 'image', attachment: { name: `shot ${secret}.png` } }] }
      : exec.name === 'contexts_sourced' ? { role: 'user', content: [{ type: 'text', text: 'ok' }], source: { summary: secret } }
      : exec.name === 'contexts_unknown' ? { role: 'user', content: [{ type: 'text', text: 'x'.repeat(8 * 1024 * 1024 + 1) }] }
      : undefined
    return message === undefined ? result : { ...result, additionalContexts: [message] }
  })
  // A decision context is appended after tool-supplied contexts, never substituted.
  ctx.on('tools/post-execute', async (exec, _result, next) => {
    const decision = await next()
    if (exec.name !== 'contexts_clean') return decision
    return { ...decision, additionalContexts: [{ role: 'user', content: [{ type: 'text', text: 'policy' }] }] }
  })
  register(ctx, 'plain_result', 'ok')
  const plain = await execute(ctx, 'plain_result')
  assert.equal(plain.isError, false)
  assert.ok(!Object.hasOwn(plain, 'additionalContexts'))
  register(ctx, 'contexts_secret', 'ok')
  const hit = await execute(ctx, 'contexts_secret')
  assert.equal(hit.isError, true)
  assert.match(hit.content[0].text, /withheld/)
  assert.ok(!JSON.stringify(hit).includes(secret))
  register(ctx, 'contexts_sourced', 'ok')
  const sourced = await execute(ctx, 'contexts_sourced')
  assert.equal(sourced.isError, true)
  assert.match(sourced.content[0].text, /withheld/)
  assert.ok(!JSON.stringify(sourced).includes(secret))
  register(ctx, 'contexts_clean', 'ok')
  const clean = await execute(ctx, 'contexts_clean')
  assert.equal(clean.isError, false)
  assert.deepEqual(clean.additionalContexts.map(message => message.content[0].text), ['plain', 'policy'])
  // A non-text context is allowed when every field is provably clean.
  register(ctx, 'contexts_image', 'ok')
  const image = await execute(ctx, 'contexts_image')
  assert.equal(image.isError, false)
  assert.equal(image.additionalContexts[0].content[0].type, 'image')
  register(ctx, 'contexts_image_hit', 'ok')
  const imageHit = await execute(ctx, 'contexts_image_hit')
  assert.equal(imageHit.isError, true)
  assert.match(imageHit.content[0].text, /withheld/)
  assert.ok(!JSON.stringify(imageHit).includes(secret))
  register(ctx, 'contexts_unknown', 'ok')
  const unknown = await execute(ctx, 'contexts_unknown')
  assert.equal(unknown.isError, true)
  assert.match(unknown.content[0].text, /withheld/)
})

test('real ToolRuntime masks reasoning and tool-call content and withholds unknown blocks', { skip: !runtime && 'Install runtime dependencies or set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t)
  const results = []
  ctx.on('tools/result', (_exec, result) => results.push(result))
  register(ctx, 'reasoning_result', 'ok', { type: 'string' }, { output: { schema: { type: 'string' }, render: () => [{ type: 'reasoning', text: `thinking ${secret}` }] } })
  const reasoning = await execute(ctx, 'reasoning_result')
  assert.equal(reasoning.isError, false)
  assert.equal(reasoning.content[0].text, 'thinking [REDACTED:provider]')
  assert.ok(!JSON.stringify(reasoning).includes(secret))
  register(ctx, 'call_result', 'ok', { type: 'string' }, { output: { schema: { type: 'string' }, render: () => [{ type: 'tool-call', id: 'c1', name: 'echo', arguments: `{"token":"${secret}"}` }] } })
  const call = await execute(ctx, 'call_result')
  assert.equal(call.isError, false)
  assert.equal(call.content[0].arguments, '{"token":"[REDACTED:provider]"}')
  assert.ok(!JSON.stringify(call).includes(secret))
  register(ctx, 'unknown_result', 'ok', { type: 'string' }, { output: { schema: { type: 'string' }, render: () => [{ type: 'custom-block', payload: secret }] } })
  const unknown = await execute(ctx, 'unknown_result')
  assert.equal(unknown.isError, true)
  assert.match(unknown.content[0].text, /withheld/)
  assert.ok(!JSON.stringify(unknown).includes(secret))
  assert.ok(results.length >= 3)
  for (const result of results) assert.ok(!JSON.stringify(result).includes(secret))
})

test('real ToolRuntime admits real tool shapes within the raised scan bounds', { skip: !runtime && 'Install runtime dependencies or set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t)
  register(ctx, 'large_array', Array.from({ length: 2000 }, () => 'plain'), { type: 'array' })
  assert.equal((await execute(ctx, 'large_array')).isError, false)
  register(ctx, 'many_keys', Object.fromEntries(Array.from({ length: 1100 }, (_, index) => [`k${index}`, 'plain'])), { type: 'object' })
  assert.equal((await execute(ctx, 'many_keys')).isError, false)
  let ten = { leaf: 'plain' }
  for (let level = 0; level < 10; level++) ten = { next: ten }
  register(ctx, 'nested_ten', ten, { type: 'object' })
  assert.equal((await execute(ctx, 'nested_ten')).isError, false)
  let deep = { leaf: 'plain' }
  for (let level = 0; level < 40; level++) deep = { next: deep }
  register(ctx, 'nested_deep', deep, { type: 'object' })
  const deepResult = await execute(ctx, 'nested_deep')
  assert.equal(deepResult.isError, true)
  assert.match(deepResult.content[0].text, /withheld/)
})

test('real ToolRuntime projects presentationMeta at the measured baseline', { skip: !runtime && 'Install runtime dependencies and set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t)
  const counts = { clean: 0, replace: 0 }
  register(ctx, 'meta_clean', 'ok', { type: 'string' }, { output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }], presentationMeta: () => { counts.clean++; return { label: 'public' } } } })
  assert.equal((await execute(ctx, 'meta_clean')).isError, false)
  // Pipeline only: one projection for the accepted body value.
  assert.equal(counts.clean, 1)
  register(ctx, 'meta_replace', secret, { type: 'string' }, { output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }], presentationMeta: () => { counts.replace++; return { label: 'public' } } } })
  assert.equal((await execute(ctx, 'meta_replace')).isError, false)
  // Pipeline 2 (body + replacement) + this hook 1 = 3; the hook contributes one call.
  assert.equal(counts.replace, 3)
})

test('real ToolRuntime PTC bridge separates program values from durable content; log hook runs independently', { skip: !runtime && 'Install runtime dependencies or set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t, { ptc: true })
  // 0.2.2: PTC execution is a separate executor plugin (mounted above). The runtime
  // class registers itself as `ptcRuntime` on construction, resolving the service.
  class FixturePtcRuntime extends runtime.ptc.PtcRuntime {
    language = 'typescript'
    isolation = 'synthetic-in-process'
    constructor(inner) { super(inner) }
    resolve(request) { return { ...request, cwd: process.cwd(), timeoutMs: 1000 } }
    async run(request) {
      const functions = request.bindings[0].functions
      assert.equal(await functions.string_result({}), '[REDACTED:provider]')
      await assert.rejects(functions.object_result({}), error => /withheld/.test(error.message) && !error.message.includes(secret))
      await assert.rejects(functions.failure({}), error => /withheld/.test(error.message) && !error.message.includes(secret))
      await assert.rejects(functions.custom_log({}), error => /withheld/.test(error.message) && !error.message.includes(secret))
      assert.equal(await functions.finalized({}), 'safe canonical value')
      return { logs: [], value: 'completed' }
    }
  }
  await ctx.plugin(FixturePtcRuntime)
  register(ctx, 'string_result', secret)
  register(ctx, 'object_result', { token: secret }, { type: 'object' })
  register(ctx, 'failure', null, { type: 'null' }, { execute: async () => { throw new Error(secret) } })
  // Unknown block kinds reach the durable PTC log only as withheld result content.
  register(ctx, 'custom_log', 'ok', { type: 'string' }, { output: { schema: { type: 'string' }, render: () => [{ type: 'custom-block', payload: secret }] } })
  // Definition finalization happens after post; the independent log hook masks it.
  register(ctx, 'finalized', 'safe canonical value', { type: 'string' }, { finalizeContent: () => [{ type: 'text', text: secret }] })
  const events = []
  // 0.2.2 requires an Agent context for release effects and a working directory service.
  const agent = { ctx, session: { header: { cwd: process.cwd() }, append: (type, data) => events.push({ type, data }) } }
  const result = await execute(ctx, 'run_code', { arguments: { code: 'fixture', description: 'Redaction bridge fixture' }, agent })
  assert.equal(result.isError, false)
  const settled = events.filter(event => event.type === 'tool/ptc-dispatch')
  assert.equal(settled.length, 5)
  for (const event of settled) assert.ok(!JSON.stringify(event.data.content).includes(secret))
  assert.ok(settled.every(event => !Object.hasOwn(event.data, 'value')))
})
