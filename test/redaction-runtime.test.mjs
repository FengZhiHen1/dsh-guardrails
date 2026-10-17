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
  const [cordis, tools, prompt, ptc] = await Promise.all(['@deepseek-ai/cordis', '@deepseek-ai/dsh-tools', '@deepseek-ai/dsh-system-prompt', '@deepseek-ai/dsh-ptc-runtime'].map(load))
  runtime = { cordis, tools, prompt, ptc }
} catch (error) {
  if (anchor || error.code !== 'MODULE_NOT_FOUND') throw error
}

const secret = `sk-${'Az78'.repeat(12)}`
const signal = new AbortController().signal

async function setup(t, mode = 'native') {
  const ctx = new runtime.cordis.Context()
  t.after(() => ctx.fiber.dispose())
  await ctx.plugin(runtime.prompt.default)
  await ctx.plugin(runtime.tools.default, { mode })
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
const execute = (ctx, name, extra = {}) => ctx.tools.execute({ callId: 'redaction-fixture', name, arguments: {}, signal, ...extra })

test('real ToolRuntime Native validates string replacement; object/meta/error remain bounded residuals', { skip: !runtime && 'Install runtime dependencies or set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t)
  register(ctx, 'string_result', secret)
  const clean = await execute(ctx, 'string_result')
  assert.equal(clean.isError, false)
  assert.equal(clean.value, '[REDACTED]')
  assert.equal(clean.content[0].text, '[REDACTED]')
  register(ctx, 'object_result', { token: secret }, { type: 'object', properties: { token: { type: 'string' } }, required: ['token'], additionalProperties: false })
  const object = await execute(ctx, 'object_result')
  assert.equal(object.isError, false)
  assert.equal(object.value.token, secret)
  assert.ok(!JSON.stringify(object.content).includes(secret))
  register(ctx, 'enum_result', secret, { type: 'string', enum: [secret] })
  const constrained = await execute(ctx, 'enum_result')
  assert.equal(constrained.isError, false)
  assert.equal(constrained.value, secret)
  assert.equal(constrained.content[0].text, '[REDACTED]')
  register(ctx, 'meta_result', { token: secret }, { type: 'object' }, { output: { schema: { type: 'object' }, render: () => [{ type: 'text', text: secret }], presentationMeta: () => ({ token: secret }) } })
  const meta = await execute(ctx, 'meta_result')
  assert.equal(meta.meta.token, secret)
  assert.equal(meta.content[0].text, '[REDACTED]')
  register(ctx, 'failure', null, { type: 'null' }, { execute: async () => { throw new Error(secret) } })
  const failed = await execute(ctx, 'failure')
  assert.equal(failed.isError, true)
  assert.equal(failed.error.message, secret)
  assert.ok(!JSON.stringify(failed.content).includes(secret))
  assert.ok(!Object.hasOwn(failed, 'value'))
})

test('real ToolRuntime PTC bridge separates program values from durable content; log hook runs independently', { skip: !runtime && 'Install runtime dependencies or set DSH_RUNTIME_PATH' }, async t => {
  const ctx = await setup(t, 'ptc')
  class FixturePtcRuntime extends runtime.ptc.PtcRuntime {
    language = 'typescript'
    isolation = 'synthetic-in-process'
    constructor(inner) { super(inner) }
    resolve(request) { return { ...request, cwd: process.cwd(), timeoutMs: 1000 } }
    async run(request) {
      const functions = request.bindings[0].functions
      assert.equal(await functions.string_result({}), '[REDACTED]')
      assert.equal((await functions.object_result({})).token, secret)
      await assert.rejects(functions.failure({}), error => error.message.includes(secret))
      assert.equal(await functions.finalized({}), 'safe canonical value')
      return { logs: [], value: 'completed' }
    }
  }
  await ctx.plugin(FixturePtcRuntime)
  register(ctx, 'string_result', secret)
  register(ctx, 'object_result', { token: secret }, { type: 'object' })
  register(ctx, 'failure', null, { type: 'null' }, { execute: async () => { throw new Error(secret) } })
  // Definition finalization happens after post; the independent log hook masks it.
  register(ctx, 'finalized', 'safe canonical value', { type: 'string' }, { finalizeContent: () => [{ type: 'text', text: secret }] })
  const events = []
  const agent = { session: { header: { cwd: process.cwd() }, append: (type, data) => events.push({ type, data }) } }
  const result = await execute(ctx, 'run_code', { arguments: { code: 'fixture', description: 'Redaction bridge fixture' }, agent })
  assert.equal(result.isError, false)
  const settled = events.filter(event => event.type === 'tool/ptc-dispatch')
  assert.equal(settled.length, 4)
  for (const event of settled) assert.ok(!JSON.stringify(event.data.content).includes(secret))
  assert.ok(settled.every(event => !Object.hasOwn(event.data, 'value')))
})
