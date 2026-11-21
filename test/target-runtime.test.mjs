// Real-runtime isolated acceptance tests for the dsh-guardrails target design
// (docs/ technical-details + DSR-025…027), run against an actual DSH 0.2.2-rc.2
// runtime through test/fixtures/target-runtime/runtime-harness.mjs.
//
// Environment contract:
// - The runtime is located ONLY through DSH_RUNTIME_PATH (launcher versions/0.2.2-rc.2,
//   its package dir, or a package.json path). Without it every test skips.
// - No DSH instance is started, no profile is written, no destructive command runs.
//   Every target is a managed mkdtemp directory under os.tmpdir(); tool bodies are
//   counting no-ops; the only mutations are the harness's own fixture writes and the
//   cleanup of those same fixtures.
//
// Matrix targets (docs/technical-details/工程结构与测试体系.md):
//   AC-01b / GT-10  20/21 deletion boundary through the real pipeline
//   AC-01f          protected-file read confirmation
//   GT-02 / GF-07   prepended pre-execute short-circuit still refuses at the final guard
//   GT-09 / DSR-027 outer run_code passes; SDK inner apply_patch dispatches are decided
//                   per dispatch, not re-inventoried by the outer program
//   GT-12           tools outside the deletion analysis keep the DSH permission flow
//   GT-13           real ApprovalService never policy rejects a confirmation
//   GT-14 (real)    the official optional apply_patch definition (dsh-tool-fs over
//                   dsh-fs-local, applyPatch: true) registered and dispatched in this
//                   composition, with the gate judging the whole patch
//   GT-14 (gate)    whole-patch judgment with a synthetic apply_patch registration —
//                   this covers ONLY the gate's parsePatch-level judgment and counting
//                   over the patch text; it is NOT live-registration evidence (GT-01)
//
// The gate cases are written against the target contract of docs/. They run the
// package entry (index.js: apply/Config/name/inject); with a runtime anchor provided,
// an entry import failure fails the affected tests instead of skipping them — an
// integration defect must not look like an environment skip. A skip is never a pass
// (工程结构与测试体系.md 判决规则).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { writeFile } from 'node:fs/promises'
import * as harness from './fixtures/target-runtime/runtime-harness.mjs'

const runtimeSkip = !harness.runtime && harness.runtimeSkipReason
let gate
let gateImportError
if (harness.runtime) {
  try {
    gate = await import('../index.js')
  } catch (error) {
    gateImportError = error
  }
}
const gateSkip = runtimeSkip

/** Fail the calling gate test loudly when the entry cannot load. */
function gateOrThrow() {
  if (gateImportError) throw gateImportError
  if (!gate) throw new Error('dsh-guardrails entry (index.js) did not load')
  return gate
}

/**
 * Mount the real runtime composition with the real ApprovalService configured
 * `ask` (the harness `real-never` option can only configure `never`). A test can
 * then append an `approval/policy` session event to create a session-level
 * override, which is the production path this fixture exists to exercise.
 */
async function mountRealApproval(t, { root, gateModule, config }) {
  const rt = harness.runtime
  const ctx = new rt.cordis.Context()
  t.after(() => ctx.fiber.dispose())
  await ctx.plugin(rt.prompt.default)
  await ctx.plugin(rt.tools.default)
  await ctx.plugin(rt.native)
  ctx.provide('workingDirectory', { get: () => root, ensure: async () => root })
  ctx.provide('sandboxPolicy', { resolve: () => ({ mode: 'workspace-write', workspaceRoot: root }) })
  const fsLocal = await harness.loadRuntimePackage('@deepseek-ai/dsh-fs-local')
  await ctx.plugin(fsLocal.default, { cwd: root })
  await ctx.plugin(rt.projections.default)
  await ctx.plugin(rt.userApproval.default, { policy: 'ask' })
  await ctx.plugin({ name: 'guardrails-test-mount', inject: ['tools'], apply: gateModule.apply }, config ?? {})
  return ctx
}

test('harness: the real runtime composition dispatches an ordinary tool once', { skip: runtimeSkip }, async t => {
  const { ctx, root } = await harness.mount(t, { label: 'selfcheck' })
  const counter = { calls: 0 }
  harness.registerCounting(ctx, 'note', counter)
  const observed = harness.observePreExecute(ctx).log
  const result = await harness.runTool(ctx, harness.makeAgent(root, ctx).agent, 'note', { text: 'x' })
  assert.equal(result.isError, false, result.error?.message)
  assert.equal(counter.calls, 1, 'the tool body dispatched exactly once')
  assert.deepEqual(observed.map(entry => entry.name), ['note'], 'the appended observer saw the forwarded execution')
})

test('AC-01b: a 20-file pwsh delete is allowed and dispatches the body once', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'twenty')
  const dir = await harness.writeTree(root, 'delete-me', 20)
  const { ctx, approvalRequests } = await harness.mount(t, { label: 'gate', workingDirectory: root, gate: gateOrThrow() })
  const counter = { calls: 0 }
  harness.registerCounting(ctx, 'pwsh', counter)
  const observed = harness.observePreExecute(ctx).log
  const result = await harness.runTool(ctx, harness.makeAgent(root, ctx).agent, 'pwsh',
    { command: `Remove-Item -LiteralPath ${harness.psLiteral(dir)} -Recurse -Force` })
  assert.equal(result.isError, false, result.error?.message)
  assert.equal(counter.calls, 1, 'an ordinary in-threshold delete dispatches its body once')
  assert.equal(approvalRequests.length, 0, 'an in-threshold delete needs no confirmation')
  assert.deepEqual(observed.map(entry => entry.name), ['pwsh'])
})

test('AC-01b: a 21-file pwsh delete confirms once, refuses, and never dispatches', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'twentyone')
  const dir = await harness.writeTree(root, 'delete-me', 21)
  const { ctx, approvalRequests } = await harness.mount(t, { label: 'gate', workingDirectory: root, gate: gateOrThrow(), approval: 'rejected' })
  const counter = { calls: 0 }
  harness.registerCounting(ctx, 'pwsh', counter)
  const result = await harness.runTool(ctx, harness.makeAgent(root, ctx).agent, 'pwsh',
    { command: `Remove-Item -LiteralPath ${harness.psLiteral(dir)} -Recurse -Force` })
  assert.equal(result.isError, true, 'above the threshold the call is refused')
  assert.equal(counter.calls, 0, 'a refused delete never dispatches the body')
  assert.equal(approvalRequests.length, 1, 'exactly one plugin confirmation was requested')
  assert.equal(existsSync(dir), true, 'the managed target is untouched')
  const message = result.error?.message ?? ''
  assert.match(message, /data\.delete\.bulk|DEL-01|at least 21|limit 20|bulk/i,
    `the bulk-deletion signal must identify the rule: ${message}`)
})

test('AC-01f: a protected-file read asks once and refuses when the grant is rejected', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'protected-read')
  const marked = join(root, 'id_rsa')
  const ordinary = join(root, 'ordinary.txt')
  await writeFile(marked, 'synthetic fixture only')
  await writeFile(ordinary, 'synthetic fixture only')
  const { ctx, approvalRequests } = await harness.mount(t, {
    label: 'gate', workingDirectory: root, gate: gateOrThrow(), config: { sensitiveFiles: [marked] }, approval: 'rejected',
  })
  const counter = { calls: 0 }
  harness.registerCounting(ctx, 'read', counter)
  const agent = harness.makeAgent(root, ctx).agent
  const ordinaryResult = await harness.runTool(ctx, agent, 'read', { file_path: ordinary })
  assert.equal(ordinaryResult.isError, false, ordinaryResult.error?.message)
  assert.equal(counter.calls, 1)
  assert.equal(approvalRequests.length, 0, 'an unmarked read needs no confirmation')
  const protectedResult = await harness.runTool(ctx, agent, 'read', { file_path: marked })
  assert.equal(protectedResult.isError, true, 'a rejected protected read is refused')
  assert.equal(counter.calls, 1, 'the refused read never dispatches the body')
  assert.equal(approvalRequests.length, 1, 'exactly one confirmation was requested for the protected read')
  // The matrix signal lives in the confirmation request body: the rule id AND the
  // protected target file list (AC-01f: 确认请求体含目标文件清单). The final refusal
  // renders the approval outcome on top of the stored decision.
  const request = approvalRequests[0]
  assert.equal(request.toolName, 'read')
  assert.match(request.reason ?? '', /S-F1|credential\.file\.read/i,
    `the confirmation request identifies the protected-read rule: ${request.reason}`)
  assert.ok(String(request.reason).includes(marked), 'the confirmation request lists the protected target file')
  assert.match(protectedResult.error?.message ?? '', /GUARDRAILS/,
    `the final refusal is rendered by guardrails: ${protectedResult.error?.message}`)
})

test('GT-08: a protected file changed during approval is refused before dispatch', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'changed-after-ask')
  const marked = join(root, 'protected.txt')
  await writeFile(marked, 'initial fixture')
  const { ctx, approvalRequests } = await harness.mount(t, {
    workingDirectory: root, gate: gateOrThrow(), config: { sensitiveFiles: [marked] },
    async approval() {
      await writeFile(marked, 'second version with a different size')
      return 'allowed-once'
    },
  })
  const counter = { calls: 0 }
  harness.registerCounting(ctx, 'read', counter)
  const result = await harness.runTool(ctx, harness.makeAgent(root, ctx).agent, 'read', { file_path: marked })
  assert.equal(approvalRequests.length, 1)
  assert.equal(counter.calls, 0)
  assert.equal(result.isError, true)
  assert.match(result.error?.message ?? '', /GUARD_SCOPE_CHANGED/)
})

test('GT-13: the real ApprovalService never policy refuses with APPROVAL_UNAVAILABLE when no question UI exists', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'approval-never')
  const marked = join(root, 'id_rsa')
  const ordinary = join(root, 'ordinary.txt')
  await writeFile(marked, 'synthetic fixture only')
  await writeFile(ordinary, 'synthetic fixture only')
  const { ctx } = await harness.mount(t, {
    label: 'gate', workingDirectory: root, gate: gateOrThrow(), config: { sensitiveFiles: [marked] }, approval: 'real-never',
  })
  const counter = { calls: 0 }
  harness.registerCounting(ctx, 'read', counter)
  const session = harness.realSession('target-runtime-never')
  const agent = { session, ctx }
  const ordinaryResult = await harness.runTool(ctx, agent, 'read', { file_path: ordinary })
  assert.equal(ordinaryResult.isError, false, ordinaryResult.error?.message)
  const protectedResult = await harness.runTool(ctx, agent, 'read', { file_path: marked })
  assert.equal(protectedResult.isError, true, 'the never policy refuses without reaching any answerer')
  assert.equal(counter.calls, 1, 'only the ordinary read dispatched')
  // With alwaysAsk on but no mounted interactive answerer, the gate reports that no
  // confirmation UI exists — never a "user rejected" text.
  const message = protectedResult.error?.message ?? ''
  assert.match(message, /APPROVAL_UNAVAILABLE: No confirmation UI is available/)
  assert.doesNotMatch(message, /The user rejected/)
  // The never policy is now resolved by the gate before the approval seam, so the
  // official approval audit pair is intentionally not written on this path.
  const types = session.snapshotEvents().map(event => event.type)
  assert.ok(!types.includes('approval/asked'))
})

test('alwaysAsk: with the real never policy and an interactive answerer, a protected read asks through the question channel and grants', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'always-ask')
  const marked = join(root, 'id_rsa')
  await writeFile(marked, 'synthetic fixture only')
  const { ctx } = await harness.mount(t, {
    workingDirectory: root, gate: gateOrThrow(), config: { sensitiveFiles: [marked] }, approval: 'real-never',
  })
  const asks = []
  ctx.provide('userQuestions', {
    async ask(request) {
      asks.push(request)
      return { answers: [{ id: 'guardrails-confirm', selected: ['Allow once'] }] }
    },
  })
  const counter = { calls: 0 }
  harness.registerCounting(ctx, 'read', counter)
  const session = harness.realSession('target-runtime-always-ask')
  const agent = { session, ctx }
  const result = await harness.runTool(ctx, agent, 'read', { file_path: marked })
  assert.equal(result.isError, false, result.error?.message)
  assert.equal(counter.calls, 1, 'the granted protected read dispatched its body')
  assert.equal(asks.length, 1, 'exactly one interactive question was asked')
  const question = asks[0].questions[0]
  assert.equal(question.intent.kind, 'approval')
  assert.ok(typeof question.detail === 'string' && question.detail.length > 0)
  // The top-level fallback detail is the same single-paragraph English summary.
  assert.match(question.detail, /^Confirmation needed \(this call only\): /)
  assert.doesNotMatch(question.detail, /\n/)
  assert.equal(question.detail, question.intent.display.detail.en)
  // The real approval seam stayed out of the decision: no approval audit pair was written.
  assert.ok(!session.snapshotEvents().some(event => event.type === 'approval/asked'))
})

test('alwaysAsk: a session approval-policy override to never asks through the question channel and grants one invocation', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'override-never')
  const marked = join(root, 'id_rsa')
  await writeFile(marked, 'synthetic fixture only')
  // Real ApprovalService configured `ask`; the never policy comes from a session
  // override event, not from config.policy — the production session-switch path.
  const ctx = await mountRealApproval(t, { root, gateModule: gateOrThrow(), config: { sensitiveFiles: [marked] } })
  const asks = []
  ctx.provide('userQuestions', {
    async ask(request) {
      asks.push(request)
      return { answers: [{ id: 'guardrails-confirm', selected: ['Allow once'] }] }
    },
  })
  const counter = { calls: 0 }
  harness.registerCounting(ctx, 'read', counter)
  const session = harness.realSession('target-runtime-override-never')
  session.append('approval/policy', { policy: 'never' })
  const agent = { session, ctx }

  const runRead = id => ctx.tools.execute({
    signal: new AbortController().signal,
    agent,
    calls: [harness.toolCall('read', { file_path: marked }, id)],
  })

  const firstResponse = await runRead('read-1')
  const first = firstResponse.results[0].result
  assert.equal(first.isError, false, first.error?.message)
  assert.equal(counter.calls, 1, 'the granted protected read dispatched its body once')
  assert.equal(asks.length, 1, 'exactly one interactive question was asked')
  assert.equal(asks[0].questions[0].intent.kind, 'approval')
  assert.ok(!session.snapshotEvents().some(event => event.type === 'approval/asked'),
    'the overridden never policy bypasses the approval audit seam')
  // The real post-execute pipeline carries the structured confirmation notice.
  const notice = (firstResponse.additionalContexts ?? []).find(message => message?.source?.kind === 'dsh-guardrails')
  assert.ok(notice, 'the confirmation notice must ride on the batch additionalContexts')
  const noticeText = notice.content[0].text
  assert.match(noticeText, /^\[Guardrails\] Approved once for this call; this approval is not reusable\./)
  for (const marker of ['rule=credential.file.read', 'confirmed_by=answerer', 'channel=question-card', 'this_call_only=yes']) {
    assert.ok(noticeText.includes(marker), `notice must contain ${marker}: ${noticeText}`)
  }
  assert.match(noticeText, /scope=Confirmation needed \(this call only\)/, `notice scope must be human: ${noticeText}`)
  assert.doesNotMatch(noticeText, /non-exempt entries:/, noticeText)
  assert.match(notice.source.summary, /credential\.file\.read/, notice.source.summary)

  // One-time authorization: a second identical invocation asks again and grants again.
  const secondResponse = await runRead('read-2')
  const second = secondResponse.results[0].result
  assert.equal(second.isError, false, second.error?.message)
  assert.equal(counter.calls, 2, 'the second granted read dispatched its body')
  assert.equal(asks.length, 2, 'a fresh invocation asks again')
  assert.ok((secondResponse.additionalContexts ?? []).some(message => message?.source?.kind === 'dsh-guardrails'),
    'the second confirmation also produced a notice')
})

test('GT-12: a registered tool outside the deletion analysis keeps the DSH permission flow', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'unwired')
  const { ctx, approvalRequests } = await harness.mount(t, { label: 'gate', workingDirectory: root, gate: gateOrThrow() })
  const counter = { calls: 0 }
  harness.registerCounting(ctx, 'cleanup_cache', counter)
  const result = await harness.runTool(ctx, harness.makeAgent(root, ctx).agent, 'cleanup_cache', { anything: true })
  assert.equal(result.isError, false, `an un-wired tool passes through: ${result.error?.message}`)
  assert.equal(counter.calls, 1, 'the DSH pipeline dispatched the un-wired tool body')
  assert.equal(approvalRequests.length, 0, 'guardrails added no deletion check for the un-wired tool')
})

test('GT-02/GF-07: a prepended pre-execute short-circuit still refuses at the final guard with zero dispatch', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'shortcircuit')
  const { ctx } = await harness.mount(t, { label: 'gate', workingDirectory: root, gate: gateOrThrow() })
  const counter = { calls: 0 }
  harness.registerCounting(ctx, 'pwsh', counter)
  const agent = harness.makeAgent(root, ctx).agent
  const args = { command: 'Get-Location' }
  // The prepended listener ends the waterfall without next(): the gate never analyses
  // this execution, so the synchronous guard must refuse it for a missing trusted result.
  const shortCircuit = ctx.on('tools/pre-execute', async () => ({ kind: 'allow' }), { prepend: true })
  const denied = await harness.runTool(ctx, agent, 'pwsh', args)
  shortCircuit()
  assert.equal(denied.isError, true, 'a short-circuited execution has no trusted analysis and is refused')
  assert.equal(counter.calls, 0, 'the refused execution never dispatched its body')
  assert.match(denied.error?.message ?? '', /guardrails|analysis/i,
    `the refusal names the missing guardrails analysis: ${denied.error?.message}`)
  // Without the short-circuit the same call passes through the gate normally.
  const allowed = await harness.runTool(ctx, agent, 'pwsh', args)
  assert.equal(allowed.isError, false, allowed.error?.message)
  assert.equal(counter.calls, 1)
})

test('a program that directly reads a marked file requires approval before PTC execution', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'ptc-protected-read')
  const marked = join(root, 'vault.txt')
  await writeFile(marked, 'synthetic fixture')
  let runs = 0
  const ptcRuntime = harness.fixturePtcRuntime(async () => { runs++; return { logs: [], value: 'executed' } })
  const { ctx, approvalRequests } = await harness.mount(t, {
    workingDirectory: root, gate: gateOrThrow(), executor: 'ptc', ptcRuntime, config: { sensitiveFiles: [marked] },
  })
  const agent = harness.makeAgent(root, ctx).agent
  const result = await harness.runTool(ctx, agent, 'run_code', {
    code: `import { readFile } from 'node:fs/promises'; return await readFile('vault.txt', 'utf8')`,
    description: 'Synthetic program file-read fixture',
  })
  assert.equal(result.isError, true)
  assert.equal(runs, 0)
  assert.equal(approvalRequests.length, 1)
  assert.match(approvalRequests[0].reason, /credential\.file\.read/)
})

test('GT-09: the outer run_code passes and its SDK inner apply_patch dispatches exactly once', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'ptc-once')
  const target = join(root, 'obsolete.txt')
  await writeFile(target, 'x')
  const counter = { calls: 0 }
  const ptcRuntime = harness.fixturePtcRuntime(async spec => {
    const { functions } = spec.bindings[0]
    return { logs: [], value: await functions.apply_patch({ input: harness.patchText([{ kind: 'delete', path: target }]) }) }
  })
  const { ctx, approvalRequests } = await harness.mount(t, {
    label: 'gate', workingDirectory: root, gate: gateOrThrow(), executor: 'ptc', ptcRuntime, approval: 'rejected',
  })
  harness.registerCounting(ctx, 'apply_patch', counter)
  const observed = harness.observePreExecute(ctx).log
  const program = `return await tools.apply_patch({ input: ${JSON.stringify(harness.patchText([{ kind: 'delete', path: target }]))} })`
  const result = await harness.runTool(ctx, harness.makeAgent(root, ctx).agent, 'run_code',
    { code: program, description: 'SDK inner dispatch fixture' })
  assert.equal(result.isError, false, result.error?.message)
  assert.equal(result.value?.result, 'synthetic-noop', 'the inner tool value returned through the program')
  assert.equal(counter.calls, 1, 'the SDK inner apply_patch dispatched its body exactly once')
  assert.equal(approvalRequests.length, 0, 'no confirmation was needed for the ordinary inner target')
  const names = observed.map(entry => entry.name)
  assert.ok(names.includes('run_code'), 'the outer run_code execution passed through the gate')
  assert.ok(names.includes('apply_patch'), 'the SDK inner execution passed through the gate as its own call')
  const outer = observed.find(entry => entry.name === 'run_code')
  const inner = observed.find(entry => entry.name === 'apply_patch')
  assert.equal(inner.nested, true, 'the inner execution carries a parent token')
  assert.equal(outer.nested, false)
  assert.notEqual(outer.execution, inner.execution, 'outer and inner are distinct ToolExecution objects')
})

test('GT-09/DSR-027: SDK inner apply_patch targets are decided per dispatch, not re-inventoried by the outer program', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'ptc-no-double')
  const files = []
  for (let i = 0; i < 21; i += 1) files.push(join(root, `v${i}.txt`))
  for (const file of files) await writeFile(file, 'x')
  const bulkPatch = harness.patchText(files.map(path => ({ kind: 'delete', path })))
  const counter = { calls: 0 }
  const ptcRuntime = harness.fixturePtcRuntime(async spec => {
    const { functions } = spec.bindings[0]
    let inner
    try {
      inner = { ok: true, value: await functions.apply_patch({ input: bulkPatch }) }
    } catch (error) {
      inner = { ok: false, message: String(error?.message ?? error) }
    }
    return { logs: [], value: inner }
  })
  const { ctx, approvalRequests } = await harness.mount(t, {
    label: 'gate', workingDirectory: root, gate: gateOrThrow(), executor: 'ptc', ptcRuntime, approval: 'rejected',
  })
  harness.registerCounting(ctx, 'apply_patch', counter)
  const observed = harness.observePreExecute(ctx).log
  const program = [
    'let inner',
    `try { inner = { ok: true, value: await tools.apply_patch({ input: ${JSON.stringify(bulkPatch)} }) } }`,
    'catch (error) { inner = { ok: false, message: String(error?.message ?? error) } }',
    'return inner',
  ].join('\n')
  const result = await harness.runTool(ctx, harness.makeAgent(root, ctx).agent, 'run_code',
    { code: program, description: 'SDK inner bulk fixture' })
  assert.equal(result.isError, false, `the outer program itself completes: ${result.error?.message}`)
  assert.equal(result.value?.result?.ok, false, 'the inner bulk patch was refused inside the program')
  assert.equal(counter.calls, 0, 'the refused inner apply_patch never dispatched its body')
  assert.equal(approvalRequests.length, 1,
    'only the inner dispatch confirmed the bulk patch — the outer program did not re-inventory it')
  assert.equal(approvalRequests[0].toolName, 'apply_patch', 'the SDK dispatch requested approval for its own tool')
  assert.equal(observed.filter(entry => entry.name === 'run_code').length, 1, 'the outer run_code reached the gate once')
  assert.match(result.value?.result?.message ?? '', /data\.delete\.bulk|DEL-01|at least 21|limit 20|bulk/i,
    'the inner refusal carries the bulk-deletion signal')
  assert.equal(files.every(file => existsSync(file)), true, 'the managed targets are untouched')
})

test('GT-14 (gate-level): a small mixed apply_patch is judged as one whole patch and dispatches once; pure updates ask nothing', { skip: gateSkip }, async t => {
  // Coverage statement: this test uses a SYNTHETIC apply_patch registration to reach the
  // gate directly. It covers the gate's whole-patch parsePatch judgment, counting, and
  // dispatch decisions — nothing about how the official dsh-tool-fs tool registers or
  // executes (the real-definition case is the GT-14 (real) test below; live bundle
  // registration evidence stays an Inspect/composition check per GT-01).
  const root = await harness.fixtureRoot(t, 'patch-mixed')
  const removable = join(root, 'obsolete.txt')
  const editable = join(root, 'edited.txt')
  const updated = join(root, 'touched.txt')
  await writeFile(removable, 'x')
  await writeFile(editable, 'old line\n')
  await writeFile(updated, 'old line\n')
  const { ctx, approvalRequests } = await harness.mount(t, { label: 'gate', workingDirectory: root, gate: gateOrThrow(), approval: 'rejected' })
  const counter = { calls: 0 }
  harness.registerCounting(ctx, 'apply_patch', counter)
  const agent = harness.makeAgent(root, ctx).agent
  // One delete (1 ≤ 20, non-protected) plus one content update: a single judgment over
  // the whole patch, allowed, body dispatched once.
  const mixed = await harness.runTool(ctx, agent, 'apply_patch', { input: harness.patchText([
    { kind: 'delete', path: removable },
    { kind: 'update', path: editable, remove: ['old line'], add: ['new line'] },
  ]) })
  assert.equal(mixed.isError, false, mixed.error?.message)
  assert.equal(counter.calls, 1)
  assert.equal(approvalRequests.length, 0)
  // A patch whose operations are pure content updates contains no delete candidates,
  // even though its hunk text mentions deletion-looking content words.
  const updates = await harness.runTool(ctx, agent, 'apply_patch', { input: harness.patchText([
    { kind: 'update', path: updated, remove: ['old line'], add: ['deleted line placeholder'] },
  ]) })
  assert.equal(updates.isError, false, updates.error?.message)
  assert.equal(counter.calls, 2)
  assert.equal(approvalRequests.length, 0, 'pure updates produce no confirmation')
})

test('GT-14 (gate-level): a 21-delete apply_patch is one confirmation over the whole patch and refuses with zero dispatch', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'patch-bulk')
  const files = []
  for (let i = 0; i < 21; i += 1) files.push(join(root, `v${i}.txt`))
  for (const file of files) await writeFile(file, 'x')
  const { ctx, approvalRequests } = await harness.mount(t, { label: 'gate', workingDirectory: root, gate: gateOrThrow(), approval: 'rejected' })
  const counter = { calls: 0 }
  harness.registerCounting(ctx, 'apply_patch', counter)
  const result = await harness.runTool(ctx, harness.makeAgent(root, ctx).agent, 'apply_patch',
    { input: harness.patchText(files.map(path => ({ kind: 'delete', path }))) })
  assert.equal(result.isError, true, 'the whole patch is refused above the threshold')
  assert.equal(counter.calls, 0, 'a refused patch never dispatches the tool body')
  assert.equal(approvalRequests.length, 1, 'the whole patch produced exactly one confirmation')
  assert.equal(files.every(file => existsSync(file)), true, 'the managed targets are untouched')
  assert.match(result.error?.message ?? '', /data\.delete\.bulk|DEL-01|at least 21|limit 20|bulk/i,
    `the bulk-deletion signal must identify the rule: ${result.error?.message}`)
})

test('GT-14 (real): the official optional apply_patch definition registers, passes the gate, and really applies', { skip: gateSkip }, async t => {
  // The official composition seam is public: `@deepseek-ai/dsh-fs-local` provides `ctx.fs`
  // and `@deepseek-ai/dsh-tool-fs` registers `apply_patch` only while its `applyPatch`
  // config is true (README Configuration table). A mount failure here is an environment
  // fact, not a gate verdict, so it skips with the mount error; the gate-level GT-14
  // tests above still cover whole-patch judgment.
  const root = await harness.fixtureRoot(t, 'patch-real')
  const removable = 'obsolete.txt'
  const editable = 'edited.txt'
  await writeFile(join(root, removable), 'x')
  await writeFile(join(root, editable), 'old line\n')
  const { ctx, approvalRequests } = await harness.mount(t, { label: 'gate', workingDirectory: root, gate: gateOrThrow(), approval: 'rejected' })
  const toolFs = await harness.loadRuntimePackage('@deepseek-ai/dsh-tool-fs')
  await ctx.plugin({ name: toolFs.name, inject: toolFs.inject, apply: toolFs.apply, Config: toolFs.Config }, {
    read: false, readImage: false, write: false, edit: false, applyPatch: true,
    readLimit: 2000, readMaxLineLength: 2000, readMaxBytes: 51200, readStreamMinSize: 10485760,
  })
  const agent = harness.makeAgent(root, ctx).agent
  assert.equal(ctx.tools.executable('apply_patch', agent)?.name, 'apply_patch',
    'the official apply_patch definition is registered by applyPatch: true')
  const observed = harness.observePreExecute(ctx).log
  // Session-relative patch paths (the official apply_patch contract): one delete plus one
  // content update, judged as one whole patch, then REALLY applied to the managed targets.
  const result = await harness.runTool(ctx, agent, 'apply_patch', { input: harness.patchText([
    { kind: 'delete', path: removable },
    { kind: 'update', path: editable, remove: ['old line'], add: ['new line'] },
  ]) })
  assert.equal(result.isError, false, result.error?.message)
  assert.equal(approvalRequests.length, 0, 'an in-threshold non-protected patch needs no confirmation')
  assert.equal(existsSync(join(root, removable)), false, 'the delete operation really removed the fixture file')
  assert.equal(readFileSync(join(root, editable), 'utf8'), 'new line\n', 'the update operation really applied')
  assert.ok(observed.some(entry => entry.name === 'apply_patch'), 'the official apply_patch execution passed through the gate')
})
