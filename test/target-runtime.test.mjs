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
//   GT-09 / DSR-027 outer run_code passes; SDK inner tools decided per dispatch, not
//                   re-inventoried by the outer program
//   GT-12           tools outside the deletion analysis keep the DSH permission flow
//   GT-13           real ApprovalService never policy rejects a confirmation
//   GT-14           whole-patch judgment for apply_patch (gate-level: the tool here is a
//                   synthetic registration; live dsh-tool-fs registration evidence is a
//                   composition/Inspect check and stays outside this harness — GT-01)
//
// The gate cases are written against the target contract of docs/. Before the new
// entry (index.js: apply/Config/name/inject) is integrated they skip with the import
// error; a skip is never a pass (工程结构与测试体系.md 判决规则).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { mkdir, writeFile } from 'node:fs/promises'
import * as harness from './fixtures/target-runtime/runtime-harness.mjs'

let gate
let gateSkipReason
try {
  gate = await import('../index.js')
} catch (error) {
  gate = undefined
  gateSkipReason = `dsh-guardrails entry (index.js) cannot be imported yet (integration pending): ${error?.message ?? error}`
}

const runtimeSkip = !harness.runtime && harness.runtimeSkipReason
const gateSkip = runtimeSkip || (!gate && gateSkipReason)

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
  const { ctx, approvalRequests } = await harness.mount(t, { label: 'gate', workingDirectory: root, gate })
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
  const { ctx, approvalRequests } = await harness.mount(t, { label: 'gate', workingDirectory: root, gate, approval: 'rejected' })
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
    label: 'gate', workingDirectory: root, gate, config: { sensitiveFiles: [marked] }, approval: 'rejected',
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
  assert.match(protectedResult.error?.message ?? '', /credential\.file\.read|S-F1/i,
    `the confirmation signal must identify the protected-read rule: ${protectedResult.error?.message}`)
})

test('GT-13: the real ApprovalService never policy rejects the protected-read confirmation', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'approval-never')
  const marked = join(root, 'id_rsa')
  const ordinary = join(root, 'ordinary.txt')
  await writeFile(marked, 'synthetic fixture only')
  await writeFile(ordinary, 'synthetic fixture only')
  const { ctx } = await harness.mount(t, {
    label: 'gate', workingDirectory: root, gate, config: { sensitiveFiles: [marked] }, approval: 'real-never',
  })
  const counter = { calls: 0 }
  harness.registerCounting(ctx, 'read', counter)
  const session = harness.realSession('target-runtime-never')
  const agent = { session, ctx }
  const ordinaryResult = await harness.runTool(ctx, agent, 'read', { file_path: ordinary })
  assert.equal(ordinaryResult.isError, false, ordinaryResult.error?.message)
  const protectedResult = await harness.runTool(ctx, agent, 'read', { file_path: marked })
  assert.equal(protectedResult.isError, true, 'the never policy resolves before any grant')
  assert.equal(counter.calls, 1, 'only the ordinary read dispatched')
  const types = session.snapshotEvents().map(event => event.type)
  assert.ok(types.includes('approval/asked'), 'the ask was audited')
  assert.ok(types.includes('approval/decided'), 'the decision was audited')
  const decided = session.snapshotEvents().find(event => event.type === 'approval/decided')
  assert.equal(decided.data.outcome, 'rejected')
})

test('GT-12: a registered tool outside the deletion analysis keeps the DSH permission flow', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'unwired')
  const { ctx, approvalRequests } = await harness.mount(t, { label: 'gate', workingDirectory: root, gate })
  const counter = { calls: 0 }
  harness.registerCounting(ctx, 'cleanup_cache', counter)
  const result = await harness.runTool(ctx, harness.makeAgent(root, ctx).agent, 'cleanup_cache', { anything: true })
  assert.equal(result.isError, false, `an un-wired tool passes through: ${result.error?.message}`)
  assert.equal(counter.calls, 1, 'the DSH pipeline dispatched the un-wired tool body')
  assert.equal(approvalRequests.length, 0, 'guardrails added no deletion check for the un-wired tool')
})

test('GT-02/GF-07: a prepended pre-execute short-circuit still refuses at the final guard with zero dispatch', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'shortcircuit')
  const { ctx } = await harness.mount(t, { label: 'gate', workingDirectory: root, gate })
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

test('GT-09: the outer run_code passes and its SDK inner tool dispatches exactly once', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'ptc-once')
  const target = join(root, 'inner-target.txt')
  await writeFile(target, 'x')
  const counter = { calls: 0 }
  const ptcRuntime = harness.fixturePtcRuntime(async spec => {
    const { functions } = spec.bindings[0]
    return { logs: [], value: await functions.delete({ file_path: target }) }
  })
  const { ctx, approvalRequests } = await harness.mount(t, {
    label: 'gate', workingDirectory: root, gate, executor: 'ptc', ptcRuntime, approval: 'rejected',
  })
  harness.registerCounting(ctx, 'delete', counter)
  const observed = harness.observePreExecute(ctx).log
  const program = `return await tools.delete({ file_path: ${JSON.stringify(target)} })`
  const result = await harness.runTool(ctx, harness.makeAgent(root, ctx).agent, 'run_code',
    { code: program, description: 'SDK inner dispatch fixture' })
  assert.equal(result.isError, false, result.error?.message)
  assert.equal(result.value?.result, 'synthetic-noop', 'the inner tool value returned through the program')
  assert.equal(counter.calls, 1, 'the SDK inner tool dispatched its body exactly once')
  assert.equal(approvalRequests.length, 0, 'no confirmation was needed for the ordinary inner target')
  const names = observed.map(entry => entry.name)
  assert.ok(names.includes('run_code'), 'the outer run_code execution passed through the gate')
  assert.ok(names.includes('delete'), 'the SDK inner execution passed through the gate as its own call')
  const outer = observed.find(entry => entry.name === 'run_code')
  const inner = observed.find(entry => entry.name === 'delete')
  assert.equal(inner.nested, true, 'the inner execution carries a parent token')
  assert.equal(outer.nested, false)
  assert.notEqual(outer.execution, inner.execution, 'outer and inner are distinct ToolExecution objects')
})

test('GT-09/DSR-027: SDK inner targets are decided per dispatch, not re-inventoried by the outer program', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'ptc-no-double')
  const dir21 = await harness.writeTree(root, 'delete-me', 21)
  const counter = { calls: 0 }
  const ptcRuntime = harness.fixturePtcRuntime(async spec => {
    const { functions } = spec.bindings[0]
    let inner
    try {
      inner = { ok: true, value: await functions.delete({ file_path: dir21 }) }
    } catch (error) {
      inner = { ok: false, message: String(error?.message ?? error) }
    }
    return { logs: [], value: inner }
  })
  const { ctx, approvalRequests } = await harness.mount(t, {
    label: 'gate', workingDirectory: root, gate, executor: 'ptc', ptcRuntime, approval: 'rejected',
  })
  harness.registerCounting(ctx, 'delete', counter)
  const observed = harness.observePreExecute(ctx).log
  const program = [
    'let inner',
    `try { inner = { ok: true, value: await tools.delete({ file_path: ${JSON.stringify(dir21)} }) } }`,
    'catch (error) { inner = { ok: false, message: String(error?.message ?? error) } }',
    'return inner',
  ].join('\n')
  const result = await harness.runTool(ctx, harness.makeAgent(root, ctx).agent, 'run_code',
    { code: program, description: 'SDK inner bulk fixture' })
  assert.equal(result.isError, false, `the outer program itself completes: ${result.error?.message}`)
  assert.equal(result.value?.result?.ok, false, 'the inner bulk delete was refused inside the program')
  assert.equal(counter.calls, 0, 'the refused inner delete never dispatched its body')
  assert.equal(approvalRequests.length, 1,
    'only the inner dispatch confirmed the bulk set — the outer program did not re-inventory it')
  assert.ok(observed.some(entry => entry.name === 'delete' && entry.nested), 'the inner delete reached the gate as its own execution')
  assert.ok(observed.some(entry => entry.name === 'run_code'), 'the outer run_code reached the gate once')
  assert.match(result.value?.result?.message ?? '', /data\.delete\.bulk|DEL-01|at least 21|limit 20|bulk/i,
    'the inner refusal carries the bulk-deletion signal')
  assert.equal(existsSync(dir21), true, 'the managed target is untouched')
})

test('GT-14: a small mixed apply_patch is judged as one whole patch and dispatches once; pure updates ask nothing', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'patch-mixed')
  const removable = join(root, 'obsolete.txt')
  const editable = join(root, 'edited.txt')
  const updated = join(root, 'touched.txt')
  await writeFile(removable, 'x')
  await writeFile(editable, 'old line\n')
  await writeFile(updated, 'old line\n')
  const { ctx, approvalRequests } = await harness.mount(t, { label: 'gate', workingDirectory: root, gate, approval: 'rejected' })
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

test('GT-14: a 21-delete apply_patch is one confirmation over the whole patch and refuses with zero dispatch', { skip: gateSkip }, async t => {
  const root = await harness.fixtureRoot(t, 'patch-bulk')
  const files = []
  for (let i = 0; i < 21; i += 1) files.push(join(root, `v${i}.txt`))
  for (const file of files) await writeFile(file, 'x')
  const { ctx, approvalRequests } = await harness.mount(t, { label: 'gate', workingDirectory: root, gate, approval: 'rejected' })
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
