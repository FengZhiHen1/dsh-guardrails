// Reusable harness for dsh-guardrails real-runtime acceptance tests.
//
// Everything here runs against the REAL DSH 0.2.2-rc.2 runtime located through the
// DSH_RUNTIME_PATH anchor (the launcher install, e.g. <launcher>/versions/0.2.2-rc.2,
// a package directory containing package.json, or a package.json path). The harness
// never starts a DSH instance, never writes a profile, and never executes a
// destructive command: every fixture lives in its own mkdtemp directory under
// os.tmpdir() and every tool body is a counting no-op unless a test explicitly says
// otherwise.
//
// Composition notes verified against the installed runtime packages:
// - Runtime deps are pnpm-hidden: the anchor MUST be resolved through its realpath
//   (symlinked `node_modules/@deepseek-ai/dsh` inside a versions dir) or sibling
//   `@deepseek-ai/*` packages do not resolve.
// - `tools.execute` dispatches through a mounted executor: exactly ONE of
//   `@deepseek-ai/dsh-tool-executor-native` or `@deepseek-ai/dsh-tool-executor-ptc`
//   per scope. The PTC executor additionally injects `systemPrompt` and `ptcRuntime`
//   and only admits `run_code` as a direct call; other tools are reachable only as
//   SDK sub-dispatches inside a program, each through the full pre-execute/guard
//   pipeline with its own ToolExecution object.
// - `tools/pre-execute` is an ordered waterfall; listeners registered later run
//   after earlier ones, so an observer appended after the gate sees only
//   invocations the gate forwarded with `next()`.
import { createRequire } from 'node:module'
import { existsSync, realpathSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'

const anchor = process.env.DSH_RUNTIME_PATH

export let runtimeSkipReason = anchor
  ? undefined
  : 'Set DSH_RUNTIME_PATH to the installed DSH runtime (launcher versions/0.2.2-rc.2, its package dir, or a package.json)'

/** Resolve a require anchored INSIDE the runtime's real package tree. */
function anchorRequire(anchor) {
  // A versions directory name such as `0.2.2-rc.2` has a trailing `.2`, so the
  // file/directory distinction comes from stat, never from the extension.
  const candidates = []
  try {
    if (statSync(anchor).isFile()) candidates.push(anchor)
  } catch {
    // Not a file path; fall through to the directory shapes below.
  }
  candidates.push(join(anchor, 'node_modules', '@deepseek-ai', 'dsh', 'package.json'), join(anchor, 'package.json'))
  for (const candidate of candidates) {
    if (!existsSync(candidate)) continue
    try {
      return createRequire(realpathSync(candidate))
    } catch {
      // Try the next candidate shape.
    }
  }
  throw new Error(`DSH_RUNTIME_PATH does not point at a usable runtime anchor: ${anchor}`)
}

export let runtime
let requireFromRuntime
if (!runtimeSkipReason) {
  try {
    requireFromRuntime = anchorRequire(anchor)
    const load = async name => import(pathToFileURL(requireFromRuntime.resolve(name)).href)
    const [cordis, tools, prompt, native, ptcExecutor, userApproval, projections, session] = await Promise.all([
      '@deepseek-ai/cordis',
      '@deepseek-ai/dsh-tools',
      '@deepseek-ai/dsh-system-prompt',
      '@deepseek-ai/dsh-tool-executor-native',
      '@deepseek-ai/dsh-tool-executor-ptc',
      '@deepseek-ai/dsh-user-approval',
      '@deepseek-ai/dsh-session-projection',
      '@deepseek-ai/dsh-session',
    ].map(load))
    runtime = { cordis, tools, prompt, native, ptcExecutor, userApproval, projections, session }
  } catch (error) {
    runtime = undefined
    runtimeSkipReason = `Runtime packages under DSH_RUNTIME_PATH could not be loaded: ${error?.message ?? error}`
  }
}

/**
 * Load an additional official runtime package on demand (e.g. the optional
 * `@deepseek-ai/dsh-tool-fs` apply_patch composition). Requires a usable anchor.
 */
export async function loadRuntimePackage(name) {
  if (!requireFromRuntime) throw new Error(runtimeSkipReason)
  return import(pathToFileURL(requireFromRuntime.resolve(name)).href)
}

/**
 * Mount one isolated real composition and register the gate under test.
 * options:
 *   executor          'native' (default) or 'ptc'
 *   ptcRuntime        required for 'ptc': a fixture PTC runtime object
 *   gate              { apply } of the guardrails entry, or omitted to run without the gate
 *   config            plain config object handed to gate.apply
 *   workingDirectory  fixture root override (default: a fresh managed temp root)
 *   approval          stub outcome ('rejected' | 'allowed-once' | fn) or 'real-never'
 *                     to mount the real ApprovalService with policy 'never'
 * Returns { ctx, root, approvalRequests }.
 */
export async function mount(t, options = {}) {
  if (!runtime) throw new Error(runtimeSkipReason)
  const root = options.workingDirectory ?? await fixtureRoot(t, options.label ?? 'mount')
  const approvalRequests = []
  const ctx = new runtime.cordis.Context()
  t.after(() => ctx.fiber.dispose())
  await ctx.plugin(runtime.prompt.default)
  await ctx.plugin(runtime.tools.default)
  if (options.executor === 'ptc') {
    if (!options.ptcRuntime) throw new Error('executor "ptc" requires a ptcRuntime fixture')
    ctx.provide('ptcRuntime', options.ptcRuntime)
    await ctx.plugin(runtime.ptcExecutor)
  } else {
    await ctx.plugin(runtime.native)
  }
  // The session working directory and the sandbox boundary are both the managed temp
  // root, so relative targets and project scoping stay inside the fixture.
  ctx.provide('workingDirectory', { get: () => root, ensure: async () => root })
  ctx.provide('sandboxPolicy', { resolve: () => ({ mode: 'workspace-write', workspaceRoot: root }) })
  if (options.approval === 'real-never') {
    await ctx.plugin(runtime.projections.default)
    await ctx.plugin(runtime.userApproval.default, { policy: 'never' })
  } else {
    const outcome = options.approval ?? 'rejected'
    ctx.provide('approval', {
      request: async request => {
        approvalRequests.push(request)
        return typeof outcome === 'function' ? outcome(request) : outcome
      },
    })
  }
  if (options.gate) {
    await ctx.plugin({ name: 'guardrails-test-mount', inject: ['tools'], apply: options.gate.apply }, options.config ?? {})
  }
  return { ctx, root, approvalRequests }
}

/** One disposable managed temp fixture root, removed at test end. */
export async function fixtureRoot(t, label = 'root') {
  const root = await mkdtemp(join(tmpdir(), `gr-target-${label}-`))
  t.after(() => rm(root, { recursive: true, force: true }))
  return root
}

/** A synthetic agent + session whose header cwd is the fixture root. */
export function makeAgent(root, ctx) {
  const session = { id: `target-${Math.random().toString(36).slice(2)}`, header: { cwd: root }, append() {} }
  return { agent: { session, ctx }, session }
}

/** A real session with one open turn, for the real ApprovalService composition. */
export function realSession(id = 'target-runtime') {
  if (!runtime) throw new Error(runtimeSkipReason)
  const session = runtime.session.Session.create(id)
  session.append('turn/start', { turn: 1 })
  return session
}

/** Register a counting no-op tool body. Dispatch counts are the observable signal. */
export function registerCounting(ctx, name, counter) {
  ctx.tools.register({
    name,
    description: 'Synthetic target-runtime fixture tool.',
    parameters: { type: 'object' },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: String(value) }] },
    execute: async () => { counter.calls += 1; return 'synthetic-noop' },
  })
}

export const toolCall = (name, args, id = 'c1') => ({ type: 'tool-call', id, name, arguments: JSON.stringify(args) })
export const resultOf = response => response.results[0].result

/** Execute one tool call and return its settled result. */
export async function runTool(ctx, agent, name, args, signal = new AbortController().signal) {
  return resultOf(await ctx.tools.execute({ signal, agent, calls: [toolCall(name, args, `${name}-c1`)] }))
}

/**
 * Append an observer AFTER the gate: entries appear only for executions the gate
 * forwarded with next(). `nested` distinguishes SDK sub-dispatches (their
 * ToolExecution carries a parent token) from outer calls.
 */
export function observePreExecute(ctx, log = []) {
  const dispose = ctx.on('tools/pre-execute', async (execution, next) => {
    log.push({ name: execution.name, callId: execution.callId, nested: execution.parent !== undefined, execution })
    return next()
  })
  return { log, dispose }
}

/** A fixture PTC runtime: unlimited sub-calls, no sandbox, stateless. */
export function fixturePtcRuntime(run) {
  return {
    language: 'typescript',
    programFormat: 'function-body',
    retainsState: false,
    resolve: spec => ({ ...spec, timeoutMs: null }),
    run,
    release() {},
  }
}

/** Create `count` files in `root/name` and return the directory path. */
export async function writeTree(root, name, count) {
  const dir = join(root, name)
  await mkdir(dir, { recursive: true })
  for (let i = 0; i < count; i += 1) await writeFile(join(dir, `f${i}.txt`), 'x')
  return dir
}

/** Quote a path as a PowerShell single-quoted literal. */
export const psLiteral = value => `'${String(value).replace(/'/g, "''")}'`

/**
 * Build a Codex-style patch text (the exact grammar `@deepseek-ai/dsh-fs-patch`
 * parses, per its documented example: `*** Begin Patch`, ordered Add/Update/Delete
 * headers, +/- hunk lines, `*** End Patch`).
 */
export function patchText(operations) {
  const lines = ['*** Begin Patch']
  for (const op of operations) {
    if (op.kind === 'delete') {
      lines.push(`*** Delete File: ${op.path}`)
    } else if (op.kind === 'add') {
      lines.push(`*** Add File: ${op.path}`)
      for (const line of op.lines ?? ['content']) lines.push(`+${line}`)
    } else if (op.kind === 'update') {
      lines.push(`*** Update File: ${op.path}`)
      for (const line of op.remove ?? []) lines.push(`-${line}`)
      for (const line of op.add ?? []) lines.push(`+${line}`)
    } else {
      throw new Error(`unknown patch operation kind: ${op.kind}`)
    }
  }
  lines.push('*** End Patch')
  return lines.join('\n')
}
