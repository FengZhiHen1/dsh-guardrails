// Strict real-runtime gate evidence: actual DSH 0.2.2 ToolRuntime native and PTC
// executors plus the guardrails host gate. Synthetic fixtures only; the only paths
// this file creates and removes are its own temp directories. No payload is executed
// except a real pwsh Remove-Item on a self-created fixture (junction-safety proof).
//
// The runtime is located only through the DSH_RUNTIME_PATH anchor; no private path or
// host instance name is hard-coded. When the anchor is absent every test skips.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { realpathSync, existsSync } from 'node:fs'
import { resolve, extname, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { mkdtemp, mkdir, writeFile, rm, lstat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { execFile as execFileCb } from 'node:child_process'
import { promisify } from 'node:util'

const execFile = promisify(execFileCb)

const anchor = process.env.DSH_RUNTIME_PATH
const resolver = anchor
  ? createRequire(realpathSync(extname(anchor) ? resolve(anchor) : resolve(anchor, 'package.json')))
  : createRequire(import.meta.url)

let runtime
try {
  const load = async name => import(pathToFileURL(resolver.resolve(name)).href)
  const [cordis, tools, prompt, native, ptc] = await Promise.all([
    '@deepseek-ai/cordis',
    '@deepseek-ai/dsh-tools',
    '@deepseek-ai/dsh-system-prompt',
    '@deepseek-ai/dsh-tool-executor-native',
    '@deepseek-ai/dsh-tool-executor-ptc',
  ].map(load))
  runtime = { cordis, tools, prompt, native, ptc }
} catch (error) {
  if (anchor || error.code !== 'MODULE_NOT_FOUND') throw error
}

const skip = !runtime && 'Set DSH_RUNTIME_PATH to the installed runtime package.json'

// Import the gate under test through the package entry (same as a mounted plugin).
const guardrails = runtime ? await import(pathToFileURL(resolve(import.meta.dirname, '../index.js')).href) : undefined

/** A synthetic working-directory service returning a fixed directory for any session. */
const cwdService = dir => ({ get: () => dir, ensure: async () => dir })
/** A synthetic sandbox policy naming a workspace root (must be lower precedence than workingDirectory). */
const sandboxService = root => ({ resolve: () => ({ workspaceRoot: root }) })

/** Build one disposable temp fixture root that is cleaned at test end. */
async function fixtureRoot(t, label) {
  const root = await mkdtemp(join(tmpdir(), `gr-strict-${label}-`))
  t.after(() => rm(root, { recursive: true, force: true }))
  return root
}

/**
 * Mount a real context: system prompt, tools, one executor, optional services and the
 * guardrails gate. `executor` is 'native' (default) or 'ptc'. `ptcRuntime` is the
 * fixture runtime object when executor === 'ptc'.
 */
async function mount(t, options = {}) {
  const ctx = new runtime.cordis.Context()
  t.after(() => ctx.fiber.dispose())
  await ctx.plugin(runtime.prompt.default)
  await ctx.plugin(runtime.tools.default)
  if (options.ptcRuntime) {
    ctx.provide('ptcRuntime', options.ptcRuntime)
    await ctx.plugin(runtime.ptc, options.ptcConfig ?? {})
  } else {
    await ctx.plugin(runtime.native)
  }
  if (options.workingDirectory) ctx.provide('workingDirectory', cwdService(options.workingDirectory))
  if (options.sandboxRoot) ctx.provide('sandboxPolicy', sandboxService(options.sandboxRoot))
  if (options.approval) ctx.provide('approval', { request: options.approval })
  await ctx.plugin({ name: 'guardrails-test-mount', inject: ['tools'], apply: guardrails.apply }, options.config ?? {})
  return ctx
}

/** Register a counting `pwsh` tool whose body either really runs pwsh or just counts. */
function registerPwsh(ctx, { real = false, counter }) {
  ctx.tools.register({
    name: 'pwsh',
    description: 'Synthetic shell fixture.',
    parameters: { type: 'object' },
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: String(v) }] },
    execute: async (args) => {
      counter.calls += 1
      if (!real) return 'synthetic-noop'
      const { stdout } = await execFile('pwsh', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', args.command], {
        windowsHide: true, timeout: 30000, maxBuffer: 1 << 20,
      })
      return String(stdout)
    },
  })
}

/** Register an arbitrary tool name with a counting no-op body. */
function registerCounting(ctx, name, counter) {
  ctx.tools.register({
    name,
    description: 'Synthetic fixture tool.',
    parameters: { type: 'object' },
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: String(v) }] },
    execute: async () => { counter.calls += 1; return 'synthetic-noop' },
  })
}

/** A session + agent pair carrying a session header cwd and a stable id. */
function makeAgent(root) {
  const session = { id: `sess-${Math.random().toString(36).slice(2)}`, header: { cwd: root }, append() {} }
  return { agent: { session, ctx: undefined }, session }
}

/** Quote a path as a PowerShell single-quoted literal (backslashes are literal there;
 * only an embedded single quote needs doubling). */
const psLiteral = value => `'${String(value).replace(/'/g, "''")}'`

const toolCall = (name, args, id = 'c1') => ({ type: 'tool-call', id, name, arguments: JSON.stringify(args) })
const resultOf = response => response.results[0].result

test('20 literal-file pwsh delete is allowed and dispatched once; 21 is denied with zero body calls', { skip }, async t => {
  // 20 files: allowed, body dispatched exactly once.
  const root20 = await fixtureRoot(t, 'twenty')
  const dir20 = join(root20, 'delete-me')
  await mkdir(dir20, { recursive: true })
  for (let i = 0; i < 20; i += 1) await writeFile(join(dir20, `f${i}.txt`), 'x')
  const counter20 = { calls: 0 }
  const ctx20 = await mount(t, { workingDirectory: root20 })
  registerPwsh(ctx20, { counter: counter20 })
  const { agent: agent20 } = makeAgent(root20)
  const allowed = resultOf(await ctx20.tools.execute({
    signal: new AbortController().signal, agent: agent20,
    calls: [toolCall('pwsh', { command: `Remove-Item -LiteralPath ${psLiteral(dir20)} -Recurse -Force` })],
  }))
  assert.equal(allowed.isError, false, allowed.error?.message)
  assert.equal(counter20.calls, 1, 'the allowed 20-file delete dispatches the body once')

  // 21 files: denied, body never dispatched.
  const root21 = await fixtureRoot(t, 'twentyone')
  const dir21 = join(root21, 'delete-me')
  await mkdir(dir21, { recursive: true })
  for (let i = 0; i < 21; i += 1) await writeFile(join(dir21, `f${i}.txt`), 'x')
  const counter21 = { calls: 0 }
  const ctx21 = await mount(t, { workingDirectory: root21 })
  registerPwsh(ctx21, { counter: counter21 })
  const { agent: agent21 } = makeAgent(root21)
  const denied = resultOf(await ctx21.tools.execute({
    signal: new AbortController().signal, agent: agent21,
    calls: [toolCall('pwsh', { command: `Remove-Item -LiteralPath ${psLiteral(dir21)} -Recurse -Force` })],
  }))
  assert.equal(denied.isError, true)
  assert.match(denied.error.message, /DEL-01|at least 21|limit 20/i)
  assert.equal(counter21.calls, 0, 'a denied delete never dispatches the body')
  // The fixture is untouched: 21 files still exist.
  const entries = await lstat(dir21)
  assert.equal(entries.isDirectory(), true)
})

test('unknown tool is denied by the real runtime with zero dispatch', { skip }, async t => {
  const root = await fixtureRoot(t, 'unknown')
  const counter = { calls: 0 }
  const ctx = await mount(t, { workingDirectory: root })
  registerCounting(ctx, 'cleanup_cache', counter)
  const { agent } = makeAgent(root)
  const result = resultOf(await ctx.tools.execute({
    signal: new AbortController().signal, agent, calls: [toolCall('cleanup_cache', { anything: true })],
  }))
  assert.equal(result.isError, true)
  assert.match(result.error.message, /UNKNOWN_TOOL/)
  assert.equal(counter.calls, 0)
})

test('terminal_send forwards a deletion command line into analysis and refuses it (zero dispatch)', { skip }, async t => {
  const root = await fixtureRoot(t, 'terminal')
  const counter = { calls: 0 }
  const ctx = await mount(t, { workingDirectory: root })
  registerCounting(ctx, 'terminal_send', counter)
  const { agent } = makeAgent(root)
  const result = resultOf(await ctx.tools.execute({
    signal: new AbortController().signal, agent, calls: [toolCall('terminal_send', { sessionId: 't1', text: 'rm -rf x' })],
  }))
  // Under v4 the text IS analysed as a command line: an unprovable deletion command is
  // refused (not because the channel is opaque, but because its deletion cannot be proven).
  assert.equal(result.isError, true)
  assert.equal(counter.calls, 0)
})

test('real PTC executor outer run_code is refused and the fixture runtime run() is never called', { skip }, async t => {
  const root = await fixtureRoot(t, 'ptc')
  const runState = { run: 0 }
  const fixtureRuntime = {
    language: 'typescript',
    programFormat: 'script',
    retainsState: false,
    resolve: spec => ({ ...spec, timeoutMs: null }),
    async run() { runState.run += 1; return { logs: [], value: 'should-not-run' } },
    release() {},
  }
  // Mount the REAL PTC executor (not a fake registration) with a synthetic runtime.
  const ctx = await mount(t, { workingDirectory: root, ptcRuntime: fixtureRuntime })
  const { agent } = makeAgent(root)
  const result = resultOf(await ctx.tools.execute({
    signal: new AbortController().signal, agent,
    calls: [toolCall('run_code', { code: 'return await tools.pwsh({ command: "x" })', description: 'synthetic program' })],
  }))
  assert.equal(result.isError, true)
  assert.match(result.error.message, /OPAQUE_CODE/)
  assert.equal(runState.run, 0, 'the PTC runtime must never be entered for a refused run_code')
})

test('workingDirectory.get takes precedence over sandbox root and a relative workdir resolves under it', { skip }, async t => {
  // realCwd/sub has ONE target file; the sandbox root's sub/ has 21 so a wrong base denies.
  const root = await fixtureRoot(t, 'cwd')
  const realCwd = join(root, 'real-cwd')
  const sandboxRoot = join(root, 'sandbox-root')
  await mkdir(join(realCwd, 'sub'), { recursive: true })
  await mkdir(join(sandboxRoot, 'sub'), { recursive: true })
  await writeFile(join(realCwd, 'sub', 'target.txt'), 'x')
  for (let i = 0; i < 21; i += 1) await writeFile(join(sandboxRoot, 'sub', `s${i}.txt`), 'x')

  const counter = { calls: 0 }
  const ctx = await mount(t, { workingDirectory: realCwd, sandboxRoot })
  registerPwsh(ctx, { counter })
  const { agent } = makeAgent(root) // header cwd deliberately not the real cwd
  agent.session.header.cwd = sandboxRoot
  const result = resultOf(await ctx.tools.execute({
    signal: new AbortController().signal, agent,
    calls: [toolCall('pwsh', { command: "Remove-Item -LiteralPath 'target.txt' -Recurse -Force", workdir: 'sub' })],
  }))
  // Allowed proves the count came from realCwd/sub (1 file), NOT sandboxRoot/sub (21 -> DEL-01).
  assert.equal(result.isError, false, result.error?.message)
  assert.equal(counter.calls, 1)
})

test('a filesystem change during the approval wait (to 21 files) refuses the dispatch', { skip }, async t => {
  const root = await fixtureRoot(t, 'planchange')
  const dir = join(root, 'delete-me')
  await mkdir(dir, { recursive: true })
  for (let i = 0; i < 19; i += 1) await writeFile(join(dir, `f${i}.txt`), 'x')
  const counter = { calls: 0 }
  let approvalRequests = 0
  const ctx = await mount(t, {
    workingDirectory: root,
    // Grow the target set past the limit WHILE the approval is being decided.
    approval: async () => {
      approvalRequests += 1
      for (let i = 0; i < 4; i += 1) await writeFile(join(dir, `late${i}.txt`), 'x')
      return 'allowed-once'
    },
  })
  registerPwsh(ctx, { counter })
  const { agent } = makeAgent(root)
  // Force an approval path: the delete of an ordinary tree is allowed, so drive an
  // approval scenario by making the tree contain a protected file first.
  const protectedPath = join(dir, 'id_rsa')
  await writeFile(protectedPath, 'synthetic')
  const result = resultOf(await ctx.tools.execute({
    signal: new AbortController().signal, agent,
    calls: [toolCall('pwsh', { command: `Remove-Item -LiteralPath ${psLiteral(dir)} -Recurse -Force` })],
  }))
  assert.equal(approvalRequests >= 1, true, 'a protected file inside the tree triggers an approval')
  assert.equal(result.isError, true)
  assert.match(result.error.message, /DEL-01|PLAN_CHANGED|limit 20|at least 21/i)
  assert.equal(counter.calls, 0, 'a changed/over-limit plan is never dispatched')
})

test('whitelist only discounts recognized disposable files; a protected file still asks', { skip }, async t => {
  // Project marker + a recognized disposable pyc + ordinary files. The pyc must not
  // count, so 19 ordinary + 3 pyc is allowed (19 non-whitelisted), and a 4th... would
  // still be under 20. Adding a protected file inside must force an approval instead.
  const root = await fixtureRoot(t, 'whitelist')
  const dir = join(root, 'proj')
  await mkdir(join(dir, '__pycache__'), { recursive: true })
  await writeFile(join(dir, 'pyproject.toml'), '[project]\nname="synthetic"\n')
  // A pyc is exempt ONLY when its paired .py source exists (regeneration evidence). The
  // paired .py sources are themselves ordinary files and DO count: 16 txt + 3 .py +
  // pyproject.toml = 20 ordinary, with 3 exempt pyc, so the call is allowed (<= 20).
  for (let i = 0; i < 16; i += 1) await writeFile(join(dir, `src${i}.txt`), 'x')
  for (let i = 0; i < 3; i += 1) {
    await writeFile(join(dir, `m${i}.py`), 'print(1)\n')
    await writeFile(join(dir, '__pycache__', `m${i}.cpython-312.pyc`), 'x')
  }

  const counterOk = { calls: 0 }
  const ctxOk = await mount(t, { workingDirectory: root })
  registerPwsh(ctxOk, { counter: counterOk })
  const { agent: agentOk } = makeAgent(root)
  const allowed = resultOf(await ctxOk.tools.execute({
    signal: new AbortController().signal, agent: agentOk,
    calls: [toolCall('pwsh', { command: `Remove-Item -LiteralPath ${psLiteral(dir)} -Recurse -Force` })],
  }))
  // 19 ordinary (+ pyproject.toml) counted, 5 pyc + the directory entries not counted as
  // non-whitelisted files; still <= 20 so the call is allowed.
  assert.equal(allowed.isError, false, allowed.error?.message)

  // Same shape plus a protected file inside -> an approval is requested.
  const root2 = await fixtureRoot(t, 'whitelist-protected')
  const dir2 = join(root2, 'proj')
  await mkdir(join(dir2, '__pycache__'), { recursive: true })
  await writeFile(join(dir2, 'pyproject.toml'), '[project]\nname="synthetic"\n')
  for (let i = 0; i < 5; i += 1) await writeFile(join(dir2, `src${i}.txt`), 'x')
  await writeFile(join(dir2, 'm.py'), 'print(1)\n')
  await writeFile(join(dir2, '__pycache__', 'm.cpython-312.pyc'), 'x')
  await writeFile(join(dir2, 'id_rsa'), 'synthetic')
  let asked = 0
  const counter2 = { calls: 0 }
  const ctx2 = await mount(t, { workingDirectory: root2, approval: async () => { asked += 1; return 'rejected' } })
  registerPwsh(ctx2, { counter: counter2 })
  const { agent: agent2 } = makeAgent(root2)
  const rejected = resultOf(await ctx2.tools.execute({
    signal: new AbortController().signal, agent: agent2,
    calls: [toolCall('pwsh', { command: `Remove-Item -LiteralPath ${psLiteral(dir2)} -Recurse -Force` })],
  }))
  assert.equal(asked, 1, 'the protected file inside the tree requests one approval even though other files are disposable')
  assert.equal(rejected.isError, true)
  assert.equal(counter2.calls, 0)
})

test('a recursive delete through a junction does not delete the junction target (real pwsh)', { skip }, async t => {
  const root = await fixtureRoot(t, 'junction')
  const victim = join(root, 'victim')
  const victimSub = join(victim, 'nested')
  const deleteDir = join(root, 'to-delete')
  await mkdir(victimSub, { recursive: true })
  await mkdir(deleteDir, { recursive: true })
  const keepFile = join(victimSub, 'keep.txt')
  await writeFile(keepFile, 'synthetic outside target that must survive')
  await writeFile(join(deleteDir, 'own.txt'), 'own file')
  // Create a real directory junction inside the delete tree pointing at the victim.
  await execFile('pwsh', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    `New-Item -ItemType Junction -Path '${join(deleteDir, 'link-to-victim').replace(/'/g, "''")}' -Target '${victim.replace(/'/g, "''")}' | Out-Null`],
  { windowsHide: true, timeout: 30000 })

  const counter = { calls: 0 }
  const ctx = await mount(t, { workingDirectory: root })
  registerPwsh(ctx, { real: true, counter })
  const { agent } = makeAgent(root)
  const result = resultOf(await ctx.tools.execute({
    signal: new AbortController().signal, agent,
    calls: [toolCall('pwsh', { command: `Remove-Item -LiteralPath ${psLiteral(deleteDir)} -Recurse -Force` })],
  }))
  // The plan allows (small tree); the real pwsh Remove-Item removes the junction entry only.
  assert.equal(result.isError, false, result.error?.message)
  assert.equal(counter.calls, 1)
  assert.equal(existsSync(deleteDir), false, 'the delete tree is gone')
  assert.equal(existsSync(keepFile), true, 'the junction target file outside the tree must survive')
})

test('an observation-unknown target is refused (0 dispatch), not allowed through policy', { skip }, async t => {
  // A command whose target the observer cannot locate/prove (a UNC share is refused as
  // non-local) must not be dispatched on the strength of a default-allow policy. The
  // post-observation reassessment surfaces DI-UNKNOWN-SEMANTICS and blocks the body.
  const root = await fixtureRoot(t, 'obs-unknown')
  const counter = { calls: 0 }
  const ctx = await mount(t, { workingDirectory: root })
  registerPwsh(ctx, { counter })
  const { agent } = makeAgent(root)
  const result = resultOf(await ctx.tools.execute({
    signal: new AbortController().signal, agent,
    calls: [toolCall('pwsh', { command: 'Get-Content -Path \'\\\\server\\share\\secret.txt\'' })],
  }))
  assert.equal(result.isError, true, 'an unprovable remote target must be refused')
  assert.equal(counter.calls, 0, 'no command body is dispatched when a target is unprovable')
})

test('language-runtime commands are allowed (node --version, python -V) and inline code is denied', { skip }, async t => {
  const root = await fixtureRoot(t, 'runtimes')
  const counter = { calls: 0 }
  const ctx = await mount(t, { workingDirectory: root })
  registerPwsh(ctx, { counter })
  const { agent } = makeAgent(root)
  const run = async (command) => resultOf(await ctx.tools.execute({
    signal: new AbortController().signal, agent, calls: [toolCall('pwsh', { command })],
  }))
  // Recognized language runtimes are accepted as opaque script runners (no counting).
  for (const command of ['node --version', 'python -V', 'node script.mjs', 'python -m pytest']) {
    const r = await run(command)
    assert.equal(r.isError, false, `${command} should be allowed: ${r.error?.message}`)
  }
  assert.equal(counter.calls, 4, 'each allowed runtime command dispatches its body')
  // Inline code turns the command line into unenumerable code: still denied, body never runs.
  for (const command of ['node -e "console.log(1)"', 'python -c "print(1)"']) {
    const r = await run(command)
    assert.equal(r.isError, true, `${command} must be denied`)
    assert.match(r.error?.message ?? '', /DI-INLINE-CODE|inline code/i)
  }
  assert.equal(counter.calls, 4, 'denied inline-code commands do not dispatch')
})

test('a >20 non-whitelisted delete denial carries the shared deletion doctrine', { skip }, async t => {
  const root = await fixtureRoot(t, 'doctrine')
  const dir = join(root, 'big')
  await mkdir(dir, { recursive: true })
  for (let i = 0; i < 21; i += 1) await writeFile(join(dir, `f${i}.txt`), 'x')
  const counter = { calls: 0 }
  const ctx = await mount(t, { workingDirectory: root })
  registerPwsh(ctx, { counter })
  const { agent } = makeAgent(root)
  const result = resultOf(await ctx.tools.execute({
    signal: new AbortController().signal, agent,
    calls: [toolCall('pwsh', { command: `Remove-Item -LiteralPath ${psLiteral(dir)} -Recurse -Force` })],
  }))
  assert.equal(result.isError, true)
  assert.equal(counter.calls, 0)
  const message = result.error?.message ?? ''
  assert.match(message, /Del-01|at least 21|at least 20|limit 20|21/i)
  assert.match(message, /Deletion is irreversible/, 'the shared deletion doctrine sentence is present')
})

/** Register an arbitrary tool whose body only counts dispatches. */
function registerCountingTool(ctx, nameForTool, counter) {
  ctx.tools.register({
    name: nameForTool,
    description: 'Synthetic framework fixture.',
    parameters: { type: 'object' },
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: String(v) }] },
    execute: async () => { counter.calls += 1; return 'synthetic-noop' },
  })
}

test('framework tools (create_worktree, terminal_open, plugin_manager) dispatch under the real runtime', { skip }, async t => {
  const root = await fixtureRoot(t, 'framework')
  const counter = { calls: 0 }
  const ctx = await mount(t, { workingDirectory: root })
  for (const nameForTool of ['create_worktree', 'terminal_open', 'plugin_manager']) registerCountingTool(ctx, nameForTool, counter)
  const { agent } = makeAgent(root)
  const run = async (name, args) => resultOf(await ctx.tools.execute({
    signal: new AbortController().signal, agent, calls: [toolCall(name, args)],
  }))
  assert.equal((await run('create_worktree', { name: 'x' })).isError, false)
  assert.equal((await run('terminal_open', { type: 'shell' })).isError, false)
  assert.equal((await run('plugin_manager', { action: 'remove_bundle', target: 'x' })).isError, false)
  assert.equal(counter.calls, 3, 'each allowed framework tool dispatches its body once')
})

test('terminal_send analyses its text: ordinary command dispatches, a dynamic command is refused', { skip }, async t => {
  const root = await fixtureRoot(t, 'term-send')
  const counter = { calls: 0 }
  const ctx = await mount(t, { workingDirectory: root })
  registerCountingTool(ctx, 'terminal_send', counter)
  const { agent } = makeAgent(root)
  const run = async (text) => resultOf(await ctx.tools.execute({
    signal: new AbortController().signal, agent, calls: [toolCall('terminal_send', { sessionId: 's', text })],
  }))
  // A plain read-only command line is analysed and allowed.
  assert.equal((await run('Get-Location')).isError, false, 'ordinary terminal_send command allowed')
  // A non-string body cannot be analysed → refused, no dispatch.
  const bad = await run(42)
  assert.equal(bad.isError, true, 'unanalysable terminal_send text is refused')
  assert.equal(counter.calls, 1, 'only the analysable command dispatched')
})

test('git clean fails closed when the evidence module is unavailable (B3)', { skip }, async t => {
  const root = await fixtureRoot(t, 'git-failclosed')
  const counter = { calls: 0 }
  const ctx = await mount(t, { workingDirectory: root })
  registerPwsh(ctx, { counter })
  const { agent } = makeAgent(root)
  // `git clean -fd` is a git action; with the evidence module present it would count. The
  // unit tests stub the module via the `_git` seam. Under the REAL runtime the module IS
  // present (merged), so `git clean` in a non-repository dir must fail closed (unknown),
  // never silently allow. Either way the body is not dispatched.
  const result = resultOf(await ctx.tools.execute({
    signal: new AbortController().signal, agent,
    calls: [toolCall('pwsh', { command: 'git clean -fd' })],
  }))
  assert.equal(result.isError, true, 'git clean that cannot be proven is refused, never allowed')
  assert.equal(counter.calls, 0, 'no dispatch for an unproven git clean')
})

/** Build a real git repo under `root` with an initial commit; returns nothing. */
async function initRepo(root) {
  const env = { ...process.env }
  await execFile('git', ['-C', root, 'init', '-q', '-b', 'main'], { env, windowsHide: true })
  await execFile('git', ['-C', root, '-c', 'user.email=t@e', '-c', 'user.name=t', 'commit', '-q', '--allow-empty', '-m', 'init'], { env: { ...env, GIT_AUTHOR_DATE: undefined }, windowsHide: true })
}

test('git grading end-to-end: reset --hard refuses (with/without rev), reset --hard -- <path> counts, checkout . restores, status allows', { skip }, async t => {
  const root = await fixtureRoot(t, 'git-grade')
  await initRepo(root)
  // A tracked file so a pathspec restore has something to act on.
  const { writeFileSync } = await import('node:fs')
  writeFileSync(join(root, 'a.txt'), 'x')
  await execFile('git', ['-C', root, 'add', 'a.txt'], { windowsHide: true })
  await execFile('git', ['-C', root, '-c', 'user.email=t@e', '-c', 'user.name=t', 'commit', '-q', '-m', 'a'], { windowsHide: true })
  const counter = { calls: 0 }
  const ctx = await mount(t, { workingDirectory: root })
  registerPwsh(ctx, { counter })
  const { agent } = makeAgent(root)
  const run = async (command) => resultOf(await ctx.tools.execute({
    signal: new AbortController().signal, agent, calls: [toolCall('pwsh', { command })],
  }))
  // Destroys uncommitted/history -> L1 refuse, never dispatched.
  for (const command of ['git reset --hard', 'git reset --hard HEAD~1', 'git reset --hard HEAD']) {
    const r = await run(command)
    assert.equal(r.isError, true, `${command} must be refused`)
    assert.match(r.error?.message ?? '', /reset --hard|DI-GIT-REFUSE|discards/i, `${command} reason`)
  }
  assert.equal(counter.calls, 0, 'no reset --hard is dispatched')
  // A pathspec restore (≤20) is counted and allowed, body dispatched.
  const restore = await run('git reset --hard -- a.txt')
  assert.equal(restore.isError, false, `reset --hard -- <path> should be allowed: ${restore.error?.message}`)
  assert.equal(counter.calls, 1, 'the restore dispatches its body')
  // checkout . restore of one path is counted and allowed.
  const checkout = await run('git checkout .')
  assert.equal(checkout.isError, false, `checkout . should be allowed: ${checkout.error?.message}`)
  // A plain read-only git command is allowed.
  const status = await run('git status --short')
  assert.equal(status.isError, false, 'git status must be allowed')
})
