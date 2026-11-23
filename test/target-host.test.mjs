// target-host — gate wiring tests for the DSH host adapter.
//
// These tests run bare Node against injected fake adapters (analyzer, evidence,
// decision, renderer, policy) and a minimal fake Cordis context that records
// effects, guards, and `tools/pre-execute` listeners. They verify the gate's
// observable contract: front-door classification (reserved run_code transport,
// shape-verified definitions), the analysis pipeline (fsProvider wrapper over
// the official ctx.fs.resolve/stat signatures), the bounded plugin-owned
// approval, the post-approval full revisit (rerun planning/analysis + diff
// semantics + evidence versions + live policy, bounded re-approval), and the
// final monotonic WeakMap guard with one-shot consumption. Official DSH
// contracts mirrored here come from the 0.2.2-rc.2 runtime and are documented
// in src/adapter/dsh-input.js.

import test from 'node:test'
import assert from 'node:assert/strict'

import { installGate, displayReasonOf } from '../src/adapter/dsh-gate.js'
import {
  planExecution,
  requiresAnalysis,
  hasInlineHttpCredential,
  sessionCwd,
  effectiveCwd,
} from '../src/adapter/dsh-input.js'

// ---------------------------------------------------------------------------
// Minimal fake Cordis context

function fakeCtx({ services = {}, definitions = {} } = {}) {
  const state = { effects: [], guards: [], listeners: [], calls: { executable: [], fsResolve: [], fsStat: [] } }
  // In the real runtime ctx.fs and ctx.get('fs') are the same mounted
  // FsProvider; mirror that identity in the fake.
  services.fs = services.fs ?? {
    async resolve(target, options) {
      state.calls.fsResolve.push({ target, options })
      return { resolved: target, cwd: options?.cwd }
    },
    async stat(target) {
      state.calls.fsStat.push(target)
      return { target }
    },
  }
  const ctx = {
    logger: { warn() {} },
    fs: services.fs,
    effect(fn) {
      const disposer = fn()
      state.effects.push(disposer)
      return disposer
    },
    on(event, listener) {
      state.listeners.push({ event, listener })
      return () => {
        const index = state.listeners.findIndex((entry) => entry.event === event && entry.listener === listener)
        if (index >= 0) state.listeners.splice(index, 1)
      }
    },
    tools: {
      guard(fn) {
        state.guards.push(fn)
        return () => {
          const index = state.guards.indexOf(fn)
          if (index >= 0) state.guards.splice(index, 1)
        }
      },
      executable(name, agent, toolSet) {
        state.calls.executable.push({ name, agent, toolSet })
        if (toolSet?.view) return toolSet.view(agent).get(name)
        return definitions[name]
      },
    },
    get(key) {
      return services[key]
    },
  }
  return { ctx, state }
}

function sessionAgent(cwd = 'E:/ws') {
  return { session: { header: { cwd } } }
}

function execution({ name, args, agent = sessionAgent(), signal } = {}) {
  return {
    callId: 'call-1',
    rootCallId: 'call-1',
    name,
    arguments: args,
    agent,
    signal: signal ?? new AbortController().signal,
  }
}

/** One official-shaped definition: declared required param plus an execute body. */
function officialDefinition(name, param) {
  return {
    name,
    execute: async () => ({}),
    ...param !== undefined
      ? { parameters: { type: 'object', properties: { [param]: { type: 'string' } }, required: [param] } }
      : {},
  }
}

const ALL_OFFICIAL = {
  pwsh: officialDefinition('pwsh', 'command'),
  bash: officialDefinition('bash', 'command'),
  terminal_send: officialDefinition('terminal_send', 'text'),
  web_fetch: officialDefinition('web_fetch', 'url'),
  read: officialDefinition('read', 'file_path'),
  read_image: officialDefinition('read_image', 'file_path'),
  write: officialDefinition('write', 'file_path'),
  edit: officialDefinition('edit', 'file_path'),
  apply_patch: officialDefinition('apply_patch', 'input'),
  grep: officialDefinition('grep', 'pattern'),
  glob: officialDefinition('glob', 'pattern'),
}

/** Pre-execute listener extracted from the installed gate. */
function preExecuteOf(state) {
  const entry = state.listeners.find((listener) => listener.event === 'tools/pre-execute')
  assert.ok(entry, 'gate must register tools/pre-execute')
  return entry.listener
}

function guardOf(state) {
  assert.equal(state.guards.length, 1, 'gate must register exactly one monotonic guard')
  return state.guards[0]
}

/** Post-execute listener extracted from the installed gate. */
function postExecuteOf(state) {
  const entry = state.listeners.find((listener) => listener.event === 'tools/post-execute')
  assert.ok(entry, 'gate must register tools/post-execute')
  return entry.listener
}

/** Default fake pipeline members; each test overrides what it observes.
 * All members are `this`-free closures: the gate destructures and calls them
 * unbound, exactly like the lead's entry wires the real injected functions. */
function fakeDeps(overrides = {}) {
  const analyzer = {
    analyzeCalls: 0,
    analyses: [],
    analyze(unit, options) {
      const index = this.analyzeCalls
      this.analyzeCalls += 1
      const queue = this.analyses
      const next = queue.length > index
        ? queue[index]
        : queue.length > 0
          ? queue[queue.length - 1]
          : { status: 'complete', operations: [], candidates: [], gaps: [] }
      return typeof next === 'function' ? next({ unit, options, call: index }) : Promise.resolve(next)
    },
    dispose() {
      analyzer.disposed = true
    },
    disposed: false,
  }
  const collectEvidenceCalls = []
  const decideCalls = []
  const state = { fingerprint: undefined, verdict: undefined, policy: undefined, readPolicyCalls: 0 }
  const defaultPolicy = { askTimeoutMs: 120000 }
  const deps = {
    analyzer,
    collectEvidenceCalls,
    collectEvidence(analysis, options) {
      collectEvidenceCalls.push({ analysis, options })
      return { analysis, options, inventory: { fingerprint: state.fingerprint ?? 'fp-1' } }
    },
    decideCalls,
    decide(evidence, policy) {
      decideCalls.push({ evidence, policy })
      return state.verdict ?? { kind: 'allow' }
    },
    renderDecision(verdict) {
      return `[GUARDRAILS] ${String(verdict.kind).toUpperCase()} ${verdict.ruleId ?? ''}\n${verdict.reason ?? ''}`.trim()
    },
    readPolicyCalls: 0,
    readPolicy() {
      state.readPolicyCalls += 1
      deps.readPolicyCalls = state.readPolicyCalls
      return state.policy ?? defaultPolicy
    },
    isProtectedPath() {
      return false
    },
  }
  // Overrides may set `verdict`, `policy`, `fingerprint`, or replace members.
  const { verdict, policy, fingerprint, ...members } = overrides ?? {}
  if (verdict !== undefined) state.verdict = verdict
  if (policy !== undefined) state.policy = policy
  if (fingerprint !== undefined) state.fingerprint = fingerprint
  return Object.assign(deps, members)
}

// ---------------------------------------------------------------------------
// dsh-input: front-door classification

test('requiresAnalysis is true only for official analyzed faces with official shapes', () => {
  const { ctx } = fakeCtx({
    definitions: ALL_OFFICIAL,
    services: { ptcRuntime: { language: 'TypeScript' } },
  })
  for (const name of ['pwsh', 'bash', 'terminal_send', 'run_code', 'web_fetch', 'read', 'write', 'edit', 'apply_patch', 'read_image', 'grep', 'glob']) {
    assert.equal(requiresAnalysis(ctx, execution({ name })), true, name)
  }
  for (const name of ['web_search', 'delete', 'move', 'copy', 'totally_unknown', 'mcp:thing']) {
    assert.equal(requiresAnalysis(ctx, execution({ name })), false, name)
  }
})

test('a grep registration without the official pattern shape is not classified', () => {
  const shadow = { name: 'grep', execute: async () => ({}), parameters: { type: 'object', properties: { q: { type: 'string' } }, required: ['q'] } }
  const { ctx } = fakeCtx({ definitions: { grep: shadow } })
  assert.equal(requiresAnalysis(ctx, execution({ name: 'grep' })), false)
})

test('run_code is the reserved transport: it classifies only with an active ptcRuntime', () => {
  const active = fakeCtx({ definitions: {}, services: { ptcRuntime: { language: 'Python' } } })
  assert.equal(requiresAnalysis(active.ctx, execution({ name: 'run_code' })), true)
  const inactive = fakeCtx({ definitions: {}, services: {} })
  assert.equal(requiresAnalysis(inactive.ctx, execution({ name: 'run_code' })), false)
  const broken = fakeCtx({ definitions: {}, services: { ptcRuntime: {} } })
  assert.equal(requiresAnalysis(broken.ctx, execution({ name: 'run_code' })), false)
})

test('requiresAnalysis is false when the definition is not executable here (scoped shadows decide)', () => {
  const { ctx } = fakeCtx({ definitions: {} })
  assert.equal(requiresAnalysis(ctx, execution({ name: 'pwsh' })), false)
})

test('a registration that only borrows an official name is not classified', () => {
  const shadow = { name: 'write', execute: async () => ({}), parameters: { data: { type: 'string', required: true } } }
  const { ctx } = fakeCtx({ definitions: { write: shadow } })
  assert.equal(requiresAnalysis(ctx, execution({ name: 'write' })), false)
  const plan = planExecution(ctx, execution({ name: 'write', args: { data: 'x' } }))
  return plan.then((value) => assert.equal(value.kind, 'skip'))
})

test('a definition without an execute body never classifies', () => {
  const { ctx } = fakeCtx({ definitions: { read: { name: 'read', parameters: { file_path: { type: 'string', required: true } } } } })
  assert.equal(requiresAnalysis(ctx, execution({ name: 'read' })), false)
})

test('a binding-time schema without the expected param does not classify', () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL })
  const exec = execution({ name: 'edit', args: { file_path: 'a' } })
  exec.schema = { name: 'edit', parameters: { payload: { type: 'string', required: true } } }
  assert.equal(requiresAnalysis(ctx, exec), false)
})

test('resolveDefinition prefers the step admission set (PTC toolSet)', () => {
  const { ctx } = fakeCtx({ definitions: { pwsh: officialDefinition('pwsh', 'command') } })
  const toolSet = { view: () => new Map([['pwsh', officialDefinition('pwsh', 'command')]]) }
  const resolved = ctx.tools.executable('pwsh', sessionAgent(), toolSet)
  assert.ok(resolved)
  assert.equal(ctx.tools.executable('pwsh', sessionAgent(), undefined)?.name, 'pwsh')
})

test('pwsh unit carries inline source, effective cwd and dialect; relative workdir resolves', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL })
  const exec = execution({ name: 'pwsh', args: { command: 'Remove-Item ./a', workdir: 'sub' } })
  const plan = await planExecution(ctx, exec)
  assert.equal(plan.kind, 'command')
  assert.deepEqual(plan.unit.source, { kind: 'inline', text: 'Remove-Item ./a' })
  assert.equal(plan.unit.context.cwd, 'E:/ws/sub')
  assert.equal(plan.unit.language, 'powershell')
  assert.equal(plan.unit.origin.entry, 'pwsh')
})

test('absolute workdir is used as-is', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL })
  const exec = execution({ name: 'bash', args: { command: 'rm -rf ./a', workdir: '/tmp/x' } })
  const plan = await planExecution(ctx, exec)
  assert.equal(plan.unit.context.cwd, '/tmp/x')
  assert.equal(plan.unit.language, 'bash')
})

test('relative workdir with no base is a bounded fault, not a process.cwd guess', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL, services: { workingDirectory: { get: () => undefined } } })
  const exec = execution({ name: 'bash', args: { command: 'x', workdir: 'sub' }, agent: {} })
  const plan = await planExecution(ctx, exec)
  assert.equal(plan.kind, 'fault')
  assert.equal(plan.code, 'GUARD_WORKDIR_UNRESOLVED')
})

test('non-string command text is a bounded fault', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL })
  const plan = await planExecution(ctx, execution({ name: 'pwsh', args: { command: 42 } }))
  assert.equal(plan.kind, 'fault')
  assert.equal(plan.code, 'GUARD_INVALID_SHELL_INPUT')
})

test('terminal_send carries no cwd/platform assumption; backend type only when authoritative', async () => {
  const withTerminal = fakeCtx({
    definitions: ALL_OFFICIAL,
    services: { terminals: { list: () => [{ sessionId: 't1', type: 'shell' }, { sessionId: 't2', type: 'tmux-shell' }] } },
  })
  const withPlan = await planExecution(withTerminal.ctx, execution({ name: 'terminal_send', args: { sessionId: 't2', text: 'rm -rf ./a' } }))
  assert.equal(withPlan.kind, 'command')
  assert.equal(withPlan.unit.context.cwd, undefined)
  assert.equal(withPlan.unit.context.platform, undefined)
  assert.deepEqual(withPlan.unit.origin.terminal, { type: 'tmux-shell' })

  const without = await planExecution(withTerminal.ctx, execution({ name: 'terminal_send', args: { sessionId: 'missing', text: 'x' } }))
  assert.equal(without.unit.origin.terminal, undefined)

  const bare = fakeCtx({ definitions: ALL_OFFICIAL })
  const barePlan = await planExecution(bare.ctx, execution({ name: 'terminal_send', args: { sessionId: 't1', text: 'x' } }))
  assert.equal(barePlan.unit.origin.terminal, undefined)
})

test('run_code unit uses the PTC runtime language and the session cwd', async () => {
  const { ctx } = fakeCtx({
    definitions: {},
    services: { ptcRuntime: { language: 'TypeScript' } },
  })
  const plan = await planExecution(ctx, execution({ name: 'run_code', args: { code: 'await tools.pwsh({command:"rm -rf ./x"})' } }))
  assert.equal(plan.unit.language, 'TypeScript')
  assert.equal(plan.unit.context.cwd, 'E:/ws')
})

test('structured read/write targets become exact fs operations with the same cwd', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL })
  const readPlan = await planExecution(ctx, execution({ name: 'read', args: { file_path: 'secrets.env' } }))
  assert.equal(readPlan.kind, 'structured')
  assert.equal(readPlan.analysis.status, 'complete')
  assert.equal(readPlan.analysis.operations.length, 1)
  const op = readPlan.analysis.operations[0]
  assert.equal(op.action, 'read-content')
  assert.deepEqual(op.context, { domain: 'fs', cwd: 'E:/ws' })
  assert.deepEqual(op.target, { kind: 'exact', paths: ['secrets.env'] })
  assert.equal(op.recursive, false)
  assert.equal(op.preview, false)
  assert.equal(op.condition, 'certain')
  assert.equal(op.origin.entry, 'read')

  const writePlan = await planExecution(ctx, execution({ name: 'write', args: { file_path: 'out.txt' } }))
  assert.equal(writePlan.analysis.operations[0].action, 'write-content')

  const editPlan = await planExecution(ctx, execution({ name: 'edit', args: { file_path: 'a.js' } }))
  assert.equal(editPlan.analysis.operations[0].action, 'write-content')
})

test('structured target with no authoritative base is partial, never process.cwd', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL, services: { workingDirectory: { get: () => undefined } } })
  const plan = await planExecution(ctx, execution({ name: 'write', args: { file_path: 'out.txt' }, agent: {} }))
  assert.equal(plan.analysis.status, 'partial')
  assert.deepEqual(plan.analysis.gaps, [{ code: 'GUARD_TARGET_BASE_UNKNOWN' }])
  const op = plan.analysis.operations[0]
  assert.deepEqual(op.context, { domain: 'fs' })
})

test('apply_patch maps Codex operations; Delete File stays nonrecursive; move splits source and write', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL })
  const patch = [
    '*** Begin Patch',
    '*** Add File: new.txt',
    '+hi',
    '*** Delete File: old.txt',
    '*** Update File: renamed.txt',
    '*** Move to: renamed2.txt',
    '@@',
    '-a',
    '+b',
    '*** Update File: kept.txt',
    '-x',
    '+y',
    '*** End Patch',
  ].join('\n')
  const plan = await planExecution(ctx, execution({ name: 'apply_patch', args: { input: patch } }), {
    parsePatch: () => [
      { kind: 'add', lineNumber: 2, path: 'new.txt' },
      { kind: 'delete', lineNumber: 4, path: 'old.txt' },
      { kind: 'update', lineNumber: 5, path: 'renamed.txt', moveTo: 'renamed2.txt', hunks: [] },
      { kind: 'update', lineNumber: 9, path: 'kept.txt', hunks: [] },
    ],
  })
  assert.equal(plan.analysis.status, 'complete')
  const actions = plan.analysis.operations.map((op) => `${op.action}:${op.target.paths[0]}:${op.recursive}`)
  assert.deepEqual(actions, [
    'write-content:new.txt:false',
    'delete:old.txt:false',
    'move-source:renamed.txt:false',
    'write-content:renamed2.txt:false',
    'write-content:kept.txt:false',
  ])
})

test('apply_patch parser failures are fault analyses with unknown candidates', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL })
  const throwing = await planExecution(ctx, execution({ name: 'apply_patch', args: { input: '*** Begin Patch' } }), {
    parsePatch: () => { throw new Error('Invalid patch') },
  })
  assert.equal(throwing.analysis.status, 'fault')
  assert.deepEqual(throwing.analysis.candidates, [{ kind: 'unknown', reason: 'patch-unparsed' }])

  const missing = await planExecution(ctx, execution({ name: 'apply_patch', args: { input: '*** Begin Patch' } }), {})
  assert.equal(missing.analysis.status, 'fault')
  assert.deepEqual(missing.analysis.candidates, [{ kind: 'unknown', reason: 'patch-parser-unavailable' }])
})

test('apply_patch accepts an async official-style parser', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL })
  const plan = await planExecution(ctx, execution({ name: 'apply_patch', args: { input: 'p' } }), {
    parsePatch: async () => [{ kind: 'delete', lineNumber: 2, path: 'x.txt' }],
  })
  assert.equal(plan.analysis.status, 'complete')
  assert.equal(plan.analysis.operations[0].action, 'delete')
})

test('web_fetch scans only the real url parameter for userinfo credentials', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL })
  const leak = await planExecution(ctx, execution({ name: 'web_fetch', args: { url: 'https://user:s3cret-password@host.example/x' } }))
  assert.equal(leak.analysis.inlineCredential, true)
  assert.equal(leak.analysis.status, 'complete')
  assert.deepEqual(leak.analysis.operations, [])

  const clean = await planExecution(ctx, execution({ name: 'web_fetch', args: { url: 'https://host.example/x?token=abc' } }))
  assert.equal(clean.analysis.inlineCredential, undefined)
})

test('hasInlineHttpCredential matches only userinfo form with a password', () => {
  assert.equal(hasInlineHttpCredential('https://user:pass@host/x'), true)
  assert.equal(hasInlineHttpCredential('http://u:p@10.0.0.1/'), true)
  assert.equal(hasInlineHttpCredential('https://user@host/x'), false)
  assert.equal(hasInlineHttpCredential('https://host/x?password=p'), false)
  assert.equal(hasInlineHttpCredential('not a url'), false)
  assert.equal(hasInlineHttpCredential(undefined), false)
})

test('web_fetch never produces deletion analysis, even with inline credentials', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL })
  const plan = await planExecution(ctx, execution({ name: 'web_fetch', args: { url: 'https://user:s3cret-password@host.example/x' } }))
  assert.equal(plan.kind, 'structured')
  assert.equal(plan.analysis.status, 'complete')
  assert.equal(plan.analysis.inlineCredential, true)
  assert.deepEqual(plan.analysis.operations, [])
  assert.deepEqual(plan.analysis.candidates, [])
  assert.deepEqual(plan.analysis.gaps, [])
})

// ---------------------------------------------------------------------------
// Official search tools: grep / glob front door (DSR-015)

/** FsProvider fake with the real resolve/stat result shapes (targetKey + displayPath). */
function searchFsFake() {
  return {
    async resolve(target, options) {
      const cwd = typeof options?.cwd === 'string' ? options.cwd.replace(/[\\/]+$/, '') : ''
      const shown = cwd ? `${cwd}/${target}` : target
      return { resolved: target, targetKey: `k:${shown}`, displayPath: shown }
    },
    async stat() {
      return { type: 'file', version: 1 }
    },
  }
}

test('grep on an explicit protected file plans read-content and the decision asks once', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL })
  const plan = await planExecution(ctx, execution({ name: 'grep', args: { pattern: 'token', path: 'secrets.env' } }))
  assert.equal(plan.kind, 'structured')
  assert.equal(plan.analysis.status, 'complete')
  const op = plan.analysis.operations[0]
  assert.equal(op.action, 'read-content')
  assert.deepEqual(op.target, { kind: 'exact', paths: ['secrets.env'] })
  assert.deepEqual(op.context, { domain: 'fs', cwd: 'E:/ws' })
  assert.equal(op.origin.entry, 'grep')

  // Evidence layer over the plan: the protected path surfaces with the read action,
  // and the pure decision point returns the credential.file.read confirmation.
  const { collectEvidence } = await import('../src/adapter/evidence/index.js')
  const { decide, isProtectedPath } = await import('../src/core/decision.js')
  const policy = { sensitiveFiles: ['E:/ws/secrets.env'] }
  const evidence = await collectEvidence(plan.analysis, { policy, fsProvider: searchFsFake(), isProtectedPath })
  assert.ok(evidence.protectedHits.some((hit) => hit.path === 'E:/ws/secrets.env' && hit.action === 'read-content'),
    JSON.stringify(evidence.protectedHits))
  const verdict = decide(evidence, policy)
  assert.equal(verdict.kind, 'confirm')
  assert.equal(verdict.ruleId, 'credential.file.read')
})

test('grep include filters matches only; a missing path records no target (DSR-015)', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL })
  const withInclude = await planExecution(ctx, execution({ name: 'grep', args: { pattern: 'token', path: 'notes.txt', include: '*.md' } }))
  assert.equal(withInclude.analysis.status, 'complete')
  assert.equal(withInclude.analysis.operations[0].action, 'read-content')
  assert.deepEqual(withInclude.analysis.operations[0].target, { kind: 'exact', paths: ['notes.txt'] })

  const workspaceScan = await planExecution(ctx, execution({ name: 'grep', args: { pattern: 'token' } }))
  assert.equal(workspaceScan.kind, 'structured')
  assert.equal(workspaceScan.analysis.status, 'complete')
  assert.deepEqual(workspaceScan.analysis.operations, [])

  // Even a builtin-named workspace scan never yields a protected hit: directory-level
  // search never triggers (DSR-015).
  const { collectEvidence } = await import('../src/adapter/evidence/index.js')
  const { decide, isProtectedPath } = await import('../src/core/decision.js')
  const evidence = await collectEvidence(workspaceScan.analysis, { policy: null, fsProvider: searchFsFake(), isProtectedPath })
  assert.deepEqual(evidence.protectedHits, [])
  assert.equal(decide(evidence, null).kind, 'allow')
})

test('glob plans a metadata query and decide never confirms it (R-04)', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL })
  const plan = await planExecution(ctx, execution({ name: 'glob', args: { pattern: '**/*.env' } }))
  assert.equal(plan.kind, 'structured')
  assert.equal(plan.analysis.status, 'complete')
  const op = plan.analysis.operations[0]
  assert.equal(op.action, 'metadata')
  assert.deepEqual(op.target, { kind: 'pattern', base: 'E:/ws', pattern: '**/*.env' })
  assert.equal(op.origin.entry, 'glob')

  // Even when the search base itself names a builtin carrier, the metadata action
  // surfaces as a hit but never confirms.
  const { collectEvidence } = await import('../src/adapter/evidence/index.js')
  const { decide, isProtectedPath } = await import('../src/core/decision.js')
  const named = await planExecution(ctx, execution({ name: 'glob', args: { pattern: '**/*', path: '.npmrc' } }))
  assert.equal(named.analysis.operations[0].action, 'metadata')
  assert.deepEqual(named.analysis.operations[0].target, { kind: 'pattern', base: '.npmrc', pattern: '**/*' })
  const evidence = await collectEvidence(named.analysis, { policy: null, fsProvider: searchFsFake(), isProtectedPath })
  assert.ok(evidence.protectedHits.some((hit) => hit.path === 'E:/ws/.npmrc' && hit.action === 'metadata'),
    JSON.stringify(evidence.protectedHits))
  const verdict = decide(evidence, null)
  assert.equal(verdict.kind, 'allow')
})

test('glob without a path and without an authoritative base skips instead of inventing one', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL, services: { workingDirectory: { get: () => undefined } } })
  const plan = await planExecution(ctx, execution({ name: 'glob', args: { pattern: '**/*' }, agent: {} }))
  assert.equal(plan.kind, 'skip')
})

test('unmodelled tools and absent targets skip analysis', async () => {
  const { ctx } = fakeCtx({ definitions: ALL_OFFICIAL })
  assert.equal((await planExecution(ctx, execution({ name: 'web_search', args: { queries: ['x'] } }))).kind, 'skip')
  assert.equal((await planExecution(ctx, execution({ name: 'read', args: {} }))).kind, 'skip')
  assert.equal((await planExecution(ctx, execution({ name: 'pwsh' }))).kind, 'fault')
})

test('sessionCwd prefers the workingDirectory service, then the header', () => {
  const overridden = fakeCtx({
    definitions: ALL_OFFICIAL,
    services: { workingDirectory: { get: () => 'E:/live' } },
  })
  assert.equal(sessionCwd(overridden.ctx, execution({})), 'E:/live')
  const headerOnly = fakeCtx({ definitions: ALL_OFFICIAL, services: {} })
  assert.equal(sessionCwd(headerOnly.ctx, execution({})), 'E:/ws')
})

test('effectiveCwd falls back to the sandbox workspace root without process.cwd', () => {
  const { ctx } = fakeCtx({
    definitions: ALL_OFFICIAL,
    services: { sandboxPolicy: { resolve: () => ({ workspaceRoot: 'E:/sandbox' }) } },
  })
  const exec = execution({ name: 'bash', args: { command: 'x' }, agent: {} })
  assert.equal(effectiveCwd(ctx, exec, {}), 'E:/sandbox')
})

// ---------------------------------------------------------------------------
// installGate: validation, wiring, and pipeline

test('installGate validates every dependency and the analyzer object members', () => {
  const { ctx } = fakeCtx()
  assert.throws(() => installGate(ctx, null), TypeError)
  assert.throws(() => installGate(ctx, fakeDeps({ collectEvidence: undefined })), /collectEvidence/)
  assert.throws(() => installGate(ctx, fakeDeps({ analyzer: 'not an object' })), /analyzer/)
  const missingDispose = fakeDeps()
  missingDispose.analyzer = { analyze() {} }
  assert.throws(() => installGate(fakeCtx().ctx, missingDispose), /analyzer\.dispose/)
  const missingAnalyze = fakeDeps()
  missingAnalyze.analyzer = { dispose() {} }
  assert.throws(() => installGate(fakeCtx().ctx, missingAnalyze), /analyzer\.analyze/)
})

test('gate registers pre-execute, post-execute and guard as disposable effects and disposes the analyzer on unload', () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  const deps = fakeDeps()
  installGate(ctx, deps)
  assert.equal(state.listeners.length, 2)
  assert.equal(state.guards.length, 1)
  assert.equal(state.effects.length, 4)
  state.effects.forEach((disposer) => disposer())
  assert.equal(deps.analyzer.disposed, true)
})

test('design skips pass without analysis; the guard leaves them untouched', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  const deps = fakeDeps()
  installGate(ctx, deps)
  const listener = preExecuteOf(state)
  const guard = guardOf(state)
  const exec = execution({ name: 'web_search', args: { queries: ['x'] } })
  let nexted = false
  const decision = await listener(exec, async () => { nexted = true; return { kind: 'allow' } })
  assert.equal(decision.kind, 'allow')
  assert.equal(nexted, true)
  assert.equal(guard(exec), undefined)
  assert.deepEqual(deps.decideCalls, [])
})

test('allow verdict runs the full pipeline; the evidence member gets the actual FsProvider', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  const deps = fakeDeps()
  installGate(ctx, deps)
  const listener = preExecuteOf(state)
  const guard = guardOf(state)
  const exec = execution({ name: 'pwsh', args: { command: 'Get-Content ./a' } })
  let nexted = false
  const decision = await listener(exec, async () => { nexted = true; return { kind: 'allow' } })
  assert.equal(nexted, true)
  const options = deps.collectEvidenceCalls[0].options
  assert.equal(options.policy, deps.readPolicy())
  assert.ok(options.signal instanceof AbortSignal)
  assert.equal(options.signal.aborted, false)
  assert.equal(options.workspaceRoot, undefined)
  assert.equal(options.isProtectedPath, deps.isProtectedPath)
  // The evidence member receives the actual mounted FsProvider unchanged and
  // calls its official resolve/stat methods directly.
  assert.equal(options.fsProvider, ctx.fs)
  assert.equal(typeof options.fsProvider?.resolve, 'function')
  assert.equal(typeof options.fsProvider?.stat, 'function')
  const observed = await options.fsProvider.resolve('rel.env', { cwd: 'E:/ws', signal: options.signal })
  assert.deepEqual(state.calls.fsResolve[0], { target: 'rel.env', options: { cwd: 'E:/ws', signal: options.signal } })
  assert.deepEqual(observed, { resolved: 'rel.env', cwd: 'E:/ws' })
  assert.equal(guard(exec), undefined)
})

test('deny verdict renders once and the guard reports the same sanitized reason', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  const deps = fakeDeps({
    verdict: { kind: 'deny', ruleId: 'catastrophic.device', reason: 'catastrophic device identity' },
  })
  installGate(ctx, deps)
  const listener = preExecuteOf(state)
  const guard = guardOf(state)
  const exec = execution({ name: 'bash', args: { command: 'dd if=/dev/zero of=/dev/sda' } })
  const decision = await listener(exec, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /DENY catastrophic\.device/)
  assert.equal(guard(exec).reason, decision.reason)
})

test('the guard consumes the completed decision; a second dispatch attempt faults', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  installGate(ctx, fakeDeps())
  const guard = guardOf(state)
  const exec = execution({ name: 'bash', args: { command: 'x' } })
  await preExecuteOf(state)(exec, async () => ({ kind: 'allow' }))
  assert.equal(guard(exec), undefined)
  assert.match(guard(exec).reason, /ANALYSIS_MISSING/)
})

test('analyzer throw is a bounded sanitized fault without command text', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  const deps = fakeDeps()
  deps.analyzer.analyze = () => { throw new Error('parser exploded: rm -rf ./secret-source') }
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'pwsh', args: { command: 'rm -rf ./x' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.doesNotMatch(decision.reason, /rm -rf|parser exploded/)
})

test('partial and fault analyses surface their gaps through diagnose', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  const diagnosed = []
  const deps = fakeDeps({
    diagnose(gaps) {
      diagnosed.push(gaps)
      return 'decoded gap text'
    },
  })
  deps.analyzer.analyze = async () => ({ status: 'partial', operations: [], candidates: [], gaps: [{ code: 'GUARD_TARGET_BASE_UNKNOWN' }] })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'x' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'allow')
  assert.deepEqual(diagnosed, [[{ code: 'GUARD_TARGET_BASE_UNKNOWN' }]])
})

test('invalid shell input is a bounded fault at the gate boundary', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  const { renderDecision } = await import('../src/core/decision.js')
  const deps = fakeDeps()
  deps.renderDecision = renderDecision
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'pwsh', args: {} }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /GUARD_INVALID_SHELL_INPUT/)
  // The rendered block now names the real stage code in its Trigger line.
  assert.match(decision.reason, /Trigger: check failure: GUARD_INVALID_SHELL_INPUT/)
  assert.match(decision.reason, /codes: GUARD_INVALID_SHELL_INPUT/)
  // STAGE_META gives an actionable alternative for this stage.
  assert.match(decision.reason, /Effect:  The tool argument carrying command text was missing or not a string/)
  assert.match(decision.reason, /Next:    Nothing was executed\. Pass the command as one string for the shell tool/)
})

test('a relative working directory fault explains the absolute-path alternative', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { workingDirectory: { get: () => undefined } } })
  const { renderDecision } = await import('../src/core/decision.js')
  const deps = fakeDeps()
  deps.renderDecision = renderDecision
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'x', workdir: 'sub' }, agent: {} }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /GUARD_WORKDIR_UNRESOLVED/)
  assert.match(decision.reason, /Effect:  The relative working directory has no resolvable base/)
  assert.match(decision.reason, /Next:    Nothing was executed\. Use an absolute working directory/)
})

test('a patch-parse fault carries the real gap code in its trigger', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  const { decide, renderDecision } = await import('../src/core/decision.js')
  const deps = fakeDeps()
  deps.collectEvidence = (analysis) => ({
    analysisStatus: analysis.status,
    operations: analysis.operations ?? [],
    candidates: analysis.candidates ?? [],
    gaps: analysis.gaps ?? [],
    identities: [],
    inventory: null,
    protectedHits: [],
    exemptions: [],
    issues: [],
  })
  deps.decide = decide
  deps.renderDecision = renderDecision
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'apply_patch', args: { input: '*** Begin Patch' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /GUARD_PATCH_PARSE_FAILED/)
  assert.match(decision.reason, /Trigger: check failure: GUARD_PATCH_PARSE_FAILED/)
  assert.match(decision.reason, /codes: GUARD_PATCH_PARSE_FAILED/)
  assert.doesNotMatch(decision.reason, /crash, protocol damage/)
  // The trigger code now selects STAGE_META, so the concrete patch alternative is shown.
  assert.match(decision.reason, /Next:    Nothing was executed\. Provide a parseable patch or an absolute base path\./)
  assert.doesNotMatch(decision.reason, /Retry with a clearer, fully literal command/)
})

test('internal invariant faults all tell the user to report the rule id', async () => {
  const { renderDecision } = await import('../src/core/decision.js')
  for (const stage of ['GUARD_DECISION_INVALID', 'GUARD_RENDER_FAILED', 'GUARD_CONFIRM_UNSCOPED']) {
    const text = renderDecision({
      kind: 'deny',
      ruleId: 'execution.check-failed',
      reason: `execution.check-failed (stage ${stage}): x`,
      trigger: `check failure: ${stage}`,
    })
    assert.match(text, /^\[GUARDRAILS\] DENY execution\.check-failed/, stage)
    assert.match(text,
      /Next:    Nothing was executed\. This is an internal guard failure with no action available to you; report it to the user with this rule id\./,
      stage)
  }
})

test('confirm with an unscoped decision is refused without asking the user', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  const deps = fakeDeps({ verdict: { kind: 'confirm', ruleId: 'data.delete.bulk' } })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /GUARD_CONFIRM_UNSCOPED/)
})

test('unknown verdict kinds never read as permission', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  installGate(ctx, fakeDeps({ verdict: { kind: 'probably-fine' } }))
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'x' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /GUARD_DECISION_INVALID/)
})

// ---------------------------------------------------------------------------
// Approval flow

function approvalService(outcomes, log = []) {
  return {
    request(req) {
      log.push(req)
      const next = outcomes.shift()
      if (next instanceof Error) throw next
      if (typeof next === 'function') return next(req)
      return Promise.resolve(next ?? 'rejected')
    },
  }
}

test('confirm asks once; only allowed-once grants; every other outcome denies', async () => {
  for (const [outcome, expectGrant] of [
    ['allowed-once', true],
    ['rejected', false],
    ['cancelled', false],
    ['unavailable', false],
    ['mysterious', false],
  ]) {
    const { ctx, state } = fakeCtx({
      definitions: ALL_OFFICIAL,
      services: { approval: approvalService([outcome]) },
    })
    const deps = fakeDeps({
      verdict: { kind: 'confirm', ruleId: 'data.delete.bulk', scope: { entries: ['./build'] } },
    })
    installGate(ctx, deps)
    const exec = execution({ name: 'bash', args: { command: 'rm -rf ./build' } })
    const decision = await preExecuteOf(state)(exec, async () => ({ kind: 'allow' }))
    assert.equal(decision.kind === 'allow', expectGrant, outcome)
    if (!expectGrant) assert.match(decision.reason, /APPROVAL_/)
  }
})

test('ask timeout for removable targets says nothing was executed and asks for literal targets', async () => {
  const { ctx, state } = fakeCtx({
    definitions: ALL_OFFICIAL,
    services: { approval: approvalService([() => new Promise(() => {})]) },
  })
  const deps = fakeDeps({
    policy: { askTimeoutMs: 20 },
    verdict: { kind: 'confirm', ruleId: 'data.delete.bulk', scope: ['./build'] },
  })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /APPROVAL_TIMEOUT: No confirmation arrived within the wait; nothing was executed\./)
  assert.match(decision.reason, /fewer, literal targets/)
})

test('ask timeout for other targets points at a manual or later run', async () => {
  const { ctx, state } = fakeCtx({
    definitions: ALL_OFFICIAL,
    services: { approval: approvalService([() => new Promise(() => {})]) },
  })
  const deps = fakeDeps({
    policy: { askTimeoutMs: 20 },
    verdict: { kind: 'confirm', ruleId: 'data.git.worktree', scope: { knownScope: ['/wt'] } },
  })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'git worktree remove /wt' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /APPROVAL_TIMEOUT: No confirmation arrived within the wait; nothing was executed\./)
  assert.match(decision.reason, /when the user can respond/)
})

test('ask timeout for credential targets suggests a redacted excerpt or injection', async () => {
  const { ctx, state } = fakeCtx({
    definitions: ALL_OFFICIAL,
    services: { approval: approvalService([() => new Promise(() => {})]) },
  })
  const deps = fakeDeps({
    policy: { askTimeoutMs: 20 },
    verdict: { kind: 'confirm', ruleId: 'credential.file.read', scope: { files: ['secrets.env'] } },
  })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'cat secrets.env' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /APPROVAL_TIMEOUT: No confirmation arrived within the wait; nothing was executed\./)
  assert.match(decision.reason, /paste a redacted excerpt, or use credential injection\/environment variables/)
  assert.doesNotMatch(decision.reason, /make the change manually/)
  assert.doesNotMatch(decision.reason, /when the user can respond/)
})

test('ask timeout for credential.file.mutate asks the user to make the change manually', async () => {
  const { ctx, state } = fakeCtx({
    definitions: ALL_OFFICIAL,
    services: { approval: approvalService([() => new Promise(() => {})]) },
  })
  const deps = fakeDeps({
    policy: { askTimeoutMs: 20 },
    verdict: { kind: 'confirm', ruleId: 'credential.file.mutate', scope: { files: ['secrets.env'] } },
  })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm secrets.env' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /Ask the user to make the change manually; agent tools must not modify credential files\./)
  assert.doesNotMatch(decision.reason, /paste a redacted excerpt/)
})

test('caller cancellation during analysis denies and never grants', async () => {
  const controller = new AbortController()
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  const deps = fakeDeps()
  deps.analyzer.analyze = async () => {
    controller.abort()
    return { status: 'complete', operations: [], candidates: [], gaps: [] }
  }
  installGate(ctx, deps)
  const exec = execution({ name: 'bash', args: { command: 'x' }, signal: controller.signal })
  const decision = await preExecuteOf(state)(exec, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /ANALYSIS_CANCELLED/)
})

test('missing completed analysis at the final guard is a bounded fault; skips never need one', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  const { renderDecision } = await import('../src/core/decision.js')
  const deps = fakeDeps()
  deps.renderDecision = renderDecision
  installGate(ctx, deps)
  const guard = guardOf(state)
  const required = execution({ name: 'bash', args: { command: 'x' } })
  const reason = guard(required).reason
  assert.match(reason, /ANALYSIS_MISSING/)
  assert.match(reason, /Trigger: check failure: ANALYSIS_MISSING/)
  assert.match(reason, /Effect:  /)
  assert.match(reason, /Next:    Nothing was executed\./)
  assert.equal(guard(execution({ name: 'todo_write', args: {} })), undefined)
})

test('plugin unload aborts the lifetime; the guard refuses afterwards', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  const { renderDecision } = await import('../src/core/decision.js')
  const deps = fakeDeps()
  deps.renderDecision = renderDecision
  installGate(ctx, deps)
  const guard = guardOf(state)
  state.effects.forEach((disposer) => disposer())
  const reason = guard(execution({ name: 'bash', args: { command: 'x' } })).reason
  assert.match(reason, /ANALYSIS_DISPOSED/)
  assert.match(reason, /Trigger: check failure: ANALYSIS_DISPOSED/)
  assert.match(reason, /Next:    Nothing was executed\./)
})

test('a cancelled guard refusal is a rendered fault block, not a single line', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  const { renderDecision } = await import('../src/core/decision.js')
  const deps = fakeDeps()
  deps.renderDecision = renderDecision
  installGate(ctx, deps)
  const controller = new AbortController()
  controller.abort()
  const exec = execution({ name: 'bash', args: { command: 'x' }, signal: controller.signal })
  const reason = guardOf(state)(exec).reason
  assert.match(reason, /ANALYSIS_CANCELLED/)
  assert.match(reason, /Trigger: check failure: ANALYSIS_CANCELLED/)
  assert.match(reason, /Effect:  /)
  assert.match(reason, /Next:    Nothing was executed\./)
})

// ---------------------------------------------------------------------------
// Post-approval full revisit

const CONFIRM = { kind: 'confirm', ruleId: 'data.delete.bulk', scope: { entries: ['./build'] } }

/** Fake pipeline members that drive one deterministic multi-round scenario. */
function scenarioDeps({ analyses, verdicts, fingerprints = ['fp-1', 'fp-1', 'fp-1'], approvals, policies }) {
  const deps = fakeDeps()
  deps.analyzer.analyses = analyses
  const decideCalls = []
  deps.decideCalls = decideCalls
  deps.decide = (evidence, policy) => {
    decideCalls.push({ evidence, policy })
    return verdicts[Math.min(decideCalls.length - 1, verdicts.length - 1)]
  }
  let collect = 0
  const collectEvidenceCalls = []
  deps.collectEvidenceCalls = collectEvidenceCalls
  deps.collectEvidence = (analysis, options) => {
    collectEvidenceCalls.push({ analysis, options })
    const fingerprint = fingerprints[Math.min(collect, fingerprints.length - 1)]
    collect += 1
    return { analysis, options, inventory: { fingerprint } }
  }
  let policyRead = 0
  deps.readPolicy = () => {
    deps.readPolicyCalls = policyRead += 1
    return policies ? policies[Math.min(policyRead - 1, policies.length - 1)] : { askTimeoutMs: 120000 }
  }
  deps.approvalLog = []
  return deps
}

function approvalCtx(outcomes, log = []) {
  return fakeCtx({
    definitions: ALL_OFFICIAL,
    services: { approval: approvalService(outcomes, log) },
  })
}

test('post-approval revisit reruns planning, analysis, live policy and evidence', async () => {
  const { ctx, state } = approvalCtx(['allowed-once'])
  const deps = scenarioDeps({
    analyses: [{ status: 'complete', operations: [] }],
    verdicts: [CONFIRM, { kind: 'allow' }],
  })
  installGate(ctx, deps)
  const exec = execution({ name: 'bash', args: { command: 'rm -rf ./a' } })
  const decision = await preExecuteOf(state)(exec, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'allow')
  // Analysis ran twice (planning rerun included), policy read twice (live), evidence twice.
  assert.equal(deps.analyzer.analyzeCalls, 2)
  assert.equal(deps.readPolicyCalls, 2)
  assert.equal(deps.collectEvidenceCalls.length, 2)
  assert.deepEqual(deps.decideCalls[1].policy, { askTimeoutMs: 120000 })
})

test('revisit denies when script contents changed the analyzed operations while waiting', async () => {
  const { ctx, state } = approvalCtx(['allowed-once'])
  const op = (path) => ({
    action: 'delete', context: { domain: 'fs', cwd: 'E:/ws' }, target: { kind: 'exact', paths: [path] },
    recursive: false, preview: false, condition: 'certain',
  })
  const deps = scenarioDeps({
    analyses: [
      { status: 'complete', operations: [op('./a')] },
      { status: 'complete', operations: [op('./b')] },
    ],
    verdicts: [CONFIRM, { kind: 'allow' }],
  })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'bash ./script.sh' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /GUARD_SCOPE_CHANGED/)
})

test('revisit denies when the evidence fingerprint version changed', async () => {
  const { ctx, state } = approvalCtx(['allowed-once'])
  const deps = scenarioDeps({
    analyses: [{ status: 'complete', operations: [] }],
    verdicts: [CONFIRM, { kind: 'allow' }],
    fingerprints: ['fp-1', 'fp-2'],
  })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /GUARD_SCOPE_CHANGED/)
})

test('an empty fingerprint is not a stable version; the decision scope still compares', async () => {
  const { ctx, state } = approvalCtx(['allowed-once'])
  const deps = scenarioDeps({
    analyses: [{ status: 'complete', operations: [] }],
    verdicts: [CONFIRM, { kind: 'allow' }],
    fingerprints: ['', ''],
  })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'allow')
})

test('a NEW confirmation after approval re-asks within the remaining total wait', async () => {
  const deps = scenarioDeps({
    analyses: [{ status: 'complete', operations: [] }],
    verdicts: [CONFIRM, { kind: 'confirm', ruleId: 'credential.file.read', scope: { files: ['secrets.env'] } }],
  })
  const { ctx, state } = approvalCtx(['allowed-once', 'allowed-once'], deps.approvalLog)
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'allow')
  assert.equal(deps.approvalLog.length, 2)
  // The second ask carries the new rule's rendered reason and stays bounded.
  assert.match(deps.approvalLog[1].reason, /CONFIRM credential\.file\.read/)
  // After the second grant the gate rechecked again (three full rounds of evidence).
  assert.equal(deps.collectEvidenceCalls.length, 3)
  assert.equal(deps.analyzer.analyzeCalls, 3)
})

test('a still-new confirmation after the second grant refuses and mandates a fresh invocation', async () => {
  const deps = scenarioDeps({
    analyses: [{ status: 'complete', operations: [] }],
    verdicts: [
      CONFIRM,
      { kind: 'confirm', ruleId: 'credential.file.read', scope: { files: ['secrets.env'] } },
      { kind: 'confirm', ruleId: 'catastrophic.git-metadata', scope: { files: ['.git'] } },
    ],
  })
  const { ctx, state } = approvalCtx(['allowed-once', 'allowed-once'], deps.approvalLog)
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /GUARD_REAPPROVAL_UNRESOLVED/)
  assert.match(decision.reason, /fresh invocation/)
})

test('reapproval budget is bounded by the total configured wait', async () => {
  const deps = scenarioDeps({
    analyses: [{ status: 'complete', operations: [] }],
    verdicts: [CONFIRM, { kind: 'confirm', ruleId: 'credential.file.read', scope: { files: ['s'] } }],
    policies: [{ askTimeoutMs: 120 }, { askTimeoutMs: 120 }],
  })
  const { ctx, state } = approvalCtx(['allowed-once', () => new Promise(() => {})], deps.approvalLog)
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'x' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.ok(deps.approvalLog[1], 'reapproval must have been requested')
  assert.match(decision.reason, /APPROVAL_TIMEOUT/)
})

test('revisit verdict deny refuses even after a grant', async () => {
  const { ctx, state } = approvalCtx(['allowed-once'])
  const deps = scenarioDeps({
    analyses: [{ status: 'complete', operations: [] }],
    verdicts: [CONFIRM, { kind: 'deny', ruleId: 'catastrophic.root', reason: 'now catastrophic' }],
  })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /catastrophic\.root/)
})

// ---------------------------------------------------------------------------
// alwaysAsk: the interactive question channel when the approval policy is "never"
// ---------------------------------------------------------------------------

/** Question-channel double: records each request and resolves `respond(request)`. */
function questionService(respond, log = []) {
  const service = {
    calls: 0,
    ask(request) {
      service.calls += 1
      log.push(request)
      return Promise.resolve().then(() => respond(request))
    },
  }
  return service
}

/** Approval-seam double for the "never" policy; its request must never run. */
function neverApproval() {
  const approval = {
    config: { policy: 'never' },
    calls: 0,
    request() {
      approval.calls += 1
      throw new Error('approval.request must not run when the policy is never')
    },
  }
  return approval
}

const NEVER_POLICY = { askTimeoutMs: 120000, alwaysAsk: true }

test('policy never + alwaysAsk asks once through the question channel and grants one invocation', async () => {
  const askLog = []
  const approval = neverApproval()
  const userQuestions = questionService(id => ({ answers: [{ id: 'guardrails-confirm', selected: ['Allow once'] }] }), askLog)
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  // A realistic block: the adapter lifts the same Scope line into the Chinese summary.
  const deps = fakeDeps({
    verdict: CONFIRM,
    policy: NEVER_POLICY,
    renderDecision: verdict => `[GUARDRAILS] ${String(verdict.kind).toUpperCase()} ${verdict.ruleId}\nWhy:     x\nTrigger: y\nEffect:  z\nScope:   non-exempt entries: 1; entries: ./build; directories: ./build; roots: ./build\nNext:    n`,
  })
  installGate(ctx, deps)
  const listener = preExecuteOf(state)

  const first = execution({ name: 'bash', args: { command: 'rm -rf ./build' } })
  const decision = await listener(first, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'allow')
  assert.equal(approval.calls, 0, 'the approval seam is bypassed under the never policy')
  assert.equal(askLog.length, 1, 'exactly one question request per invocation')
  const request = askLog[0]
  assert.equal(request.questions.length, 1)
  const question = request.questions[0]
  assert.equal(question.id, 'guardrails-confirm')
  assert.equal(question.intent.kind, 'approval')
  assert.equal(question.intent.approve, 'Allow once')
  assert.equal(question.intent.reject, 'Reject')
  assert.ok(typeof question.detail === 'string' && question.detail.length > 0, 'detail is the rendered block')
  assert.deepEqual(question.options.map(option => option.label), ['Allow once', 'Reject'])
  assert.equal(question.multiSelect, undefined)
  assert.equal(request.wait, undefined)
  assert.equal(request.agent, first.agent)
  // Bilingual single-paragraph display for the shared approval card.
  const display = question.intent.display
  assert.deepEqual(display.question, { en: 'Allow this operation once?', zh: '是否允许本次操作？（仅本次）' })
  assert.match(display.detail.en, /^Confirmation needed \(this call only\): it will delete 1 entry \(rule data\.delete\.bulk\)/)
  assert.ok(typeof display.detail.zh === 'string' && display.detail.zh.length > 0)
  assert.ok(display.detail.zh.includes('需要你确认（仅本次）'))
  assert.ok(display.detail.zh.includes('将删除 1 个条目'))
  assert.ok(display.detail.zh.includes('规则 data.delete.bulk'))
  assert.match(display.detail.zh, /目标：\.\/build/)
  assert.ok(display.detail.zh.includes('批准只对本次调用有效'))
  assert.doesNotMatch(display.detail.zh, /非豁免/, 'no internal jargon')
  assert.doesNotMatch(display.detail.zh, /范围：/, 'no internal 范围 label anymore')
  assert.doesNotMatch(display.detail.zh, /\n/, 'the card detail is a single paragraph')
  // The top-level fallback detail is the same single-paragraph English text.
  assert.equal(question.detail, display.detail.en)
  assert.doesNotMatch(question.detail, /\n/)
  assert.deepEqual(display.approve, { en: 'Allow once', zh: '允许一次' })

  // The grant is one-time for that exact call: a new identical invocation re-asks.
  const second = execution({ name: 'bash', args: { command: 'rm -rf ./build' } })
  const again = await listener(second, async () => ({ kind: 'allow' }))
  assert.equal(again.kind, 'allow')
  assert.equal(askLog.length, 2, 'a fresh invocation asks again')
})

const SCOPED_RENDER = verdict => `[GUARDRAILS] ${String(verdict.kind).toUpperCase()} ${verdict.ruleId}\nWhy:     x\nTrigger: y\nEffect:  z\nScope:   non-exempt entries: 1; entries: ./build; directories: ./build; roots: ./build\nNext:    n`

/** Run one confirmed question-channel ask and return the card display object. */
async function questionDisplayFor(scope, ruleId = 'data.delete.bulk') {
  const askLog = []
  const approval = neverApproval()
  const userQuestions = questionService(() => ({ answers: [{ id: 'guardrails-confirm', selected: ['Allow once'] }] }), askLog)
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const deps = fakeDeps({
    verdict: { kind: 'confirm', ruleId, scope },
    policy: NEVER_POLICY,
    renderDecision: verdict => `[GUARDRAILS] CONFIRM ${verdict.ruleId}`,
  })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'x' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'allow')
  return askLog[0].questions[0].intent.display
}

test('a confirmed question-channel allow injects one structured post-execute notice (consumed once)', async () => {
  const approval = neverApproval()
  const userQuestions = questionService(() => ({ answers: [{ id: 'guardrails-confirm', selected: ['Allow once'] }] }))
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const deps = fakeDeps({ verdict: CONFIRM, policy: NEVER_POLICY, renderDecision: SCOPED_RENDER })
  installGate(ctx, deps)
  const exec = execution({ name: 'bash', args: { command: 'rm -rf ./build' } })
  const decision = await preExecuteOf(state)(exec, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'allow')
  const post = postExecuteOf(state)
  let nextCalls = 0
  const merged = await post(exec, { isError: false, content: [] }, async () => { nextCalls += 1; return { kind: 'accept' } })
  assert.equal(nextCalls, 1, 'the downstream decision must be awaited first')
  assert.ok(Array.isArray(merged.additionalContexts) && merged.additionalContexts.length === 1)
  const notice = merged.additionalContexts[0]
  assert.equal(notice.role, 'user')
  assert.equal(notice.source.kind, 'dsh-guardrails')
  assert.equal(notice.source.form, 'notice')
  assert.equal(notice.source.summary, 'Guardrails confirmation (data.delete.bulk)')
  assert.equal(typeof notice.id, 'string')
  const text = notice.content[0].text
  assert.match(text, /^\[Guardrails\] Approved once for this call; this approval is not reusable\./)
  for (const marker of [
    'rule=data.delete.bulk',
    'confirmed_by=answerer',
    'channel=question-card',
    'this_call_only=yes',
  ]) {
    assert.ok(text.includes(marker), `notice must contain ${marker}: ${text}`)
  }
  // The scope is the human single-paragraph summary, never the internal scope string.
  assert.match(text, /scope=Confirmation needed \(this call only\)/, `notice scope must be human: ${text}`)
  assert.match(text, /Targets:/, text)
  assert.doesNotMatch(text, /non-exempt entries:/, 'internal scope fields must not leak')
  assert.doesNotMatch(text, /scope=\s*(\n|$)/, 'scope must not be empty')
  // The record is consumed: a second post-execute for the same exec injects nothing.
  const againPost = await post(exec, { isError: false, content: [] }, async () => ({ kind: 'accept' }))
  assert.equal(againPost.additionalContexts, undefined)
})

test('a confirmed approval-channel allow records channel=approval-card in the notice', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval: approvalService(['allowed-once']) } })
  const deps = fakeDeps({ verdict: CONFIRM, renderDecision: SCOPED_RENDER })
  installGate(ctx, deps)
  const exec = execution({ name: 'bash', args: { command: 'rm -rf ./build' } })
  const decision = await preExecuteOf(state)(exec, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'allow')
  const merged = await postExecuteOf(state)(exec, { isError: false, content: [] }, async () => ({ kind: 'accept' }))
  const text = merged.additionalContexts?.[0]?.content?.[0]?.text ?? ''
  assert.match(text, /^\[Guardrails\] Approved once for this call; this approval is not reusable\./)
  assert.ok(text.includes('confirmed_by=answerer'), text)
  assert.ok(text.includes('channel=approval-card'), text)
  assert.ok(text.includes('this_call_only=yes'), text)
  assert.match(text, /scope=Confirmation needed \(this call only\)/, text)
  assert.doesNotMatch(text, /non-exempt entries:/, text)
  assert.doesNotMatch(text, /policy=/, text)
})

test('an explicit string verdict scope is used directly for the question detail', async () => {
  const askLog = []
  const approval = neverApproval()
  const userQuestions = questionService(() => ({ answers: [{ id: 'guardrails-confirm', selected: ['Allow once'] }] }), askLog)
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const deps = fakeDeps({
    verdict: { kind: 'confirm', ruleId: 'credential.file.read', scope: 'protected files: /a/.env (read-content)' },
    policy: NEVER_POLICY,
    // No Scope line in the rendered block: the explicit string scope must win.
    renderDecision: verdict => `[GUARDRAILS] CONFIRM ${verdict.ruleId}`,
  })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'x' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'allow')
  const display = askLog[0].questions[0].intent.display
  // Non-delete family: human single paragraph, no internal field name.
  assert.match(display.detail.en, /^Confirmation needed \(this call only\)/)
  assert.ok(display.detail.zh.includes('需要你确认（仅本次）'))
  assert.ok(display.detail.zh.includes('受保护文件：/a/.env（读取内容）'))
  assert.ok(display.detail.zh.includes('规则 credential.file.read'))
  assert.ok(display.detail.en.includes('protected files: /a/.env (read)'), 'ACTION_EN maps the action token')
  assert.doesNotMatch(display.detail.zh, /entries|范围：/, 'no internal field names')
  assert.doesNotMatch(display.detail.zh, /\n/, 'single paragraph')
})

test('more than six delete targets collapse to a count instead of dumping every path', async () => {
  const askLog = []
  const approval = neverApproval()
  const userQuestions = questionService(() => ({ answers: [{ id: 'guardrails-confirm', selected: ['Allow once'] }] }), askLog)
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const scope = 'non-exempt entries: 9; entries: /t/1; /t/2; /t/3; /t/4; /t/5; /t/6; /t/7; /t/8'
  const deps = fakeDeps({
    verdict: { kind: 'confirm', ruleId: 'data.delete.bulk', scope },
    policy: NEVER_POLICY,
    renderDecision: verdict => `[GUARDRAILS] CONFIRM ${verdict.ruleId}`,
  })
  installGate(ctx, deps)
  assert.equal((await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'x' } }), async () => ({ kind: 'allow' }))).kind, 'allow')
  const zh = askLog[0].questions[0].intent.display.detail.zh
  assert.match(zh, /等共 9 项/)
  assert.ok(zh.includes('/t/1'), zh)
  assert.ok(!zh.includes('/t/7'), 'paths beyond the first six are represented by the count')
})

test('roots that repeat directories are not shown twice', async () => {
  const askLog = []
  const approval = neverApproval()
  const userQuestions = questionService(() => ({ answers: [{ id: 'guardrails-confirm', selected: ['Allow once'] }] }), askLog)
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const scope = 'non-exempt entries: 1; entries: /target/file.txt; directories: /dirroot; roots: /dirroot'
  const deps = fakeDeps({
    verdict: { kind: 'confirm', ruleId: 'data.delete.bulk', scope },
    policy: NEVER_POLICY,
    renderDecision: verdict => `[GUARDRAILS] CONFIRM ${verdict.ruleId}`,
  })
  installGate(ctx, deps)
  assert.equal((await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'x' } }), async () => ({ kind: 'allow' }))).kind, 'allow')
  const zh = askLog[0].questions[0].intent.display.detail.zh
  assert.match(zh, /目标：\/target\/file\.txt/)
  assert.equal((zh.match(/\/dirroot/g) ?? []).length, 1, `directory shown once: ${zh}`)
})

test('the delete preview is human: no jargon, redundant Git flag omitted', async () => {
  const scope = 'non-exempt entries: 1; entries: C:\\guardrails\\a.txt; directories: C:\\guardrails\\guardrails-live-fixture; roots: C:\\guardrails\\guardrails-live-fixture; unobserved: git metadata (.git) at C:\\guardrails\\.git would also be destroyed; git-metadata-inside-tree'
  const display = await questionDisplayFor(scope)
  assert.equal(display.detail.zh,
    '需要你确认（仅本次）：将删除 1 个条目（规则 data.delete.bulk）。目标：C:\\guardrails\\a.txt；涉及目录：C:\\guardrails\\guardrails-live-fixture；另将销毁：.git 元数据（C:\\guardrails\\.git）。批准只对本次调用有效。')
  assert.equal(display.detail.en,
    'Confirmation needed (this call only): it will delete 1 entry (rule data.delete.bulk). Targets: C:\\guardrails\\a.txt; directories: C:\\guardrails\\guardrails-live-fixture; also destroys: Git metadata (C:\\guardrails\\.git). The approval applies to this call only.')
  assert.doesNotMatch(display.detail.zh, /非豁免/)
  assert.doesNotMatch(display.detail.zh, /git-metadata-inside-tree/, 'the redundant flag is omitted')
})

test('a Git worktree card explains the reason and never says "delete N entries"', async () => {
  const display = await questionDisplayFor('known scope: C:\\git\\wt; notes: merge state / uncommitted changes', 'data.git.worktree')
  assert.ok(display.detail.zh.includes('将移除 Git 工作树（合并状态 / 未提交改动）'), display.detail.zh)
  assert.doesNotMatch(display.detail.zh, /删除/)
  assert.ok(display.detail.en.includes('it will remove a Git worktree (merge state / uncommitted changes)'), display.detail.en)
  assert.doesNotMatch(display.detail.en, /delete \d+ entries/)
})

test('a move card says the original locations will not remain and lists targets', async () => {
  const display = await questionDisplayFor('entries: /src/a; /src/b', 'data.move.source')
  assert.ok(display.detail.zh.includes('将移动这些来源（原位置不再保留）'), display.detail.zh)
  assert.match(display.detail.zh, /目标：\/src\/a、\/src\/b/)
  assert.ok(display.detail.en.includes('it will move these sources (the original locations will not remain).'), display.detail.en)
  assert.ok(display.detail.en.includes('Targets: /src/a, /src/b.'), display.detail.en)
})

test('delete heads avoid stray spaces and handle 若干 / 至少 N', async () => {
  const unknownCount = await questionDisplayFor('entries: /a')
  assert.ok(unknownCount.detail.zh.includes('将删除若干条目'), unknownCount.detail.zh)
  assert.doesNotMatch(unknownCount.detail.zh, /将删除\s+若干/)
  assert.ok(unknownCount.detail.en.includes('delete some entries'), unknownCount.detail.en)
  const atLeast = await questionDisplayFor('non-exempt entries: at least 21 (threshold exceeded); entries: /a')
  assert.ok(atLeast.detail.zh.includes('将删除至少 21 个条目'), atLeast.detail.zh)
  assert.ok(atLeast.detail.en.includes('delete at least 21 entries'), atLeast.detail.en)
})

test('scope notes are rendered: known notes translated, unknown notes marked as original', async () => {
  const display = await questionDisplayFor('non-exempt entries: 1; entries: /a; notes: stdin stream; merge state / uncommitted changes; custom-note-x')
  assert.ok(display.detail.zh.includes('说明：标准输入流；合并状态 / 未提交改动'), display.detail.zh)
  assert.ok(display.detail.zh.includes('说明（原文）：custom-note-x'), display.detail.zh)
  assert.ok(display.detail.en.includes('Note: stdin stream; merge state / uncommitted changes; custom-note-x'), display.detail.en)
})

test('a known multi-clause note is not split into two English fragments', async () => {
  const display = await questionDisplayFor('non-exempt entries: 1; entries: /a; notes: unresolved dynamic operand; credential name referenced in text')
  assert.ok(display.detail.zh.includes('说明：动态操作数无法解析；文本中出现凭据名'), display.detail.zh)
  assert.doesNotMatch(display.detail.zh, /unresolved dynamic operand/)
})

test('a compound note followed by another note is matched greedily, not shredded', async () => {
  const display = await questionDisplayFor('non-exempt entries: 1; entries: /a; notes: unresolved dynamic operand; credential name referenced in text; stdin stream')
  assert.ok(display.detail.zh.includes('说明：动态操作数无法解析；文本中出现凭据名；标准输入流'), display.detail.zh)
  assert.doesNotMatch(display.detail.zh, /unresolved dynamic operand|credential name referenced/, display.detail.zh)
})

test('the renderList ellipsis is not counted as an item; the real count is used', async () => {
  const display = await questionDisplayFor('non-exempt entries: 21; entries: a; b; …')
  assert.ok(display.detail.zh.includes('等共 21 项'), display.detail.zh)
  assert.ok(display.detail.zh.includes('将删除 21 个条目'), display.detail.zh)
  assert.ok(!display.detail.zh.includes('…'), display.detail.zh)
  assert.doesNotMatch(display.detail.zh, /9/, display.detail.zh)
  assert.ok(display.detail.en.includes('and 21 total'), display.detail.en)
  assert.ok(!display.detail.en.includes('…'), display.detail.en)
})

test('the delete card lists the non-enumerable part instead of dropping it (H2)', async () => {
  const display = await questionDisplayFor('entries: a; unknown: unresolved-target; unobserved: pattern * under C:\\ws')
  assert.ok(display.detail.zh.includes('另含无法枚举的部分'), display.detail.zh)
  assert.ok(display.detail.zh.includes('pattern * under'), display.detail.zh)
  assert.ok(display.detail.zh.includes('原文：unresolved-target'), display.detail.zh)
  assert.ok(display.detail.en.includes('Not enumerable:'), display.detail.en)
  assert.ok(display.detail.en.includes('pattern * under'), display.detail.en)
})

test('Windows drive paths stay in the list and are never read as keys (H1)', async () => {
  const deleteCard = await questionDisplayFor('non-exempt entries: 3; entries: C:\\ws\\a.txt; C:\\ws\\b.txt; C:\\ws\\c.txt')
  assert.ok(deleteCard.detail.zh.includes('将删除 3 个条目'), deleteCard.detail.zh)
  for (const path of ['C:\\ws\\a.txt', 'C:\\ws\\b.txt', 'C:\\ws\\c.txt']) {
    assert.ok(deleteCard.detail.zh.includes(path), `missing ${path}: ${deleteCard.detail.zh}`)
  }

  const moveCard = await questionDisplayFor('known scope: E:/s/a; E:/s/b; E:/s/c', 'data.move.source')
  for (const path of ['E:/s/a', 'E:/s/b', 'E:/s/c']) {
    assert.ok(moveCard.detail.zh.includes(path), `missing ${path}: ${moveCard.detail.zh}`)
  }

  const protectedCard = await questionDisplayFor('protected files: C:\\ws\\.env; C:\\ws\\id_rsa', 'credential.file.read')
  assert.ok(protectedCard.detail.zh.includes('受保护文件：'), protectedCard.detail.zh)
  for (const path of ['C:\\ws\\.env', 'C:\\ws\\id_rsa']) {
    assert.ok(protectedCard.detail.zh.includes(path), `missing ${path}: ${protectedCard.detail.zh}`)
  }
  assert.doesNotMatch(protectedCard.detail.zh, /C：/, 'a drive letter must not become a pseudo label')

  const mixed = await questionDisplayFor('entries: /posix/a; C:\\ws\\b; /posix/c')
  for (const path of ['/posix/a', 'C:\\ws\\b', '/posix/c']) {
    assert.ok(mixed.detail.zh.includes(path), `missing ${path}: ${mixed.detail.zh}`)
  }
})

test('move and worktree cards disclose the entry count and directory scope', async () => {
  const worktree = await questionDisplayFor('non-exempt entries: 5; known scope: /wt; directories: /dirroot; roots: /dirroot; notes: merge state / uncommitted changes', 'data.git.worktree')
  assert.ok(worktree.detail.zh.includes('涉及 5 个条目'), worktree.detail.zh)
  assert.equal((worktree.detail.zh.match(/\/dirroot/g) ?? []).length, 1, worktree.detail.zh)
  assert.ok(worktree.detail.en.includes('affecting 5 entries'), worktree.detail.en)
  assert.ok(worktree.detail.en.includes('directories: /dirroot'), worktree.detail.en)

  const move = await questionDisplayFor('non-exempt entries: at least 21; entries: /s/a; /s/b', 'data.move.source')
  assert.ok(move.detail.zh.includes('涉及 至少 21 个条目'), move.detail.zh)
  assert.ok(move.detail.en.includes('affecting at least 21 entries'), move.detail.en)
})

test('the Git metadata flag is shown in human words when no destruction note exists', async () => {
  const display = await questionDisplayFor('non-exempt entries: 2; entries: /a; /b; unobserved: git-metadata-inside-tree')
  assert.match(display.detail.zh, /范围内含 Git 元数据/)
  assert.match(display.detail.en, /also includes Git metadata/)
  assert.doesNotMatch(display.detail.zh, /git-metadata-inside-tree/)
  assert.doesNotMatch(display.detail.zh, /另将销毁/, 'no destruction note to claim')
})

test('an unknown unobserved token is shown as original wording and stays in the reason (H2)', async () => {
  const scope = 'non-exempt entries: 1; entries: /a; unobserved: custom-flag-x'
  const log = []
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval: approvalService(['allowed-once'], log) } })
  const deps = fakeDeps({
    verdict: { kind: 'confirm', ruleId: 'data.delete.bulk', scope },
    renderDecision: verdict => `[GUARDRAILS] CONFIRM ${verdict.ruleId}\nScope:   ${verdict.scope}\nNext:    n`,
  })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'x' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'allow')
  const request = log[0]
  assert.ok(request.displayReason, 'the card gets a localized summary')
  // H2: unenumerable content is disclosed, unknown tokens marked as original wording.
  assert.ok(request.displayReason.zh.includes('另含无法枚举的部分'), request.displayReason.zh)
  assert.ok(request.displayReason.zh.includes('原文：custom-flag-x'), request.displayReason.zh)
  assert.doesNotMatch(request.displayReason.zh, /其他标记/)
  assert.ok(request.reason.includes('custom-flag-x'), 'the audit reason keeps the raw scope')
})

test('the approval channel receives a localized single-paragraph displayReason', async () => {
  const log = []
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval: approvalService(['allowed-once'], log) } })
  const deps = fakeDeps({ verdict: CONFIRM, renderDecision: SCOPED_RENDER })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'allow')
  const request = log[0]
  assert.ok(request.displayReason)
  assert.ok(typeof request.displayReason.en === 'string' && request.displayReason.en.length > 0)
  assert.ok(typeof request.displayReason.zh === 'string' && request.displayReason.zh.length > 0)
  assert.doesNotMatch(request.displayReason.en, /\n/)
  assert.doesNotMatch(request.displayReason.zh, /\n/)
  assert.ok(request.displayReason.zh.includes('需要你确认'))
  assert.match(request.displayReason.en, /^Confirmation needed \(this call only\)/)
  // reason stays the audit/model-facing multi-line fixed block.
  assert.match(request.reason, /\[GUARDRAILS\] CONFIRM/)
  assert.match(request.reason, /\n/)
})

test('a missing confirmInfo yields no displayReason and never throws', () => {
  for (const value of [undefined, null, {}, { ruleIds: 'x', scopeText: '' }, { ruleIds: [], scopeText: 42 }]) {
    assert.equal(displayReasonOf(value), undefined)
  }
  assert.equal(displayReasonOf({ ruleIds: [], scopeText: '' })?.en !== undefined, true)
})

test('an unparseable scope falls back to the raw text without undefined', async () => {
  const askLog = []
  const approval = neverApproval()
  const userQuestions = questionService(() => ({ answers: [{ id: 'guardrails-confirm', selected: ['Allow once'] }] }), askLog)
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const deps = fakeDeps({
    verdict: { kind: 'confirm', ruleId: 'credential.file.read', scope: '@@not a scope@@' },
    policy: NEVER_POLICY,
    renderDecision: verdict => `[GUARDRAILS] CONFIRM ${verdict.ruleId}`,
  })
  installGate(ctx, deps)
  assert.equal((await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'x' } }), async () => ({ kind: 'allow' }))).kind, 'allow')
  const zh = askLog[0].questions[0].intent.display.detail.zh
  assert.ok(typeof zh === 'string' && zh.length > 0)
  assert.ok(!zh.includes('undefined'), zh)
  assert.ok(zh.includes('@@not a scope@@'), zh)
})

test('a downstream block decision receives no confirmation notice', async () => {
  const approval = neverApproval()
  const userQuestions = questionService(() => ({ answers: [{ id: 'guardrails-confirm', selected: ['Allow once'] }] }))
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const deps = fakeDeps({ verdict: CONFIRM, policy: NEVER_POLICY, renderDecision: SCOPED_RENDER })
  installGate(ctx, deps)
  const exec = execution({ name: 'bash', args: { command: 'rm -rf ./build' } })
  assert.equal((await preExecuteOf(state)(exec, async () => ({ kind: 'allow' }))).kind, 'allow')
  const blocked = { kind: 'block', feedback: [{ type: 'text', text: 'blocked downstream' }] }
  const merged = await postExecuteOf(state)(exec, { isError: false, content: [] }, async () => blocked)
  assert.equal(merged, blocked, 'the block decision passes through unchanged')
  assert.equal(merged.additionalContexts, undefined)
})

test('an ordinary allow without a confirmation injects no post-execute notice', async () => {
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL })
  const deps = fakeDeps({ verdict: { kind: 'allow' } })
  installGate(ctx, deps)
  const exec = execution({ name: 'bash', args: { command: 'Get-Location' } })
  const decision = await preExecuteOf(state)(exec, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'allow')
  const merged = await postExecuteOf(state)(exec, { isError: false, content: [] }, async () => ({ kind: 'accept' }))
  assert.equal(merged.additionalContexts, undefined)
})

test('a denied confirmation never leaves a post-execute notice behind', async () => {
  const approval = neverApproval()
  const userQuestions = questionService(() => ({ answers: [{ id: 'guardrails-confirm', selected: ['Reject'] }] }))
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const deps = fakeDeps({ verdict: CONFIRM, policy: NEVER_POLICY, renderDecision: SCOPED_RENDER })
  installGate(ctx, deps)
  const exec = execution({ name: 'bash', args: { command: 'rm -rf ./build' } })
  const decision = await preExecuteOf(state)(exec, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  const merged = await postExecuteOf(state)(exec, { isError: true, content: [] }, async () => ({ kind: 'accept' }))
  assert.equal(merged.additionalContexts, undefined)
})

test('policy never + alwaysAsk:true without a question provider refuses with APPROVAL_UNAVAILABLE', async () => {
  const approval = neverApproval()
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval } })
  const deps = fakeDeps({ verdict: CONFIRM, policy: NEVER_POLICY })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /APPROVAL_UNAVAILABLE: No confirmation UI is available/)
  assert.doesNotMatch(decision.reason, /APPROVAL_POLICY_NEVER/)
  assert.doesNotMatch(decision.reason, /The user rejected/, 'a silent refusal must never be reported as a user rejection')
  assert.equal(approval.calls, 0)
})

test('policy never + alwaysAsk:false refuses without touching the question channel', async () => {
  const askLog = []
  const approval = neverApproval()
  const userQuestions = questionService(() => ({ answers: [{ id: 'guardrails-confirm', selected: ['Allow once'] }] }), askLog)
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const deps = fakeDeps({ verdict: CONFIRM, policy: { askTimeoutMs: 120000, alwaysAsk: false } })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /APPROVAL_POLICY_NEVER/)
  assert.equal(askLog.length, 0, 'the question channel is never asked when alwaysAsk is false')
  assert.equal(approval.calls, 0)
})

test('policy ask + approval seam rejected stays APPROVAL_REJECTED and never asks questions', async () => {
  const askLog = []
  const approval = { config: { policy: 'ask' }, calls: 0, request() { approval.calls += 1; return Promise.resolve('rejected') } }
  const userQuestions = questionService(() => ({ answers: [{ id: 'guardrails-confirm', selected: ['Allow once'] }] }), askLog)
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const deps = fakeDeps({ verdict: CONFIRM, policy: NEVER_POLICY })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /APPROVAL_REJECTED/)
  assert.match(decision.reason, /The user rejected/)
  assert.match(decision.reason, /ask the user which alternative they prefer \(a narrower scope, or a manual run\)/)
  assert.equal(approval.calls, 1)
  assert.equal(askLog.length, 0)
})

test('cancelled and failed denials each carry an actionable alternative', async () => {
  for (const [outcome, pattern] of [
    ['cancelled', /Re-issue it when it is still needed/],
    ['mysterious', /run the operation manually or ask the user to confirm from another session/],
  ]) {
    const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval: approvalService([outcome]) } })
    installGate(ctx, fakeDeps({ verdict: CONFIRM }))
    const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
    assert.equal(decision.kind, 'deny', outcome)
    assert.match(decision.reason, pattern, outcome)
  }
})

test('question channel DELEGATED_CALLER maps to APPROVAL_DELEGATED', async () => {
  const delegated = Object.assign(new Error('delegated'), { code: 'DELEGATED_CALLER' })
  const approval = neverApproval()
  const userQuestions = questionService(() => { throw delegated })
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const deps = fakeDeps({ verdict: CONFIRM, policy: NEVER_POLICY })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /APPROVAL_DELEGATED/)
})

test('question channel NO_PROVIDER maps to APPROVAL_UNAVAILABLE', async () => {
  const noProvider = Object.assign(new Error('no provider'), { code: 'NO_PROVIDER' })
  const approval = neverApproval()
  const userQuestions = questionService(() => { throw noProvider })
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const deps = fakeDeps({ verdict: CONFIRM, policy: NEVER_POLICY })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /APPROVAL_UNAVAILABLE: No confirmation UI is available/)
  assert.doesNotMatch(decision.reason, /The user rejected/)
})

test('question channel CALLER_NOT_LIVE maps to APPROVAL_UNAVAILABLE', async () => {
  const notLive = Object.assign(new Error('not live'), { code: 'CALLER_NOT_LIVE' })
  const approval = neverApproval()
  const userQuestions = questionService(() => { throw notLive })
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const deps = fakeDeps({ verdict: CONFIRM, policy: NEVER_POLICY })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /APPROVAL_UNAVAILABLE: No confirmation UI is available/)
})

test('an answer item with a non-matching id is never read as a grant', async () => {
  const approval = neverApproval()
  // A single question id is 'guardrails-confirm'; an answer for another id must not grant.
  const userQuestions = questionService(() => ({ answers: [{ id: 'other', selected: ['Allow once'] }] }))
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const deps = fakeDeps({ verdict: CONFIRM, policy: NEVER_POLICY })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /APPROVAL_REJECTED/)
})

test('question channel ASK_ABORTED maps to APPROVAL_CANCELLED', async () => {
  const aborted = Object.assign(new Error('aborted'), { code: 'ASK_ABORTED' })
  const approval = neverApproval()
  const userQuestions = questionService(() => { throw aborted })
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const deps = fakeDeps({ verdict: CONFIRM, policy: NEVER_POLICY })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /APPROVAL_CANCELLED/)
})

test('a question-channel Reject answer is a real APPROVAL_REJECTED', async () => {
  const approval = neverApproval()
  const userQuestions = questionService(() => ({ answers: [{ id: 'guardrails-confirm', selected: ['Reject'] }] }))
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const deps = fakeDeps({ verdict: CONFIRM, policy: NEVER_POLICY })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /APPROVAL_REJECTED/)
  assert.match(decision.reason, /The user rejected/)
})

test('a question-channel wait that never answers times out as APPROVAL_TIMEOUT', async () => {
  const approval = neverApproval()
  const userQuestions = questionService(() => new Promise(() => {}))
  const { ctx, state } = fakeCtx({ definitions: ALL_OFFICIAL, services: { approval, userQuestions } })
  const deps = fakeDeps({ verdict: CONFIRM, policy: { askTimeoutMs: 20, alwaysAsk: true } })
  installGate(ctx, deps)
  const decision = await preExecuteOf(state)(execution({ name: 'bash', args: { command: 'rm -rf ./build' } }), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /APPROVAL_TIMEOUT/)
})

