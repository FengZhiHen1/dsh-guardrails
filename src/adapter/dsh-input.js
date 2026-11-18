// dsh-input — front-door classification: map one official ToolExecution to an
// analysis unit (inline source) or a structured target analysis, per the
// architecture contract (架构重构设计「前门分类」, DSR-022, DSR-026).
//
// Verified official facts this file relies on (DSH 0.2.2-rc.2, Inspect + source):
//   ToolExecution { callId, rootCallId, name, schema?, arguments, agent?, toolSet?, parent?, signal }
//     — `agent` is the scope; `parent` marks a PTC sub-dispatch; arguments are deep-frozen.
//   Definition selection: ctx.tools.executable(name, execution.agent, execution.toolSet) —
//     scoped registrations shadow globals and the step admission applies, so the
//     executable definition decides existence, never the name alone.
//   pwsh / bash args: { command, description, workdir?, ... } (fresh process; the official
//     default directory is the session workspace).
//   terminal_send args: { sessionId, text, ... }; terminals.list(owner) snapshots carry the
//     authoritative backend `type` of the target session. No contract states the
//     terminal's shell dialect or directory: the unit carries NO cwd/platform
//     assumption, and only the snapshot type when found (optional metadata).
//   run_code args: { code, description, ... }; the program starts in the Session's
//     current directory; its language is ctx.ptcRuntime.language.
//   fs tools: read/read_image(file_path), write(file_path), edit(file_path),
//     apply_patch(input) — patch paths are relative to the Session working directory and
//     parse via the official Codex-style parser (@deepseek-ai/dsh-fs-patch parsePatch).
//   web_fetch args: { url } — standalone HTTP face; only real official params are scanned.
//
// Structured file tools never go through the shell/program analyzer (架构「前门分类」).
// This module synthesizes the same analysis shape the analyzer members return:
//   { status: 'complete'|'partial'|'fault', operations, candidates, gaps, inlineCredential? }
// Operations carry raw targets only:
//   { action, context:{domain:'fs',cwd?}, target:{kind:'exact',paths:[fsTarget]},
//     recursive, preview, condition, origin }
// The evidence adapter resolves each path via ctx.fs.resolve against the SAME
// context.cwd recorded here, and observes it with ctx.fs.stat (evidence peer).
//
// Statuses are honest, not comforting: 'complete' when every target is
// enumerated with an authoritative base directory; 'partial' when a real
// assumption is missing (unknown target base) — never fabricated; 'fault' when
// analysis could not enumerate at all (patch parse unavailable/failed), which
// routes through the unified failure semantics in the decision point.

/** Official one-shot shell tools: tool name → command dialect/language. */
const SHELL_TOOLS = new Map([
  ['pwsh', 'powershell'],
  ['bash', 'bash'],
])

/** Structured file tools whose explicit target arguments this module models. */
const STRUCTURED_TARGET_TOOLS = new Set(['read', 'read_image', 'write', 'edit', 'apply_patch'])

/** The one argument each classified official tool must declare as required. */
const EXPECTED_PARAM = new Map([
  ['pwsh', 'command'],
  ['bash', 'command'],
  ['terminal_send', 'text'],
  ['read', 'file_path'],
  ['read_image', 'file_path'],
  ['write', 'file_path'],
  ['edit', 'file_path'],
  ['apply_patch', 'input'],
  ['web_fetch', 'url'],
])

/** The reserved model-facing program transport (dsh-tools RUN_CODE_NAME). */
const RUN_CODE = 'run_code'

/**
 * Resolve the executable tool definition the dispatcher will actually use for
 * this execution, including scoped shadows and the step's admission set.
 * NOTE: `run_code` is a reserved transport, never a registration —
 * ctx.tools.executable returns undefined for it, so callers special-case it.
 * @returns {object|undefined} the definition, or undefined when the name is
 *   not executable here (the dispatcher then fails as UNKNOWN_TOOL).
 */
export function resolveDefinition(ctx, execution) {
  return ctx.tools.executable(execution.name, execution.agent, execution.toolSet)
}

/** Whether a PTC runtime is actually mounted for this context (run_code's carrier). */
function ptcRuntimeActive(ctx) {
  const runtime = ctx.get('ptcRuntime')
  return Boolean(runtime && typeof runtime === 'object'
    && typeof runtime.language === 'string' && runtime.language.length > 0)
}

/** The declared parameter map of a ToolSchema/ToolDefinition, when inspectable. */
function declaredParams(source) {
  const params = source?.parameters
  return params && typeof params === 'object' && !Array.isArray(params) ? params : undefined
}

/**
 * Whether the source declares the expected argument. When the declaration is
 * not inspectable the answer is "cannot confirm" (true) and the argument
 * validation in planExecution stays authoritative; when it IS inspectable and
 * the expected key is missing, the registration does not have the official
 * shape and must not be classified by name alone.
 */
function declaresParam(source, key) {
  const params = declaredParams(source)
  return params === undefined || Object.hasOwn(params, key)
}

/**
 * The classified definition for one execution, applying every check the
 * official contract allows: existence (or the reserved PTC transport), a real
 * `execute` body, and the declared required parameter on the definition and on
 * the binding-time schema. A name match on an arbitrary scoped registration
 * with a different shape does NOT classify.
 */
function definitionFor(ctx, execution) {
  if (!execution || typeof execution.name !== 'string') return undefined
  const name = execution.name
  if (name === RUN_CODE) {
    // Reserved transport: no registration exists; require the active runtime.
    return ptcRuntimeActive(ctx) ? { name: RUN_CODE, reserved: true } : undefined
  }
  const definition = resolveDefinition(ctx, execution)
  if (definition === undefined) return undefined
  if (typeof definition.execute !== 'function') return undefined
  const expected = EXPECTED_PARAM.get(name)
  if (expected !== undefined) {
    if (!declaresParam(definition, expected)) return undefined
    if (execution.schema !== undefined && !declaresParam(execution.schema, expected)) return undefined
  }
  return definition
}

/** The faces this gate analyzes end to end; membership is the first filter. */
const ANALYZED_FACES = new Set([
  ...SHELL_TOOLS.keys(),
  'terminal_send',
  RUN_CODE,
  'web_fetch',
  ...STRUCTURED_TARGET_TOOLS,
])

/**
 * Sync front-door predicate used by both hooks. True only for faces this gate
 * analyzes end to end (command execution face + structured file tools + the
 * standalone HTTP credential face) whose definition passes every check the
 * official contract allows. Never performs IO or parsing.
 * @throws when the registry lookup itself fails (bounded fault upstream).
 */
export function requiresAnalysis(ctx, execution) {
  if (!execution || typeof execution.name !== 'string') return false
  if (!ANALYZED_FACES.has(execution.name)) return false
  return definitionFor(ctx, execution) !== undefined
}

/**
 * The actual session working directory (committed), the authoritative base for
 * relative targets. When no authoritative directory is available this returns
 * undefined — the caller records the target base as unknown instead of
 * substituting an unproven process cwd.
 */
export function sessionCwd(ctx, execution) {
  const session = execution?.agent?.session
  const directories = ctx.get('workingDirectory')
  if (session && directories && typeof directories.get === 'function') {
    const cwd = directories.get(session)
    if (typeof cwd === 'string' && cwd.length > 0) return cwd
  }
  return session?.header?.cwd
}

/**
 * Sandbox-confined workspace root, resolved per session. A throwing policy is
 * a hard analysis failure and is NOT swallowed: another directory could
 * misattribute relative targets.
 */
export function workspaceRootOf(ctx, execution) {
  const policy = ctx.get('sandboxPolicy')
  if (!policy || typeof policy.resolve !== 'function') return undefined
  const resolved = policy.resolve(execution?.agent?.session ? { session: execution.agent.session } : {})
  return typeof resolved?.workspaceRoot === 'string' ? resolved.workspaceRoot : undefined
}

/**
 * The ONE effective cwd for a shell execution. Only shell tools carry a
 * `workdir` argument; other tools must not be redirected by an unrelated
 * argument. Relative workdir values resolve against the real session cwd, then
 * the official session-workspace default; with neither, the base is unknown
 * and no directory is invented.
 */
export function effectiveCwd(ctx, execution, args) {
  const workdir = SHELL_TOOLS.has(execution.name) &&
    args && typeof args.workdir === 'string' && args.workdir.length > 0
    ? args.workdir : undefined
  const base = sessionCwd(ctx, execution) ?? workspaceRootOf(ctx, execution)
  if (workdir) {
    if (base === undefined || base.length === 0) {
      throw new Error('guardrails: relative workdir has no resolvable base directory')
    }
    if (isAbsolute(workdir)) return workdir
    return resolveRelative(base, workdir)
  }
  return base
}

// Bounded local path helpers: the gate resolves a `workdir` shell argument
// only; every other path stays raw until the evidence adapter's fsProvider.
function isAbsolute(value) {
  return /^[A-Za-z]:[\\/]/.test(value) || value.startsWith('/') || value.startsWith('\\\\')
}

function resolveRelative(base, value) {
  const separator = base.includes('\\') ? '\\' : '/'
  const trimmed = base.endsWith(separator) || base.endsWith('/') ? base : base + separator
  return trimmed + value
}

/**
 * Authoritative terminal metadata for a terminal_send target, when the actual
 * contract provides it. `type` is the backend type that created the session;
 * it names the terminal backend, not a shell dialect, so callers treat it as
 * optional context and fall back to nothing (no assumptions) when absent.
 */
export function terminalSnapshotOf(ctx, execution, args) {
  const terminals = ctx.get('terminals')
  if (!terminals || typeof terminals.list !== 'function') return undefined
  if (!execution?.agent || !args || typeof args.sessionId !== 'string') return undefined
  try {
    const snapshots = terminals.list(execution.agent)
    if (!Array.isArray(snapshots)) return undefined
    return snapshots.find((snapshot) => snapshot?.sessionId === args.sessionId)
  } catch {
    return undefined
  }
}

/** Build one inline-source analysis unit for the shell/program analyzer. */
function inlineUnit({ text, domain, cwd, platform, language, execution, terminal }) {
  return {
    source: { kind: 'inline', text },
    context: {
      domain,
      ...cwd !== undefined ? { cwd } : {},
      ...platform !== undefined ? { platform } : {},
    },
    origin: {
      entry: execution.name,
      callId: execution.callId,
      ...terminal !== undefined ? { terminal } : {},
    },
    ...language !== undefined ? { language } : {},
  }
}

/** One structured target operation; the raw path stays unresolved until evidence. */
function targetOperation({ action, execution, cwd, fsTarget, recursive = false }) {
  return {
    action,
    context: { domain: 'fs', ...cwd !== undefined ? { cwd } : {} },
    target: { kind: 'exact', paths: [fsTarget] },
    recursive,
    preview: false,
    condition: 'unconditional',
    origin: { entry: execution.name, callId: execution.callId },
  }
}

/** The single explicit file target of a structured tool, honoring both spellings. */
function targetOf(args) {
  if (!args || typeof args !== 'object') return undefined
  const target = args.file_path ?? args.path
  return typeof target === 'string' && target.length > 0 ? target : undefined
}

/**
 * High-confidence inline credentials in a standalone HTTP parameter. Only the
 * URL userinfo form (scheme://user:password@host) with a non-empty password
 * qualifies: it is the one spelling that always names a real secret transport.
 * Variable references, placeholders, and query attributes are not judged here.
 */
export function hasInlineHttpCredential(url) {
  if (typeof url !== 'string' || url.length === 0) return false
  const match = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/:@\\\s]+):([^@\\\s]+)@/.exec(url)
  return match !== null && match[1].length > 0 && match[2].length > 0
}

/** Synthesize the analysis shape shared with the analyzer members (structured faces). */
function structuredAnalysis({ status, operations, candidates = [], gaps = [], inlineCredential }) {
  return {
    status,
    operations,
    candidates,
    gaps,
    ...inlineCredential === true ? { inlineCredential: true } : {},
  }
}

/** Non-string command text is a bounded fault, never a guess. */
function invalidUnitFault(code) {
  return {
    kind: 'fault',
    code,
    reason: `${code}: the tool argument carrying command text was not a string; invocation refused.`,
  }
}

/**
 * apply_patch: parse with the injected official-style parser (may be async) and
 * map Codex operations onto target actions. A parse failure or a missing
 * parser is a 'fault' analysis with an explicit unknown candidate, never a
 * silent pass (统一失败语义). Delete File removes one file, nonrecursive; an
 * Update with Move to separates into the source removal and a destination
 * write; every Add/Update content change is a content write.
 */
async function planApplyPatch(ctx, execution, patch, deps) {
  const cwd = sessionCwd(ctx, execution)
  const parsePatch = typeof deps.parsePatch === 'function' ? deps.parsePatch : undefined
  if (parsePatch === undefined) {
    return { kind: 'structured', analysis: structuredAnalysis({
      status: 'fault',
      operations: [],
      candidates: [{ kind: 'unknown', reason: 'patch-parser-unavailable' }],
      gaps: [{ code: 'GUARD_PATCH_PARSE_FAILED' }],
    }) }
  }
  let parsed
  try {
    parsed = await parsePatch(patch)
  } catch {
    parsed = undefined
  }
  if (!Array.isArray(parsed)) {
    return { kind: 'structured', analysis: structuredAnalysis({
      status: 'fault',
      operations: [],
      candidates: [{ kind: 'unknown', reason: 'patch-unparsed' }],
      gaps: [{ code: 'GUARD_PATCH_PARSE_FAILED' }],
    }) }
  }
  const operations = []
  for (const operation of parsed) {
    if (!operation || typeof operation.path !== 'string' || operation.path.length === 0) continue
    if (operation.kind === 'delete') {
      operations.push(targetOperation({
        action: 'delete', execution, cwd, fsTarget: operation.path, recursive: false,
      }))
    } else if (operation.kind === 'update') {
      if (typeof operation.moveTo === 'string' && operation.moveTo.length > 0) {
        operations.push(targetOperation({ action: 'move-source', execution, cwd, fsTarget: operation.path }))
        operations.push(targetOperation({ action: 'write-content', execution, cwd, fsTarget: operation.moveTo }))
      } else {
        operations.push(targetOperation({ action: 'write-content', execution, cwd, fsTarget: operation.path }))
      }
    } else if (operation.kind === 'add') {
      operations.push(targetOperation({ action: 'write-content', execution, cwd, fsTarget: operation.path }))
    }
  }
  return { kind: 'structured', analysis: structuredAnalysis({ status: 'complete', operations }) }
}

async function planStructuredTool(ctx, execution, args, deps) {
  const name = execution.name
  if (name === 'apply_patch') {
    if (typeof args?.input !== 'string') return { kind: 'skip' }
    return planApplyPatch(ctx, execution, args.input, deps)
  }
  const target = targetOf(args)
  if (target === undefined) {
    // A missing/invalid target is the tool's own argument error; there is no
    // target set to protect, so the gate does not fabricate one.
    return { kind: 'skip' }
  }
  const cwd = sessionCwd(ctx, execution)
  if (cwd === undefined) {
    // No authoritative base directory: record the gap honestly instead of
    // substituting an unproven process cwd. The target itself is still exact.
    return { kind: 'structured', analysis: structuredAnalysis({
      status: 'partial',
      operations: [targetOperation({
        action: name === 'read' || name === 'read_image' ? 'read-content' : 'write-content',
        execution,
        cwd: undefined,
        fsTarget: target,
      })],
      gaps: [{ code: 'GUARD_TARGET_BASE_UNKNOWN' }],
    }) }
  }
  return { kind: 'structured', analysis: structuredAnalysis({
    status: 'complete',
    operations: [targetOperation({
      action: name === 'read' || name === 'read_image' ? 'read-content' : 'write-content',
      execution,
      cwd,
      fsTarget: target,
    })],
  }) }
}

/**
 * Classify one execution into the plan the gate runs. Async only because the
 * injected patch parser may be async (it is awaited); all context resolution
 * here is synchronous registry/service reads.
 *
 * @returns {Promise<{kind:'skip'}|{kind:'command',unit}|{kind:'structured',analysis}|{kind:'fault',code,reason}>}
 */
export async function planExecution(ctx, execution, deps = {}) {
  if (!execution || typeof execution.name !== 'string') return { kind: 'skip' }
  // Same classification gate as requiresAnalysis: reserved PTC transport and
  // shape-verified definitions only, so a name match on an arbitrary scoped
  // registration never enters the analysis pipeline.
  if (definitionFor(ctx, execution) === undefined) return { kind: 'skip' }
  const args = execution.arguments
  const name = execution.name

  // Command execution face: shell tools, terminal text, and the PTC program.
  if (SHELL_TOOLS.has(name)) {
    if (typeof args?.command !== 'string') return invalidUnitFault('GUARD_INVALID_SHELL_INPUT')
    let cwd
    try {
      cwd = effectiveCwd(ctx, execution, args)
    } catch {
      return {
        kind: 'fault',
        code: 'GUARD_WORKDIR_UNRESOLVED',
        reason: 'GUARD_WORKDIR_UNRESOLVED: the relative workdir has no resolvable base directory; invocation refused.',
      }
    }
    return { kind: 'command', unit: inlineUnit({
      text: args.command,
      domain: 'host',
      cwd,
      platform: process.platform,
      language: SHELL_TOOLS.get(name),
      execution,
    }) }
  }
  if (name === 'terminal_send') {
    if (typeof args?.text !== 'string') return invalidUnitFault('GUARD_INVALID_SHELL_INPUT')
    // No contract states the terminal's shell dialect or directory: the unit
    // carries no cwd/platform assumption; only the authoritative backend type
    // when the terminals service knows this session.
    const snapshot = terminalSnapshotOf(ctx, execution, args)
    return { kind: 'command', unit: inlineUnit({
      text: args.text,
      domain: 'host',
      execution,
      terminal: snapshot ? { type: snapshot.type } : undefined,
    }) }
  }
  if (name === RUN_CODE) {
    if (typeof args?.code !== 'string') return invalidUnitFault('GUARD_INVALID_SHELL_INPUT')
    // Official contract: each program starts in the Session's current directory.
    return { kind: 'command', unit: inlineUnit({
      text: args.code,
      domain: 'host',
      cwd: sessionCwd(ctx, execution),
      platform: process.platform,
      language: ctx.get('ptcRuntime')?.language,
      execution,
    }) }
  }

  // Standalone HTTP face: credential-inline determination inside the one real
  // official parameter; no deletion analysis (DSR-022 leaves network tools to pass).
  if (name === 'web_fetch') {
    if (typeof args?.url !== 'string') return { kind: 'skip' }
    return { kind: 'structured', analysis: structuredAnalysis({
      status: 'complete',
      operations: [],
      inlineCredential: hasInlineHttpCredential(args.url),
    }) }
  }

  // Structured file tools: explicit target operations, no command parsing.
  if (STRUCTURED_TARGET_TOOLS.has(name)) {
    return planStructuredTool(ctx, execution, args, deps)
  }

  // Everything else — MCP, unknown, orchestration, read-only observation —
  // passes without entering deletion analysis (DSR-022).
  return { kind: 'skip' }
}
