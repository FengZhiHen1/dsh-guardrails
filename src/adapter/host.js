// host — execution-local analysis, bounded approval, and final monotonic guard.
// Official parser failures refuse dispatch; dynamic semantic unknowns stay explicit.
//
// Design stance for an UNRECOGNIZED tool: it is NOT automatically safe. A custom tool
// named e.g. `cleanup_cache` may delete files. This gate therefore classifies tools:
//  1. Read-only framework tools and exact-shape file tools with known semantics
//     (read/read_image/grep/glob) -> analysed/observed, never count as deletion.
//  2. Exact-shape mutators with a known argument contract (write/edit/delete/move/copy) ->
//     analysed structurally: deletes and a move's source removal are counted (L2), while
//     copy leaves the source intact and is allowed.
//  3. Shell tools pwsh/bash -> recursive wrapper analysis + intent + plan gate.
//  4. `run_code` (PTC): denied outright (a JS program's direct runtime side effects
//     cannot be proven free of deletion from its source text; its payload is a program,
//     not a command line whose target set could be enumerated).
//  5. `terminal_send`: the forwarded text IS a command line, so it is analysed in place
//     with the platform dialect (PowerShell on Windows, POSIX shell elsewhere). Text that
//     cannot be analysed is denied; a recognised deletion is counted by the same gate.
//  6. Any other (unknown) tool -> DENIED by default, because its effect cannot be proven
//     free of unexpected deletion. There is no name allowlist that would false-allow a
//     custom destructive tool. A maintainer must add an explicit adapter for a new tool.
//  7. Reviewed framework-coordination tools with NO filesystem-deletion capability pass
//     untouched, including worktree creation, terminal opening and every plugin_manager
//     action (profile management is not a filesystem delete under the catastrophe standard;
//     whatever it launches is a separate guarded execution).
//
// Deletion safety is NOT atomic: the inventory races a concurrent filesystem change and
// a mutation earlier in the same invocation. This gate denies preceding in-command
// mutation (intent layer) and re-checks the inventory after any approval wait; it does
// not claim atomic <=20 execution under concurrent mutation.

import z from '@deepseek-ai/schemastery'
import path from 'node:path'
import { ASK_TIMEOUT_MAX, evaluateRules } from '../core/rules.js'
import { evaluatePolicy, structuredCommands } from '../core/policy.js'
import { observeTargets } from './targets.js'
import { createShellParsers } from './parsers/index.mjs'
import { analyzeShell } from './shell-analysis.mjs'
import { assessCommands, DELETION_DOCTRINE } from '../core/deletion-intent.js'
import { planDeletions } from './deletion-plan.js'
import { requestApproval, DEFAULT_ASK_TIMEOUT_MS } from './approval.js'
import { installRedaction } from './redaction.js'
import { inlineCredentialDecision } from '../core/redaction.js'

/** Live profile settings; zero from legacy configs now selects the bounded default. */
export const Config = z.object({
  sensitiveFiles: z.array(z.string()).default([]).volatile(),
  builtinSensitiveAsk: z.boolean().default(true).volatile(),
  askTimeoutMs: z.number().min(0).max(ASK_TIMEOUT_MAX).default(DEFAULT_ASK_TIMEOUT_MS).volatile(),
})
/** Host plugin identity. */
export const name = 'dsh-guardrails'
/** Required monotonic tool gate. */
export const inject = ['tools']
/** Loader row namespace retained across configuration migration. */
export const SETTINGS_NS = 'guardrails'

function readConfig(config) {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) return config
  return Object.fromEntries(Object.entries(config).map(([key, value]) =>
    [key, value !== null && typeof value === 'object' && typeof value.get === 'function' ? value.get() : value]))
}

/** Shell dialects of the supported shell tools. Both map 1:1 onto official parsers. */
function dialectOf(execution) {
  if (execution.name === 'pwsh') return 'powershell'
  if (execution.name === 'bash') return 'bash'
  return undefined
}

/**
 * The command text and the dialect that must parse it, for any tool whose argument IS a
 * command line. `terminal_send` forwards its `text` into a persistent terminal: on Windows
 * that terminal is PowerShell, elsewhere a POSIX shell. Analysing that text in place is
 * what makes the tool allowable at all — the same intent classifier and count gate then
 * decide it. Unanalysable text (non-string, parser failure, dynamic construct) is denied.
 */
function commandInputOf(execution) {
  if (execution.name === 'pwsh') return { dialect: 'powershell', source: execution.arguments?.command }
  if (execution.name === 'bash') return { dialect: 'bash', source: execution.arguments?.command }
  if (execution.name === 'terminal_send') {
    return { dialect: process.platform === 'win32' ? 'powershell' : 'bash', source: execution.arguments?.text }
  }
  return undefined
}

/** Operations the intent layer can emit for `git`; all are resolved by the plan gate. */
const GIT_ACTIONS = new Set(['git-clean', 'git-restore', 'git-worktree-remove'])

/**
 * True for a bare OS errno code (ENOENT, ENOTDIR, EACCES, …): it only says a named path could
 * not be stat'd. That is expected for a create/write/copy/move-destination that does not
 * exist yet, and a delete of a missing path is a harmless no-op — neither is a catastrophe.
 */
function isBareErrno(entry) {
  return typeof entry === 'string' && /^E[A-Z][A-Z0-9]*$/.test(entry)
}

/**
 * True for the shell-analysis marker emitted when a state-mutating command changed the
 * session so a fixed delete target set is no longer trustworthy. It only has teeth when the
 * same invocation actually deletes; with no delete it harms nothing to gate.
 */
function isStateChangingUnknown(entry) {
  return typeof entry === 'string' && /^State-changing command\b.*invalidates a fixed target set/.test(entry)
}

/** Read-only file tools with known, non-destructive argument semantics. */
const READ_FILE_TOOLS = new Set(['read', 'read_image', 'grep', 'glob'])
/** Mutating file tools with a known, explicit single-target argument contract. */
const MUTATE_FILE_TOOLS = new Set(['write', 'edit'])
/** Tools that name a delete disposition directly (single literal target). */
const DELETE_FILE_TOOLS = new Set(['delete'])
/** Tools that transfer content between paths: `move` removes its source (counted as an L2
 *  deletion) while `copy` leaves the source intact (allowed). They are deliberately NOT
 *  treated as one family — see `classifyStructured`. */
const TRANSFER_FILE_TOOLS = new Set(['move', 'copy'])
/** Tools whose arguments carry arbitrary program text executed by a runtime, not a shell. */
const CODE_TOOLS = new Set(['run_code'])
/** Tools that forward raw text into a persistent, stateful terminal. */
const TERMINAL_TOOLS = new Set(['terminal_send'])

/**
 * Reviewed framework-coordination tools that have NO filesystem-deletion capability:
 * they read session/task/inspect state, manage agent messaging/scheduling, report
 * progress, stop/control already-running processes, or orchestrate subagents. Their names
 * are allowlisted EXACTLY (no prefix matching), verified against the live tool surface.
 * Under the catastrophe standard (v4) this also includes tools that manage the workspace or
 * the profile rather than deleting files: `create_worktree` (creates a branch/worktree),
 * `terminal_open` (opens a session; any text it later runs travels through the analysed
 * `terminal_send`), and `plugin_manager` with EVERY action (install/enable/disable/remove
 * affect profile bundles, not a filesystem delete set; their effects are a separate
 * concern from this delete gate). Any tool NOT in a known group is still default-denied.
 */
const FRAMEWORK_SAFE_TOOLS = new Set([
  // Cordis Inspect (read-only discovery).
  'cordis_inspect_list', 'cordis_inspect_query',
  // Session history read-only search / trace / read.
  'session_search', 'session_event_search', 'session_trace', 'session_event_trace', 'session_event_read',
  // Agent/subagent coordination (message passing; children are bounded by delegation depth).
  'list_agents', 'wait_agent', 'send_message', 'subagent', 'subagent_fork', 'list_subagent_models',
  // Team task board (shared metadata; no file deletion).
  'team_task_create', 'team_task_get', 'team_task_list', 'team_task_update',
  // Progress / goal / todo bookkeeping.
  'todo_write', 'create_goal', 'get_goal', 'update_goal',
  // Scheduling (delivers prompts; does not itself delete here).
  'schedule_create', 'schedule_edit', 'schedule_list', 'schedule_view',
  // Background job control (owns process jobs; not a filesystem delete by name).
  'job_list', 'job_output', 'job_kill',
  // Workspace directory read/select (no content deletion).
  'working_directory',
  // Workspace/profile management with no filesystem-deletion capability in the gate's
  // sense: creating a worktree, opening a terminal session, and every plugin_manager
  // action (list/install/enable/disable/remove bundle). Whatever these later cause to run
  // is a separate guarded execution (commands go through pwsh/bash/terminal_send analysis).
  'create_worktree', 'terminal_open', 'plugin_manager',
  // Persistent-terminal READ-ONLY observation and STOP/CONTROL of already-running
  // processes (no new executable is started and no raw text is entered; terminal_send
  // and terminal_open are handled separately).
  'terminal_list', 'terminal_read', 'user_terminal_list', 'user_terminal_read', 'terminal_signal', 'terminal_close',
  // Workflow orchestration: the tool contract is restricted orchestration only (no fs/
  // network/timer APIs); each child agent tool call is an independent guarded execution.
  'workflow',
  // User question / plan mode / presentation (no deletion).
  'ask_user_question', 'exit_plan_mode', 'present',
  // Skill loading and documentation.
  'skill',
  // Web research (network read; no local deletion).
  'web_search',
])

/** Tools this gate analyses end-to-end (parsed/observed/gated). */
function isAnalysedTool(execution) {
  return Boolean(dialectOf(execution)) || READ_FILE_TOOLS.has(execution.name) || MUTATE_FILE_TOOLS.has(execution.name)
    || DELETE_FILE_TOOLS.has(execution.name) || TRANSFER_FILE_TOOLS.has(execution.name)
    || execution.name === 'web_fetch' || CODE_TOOLS.has(execution.name) || TERMINAL_TOOLS.has(execution.name)
}

/** Tools that are reviewed as having no deletion capability and pass untouched. */
function isFrameworkSafe(execution) {
  return FRAMEWORK_SAFE_TOOLS.has(execution.name)
}

const SINGLE_TARGET_ARG = /^[^*?[\]\u0000]{1,32768}$/

/** @throws {Error} If the composed configuration is invalid. */
export function apply(ctx, config = {}) {
  evaluateRules(readConfig(config))
  const completed = new WeakMap()
  const lifetime = new AbortController()
  const parsers = createShellParsers()
  ctx.effect(() => () => {
    lifetime.abort()
    return parsers.dispose()
  })
  ctx.inject(['settings'], (sctx) => {
    sctx.effect(() => sctx.settings.configure({ auto: false }, ctx.fiber))
  })
  installRedaction(ctx)

  /** Resolve the actual session working directory (committed, no filesystem IO).
   * The workingDirectory service for THIS session is authoritative; the recorded
   * header is only a fallback when the service is unavailable. */
  function sessionCwd(execution) {
    const session = execution.agent?.session
    const directories = ctx.get('workingDirectory')
    if (session && directories && typeof directories.get === 'function') {
      const cwd = directories.get(session)
      if (typeof cwd === 'string' && cwd.length > 0) return cwd
    }
    return session?.header?.cwd
  }

  /** Resolve the sandbox-confined workspace root. A `sandboxPolicy` that throws is a
   *  hard analysis failure and is NOT swallowed (falling back to another directory
   *  could misattribute relative targets). */
  function sandboxWorkspace(execution) {
    const policy = ctx.get('sandboxPolicy')
    if (!policy || typeof policy.resolve !== 'function') return undefined
    const resolved = policy.resolve(execution.agent?.session ? { session: execution.agent.session } : {})
    return typeof resolved?.workspaceRoot === 'string' ? resolved.workspaceRoot : undefined
  }

  /**
   * Resolve the ONE effective cwd used for parsing, target observation and deletion
   * inventory, shared across every stage so counting never happens in a different
   * directory than parsing.
   *
   * The ACTUAL working directory is the session's committed directory (workingDirectory
   * service), NOT the sandbox root boundary. `workdir` (a shell-tool argument) is
   * resolved against that real cwd, never assumed absolute. The sandbox root/process cwd
   * are only last-resort fallbacks when no session/workingDirectory is available.
   */
  function effectiveCwd(execution, args) {
    // Only shell tools carry a `workdir` argument; other tools resolve relative to the
    // real session cwd and must not be redirected by an unrelated argument.
    const workdir = dialectOf(execution) && args && typeof args.workdir === 'string' && args.workdir.length > 0
      ? args.workdir : undefined
    const base = sessionCwd(execution) ?? sandboxWorkspace(execution) ?? process.cwd()
    if (workdir) {
      if (path.isAbsolute(workdir)) return workdir
      if (typeof base === 'string' && base.length > 0) return path.resolve(base, workdir)
      throw new Error('guardrails: relative workdir has no resolvable base directory')
    }
    return base
  }

  /** Evaluate one invocation end to end. Unknowns are explicit and never grant. */
  async function analyze(execution) {
    const rules = evaluateRules(readConfig(config))
    const signal = AbortSignal.any([lifetime.signal, execution.signal].filter(Boolean))
    const args = execution.arguments

    // `run_code` executes a program, not a command line, so its target set can never be
    // enumerated; it stays denied. `terminal_send` is deliberately NOT denied here: its
    // text is a command line and is analysed below like pwsh/bash input.
    if (CODE_TOOLS.has(execution.name)) {
      return { kind: 'deny', reason:
        '[OPAQUE_CODE] run_code executes an arbitrary program whose direct runtime side effects (filesystem/process/'
        + 'network/dynamic imports) cannot be proven free of deletion from its source text. This environment does not '
        + 'permit it. Call a checked tool explicitly for the exact target (e.g. delete with a literal path, or a guarded '
        + 'pwsh/bash command).', unknown: [] }
    }
    if (!isAnalysedTool(execution)) {
      // Default-deny: an unrecognized tool may have deletion side effects we cannot prove
      // absent. Do not false-allow a custom destructive tool by an unknown name.
      return { kind: 'deny', reason:
        '[UNKNOWN_TOOL] This tool is not a recognized, analysed capability; its file and deletion side effects cannot '
        + 'be proven safe, so dispatch is refused. Use a checked tool (read/write/edit/delete/pwsh/bash) for the exact '
        + 'operation, or request an explicit guardrails adapter for this tool before using it.', unknown: [] }
    }

    // Resolve the single effective cwd up front so parse, observe and count agree. The
    // projectBoundary for whitelist confinement is the sandbox workspace root when known;
    // it is a SEPARATE value from the authoritative execution cwd.
    const cwd = effectiveCwd(execution, args)
    const boundary = sandboxWorkspace(execution)
    const unknown = []
    let commands
    const shell = commandInputOf(execution)
    const dialect = shell?.dialect
    if (shell) {
      if (typeof shell.source !== 'string') throw new Error('invalid shell input')
      const analyzed = await analyzeShell({ dialect: shell.dialect, source: shell.source, parsers, cwd, signal })
      commands = analyzed.commands
      unknown.push(...analyzed.unknown)
    } else if (execution.name === 'web_fetch') {
      commands = typeof args?.url === 'string' ? [{ name: 'Invoke-WebRequest', args: [args.url], dialect: 'powershell', domain: 'host' }] : []
    } else {
      // Structured file tool: only exact single-target shapes are modelled. Any extra or
      // ambiguous argument that could change the disposition is refused downstream.
      commands = structuredCommands(execution.name, args)
    }

    // Deletion intent is classified BEFORE observing targets so that a REAL -WhatIf
    // preview command can be excluded from destructive observation/inventory. Preview
    // commands still pass path/mode validation and still contribute any deny; they simply
    // do not delete, so they must not be counted or denied as a real target set. Ordinary
    // opaque commands are still refused by the classifier regardless of preview.
    let deletes
    let previewIndexes = new Set()
    if (dialect) {
      const assessed = assessCommands(commands, { unknown })
      // Filesystem deletes, `move-source` (a move removes its source), AND the three git
      // actions are counted by the plan gate. A git command the intent layer allows emits
      // NO operation, so it never enters the plan and is never walked, counted or
      // boundary-checked as a filesystem target set.
      const allDeletes = assessed.operations.filter((operation) =>
        operation.action === 'delete' || operation.action === 'move-source' || GIT_ACTIONS.has(operation.action))
      if (assessed.denial) {
        // Split the classifier unknowns into ones that can never by themselves indicate a
        // catastrophic deletion versus ones that still matter:
        //   - a bare errno (ENOENT/ENOTDIR/…) only says some named path does not exist; a
        //     create/copy/move-destination that does not exist yet, or a delete of a missing
        //     file (a harmless no-op), is never a catastrophe. Drop it whether or not the call
        //     also deletes.
        //   - a state-changing-command marker means the fixed target set for a real delete is
        //     untrustworthy — that only matters when the call actually deletes.
        // Everything else (link-entry-removal, nonliteral-or-remote, dynamic-provider, budget,
        // cwd, device-identity, genuine semantic unknowns) is always kept.
        const weakening = allDeletes.length > 0
          ? (entry) => isBareErrno(entry)
          : (entry) => isBareErrno(entry) || isStateChangingUnknown(entry)
        const relaxed = unknown.filter((entry) => !weakening(entry))
        if (relaxed.length !== unknown.length) {
          const recheck = assessCommands(commands, { unknown: relaxed })
          if (recheck.denial) return { kind: 'deny', ruleId: recheck.denial.ruleId, reason: recheck.denial.reason, unknown }
        } else {
          return { kind: 'deny', ruleId: assessed.denial.ruleId, reason: assessed.denial.reason, unknown }
        }
      }
      previewIndexes = new Set(Array.isArray(assessed.previewCommandIndexes) ? assessed.previewCommandIndexes : [])
      deletes = allDeletes
    } else {
      const structured = classifyStructured(execution, args)
      if (structured.denial) return { kind: 'deny', reason: structured.denial, unknown }
      deletes = structured.deletes
    }
    // A `preview:true` delete operation is a pure -WhatIf: keep it out of the destructive
    // target observation and the 20-file inventory (it removes nothing), but its command
    // still participates in policy/credential scanning below via the full `commands`.
    const realDeletes = deletes.filter((operation) => operation.preview !== true)
    const observedCommands = previewIndexes.size > 0 ? commands.filter((_, index) => !previewIndexes.has(index)) : commands

    const targets = await observeTargets({ commands: observedCommands, cwd, rules, signal })
    for (const operation of targets.operations) {
      if (operation.unknown) unknown.push(operation.unknown)
      if (operation.scanUnknown) unknown.push(operation.scanUnknown)
    }
    if (targets.unknown) unknown.push(...targets.unknown)

    // L3 over-defence fix (post-observation): drop bare-errno unknowns always (a nonexistent
    // create/copy/move-destination or a delete of a missing path is never a catastrophe), and
    // also drop the state-changing marker when the call performs no real deletion. When the
    // call DOES delete, the state-changing marker is kept (a mutated session makes the fixed
    // set untrustworthy → fail-closed); only bare errno is still dropped.
    const realDeletionPresent = realDeletes.length > 0
    {
      const kept = unknown.filter((entry) =>
        !(isBareErrno(entry) || (!realDeletionPresent && isStateChangingUnknown(entry))))
      unknown.length = 0
      unknown.push(...kept)
    }

    // The observation stage can surface NEW unknowns (e.g. a non-filesystem/unlocatable
    // target) that were not known when the pre-observation classifier ran. The original
    // pipeline classified AFTER observation so those facts reached DI-UNKNOWN-SEMANTICS.
    // Re-run the classifier with the merged unknowns and honor its denial; do NOT rely on
    // evaluatePolicy (which defaults unknown to allow). This second pass also covers
    // observation unknowns for non-preview commands; preview commands were already
    // excluded from observation, so they add no observation unknown here.
    if (dialect) {
      const reassessed = assessCommands(commands, { unknown })
      if (reassessed.denial) return { kind: 'deny', ruleId: reassessed.denial.ruleId, reason: reassessed.denial.reason, unknown }
    }

    let decision = evaluatePolicy({ commands, targets })
    const inline = inlineCredentialDecision(commands)
    if (decision.kind !== 'deny' && inline) decision = inline

    // Deletion plan: inventory + 20-file hard gate + protected-file approval. Only real
    // deletes are inventoried. The plan is computed ONCE here; a plan denial never reaches
    // the approval request.
    if (realDeletes.length > 0 && decision.kind !== 'deny') {
      const plan = await planDeletions({ operations: realDeletes, cwd, boundary, rules, signal })
      if (plan.kind === 'deny') {
        decision = { kind: 'deny', ruleId: plan.ruleId, reason: plan.reason }
      } else {
        const protectedEntry = Array.isArray(plan.entries) && plan.entries.some((entry) => entry.protected === true)
        if (decision.kind === 'allow' && protectedEntry) {
          decision = { kind: 'ask', ruleId: 'S-F1', reason: `S-F1: this deletion would remove or access an actual protected file inside the target tree. Use runtime credential injection or a health check that reports only non-secret status when possible; approval applies only to this call. ${DELETION_DOCTRINE}` }
        }
      }
    }

    if (decision.kind === 'ask') {
      // Snapshot the inventory signature (a plain string) before the approval wait.
      const before = await deletionSignature(realDeletes, cwd, boundary, rules, signal)
      // If the current inventory already denies (>20 / unknown / .git / link), do not
      // request approval: return the plan denial directly.
      if (before.kind === 'deny') return { kind: 'deny', ruleId: before.ruleId, reason: before.reason, unknown }
      decision = await requestApproval(ctx, execution, decision.reason, rules.askTimeoutMs, lifetime.signal)
      // An approval wait is unbounded; a concurrent or staged change can enlarge the set
      // after the pre-count. Re-inventory and refuse on any change or a newly-denied plan.
      if (decision.kind === 'allow' && realDeletes.length > 0 && !signal.aborted) {
        const after = await deletionSignature(realDeletes, cwd, boundary, rules, signal)
        if (after.kind === 'deny') {
          decision = { kind: 'deny', ruleId: after.ruleId, reason: after.reason }
        } else if (after.signature !== before.signature) {
          decision = { kind: 'deny', reason: '[PLAN_CHANGED] The deletion target set changed between approval request and dispatch; invocation refused. Re-issue the deletion with the current, verified set.' }
        }
      }
    }
    if (signal.aborted) decision = { kind: 'deny', reason: '[ANALYSIS_CANCELLED] Invocation cancelled before dispatch.' }
    return { ...decision, unknown }
  }

  /**
   * Stable inventory signature for the re-check after approval. Returns an object with
   * an explicit `kind` so a deny result is never compared by object identity:
   *   - { kind: 'deny', ruleId, reason }  -> the plan now denies; refuse.
   *   - { kind: 'allow', signature }      -> deterministic string of counts + entry paths.
   */
  async function deletionSignature(deletes, cwd, boundary, rules, signal) {
    if (deletes.length === 0) return { kind: 'allow', signature: 'none' }
    const plan = await planDeletions({ operations: deletes, cwd, boundary, rules, signal })
    if (plan.kind === 'deny') return { kind: 'deny', ruleId: plan.ruleId, reason: plan.reason }
    const paths = Array.isArray(plan.entries)
      ? plan.entries.map((entry) => `${entry.type}:${entry.path}`).sort().join('\n')
      : ''
    return { kind: 'allow', signature: `files:${plan.counts?.files ?? 0}:links:${plan.counts?.links ?? 0}:dirs:${plan.counts?.directories ?? 0}\n${paths}` }
  }

  ctx.effect(() => ctx.tools.guard((execution) => {
    // Final synchronous guard. Framework-safe tools are reviewed to have no deletion
    // capability and pass. Every OTHER tool must have a completed analysis; an unknown
    // tool can never be short-circuited by earlier pre-execute policy to bypass this.
    if (isFrameworkSafe(execution)) return undefined
    const result = completed.get(execution)
    if (!result) {
      if (!isAnalysedTool(execution)) {
        return '[UNKNOWN_TOOL] This tool is not a recognized, analysed capability; dispatch is refused because its file and deletion side effects cannot be proven safe.'
      }
      return '[ANALYSIS_MISSING] Guardrails has no completed analysis for this exact execution; dispatch refused.'
    }
    if (lifetime.signal.aborted) return '[ANALYSIS_DISPOSED] Guardrails was unloaded during analysis.'
    if (execution.signal?.aborted) return '[ANALYSIS_CANCELLED] Invocation cancelled.'
    return result.kind === 'allow' ? undefined : result.reason ?? '[APPROVAL_CANCELLED] No one-time authorization.'
  }))
  ctx.effect(() => ctx.on('tools/pre-execute', async (execution, next) => {
    // Framework-safe tools carry no deletion capability; return early so team/inspect/
    // messaging/scheduling continue to work. Every other tool must be analysed; an
    // unrecognized tool is default-denied (never silently forwarded).
    if (isFrameworkSafe(execution)) return next()
    let decision
    try {
      decision = await analyze(execution)
    } catch {
      // Parser diagnostics may contain script source; report only a safe category.
      decision = { kind: 'deny', reason: '[ANALYSIS_UNAVAILABLE] Official syntax or target analysis failed; invocation refused. Check parser availability and valid syntax.', unknown: [] }
    }
    // Unknown diagnostics belong to this invocation; they never create permission.
    completed.set(execution, decision)
    if (decision.kind !== 'allow') return { kind: 'deny', reason: decision.reason ?? '[DENIED] Invocation refused.' }
    return next()
  }))
}

/**
 * Classify a structured file tool's arguments into delete plans, or a denial when the
 * shape is not a single unambiguous literal target. move/copy are refused: their source
 * removal / target overwrite side effects cannot be proven absent without more data.
 */
function classifyStructured(execution, args) {
  const name = execution.name
  if (DELETE_FILE_TOOLS.has(name)) {
    // Both file_path and path present with different values is ambiguous: which one the
    // real tool deletes is unknown, so refuse rather than guess.
    if (typeof args?.file_path === 'string' && typeof args?.path === 'string' && args.file_path !== args.path) {
      return { denial: '[UNSUPPORTED_DELETE] The delete tool received both file_path and path with different values; the actual target is ambiguous, so invocation is refused.' }
    }
    if (args && Object.hasOwn(args, 'recursive') && typeof args.recursive !== 'boolean') {
      return { denial: '[UNSUPPORTED_DELETE] The delete tool recursive argument is not a boolean; invocation refused.' }
    }
    const target = args?.file_path ?? args?.path
    if (typeof target !== 'string' || !SINGLE_TARGET_ARG.test(target)) {
      return { denial: '[UNSUPPORTED_DELETE] The delete tool needs one literal local path (no wildcards or dynamic expansion); invocation refused.' }
    }
    // Reject any extra argument that could broaden or redirect the disposition.
    const extra = Object.keys(args ?? {}).filter((key) => !['file_path', 'path', 'recursive', 'justification', 'sandbox_permissions'].includes(key))
    if (extra.length > 0) {
      return { denial: `[UNSUPPORTED_DELETE] The delete tool received unmodelled argument(s): ${extra.join(', ')}; invocation refused.` }
    }
    return { deletes: [{ action: 'delete', path: target, recursive: args?.recursive === true, domain: 'host' }] }
  }
  if (name === 'move') {
    // Moving REMOVES the source tree, which is an enumerable L2 deletion of the source and
    // is counted by the same gate (>20 → DEL-14). Only one literal source is modelled; a
    // wildcard/dynamic source cannot be enumerated. A silent overwrite of an existing
    // destination is NOT additionally blocked (documented in the copy/settings copy); a
    // protected destination is still observed and requires approval through policy.
    const target = args?.file_path ?? args?.path
    if (typeof target !== 'string' || !SINGLE_TARGET_ARG.test(target)) {
      return { denial: '[UNSUPPORTED_TRANSFER] The move tool needs exactly one literal source path (no wildcards or dynamic expansion) so the source removal can be counted; invocation refused.' }
    }
    return { deletes: [{ action: 'move-source', path: target, recursive: true, domain: 'host' }] }
  }
  if (name === 'copy') {
    // Copy leaves the source intact, so it is not a deletion. Overwriting an existing
    // destination replaces content but removes no source entry; a protected destination is
    // still observed and requires approval through policy. Nothing to count here.
    return { deletes: [] }
  }
  // write/edit/read/grep/glob: no deletion intent from their own arguments.
  return { deletes: [] }
}
