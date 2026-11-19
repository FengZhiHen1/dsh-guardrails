// shell — official-AST analysis of ONE routed shell unit.
//
// Boundary: this analyzer only re-parses *text* through the official parsers
// (Microsoft PowerShell Parser via the persistent pwsh helper, official
// mvdan/sh v3.12.0 typed JSON). It never interprets, evaluates or executes
// inspected text and never spawns the analyzed shell. It owns: AST-level
// command facts, execution-vs-data marking, PowerShell invocation-flag
// semantics for inline extraction, provable `cd` state, and file redirections.
// The shared command catalog (main) owns wrapper routing, script files, WSL,
// and delete-sink recognition — this module has zero sink knowledge.
//
// Per-unit contract (`analyze(unit, env)` resolves with no value):
//
// unit = {
//   unitId: string,                       // correlation id assigned by main
//   source: { kind: 'inline', text },     // shell text under analysis (data)
//   language: 'bash' | 'posix' | 'powershell' ('pwsh' accepted as alias),
//   context: { domain?, cwd?, platform?, distribution?, user? },
//                                         // domain 'host' | 'unknown' | other string
//                                         // distribution/user pass through (WSL routing)
//   origin?,                              // opaque, echoed back on every fact
//   scriptArgs?,                          // noted only; positional params stay dynamic
// }
//
// env emitters (all optional; an absent emitter drops that channel):
//   command(executable, args, options) — one command invocation fact.
//     args: (string|null)[]; null = dynamic/unprovable word.
//     options: {
//       origin: { ...unit.origin, commandIndex, commandName },
//       context: { dialect, domain, cwd?, platform? },
//       condition: 'certain' | 'possible' | 'unknown',
//       powershell?: true,               // args follow PowerShell invocation semantics
//       patterns: boolean[],             // parallel: value is a glob-pattern word
//       literalOperands?: boolean[],     // POSIX only: quoted literal value starting with '-'
//       dataArgs: boolean[],             // parallel: argument is a data position (R-19)
//       pipeline?: { index: number, source: string|null },
//                                        // PowerShell only (DSR-031 decision 9). index is the
//                                        // 0-based slot of this command in its PipelineAst;
//                                        // source is the bounded, literal-only text of the
//                                        // IMMEDIATELY PRECEDING pipeline element, or null
//                                        // when that element is not a provable command. It is
//                                        // an adjacent-element scope label, not the whole
//                                        // pipeline and not a deletion verdict; absent when
//                                        // the parser returned no pipeline information.
//     }
//   operation(action, target, options) — file redirection effect.
//     action: 'truncate-content' | 'write-content' | 'read-content'
//     target: { kind: 'exact', paths: [text] } | { kind: 'unknown', reason }
//     options: { origin, context, condition, recursive: false, preview: false, details: { operator } }
//     Redirections are modeled BEFORE the command fact they belong to so a
//     same-call inventory sees the file effect first; heredoc delimiters and
//     stream merges produce no operation.
//   child(unit) — explicit nested execution found in the outer AST (provable
//     inline script of bash/sh/pwsh); unitId is `${parent}/${commandIndex}`.
//     Main drains and routes it (shell again or a language provider).
//   gap(kind, origin?) — analysis-coverage failure. Kinds: 'parse-error',
//     'budget-commands', 'budget-children', 'unsupported-language',
//     'control-flow', 'state-mutation', 'startup-code', 'pwsh-profile',
//     'pwsh-trailing-args', 'pwsh-context-option', 'encoded-command',
//     'cmd-inline', 'unsupported-interpreter', 'untrusted-interpreter-path',
//     'opaque-interpreter', 'dynamic-script', 'interactive-shell',
//     'unmodeled-interpreter-option', 'local-function', 'dynamic-code',
//     'parser-unknown'.
//   candidate('dynamic-execution', reason, knownScope?, origin?) — dynamic
//     execution channel (DSR-026). Reasons never contain the executable name
//     or raw source text.
//   step(count = 1) — work-unit accounting for main's global budget.
//
// Working-directory rules: the unit cwd is accepted only when absolute under
// the TARGET platform's path semantics (WSL is POSIX even on a Windows host).
// A literal `cd` verified against the host filesystem refines it; an
// unprovable `cd` removes the cwd from later facts and emits a
// 'state-mutation' gap; a subshell cd neither propagates nor flags, and
// commands inside a subshell carry no provable cwd.
//
// env.signal aborts parsing (rethrows a CANCELLED-coded error); env.limits is
// not read (limits come from createShellAnalyzer options.limits).
//
// Failure split (per 架构重构设计 统一失败语义):
// - parser SYNTAX failure -> gap('parse-error'), analysis ends (partial facts).
// - binary/IO/protocol/timeout/queue/integrity/input-limit failures and
//   cancellation -> throw (fail-closed at the caller).
// - malformed unit / env -> TypeError (routing bug, main fails the call).

import path from 'node:path';
import fs from 'node:fs/promises';
import { createShellParsers } from '../parsers/index.mjs';
import { parsePosix } from './shell/posix-parser.js';
import { wrapperName, looksLikeOpaqueInterpreter, interpreterShapedName, interpreterInlineScript, SHELL_WRAPPER_DIALECT, OTHER_POSIX_SHELLS, POWERSHELL_NAMES, CMD_NAMES } from './shell/wrappers.js';
import { computeDataArgs, computePatterns, computeLiteralOperands, collectHeredocs, classifyParserUnknown, mapInterpreterUnknowns, isStateMutator, CD_FAMILY, trackableCdArgument } from './shell/facts.js';

const DEFAULT_LIMITS = Object.freeze({ maxCommands: 4096, maxChildren: 64 });
const DEFAULT_PARSER_LIMITS = Object.freeze({ timeoutMs: 5000, maxInputBytes: 262144, maxOutputBytes: 8388608, maxConcurrent: 2, maxQueue: 16 });
const PARSER_LIMIT_KEYS = ['timeoutMs', 'maxInputBytes', 'maxOutputBytes', 'maxConcurrent', 'maxQueue', 'pwshPath', 'spawnProcess'];
const SUPPORTED_LANGUAGES = new Set(['bash', 'posix', 'powershell']);

/** PowerShell pipeline provenance for one parsed command (DSR-031 decision 9).
 * `index` is the command's 0-based slot in its PipelineAst; `source` is the text
 * of the IMMEDIATELY PRECEDING element only, as produced by the parser (literal
 * words only, bounded, no guessed dynamic content). Returns undefined when the
 * parser supplied no pipeline information (non-PowerShell dialect, injected
 * pool, or an older helper), so payload semantics stay unchanged there. */
function pipelineOf(cmd) {
  if (!Number.isSafeInteger(cmd?.pipelineIndex) || cmd.pipelineIndex < 0) return undefined;
  const source = typeof cmd.pipelineSource === 'string' && cmd.pipelineSource.length > 0 ? cmd.pipelineSource : null;
  return { index: cmd.pipelineIndex, source };
}

/**
 * Create a shell analyzer bound to one official-parser pool.
 * @param {object} [options]
 * @param {{parse:function, dispose?:function}} [options.parsers] injected pool;
 *   when omitted a dedicated pool is created and disposed by `dispose()`.
 * @param {{maxCommands?:number, maxChildren?:number, parser?:object,
 *   timeoutMs?:number, maxInputBytes?:number, maxOutputBytes?:number,
 *   maxConcurrent?:number, maxQueue?:number}} [options.limits]
 */
export function createShellAnalyzer(options = {}) {
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const parserLimits = {
    ...DEFAULT_PARSER_LIMITS,
    ...Object.fromEntries(PARSER_LIMIT_KEYS.filter((key) => options.limits && options.limits[key] !== undefined).map((key) => [key, options.limits[key]])),
    ...(options.limits?.parser ?? {}),
  };
  const ownedParsers = options.parsers ? null : createShellParsers(parserLimits);
  const parsers = options.parsers ?? ownedParsers;

  /**
   * Analyze one shell unit and emit facts through `env`. Resolves with no
   * value; all results are delivered synchronously through the emitters
   * except the parser call.
   */
  async function analyze(unit, env) {
    if (!env || typeof env !== 'object') throw new TypeError('shell.analyze: env must be an object');
    if (!unit || typeof unit !== 'object') throw new TypeError('shell.analyze: unit must be an object');
    if (typeof unit.unitId !== 'string' || unit.unitId.length === 0) throw new TypeError('shell.analyze: unit.unitId must be a non-empty string');
    const source = unit.source;
    if (!source || source.kind !== 'inline' || typeof source.text !== 'string') {
      throw new TypeError('shell.analyze: unit.source must be { kind: "inline", text: string }');
    }
    const context = unit.context ?? {};
    if (typeof context !== 'object') throw new TypeError('shell.analyze: unit.context must be an object');
    const origin = (unit.origin && typeof unit.origin === 'object') ? unit.origin : {};

    const language = unit.language === 'pwsh' ? 'powershell' : unit.language;
    const command = env.command ?? (() => {});
    const operation = env.operation ?? (() => {});
    const child = env.child ?? (() => {});
    const gap = env.gap ?? (() => {});
    const candidate = env.candidate ?? (() => {});
    const step = env.step ?? (() => {});

    if (typeof language !== 'string' || !SUPPORTED_LANGUAGES.has(language)) {
      gap('unsupported-language', origin);
      return;
    }

    const domain = context.domain ?? 'host';
    const platform = typeof context.platform === 'string' ? context.platform : undefined;
    // Path semantics follow the TARGET platform: WSL units are POSIX even on a
    // Windows host; inherited inputs keep their declared platform.
    const pathMod = domain === 'wsl' || platform === 'linux' ? path.posix : platform === 'win32' ? path.win32 : path;

    const unitContext = () => {
      const value = { dialect: language, domain };
      if (platform) value.platform = platform;
      if (context.distribution !== undefined) value.distribution = context.distribution;
      if (context.user !== undefined) value.user = context.user;
      return value;
    };

    step(1); // parse work
    let parsed;
    try {
      parsed = language === 'powershell'
        ? await parsers.parse('powershell', source.text, { signal: env.signal })
        : await parsePosix(source.text, language, parserLimits, env.signal);
    } catch (error) {
      // Parser syntax failure -> partial analysis, triaged by main through the
      // gap channel. Resource/infrastructure failures and cancellation
      // propagate so the caller fails closed.
      if (error?.code === 'SYNTAX') { gap('parse-error', origin); return; }
      throw error;
    }

    const state = { commands: 0, children: 0 };
    const gapKinds = new Set();
    let controlFlowSeen = false;
    const emitGap = (kind) => {
      if (kind === 'control-flow') controlFlowSeen = true;
      if (gapKinds.has(kind)) return;
      gapKinds.add(kind);
      gap(kind, origin);
    };
    const commandOrigin = (index, name) => ({ ...origin, commandIndex: index, commandName: name });
    const conditionOf = (cmd) => {
      if (language === 'powershell') {
        // Scriptblock/subexpression scope is gated execution. Top-level scope
        // is only provably unconditional when the unit has no control-flow
        // construct the helper could not attribute to a single command.
        if (cmd.scope !== undefined && cmd.scope !== 'script') return 'possible';
        return controlFlowSeen ? 'unknown' : 'certain';
      }
      return cmd.condition ?? 'unknown';
    };
    const SUBSHELL_SCOPES = new Set(['CmdSubst', 'Subshell', 'ProcSubst']);
    const emitContext = (cmd) => {
      const value = unitContext();
      // A command inside a command substitution/subshell runs with that
      // subshell's cwd, which this analysis does not track: its cwd stays
      // unprovable (omitted) rather than inheriting the parent's.
      const subshell = cmd !== undefined && SUBSHELL_SCOPES.has(cmd.scope);
      if (!subshell && trackedCwd !== undefined) value.cwd = trackedCwd;
      return value;
    };

    for (const reason of parsed.unknown ?? []) {
      const kind = classifyParserUnknown(reason);
      if (kind) emitGap(kind);
    }

    // Provable working directory: main-provided absolute cwd (target-platform
    // semantics), refined by same-unit literal `cd` commands verified against
    // the host filesystem. An unprovable cd REMOVES the provable cwd.
    let trackedCwd = typeof context.cwd === 'string' && pathMod.isAbsolute(context.cwd) ? pathMod.normalize(context.cwd) : undefined;

    for (let index = 0; index < parsed.commands.length; index += 1) {
      if (state.commands >= limits.maxCommands) { emitGap('budget-commands'); return; }
      const cmd = parsed.commands[index];
      const posix = language !== 'powershell';
      const args = Array.isArray(cmd.args) ? cmd.args : [];
      const name = cmd.name;

      if (typeof name === 'string' && CD_FAMILY.has(name.toLowerCase())) await trackCd(cmd);

      if (typeof name === 'string' && isStateMutator(name, language)) emitGap('state-mutation');

      if (name === null) {
        // Dynamic execution channel (name is dynamic) or a redirect-only
        // statement (no command words). Redirects still take effect.
        if (args.length > 0 || (parsed.unknown ?? []).some((reason) => String(reason).startsWith('Dynamic command or argument'))) {
          candidate('dynamic-execution', 'Command name is dynamic; the executed program cannot be identified from the AST', undefined, commandOrigin(index, null));
          step(1);
        }
        emitRedirects(cmd, index, { operation, commandOrigin, emitContext, conditionOf, step, state, limits, emitGap, name: null });
        continue;
      }

      const consumed = await handleWrapper({ cmd, index, name, posix, args, language, context, state, limits, emitGap, child, step, operation, emitRedirects, emitContext, commandOrigin, conditionOf });
      if (!consumed) {
        // Redirections are modeled BEFORE their owning invocation so a same-call
        // inventory sees the file effect first.
        emitRedirects(cmd, index, { operation, commandOrigin, emitContext, conditionOf, step, state, limits, emitGap, name });
        emitCommand({ cmd, index, name, args, language, command, step, state, limits, emitGap, emitContext, commandOrigin });
      }
    }

    async function trackCd(cmd) {
      // A cd inside a command substitution/subshell does not change the parent
      // shell's cwd: never propagate it, never flag it.
      if (language !== 'powershell' && SUBSHELL_SCOPES.has(cmd.scope)) return;
      const arg = trackableCdArgument(Array.isArray(cmd.args) ? cmd.args : []);
      const scopeOk = cmd.scope === undefined || cmd.scope === 'script' || cmd.scope === 'file';
      if (arg !== null && domain === 'host' && scopeOk && typeof trackedCwd === 'string') {
        const resolved = pathMod.isAbsolute(arg) ? pathMod.normalize(arg) : pathMod.resolve(trackedCwd, arg);
        try {
          const info = await fs.lstat(resolved);
          // A real directory moves the tracked cwd; a missing/non-directory/
          // symlink target could resolve differently at execution time.
          if (info.isDirectory() && !info.isSymbolicLink()) { trackedCwd = resolved; return; }
        } catch { /* fall through: unprovable */ }
      }
      trackedCwd = undefined;
      emitGap('state-mutation');
    }

    function emitCommand({ cmd, index, name, args, language: dialect, command: emitCommandFn, step: stepFn, state: st, limits: budget, emitGap: emitGapLocal, emitContext: ctxFn, commandOrigin: originFn }) {
      if (st.commands >= budget.maxCommands) { emitGapLocal('budget-commands'); return; }
      const powershell = dialect === 'powershell';
      const payload = {
        origin: originFn(index, name),
        context: ctxFn(cmd),
        condition: conditionOf(cmd),
        ...(powershell ? { powershell: true } : {}),
        patterns: computePatterns(args, cmd.words, { powershell }),
        dataArgs: computeDataArgs(name, args, { powershell }),
      };
      if (!powershell) {
        const literalOperands = computeLiteralOperands(cmd.words);
        if (literalOperands) payload.literalOperands = literalOperands;
      } else {
        // Adjacent upstream provenance stays a fact, not a decision: this module
        // never calls env.candidate and never removes a command based on it.
        const pipeline = pipelineOf(cmd);
        if (pipeline) payload.pipeline = pipeline;
      }
      // Raw heredoc bodies travel with the command fact: the shared catalog
      // decides which receiver consumes them (shell interpreters, ssh) and
      // which ones stay data (cat, tee, python, …). No file operation exists
      // for a heredoc, so this stays separate from the redirect operations.
      const heredocs = collectHeredocs(cmd.redirects);
      if (heredocs) payload.heredocs = heredocs;
      emitCommandFn(name, args, payload);
      stepFn(1);
      st.commands += 1;
    }

    function emitRedirects(cmd, index, { operation: emitOperationFn, commandOrigin: originFn, emitContext: ctxFn, conditionOf: condFn, step: stepFn, state: st, limits: budget, emitGap: emitGapLocal, name }) {
      for (const redirect of Array.isArray(cmd.redirects) ? cmd.redirects : []) {
        const action = redirect.operator === '>' || redirect.operator === '>|' || redirect.operator === '&>' ? 'truncate-content'
          : redirect.operator === '>>' || redirect.operator === '&>>' ? 'write-content'
            : redirect.operator === '<' || redirect.operator === '<>' ? 'read-content'
              : null; // heredocs and stream merges have no file target
        if (!action) continue;
        if (st.commands >= budget.maxCommands) { emitGapLocal('budget-commands'); return; }
        emitOperationFn(action,
          redirect.target === null || redirect.target === undefined
            ? { kind: 'unknown', reason: 'Redirect target is dynamic' }
            : { kind: 'exact', paths: [redirect.target] },
          {
            origin: originFn(index, name),
            context: ctxFn(cmd),
            condition: condFn(cmd),
            recursive: false,
            preview: false,
            details: { operator: redirect.operator },
          });
        stepFn(1);
        st.commands += 1;
      }
    }

    /**
     * Attempt to consume an interpreter invocation whose inline script is
     * explicitly present in the outer AST, emitting a nested-analysis child
     * unit. Everything else (script files, WSL, cmd, dynamic inline scripts,
     * non-shell programs) stays a plain command fact for the shared catalog.
     * Returns true when the wrapper was consumed.
     */
    async function handleWrapper({ cmd, index, name, posix, args, language: dialect, context: ctx, state: st, limits: budget, emitGap: emitGapLocal, child: emitChild, step: stepFn, operation: emitOperationFn, emitRedirects: redirectFn, emitContext: ctxFn, commandOrigin: originFn, conditionOf: condFn }) {
      const { trusted, base, qualified } = wrapperName(name, { posix });
      if (qualified) {
        // A path-qualified interpreter-shaped name (e.g. /tmp/bash) is not a
        // trusted wrapper and is not consumed; it stays a command fact.
        if (interpreterShapedName(name)) emitGapLocal('untrusted-interpreter-path');
        return false;
      }
      if (looksLikeOpaqueInterpreter(name, posix)) {
        // e.g. POSIX `BASH`/`bash.exe`/`BaSh`: may be an arbitrary external program.
        emitGapLocal('opaque-interpreter');
        return false;
      }
      if (!trusted || base === null) return false;

      if (CMD_NAMES.has(base)) { emitGapLocal('cmd-inline'); return false; }
      if (OTHER_POSIX_SHELLS.has(base)) {
        // dash/zsh/ksh/... have no supported grammar; inline forms stay opaque.
        emitGapLocal('unsupported-interpreter');
        return false;
      }
      let innerDialect;
      if (POWERSHELL_NAMES.has(base)) innerDialect = 'powershell';
      else innerDialect = SHELL_WRAPPER_DIALECT.get(base);
      if (!innerDialect) return false; // not a shell interpreter: plain command fact

      const inline = interpreterInlineScript(args, { powershell: innerDialect === 'powershell' });
      if (inline.encoded) emitGapLocal('encoded-command');
      if (inline.unknownReason) for (const kind of mapInterpreterUnknowns(inline.unknownReason)) emitGapLocal(kind);
      if (inline.dynamic) emitGapLocal('dynamic-script');
      if (inline.dynamic || inline.hasFileArg || inline.script === null) return false;

      // Explicit nested execution: consume the wrapper and hand the provable
      // inline text back to main for routing. The child inherits the unit's
      // context (domain/platform/distribution/user) and the tracked cwd; a
      // wrapper inside a subshell has no provable cwd to inherit.
      if (st.children >= budget.maxChildren) { emitGapLocal('budget-children'); return false; }
      const childContext = { ...ctxFn(cmd), dialect: innerDialect };
      // The outer interpreter still performs the wrapper's own redirections;
      // they are modeled before the invocation they belong to.
      redirectFn(cmd, index, { operation: emitOperationFn, commandOrigin: originFn, emitContext: ctxFn, conditionOf: condFn, step: stepFn, state: st, limits: budget, emitGap: emitGapLocal, name });
      emitChild({
        unitId: `${unit.unitId}/${index}`,
        source: { kind: 'inline', text: inline.script },
        language: innerDialect,
        context: childContext,
        origin: originFn(index, name),
      });
      stepFn(1);
      st.children += 1;
      return true;
    }
  }

  return {
    analyze,
    /** Terminate the owned parser pool; an injected pool is left untouched. */
    async dispose() {
      if (ownedParsers) await ownedParsers.dispose();
    },
  };
}
