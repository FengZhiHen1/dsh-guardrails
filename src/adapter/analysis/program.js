// program — best-effort static analysis of inline program sources (execution face).
//
// Entry point `createProgramAnalyzer(options)` implements the shared provider
// contract: `analyze(unit, env)` reports facts through the env callbacks and
// returns nothing; `dispose()` releases cached runtime probes.
//
// Design sources: docs/decisions/DSR-026-执行面尽力分析.md and
// docs/technical-details/跨语言删除分析.md. The analysis only READS the source
// (AST walk plus pure literal path arithmetic); it never executes, imports,
// compiles or evaluates the unit under review, and never touches the file
// system itself. Facts are delegated, never judged: the pipeline's single
// decision point owns dispositions.
//
// env contract (fixed by the pipeline):
// - env.signal (AbortSignal), env.limits { timeoutMs, maxInputBytes, maxOutputBytes, maxSteps }
// - env.command(executable, args, { origin, context, condition })
//     static-argv process spawns of NON-runtime executables (command facts)
// - env.operation(action, target, { origin, context, condition, recursive, preview, details })
//     action 'delete' | 'move-source'; target AbstractPath (exact/subtree/pattern/unknown)
// - env.child(input)
//     { source: { kind: 'argv', executable, args }, language: 'unknown', context, origin }
//       -> language-runtime spawns; the entry recognizer owns them
//     { source: { kind: 'inline', text }, language: <dialect>, context, origin }
//       -> embedded shell texts (os.system / child_process.exec …)
// - env.gap(kind, origin), env.candidate(kind, reason, knownScope?, origin?), env.step(count)
//
// Step debit: env.limits.maxSteps is the REMAINING shared walker budget for the
// whole analysis tree (child units included). Providers cap their AST walk at
// that budget and return `stepsUsed`; program.js debits it exactly once via
// env.step(stepsUsed) after the provider returns — per-fact stepping would
// double-charge shared work.
//
// Failure semantics (distinguished per lead contract):
// - executable absent (no probed Python runtime / typescript not installed)
//     -> gap 'no-python-runtime' / 'no-typescript-runtime', no throw
// - parse subprocess failure, timeout, protocol damage -> THROWS (pipeline
//     treats analyzer faults through the parse-failure branch, never as checked)
// - budget exhaustion -> partial facts already emitted plus gap 'budget-exhausted'
// - source syntax error (Python) -> gap fact 'parse-failed'; JS/TS parse
//     diagnostics -> gap 'parse-diagnostics' with partial facts
// - internal provider error -> thrown as ProgramAnalysisError

import { createPythonProvider, RuntimeAbsent, RuntimeFailed } from './program/python.js';
import { createJsProvider } from './program/js.js';
import { DEFAULT_LIMITS, normalizeTarget, factOrigin, shellLanguageForPlatform } from './program/common.js';

export class ProgramAnalysisError extends Error {
  constructor(code, message, options) { super(message, options); this.name = 'ProgramAnalysisError'; this.code = code; }
}

const PROGRAM_LANGUAGES = new Set(['python', 'javascript', 'typescript']);
// Shell dialects belong to the shell provider; if one reaches the program
// analyzer it is reported, never guessed as a program language.
const SHELL_LANGUAGES = new Set(['bash', 'posix', 'powershell']);

function validateUnit(unit) {
  if (!unit || typeof unit !== 'object') throw new TypeError('unit must be an object');
  if (typeof unit.unitId !== 'string' || unit.unitId.length === 0) throw new TypeError('unit.unitId must be a non-empty string');
  if (!unit.source || unit.source.kind !== 'inline' || typeof unit.source.text !== 'string') {
    throw new TypeError('unit.source must be { kind: "inline", text: string }');
  }
  if (typeof unit.language !== 'string') throw new TypeError('unit.language must be a string');
}

function emitFacts(unit, env, facts) {
  for (const fact of facts) {
    if (env.signal?.aborted) return;
    const origin = factOrigin(unit.origin, fact);
    switch (fact.t) {
      case 'operation':
        env.operation(fact.action, normalizeTarget(fact.target), {
          origin,
          context: unit.context,
          condition: fact.condition,
          recursive: fact.recursive === true,
          preview: false,
          details: fact.details,
        });
        break;
      case 'command':
        env.command(fact.executable, fact.args ?? [], { origin, context: unit.context, condition: fact.condition });
        break;
      case 'shell':
        env.child({ source: { kind: 'inline', text: fact.text }, language: shellLanguageForPlatform(unit.context?.platform), context: unit.context, origin, condition: fact.condition });
        break;
      case 'child-script':
        env.child({ source: { kind: 'argv', executable: fact.executable, args: fact.args ?? [] }, language: 'unknown', context: unit.context, origin, condition: fact.condition });
        break;
      case 'candidate':
        env.candidate(fact.kind, fact.reason, fact.knownScope, origin);
        break;
      case 'gap': {
        // env.gap(kind, origin) carries detail/line/function inside the origin
        // object when the unit origin is object-shaped.
        let gapOrigin = origin;
        if (origin && typeof origin === 'object' && !Array.isArray(origin) && (fact.detail || fact.line !== undefined || fact.function !== undefined)) {
          gapOrigin = { ...origin };
          if (fact.detail !== undefined) gapOrigin.detail = fact.detail;
          if (fact.line !== undefined) gapOrigin.line = fact.line;
          if (fact.function !== undefined) gapOrigin.function = fact.function;
        }
        env.gap(fact.kind, gapOrigin);
        break;
      }
      default:
        break;
    }
  }
}

export function createProgramAnalyzer(options = {}) {
  const python = createPythonProvider({ pythonExecutable: options.pythonExecutable });
  const js = createJsProvider({ typescript: options.typescript });
  let disposed = false;

  return {
    /**
     * Analyze one inline program unit. Reports facts via env; no return value.
     * @throws {TypeError} on malformed unit (caller contract violation)
     * @throws {ProgramAnalysisError} on provider parse faults (timeout/protocol)
     */
    async analyze(unit, env) {
      if (disposed) throw new ProgramAnalysisError('DISPOSED', 'program analyzer disposed');
      validateUnit(unit);
      if (!env || typeof env !== 'object') throw new TypeError('env must be an object');
      if (env.signal?.aborted) return;
      const limits = { ...DEFAULT_LIMITS, ...(env.limits ?? {}) };
      for (const key of ['timeoutMs', 'maxInputBytes', 'maxOutputBytes', 'maxSteps']) {
        if (!Number.isSafeInteger(limits[key]) || limits[key] < 1) throw new TypeError(`env.limits.${key} must be a positive integer`);
      }
      if (limits.deadline !== undefined && (!Number.isSafeInteger(limits.deadline) || limits.deadline <= 0)) {
        throw new TypeError('env.limits.deadline must be a positive epoch timestamp');
      }
      const text = unit.source.text;
      const context = unit.context ?? {};
      const origin = factOrigin(unit.origin, null);

      if (Buffer.byteLength(text, 'utf8') > limits.maxInputBytes) {
        env.gap('input-limit', origin);
        return;
      }
      if (!PROGRAM_LANGUAGES.has(unit.language)) {
        env.gap(SHELL_LANGUAGES.has(unit.language) ? 'no-program-provider' : 'no-provider', origin);
        return;
      }

      let outcome;
      if (unit.language === 'python') {
        try {
          outcome = await python.analyze(text, { cwd: context.cwd, platform: context.platform, limits, signal: env.signal });
        } catch (error) {
          if (error instanceof RuntimeAbsent) {
            env.gap('no-python-runtime', origin);
            return;
          }
          if (error instanceof RuntimeFailed) throw new ProgramAnalysisError('PYTHON_PARSER', error.message, { cause: error });
          throw error;
        }
      } else {
        let jsOutcome;
        try {
          jsOutcome = js.analyze(text, { language: unit.language, cwd: context.cwd, platform: context.platform, limits, signal: env.signal });
        } catch (error) {
          if (error && error.unavailable) {
            env.gap('no-typescript-runtime', origin);
            return;
          }
          if (error === 'cancelled') return;
          if (error === 'timeout') throw new ProgramAnalysisError('JS_TIMEOUT', 'js walker deadline exceeded');
          throw new ProgramAnalysisError('JS_PARSER', String(error?.message ?? error), { cause: error });
        }
        if (jsOutcome.parseDiagnostics) env.gap('parse-diagnostics', origin);
        outcome = jsOutcome;
      }

      emitFacts(unit, env, outcome.facts);
      if (outcome.truncated) env.gap('budget-exhausted', origin);
      if (outcome.stepsUsed > 0) env.step(outcome.stepsUsed);
    },

    /** Release cached runtime probes; safe to call once. */
    dispose() {
      if (disposed) return;
      disposed = true;
      python.dispose();
      js.dispose();
    },
  };
}
