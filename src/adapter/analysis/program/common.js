// common — shared vocabulary for the program (inline source) analysis providers.
//
// This module owns the fact shapes the providers emit and the mapping into the
// `env` callback contract of `createProgramAnalyzer`. It contains no analysis
// logic: providers produce plain fact objects, `program.js` maps them onto the
// env callbacks so nothing is silently dropped.
//
// Fact shapes (internal contract between providers and program.js):
//   { t: 'operation', action: 'delete'|'move-source', target, recursive: boolean,
//     condition, line, function?, details? }
//   { t: 'command', executable: string, args: (string|null)[], condition, line, function? }
//   { t: 'shell', text: string, condition, line, function? }
//   { t: 'child-script', executable: string, args: string[], condition, line, function? }
//   { t: 'candidate', kind: string, reason: string, knownScope?: string[], line, function? }
//   { t: 'gap', kind: string, detail?, line?, function? }
//
// Target shapes (AbstractPath, per docs/technical-details/架构重构设计.md):
//   { kind: 'exact', paths: string[] } | { kind: 'pattern', base, glob }
//   | { kind: 'subtree', root: string } | { kind: 'unknown', reason: string }

// Condition vocabulary from the shared API: a top-level reachable sink is
// 'certain'; a sink nested in control flow (or reachable only through
// conditional call sites) is 'possible'; unresolved reachability is 'unknown'.
export const CONDITION = Object.freeze({ CERTAIN: 'certain', POSSIBLE: 'possible', UNKNOWN: 'unknown' });

// Resource defaults; env.limits (timeoutMs, maxInputBytes, maxOutputBytes, maxSteps)
// overrides them per call.
export const DEFAULT_LIMITS = Object.freeze({
  timeoutMs: 5000,
  maxInputBytes: 1 << 20, // 1 MiB, same bound as external script files
  maxOutputBytes: 8388608,
  maxSteps: 20000,
});

// Language runtimes whose argv spawns name a program unit that the entry
// recognizer (docs/technical-details/跨语言删除分析.md「入口识别」) must handle:
// the spawned script or inline source needs its own analysis pass. Everything
// else with static argv is reported as a plain command fact.
const RUNTIME_BARE_NAMES = new Set([
  'python', 'python3', 'pythonw', 'py',
  'node', 'nodejs', 'tsx', 'ts-node', 'deno', 'bun',
  'uv', 'npm', 'pnpm', 'yarn',
]);

/**
 * Classify a statically spawned executable name.
 * - Only bare (unqualified) names are trusted as runtimes; a path-qualified
 *   name may be an arbitrary program and is reported as a command fact.
 * - `uv run ...` / `npm|pnpm|yarn run|exec ...` count as runtime spawns.
 */
export function isRuntimeSpawn(executable, args) {
  if (typeof executable !== 'string' || executable.length === 0) return false;
  if (executable.includes('/') || executable.includes('\\') || executable.includes(':')) return false;
  const base = executable.toLowerCase().replace(/\.exe$/, '');
  if (!RUNTIME_BARE_NAMES.has(base)) return false;
  const first = Array.isArray(args) ? args[0] : null;
  if ((base === 'uv' || base === 'npm' || base === 'pnpm' || base === 'yarn') && first !== 'run' && first !== 'exec') return false;
  return true;
}

// Shell dialect for an embedded shell text (os.system / child_process.exec …).
// POSIX /bin/sh is the `posix` dialect; Windows runs these through cmd.exe,
// which no provider models, so the dialect is honestly `unknown` there.
export function shellLanguageForPlatform(platform) {
  return platform === 'win32' ? 'unknown' : 'posix';
}

/**
 * Compose a per-fact origin from the unit origin plus a source location.
 * When the unit origin is an object it is extended with `line`/`function`;
 * any other origin shape is passed through unchanged (the location is then
 * only available in diagnostics of the pipeline, not lost at the fact level).
 */
export function factOrigin(unitOrigin, fact) {
  if (unitOrigin && typeof unitOrigin === 'object' && !Array.isArray(unitOrigin)) {
    const origin = { ...unitOrigin };
    if (fact && Number.isInteger(fact.line)) origin.line = fact.line;
    if (fact && typeof fact.function === 'string') origin.function = fact.function;
    return origin;
  }
  return unitOrigin;
}

/** Validate a target emitted by a provider; anything malformed becomes unknown. */
export function normalizeTarget(target) {
  if (!target || typeof target !== 'object') return { kind: 'unknown', reason: 'malformed target' };
  if (target.kind === 'exact') {
    if (Array.isArray(target.paths) && target.paths.length > 0 && target.paths.every(p => typeof p === 'string' && p.length > 0)) {
      return { kind: 'exact', paths: [...new Set(target.paths)] };
    }
    return { kind: 'unknown', reason: 'unresolved target path' };
  }
  if (target.kind === 'subtree' && typeof target.root === 'string' && target.root.length > 0) return { kind: 'subtree', root: target.root };
  if (target.kind === 'pattern' && typeof target.base === 'string' && typeof target.glob === 'string') return { kind: 'pattern', base: target.base, glob: target.glob };
  if (target.kind === 'unknown' && typeof target.reason === 'string') return { kind: 'unknown', reason: target.reason };
  return { kind: 'unknown', reason: 'unresolved target path' };
}
