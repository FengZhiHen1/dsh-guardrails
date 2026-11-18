// Wrapper / interpreter argv semantics for the shell analysis layer.
//
// Ported from the verified adapter mechanics (src/adapter/shell-analysis.mjs).
// These helpers only INSPECT the argv the official parser already produced;
// they never execute or interpret the analyzed text. Per the current split the
// shared command catalog owns wrapper routing (scripts, WSL, cmd); this module
// only decides whether an inline nested script text is provably present in the
// outer AST so the analyzer can emit an explicit nested-analysis child unit.

// Interpreter entry points whose inline script the official parser can re-parse,
// mapped to the parse dialect. `bash` -> bash dialect, `sh` -> posix dialect
// (never bash: the semantics differ).
export const SHELL_WRAPPER_DIALECT = new Map([['bash', 'bash'], ['sh', 'posix']]);
// POSIX shells with no supported grammar; their inline `-c` form is never
// guessed (a substituted grammar cannot prove inline semantics).
export const OTHER_POSIX_SHELLS = new Set(['dash', 'zsh', 'ksh', 'mksh', 'ash', 'fish']);
export const POWERSHELL_NAMES = new Set(['pwsh', 'powershell']);
export const CMD_NAMES = new Set(['cmd']);
export const WSL_NAMES = new Set(['wsl']);

const WRAPPER_BASENAMES = new Set([
  ...SHELL_WRAPPER_DIALECT.keys(),
  ...OTHER_POSIX_SHELLS,
  ...POWERSHELL_NAMES,
  ...CMD_NAMES,
  ...WSL_NAMES,
]);

/**
 * Classify a command name as a wrapper ONLY when it is a bare (unqualified)
 * command word. A path-qualified name such as `/tmp/bash` or `C:\evil\bash` is
 * NOT trusted: it may be an arbitrary attacker program, so it must not be
 * consumed as if it were the real interpreter.
 * - On a POSIX source dialect only an EXACT bare name is trusted; `BASH`,
 *   `bash.exe`, `Bash` may be arbitrary external programs and stay opaque.
 * - On a Windows/PowerShell source dialect matching is case-insensitive and a
 *   trailing `.exe` is stripped (real Windows behavior for a native command).
 * Returns `{ trusted, base, qualified? }`.
 */
export function wrapperName(name, { posix = false } = {}) {
  if (typeof name !== 'string' || name.length === 0) return { trusted: false, base: null };
  if (name.includes('/') || name.includes('\\') || name.includes(':')) return { trusted: false, base: null, qualified: true };
  if (posix) return { trusted: true, base: name };
  return { trusted: true, base: name.toLowerCase().replace(/\.exe$/, '') };
}

/** True when the path-qualified basename normalizes to a known interpreter name. */
export function interpreterShapedName(name) {
  if (typeof name !== 'string' || name.length === 0) return false;
  const base = name.split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, '');
  return WRAPPER_BASENAMES.has(base);
}

/**
 * Detect a bare name that only LOOKS like a known interpreter after POSIX
 * untrusted normalization (case fold or `.exe` strip). Such a name may be an
 * arbitrary external program, so it must never be unwrapped.
 */
export function looksLikeOpaqueInterpreter(name, posix) {
  if (typeof name !== 'string' || name.length === 0) return false;
  if (name.includes('/') || name.includes('\\') || name.includes(':')) return false;
  if (!posix) return false;
  const folded = name.toLowerCase().replace(/\.exe$/, '');
  if (name === folded) return false; // exact bare name: a genuine trusted wrapper
  return WRAPPER_BASENAMES.has(folded);
}

/**
 * Enumerate the options of an interpreter invocation to locate the inline script.
 * Returns `{ script, hasFileArg, dynamic, encoded?, unknownReason }`:
 * - `script`: literal inline-script string when `-c`/`-Command` is present and literal;
 * - `hasFileArg`: a script-file argument (or encoded command) is present (opaque;
 *   the shared catalog owns script routing);
 * - `dynamic`: the relevant argument was dynamic / unprovable;
 * - `encoded`: an `-EncodedCommand` payload is present;
 * - `unknownReason`: non-null when the invocation carries options whose effect we
 *   cannot prove (unknown flags, startup/profile options, login/interactive
 *   shells, missing -NoProfile, trailing args after -Command). The analyzer maps
 *   these to explicit gap kinds; nothing is silently dropped.
 */
export function interpreterInlineScript(args, { powershell = false } = {}) {
  let i = 0;
  const valueOptions = new Set(['-o', '+o']);
  const startupOptions = new Set(['--rcfile', '--init-file', '--profile', '-profile']);
  // PowerShell: ONLY these simple startup flags are treated as safe (no state/config change).
  const psSafeSwitches = new Set(['-noprofile', '-nop', '-nologo', '-nol', '-noninteractive', '-noni']);
  // These change cwd/config/environment (or enter an interactive session), so even when
  // their value is consumed the inner execution context is NOT proven: they yield a gap.
  const psUnsafeValueOptions = new Set(['-workingdirectory', '-wd', '-executionpolicy', '-ep', '-windowstyle', '-version', '-v', '-configurationname', '-inputformat', '-outputformat', '-psconsolefile', '-custompipename']);
  const psUnsafeSwitches = new Set(['-noexit']);
  let optionUnknown = null;
  const merge = (reason) => {
    if (!reason) return optionUnknown;
    return optionUnknown ? `${optionUnknown}; ${reason}` : reason;
  };
  let psNoProfile = false;
  while (i < args.length) {
    const arg = args[i];
    if (arg === null || typeof arg !== 'string') return { script: null, hasFileArg: false, dynamic: true, unknownReason: optionUnknown };
    if (arg === '--') { i += 1; return attach(fileOrRest(args, i), optionUnknown); }
    if (powershell) {
      const lower = arg.toLowerCase();
      if (lower === '-noprofile' || lower === '-nop') { psNoProfile = true; i += 1; continue; }
      if (lower === '-command' || lower === '-c') {
        const next = args[i + 1];
        if (next === undefined || next === null || typeof next !== 'string') {
          return { script: null, hasFileArg: false, dynamic: true, unknownReason: optionUnknown };
        }
        const trailing = args.slice(i + 2);
        if (trailing.length > 0) {
          return { script: null, hasFileArg: false, dynamic: false, unknownReason: merge('PowerShell -Command followed by extra arguments; command string not provable') };
        }
        const baseUnknown = !psNoProfile ? 'PowerShell inner invocation without -NoProfile may load profile startup code' : null;
        return { script: next, hasFileArg: false, dynamic: false, unknownReason: merge(baseUnknown) };
      }
      if (lower === '-encodedcommand' || lower === '-ec') {
        return { script: null, hasFileArg: true, dynamic: false, encoded: true, unknownReason: optionUnknown };
      }
      if (lower === '-file' || lower === '-f') {
        // The value names a script file; the remaining words are that script's arguments.
        // Without -NoProfile the profile startup code can redefine the commands the script
        // runs, so the text alone would not prove the real effect: flag it like -Command.
        const fileUnknown = !psNoProfile ? 'PowerShell script-file invocation without -NoProfile may load profile startup code' : null;
        const next = args[i + 1];
        if (next === undefined || next === null || typeof next !== 'string') {
          return { script: null, hasFileArg: true, dynamic: true, unknownReason: merge(fileUnknown) };
        }
        return { script: null, hasFileArg: true, dynamic: false, unknownReason: merge(fileUnknown), scriptFile: next };
      }
      if (psUnsafeValueOptions.has(lower)) {
        // Consume the value (not a program/command string) but the context is NOT proven.
        const value = args[i + 1];
        optionUnknown = merge(`PowerShell option '${arg}' changes execution context (cwd/config/environment); inner target not proven`);
        if (value === undefined || value === null || typeof value !== 'string') {
          return { script: null, hasFileArg: false, dynamic: true, unknownReason: optionUnknown };
        }
        i += 2;
        continue;
      }
      if (psUnsafeSwitches.has(lower)) {
        optionUnknown = merge(`PowerShell option '${arg}' enters an interactive session; context not proven`);
        i += 1;
        continue;
      }
      if (psSafeSwitches.has(lower)) { i += 1; continue; }
      if (lower.startsWith('-')) {
        return { script: null, hasFileArg: false, dynamic: false, unknownReason: merge(`PowerShell option '${arg}' is not modeled`) };
      }
      // First bare word in PowerShell option position: the command string itself.
      const baseUnknown = !psNoProfile ? 'PowerShell inner invocation without -NoProfile may load profile startup code' : null;
      return { script: arg, hasFileArg: false, dynamic: false, unknownReason: merge(baseUnknown) };
    }
    // POSIX-style interpreter.
    if (startupOptions.has(arg)) {
      return { script: null, hasFileArg: false, dynamic: false, unknownReason: `Interpreter startup option '${arg}' can run arbitrary startup code` };
    }
    // A `+`-prefixed cluster disables options (e.g. `+c`); it never requests an inline
    // command string. `bash +c 'x'` runs `x` as a script file, not as a command.
    if (arg.length > 1 && arg[0] === '+' && !arg.startsWith('++')) {
      return { script: null, hasFileArg: false, dynamic: false, unknownReason: `Interpreter '${arg}' is an option-disabling form; inline command not proven` };
    }
    if (arg.length > 1 && arg[0] === '-' && !arg.startsWith('--')) {
      const cluster = arg.slice(1);
      if (cluster.includes('c')) {
        const next = args[i + 1];
        if (next === undefined || next === null || typeof next !== 'string') {
          return { script: null, hasFileArg: false, dynamic: true, unknownReason: optionUnknown };
        }
        // Only an EXACT `-c` is a silently-accepted inline-command flag. Any combined
        // cluster (e.g. -lc/-ic/-ec/-xc) still lets us extract the script, but the other
        // flags are not proven safe, so it must carry an explicit unknown.
        if (cluster !== 'c') {
          optionUnknown = merge(`Interpreter flags '-${cluster}' alongside -c are not proven safe`);
        }
        return { script: next, hasFileArg: false, dynamic: false, unknownReason: optionUnknown };
      }
      if (cluster.includes('l') || cluster.includes('i')) {
        return { script: null, hasFileArg: false, dynamic: false, unknownReason: merge(`Interpreter flags '-${cluster}' can load startup/profile code`) };
      }
      // `-o <value>` consumes a following value but alters shell behavior; not proven safe.
      if (cluster === 'o') {
        optionUnknown = merge(`Interpreter option '-o' is not proven safe`);
        i += 2;
        continue;
      }
      return { script: null, hasFileArg: false, dynamic: false, unknownReason: merge(`Interpreter option '${arg}' is not modeled`) };
    }
    if (valueOptions.has(arg)) {
      optionUnknown = merge(`Interpreter option '${arg}' is not proven safe`);
      i += 2;
      continue;
    }
    if (arg.startsWith('--')) {
      return { script: null, hasFileArg: false, dynamic: false, unknownReason: merge(`Interpreter option '${arg}' is not modeled`) };
    }
    // First bare word: a script path passed to the interpreter. Script-file routing
    // (bounded read and re-parse) belongs to the shared command catalog.
    return fileOrRest(args, i);
  }
  // No inline script and no file arg: an interactive shell. Its startup files may run code.
  return { script: null, hasFileArg: false, dynamic: false, unknownReason: 'Interactive shell (no inline script) may run startup/profile code' };
}

function fileOrRest(args, i) {
  const word = args[i];
  if (word === null || typeof word !== 'string') {
    return { script: null, hasFileArg: false, dynamic: true, unknownReason: null };
  }
  return { script: null, hasFileArg: true, dynamic: false, unknownReason: null, scriptFile: word };
}

/** Attach an accumulated option-unknown reason to a result object. */
function attach(result, extra) {
  if (!extra) return result;
  return { ...result, unknownReason: result.unknownReason ? `${result.unknownReason}; ${extra}` : extra };
}
