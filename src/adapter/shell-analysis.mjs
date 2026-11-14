// shell-analysis — bounded recursive unwrapping of known shell wrapper commands.
//
// Boundary: this module only re-parses *text* through the official parsers. It never
// interprets, evaluates or executes inspected text; it never spawns the inspected
// shell. Wrap detection trusts only the argv the official parser already produced and
// never claims that the outer AST equals the native argv of a downstream interpreter.
// Anything ambiguous or unsupported is preserved (as a command or as an explicit
// unknown reason) so a downstream gate can reject it. Nothing may silently disappear.
//
// External script files: `bash|sh|dash|zsh <script>` and `pwsh|powershell -File <script>`
// name a script file instead of inline text. For those forms this adapter reads the file
// with BOUNDED, metadata-only-then-content IO (regular non-symlink file, <= 1 MiB,
// decidable encoding) and re-parses the decoded text as its shell dialect, so the inner
// commands become analyzable facts instead of an opaque "external script file". The text
// is still never executed. Every failure to prove the file's content (non-literal or
// dynamic path, missing/unreadable file, symlink, non-regular, oversize, undecodable,
// unprovable working directory, non-host domain) emits an explicit unknown so the caller
// denies; no failure path may fall through to "allow".

import fs from 'node:fs/promises';
import path from 'node:path';

// Interpreter entry points the official parser can re-parse, mapped to the parse dialect.
// `bash` -> bash dialect, `sh` -> posix dialect (never bash: semantics differ).
const SHELL_WRAPPER_DIALECT = new Map([['bash', 'bash'], ['sh', 'posix']]);
// POSIX shells the official parser does not support; never guessed as bash.
const OTHER_POSIX_SHELLS = new Set(['dash', 'zsh', 'ksh', 'mksh', 'ash', 'fish']);
// Script-FILE forms are also analyzed for the two additional POSIX shells whose grammar
// has a faithful-enough supported counterpart: dash is strict POSIX -> posix grammar;
// zsh is parsed with the bash grammar (closest supported dialect; zsh-specific syntax the
// bash grammar does not model still surfaces as an unknown from the parser). Their INLINE
// `-c` form stays unsupported: a substituted grammar cannot prove inline semantics.
const OTHER_SHELL_SCRIPT_DIALECT = new Map([['dash', 'posix'], ['zsh', 'bash']]);
const POWERSHELL_NAMES = new Set(['pwsh', 'powershell']);
const CMD_NAMES = new Set(['cmd']);
const WSL_NAMES = new Set(['wsl']);

// Default resource budget for the whole recursive analysis of one invocation.
const DEFAULT_BUDGET = Object.freeze({
  maxDepth: 8,          // wrapper nesting depth
  maxParseCalls: 24,    // total official parser invocations across the whole analysis
  maxCommands: 4096,    // total command IR entries retained
});

// Hard bound for an external script file that may be read and re-parsed. A larger file is
// not analyzed at all: its target set would not be bounded by the analysis budget.
const MAX_SCRIPT_FILE_BYTES = 1 << 20; // 1 MiB
// UTF byte-order marks that identify an encoding we accept.
const BOM_UTF8 = [0xef, 0xbb, 0xbf];
const BOM_UTF16LE = [0xff, 0xfe];
const BOM_UTF16BE = [0xfe, 0xff];
const BOM_UTF32LE = [0xff, 0xfe, 0x00, 0x00];

/**
 * Classify a command name as a wrapper ONLY when it is a bare (unqualified) command word.
 * A path-qualified name such as `/tmp/bash.exe` or `.\pwsh.exe` is NOT trusted: it may be an
 * arbitrary attacker program, so we must not consume it as if it were the real interpreter.
 * Returns `{ trusted: boolean, base: string|null }`.
 */
/**
 * Classify a command name as a wrapper.
 * - Reject path-qualified names (`/tmp/bash`, `C:\evil\bash`, `./pwsh`) — never trusted.
 * - On a POSIX source dialect, only an EXACT bare name (`bash`, `sh`, `pwsh`, `wsl`) is a
 *   trusted wrapper; `BASH`, `bash.exe`, `Bash` may be an arbitrary external program, so
 *   they are NOT unwrapped (the caller keeps them + unknown).
 * - On a Windows/PowerShell source dialect, matching is case-insensitive and a trailing
 *   `.exe` is stripped (real Windows behavior for a native command).
 * Returns `{ trusted, base, qualified? , caseOrExeMismatch? }`.
 */
function wrapperName(name, { posix = false } = {}) {
  if (typeof name !== 'string' || name.length === 0) return { trusted: false, base: null };
  if (name.includes('/') || name.includes('\\') || name.includes(':')) return { trusted: false, base: null, qualified: true };
  if (posix) {
    // Exact, case-sensitive bare interpreter names only.
    return { trusted: true, base: name };
  }
  return { trusted: true, base: name.toLowerCase().replace(/\.exe$/, '') };
}

/**
 * Enumerate the options of an interpreter invocation to locate the inline script.
 * Returns `{ script, hasFileArg, dynamic, unknownReason }`:
 * - `script`: literal inline-script string when `-c`/`-Command` is present and literal;
 * - `hasFileArg`: a script-file argument (or encoded command) is present (opaque);
 * - `dynamic`: the relevant argument was dynamic (`null`) / unprovable;
 * - `unknownReason`: non-null when the invocation carries options we cannot prove safe
 *   (unknown flags, startup/profile options, login/interactive shells, missing -NoProfile,
 *   trailing args after -Command). The caller must surface this as explicit unknown.
 */
function interpreterInlineScript(args, { powershell = false } = {}) {
  let i = 0;
  const valueOptions = new Set(['-o', '+o']);
  const startupOptions = new Set(['--rcfile', '--init-file', '--profile', '-profile']);
  // PowerShell: ONLY these simple startup flags are treated as safe (no state/config change).
  const psSafeSwitches = new Set(['-noprofile', '-nop', '-nologo', '-nol', '-noninteractive', '-noni']);
  // These change cwd/config/environment (or enter an interactive session), so even when their
  // value is consumed the inner execution context is NOT proven: they must yield unknown.
  // `-WorkingDirectory` changes the inner cwd (relative deletes would be counted in the wrong
  // directory); `-ConfigurationName`/`-PSConsoleFile`/`-CustomPipeName` load a different
  // environment; `-ExecutionPolicy`/`-WindowStyle`/`-Version`/`-InputFormat`/`-OutputFormat`
  // alter behavior; `-NoExit` enters an interactive session.
  const psUnsafeValueOptions = new Set(['-workingdirectory', '-wd', '-executionpolicy', '-ep', '-windowstyle', '-version', '-v', '-configurationname', '-inputformat', '-outputformat', '-psconsolefile', '-custompipename']);
  const psUnsafeSwitches = new Set(['-noexit']);
  // Accumulated unknowns from options seen; any return path must carry them.
  let optionUnknown = null;
  const merge = (reason) => {
    if (!reason) return optionUnknown;
    return optionUnknown ? `${optionUnknown}; ${reason}` : reason;
  };
  let psNoProfile = false;
  while (i < args.length) {
    const arg = args[i];
    if (arg === null) return { script: null, hasFileArg: false, dynamic: true, unknownReason: optionUnknown };
    if (typeof arg !== 'string') return { script: null, hasFileArg: false, dynamic: true, unknownReason: optionUnknown };
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
        return { script: null, hasFileArg: true, dynamic: false, unknownReason: optionUnknown };
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
    // A `+`-prefixed cluster disables options (e.g. `+c`), it never requests an inline
    // command string. `bash +c 'x'` runs `x` as a script file, not as a command. Do not
    // unwrap it as if it were `-c`; treat as unmodeled (keep wrapper + unknown).
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
    // First bare word: a script path passed to the interpreter (opaque contents).
    return attach(fileOrRest(args, i), optionUnknown);
  }
  // No inline script and no file arg: an interactive shell. Its startup files may run code.
  return { script: null, hasFileArg: false, dynamic: false, unknownReason: 'Interactive shell (no inline script) may run startup/profile code' };
}

function fileOrRest(args, i) {
  const word = args[i];
  if (word === null || typeof word !== 'string') {
    return { script: null, hasFileArg: false, dynamic: true, unknownReason: null };
  }
  // A bare script-file word is only *named* here. Whether it may be read and re-parsed is
  // decided later by expandScriptFile; an unprovable file must still be surfaced as unknown.
  return { script: null, hasFileArg: true, dynamic: false, unknownReason: null, scriptFile: word };
}

/** Attach an accumulated option-unknown reason to a result object. */
function attach(result, extra) {
  if (!extra) return result;
  return { ...result, unknownReason: result.unknownReason ? `${result.unknownReason}; ${extra}` : extra };
}

/**
 * Parse a WSL invocation's argv to locate the Linux-side program and its arguments.
 * Only explicit flags are honored; anything not understood is reported (never guessed).
 */
function parseWslArgs(args) {
  const result = { program: null, programArgs: [], distribution: undefined, user: undefined, cwd: undefined, exec: false, dynamic: false, unknownOption: undefined };
  let i = 0;
  const valueOptions = new Set(['--distribution', '-d', '--user', '-u', '--cd', '--cwd', '--shell-type', '--system']);
  while (i < args.length) {
    const arg = args[i];
    if (arg === null) { result.dynamic = true; return result; }
    if (typeof arg !== 'string') { result.dynamic = true; return result; }
    if (arg === '--exec' || arg === '-e') { result.exec = true; i += 1; continue; }
    if (arg === '--') { i += 1; break; }
    if (valueOptions.has(arg)) {
      const value = args[i + 1];
      if (arg === '--distribution' || arg === '-d') result.distribution = value ?? undefined;
      else if (arg === '--user' || arg === '-u') result.user = value ?? undefined;
      else if (arg === '--cd' || arg === '--cwd') result.cwd = value ?? undefined;
      i += 2;
      continue;
    }
    if (arg.startsWith('-') && arg !== '-') {
      result.unknownOption = arg;
      i += 1;
      continue;
    }
    result.program = arg;
    result.programArgs = args.slice(i + 1);
    return result;
  }
  return result;
}

/**
 * Recursively analyze a shell invocation, unwrapping known wrapper commands.
 *
 * @param {object} opts
 * @param {'powershell'|'bash'|'posix'} opts.dialect  Dialect of the *source*.
 * @param {string} opts.source   The shell text to analyze (data, never executed).
 * @param {{parse:(d:string,s:string,o?:object)=>Promise<{commands:Array,unknown:Array}>}} opts.parsers
 * @param {string=} opts.cwd     Provable working directory of the outermost invocation.
 * @param {AbortSignal=} opts.signal
 * @returns {Promise<{commands:Array, unknown:string[]}>}
 */
export async function analyzeShell({ dialect, source, parsers, cwd, signal } = {}) {
  if (typeof source !== 'string') throw new TypeError('analyzeShell: source must be a string');
  if (!parsers || typeof parsers.parse !== 'function') throw new TypeError('analyzeShell: parsers.parse is required');
  const normalized = normalizeDialect(dialect);
  const budget = { ...DEFAULT_BUDGET };
  const state = { parses: 0, emitted: 0 };
  const unknown = new Set();

  const outCommands = [];
  await unwrapInto({ parsers, dialect: normalized, source, domain: 'host', cwd, signal, depth: 0, state, budget, unknown, outCommands });
  return { commands: outCommands, unknown: [...unknown] };
}

function normalizeDialect(dialect) {
  if (dialect === 'pwsh') return 'powershell';
  if (dialect === 'posix') return 'posix';
  if (dialect === 'powershell' || dialect === 'bash') return dialect;
  throw new TypeError(`analyzeShell: unsupported dialect ${String(dialect)}`);
}

async function unwrapInto(ctx) {
  const { source, dialect, domain, cwd, signal, depth, state, budget, unknown, outCommands, distribution, user, inheritedRedirects } = ctx;
  if (signal?.aborted) throw new ShellAbortError();
  if (depth > budget.maxDepth) { unknown.add('Wrapper nesting depth budget exceeded'); return; }
  if (state.parses >= budget.maxParseCalls) { unknown.add('Parser call budget exceeded'); return; }
  let parsed;
  state.parses += 1;
  parsed = await ctx.parsers.parse(dialect, source, { signal }); // parser failure propagates (fail-closed)
  for (const reason of parsed.unknown ?? []) unknown.add(String(reason));
  flagStateInvalidation(parsed.commands ?? [], dialect, unknown);
  for (const command of parsed.commands ?? []) {
    if (state.emitted >= budget.maxCommands) { unknown.add('Command budget exceeded'); return; }
    // eslint-disable-next-line no-await-in-loop
    const handled = await expandWrapper({ ...ctx, command, dialect, domain, cwd, depth, distribution, user, inheritedRedirects });
    if (!handled) {
      emit(outCommands, command, { dialect, domain, cwd, distribution, user, inheritedRedirects });
      state.emitted += 1;
    }
  }
}

// Commands that mutate shell/session state so a fixed target set is not trustworthy.
const BASH_STATE_MUTATORS = new Set(['cd', 'pushd', 'popd', 'alias', 'unalias', 'export', 'unset', 'declare', 'typeset', 'local', 'readonly', 'source', '.', 'eval', 'exec', 'trap', 'set', 'shopt', 'enable', 'hash', 'builtin', 'command']);
const POWERSHELL_STATE_MUTATORS = new Set(['cd', 'set-location', 'sl', 'chdir', 'push-location', 'pop-location', 'set-variable', 'new-variable', 'remove-variable', 'set-item', 'new-item', 'invoke-expression', 'iex', 'import-module', 'set-alias', 'new-alias', 'set-executionpolicy', 'set-psdebug', '.']);

/** Mark state-invalidating command constructs as explicit unknown. */
function flagStateInvalidation(commands, dialect, unknown) {
  const mutators = dialect === 'powershell' ? POWERSHELL_STATE_MUTATORS : BASH_STATE_MUTATORS;
  const posix = isPosixDialect(dialect);
  for (const command of commands) {
    const { trusted, base } = wrapperName(command.name, { posix });
    if (!trusted || base === null) continue;
    // State-mutator names are matched case-insensitively here (conservative: flagging more).
    if (mutators.has(base.toLowerCase())) unknown.add(`State-changing command '${base}' invalidates a fixed target set`);
  }
}

/** True when the source dialect treats command names case-sensitively (POSIX shells). */
function isPosixDialect(dialect) {
  return dialect === 'bash' || dialect === 'posix';
}

/**
 * Detect a name that only *looks like* a known interpreter after POSIX-untrusted
 * normalization (case fold or `.exe` strip). Such a name may be an arbitrary external
 * program, so it must never be unwrapped and must be surfaced as opaque.
 */
function looksLikeOpaqueInterpreter(name, posix) {
  if (typeof name !== 'string' || name.length === 0) return false;
  if (name.includes('/') || name.includes('\\') || name.includes(':')) return false;
  if (!posix) return false;
  const folded = name.toLowerCase().replace(/\.exe$/, '');
  // Exact bare lowercase name is a genuine trusted wrapper (handled elsewhere); only a
  // name that resembles an interpreter AFTER case-folding / .exe-stripping is opaque.
  if (name === folded) return false;
  return SHELL_WRAPPER_DIALECT.has(folded) || POWERSHELL_NAMES.has(folded) || WSL_NAMES.has(folded) || OTHER_POSIX_SHELLS.has(folded);
}

/**
 * Emit a command enriched with dialect/domain/cwd and any redirects inherited from the
 * wrapper that produced it. Wrapper redirects/scope must never be silently dropped.
 */
function emit(outCommands, command, { dialect, domain, cwd, distribution, user, inheritedRedirects }) {
  const enriched = { ...command, dialect, domain };
  if (typeof cwd === 'string') enriched.cwd = cwd;
  if (domain === 'wsl') {
    if (distribution !== undefined) enriched.distribution = distribution;
    if (user !== undefined) enriched.user = user;
  }
  if (Array.isArray(inheritedRedirects) && inheritedRedirects.length > 0) {
    enriched.redirects = [...(command.redirects ?? []), ...inheritedRedirects];
  }
  outCommands.push(enriched);
}

// ---- External script files -------------------------------------------------
// These helpers only READ a bounded, literal script file and hand its decoded text to the
// official parser. Nothing here executes, sources or evaluates the file.

function startsWithBytes(bytes, prefix) {
  if (bytes.length < prefix.length) return false;
  for (let index = 0; index < prefix.length; index += 1) {
    if (bytes[index] !== prefix[index]) return false;
  }
  return true;
}

/**
 * Decode script bytes with a DECIDABLE encoding only: UTF-8 (with or without BOM) or
 * UTF-16LE with a BOM. Anything else (UTF-16BE, UTF-32, BOM-less UTF-16, invalid UTF-8) is
 * undecidable from the bytes and must be refused, never guessed.
 * @returns {{ok: true, text: string} | {ok: false, detail: string}}
 */
function decodeScriptBytes(bytes) {
  if (startsWithBytes(bytes, BOM_UTF32LE)) {
    return { ok: false, detail: 'declares a UTF-32LE byte-order mark, an unsupported encoding' };
  }
  if (startsWithBytes(bytes, BOM_UTF8)) {
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(BOM_UTF8.length));
      return { ok: true, text };
    } catch {
      return { ok: false, detail: 'declares a UTF-8 byte-order mark but its body is not valid UTF-8' };
    }
  }
  if (startsWithBytes(bytes, BOM_UTF16BE)) {
    return { ok: false, detail: 'declares a UTF-16BE byte-order mark, an unsupported encoding' };
  }
  if (startsWithBytes(bytes, BOM_UTF16LE)) {
    if (bytes.length % 2 !== 0) {
      return { ok: false, detail: 'declares a UTF-16LE byte-order mark but has an odd byte length' };
    }
    try {
      const text = new TextDecoder('utf-16le', { fatal: true }).decode(bytes.subarray(BOM_UTF16LE.length));
      return { ok: true, text };
    } catch {
      return { ok: false, detail: 'declares a UTF-16LE byte-order mark but its body is not valid UTF-16LE' };
    }
  }
  // No BOM: only strict UTF-8 is decidable. A BOM-less UTF-16 body is invalid UTF-8 in
  // practice; if it ever decoded, the NUL guard below still refuses it.
  try {
    return { ok: true, text: new TextDecoder('utf-8', { fatal: true }).decode(bytes) };
  } catch {
    return { ok: false, detail: 'is not valid UTF-8 and carries no byte-order mark that proves another encoding' };
  }
}

/**
 * Resolve and read one literal script file under strict metadata and encoding rules.
 * @param {unknown} scriptFile Literal path named on the command line.
 * @param {string|undefined} cwd Provable working directory for a relative path.
 * @returns {Promise<{ok: true, text: string, resolved: string} | {ok: false, detail: string}>}
 */
async function readScriptFile(scriptFile, cwd) {
  if (typeof scriptFile !== 'string' || scriptFile.length === 0) {
    return { ok: false, detail: 'path is not a literal, non-empty string' };
  }
  if (scriptFile.includes('\u0000')) return { ok: false, detail: 'path contains a NUL byte' };
  if (scriptFile === '-') return { ok: false, detail: 'reads standard input rather than a regular file' };
  let resolved;
  if (path.isAbsolute(scriptFile)) {
    resolved = path.normalize(scriptFile);
  } else if (typeof cwd === 'string' && path.isAbsolute(cwd)) {
    resolved = path.resolve(cwd, scriptFile);
  } else {
    return { ok: false, detail: 'is a relative path with no provable working directory' };
  }
  let info;
  try {
    info = await fs.lstat(resolved);
  } catch (error) {
    return { ok: false, detail: `could not be inspected (${error?.code ?? error?.name ?? 'error'})` };
  }
  // A symlink is refused: the text we could read is not proven to be the text that runs.
  if (info.isSymbolicLink()) return { ok: false, detail: 'is a symbolic link, so its executed text is not provable' };
  if (!info.isFile()) return { ok: false, detail: 'is not a regular file' };
  if (info.size > MAX_SCRIPT_FILE_BYTES) {
    return { ok: false, detail: `exceeds the ${MAX_SCRIPT_FILE_BYTES}-byte script-analysis limit` };
  }
  let bytes;
  try {
    bytes = await fs.readFile(resolved);
  } catch (error) {
    return { ok: false, detail: `could not be read (${error?.code ?? error?.name ?? 'error'})` };
  }
  // Re-check the read length: the file could grow between lstat and readFile.
  if (bytes.length > MAX_SCRIPT_FILE_BYTES) {
    return { ok: false, detail: `exceeds the ${MAX_SCRIPT_FILE_BYTES}-byte script-analysis limit` };
  }
  const decoded = decodeScriptBytes(bytes);
  if (!decoded.ok) return decoded;
  // NUL text means the bytes were not the encoding we assumed; the parser would silently
  // miss every command, so refuse instead.
  if (decoded.text.includes('\u0000')) {
    return { ok: false, detail: 'decodes to text containing NUL bytes, so its encoding is not decidable' };
  }
  return { ok: true, text: decoded.text, resolved };
}

/**
 * Read a literal script file and analyze its text as `innerDialect`, splicing the resulting
 * commands like the inline `-c` path. Returns true only when the file WAS analyzed; every
 * failure emits an explicit unknown and returns false so the wrapper stays visible.
 */
async function expandScriptFile(ctx, base, scriptFile, innerDialect) {
  const { unknown, domain } = ctx;
  // A non-host (WSL) domain cannot be read through this host's filesystem view.
  if (domain !== 'host') {
    unknown.add(`Interpreter '${base}' runs a script file in a non-host (${domain}) domain; its contents cannot be read from here`);
    return false;
  }
  const loaded = await readScriptFile(scriptFile, ctx.cwd);
  if (!loaded.ok) {
    unknown.add(`Interpreter '${base}' script file '${String(scriptFile)}' ${loaded.detail}; contents not analyzed`);
    return false;
  }
  const redirects = [...(ctx.inheritedRedirects ?? []), ...wrapperRedirects(ctx.command)];
  try {
    await unwrapInto({
      ...ctx,
      source: loaded.text,
      dialect: innerDialect,
      depth: ctx.depth + 1,
      inheritedRedirects: redirects,
    });
  } catch (error) {
    // A parser rejection inside an external file means its target set is not provable.
    // Surface that as an unknown instead of letting it read as an ordinary parse failure;
    // the caller keeps the wrapper command visible, so the invocation still denies.
    unknown.add(`Interpreter '${base}' script file '${String(scriptFile)}' could not be parsed as ${innerDialect}: ${error?.message ?? 'parse error'}`);
    return false;
  }
  return true;
}

/**
 * Attempt to consume a known wrapper command by recursively analyzing its inner script.
 * Returns true when the wrapper was fully consumed; false when it should be kept as-is.
 */
async function expandWrapper(ctx) {
  const { command, unknown, dialect } = ctx;
  if (command.name === null) return false; // dynamic command name — upstream already unknown
  const posix = isPosixDialect(dialect);
  const { trusted, base, qualified } = wrapperName(command.name, { posix });
  if (qualified) {
    // A path-qualified "interpreter" (e.g. /tmp/bash.exe) is not trusted; never consume it.
    unknown.add(`Path-qualified interpreter '${command.name}' is not a trusted wrapper and was not unwrapped`);
    return false;
  }
  if (looksLikeOpaqueInterpreter(command.name, posix)) {
    // e.g. POSIX `BASH`/`bash.exe`/`BaSh`: only looks like an interpreter after untrusted
    // normalization; it may be an arbitrary external program. Keep it opaque + flag.
    unknown.add(`Command '${command.name}' resembles an interpreter but is not an exact trusted name; possible opaque program`);
    return false;
  }
  if (!trusted || base === null) return false;

  if (WSL_NAMES.has(base)) return expandWsl(ctx, base);

  const innerDialect = SHELL_WRAPPER_DIALECT.get(base);
  if (innerDialect) return expandInterpreter(ctx, base, innerDialect);

  if (POWERSHELL_NAMES.has(base)) return expandInterpreter(ctx, base, 'powershell');

  if (OTHER_POSIX_SHELLS.has(base)) {
    // A script-FILE form is analyzable for the shells with a supported grammar counterpart.
    // Their inline `-c` form stays unsupported (a substituted grammar cannot prove inline
    // semantics), so only a named literal file is considered here.
    const scriptDialect = OTHER_SHELL_SCRIPT_DIALECT.get(base);
    if (scriptDialect) {
      const inline = interpreterInlineScript(command.args ?? [], { powershell: false });
      if (inline.unknownReason) unknown.add(`Interpreter '${base}': ${inline.unknownReason}`);
      if (typeof inline.scriptFile === 'string') {
        return expandScriptFile(ctx, base, inline.scriptFile, scriptDialect);
      }
    }
    // We cannot parse these as any supported dialect; keep visible and flag.
    unknown.add(`Unsupported shell interpreter '${base}' cannot be parsed by official parsers`);
    return false;
  }

  if (CMD_NAMES.has(base)) {
    const args = command.args ?? [];
    const flagIndex = args.findIndex(a => typeof a === 'string' && /^\/[ck]$/i.test(a));
    if (flagIndex >= 0) unknown.add('Windows cmd inline command cannot be parsed by official parsers');
    return false;
  }

  return false;
}

// Wrapper redirects must survive consumption: hand them down to emitted inner commands.
function wrapperRedirects(command) {
  return Array.isArray(command.redirects) ? command.redirects : [];
}

async function expandInterpreter(ctx, base, innerDialect) {
  const { command, unknown } = ctx;
  const inline = interpreterInlineScript(command.args ?? [], { powershell: innerDialect === 'powershell' });
  if (inline.unknownReason) unknown.add(`Interpreter '${base}': ${inline.unknownReason}`);
  if (inline.dynamic) {
    unknown.add(`Interpreter '${base}' inner script is dynamic or unprovable`);
    return false;
  }
  if (inline.hasFileArg) {
    // A literal script file named on the command line is read (bounded) and re-parsed as
    // this interpreter's dialect; any unprovable file is reported as unknown, never allowed.
    if (typeof inline.scriptFile === 'string') {
      return expandScriptFile(ctx, base, inline.scriptFile, innerDialect);
    }
    unknown.add(`Interpreter '${base}' runs an external script file or encoded command; contents not analyzed`);
    return false;
  }
  if (inline.script === null) {
    // Interactive shell with no inline script — never drop silently; keep + unknown (set above).
    if (!inline.unknownReason) unknown.add(`Interpreter '${base}' has no inline script to analyze`);
    return false;
  }
  const redirects = [...(ctx.inheritedRedirects ?? []), ...wrapperRedirects(command)];
  await unwrapInto({ ...ctx, source: inline.script, dialect: innerDialect, depth: ctx.depth + 1, inheritedRedirects: redirects });
  return true;
}

async function expandWsl(ctx, base) {
  const { command, unknown, outCommands } = ctx;
  const wsp = parseWslArgs(command.args ?? []);
  if (wsp.dynamic) { unknown.add(`wsl '${base}' arguments are dynamic; inner program not provable`); return false; }
  if (wsp.unknownOption) { unknown.add(`wsl option '${wsp.unknownOption}' is not modeled; inner program boundary unproven`); return false; }
  if (!wsp.program) {
    // Bare `wsl` (interactive login shell) — its startup may run code; keep + unknown.
    unknown.add('wsl with no explicit program launches an interactive shell that may run startup code');
    return false;
  }
  const wslContext = {
    ...ctx,
    domain: 'wsl',
    cwd: wsp.cwd !== undefined ? wsp.cwd : ctx.cwd,
    distribution: wsp.distribution,
    user: wsp.user,
    inheritedRedirects: [...(ctx.inheritedRedirects ?? []), ...wrapperRedirects(command)],
  };
  const { trusted, base: programBase, qualified } = wrapperName(wsp.program, { posix: true });
  let innerDialect = trusted ? SHELL_WRAPPER_DIALECT.get(programBase) : undefined;
  if (trusted && POWERSHELL_NAMES.has(programBase)) innerDialect = 'powershell';
  if (!wsp.exec) {
    // Without --exec, WSL runs the program through the distribution's default login shell,
    // so argument/glob expansion is not provable from argv alone. Flag it (still extract facts).
    unknown.add('wsl command runs via the default WSL shell; argv/expansion unproven');
  }
  if (innerDialect) {
    return expandWslInterpreter(ctx, wsp, programBase, innerDialect, wslContext);
  }
  // Inner program is not a parseable shell: keep it as an explicit command with wsl domain.
  const synthetic = { name: wsp.program, args: wsp.programArgs, redirects: [], scope: command.scope };
  if (qualified || OTHER_POSIX_SHELLS.has(programBase) || CMD_NAMES.has(programBase) || POWERSHELL_NAMES.has(programBase)) {
    unknown.add(`wsl runs '${wsp.program}' which cannot be reliably parsed`);
  }
  emit(outCommands, synthetic, { dialect: 'posix', domain: 'wsl', cwd: wslContext.cwd, distribution: wslContext.distribution, user: wslContext.user, inheritedRedirects: wslContext.inheritedRedirects });
  ctx.state.emitted += 1;
  return true;
}

async function expandWslInterpreter(ctx, wsp, programBase, innerDialect, wslContext) {
  const inline = interpreterInlineScript(wsp.programArgs, { powershell: innerDialect === 'powershell' });
  if (inline.unknownReason) wslContext.unknown.add(`wsl inner interpreter '${programBase}': ${inline.unknownReason}`);
  if (inline.dynamic) { wslContext.unknown.add(`wsl inner interpreter '${programBase}' script is dynamic or unprovable`); return false; }
  if (inline.hasFileArg) { wslContext.unknown.add(`wsl inner interpreter '${programBase}' runs an external script file or encoded command; contents not analyzed`); return false; }
  if (inline.script === null) {
    if (!inline.unknownReason) wslContext.unknown.add(`wsl inner interpreter '${programBase}' has no inline script to analyze`);
    return false;
  }
  await unwrapInto({ ...wslContext, source: inline.script, dialect: innerDialect, depth: ctx.depth + 1 });
  return true;
}

export class ShellAbortError extends Error {
  constructor() { super('Shell analysis cancelled'); this.name = 'ShellAbortError'; this.code = 'CANCELLED'; }
}
