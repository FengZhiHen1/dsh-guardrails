// Bounded fact tables for the shell analysis layer: data-position marking,
// glob metadata, quoted-operand metadata, parser-unknown classification,
// state-mutator sets and literal `cd` tracking.
//
// Everything here derives facts from the typed parser output only. Nothing in
// this module reads the analyzed text as code, executes anything, or produces a
// risk judgment (decisions live in the single policy decision point).

// Commands whose arguments are pure text payloads (需求 R-19 / 命令文本分析
// 「有界事实提取」数据位置标注). Their arguments never name deletion targets.
export const DATA_ALL_COMMANDS = new Set(['echo', 'printf', 'write', 'write-output', 'write-host']);

// Options whose FOLLOWING value is a text payload (message / pattern / title).
export const DATA_VALUE_OPTIONS = {
  git: new Set(['-m', '--message']),
  grep: new Set(['-e', '--regexp']),
  egrep: new Set(['-e', '--regexp']),
  fgrep: new Set(['-e', '--regexp']),
  rg: new Set(['-e', '--regexp']),
  gh: new Set(['-t', '--title', '-b', '--body']),
};

/** Parallel-to-args boolean vector marking data positions. */
export function computeDataArgs(name, args, { powershell = false } = {}) {
  const flags = new Array(args.length).fill(false);
  if (typeof name !== 'string') return flags;
  const lower = name.toLowerCase();
  if (DATA_ALL_COMMANDS.has(lower)) return flags.fill(true);
  const options = DATA_VALUE_OPTIONS[lower];
  if (!options) return flags;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (typeof arg !== 'string') continue;
    const key = powershell ? arg.toLowerCase() : arg;
    if (options.has(key) && i + 1 < args.length) flags[i + 1] = true;
  }
  return flags;
}

/**
 * Parallel-to-args boolean vector marking glob-pattern values.
 * POSIX: set from the word facts (only unquoted glob metacharacters expand in
 * POSIX shells; quoted globs are literal data and stay false).
 * PowerShell: wildcards are expanded for path parameters, so any literal value
 * containing `*`, `?` or `[` is marked (conservative for literal brackets).
 */
export function computePatterns(args, words, { powershell = false } = {}) {
  const flags = new Array(args.length).fill(false);
  if (powershell) {
    for (let i = 0; i < args.length; i += 1) {
      if (typeof args[i] === 'string' && /[*?[]/.test(args[i])) flags[i] = true;
    }
    return flags;
  }
  if (Array.isArray(words)) {
    for (let i = 0; i < words.length && i < flags.length; i += 1) {
      if (words[i]?.glob) flags[i] = true;
    }
  }
  return flags;
}

/**
 * Parallel-to-args boolean vector marking quoted operand words that start with
 * `-`: in POSIX shells a quoted word is a literal VALUE, never an option flag.
 * Only available for POSIX sources — the PowerShell helper output does not
 * carry parameter/literal provenance (documented limitation).
 */
export function computeLiteralOperands(words) {
  if (!Array.isArray(words)) return undefined;
  return words.map((word) => Boolean(word?.quoted && typeof word?.text === 'string' && word.text.startsWith('-')));
}

/**
 * Map a parser diagnostic to a gap kind. Returns null when the diagnostic is
 * already fully represented by the emitted facts (e.g. dynamic words surface
 * as null arguments and must not fail the whole unit).
 */
export function classifyParserUnknown(reason) {
  const text = String(reason);
  if (/Dynamic command or argument/.test(text)) return null;
  if (/loop repeats execution|for loop repeats|conditional statement gates|case statement gates|try\/catch statement gates|switch statement gates|trap statement installs/.test(text)) return 'control-flow';
  if (/assignment changes state/.test(text)) return 'state-mutation';
  if (/locally defined (Bash|PowerShell) function/.test(text)) return 'local-function';
  if (/#requires|using statement/.test(text)) return 'startup-code';
  if (/member\/type expression|construct can execute or load code/.test(text)) return 'dynamic-code';
  if (/(DeclClause|LetClause|ArithmCmd|ArithmExp) evaluation/.test(text)) return 'dynamic-code';
  return 'parser-unknown';
}

/**
 * Map an interpreter-invocation unknown reason (wrappers.js) to gap kinds.
 * The reason may merge several facts with '; '.
 */
export function mapInterpreterUnknowns(reason) {
  const kinds = new Set();
  for (const segment of String(reason).split('; ')) {
    if (/NoProfile|profile startup/.test(segment)) kinds.add('pwsh-profile');
    else if (/extra arguments/.test(segment)) kinds.add('pwsh-trailing-args');
    else if (/changes execution context/.test(segment)) kinds.add('pwsh-context-option');
    else if (/interactive session|Interactive shell|no inline script/.test(segment)) kinds.add('interactive-shell');
    else if (/encoded command|EncodedCommand/i.test(segment)) kinds.add('encoded-command');
    else if (/startup|rcfile|init-file/.test(segment)) kinds.add('startup-code');
    else kinds.add('unmodeled-interpreter-option');
  }
  return [...kinds];
}

// Commands that mutate shell/session state so a fixed target set is not
// trustworthy. cwd-changing commands whose LITERAL target can be tracked are
// handled by the cd tracker and are skipped (pushd/popd change a stack and stay
// explicit state-mutation gaps).
export const BASH_STATE_MUTATORS = new Set(['pushd', 'popd', 'alias', 'unalias', 'export', 'unset', 'declare', 'typeset', 'local', 'readonly', 'source', '.', 'eval', 'exec', 'trap', 'set', 'shopt', 'enable', 'hash', 'builtin', 'command']);
export const POWERSHELL_STATE_MUTATORS = new Set(['push-location', 'pop-location', 'set-variable', 'new-variable', 'remove-variable', 'set-item', 'new-item', 'invoke-expression', 'iex', 'import-module', 'set-alias', 'new-alias', 'set-executionpolicy', 'set-psdebug', '.']);
export const CD_FAMILY = new Set(['cd', 'set-location', 'sl', 'chdir']);
const CD_PATH_OPTIONS = new Set(['-path', '-literalpath']);

/** True when the command mutates state and is not a trackable literal cd. */
export function isStateMutator(name, dialect) {
  if (typeof name !== 'string') return false;
  const lower = name.toLowerCase();
  if (CD_FAMILY.has(lower)) return false;
  return (dialect === 'powershell' ? POWERSHELL_STATE_MUTATORS : BASH_STATE_MUTATORS).has(lower);
}

/** Return the literal directory argument of a simple `cd`/`Set-Location`, or null. */
function literalCdArgument(args) {
  if (args.length === 1 && typeof args[0] === 'string') return args[0];
  if (args.length === 2 && typeof args[0] === 'string' && CD_PATH_OPTIONS.has(args[0].toLowerCase()) && typeof args[1] === 'string') return args[1];
  return null;
}

/**
 * A literal cd target is trackable only when it is a plain directory word (no
 * glob, tilde, NUL or `..` segment, whose resolution could differ from the
 * shell's real path). Returns the literal directory text or null.
 */
export function trackableCdArgument(args) {
  const arg = literalCdArgument(args);
  if (arg === null || arg.length === 0) return null;
  if (/[*?[\]{}]/.test(arg) || arg.includes('\u0000')) return null;
  if (arg === '~' || arg.startsWith('~/') || arg.startsWith('~\\')) return null;
  if (arg.split(/[\\/]/).some((segment) => segment === '..')) return null;
  return arg;
}
