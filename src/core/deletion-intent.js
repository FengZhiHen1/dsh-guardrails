// deletion-intent — pure deletion-intent classification for already-parsed command IR.
// Boundary: no filesystem, process or network access; never executes inspected text.
// Policy: recognize deletion intent as far as provable; unknown/opaque/unsupported
// effects fail closed with an English denial that asks for clearer commands.

import { isUnsupportedProviderPath } from './filesystem-path.js'
import { assessGit } from './git-intent.js'

/**
 * Denial kind is fixed so callers and tests can match without parsing prose.
 * @typedef {{ kind: 'deny', ruleId: string, reason: string }} Denial
 * @typedef {{
 *   action: 'delete' | 'git-clean' | 'git-restore' | 'git-worktree-remove' | 'move-source',
 *   path: string | null,
 *   recursive: boolean,
 *   domain: 'host' | 'wsl',
 *   cwd?: string,
 *   commandName: string,
 *   unknown?: string,
 *   dialect?: string,
 *   distribution?: string,
 *   user?: string,
 *   preview?: boolean,
 *   paths?: string[],
 *   ignored?: boolean,
 *   force?: boolean,
 * }} DeleteOperation
 */

/** Maximum command list size mirrors the parser's own analysis budget. */
const MAX_COMMANDS = 2048;
/** Maximum arguments per command keeps classification bounded. */
const MAX_ARGS = 4096;
/** English suffix asking for a clearer command; one wording keeps diagnostics stable. */
const CLEARER = 'Use a clearer, supported command with explicit literal paths and supported options.';

/**
 * Read-only inspection commands that have no filesystem, process or config
 * side effects when used with their own dialect's plain options. Kept small and
 * dialect-specific: a GNU option on a PowerShell alias (or the reverse) is not
 * modeled, so it denies. Unknown options, redirection or dynamic names deny.
 *
 * Properties: `options` (exact, non-value flags), `valueOptions` (exact flags
 * that consume the next word), `optionalValue` (flags whose value is optional).
 */
const POSIX_NEUTRAL = {
  echo: { options: new Set(), valueOptions: new Set() },
  pwd: { options: new Set(), valueOptions: new Set() },
  ls: { options: new Set(['-l', '-a', '-la', '-al', '-h', '-lh', '-ah', '-lah', '-1', '-r', '-t']), valueOptions: new Set() },
  cat: { options: new Set(['-n', '-b', '-s', '-e', '-t', '-v', '-a', '-u']), valueOptions: new Set() },
  true: { options: new Set(), valueOptions: new Set() },
  false: { options: new Set(), valueOptions: new Set() },
  exit: { options: new Set(), valueOptions: new Set() },
  ':': { options: new Set(), valueOptions: new Set() },
};

/**
 * PowerShell read-only commands. `ls`/`cat`/`echo` are aliases whose target
 * can be shadowed, so only the full cmdlet names are accepted here. Options
 * that read external files or alter the pipeline (`-Filter`, `-Include`) deny.
 */
const POWERSHELL_NEUTRAL = {
  'write-output': { options: new Set(['-noenumerate']), valueOptions: new Set(['-inputobject']) },
  'write-host': { options: new Set(['-nonewline']), valueOptions: new Set(['-foregroundcolor', '-backgroundcolor', '-separator', '-object']) },
  'get-location': { options: new Set(), valueOptions: new Set() },
  'get-childitem': { options: new Set(['-force', '-recurse', '-file', '-directory', '-hidden', '-name']), valueOptions: new Set(['-path', '-literalpath', '-depth']) },
  'get-content': { options: new Set(['-raw', '-force']), valueOptions: new Set(['-path', '-literalpath', '-totalcount', '-tail', '-first', '-last', '-encoding', '-delimiter', '-readcount']) },
};

/**
 * Language runtimes the operator accepts as opaque script runners: running the
 * agent's own program is not a shell command line. They are allowed without
 * deletion analysis. Inline-code switches and stdin scripts are still refused,
 * because they turn the command line itself into code whose target set cannot
 * be enumerated.
 */
const OPAQUE_ALLOWED_INTERPRETERS = new Set([
  'node', 'nodejs', 'python', 'python3', 'py', 'perl', 'ruby', 'php', 'deno', 'bun', 'uv',
])
const INLINE_CODE_SWITCHES = new Set([
  '-e', '--eval', '-p', '--print', '-c', '-r', '-E', '-i', '--interactive', '-',
])

/**
 * Universal doctrine appended to every deletion-related refusal and protected
 * file approval. English is the tool-return language for this plugin.
 */
export const DELETION_DOCTRINE =
  'Deletion is irreversible. Before deleting, state and verify the exact files you intend to remove. ' +
  'If you cannot enumerate the exact target set, do not delete: inspect first (list or read the paths), ' +
  'then re-issue one explicit command with literal paths.'

/**
 * Named tool families whose deletion modes, interpreters or lookup/replace
 * behavior are known but not modeled here. Each is refused with a family
 * specific reason so the operator can switch to an explicit supported command,
 * and so these names are never mistaken for a neutral command.
 */
const NAMED_REFUSALS = {
  rsync: 'Rsync deletion modes (--delete*, --remove-source-files) cannot be proven safe from arguments.',
  robocopy: 'Robocopy mirror/purge modes (/MIR, /PURGE, /MOV) cannot be proven safe from arguments.',
  xcopy: 'xcopy options and their effects are not audited here, so the operation cannot be proven free of deletion.',
  sh: 'A bare shell invocation or shell script file whose text was not proven and analyzed cannot be proven free of deletion; a literal script file is analyzed by the shell adapter before this core layer, so this refusal means the script text (or the invocation target) was not provable.',
  bash: 'A bare shell invocation or shell script file whose text was not proven and analyzed cannot be proven free of deletion; a literal script file is analyzed by the shell adapter before this core layer, so this refusal means the script text (or the invocation target) was not provable.',
  zsh: 'A bare shell invocation or shell script file whose text was not proven and analyzed cannot be proven free of deletion; a literal script file is analyzed by the shell adapter before this core layer, so this refusal means the script text (or the invocation target) was not provable.',
  dash: 'A bare shell invocation or shell script file whose text was not proven and analyzed cannot be proven free of deletion; a literal script file is analyzed by the shell adapter before this core layer, so this refusal means the script text (or the invocation target) was not provable.',
  wsl: 'The wsl wrapper runs opaque inner commands that were not proven and analyzed; provide an explicit host command for the exact target.',
  cmd: 'A bare cmd host runs an opaque command line whose text was not proven and analyzed; its deletion effects cannot be inspected.',
  powershell: 'The PowerShell host runs script blocks or script files whose text was not proven and analyzed; a literal -File script is analyzed by the shell adapter before this core layer.',
  pwsh: 'The PowerShell host runs script blocks or script files whose text was not proven and analyzed; a literal -File script is analyzed by the shell adapter before this core layer.',
  npx: 'npx runs arbitrary packages whose deletion effects cannot be inspected.',
  env: 'env resolves and runs an arbitrary program; the resolved effect cannot be proven safe.',
  xargs: 'xargs runs arbitrary commands (often deletions) built from its input.',
  timeout: 'timeout runs an arbitrary wrapped program whose effects cannot be proven safe.',
  nice: 'nice runs an arbitrary wrapped program whose effects cannot be proven safe.',
  nohup: 'nohup runs an arbitrary wrapped program whose effects cannot be proven safe.',
  sudo: 'Elevation runs an arbitrary program whose effects cannot be proven safe.',
  su: 'su runs an arbitrary program whose effects cannot be proven safe.',
  doas: 'doas runs an arbitrary program whose effects cannot be proven safe.',
  start: 'start launches an arbitrary program or association whose effects cannot be proven safe.',
  call: 'call invokes a batch label or program whose effects cannot be proven safe.',
  source: 'source/. loads an opaque script that can redefine commands or delete files.',
  '.': 'source/. loads an opaque script that can redefine commands or delete files.',
  'invoke-expression': 'Invoke-Expression executes opaque text whose deletion effects cannot be inspected.',
  iex: 'Invoke-Expression executes opaque text whose deletion effects cannot be inspected.',
  'invoke-command': 'Invoke-Command runs a remote or script block whose deletion effects cannot be inspected.',
  format: 'Disk/volume format destroys data on a whole device.',
  'format-volume': 'Formatting a volume destroys data on a whole device.',
  'clear-disk': 'Disk clearing destroys data on a whole device.',
  'initialize-disk': 'Disk initialization can destroy existing data.',
  'remove-partition': 'Partition removal destroys data on a whole device.',
  dd: 'dd writes to raw devices and can destroy whole disks.',
  wipefs: 'wipefs destroys filesystem/partition signatures on a device.',
  blkdiscard: 'blkdiscard destroys data on a whole block device.',
  shred: 'shred destroys file contents irreversibly.',
  mkfs: 'mkfs formats a whole device, destroying its data.',
};

/** True when any argument equals `word` ignoring ASCII case. */
function hasWord(args, word) {
  return args.some((arg) => typeof arg === 'string' && arg.toLowerCase() === word);
}

/** True when any argument is the exact option or the `--opt=value` form. */
function hasOption(args, option) {
  return args.some((arg) => typeof arg === 'string' && (arg === option || arg.startsWith(`${option}=`)));
}

/**
 * A3 read-tool families are graded by their exact argv instead of refused wholesale:
 * `grep`/`printf` are always allowed (printf writes stdout, not files), while only the
 * documented execution-channel / unenumerable-delete options refuse the others.
 * Matching is token-exact: no prefix or glob guessing beyond the `--opt=value` form.
 */
function readToolRefusal(name, args) {
  if (name === 'rg') {
    if (hasOption(args, '--pre') || hasOption(args, '--pre-glob')) {
      return 'rg --pre/--pre-glob runs an arbitrary program on every searched file, which is an execution channel that can delete files.';
    }
    return null;
  }
  if (name === 'fd') {
    const exec = args.some((arg) => typeof arg === 'string' &&
      (arg === '-x' || arg === '-X' || arg === '--exec' || arg === '--exec-batch'));
    if (exec) return 'fd -x/-X/--exec runs an arbitrary command for every match, which is an execution channel that can delete files.';
    return null;
  }
  if (name === 'find') {
    const dangerous = args.some((arg) => typeof arg === 'string' &&
      (arg === '-delete' || arg === '-exec' || arg === '-execdir' || arg === '-ok' || arg === '-okdir'));
    if (dangerous) return 'find -delete/-exec/-ok deletes files or runs an arbitrary command, which cannot be enumerated from the command line.';
    return null;
  }
  return null;
}

/**
 * L1 catastrophe device/volume tools. Matched case-insensitively: a Windows or
 * PowerShell spelling (`Format-Volume`, `DD`) must not slip past a whole-device
 * wipe just because the dialect is unknown. The three admin tools whose destructive
 * mode is a specific subcommand are graded by argument instead of refused wholesale.
 */
const CATASTROPHE_REFUSALS = {
  format: () => NAMED_REFUSALS.format,
  'format-volume': () => NAMED_REFUSALS['format-volume'],
  'clear-disk': () => NAMED_REFUSALS['clear-disk'],
  'initialize-disk': () => NAMED_REFUSALS['initialize-disk'],
  'remove-partition': () => NAMED_REFUSALS['remove-partition'],
  dd: () => NAMED_REFUSALS.dd,
  wipefs: () => NAMED_REFUSALS.wipefs,
  blkdiscard: () => NAMED_REFUSALS.blkdiscard,
  shred: () => NAMED_REFUSALS.shred,
  mkfs: () => NAMED_REFUSALS.mkfs,
  diskpart: () => 'diskpart can repartition or wipe a whole disk.',
  fdisk: () => 'fdisk edits partition tables and can destroy a whole disk.',
  parted: () => 'parted edits partition tables and can destroy a whole disk.',
  vssadmin: (args) => (hasWord(args, 'delete') ? 'vssadmin delete destroys volume shadow copies (backup/recovery points).' : null),
  wbadmin: (args) => (hasWord(args, 'delete') ? 'wbadmin delete destroys backups or the catalog that makes recovery possible.' : null),
  cipher: (args) => (hasWord(args, '/w') ? 'cipher /w overwrites free space, destroying deleted data beyond recovery.' : null),
};

/** Return a catastrophe reason for this program name, or null when it is not one. */
function catastropheRefusal(name, args) {
  const grade = CATASTROPHE_REFUSALS[name.toLowerCase()];
  return grade ? grade(args) : null;
}

/** POSIX delete grammar. Options after `--` are operands. */
const POSIX_DELETE = {
  rm: {
    options: new Set(),
    valueOptions: new Set(),
    recursive: new Set(['-r', '-R', '--recursive']),
    // Single-letter flags that may appear in a cluster such as -rf / -rv.
    // `r` recurses; `f`/`v`/`i`/`d` do not change target identity.
    shortFlags: new Set(['r', 'f', 'v', 'i', 'd']),
    shortRecursive: new Set(['r', 'R']),
    refuse: new Set(['--no-preserve-root', '--preserve-root']),
  },
  rmdir: { options: new Set(['--ignore-fail-on-non-empty']), valueOptions: new Set(), recursive: new Set(), shortFlags: new Set(), shortRecursive: new Set(), refuse: new Set(['-p', '--parents']) },
  unlink: { options: new Set(), valueOptions: new Set(), recursive: new Set(), shortFlags: new Set(), shortRecursive: new Set(), refuse: new Set() },
};

/**
 * PowerShell Remove-Item grammar. Only exact option names are accepted; a
 * PowerShell abbreviation (e.g. -Rec) cannot be proven unique, so it fails.
 * Only -Path/-LiteralPath change the target set and are modeled; every other
 * switch (e.g. -Stream deletes an ADS, -Filter/-Include/-Exclude widen the set,
 * -Credential/-Attributes are unmodeled) denies.
 */
const POWERSHELL_REMOVE = {
  options: new Set(['-recurse', '-force', '-whatif', '-confirm']),
  valueOptions: new Set(['-path', '-literalpath']),
  valuePaths: new Set(['-path', '-literalpath']),
  recursive: new Set(['-recurse']),
};

/**
 * Names whose meaning depends on the shell dialect. `rm`, `del`, `erase`, `rd`
 * and `ri` are PowerShell aliases for Remove-Item, not GNU rm, so the dialect
 * selects the grammar. Without a dialect these names are ambiguous and deny.
 */
const DIALECT_ALIASES = new Set(['rm', 'ri', 'del', 'erase', 'rd']);

function deny(ruleId, reason) {
  return { kind: 'deny', ruleId, reason };
}

/**
 * Append the universal DELETION_DOCTRINE to a deletion-related refusal reason, exactly
 * once. A single helper keeps one consistent sentence and prevents duplication when a
 * reason already embeds it (e.g. the inline-code refusal).
 */
function withDoctrine(reason) {
  return reason.includes(DELETION_DOCTRINE) ? reason : `${reason} ${DELETION_DOCTRINE}`;
}

function domainOf(command) {
  return command.domain === 'wsl' ? 'wsl' : 'host';
}

function carryDomain(operation, command) {
  if (command.dialect !== undefined) operation.dialect = command.dialect;
  if (command.distribution !== undefined) operation.distribution = command.distribution;
  if (command.user !== undefined) operation.user = command.user;
}

function unsupportedOption(name, option) {
  return deny('DI-UNSUPPORTED-OPTION', `Command "${name}" uses option "${option}", whose effect is not supported; ${CLEARER}`);
}

/** True when a redirection creates, overwrites or read-write opens a file.
 * Any operator containing '>' is an output redirection (>, >>, >|, 2>, &>, >&,
 * &>>, *>); '<>' opens a file read-write and may create it. Input-only forms
 * (<, <<, <<<, <&) do not write and are not flagged here. */
function redirectionWrite(command) {
  for (const redirect of command.redirects ?? []) {
    if (!redirect || typeof redirect.operator !== 'string') continue;
    const op = redirect.operator;
    if (op.includes('>') || op === '<>') return true;
  }
  return false;
}

/**
 * Refuse any literal target that resolves through a non-filesystem provider/scheme.
 * Applied to BOTH real and preview delete plans (a preview must still name a real
 * local path). Dynamic (null) paths are handled separately as DI-DYNAMIC-ARGUMENT.
 */
function providerDenial(name, paths) {
  for (const path of paths) {
    if (typeof path === 'string' && isUnsupportedProviderPath(path)) {
      return deny('DI-PROVIDER-PATH', `Command "${name}" targets a non-filesystem provider or scheme path ("${path}"), which cannot be counted or resolved as a local file; ${CLEARER}`);
    }
  }
  return null;
}

/**
 * A pure -WhatIf preview is removed from destructive host observation, so the core must
 * itself guarantee the preview names a certain, literal, LOCAL host path. Dynamic/null,
 * empty, NUL, UNC, tilde-expanded or wildcard targets are not certain and deny; a WSL
 * (non-host) preview always denies because its domain cannot be inventoried from here.
 * Provider/scheme paths are already refused by providerDenial.
 */
function previewDenial(name, paths, command) {
  if (command.domain !== undefined && command.domain !== 'host') {
    return deny('DI-PREVIEW-DOMAIN', `Command "${name}" is a -WhatIf preview in a non-host (${command.domain}) domain, whose targets cannot be inventoried here; ${CLEARER}`);
  }
  for (const path of paths) {
    if (typeof path !== 'string') {
      return deny('DI-PREVIEW-UNPROVEN', `Command "${name}" is a -WhatIf preview whose target is dynamic, so it cannot be verified as a local path; ${CLEARER}`);
    }
    if (path === '' || path.includes('\0')) {
      return deny('DI-PREVIEW-UNPROVEN', `Command "${name}" is a -WhatIf preview whose target is empty or contains NUL; ${CLEARER}`);
    }
    if (/^[\\/]{2}/.test(path)) {
      return deny('DI-PREVIEW-UNPROVEN', `Command "${name}" is a -WhatIf preview whose target is a UNC/network path, which cannot be verified locally; ${CLEARER}`);
    }
    if (/(^|[\\/])~([\\/]|$)/.test(path) || /^~([\\/]|$)/.test(path)) {
      return deny('DI-PREVIEW-UNPROVEN', `Command "${name}" is a -WhatIf preview whose target depends on tilde expansion; ${CLEARER}`);
    }
    if (/[*?[]/.test(path)) {
      return deny('DI-PREVIEW-UNPROVEN', `Command "${name}" is a -WhatIf preview whose target uses wildcards, so the target set is not certain; ${CLEARER}`);
    }
  }
  return null;
}

/** Emit delete operations for the collected target paths. `preview` marks a pure
 * -WhatIf plan whose operations the host must exclude from destructive work. */
function emitDeletes(command, name, recursive, paths, preview = false) {
  const domain = domainOf(command);
  const operations = [];
  for (const path of paths) {
    const operation = {
      action: 'delete',
      path: typeof path === 'string' ? path : null,
      recursive,
      domain,
      commandName: name,
    };
    if (command.cwd !== undefined) operation.cwd = command.cwd;
    carryDomain(operation, command);
    if (path === null) operation.unknown = 'dynamic-path';
    if (preview) operation.preview = true;
    operations.push(operation);
  }
  return operations;
}

/** Emit one `move-source` operation per enumerable source path. A move deletes the
 * source, so its source set is counted exactly like a delete (the destination is
 * created, not removed). */
function emitMoveSources(command, name, paths) {
  const domain = domainOf(command);
  const operations = [];
  for (const path of paths) {
    const operation = {
      action: 'move-source',
      path: typeof path === 'string' ? path : null,
      recursive: true,
      domain,
      commandName: name,
    };
    if (command.cwd !== undefined) operation.cwd = command.cwd;
    carryDomain(operation, command);
    operations.push(operation);
  }
  return operations;
}

/** True when a literal source path uses a wildcard, so the source set cannot be
 * enumerated and a move over it cannot be proven bounded. */
function hasWildcard(path) {
  return typeof path === 'string' && /[*?[]/.test(path);
}

/**
 * Parse a PowerShell Move-Item invocation (cmdlet `Move-Item` and aliases `move`/`mi`).
 * Sources are positional words plus the value of -Path/-LiteralPath; the value after
 * -Destination is the target and is never a source. A dynamic argument or a wildcard
 * source refuses because the source set cannot be statically enumerated.
 */
function classifyPowershellMove(command, name) {
  const valueOptions = new Set(['-path', '-literalpath', '-destination', '-dest']);
  const destinationOptions = new Set(['-destination', '-dest']);
  const otherOptions = new Set(['-force', '-whatif', '-confirm', '-recurse']);
  const sources = [];
  for (let index = 0; index < command.args.length; index += 1) {
    const arg = command.args[index];
    if (arg === null) return { denial: deny('DI-DYNAMIC-ARGUMENT', `Command "${name}" moves a dynamic source whose target cannot be enumerated; ${CLEARER}`) };
    if (typeof arg !== 'string') return { denial: deny('DI-MALFORMED', `Command "${name}" has a non-string argument; ${CLEARER}`) };
    if (arg === '--%') return { denial: deny('DI-STOP-PARSING', `Command "${name}" uses the --% stop-parsing token whose native semantics cannot be proven; ${CLEARER}`) };
    if (/^-/.test(arg) && arg !== '-') {
      const lower = arg.toLowerCase();
      if (valueOptions.has(lower)) {
        const value = command.args[index + 1];
        index += 1;
        if (value === null) {
          if (!destinationOptions.has(lower)) return { denial: deny('DI-DYNAMIC-ARGUMENT', `Command "${name}" moves a dynamic source whose target cannot be enumerated; ${CLEARER}`) };
          continue;
        }
        if (typeof value !== 'string') return { denial: deny('DI-MALFORMED', `Command "${name}" option "${arg}" has a non-string value; ${CLEARER}`) };
        if (!destinationOptions.has(lower)) sources.push(value);
        continue;
      }
      if (otherOptions.has(lower)) continue;
      return { denial: unsupportedOption(name, arg) };
    }
    sources.push(arg);
  }
  if (sources.length === 0) return { denial: deny('DI-NO-TARGET', `Command "${name}" has no provable move source; ${CLEARER}`) };
  if (sources.some(hasWildcard)) {
    return { denial: deny('DI-UNSUPPORTED-COMMAND', `Command "${name}" moves a wildcard source whose set cannot be enumerated; ${CLEARER}`) };
  }
  return { operations: emitMoveSources(command, name, sources) };
}

/**
 * Parse a POSIX move (`mv`, and `move` when used as an mv alias). The last operand is
 * the destination unless -t/--target-directory names it; every other operand is a
 * source. `--` ends options. A dynamic or wildcard source refuses.
 */
function classifyPosixMove(command, name) {
  const operands = [];
  let targetDirectory = false;
  let sawSeparator = false;
  for (let index = 0; index < command.args.length; index += 1) {
    const arg = command.args[index];
    if (!sawSeparator && arg === '--') { sawSeparator = true; continue; }
    if (arg === null) return { denial: deny('DI-DYNAMIC-ARGUMENT', `Command "${name}" moves a dynamic source whose target cannot be enumerated; ${CLEARER}`) };
    if (typeof arg !== 'string') return { denial: deny('DI-MALFORMED', `Command "${name}" has a non-string argument; ${CLEARER}`) };
    if (!sawSeparator && (arg === '-t' || arg === '--target-directory')) {
      const value = command.args[index + 1];
      index += 1;
      if (value === null) return { denial: deny('DI-DYNAMIC-ARGUMENT', `Command "${name}" has a dynamic destination directory; ${CLEARER}`) };
      if (typeof value !== 'string') return { denial: deny('DI-MALFORMED', `Command "${name}" option "${arg}" has a non-string value; ${CLEARER}`) };
      targetDirectory = true;
      continue;
    }
    if (!sawSeparator && arg.startsWith('--target-directory=')) { targetDirectory = true; continue; }
    if (!sawSeparator && /^-./.test(arg) && arg !== '-') continue; // other modeled-neutral flags
    operands.push(arg);
  }
  const sources = targetDirectory ? operands : operands.slice(0, -1);
  const destination = targetDirectory ? '(target-directory)' : operands.at(-1);
  if (sources.length === 0 || (!targetDirectory && operands.length < 2)) {
    return { denial: deny('DI-NO-TARGET', `Command "${name}" has no provable move source; ${CLEARER}`) };
  }
  void destination;
  if (sources.some(hasWildcard)) {
    return { denial: deny('DI-UNSUPPORTED-COMMAND', `Command "${name}" moves a wildcard source whose set cannot be enumerated; ${CLEARER}`) };
  }
  return { operations: emitMoveSources(command, name, sources) };
}


function gitOperation(command, action, extra = {}) {
  const operation = {
    action,
    path: extra.path !== undefined ? extra.path : null,
    recursive: false,
    domain: domainOf(command),
    commandName: 'git',
    ...extra,
  };
  if (command.cwd !== undefined) operation.cwd = command.cwd;
  carryDomain(operation, command);
  return operation;
}

/**
 * Parse POSIX delete operands under a strict grammar. Dynamic path words are
 * kept as null so deletion intent survives; unknown options deny.
 */
function classifyPosixDelete(command, name, spec) {
  const paths = [];
  let literal = false;
  let recursive = false;
  for (let index = 0; index < command.args.length; index += 1) {
    const arg = command.args[index];
    if (arg === null) { paths.push(null); continue; }
    if (typeof arg !== 'string') return { denial: deny('DI-MALFORMED', `Command "${name}" has a non-string argument; ${CLEARER}`) };
    if (!literal && arg === '--') { literal = true; continue; }
    if (!literal && /^-{1,2}/.test(arg) && arg !== '-') {
      const lower = arg.toLowerCase();
      if (spec.refuse.has(arg) || spec.refuse.has(lower)) return { denial: unsupportedOption(name, arg) };
      if (spec.recursive.has(arg) || spec.recursive.has(lower)) { recursive = true; continue; }
      if (spec.options.has(arg) || spec.options.has(lower)) continue;
      // Short option cluster like -rf / -rv: every letter must be modeled.
      if (/^-[A-Za-z]+$/.test(arg) && spec.shortFlags) {
        let clusterOk = true;
        for (const ch of arg.slice(1)) {
          if (!spec.shortFlags.has(ch)) { clusterOk = false; break; }
          if (spec.shortRecursive.has(ch)) recursive = true;
        }
        if (clusterOk) continue;
      }
      return { denial: unsupportedOption(name, arg) };
    }
    paths.push(arg);
  }
  if (paths.length === 0) return { denial: deny('DI-NO-TARGET', `Command "${name}" has no provable deletion target; ${CLEARER}`) };
  const provider = providerDenial(name, paths);
  if (provider) return { denial: provider };
  return { operations: emitDeletes(command, name, recursive, paths) };
}

/**
 * Parse PowerShell Remove-Item operands. Only exact option names are modeled;
 * abbreviations and unknown switches deny. Dynamic path values stay null.
 */
function classifyPowershellRemove(command, name) {
  const spec = POWERSHELL_REMOVE;
  const paths = [];
  let literal = false;
  let recursive = false;
  // A pure -WhatIf previews the deletion; -Confirm still performs it.
  let preview = false;
  for (let index = 0; index < command.args.length; index += 1) {
    const arg = command.args[index];
    if (arg === null) { paths.push(null); continue; }
    if (typeof arg !== 'string') return { denial: deny('DI-MALFORMED', `Command "${name}" has a non-string argument; ${CLEARER}`) };
    // --% stops PowerShell parsing and passes raw text to a native command;
    // the resulting semantics are unpredictable, so refuse instead of guessing.
    if (!literal && arg === '--%') return { denial: deny('DI-STOP-PARSING', `Command "${name}" uses the --% stop-parsing token whose native semantics cannot be proven; ${CLEARER}`) };
    if (!literal && /^-/.test(arg) && arg !== '-') {
      const lower = arg.toLowerCase();
      if (spec.recursive.has(lower)) { recursive = true; continue; }
      if (spec.valueOptions.has(lower)) {
        // A value (including the literal filename '-WhatIf') is consumed here and is
        // never mistaken for a switch.
        const value = command.args[index + 1];
        index += 1;
        if (value === null) { if (spec.valuePaths.has(lower)) paths.push(null); continue; }
        if (typeof value !== 'string') return { denial: deny('DI-MALFORMED', `Command "${name}" option "${arg}" has a non-string value; ${CLEARER}`) };
        if (spec.valuePaths.has(lower)) paths.push(value);
        continue;
      }
      if (lower === '-whatif') { preview = true; continue; }
      if (lower === '-whatif:$true') { preview = true; continue; }
      if (lower === '-whatif:$false') { continue; } // explicitly disables preview: real
      if (lower === '-confirm' || lower === '-confirm:$true' || lower === '-confirm:$false') continue; // real, never preview
      if (spec.options.has(lower)) continue; // other modeled switches: real
      return { denial: unsupportedOption(name, arg) };
    }
    paths.push(arg);
  }
  if (paths.length === 0) return { denial: deny('DI-NO-TARGET', `Command "${name}" has no provable deletion target; ${CLEARER}`) };
  // A preview must still name real local file paths; provider syntax is refused here too.
  const provider = providerDenial(name, paths);
  if (provider) return { denial: provider };
  // A pure preview is excluded from destructive host observation, so it must be
  // provably a HOST-domain, certain, literal local path. Anything else denies rather
  // than being silently omitted from observation.
  if (preview) {
    const previewProblem = previewDenial(name, paths, command);
    if (previewProblem) return { denial: previewProblem };
  }
  return { operations: emitDeletes(command, name, recursive, paths, preview), preview };
}

/**
 * Classify a neutral read-only command. Unknown options, a dynamic (null)
 * operand or file redirection deny; otherwise nothing is emitted.
 */
function classifyNeutral(command, name, spec) {
  if (redirectionWrite(command)) {
    return { denial: deny('DI-REDIRECTION', `Command "${name}" writes files through redirection, which this checker cannot clear; ${CLEARER}`) };
  }
  let literal = false;
  for (let index = 0; index < command.args.length; index += 1) {
    const arg = command.args[index];
    // A dynamic operand could expand to an option or change the effect; a lone
    // core layer must not silently pass it, so deny.
    if (arg === null) return { denial: deny('DI-DYNAMIC-ARGUMENT', `Command "${name}" uses a dynamic argument whose effect cannot be proven; ${CLEARER}`) };
    if (typeof arg !== 'string') return { denial: deny('DI-MALFORMED', `Command "${name}" has a non-string argument; ${CLEARER}`) };
    if (!literal && arg === '--') { literal = true; continue; }
    if (!literal && /^-{1,2}/.test(arg) && arg !== '-') {
      const lower = arg.toLowerCase();
      if (spec.options.has(lower)) continue;
      if (spec.valueOptions.has(lower)) {
        const value = command.args[index + 1];
        if (spec.optionalValue?.has(lower)) continue;
        index += 1;
        if (value === null) return { denial: deny('DI-DYNAMIC-ARGUMENT', `Command "${name}" option "${arg}" has a dynamic value whose effect cannot be proven; ${CLEARER}`) };
        if (typeof value === 'string') continue;
        return { denial: deny('DI-MALFORMED', `Command "${name}" option "${arg}" has an invalid value; ${CLEARER}`) };
      }
      return { denial: unsupportedOption(name, arg) };
    }
  }
  return { operations: [] };
}

/** Scopes that represent straight-line top-level execution. */
const SCRIPT_SCOPES = new Set([undefined, 'script', 'file']);
/** Scopes where a command still runs but inside a substitution/subshell/definition. */
function isNonScriptScope(scope) {
  return !SCRIPT_SCOPES.has(scope);
}

/**
 * Assess parsed commands for deletion intent.
 *
 * Known delete commands still produce operations even when parser-level
 * uncertainty exists (their targets may be null), so evidence is never lost;
 * in that case a denial is also set because denial dominates allow.
 *
 * @param {Array<{name: string|null, args: Array<string|null>, redirects?: Array<{operator: string, target: string|null}>, scope?: string, dialect?: string, domain?: 'host'|'wsl', cwd?: string, distribution?: string, user?: string}>} commands
 * @param {{ unknown?: string[] }} [options]
 * @returns {{ operations: DeleteOperation[], denial?: Denial, previewCommandIndexes?: number[] }}
 */
export function assessCommands(commands, options = {}) {
  if (!Array.isArray(commands)) throw new TypeError('guardrails: commands must be an array');
  if (commands.length > MAX_COMMANDS) throw new RangeError('guardrails: command count exceeds analysis budget');
  const unknown = options?.unknown ?? [];
  if (!Array.isArray(unknown) || unknown.some((reason) => typeof reason !== 'string')) {
    throw new TypeError('guardrails: unknown reasons must be an array of strings');
  }

  const operations = [];
  let denial;
  // Indexes (into the input `commands` array) of commands that are a pure -WhatIf
  // preview. Only surfaced when non-empty so results without preview are unchanged.
  const previewCommandIndexes = [];

  for (let commandIndex = 0; commandIndex < commands.length; commandIndex += 1) {
    const command = commands[commandIndex];
    if (!command || typeof command !== 'object' || !Array.isArray(command.args)) {
      throw new TypeError('guardrails: invalid command IR');
    }
    if (command.args.length > MAX_ARGS) {
      return { operations: [], denial: deny('DI-MALFORMED', `A command has too many arguments to classify; ${CLEARER}`) };
    }
    if (command.name === null) {
      denial ??= deny('DI-DYNAMIC-COMMAND', withDoctrine(`A command has a dynamic name that cannot be resolved; ${CLEARER}`));
      if (redirectionWrite(command)) {
        denial ??= deny('DI-REDIRECTION', withDoctrine(`A dynamic command also writes files through redirection, which this checker cannot clear; ${CLEARER}`));
      }
      continue;
    }
    if (typeof command.name !== 'string' || command.name.trim() === '') {
      return { operations: [], denial: deny('DI-MALFORMED', `A command entry has an empty command name; ${CLEARER}`) };
    }
    // A path-qualified executable is a custom program: its familiar basename is
    // not proof it behaves like the stock utility, so it is never trusted.
    if (/[\\/]/.test(command.name)) {
      return { operations: [], denial: deny('DI-UNTRUSTED-PATH', withDoctrine(`Command "${command.name}" is a path-qualified executable whose behavior cannot be proven from its name; ${CLEARER}`)) };
    }
    // A name ending in .exe/.com/.cmd/.bat is a native program, not the shell
    // cmdlet/alias/utility it might resemble (e.g. Remove-Item.exe, rm.exe).
    // None are modeled as native here, so they are never exempted by basename.
    if (/\.(?:exe|com|cmd|bat)$/i.test(command.name)) {
      return { operations: [], denial: deny('DI-NATIVE-PROGRAM', withDoctrine(`Command "${command.name}" is a native program identified by its extension, which is not modeled; ${CLEARER}`)) };
    }

    const dialect = command.dialect;
    const isPowershell = dialect === 'powershell';
    const isPosix = dialect === 'bash' || dialect === 'posix' || dialect === 'sh';

    // Native names are case-sensitive on POSIX ('RM' is not 'rm'); PowerShell
    // cmdlet/alias names are case-insensitive. No suffix is ever stripped.
    const name = isPowershell ? command.name.toLowerCase() : command.name;
    // Tool families below are matched case-insensitively: a Windows/PowerShell spelling
    // (`Find`, `Invoke-Expression`, `GIT`) must not bypass a refusal or a git grade just
    // because the dialect was not declared. POSIX real names stay exact for delete grammars.
    const lowerName = name.toLowerCase();
    const neutralSet = isPowershell ? POWERSHELL_NEUTRAL : isPosix ? POSIX_NEUTRAL : null;

    // Move commands delete their SOURCE, so they are graded like deletes (L2 count),
    // never allowed. `copy`/`cp`/`Copy-Item` keep their source and stay L3 allow (they
    // are not matched here and fall through to the allow fallback).
    //   PowerShell: Move-Item and its aliases move/mi (and mv under PowerShell).
    //   POSIX: mv, and `move` used as an mv alias.
    let moveClassification = null;
    if (isPowershell) {
      if (name === 'move-item' || name === 'move' || name === 'mi' || name === 'mv') {
        moveClassification = () => classifyPowershellMove(command, name);
      }
    } else if (isPosix) {
      if (name === 'mv' || name === 'move') moveClassification = () => classifyPosixMove(command, name);
    } else {
      // No dialect: never allow a move program as unknown. Pick the grammar by name so
      // the source set is still enumerated (mv/move = POSIX operands, move-item/mi = PS).
      if (name === 'mv' || name === 'move') moveClassification = () => classifyPosixMove(command, name);
      else if (name === 'move-item' || name === 'mi') moveClassification = () => classifyPowershellMove(command, name);
    }

    if (moveClassification) {
      const result = moveClassification();
      if (result.denial) return { operations, denial: { ...result.denial, reason: withDoctrine(result.denial.reason) } };
      operations.push(...result.operations);
      if (isNonScriptScope(command.scope)) {
        denial ??= deny('DI-NONSCRIPT-SCOPE', withDoctrine(`Move runs inside a ${command.scope} scope, so a fixed source set cannot be proven; ${CLEARER}`));
      }
      if (command.args.some((arg) => arg === null)) {
        denial ??= deny('DI-DYNAMIC-ARGUMENT', withDoctrine(`Move uses a dynamic argument whose source cannot be proven; ${CLEARER}`));
      }
      if (redirectionWrite(command)) {
        denial ??= deny('DI-REDIRECTION', withDoctrine(`Command "${name}" also writes files through redirection, which this checker cannot clear; ${CLEARER}`));
      }
      continue;
    }

    // Resolve the delete grammar for this command, or none.
    let deleteClassification = null;
    if (isPosix && DIALECT_ALIASES.has(name) && POSIX_DELETE[name]) {
      // POSIX: only real POSIX delete utilities classify (rm/rmdir/unlink).
      if (name === 'rm') deleteClassification = () => classifyPosixDelete(command, name, POSIX_DELETE.rm);
    } else if (name === 'remove-item' || (isPowershell && DIALECT_ALIASES.has(name)) || (isPowershell && name === 'rmdir')) {
      // PowerShell: Remove-Item and its aliases (rm/ri/del/erase/rd/rmdir).
      deleteClassification = () => classifyPowershellRemove(command, name);
    } else if (isPosix && name === 'rmdir') {
      deleteClassification = () => classifyPosixDelete(command, name, POSIX_DELETE.rmdir);
    } else if (isPosix && name === 'unlink') {
      deleteClassification = () => classifyPosixDelete(command, name, POSIX_DELETE.unlink);
    } else if (DIALECT_ALIASES.has(name) || name === 'remove-item' ||
      ((name === 'rmdir' || name === 'unlink') && !isPosix && !isPowershell)) {
      // No dialect: an alias/cmdlet could be Remove-Item or a GNU tool. Deny.
      denial ??= deny('DI-AMBIGUOUS-DIALECT', withDoctrine(`Command "${name}" is a shell-dialect alias whose grammar cannot be proven without a dialect; ${CLEARER}`));
      if (redirectionWrite(command)) {
        denial ??= deny('DI-REDIRECTION', withDoctrine(`Command "${name}" also writes files through redirection, which this checker cannot clear; ${CLEARER}`));
      }
      continue;
    }

    if (deleteClassification) {
      const result = deleteClassification();
      if (result.denial) return { operations: [], denial: { ...result.denial, reason: withDoctrine(result.denial.reason) } };
      operations.push(...result.operations);
      // A real -WhatIf command is pure preview: its operations carry preview:true and
      // the host may exclude it from destructive target/policy work. It does not make
      // the command safe from other denials below.
      if (result.preview === true) previewCommandIndexes.push(commandIndex);
      // A delete that runs inside a substitution/subshell/definition, or that
      // uses a dynamic (null) argument, executes over an unproven target set.
      // Preserve the intent operation, but deny because it cannot be cleared.
      if (isNonScriptScope(command.scope)) {
        denial ??= deny('DI-NONSCRIPT-SCOPE', withDoctrine(`Deletion runs inside a ${command.scope} scope, so a fixed target set cannot be proven; ${CLEARER}`));
      }
      if (command.args.some((arg) => arg === null)) {
        denial ??= deny('DI-DYNAMIC-ARGUMENT', withDoctrine(`Deletion uses a dynamic argument whose target cannot be proven; ${CLEARER}`));
      }
      // A redirection on a delete command creates/overwrites a file as an unmodeled
      // side effect. Keep the delete evidence, but deny the whole command.
      if (redirectionWrite(command)) {
        denial ??= deny('DI-REDIRECTION', withDoctrine(`Command "${name}" also writes files through redirection, which this checker cannot clear; ${CLEARER}`));
      }
      continue;
    }

    const neutral = neutralSet ? neutralSet[name] : undefined;
    if (neutral) {
      const result = classifyNeutral(command, name, neutral);
      if (result.denial) return { operations: [], denial: result.denial };
      continue;
    }

    // Accepted language runtimes are opaque script runners. Running the agent's own
    // program is allowed; only an inline-code switch or stdin script turns the command
    // line itself into unenumerable code, which is refused.
    if (OPAQUE_ALLOWED_INTERPRETERS.has(name)) {
      const inline = command.args.find((arg) => typeof arg !== 'string' || INLINE_CODE_SWITCHES.has(arg.toLowerCase()))
      if (inline !== undefined) {
        const shown = typeof inline === 'string' ? inline : 'a dynamic argument'
        return {
          operations,
          denial: deny('DI-INLINE-CODE',
            withDoctrine(`Command "${name}" runs inline code (${shown}) whose target set cannot be enumerated; ${CLEARER}`)),
        }
      }
      continue
    }

    // git is graded rather than refused: history-destroying subcommands deny outright,
    // file-discarding subcommands become count-later operations, the rest is allowed.
    if (lowerName === 'git') {
      const git = assessGit(command.args)
      if (git.kind === 'refuse') {
        return { operations, denial: deny('DI-GIT-REFUSE', withDoctrine(`${git.reason} ${CLEARER}`)) }
      }
      if (git.kind === 'clean') {
        operations.push(gitOperation(command, 'git-clean', { ignored: git.ignored, force: git.force }))
      } else if (git.kind === 'restore') {
        operations.push(gitOperation(command, 'git-restore', { paths: git.paths }))
      } else if (git.kind === 'worktree-remove') {
        operations.push(gitOperation(command, 'git-worktree-remove', { path: git.path, force: git.force }))
      }
      // An allowed git command produces no operation, so the adapter must not fall
      // back to a generic filesystem scan for it (the command itself deletes nothing).
      if (isNonScriptScope(command.scope)) {
        denial ??= deny('DI-NONSCRIPT-SCOPE', withDoctrine(`git runs inside a ${command.scope} scope, so its target set cannot be proven; ${CLEARER}`));
      }
      continue
    }

    // A3: read-tool families are allowed unless their exact argv shows an execution
    // channel or an unenumerable deletion mode.
    const readTool = readToolRefusal(lowerName, command.args);
    if (readTool) {
      return { operations, denial: deny('DI-UNSUPPORTED-COMMAND', withDoctrine(`${readTool} ${CLEARER}`)) };
    }

    // L1 catastrophe: whole-device/volume destruction denies in any letter case.
    const catastrophe = catastropheRefusal(name, command.args);
    if (catastrophe) {
      return { operations, denial: deny('DI-UNSUPPORTED-COMMAND', withDoctrine(`${catastrophe} ${CLEARER}`)) };
    }

    const named = NAMED_REFUSALS[name] ?? NAMED_REFUSALS[lowerName];
    if (named) {
      return { operations, denial: deny('DI-UNSUPPORTED-COMMAND', withDoctrine(`${named} ${CLEARER}`)) };
    }
    if (lowerName.startsWith('mkfs.')) {
      return { operations, denial: deny('DI-UNSUPPORTED-COMMAND', withDoctrine(`${NAMED_REFUSALS.mkfs} ${CLEARER}`)) };
    }

    // Anything else is an unmodelled program. Under the v4 catastrophe standard this
    // is L3: allow it. Only the named catastrophe/execution-channel families above,
    // explicit delete grammars, and the execution-channel `unknown` list deny.
    continue;
  }

  // Parser-level uncertainty can hide a deletion that was not attributed to a
  // command. Denial dominates allow, but known-delete operations above survive.
  if (unknown.length > 0) {
    denial ??= deny('DI-UNKNOWN-SEMANTICS', withDoctrine(`Shell analysis reported unresolved semantics (${unknown.join('; ')}), so deletion intent cannot be ruled out; ${CLEARER}`));
  }

  const result = denial ? { operations, denial } : { operations };
  // Only add the preview index list when a real preview exists, so callers/tests for
  // non-preview invocations keep the exact previous result shape.
  if (previewCommandIndexes.length > 0) result.previewCommandIndexes = previewCommandIndexes;
  return result;
}

export default assessCommands;
