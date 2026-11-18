import os from 'node:os'
import path from 'node:path'
import { resolveCmdText } from './cmd.js'
import { resolveRemoteCommand } from './commands-remote.js'

const deleting = new Set(['rm', 'rmdir', 'unlink', 'mv'])
const deviceUtilities = new Set(['mkfs', 'mkfs.ext2', 'mkfs.ext3', 'mkfs.ext4', 'mkfs.xfs', 'mkfs.btrfs', 'mke2fs', 'wipefs'])
const contentReaders = new Set(['cat', 'head', 'tail', 'less', 'more', 'grep', 'rg'])
const windowsDeviceCommands = new Map([
  ['clear-disk', 'number'], ['initialize-disk', 'number'], ['format-volume', 'driveletter'],
  ['remove-partition', 'driveletter'],
])
const interpreters = new Map([
  ['bash', 'bash'], ['sh', 'posix'], ['dash', 'posix'], ['pwsh', 'powershell'], ['powershell', 'powershell'],
  ['python', 'python'], ['python3', 'python'], ['py', 'python'], ['node', 'javascript'],
  ['tsx', 'typescript'], ['ruby', 'unknown'], ['perl', 'unknown'], ['php', 'unknown'],
  ['zsh', 'unknown'], ['fish', 'unknown'],
])

/** Normalize a leading unquoted tilde operand to the host home directory
 * (F-24): an adapter fact at the same trust level as a verified `cd`. `~user`
 * forms and an unavailable homedir stay unresolvable (gap + null operand). */
function expandTildeOperand(value, index, options, env) {
  if (options.literalOperands?.[index] === true) return value // quoted `~` is literal data, not an expansion
  const next = value.charAt(1)
  if (next !== '' && next !== '/' && next !== '\\') {
    env.gap('tilde-user', options.origin)
    return null
  }
  const home = os.homedir()
  if (typeof home !== 'string' || home === '') {
    env.gap('tilde-user', options.origin)
    return null
  }
  const rest = value.slice(2)
  if (rest === '') return home
  const api = options.context.platform === 'win32' ? path.win32 : path.posix
  return api.join(home, rest)
}

function emitTargets(action, operands, options, env) {
  const { context, recursive = false, patterns = [] } = options
  const normalized = operands.map(({ value, index }) => ({
    value: typeof value === 'string' && value.startsWith('~') ? expandTildeOperand(value, index, options, env) : value,
    index,
  }))
  // D2 (非宿主域): a deletion whose execution domain is not the host never walks
  // host paths. The literal operands become the known scope with the domain label;
  // the evidence layer records the domain boundary as a deliberate unknown.
  if (typeof context?.domain === 'string' && context.domain !== 'host' && (action === 'delete' || action === 'move-source')) {
    const literals = normalized.filter(({ value }) => typeof value === 'string').map(({ value }) => value)
    if (literals.length > 0 || normalized.some(({ value }) => value == null)) {
      env.operation(action, {
        kind: 'unknown',
        reason: 'non-host-domain',
        ...(literals.length > 0 && {
          knownScope: literals.map((value) => `${context.domain}: ${value}${recursive === true ? ' (recursive)' : ''}`),
        }),
      }, options)
      return
    }
    // An operand-less destructive call in a non-host domain has nothing to express.
    env.gap('command-options', options.origin)
    return
  }
  const api = context.platform === 'win32' ? path.win32 : path.posix
  const known = normalized.filter(({ value, index }) => typeof value === 'string' && !patterns[index])
  const usable = known.filter(({ value }) => api.isAbsolute(value) || api.isAbsolute(context.cwd ?? ''))
  if (recursive === true && ['delete', 'move-source'].includes(action)) {
    for (const { value } of usable) env.operation(action, { kind: 'subtree', root: value }, options)
  } else if (usable.length) {
    env.operation(action, { kind: 'exact', paths: usable.map(({ value }) => value) }, options)
  }
  for (const { value, index } of normalized) {
    if (typeof value !== 'string' || !patterns[index]) continue
    const root = api.parse(value).root
    const prefixEnd = value.search(/[*?\[]/u)
    const prefix = prefixEnd < 0 ? '' : value.slice(0, prefixEnd)
    const split = Math.max(root.length, prefix.lastIndexOf('/') + 1, prefix.lastIndexOf(api.sep) + 1)
    const directory = value.slice(0, split)
    const base = api.isAbsolute(directory) ? directory : context.cwd && api.resolve(context.cwd, directory)
    if (base) env.operation(action, { kind: 'pattern', base, pattern: value.slice(split),
      dialect: options.powershell ? 'powershell' : 'posix' }, options)
    else env.operation(action, { kind: 'unknown', reason: 'relative-pattern' }, options)
  }
  if (normalized.some(({ value }) => value == null) || known.length > usable.length) {
    env.operation(action, { kind: 'unknown', reason: 'unresolved-target' }, { ...options, recursive })
  }
}

function posixFileCommand(name, args, options, env) {
  const operands = []
  let recursive = false
  let end = false
  let destination
  let unmodeled = false
  for (let i = 0; i < args.length; i++) {
    const value = args[i]
    if (!end && value === '--') { end = true; continue }
    if (!end && value?.startsWith('-') && value !== '-') {
      if ((name === 'mv' || name === 'cp') && (value === '-t' || value === '--target-directory')) {
        destination = { value: args[++i] ?? null, index: i }
        continue
      }
      if ((name === 'mv' || name === 'cp') && value.startsWith('--target-directory=')) {
        destination = { value: value.slice(19), index: i }
        continue
      }
      if (name === 'rm' && (/^-[firdvIR]+$/u.test(value) || value === '--recursive')) recursive ||= /[rR]/u.test(value)
      else if (name === 'rm' && /^(?:--force|--interactive(?:=(?:never|once|always))?|--one-file-system|--no-preserve-root|--preserve-root(?:=all)?|--dir|--verbose)$/u.test(value)) continue
      else if (name === 'rmdir' && (value === '-p' || value === '--parents')) unmodeled = true
      else if (!['-v', '-f', '-i', '-n', '-T', '-r', '-R', '-a', '-p', '-d', '--verbose', '--force', '--no-clobber', '--no-target-directory'].includes(value)) unmodeled = true
      continue
    }
    operands.push({ value, index: i })
  }
  if (unmodeled) {
    env.gap('command-options', options.origin)
    if (deleting.has(name) && operands.length) env.candidate('unverified-effect', 'Deletion options could not be interpreted', undefined, options.origin)
    return
  }
  if (name === 'mv' || name === 'cp') {
    destination ??= operands.pop()
    if (!destination || !operands.length) return
    emitTargets(name === 'mv' ? 'move-source' : 'copy-content', operands, { ...options, recursive: name === 'mv' || recursive }, env)
    emitTargets('write-content', [destination], options, env)
  } else {
    emitTargets('delete', operands, { ...options, recursive }, env)
  }
}

function contentCommand(name, args, options, env) {
  const searching = name === 'grep' || name === 'rg'
  const targets = []
  let needPattern = searching
  let end = false
  let expects
  for (const [index, value] of args.entries()) {
    if (expects) {
      if (expects === 'file') targets.push({ value, index })
      expects = undefined
      continue
    }
    if (!end && value === '--') { end = true; continue }
    if (!end && typeof value === 'string' && value.startsWith('-') && value !== '-') {
      if (searching && /^(?:-e|--regexp)(?:=.*)?$/u.test(value)) {
        needPattern = false
        if (!value.includes('=')) expects = 'value'
      } else if (searching && ['-f', '--file'].includes(value)) {
        needPattern = false
        expects = 'file'
      } else if (['head', 'tail'].includes(name) && ['-n', '-c', '--lines', '--bytes'].includes(value)) expects = 'value'
      else if (searching && ['-g', '--glob', '--include', '--exclude', '-A', '-B', '-C', '-m', '--max-count'].includes(value)) expects = 'value'
      continue
    }
    if (needPattern) { needPattern = false; continue }
    if (value !== '-') targets.push({ value, index })
  }
  emitTargets('read-content', targets, options, env)
}

const psActions = new Map([
  ['remove-item', 'delete'], ['move-item', 'move-source'], ['rename-item', 'move-source'],
  ['copy-item', 'copy-content'], ['get-content', 'read-content'], ['select-string', 'read-content'],
  ['set-content', 'write-content'], ['add-content', 'write-content'], ['clear-content', 'truncate-content'],
  ['out-file', 'write-content'], ['get-item', 'metadata'], ['get-childitem', 'metadata'], ['test-path', 'metadata'],
])
const psAliases = new Map([
  ['ri', 'remove-item'], ['mi', 'move-item'], ['ren', 'rename-item'], ['cpi', 'copy-item'],
  ['gc', 'get-content'], ['sls', 'select-string'], ['sc', 'set-content'], ['ac', 'add-content'], ['clc', 'clear-content'],
  ['gi', 'get-item'], ['gci', 'get-childitem'], ['ls', 'get-childitem'],
])

function psFileCommand(name, args, options, env) {
  const action = psActions.get(name)
  let destination
  let preview = false
  let recursive = action === 'move-source'
  let unmodeled = false
  let paths = []
  const positionals = []
  const patterns = []
  const namedValues = new Set(['filter', 'include', 'exclude', 'credential', 'erroraction', 'errorvariable',
    'warningaction', 'warningvariable', 'informationaction', 'informationvariable', 'outvariable', 'outbuffer',
    'pipelinevariable', 'progressaction', 'value', 'encoding', 'stream', 'totalcount', 'readcount', 'tail',
    'delimiter', 'depth', 'width', 'inputobject', 'context', 'pattern'])
  for (let i = 0; i < args.length; i++) {
    const value = args[i]
    if (options.literalOperands?.[i]) { positionals.push({ value, index: i }); continue }
    if (typeof value !== 'string' || !value.startsWith('-')) { positionals.push({ value, index: i }); continue }
    const arg = /^-([^:]+)(?::(.*))?$/u.exec(value)
    const option = arg?.[1].toLowerCase()
    const attached = arg?.[2]
    const operand = () => attached === undefined ? { value: args[++i] ?? null, index: i } : { value: attached, index: i }
    if (['path', 'literalpath', 'pspath', 'lp', 'filepath'].includes(option)) {
      const target = operand()
      paths.push(target)
      patterns[target.index] = option === 'path' && typeof target.value === 'string' && /[*?\[]/u.test(target.value)
    } else if (['destination', 'newname'].includes(option)) destination = operand()
    else if (option === 'recurse') recursive = attached === undefined || /^\$?true$/iu.test(attached) ? true : /^\$?false$/iu.test(attached) ? false : 'unknown'
    else if (option === 'whatif' || option === 'wi') preview = !['read-content', 'metadata'].includes(action) && (attached === undefined || /^\$?true$/iu.test(attached))
    else if (namedValues.has(option)) operand()
    else if (!['force', 'confirm', 'cf', 'verbose', 'debug', 'raw', 'passthru', 'name', 'file', 'directory', 'append', 'nonewline'].includes(option)) unmodeled = true
  }
  if (!paths.length) {
    paths = positionals.slice(name === 'select-string' ? 1 : 0, name === 'select-string' ? 2 : 1)
    for (const item of paths) patterns[item.index] = typeof item.value === 'string' && /[*?\[]/u.test(item.value)
    if (action === 'delete' && positionals.length > 1) {
      paths = positionals
      for (const item of paths) patterns[item.index] = typeof item.value === 'string' && /[*?\[]/u.test(item.value)
    }
  }
  if ((action === 'move-source' || action === 'copy-content') && !destination) destination = positionals.find((item) => !paths.includes(item))
  if (unmodeled) {
    env.gap('command-options', options.origin)
    if (['delete', 'move-source'].includes(action)) env.candidate('unverified-effect', 'File operation options could not be interpreted', undefined, options.origin)
  }
  emitTargets(action, paths, { ...options, patterns, recursive, preview }, env)
  if (destination) {
    // Rename-Item interprets NewName relative to the source's parent.
    if (name === 'rename-item' && typeof paths[0]?.value === 'string' && typeof destination.value === 'string') {
      const api = options.context.platform === 'win32' ? path.win32 : path.posix
      destination = { ...destination, value: api.join(api.dirname(paths[0].value), destination.value) }
    }
    emitTargets('write-content', [destination], { ...options, preview }, env)
  }
}

function windowsDeviceCommand(name, args, options, env) {
  const parameter = windowsDeviceCommands.get(name)
  const matches = []
  let preview = false
  for (const [index, argument] of args.entries()) {
    if (typeof argument !== 'string' || options.literalOperands?.[index]) continue
    const match = /^-([^:]+)(?::(.*))?$/u.exec(argument)
    if (!match) continue
    const flag = match[1].toLowerCase()
    if (flag === parameter) matches.push(match[2] ?? args[index + 1])
    if (flag === 'whatif' || flag === 'wi') preview = match[2] === undefined || /^\$?true$/iu.test(match[2])
  }
  if (preview) return
  const [value] = matches
  const diskNumber = parameter === 'number' && typeof value === 'string' && /^\d{1,8}$/u.test(value) ? Number(value) : undefined
  const driveLetter = parameter === 'driveletter' && typeof value === 'string' && /^[a-z]$/iu.test(value) ? value.toUpperCase() : undefined
  if (matches.length !== 1 || (diskNumber === undefined && driveLetter === undefined)) {
    env.candidate('unverified-effect', 'Storage mutation selector could not be determined', undefined, options.origin)
    return
  }
  const deviceMutation = diskNumber === undefined ? { driveLetter } : { diskNumber }
  env.operation('write-content', { kind: 'unknown', reason: 'storage-selector' }, { ...options, details: { deviceMutation } })
}

// --- coverage additions: find, stream-fed deletion, shred, rsync, wrappers, cmd ---

const FIND_VALUE_PREDICATES = new Set(['-maxdepth', '-mindepth', '-type', '-size', '-mtime', '-mmin',
  '-atime', '-amin', '-ctime', '-cmin', '-perm', '-user', '-group', '-uid', '-gid', '-links', '-newer',
  '-lname', '-printf', '-fprintf', '-fstype', '-context', '-samefile'])
const FIND_FLAG_PREDICATES = new Set(['-print', '-print0', '-ls', '-quit', '-prune', '-depth', '-xdev',
  '-mount', '-noleaf', '-daystart', '-follow', '-not', '-a', '-o', '-and', '-or', '-L', '-P', '-H',
  '-true', '-false', '-empty', '-d'])
const FIND_EXEC_FAMILY = new Set(['rm', 'rmdir', 'unlink'])

/** `find` deletion forms (F-01/F-02): `-delete` and `-exec <rm family>`. All
 * read-only find usage stays untouched (D3/D4). A confirmed deletion is never
 * dropped as a bare gap (D1): an unprovable predicate keeps the start points as
 * the decision scope (dynamic confirm), an unresolvable start point escalates to
 * an unverified-effect candidate (existing deny semantics), and only the
 * prompted-exec and missing-start forms stay a plain gap. */
function findCommand(args, options, env) {
  const bases = []
  let index = 0
  let dynamicBase = false
  while (index < args.length && (typeof args[index] !== 'string' ||
    (!args[index].startsWith('-') && args[index] !== '!'))) {
    if (typeof args[index] !== 'string') dynamicBase = true // a dynamic start point
    else bases.push(args[index])
    index += 1
  }
  const rest = args.slice(index)
  const strayBases = []
  let deleteMode = false
  let matchPattern
  let unmodeled = false
  let execRm = false
  let execPrompted = false
  let execOther = false
  for (let i = 0; i < rest.length; i++) {
    const value = rest[i]
    if (typeof value !== 'string') {
      unmodeled = true
      dynamicBase = true // a dynamic bare word could be another start point
      continue
    }
    if (value === '!' || value === '(' || value === ')') {
      unmodeled = true // operator grouping cannot be scoped
      continue
    }
    if (!value.startsWith('-')) {
      strayBases.push(value) // an extra start point: it joins the scope, never dropped
      continue
    }
    if (value === '-delete') { deleteMode = true; continue }
    if (value === '-name' || value === '-iname') { matchPattern ??= { kind: 'name', value: rest[++i] }; continue }
    if (value === '-path' || value === '-ipath' || value === '-wholename') { matchPattern ??= { kind: 'path', value: rest[++i] }; continue }
    if (value === '-regex' || value === '-iregex') { matchPattern ??= { kind: 'regex', value: rest[++i] }; continue }
    if (FIND_VALUE_PREDICATES.has(value)) { i += 1; continue }
    if (FIND_FLAG_PREDICATES.has(value)) continue
    if (value === '-exec' || value === '-execdir' || value === '-ok' || value === '-okdir') {
      const tokens = []
      let end = i
      for (let j = i + 1; j < rest.length; j++) {
        end = j
        const token = rest[j]
        if (token === ';' || token === '+') break
        // An escaped `\;` reaches the analyzer as a dynamic word; the `{}` the
        // syntax requires proves the terminator reading.
        if (token === null) { if (tokens.includes('{}')) break; unmodeled = true; break }
        tokens.push(token)
      }
      i = end
      if (value === '-ok' || value === '-okdir') { execPrompted = true; continue }
      const program = tokens[0]
      if (typeof program !== 'string' || !FIND_EXEC_FAMILY.has(program)) { execOther = true; continue }
      if (tokens.slice(1).some((token) => token === '-i' || token === '--interactive')) { execPrompted = true; continue }
      execRm = true
      continue
    }
    unmodeled = true
  }
  if (!deleteMode && !execRm) {
    // No confirmed deletion: coverage gap only (D3), never an operation or candidate.
    if (unmodeled || execPrompted) { env.gap('command-options', options.origin); return }
    if (execOther) env.gap('unmodeled-command', options.origin)
    return
  }
  // A confirmed deletion must produce a decision-grade fact (D1), never a bare gap.
  if (execPrompted) { env.gap('command-options', options.origin); return } // prompts gate the deletion (F-02)
  if (execOther) env.gap('unmodeled-command', options.origin) // non-rm exec stays allowed; -delete still applies
  if (dynamicBase) {
    env.candidate('unverified-effect', 'Find deletion scope could not be resolved: the start point is not statically known', undefined, options.origin)
    return
  }
  if (bases.length + strayBases.length === 0) {
    env.gap('command-options', options.origin) // usage error: find requires start paths
    return
  }
  const api = options.context.platform === 'win32' ? path.win32 : path.posix
  const starts = [...bases, ...strayBases].map((base) => api.isAbsolute(base)
    ? base
    : api.isAbsolute(options.context.cwd ?? '') ? api.resolve(options.context.cwd, base) : null)
  if (starts.some((start) => start === null)) {
    // The start point cannot be anchored; the literal text stays the scope (F-01b).
    env.operation('delete', { kind: 'unknown', reason: 'find-base-unresolved', knownScope: [...bases, ...strayBases] }, options)
    return
  }
  if (unmodeled || (matchPattern !== undefined && typeof matchPattern.value !== 'string')) {
    // The predicate set is not fully provable, but every match lies inside the
    // start points: the literal starts stay the decision scope (dynamic confirm).
    env.operation('delete', { kind: 'unknown', reason: 'find-predicate-unresolved', knownScope: starts }, { ...options, recursive: true })
    return
  }
  if (execRm) {
    for (const start of starts) {
      env.operation('delete', { kind: 'unknown', reason: 'find-exec-targets', knownScope: [start] }, options)
    }
  }
  if (deleteMode) {
    for (const start of starts) {
      if (matchPattern?.kind === 'name') {
        env.operation('delete', { kind: 'pattern', base: start, pattern: matchPattern.value, dialect: 'posix' },
          { ...options, recursive: true })
      } else if (matchPattern !== undefined) {
        env.operation('delete', { kind: 'unknown', reason: 'find-path-match', knownScope: [`${start} matching ${matchPattern.value}`] }, options)
      } else {
        env.operation('delete', { kind: 'subtree', root: start }, { ...options, recursive: true })
      }
    }
  }
}

const XARGS_VALUE_FLAGS = new Set(['-n', '-P', '-s', '-d', '-I', '-E', '-e', '-L', '-a'])
const XARGS_FLAGS = new Set(['-0', '-r', '-t', '-p', '-x', '-q', '-o', '--null', '--no-run-if-empty',
  '--exit', '--verbose', '--interactive'])
const PARALLEL_VALUE_FLAGS = new Set(['-j', '-a', '-S', '-d', '-I', '-N', '-L', '-t', '--jobs', '--arg-file',
  '--sshlogin', '--workdir', '--delimiter', '--replace-str', '--timeout', '--tagstring', '--retries',
  '--block', '--results', '--joblog', '--env', '--files'])
const STREAM_FED_FAMILY = new Set(['rm', 'rmdir', 'shred', 'unlink', 'mv'])

/** `xargs`/`parallel` with a literal destructive inner argv (F-03, D5): the fed
 * targets are a stream, so the scope is the stream plus the inner argv. A dynamic
 * inner program or a non-destructive inner command stays a gap — never a candidate. */
function streamFedCommand(name, args, options, env) {
  const valueFlags = name === 'parallel' ? PARALLEL_VALUE_FLAGS : XARGS_VALUE_FLAGS
  const flags = name === 'parallel' ? null : XARGS_FLAGS
  const separator = name === 'parallel' ? ':::' : undefined
  let unmodeled = false
  let i = 0
  while (i < args.length) {
    const value = args[i]
    if (typeof value !== 'string') { unmodeled = true; break }
    if (value === separator) break
    if (!value.startsWith('-') || value === '-' || value === '--') break
    if (valueFlags.has(value)) { i += 2; continue }
    if (/^--[^=\s]+=/u.test(value) || /^-[a-z]\d/iu.test(value)) { i += 1; continue }
    if (flags === null || flags.has(value)) { i += 1; continue }
    i += 1 // an unknown flag would be rejected at run time; it cannot hide the inner command
  }
  const program = args[i]
  const innerFlags = []
  for (let j = i + 1; j < args.length; j++) {
    const value = args[j]
    if (value === separator) break
    if (typeof value !== 'string') { unmodeled = true; break }
    innerFlags.push(value)
  }
  if (unmodeled || program === null) {
    env.gap('unmodeled-command', options.origin) // dynamic inner argv (D5): gap, never a candidate
    return
  }
  if (typeof program !== 'string' || program.startsWith('-')) return // bare `xargs` runs echo
  const destructive = STREAM_FED_FAMILY.has(program) || (program === 'git' && innerFlags[0] === 'rm')
  if (!destructive) {
    env.gap('unmodeled-command', options.origin)
    return
  }
  env.operation('delete', { kind: 'unknown', reason: 'stream-fed-targets', knownScope: ['stdin stream', [program, ...innerFlags].join(' ')] }, options)
}

/** `shred` (F-04, lead ruling 2026-11-18): shredding always tiers as a deletion,
 * with or without `-u`; `--help`/`--version` are lookups with no effect. */
function shredCommand(args, options, env) {
  const operands = []
  let unmodeled = false
  for (let i = 0; i < args.length; i++) {
    const value = args[i]
    if (typeof value !== 'string') { operands.push({ value, index: i }); continue }
    if (value === '--') {
      for (let j = i + 1; j < args.length; j++) operands.push({ value: args[j], index: j })
      break
    }
    if (value === '--help' || value === '--version') return
    if (value.startsWith('-') && value !== '-') {
      if (['-n', '--iterations', '-s', '--size', '--random-source'].includes(value)) { i += 1; continue }
      if (/^-[fuzwxv]+$/u.test(value) || value === '--remove' || /^--(?:remove|iterations|size|random-source)=/u.test(value) ||
        value === '--zero' || value === '--force') continue
      unmodeled = true
      continue
    }
    operands.push({ value, index: i })
  }
  if (unmodeled) { env.gap('command-options', options.origin); return }
  if (operands.length === 0) { env.gap('command-options', options.origin); return }
  emitTargets('delete', operands, options, env)
}

const RSYNC_FLAG_LETTERS = new Set([...'arRvzqnclptgodDHXASKuibWLPCE0kfh8Ixm'])
const RSYNC_VALUE_FLAGS = new Set(['--exclude', '--exclude-from', '--include', '--include-from', '--filter',
  '--rsh', '--block-size', '--max-size', '--min-size', '--max-delete', '--timeout', '--contimeout',
  '--bwlimit', '--temp-dir', '--compare-dest', '--copy-dest', '--link-dest', '--backup-dir', '--files-from',
  '--rsync-path', '--port', '--password-file', '--out-format', '--log-file', '--log-file-format',
  '--modify-window', '--usermap', '--groupmap', '--chown', '--iconv', '--protocol', '--sockopts'])
const RSYNC_BOOL_FLAGS = new Set(['--archive', '--recursive', '--relative', '--verbose', '--quiet',
  '--checksum', '--links', '--copy-links', '--copy-dirlinks', '--copy-unsafe-links', '--safe-links',
  '--perms', '--executability', '--times', '--group', '--owner', '--devices', '--specials', '--dry-run',
  '--whole-file', '--one-file-system', '--ignore-times', '--size-only', '--stats', '--progress', '--partial',
  '--prune-empty-dirs', '--numeric-ids', '--super', '--8-bit-output', '--human-readable', '--itemize-changes',
  '--ignore-existing', '--ignore-errors', '--keep-dirlinks', '--hard-links', '--sparse', '--append',
  '--append-verify', '--list-only', '--no-implied-dirs'])
const RSYNC_DELETE_FLAGS = new Set(['--delete', '--delete-before', '--delete-during', '--delete-delay',
  '--delete-after', '--delete-excluded', '--delete-missing-args'])

/** `rsync --delete*` models the destination tree (F-05); forms without a delete
 * flag keep the existing coverage-gap allowance, and `-n`/`--dry-run` is a proven preview. */
function rsyncCommand(args, options, env) {
  let deleteMode = false
  let preview = false
  let unmodeled = false
  const operands = []
  for (let i = 0; i < args.length; i++) {
    const value = args[i]
    if (typeof value !== 'string') { unmodeled = true; continue }
    if (value === '--') {
      for (let j = i + 1; j < args.length; j++) operands.push({ value: args[j], index: j })
      break
    }
    if (value === '--help' || value === '--version') return
    if (value.startsWith('-') && value !== '-') {
      if (value.startsWith('--')) {
        if (RSYNC_DELETE_FLAGS.has(value)) { deleteMode = true; continue }
        if (value === '--dry-run') { preview = true; continue }
        if (RSYNC_VALUE_FLAGS.has(value)) { i += 1; continue }
        if (/^--[^=\s]+=/u.test(value)) {
          if (RSYNC_VALUE_FLAGS.has(value.slice(0, value.indexOf('='))) || RSYNC_BOOL_FLAGS.has(value.slice(0, value.indexOf('=')))) continue
          unmodeled = true
          continue
        }
        if (RSYNC_BOOL_FLAGS.has(value)) continue
        unmodeled = true
        continue
      }
      if (value === '-e') { i += 1; continue }
      if (/^-[a-z]+$/iu.test(value)) {
        for (const letter of value.slice(1)) {
          if (letter === 'n') preview = true
          else if (!RSYNC_FLAG_LETTERS.has(letter)) { unmodeled = true; break }
        }
        continue
      }
      unmodeled = true
      continue
    }
    operands.push({ value, index: i })
  }
  if (unmodeled) { env.gap('command-options', options.origin); return }
  if (!deleteMode) { env.gap('unmodeled-command', options.origin); return }
  if (operands.length < 2) { env.gap('command-options', options.origin); return }
  emitTargets('delete', [operands[operands.length - 1]], { ...options, recursive: true, preview, details: { rsyncDelete: true } }, env)
}

const WRAPPER_SPECS = {
  sudo: {
    valueFlags: new Set(['-u', '-g', '-p', '-C', '-e', '-h', '-D', '--user', '--group', '--prompt', '--host', '--chdir']),
    boolFlags: new Set(['-E', '-H', '-b', '-l', '-v', '-n', '-A', '-k', '-K', '-B', '--reset-timestamp']),
    interactive: new Set(['-i', '-s', '--login', '--shell']),
    skipUnknown: true,
  },
  timeout: {
    valueFlags: new Set(['-k', '--kill-after', '--signal', '-s']),
    boolFlags: new Set(['--preserve-status', '--foreground', '-v', '--verbose']),
    skipUnknown: true,
    duration: true,
  },
  nohup: { transparentAll: true },
  env: {
    valueFlags: new Set(['-u']),
    boolFlags: new Set(['-i', '-0', '-v']),
    assignments: true,
    skipUnknown: true,
  },
  command: { boolFlags: new Set(['-p']), query: new Set(['-v', '-V']) },
  exec: { boolFlags: new Set(['-l', '-c']), valueFlags: new Set(['-a']) },
  nice: { valueFlags: new Set(['-n', '--adjustment']) },
  time: {
    valueFlags: new Set(['-f', '-o', '--format', '--output']),
    boolFlags: new Set(['-p', '-a', '--append', '--portability', '--quiet']),
    skipUnknown: true,
  },
  stdbuf: {
    valueFlags: new Set(['-o', '-e', '-i', '--output', '--error', '--input']),
    attached: /^-[oei].{1,32}$/u,
  },
}
const TRANSPARENT_WRAPPERS = new Set(Object.keys(WRAPPER_SPECS))

/** Index of the inner program token of a transparent wrapper (F-06, D5), or -1
 * when the wrapper is not executable as written (its gap was emitted), or -2
 * for a pure lookup form (`command -v x`). */
function wrapperUnwrap(name, args, options, env) {
  const spec = WRAPPER_SPECS[name]
  if (spec.transparentAll) return args.length > 0 ? 0 : -1
  let i = 0
  while (i < args.length) {
    const value = args[i]
    if (typeof value !== 'string') { env.gap('unmodeled-command', options.origin); return -1 }
    if (spec.assignments && /^[A-Za-z_][A-Za-z_0-9]*=/u.test(value)) { i += 1; continue }
    if (value === '--') { i += 1; break }
    if (!value.startsWith('-') || value === '-') break
    if (spec.query?.has(value)) return -2
    if (spec.interactive?.has(value)) { env.gap('unmodeled-command', options.origin); return -1 }
    if (spec.valueFlags?.has(value)) { i += 2; continue }
    if (spec.attached?.test(value) || /^--[^=\s]+=/u.test(value) || /^-[a-z]\d/iu.test(value)) { i += 1; continue }
    if (spec.boolFlags?.has(value)) { i += 1; continue }
    if (spec.skipUnknown === true) { i += 1; continue }
    env.gap('unmodeled-command', options.origin)
    return -1
  }
  if (spec.duration === true && i < args.length) i += 1
  return i
}

const CMD_SWITCH = /^[-/](?:c|k|d|a|u|q|v|x|t|e|r|s)(?::\S*)?$/iu

/** `cmd /c <text>` (F-09..F-11 entry from the shell layer): the payload is joined
 * back into one cmd command line and routed through the bounded cmd lexer. */
function cmdCommand(args, options, env) {
  let index = 0
  while (index < args.length) {
    const value = args[index]
    if (typeof value !== 'string') { env.gap('cmd-inline', options.origin); return }
    if (!/[-/]/u.test(value.charAt(0))) break
    if (!CMD_SWITCH.test(value)) { env.gap('cmd-inline', options.origin); return }
    if (value.toLowerCase() === '/k' || value.toLowerCase() === '-k') { env.gap('cmd-inline', options.origin); return }
    index += 1
  }
  const payload = args.slice(index)
  if (payload.length === 0 || payload.some((value) => typeof value !== 'string')) {
    env.gap('cmd-inline', options.origin)
    return
  }
  resolveCmdText(payload.join(' '), { origin: options.origin, condition: options.condition }, env)
}

/** cmd.exe builtin deletion family (F-09/F-10): `rmdir`/`rd` and `del`/`erase`
 * with `/`-switch semantics. Unknown switches stay a gap (D3). */
function cmdInline(name, args, options, env) {
  const delFamily = name === 'del' || name === 'erase'
  const paths = []
  let recursive = false
  let subDirs = false
  let unmodeled = false
  for (const value of args) {
    if (typeof value !== 'string') { unmodeled = true; continue }
    if (value.startsWith('/')) {
      const flag = value.toLowerCase()
      if (flag === '/?') { env.gap('command-options', options.origin); return }
      if (flag === '/s') { subDirs = true; if (!delFamily) recursive = true; continue }
      if (delFamily ? (['/p', '/f', '/q', '/a'].includes(flag) || flag.startsWith('/a:')) : flag === '/q') continue
      unmodeled = true
      continue
    }
    paths.push({ value, index: paths.length })
  }
  if (unmodeled) { env.gap('command-options', options.origin); return }
  if (paths.length === 0) return
  if (delFamily && subDirs) {
    env.operation('delete', {
      kind: 'unknown',
      reason: 'cmd-del-recursive-match',
      knownScope: [`files matching ${paths.map(({ value }) => value).join(', ')} in the working directory tree (del /s)`],
    }, options)
    return
  }
  emitTargets('delete', paths, {
    ...options,
    recursive,
    ...(delFamily && { patterns: args.map((value) => typeof value === 'string' && /[*?]/u.test(value)) }),
  }, env)
}


function gitCommand(args, options, env) {
  const context = { ...options.context }
  const api = context.platform === 'win32' ? path.win32 : path.posix
  let index = 0
  const global = []
  for (; index < args.length; index++) {
    const value = args[index]
    if (value == null) { env.gap('git-command', options.origin); return }
    if (!value.startsWith('-')) break
    if (value === '-C') {
      const cwd = args[++index]
      context.cwd = cwd && (api.isAbsolute(cwd) ? cwd : context.cwd && api.resolve(context.cwd, cwd)) || undefined
    } else if (['--git-dir', '--work-tree', '-c', '--config-env', '--namespace'].includes(value)) {
      global.push(value, args[++index] ?? null)
    } else global.push(value)
  }
  const cmd = args[index]
  const rest = args.slice(index + 1)
  const terminator = rest.indexOf('--')
  const flags = terminator < 0 ? rest : rest.slice(0, terminator)
  const has = (name) => flags.includes(name)
  const isReset = cmd === 'reset' && has('--hard') && (terminator < 0 || terminator === rest.length - 1)
  const rewritesRefs = cmd === 'push' && flags.some((value) => typeof value === 'string' && (
    /^(?:-[a-zA-Z]*[df][a-zA-Z]*|--force|--force-with-lease(?:=.*)?|--delete|--mirror)$/u.test(value) ||
    /^(?:\+[^:]+:[^:]+|:[^:]+)$/u.test(value)
  ))
  const dangerous = (cmd === 'stash' && ['drop', 'clear'].includes(rest[0])) ||
    (cmd === 'gc' && (has('--prune=now') || has('--prune=all'))) ||
    ['filter-branch', 'filter-repo'].includes(cmd) || rewritesRefs || isReset ||
    (cmd === 'reflog' && rest[0] === 'expire' && has('--all') && (has('--expire=now') || has('--expire=all')))
  const action = dangerous ? 'git-history-destroy' : cmd === 'clean' ? 'git-clean' : cmd === 'restore' ? 'git-restore'
    : cmd === 'worktree' && rest[0] === 'remove' ? 'git-worktree-remove' : undefined
  if (!action) {
    // Git subcommand surface extension (F-12..F-18, D6): only truly irreversible
    // forms enter a tier; reversible and read-only usage stays untouched.
    if (cmd === 'rm') return gitRmCommand(index, rest, options, env)
    if (cmd === 'branch') return gitRefDeletion('branch', 'refs/heads/', rest, global, options, env)
    if (cmd === 'tag') return gitRefDeletion('tag', 'refs/tags/', rest, global, options, env)
    if (cmd === 'checkout') return gitCheckout(rest, options, env)
    if (cmd === 'switch') return gitSwitch(rest, options, env)
    if (cmd === 'reset' && has('--merge')) {
      env.operation('git-restore', {
        kind: 'unknown', reason: 'git-state-scope', knownScope: ['merge state / uncommitted changes'],
      }, { ...options, context, details: { command: 'reset', args: rest, global } })
    }
    return
  }
  const preview = (action === 'git-clean' && flags.some((value) => typeof value === 'string' &&
    /^(?:--dry-run|-[a-zA-Z]*n[a-zA-Z]*)$/u.test(value))) ||
    (cmd === 'push' && (has('--dry-run') || has('-n')))
  env.operation(action, { kind: 'unknown', reason: 'git-evidence' }, {
    ...options, context, preview, details: { command: cmd, args: rest, global },
  })
}

/** `git rm <paths>` (F-12): a real worktree deletion, tiered like `rm`. Only
 * `--cached` (index-only), `-n`/`--dry-run` and operand-less calls stay untouched. */
function gitRmCommand(index, rest, options, env) {
  const operands = []
  let recursive = false
  let cached = false
  let preview = false
  let unmodeled = false
  for (let i = 0; i < rest.length; i++) {
    const value = rest[i]
    if (typeof value !== 'string') { operands.push({ value, index: index + 1 + i }); continue }
    if (value === '--') {
      for (let j = i + 1; j < rest.length; j++) operands.push({ value: rest[j], index: index + 1 + j })
      break
    }
    if (value === '--cached') { cached = true; continue }
    if (value === '--dry-run') { preview = true; continue }
    if (value === '--ignore-unmatch' || value === '--sparse') continue
    if (/^-[a-z]+$/iu.test(value)) {
      for (const letter of value.slice(1)) {
        if (letter === 'r' || letter === 'R') recursive = true
        else if (letter === 'n') preview = true
        else if (!'fq'.includes(letter)) { unmodeled = true; break }
      }
      continue
    }
    if (value.startsWith('-')) { unmodeled = true; continue }
    operands.push({ value, index: index + 1 + i })
  }
  if (unmodeled) { env.gap('command-options', options.origin); return }
  if (cached || preview || operands.length === 0) return
  emitTargets('delete', operands, { ...options, recursive, details: { command: 'rm', args: rest } }, env)
}

/** `git branch -D` / `git tag -d` (F-13/F-14): forced deletion of a ref. Merged
 * (`branch -d`), creation and lookup forms produce no operation (D6). */
function gitRefDeletion(command, prefix, rest, global, options, env) {
  const forced = command === 'tag'
    ? (rest.includes('-d') || rest.includes('--delete'))
    : (rest.includes('-D') || (rest.includes('--delete') && (rest.includes('--force') || rest.includes('-f'))))
  if (!forced) return
  const names = []
  for (const value of rest) {
    if (value === '--') continue
    if (typeof value !== 'string') { env.gap('git-command', options.origin); return }
    if (!value.startsWith('-')) names.push(value)
  }
  if (names.length === 0) return
  env.operation('git-restore', {
    kind: 'unknown', reason: 'git-ref-scope', knownScope: names.map((name) => `${prefix}${name}`),
  }, { ...options, details: { command, args: rest, global } })
}

/** `git checkout` (F-15/F-16): a pathspec discard is proven per path; a forced
 * branch switch discards uncommitted changes and keeps the state scope. */
function gitCheckout(rest, options, env) {
  const marker = rest.indexOf('--')
  const pathspecs = marker < 0 ? [] : rest.slice(marker + 1)
  if (pathspecs.some((value) => typeof value !== 'string')) { env.gap('git-command', options.origin); return }
  if (marker >= 0 && pathspecs.length > 0) {
    env.operation('git-restore', { kind: 'exact', paths: pathspecs },
      { ...options, details: { command: 'checkout', args: rest } })
    return
  }
  const flags = marker < 0 ? rest : rest.slice(0, marker)
  const discard = flags.includes('--force') || flags.includes('-f')
  const keepsChanges = flags.some((value) => ['-m', '--merge', '--ours', '--theirs', '--conflict'].includes(value))
  const createsBranch = flags.some((value) => ['-b', '-B', '--orphan', '-t', '--track'].includes(value))
  if (discard && !keepsChanges && !createsBranch) {
    env.operation('git-restore', {
      kind: 'unknown', reason: 'git-state-scope',
      knownScope: ['working tree (branch switch discards local changes)'],
    }, { ...options, details: { command: 'checkout', args: rest } })
  }
}

/** `git switch --force|--discard-changes` (F-17); plain switches and `-c` stay untouched. */
function gitSwitch(rest, options, env) {
  const discard = rest.includes('--force') || rest.includes('-f') || rest.includes('--discard-changes')
  if (!discard) return
  env.operation('git-restore', {
    kind: 'unknown', reason: 'git-state-scope',
    knownScope: ['working tree (branch switch discards local changes)'],
  }, { ...options, details: { command: 'switch', args: rest } })
}

function wrapper(language, args, options, env) {
  const emit = (source, scriptArgs, childContext = options.context) => env.child({ source, language,
    scriptArgs, context: childContext, condition: options.condition, origin: options.origin })
  if (language === 'unknown') { env.gap('no-provider', options.origin); return }
  const context = { ...options.context }
  if (language === 'powershell' && !args.some((value) => typeof value === 'string' && /^(?:-noprofile|-nop)$/iu.test(value))) {
    env.gap('shell-startup', options.origin)
  }
  for (let i = 0; i < args.length; i++) {
    const value = args[i]
    if (value == null) { env.candidate('dynamic-execution', 'Interpreter payload is unknown', undefined, options.origin); return }
    if (value === '-') { env.gap('stdin-source', options.origin); return }
    if (value === '--') {
      if (typeof args[i + 1] === 'string') emit({ kind: 'file', path: args[i + 1] }, args.slice(i + 2), context)
      else env.gap('stdin-source', options.origin)
      return
    }
    if (language === 'powershell') {
      const lower = value.toLowerCase()
      if (['-workingdirectory', '-wd', '-wo'].includes(lower)) {
        const api = context.platform === 'win32' ? path.win32 : path.posix
        const cwd = args[++i]
        context.cwd = cwd && (api.isAbsolute(cwd) ? cwd : context.cwd && api.resolve(context.cwd, cwd)) || undefined
        continue
      }
      if (['-encodedcommand', '-ec'].includes(lower)) { env.candidate('dynamic-execution', 'Encoded program was not analyzed', undefined, options.origin); return }
      if (['-command', '-c', '-commandwithargs', '-cwa', '-file', '-f'].includes(lower)) {
        const payload = args[i + 1]
        if (typeof payload !== 'string' || (['-c', '-command'].includes(lower) && args.length > i + 2)) {
          env.candidate('dynamic-execution', 'Interpreter payload is unknown', undefined, options.origin)
        } else emit(lower === '-file' || lower === '-f' ? { kind: 'file', path: payload } : { kind: 'inline', text: payload }, args.slice(i + 2), context)
        return
      }
      if (['-noprofile', '-nop', '-nologo', '-nol', '-noninteractive', '-noni', '-noexit'].includes(lower)) continue
      if (['-executionpolicy', '-ep', '-ex', '-inputformat', '-if', '-outputformat', '-o'].includes(lower)) { i++; continue }
      if (['-help', '-version'].includes(lower)) return
    }
    const isShell = language === 'bash' || language === 'posix'
    const isEval = (isShell && /^-[a-z]*c[a-z]*$/u.test(value)) ||
      (language === 'python' && value === '-c') || (language !== 'python' && !isShell && ['-e', '--eval'].includes(value))
    if (isEval) {
      if (typeof args[i + 1] === 'string') emit({ kind: 'inline', text: args[i + 1] }, args.slice(i + 2), context)
      else env.candidate('dynamic-execution', 'Interpreter payload is unknown', undefined, options.origin)
      if (isShell && /[li]/u.test(value)) env.gap('shell-startup', options.origin)
      return
    }
    if (isShell && ['--noprofile', '--norc', '--login', '-l', '-i'].includes(value)) {
      if (['--login', '-l', '-i'].includes(value)) env.gap('shell-startup', options.origin)
      continue
    }
    if (language === 'python' && /^-[BISEsOu]+$/u.test(value)) continue
    if (!value.startsWith('-') && !value.startsWith('+')) {
      emit({ kind: 'file', path: value }, args.slice(i + 1), context)
      return
    }
    env.gap('interpreter-options', options.origin)
    return
  }
  env.gap('stdin-source', options.origin)
}

/** Shared semantics for commands emitted by either a Shell or a program. */
export function resolveCommand(executable, args, unit, env) {
  const origin = unit.origin
  const options = { context: unit.context, origin, condition: unit.condition, powershell: unit.powershell,
    patterns: unit.patterns, literalOperands: unit.literalOperands }
  if (typeof executable !== 'string') {
    env.candidate('dynamic-execution', 'Program identity could not be determined', undefined, origin)
    return
  }
  if (!Array.isArray(args)) throw new TypeError('Expected an argument vector')
  const windows = unit.context.platform === 'win32'
  const name = windows ? executable.toLowerCase().replace(/\.exe$/u, '') : executable
  if (/[\\/:]/u.test(name)) { env.gap('external-program-identity', origin); return }
  if (name === 'eval' && !unit.powershell) {
    if (args.length && args.every((value) => typeof value === 'string')) {
      env.child({ source: { kind: 'inline', text: args.join(' ') }, language: unit.language === 'posix' ? 'posix' : 'bash',
        context: unit.context, condition: unit.condition, origin })
    } else if (args.length) env.candidate('dynamic-execution', 'Shell expression is unknown', undefined, origin)
    return
  }
  // Transparent wrapper unwrap (F-06, D5): the inner command's real action is the
  // only action; the wrapper itself never adds a candidate or a rejection. A dynamic
  // inner program stays a gap (no candidate).
  if (!unit.powershell && TRANSPARENT_WRAPPERS.has(name)) {
    const inner = wrapperUnwrap(name, args, options, env)
    if (inner >= 0) {
      const program = args[inner]
      const rest = args.slice(inner + 1)
      if (typeof program === 'string') {
        return resolveCommand(program, rest, {
          ...unit,
          ...(Array.isArray(unit.patterns) && { patterns: unit.patterns.slice(inner + 1) }),
          ...(Array.isArray(unit.literalOperands) && { literalOperands: unit.literalOperands.slice(inner + 1) }),
        }, env)
      }
    }
    return
  }
  if (unit.powershell) {
    const lower = name.toLowerCase()
    const normalized = psAliases.get(lower) ?? (windows && ['rm', 'del', 'erase', 'rd', 'rmdir'].includes(lower) ? 'remove-item'
      : windows && ['mv', 'move'].includes(lower) ? 'move-item'
        : windows && ['cp', 'copy'].includes(lower) ? 'copy-item'
          : windows && lower === 'type' ? 'get-content' : lower)
    if (psActions.has(normalized)) return psFileCommand(normalized, args, options, env)
    if (windows && windowsDeviceCommands.has(normalized)) return windowsDeviceCommand(normalized, args, options, env)
    if (['iex', 'invoke-expression'].includes(normalized)) {
      if (args.length === 1 && typeof args[0] === 'string') env.child({ source: { kind: 'inline', text: args[0] }, language: 'powershell', context: unit.context, origin })
      else env.candidate('dynamic-execution', 'PowerShell expression is unknown', undefined, origin)
      return
    }
  }
  if (unit.cmdDialect === true && ['rmdir', 'rd', 'del', 'erase'].includes(name)) return cmdInline(name, args, options, env)
  if (deleting.has(name) || name === 'cp') return posixFileCommand(name, args, options, env)
  if (name === 'git') return gitCommand(args, options, env)
  if (name === 'find' && !unit.powershell && !unit.cmdDialect) return findCommand(args, options, env)
  if (name === 'xargs' && !unit.powershell) return streamFedCommand('xargs', args, options, env)
  if (name === 'parallel' && !unit.powershell) return streamFedCommand('parallel', args, options, env)
  if (name === 'shred' && !unit.powershell) return shredCommand(args, options, env)
  if (name === 'rsync' && !unit.powershell) return rsyncCommand(args, options, env)
  if (name === 'cmd') return cmdCommand(args, options, env)
  if (name === 'dd') {
    const outputs = args.flatMap((value, index) => typeof value === 'string' && value.startsWith('of=')
      ? [{ value: value.slice(3), index }] : [])
    emitTargets('write-content', outputs, options, env)
    if (args.includes(null)) env.gap('storage-output', origin)
    return
  }
  if (name === 'truncate') {
    const operands = []
    let end = false
    for (let index = 0; index < args.length; index++) {
      const value = args[index]
      if (!end && value === '--') { end = true; continue }
      if (!end && ['-s', '--size', '-r', '--reference'].includes(value)) { index++; continue }
      if (end || !value?.startsWith('-')) operands.push({ value, index })
    }
    emitTargets('truncate-content', operands, options, env)
    return
  }
  if (deviceUtilities.has(name)) {
    const targetIndex = args.findLastIndex((value) => typeof value === 'string' && !value.startsWith('-'))
    if (targetIndex >= 0) emitTargets('write-content', [{ value: args[targetIndex], index: targetIndex }], {
      ...options, details: { deviceMutation: true },
    }, env)
    else env.candidate('unverified-effect', 'Device utility target is unknown', undefined, origin)
    return
  }
  if (contentReaders.has(name)) return contentCommand(name, args, options, env)
  if (name === 'wsl' && windows) {
    const context = { domain: 'wsl', platform: 'linux' }
    for (let index = 0; index < args.length; index++) {
      const flag = args[index]
      if (flag === '-e' || flag === '--exec') {
        if (typeof args[index + 1] !== 'string') { env.gap('wsl-shell', origin); return }
        env.child({ source: { kind: 'argv', executable: args[index + 1], args: args.slice(index + 2) },
          language: 'unknown', context, condition: unit.condition, origin })
        return
      }
      if (['-d', '--distribution', '-u', '--user', '--cd'].includes(flag)) {
        const value = args[++index]
        if (typeof value !== 'string') { env.gap('wsl-context', origin); continue }
        if (flag === '-d' || flag === '--distribution') context.distribution = value
        else if (flag === '-u' || flag === '--user') context.user = value
        else if (value.startsWith('/')) context.cwd = value
        else env.gap('wsl-context', origin)
        continue
      }
      // Without --exec the distribution shell interprets the remaining command line.
      break
    }
    env.gap('wsl-shell', origin)
    return
  }
  if (name === 'uv' && args[0] === 'run' && typeof args[1] === 'string' && !args[1].startsWith('-')) {
    env.gap('launcher-environment', origin)
    env.child({ source: { kind: 'argv', executable: args[1], args: args.slice(2) }, language: 'unknown', context: unit.context, origin })
    return
  }
  if (['npm', 'pnpm', 'yarn'].includes(name) && args[0] === 'run' && typeof args[1] === 'string') {
    env.child({ source: { kind: 'package-script', path: 'package.json', script: args[1] }, context: unit.context, origin })
    return
  }
  const language = interpreters.get(name) ?? (/^python3\.\d+$/u.test(name) ? 'python' : undefined)
  if (language) return wrapper(language, args, options, env)
  if (resolveRemoteCommand(name, args, options, env)) return
  env.gap(unit.cmdDialect === true ? 'cmd-inline' : 'unmodeled-command', origin)
}
