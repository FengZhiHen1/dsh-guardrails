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
    if (options.exactRecursive === true) {
      // Archive tools remove exactly the members they archived and recurse into
      // directory members by default. Keep the member path as an EXACT target and
      // let the evidence layer split by the real entry type (a file counts one
      // entry, a directory is walked because recursive === true).
      for (const { value } of usable) env.operation(action, { kind: 'exact', paths: [value] }, options)
    } else {
      for (const { value } of usable) env.operation(action, { kind: 'subtree', root: value }, options)
    }
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
  // DSR-031 决定 9: a PowerShell deletion with no explicit path consumes the
  // pipeline input (`Get-ChildItem … | Remove-Item`). Only the deletion intent and
  // the ADJACENT upstream element are proven, so the target stays unknown with a
  // non-empty known scope — never a fabricated path. An empty knownScope would
  // deny an unscoped unknown target; a preview (`-WhatIf`) removes nothing (D3).
  if (action === 'delete' && paths.length === 0 && options.pipeline?.index > 0) {
    if (!preview) {
      const source = typeof options.pipeline.source === 'string' && options.pipeline.source.length > 0
        ? options.pipeline.source : null
      env.operation('delete', {
        kind: 'unknown',
        reason: 'pipeline-input',
        knownScope: [source ? `pipeline input of \`${source}\`` : 'pipeline input (adjacent upstream element is not provable)'],
      }, { ...options, recursive })
    }
    return
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

// DSR-031 第二轮 A: `host:path` / `user@host:path` / `[ipv6]:path` is a remote
// target; a Windows drive path (`C:\...`, `C:/...`) stays local.
function rsyncRemoteTarget(value) {
  if (typeof value !== 'string') return false
  if (/^[A-Za-z]:[\\/]/u.test(value)) return false
  if (value.startsWith('[')) {
    const close = value.indexOf(']')
    return close > 1 && value[close + 1] === ':'
  }
  const colon = value.indexOf(':')
  if (colon <= 0) return false
  const host = value.slice(0, colon)
  return !host.includes('/') && !host.includes('\\')
}

/** `rsync --delete*` models the destination tree (F-05); forms without a delete
 * flag keep the existing coverage-gap allowance, and `-n`/`--dry-run` is a proven preview.
 * An unresolvable destination (variable, expansion, substitution) is the incident
 * shape (2026-11-14): the deletion is confirmed on the command shape instead of
 * being dropped — never resolved to a literal path the source text disagrees with. */
function rsyncCommand(args, options, env) {
  let deleteMode = false
  let preview = false
  let unmodeled = false
  const positionals = []
  for (let i = 0; i < args.length; i++) {
    const value = args[i]
    if (typeof value !== 'string') { positionals.push({ value: null, index: i }); continue }
    if (value === '--') {
      for (let j = i + 1; j < args.length; j++) positionals.push({ value: args[j], index: j })
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
    positionals.push({ value, index: i })
  }
  if (unmodeled) { env.gap('command-options', options.origin); return }
  // Upload direction: a remote destination means the literal local sources are
  // read (DSR-031 決定 6 / 第二轮 A). Independent of --delete, so the read fact
  // can coexist with the deletion branch below; that branch is unchanged.
  if (positionals.length >= 2) {
    const target = positionals[positionals.length - 1]
    if (typeof target.value === 'string' && rsyncRemoteTarget(target.value)) {
      for (const source of positionals.slice(0, -1)) {
        if (typeof source.value !== 'string' || source.value === '-') continue
        if (rsyncRemoteTarget(source.value)) continue
        env.operation('read-content', { kind: 'exact', paths: [source.value] }, options)
      }
    }
  }
  if (!deleteMode) { env.gap('unmodeled-command', options.origin); return }
  if (positionals.length < 2) { env.gap('command-options', options.origin); return }
  // The delete scope is the LAST positional (the destination copy); dynamic
  // sources do not affect it.
  const destination = positionals[positionals.length - 1]
  const sources = positionals.slice(0, -1)
  // DSR-031 第二轮 F / D2: a remote destination (`host:path`) is not a host path.
  // The deletion is still proven on the command shape, but the target stays
  // unknown with a non-empty known scope instead of a fabricated local subtree.
  if (typeof destination.value === 'string' && rsyncRemoteTarget(destination.value)) {
    const sourceText = sources.some((source) => source.value === null)
      ? '(unresolved source)'
      : sources.map((source) => source.value).join(' ')
    env.operation('delete', {
      kind: 'unknown',
      reason: 'rsync-remote-delete-target',
      knownScope: [`rsync --delete ${sourceText} -> ${destination.value}`],
    }, { ...options, recursive: true, preview, details: { rsyncDelete: true } })
    return
  }
  if (destination.value === null) {
    const sourceText = sources.some((source) => source.value === null)
      ? '(unresolved source)'
      : sources.map((source) => source.value).join(' ')
    env.operation('delete', {
      kind: 'unknown',
      reason: 'rsync-delete-target',
      knownScope: [`rsync --delete ${sourceText} -> (unresolved destination expression)`],
    }, { ...options, recursive: true, preview, details: { rsyncDelete: true } })
    return
  }
  emitTargets('delete', [destination], { ...options, recursive: true, preview, details: { rsyncDelete: true } }, env)
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

/** Extract the payload words of a `cmd /c <text>` invocation, or null when the
 * switches cannot be proven (`/k`, an unknown switch, a non-literal token, or no
 * payload). Shared by the local `cmd` entry and the `ssh host cmd /c …` channel. */
function cmdPayload(args) {
  let index = 0
  while (index < args.length) {
    const value = args[index]
    if (typeof value !== 'string') return null
    if (!/[-/]/u.test(value.charAt(0))) break
    if (!CMD_SWITCH.test(value)) return null
    if (value.toLowerCase() === '/k' || value.toLowerCase() === '-k') return null
    index += 1
  }
  const payload = args.slice(index)
  if (payload.length === 0 || payload.some((value) => typeof value !== 'string')) return null
  return payload
}

/** `cmd /c <text>` (F-09..F-11 entry from the shell layer): the payload is joined
 * back into one cmd command line and routed through the bounded cmd lexer. */
function cmdCommand(args, options, env) {
  const payload = cmdPayload(args)
  if (payload === null) { env.gap('cmd-inline', options.origin); return }
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


// --- heredoc-fed stdin scripts -------------------------------------------------

/** POSIX shell interpreters whose stdin script a heredoc can feed. The body is
 * analyzed under the closest supported grammar: bash keeps its dialect, the
 * others the POSIX dialect (an unsupported construct stays a parse gap, never
 * a guess). */
const HEREDOC_SHELL_RECEIVERS = new Set(['bash', 'sh', 'dash', 'zsh', 'ksh'])

/** True when the receiver argv leaves the interpreter reading its script from
 * stdin: no `-c` inline script (possibly clustered) and no script-file
 * operand. Other options stay; a value-taking option followed by its value
 * looks like a file operand here, which conservatively keeps the old
 * coverage-gap behavior for that invocation. */
function readsStdinScript(args) {
  for (let i = 0; i < args.length; i++) {
    const value = args[i]
    if (value === null || typeof value !== 'string') return false
    if (value === '--') return i === args.length - 1
    if (value.startsWith('-') && value !== '-') {
      if (/^-[a-z]*c/iu.test(value)) return false // inline script mode: the heredoc stays data
      continue
    }
    return false // a bare word would be the script file
  }
  return true
}

/** A heredoc attached to a POSIX shell interpreter with no inline script and no
 * file argument IS the script that interpreter reads from stdin, quoted
 * delimiter or not (the delimiter only changes variable evaluation, not that
 * the text executes). The raw body is analyzed as a same-domain child unit.
 * Receiver option semantics stay on the invocation: `-s` is the explicit
 * stdin-script mode the body now proves, login/interactive flags still load
 * startup code, anything else stays an unmodeled option (gap, no candidate).
 * Returns true when the heredoc body was consumed. */
function emitHeredocShellChild(name, args, options, env, context = options.context) {
  const heredocs = Array.isArray(options.heredocs) ? options.heredocs : []
  const bodies = heredocs.filter((entry) => typeof entry?.body === 'string' && entry.body !== '')
  if (bodies.length === 0 || !readsStdinScript(args)) return false
  for (const value of args) {
    if (typeof value !== 'string' || !value.startsWith('-') || value === '-') continue
    if (['--noprofile', '--norc', '-s'].includes(value)) continue
    if (['--login', '-l', '-i'].includes(value)) env.gap('shell-startup', options.origin)
    else env.gap('interpreter-options', options.origin)
  }
  env.child({
    source: { kind: 'inline', text: bodies.map((entry) => entry.body).join('\n') },
    language: name === 'bash' ? 'bash' : 'posix',
    context, condition: options.condition, origin: options.origin,
  })
  return true
}

// --- ssh remote payloads -------------------------------------------------------

/** OpenSSH flags that take a value. A value letter inside a short cluster
 * cannot be split safely and stays an unmodeled option (gap). The boolean set
 * only changes local behavior; `-t`/`-T` affect only the TTY and never
 * introduce a remote command. */
const SSH_VALUE_FLAGS = new Set(['-b', '-c', '-D', '-E', '-e', '-F', '-I', '-i', '-J', '-L', '-l', '-m', '-O', '-o', '-p', '-Q', '-R', '-S', '-w', '-W'])
const SSH_BOOLEAN_FLAGS = new Set(['-4', '-6', '-A', '-a', '-B', '-C', '-f', '-G', '-g', '-K', '-k', '-M', '-N', '-n', '-q', '-s', '-T', '-t', '-v', '-x', '-X', '-Y', '-y'])
const SSH_VALUE_LETTERS = new Set([...'bDEeFIiJLlmOopQRSwWc'])

/** Remote receivers whose payload is another interpreter dialect (DSR-031 决定 2).
 * Both spellings are literal receiver identities on the remote side, never an
 * inference from the local platform. */
const SSH_POWERSHELL_RECEIVERS = new Set(['powershell', 'pwsh', 'powershell.exe', 'pwsh.exe'])
const SSH_CMD_RECEIVERS = new Set(['cmd', 'cmd.exe'])

/** `ssh [options] <host> [command…]`: everything after the destination is one
 * POSIX shell command line executed in the `ssh` domain; a heredoc fed to a
 * POSIX shell receiver is that shell's stdin script, and a heredoc fed to a bare
 * `ssh host` is that remote shell's stdin script. A PowerShell/cmd receiver is
 * analyzed as its own dialect. A host without a command and every unmodeled
 * option stay coverage gaps (放行). */
function sshCommand(args, options, env) {
  let index = 0
  while (index < args.length) {
    const value = args[index]
    if (typeof value !== 'string') { env.gap('unmodeled-command', options.origin); return }
    if (value === '--') { index += 1; break }
    if (value.startsWith('-') && value !== '-') {
      if (SSH_VALUE_FLAGS.has(value)) {
        if (index + 1 >= args.length) { env.gap('unmodeled-command', options.origin); return }
        index += 2
        continue
      }
      if (value.length > 2 && /^-[a-z]+$/iu.test(value)) {
        const letters = [...value.slice(1)]
        if (letters.some((letter) => SSH_VALUE_LETTERS.has(letter))) {
          env.gap('unmodeled-command', options.origin) // a value letter in a cluster cannot be split safely
          return
        }
        if (letters.every((letter) => SSH_BOOLEAN_FLAGS.has(`-${letter}`))) { index += 1; continue }
        env.gap('unmodeled-command', options.origin)
        return
      }
      const attached = /^-([a-zA-Z])(\S+)$/u.exec(value)
      if (attached && SSH_VALUE_LETTERS.has(attached[1])) { index += 1; continue }
      if (value.length === 2 && SSH_BOOLEAN_FLAGS.has(value)) { index += 1; continue }
      env.gap('unmodeled-command', options.origin)
      return
    }
    break
  }
  const destination = args[index]
  if (typeof destination !== 'string') { env.gap('unmodeled-command', options.origin); return }
  const rest = args.slice(index + 1)
  const receiver = rest[0]
  const loweredReceiver = typeof receiver === 'string' ? receiver.toLowerCase() : receiver
  if (typeof receiver === 'string' && HEREDOC_SHELL_RECEIVERS.has(receiver) &&
    emitHeredocShellChild(receiver, rest.slice(1), options, env, { domain: 'ssh', platform: 'linux' })) return
  // DSR-031 决定 2: a remote PowerShell receiver analyzes the payload as PowerShell.
  // The sub-unit carries ONLY the ssh domain: `platform: 'win32'` would make `rm`
  // take the Windows alias and path semantics on a remote that may run pwsh on Linux,
  // so a deletion stays `unknown` + knownScope under `data.delete.dynamic`.
  if (SSH_POWERSHELL_RECEIVERS.has(loweredReceiver)) {
    wrapper('powershell', rest.slice(1), { ...options, context: { domain: 'ssh' } }, env)
    return
  }
  if (SSH_CMD_RECEIVERS.has(loweredReceiver)) {
    const payload = cmdPayload(rest.slice(1))
    if (payload === null) { env.gap('cmd-inline', options.origin); return }
    env.child({
      source: { kind: 'inline', text: payload.join(' ') },
      language: 'cmd',
      context: { domain: 'ssh' },
      condition: options.condition, origin: options.origin,
    })
    return
  }
  // DSR-031 决定 1: `ssh host <<EOF` — a bare destination plus a heredoc is that
  // remote shell's stdin script (no remote command is given, so posix is the
  // receiver language). Without either, the host stays a coverage gap (放行).
  if (rest.length === 0 && emitHeredocShellChild('posix', [], options, env, { domain: 'ssh', platform: 'linux' })) return
  if (rest.length === 0) { env.gap('unmodeled-command', options.origin); return }
  const literals = rest.filter((value) => typeof value === 'string')
  if (literals.length === 0) { env.gap('unmodeled-command', options.origin); return }
  if (literals.length < rest.length) env.gap('unmodeled-command', options.origin)
  // The joined text is the literal remainder of the remote argv; local shell
  // operators cannot appear between the arguments (they never reach ssh).
  env.child({
    source: { kind: 'inline', text: literals.join(' ') },
    language: 'posix',
    context: { domain: 'ssh', platform: 'linux' },
    condition: options.condition, origin: options.origin,
  })
}

// --- awk system() payloads ------------------------------------------------------

/** Extract the literal argument of each `system("…")` call in an awk program.
 * Awk string literals and comments never execute, so they are skipped before
 * matching; only a double-quoted awk string argument is literal. An unterminated
 * string, a non-string argument or a concatenated argument is dynamic. */
function awkSystemPrograms(program) {
  const literal = []
  let dynamic = false
  const isSpace = (ch) => ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n'
  let i = 0
  while (i < program.length) {
    const ch = program[i]
    if (ch === '#') { while (i < program.length && program[i] !== '\n') i += 1; continue }
    if (ch === '"') {
      i += 1
      while (i < program.length && program[i] !== '"') { if (program[i] === '\\') i += 1; i += 1 }
      i += 1
      continue
    }
    if ((i === 0 || !/[A-Za-z0-9_$]/u.test(program[i - 1])) && /^system\s*\(/u.test(program.slice(i))) {
      let j = i + program.slice(i).match(/^system\s*\(/u)[0].length
      while (j < program.length && isSpace(program[j])) j += 1
      if (program[j] !== '"') { dynamic = true; i = j; continue }
      j += 1
      let text = ''
      let closed = false
      while (j < program.length) {
        const c = program[j]
        if (c === '\\') {
          const next = program[j + 1]
          if (next === undefined) break
          text += next === 'n' ? '\n' : next === 't' ? '\t' : next === 'r' ? '\r' : next
          j += 2
          continue
        }
        if (c === '"') { closed = true; j += 1; break }
        text += c
        j += 1
      }
      if (!closed) { dynamic = true; i = j; continue }
      while (j < program.length && (program[j] === ' ' || program[j] === '\t')) j += 1
      if (program[j] !== ')') { dynamic = true; i = j; continue } // concatenation or expression argument
      if (text !== '') literal.push(text)
      i = j + 1
      continue
    }
    i += 1
  }
  return { literal, dynamic }
}

/** `awk '…system("cmd")…'`: the string literal is a shell command line executed
 * through /bin/sh in the same execution domain. A non-literal `system()`
 * argument is the established dynamic-execution candidate. The awk language
 * surface itself stays an unmodeled-command gap (partial coverage). */
function awkCommand(args, options, env) {
  let program
  for (let i = 0; i < args.length; i++) {
    const value = args[i]
    if (typeof value !== 'string') break
    if (value.startsWith('-') && value !== '-') {
      if (/^-[fFvme]$/u.test(value)) { i += 1; continue } // value-taking short options
      continue // attached or clustered options cannot hide the program word here
    }
    if (value === '--') { program = args[i + 1]; break }
    program = value
    break
  }
  env.gap('unmodeled-command', options.origin)
  if (typeof program !== 'string' || program === '') return
  const { literal, dynamic } = awkSystemPrograms(program)
  if (dynamic) env.candidate('dynamic-execution', 'Dynamic system() argument was not analyzed', undefined, options.origin)
  for (const text of literal) {
    env.child({ source: { kind: 'inline', text }, language: 'posix',
      context: options.context, condition: options.condition, origin: options.origin })
  }
}

// --- tar --remove-files ---------------------------------------------------------

const TAR_BOOLEAN_LETTERS = new Set([...'czjJtxvprukaihlmnMSsUVwWyZPGqABOo'])
const TAR_VALUE_LETTERS = new Set([...'fbCTKXLgF'])
const TAR_BOOLEAN_LONGS = new Set(['--create', '--gzip', '--verbose', '--list', '--extract', '--get',
  '--bzip2', '--xz', '--zstd', '--lzma', '--lzop', '--compress', '--totals', '--dereference',
  '--one-file-system', '--same-permissions', '--absolute-names', '--no-recursion'])

/** `tar … --remove-files`: archiving deletes the named source members afterwards.
 * Directory members (trailing separator) delete recursively; a member list that
 * cannot be fully interpreted (unknown option, dynamic operand) keeps the
 * visible members as the known scope. `-C/--directory` relocates the member
 * resolution base cumulatively (DSR-031 决定 4): a member is resolved against the
 * directory in force when it appears; an unprovable `-C` value (dynamic or a
 * relative value with no provable cwd) leaves that member's target unknown with
 * a non-empty known scope. Without `--remove-files` the call stays the existing
 * unmodeled-command gap. */
function tarCommand(args, options, env) {
  const api = options.context?.platform === 'win32' ? path.win32 : path.posix
  let removeFiles = false
  let archiveNamed = false
  let filesFrom = false
  let unmodeled = false
  let sawDirectory = false
  let base
  const positionals = []
  const member = (value, index) => {
    const entry = { value, index }
    if (sawDirectory) entry.base = base
    positionals.push(entry)
  }
  const applyDirectory = (value) => {
    if (!sawDirectory) {
      sawDirectory = true
      base = typeof options.context?.cwd === 'string' && api.isAbsolute(options.context.cwd)
        ? api.normalize(options.context.cwd) : null
    }
    if (typeof value !== 'string' || value === '') { base = null; return }
    if (api.isAbsolute(value)) { base = api.normalize(value); return }
    base = base === null ? null : api.normalize(api.resolve(base, value))
  }
  let i = 0
  while (i < args.length) {
    const value = args[i]
    if (typeof value !== 'string') { member(null, i); i += 1; continue }
    if (value === '--') {
      for (let j = i + 1; j < args.length; j++) member(args[j], j)
      break
    }
    if (value.startsWith('--')) {
      const eq = value.indexOf('=')
      const name = eq < 0 ? value : value.slice(0, eq)
      if (name === '--remove-files') removeFiles = true
      else if (name === '--directory') {
        applyDirectory(eq < 0 ? args[i + 1] : value.slice(eq + 1))
        if (eq < 0) i += 1
      } else if (name === '--file') {
        archiveNamed = true
        if (eq < 0) i += 1 // the archive path is the next argument
      } else if (name === '--files-from' || name === '--exclude-from') {
        filesFrom = name === '--files-from'
        if (eq < 0) i += 1
      } else if (!TAR_BOOLEAN_LONGS.has(name)) unmodeled = true
      i += 1
      continue
    }
    // GNU old-style: `tar cf out.tgz src/` — a leading all-letters word is a cluster.
    const isCluster = (value.startsWith('-') && value !== '-' && !value.startsWith('--')) ||
      (i === 0 && /^[a-zA-Z]+$/u.test(value))
    if (!isCluster) { member(value, i); i += 1; continue }
    const letters = value.startsWith('-') ? value.slice(1) : value
    let advance = i + 1
    for (let k = 0; k < letters.length; k++) {
      const letter = letters[k]
      if (letter === 'C') {
        const attached = letters.slice(k + 1)
        if (attached !== '') applyDirectory(attached)
        else if (advance < args.length) { applyDirectory(args[advance]); advance += 1 }
        else applyDirectory(undefined)
        break // the cluster ends at its value letter
      }
      if (letter === 'f') {
        archiveNamed = true
        if (letters.slice(k + 1) === '' && advance < args.length && typeof args[advance] === 'string') advance += 1
        else if (letters.slice(k + 1) === '') unmodeled = true
        break // the cluster ends at its value letter
      }
      if (letter === 'T') {
        filesFrom = true
        if (letters.slice(k + 1) === '' && advance < args.length && typeof args[advance] === 'string') advance += 1
        else if (letters.slice(k + 1) === '') unmodeled = true
        break // the cluster ends at its value letter
      }
      if (TAR_VALUE_LETTERS.has(letter)) {
        if (letters.slice(k + 1) === '') {
          if (advance < args.length && typeof args[advance] === 'string') advance += 1
          else unmodeled = true
        }
        break // the cluster ends at its value letter
      }
      if (!TAR_BOOLEAN_LETTERS.has(letter)) unmodeled = true
    }
    i = advance
  }
  if (!removeFiles) { env.gap('unmodeled-command', options.origin); return }
  const sources = archiveNamed ? positionals : positionals.slice(1)
  // The member list itself comes from a file (-T/--files-from): the visible
  // operands cannot stand in for it (find's dynamic-base tier).
  if (filesFrom) {
    env.gap('command-options', options.origin)
    env.candidate('unverified-effect', 'tar --remove-files member list could not be enumerated: it is read from a file', undefined, options.origin)
    return
  }
  if (unmodeled || sources.length === 0) {
    env.gap('command-options', options.origin)
    if (sources.length === 0) return
    // The deletion is proven on the command shape; the visible members stay the
    // known scope (same treatment as an unprovable find predicate).
    env.operation('delete', {
      kind: 'unknown',
      reason: 'tar-remove-files-members',
      knownScope: [...sources.filter((source) => typeof source.value === 'string').map(({ value }) => value),
        'tar --remove-files (member list not fully interpretable)'],
    }, options)
    return
  }
  for (const source of sources) {
    const dirLike = typeof source.value === 'string' && /[\\/]$/u.test(source.value)
    const glob = typeof source.value === 'string' && /[*?[]/u.test(source.value)
    // GNU tar removes an archived directory recursively even without a trailing
    // separator (`--no-recursion` aside), so every member fact is recursive. A
    // trailing separator keeps the precise subtree shape; an ambiguous member
    // stays exact and the evidence layer splits a file (one entry) from a
    // directory (walked because recursive === true).
    const memberOptions = { ...options, recursive: true, ...(dirLike ? {} : { exactRecursive: true }) }
    if (source.base === undefined) {
      emitTargets('delete', [source], { ...memberOptions, ...(glob && { patterns: [true] }) }, env)
      continue
    }
    if (typeof source.value !== 'string') {
      env.operation('delete', {
        kind: 'unknown',
        reason: 'tar-remove-files-directory',
        knownScope: ['tar --remove-files (member path not provable)'],
      }, { ...options, recursive: true })
      continue
    }
    if (source.base === null) {
      env.operation('delete', {
        kind: 'unknown',
        reason: 'tar-remove-files-directory',
        knownScope: [`${source.value} (relative to an unprovable -C directory)`, 'tar --remove-files'],
      }, { ...options, recursive: true })
      continue
    }
    const resolved = api.isAbsolute(source.value) ? api.normalize(source.value) : api.resolve(source.base, source.value)
    emitTargets('delete', [{ value: resolved, index: source.index }], {
      ...memberOptions, ...(glob && { patterns: [true] }),
    }, env)
  }
}

// --- archive-then-delete: 7z -sdel and zip -m (DSR-031 决定 4) ----------------

const ZIP_VALUE_SHORT = new Set(['x', 'i', 'P', 'b', 'n', 't', 'O', 'Z'])
const ZIP_BOOL_SHORT = new Set([...'qvjkJlLDFSTUXyzosugh2345890A'])
const ZIP_VALUE_LONG = new Set(['--password', '--temp-path', '--suffixes', '--include', '--exclude',
  '--output-file', '--unzip-command', '--level', '--compression-method'])
const ZIP_BOOL_LONG = new Set(['--recurse-paths', '--recurse-paths-symlinks', '--junk-paths',
  '--junk-symlinks', '--symlinks', '--quiet', '--verbose', '--display-counts', '--latest-time',
  '--grow', '--filesync', '--test', '--show-files'])

/** One archive tool's source-member deletions (shared by 7z -sdel / zip -m, same
 * grade as `tar --remove-files`). Literal members are deleted; a member that is
 * dynamic or a wildcard keeps the deletion proven but the target unknown with a
 * non-empty known scope (an unscoped unknown would deny instead of confirm).
 * `archiveDefaultsRecursive` marks tools that recurse into directory members by
 * default (7-Zip): those facts are recursive with the member kept as an EXACT
 * target, and the evidence layer counts a file as one entry and walks a directory.
 * zip keeps the explicit `-r`/trailing-separator behavior. */
function emitArchivedSourceDeletes(sources, { recurse, tool, options, env, archiveDefaultsRecursive = false }) {
  const alwaysRecursive = archiveDefaultsRecursive === true
  for (const source of sources) {
    const dirLike = typeof source.value === 'string' && /[\\/]$/u.test(source.value)
    const recursive = alwaysRecursive || recurse || dirLike
    const memberOptions = { ...options, recursive, ...(alwaysRecursive ? { exactRecursive: true } : {}) }
    if (typeof source.value !== 'string') {
      env.operation('delete', {
        kind: 'unknown',
        reason: 'archive-source-members',
        knownScope: [`${tool} (member path not provable)`],
      }, memberOptions)
      continue
    }
    if (/[*?[]/u.test(source.value)) {
      env.operation('delete', {
        kind: 'unknown',
        reason: 'archive-source-members',
        knownScope: [`${tool} ${source.value}`, 'member set cannot be enumerated'],
      }, memberOptions)
      continue
    }
    emitTargets('delete', [source], memberOptions, env)
  }
}

/** `7z a -sdel …`: compression deletes the source members afterwards. Every
 * 7-Zip switch carries its value attached (`-mx=9`, `-oDIR`, `-x!…`), so switches
 * never consume the next token; the first positional is the archive name and the
 * rest are members. Without `-sdel` the call stays a coverage gap. */
function sevenZipCommand(args, options, env) {
  const sub = typeof args[0] === 'string' ? args[0].toLowerCase() : ''
  if (sub !== 'a') { env.gap('unmodeled-command', options.origin); return }
  let deleteAfter = false
  const positionals = []
  for (let i = 1; i < args.length; i++) {
    const value = args[i]
    if (typeof value !== 'string') { positionals.push({ value: null, index: i }); continue }
    if (value === '--') {
      for (let j = i + 1; j < args.length; j++) positionals.push({ value: args[j], index: j })
      break
    }
    if (value.startsWith('-') && value !== '-') {
      if (value.toLowerCase() === '-sdel') deleteAfter = true
      // Every other 7-Zip switch carries its value attached (`-mx=9`, `-oDIR`,
      // `-x!…`, `-r`), so switches never consume the next token.
      continue
    }
    positionals.push({ value, index: i })
  }
  if (!deleteAfter) { env.gap('unmodeled-command', options.origin); return }
  const sources = positionals.slice(1)
  if (sources.length === 0) { env.gap('command-options', options.origin); return }
  // 7-Zip deletes an archived directory recursively even without `-r`.
  emitArchivedSourceDeletes(sources, { recurse: true, tool: '7z a -sdel', options, env, archiveDefaultsRecursive: true })
}

/** `zip -m/--move`: archive creation moves (deletes) the source members after a
 * successful write. Without `-m/--move` ordinary zip calls stay a gap; the first
 * positional is the archive name, the rest are members. */
function zipCommand(args, options, env) {
  let move = false
  let recurse = false
  let fromFile = false
  const positionals = []
  for (let i = 0; i < args.length; i++) {
    const value = args[i]
    if (typeof value !== 'string') { positionals.push({ value: null, index: i }); continue }
    if (value === '--') {
      for (let j = i + 1; j < args.length; j++) positionals.push({ value: args[j], index: j })
      break
    }
    if (value.startsWith('--')) {
      const eq = value.indexOf('=')
      const name = eq < 0 ? value : value.slice(0, eq)
      if (name === '--move') { move = true; continue }
      if (ZIP_VALUE_LONG.has(name)) { if (eq < 0) i += 1; continue }
      if (ZIP_BOOL_LONG.has(name)) continue
      env.gap('unmodeled-command', options.origin)
      return
    }
    if (value.startsWith('-') && value !== '-') {
      for (let k = 1; k < value.length; k++) {
        const letter = value[k]
        if (letter === 'm') { move = true; continue }
        if (letter === 'r' || letter === 'R') { recurse = true; continue }
        if (letter === '@') { fromFile = true; break }
        if (ZIP_VALUE_SHORT.has(letter)) {
          if (k === value.length - 1) i += 1
          break
        }
        if (ZIP_BOOL_SHORT.has(letter)) continue
        env.gap('unmodeled-command', options.origin)
        return
      }
      continue
    }
    positionals.push({ value, index: i })
  }
  if (!move) { env.gap('unmodeled-command', options.origin); return }
  if (fromFile) {
    env.gap('command-options', options.origin)
    env.candidate('unverified-effect', 'zip --move source list could not be enumerated: it is read from a file', undefined, options.origin)
    return
  }
  const sources = positionals.slice(1)
  if (sources.length === 0) { env.gap('command-options', options.origin); return }
  emitArchivedSourceDeletes(sources, { recurse, tool: 'zip --move', options, env })
}

// --- docker run/exec payload (DSR-031 决定 10) -------------------------------

const DOCKER_RUN_VALUE_SHORT = new Set(['v', 'p', 'e', 'w', 'u', 'm', 'l', 'h', 'a', 'c'])
const DOCKER_RUN_BOOL_SHORT = new Set(['d', 'i', 't', 'P'])
const DOCKER_RUN_VALUE_LONG = new Set(['--volume', '--mount', '--publish', '--env', '--env-file', '--workdir',
  '--name', '--network', '--net', '--user', '--entrypoint', '--device', '--cap-add', '--cap-drop',
  '--security-opt', '--label', '--label-file', '--memory', '--memory-swap', '--memory-reservation',
  '--cpus', '--restart', '--platform', '--ulimit', '--add-host', '--dns', '--dns-search', '--dns-option',
  '--log-driver', '--log-opt', '--tmpfs', '--ipc', '--pid', '--uts', '--cgroupns', '--hostname',
  '--gpus', '--group-add', '--shm-size', '--sysctl', '--stop-signal', '--stop-timeout', '--cidfile',
  '--attach', '--blkio-weight', '--cpu-shares', '--cpu-quota', '--cpuset-cpus', '--cpuset-mems',
  '--pids-limit', '--ip', '--mac-address', '--expose', '--link', '--volumes-from',
  '--device-cgroup-rule', '--runtime', '--isolation', '--userns', '--annotation'])
const DOCKER_RUN_BOOL_LONG = new Set(['--detach', '--interactive', '--tty', '--rm', '--privileged',
  '--init', '--read-only', '--oom-kill-disable', '--no-healthcheck', '--tls', '--tlsverify',
  '--disable-content-trust', '--sig-proxy', '--publish-all'])
const DOCKER_EXEC_VALUE_SHORT = new Set(['e', 'u', 'w'])
const DOCKER_EXEC_BOOL_SHORT = new Set(['d', 'i', 't'])
const DOCKER_EXEC_VALUE_LONG = new Set(['--env', '--env-file', '--user', '--workdir', '--detach-keys'])
const DOCKER_EXEC_BOOL_LONG = new Set(['--detach', '--interactive', '--tty', '--privileged'])

/** A `-v/--volume` value names a HOST bind only when its source is a host path
 * (`/x`, `./x`, `../x`, `~/x`, a Windows drive path). A named or anonymous volume
 * (`vol:/data`, `/data`) never exposes the host filesystem. A dynamic value is
 * treated as a possible bind (its payload is analyzed rather than silently allowed). */
function dockerVolumeBinds(value) {
  if (typeof value !== 'string') return true
  const colon = value.indexOf(':')
  if (colon < 0) return false // anonymous volume (`/data`) or empty source
  let source = value.slice(0, colon)
  if (/^[A-Za-z]$/u.test(source) && /^[A-Za-z]:[\\/]/u.test(value)) {
    const second = value.indexOf(':', 2)
    source = second < 0 ? value : value.slice(0, second)
    return path.win32.isAbsolute(source)
  }
  return source.startsWith('/') || source.startsWith('.') || source === '~' || source.startsWith('~/')
}

/** `--mount` exposes host state for `type=bind`, or for any source-bearing spec
 * whose type is not `volume`/`tmpfs`. A dynamic spec stays a possible bind. */
function dockerMountBinds(value) {
  if (typeof value !== 'string') return true
  const fields = new Map()
  for (const part of value.split(',')) {
    const eq = part.indexOf('=')
    if (eq < 0) fields.set(part.trim().toLowerCase(), '')
    else fields.set(part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1))
  }
  const type = (fields.get('type') ?? '').toLowerCase()
  if (type === 'bind') return true
  if (type === 'volume' || type === 'tmpfs') return false
  const source = fields.get('source') ?? fields.get('src')
  return typeof source === 'string' && source !== ''
}

/** DSR-031 决定 10 + device correction: only a `docker run|exec` that can touch
 * host state (host bind mount, `--device`, `--privileged`) has its payload
 * analyzed, in the `container` domain. Without such a trigger the payload cannot
 * reach host paths, so no fact is emitted and ordinary runs stay allows. An
 * unknown `--opt=value` cannot consume another token, so scanning continues; an
 * unknown bare long option marks the payload boundary unproven — if host exposure
 * was already detected the call carries an unverified-effect candidate
 * (confirm, never a silent allow) plus the coverage gap. */
function dockerPayloadCommand(args, options, env) {
  const sub = typeof args[0] === 'string' ? args[0] : ''
  if (sub !== 'run' && sub !== 'exec') return false
  const run = sub === 'run'
  const valueLong = run ? DOCKER_RUN_VALUE_LONG : DOCKER_EXEC_VALUE_LONG
  const boolLong = run ? DOCKER_RUN_BOOL_LONG : DOCKER_EXEC_BOOL_LONG
  const valueShort = run ? DOCKER_RUN_VALUE_SHORT : DOCKER_EXEC_VALUE_SHORT
  const boolShort = run ? DOCKER_RUN_BOOL_SHORT : DOCKER_EXEC_BOOL_SHORT
  let privileged = false
  let hostAccess = false
  let unmodeled = false
  let i = 1
  while (i < args.length) {
    const value = args[i]
    if (typeof value !== 'string') { unmodeled = true; i += 1; continue }
    if (value === '--') { i += 1; break }
    if (!value.startsWith('-') || value === '-') break
    if (value.startsWith('--')) {
      const eq = value.indexOf('=')
      const name = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
      const attached = eq < 0 ? undefined : value.slice(eq + 1)
      if (name === '--privileged') { privileged = true; i += 1; continue }
      if (run && name === '--volume') {
        if (dockerVolumeBinds(attached === undefined ? args[i + 1] : attached)) hostAccess = true
        if (attached === undefined) i += 1
        i += 1
        continue
      }
      if (run && name === '--mount') {
        if (dockerMountBinds(attached === undefined ? args[i + 1] : attached)) hostAccess = true
        if (attached === undefined) i += 1
        i += 1
        continue
      }
      if (name === '--device') {
        hostAccess = true
        if (attached === undefined) i += 1
        i += 1
        continue
      }
      if (valueLong.has(name)) {
        if (attached === undefined) i += 1
        i += 1
        continue
      }
      if (boolLong.has(name)) { i += 1; continue }
      // Unknown option: `--opt=value` is unambiguous and skipped; a bare unknown
      // option may consume the next token, so the payload boundary is unproven.
      if (attached === undefined) unmodeled = true
      i += 1
      continue
    }
    let advance = 1
    for (let k = 1; k < value.length; k++) {
      const letter = value[k]
      const rawAttached = value.slice(k + 1)
      const hadEquals = rawAttached.startsWith('=')
      const attached = hadEquals ? rawAttached.slice(1) : rawAttached
      if (run && letter === 'v') {
        const volume = attached !== '' || hadEquals ? attached : args[i + 1]
        if (!hadEquals && attached === '' && typeof args[i + 1] === 'string') advance = 2
        if (dockerVolumeBinds(volume)) hostAccess = true
        break
      }
      if (valueShort.has(letter)) {
        if (!hadEquals && attached === '' && typeof args[i + 1] === 'string') advance = 2
        break
      }
      if (boolShort.has(letter)) continue
      unmodeled = true
      break
    }
    i += advance
  }
  if (unmodeled) {
    env.gap('unmodeled-command', options.origin)
    if (hostAccess || privileged) {
      env.candidate('unverified-effect', 'docker run options could not be fully interpreted; a host bind mount may be present',
        ['docker run (payload boundary not provable)'], options.origin)
    }
    return true
  }
  if (i >= args.length || typeof args[i] !== 'string') { env.gap('unmodeled-command', options.origin); return true }
  // `run`: image name; `exec`: container name. The payload starts after it.
  const payload = args.slice(i + 1)
  const triggered = run ? (hostAccess || privileged) : privileged
  if (!triggered) return true
  if (payload.length === 0) { env.gap('unmodeled-command', options.origin); return true }
  if (typeof payload[0] !== 'string') { env.gap('unmodeled-command', options.origin); return true }
  env.child({
    source: { kind: 'argv', executable: payload[0], args: payload.slice(1) },
    language: 'unknown',
    context: { domain: 'container' },
    condition: options.condition,
    origin: options.origin,
  })
  return true
}

// --- raw storage erase / partition tools ----------------------------------------

/** One raw storage mutation fact, same channel as `dd`/`mkfs`: the device
 * operand stays an enumerable path ({kind:'exact'} plus the declared
 * deviceMutation), so the evidence layer resolves it — cwd-relative forms
 * included — and grants `catastrophic.device` only when the read-only probe
 * proves real hardware. A selector that cannot name a host device path at all
 * keeps the storage-selector shape AND carries the unverified-effect candidate:
 * an irreversible device erase must never fall through as a silent allow. */
function storageMutationFact(selector, options, env) {
  if (typeof selector !== 'string' || selector === '') {
    env.candidate('unverified-effect', 'Storage mutation selector could not be resolved to a host device', undefined, options.origin)
    return
  }
  emitTargets('write-content', [{ value: selector, index: 0 }], {
    ...options, details: { deviceMutation: true },
  }, env)
}

function diskutilCommand(args, options, env) {
  const sub = typeof args[0] === 'string' ? args[0].toLowerCase() : ''
  if (/^(?:erase|partition)/u.test(sub)) {
    if (args.some((value) => value === '-dryrun' || value === '--dryrun' || value === '-dry-run')) {
      env.gap('unmodeled-command', options.origin)
      return
    }
    // The device identifier is a macOS diskN token or a /dev path; its argument
    // position varies by verb, so match the selector shape instead.
    const selector = args.slice(1).findLast((value) => typeof value === 'string' &&
      (value.startsWith('/dev/') || /^disk\d/u.test(value)))
    if (typeof selector === 'string' && selector.startsWith('/dev/')) {
      // A /dev path is enumerable for the device-identity probes.
      emitTargets('write-content', [{ value: selector, index: 0 }], {
        ...options, details: { deviceMutation: true },
      }, env)
      return
    }
    if (typeof selector === 'string' && selector !== '') {
      // A bare diskN identifier is not a host device path: the shape is stated,
      // but the selector is unresolvable and must deny, not allow silently.
      env.operation('write-content', { kind: 'unknown', reason: 'storage-selector' },
        { ...options, details: { deviceMutation: { path: selector } } })
    }
    env.candidate('unverified-effect', 'Storage mutation selector could not be resolved to a host device', undefined, options.origin)
    return
  }
  env.gap('unmodeled-command', options.origin)
}

const PARTED_WRITE_SUBCOMMANDS = new Set(['mklabel', 'mkpart', 'rm', 'resizepart'])

function partedCommand(args, options, env) {
  let i = 0
  while (i < args.length) {
    const value = args[i]
    if (typeof value !== 'string') { env.gap('unmodeled-command', options.origin); return }
    if (value === '--') { i += 1; break }
    if (value.startsWith('-') && value !== '-') {
      // -l/-m/--list/--machine print and exit; -v/--version likewise.
      if (['-l', '--list', '-m', '--machine', '-v', '--version'].includes(value)) {
        env.gap('unmodeled-command', options.origin)
        return
      }
      if (value === '-a') { i += 2; continue } // --align takes a value
      if (/^--[^=\s]+=/u.test(value) || value.startsWith('--')) { i += 1; continue }
      if (['-s', '--script'].includes(value)) { i += 1; continue }
      env.gap('unmodeled-command', options.origin)
      return
    }
    break
  }
  // `parted [options] [device] [command…]`: the write subcommand marks the
  // destructive form; the device is the literal operand before it, when present.
  const rest = args.slice(i)
  const writeIndex = rest.findIndex((value) => typeof value === 'string' && PARTED_WRITE_SUBCOMMANDS.has(value))
  if (writeIndex < 0) { env.gap('unmodeled-command', options.origin); return }
  const device = rest.slice(0, writeIndex).find((value) => typeof value === 'string' && !value.startsWith('-'))
  storageMutationFact(device, options, env)
}

const SGDISK_WRITE_VALUE_SHORT = new Set(['d', 'n', 't', 'A', 'c'])
const SGDISK_WRITE_VALUE_LONG = new Set(['--delete', '--new', '--typecode', '--attributes', '--change-name'])
const SGDISK_WRITE_BOOL_SHORT = new Set(['Z', 'o'])
const SGDISK_WRITE_BOOL_LONG = new Set(['--zap-all', '--clear'])
const SGDISK_READ_FLAGS = new Set(['-p', '--print', '-v', '--verify', '-V', '--version', '-h', '--help', '-?'])

/** `sgdisk` partition-table writes (DSR-031 决定 3). Every write option's value is
 * consumed (attached `-t1:8300` and separate `-t 1:8300` forms), so it can never
 * be mistaken for the device operand or shift the selection. `-P/--pretend` is a
 * real dry-run: when it appears no operation is produced (D3/preview). Read-only
 * forms (`-p/--print`, `-v/--verify`, version/help) stay coverage gaps. */
function sgdiskCommand(args, options, env) {
  let write = false
  let pretend = false
  const operands = []
  for (let i = 0; i < args.length; i++) {
    const value = args[i]
    if (typeof value !== 'string') continue
    if (!value.startsWith('-') || value === '-') { operands.push(value); continue }
    if (value.startsWith('--')) {
      const eq = value.indexOf('=')
      const name = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
      if (name === '--pretend') { pretend = true; continue }
      if (SGDISK_READ_FLAGS.has(name)) continue
      if (SGDISK_WRITE_BOOL_LONG.has(name)) { write = true; continue }
      if (SGDISK_WRITE_VALUE_LONG.has(name)) {
        write = true
        if (eq < 0 && typeof args[i + 1] === 'string') i += 1
        continue
      }
      continue
    }
    const letter = value[1]
    if (letter === 'P') { pretend = true; continue }
    if (SGDISK_READ_FLAGS.has('-' + letter)) continue
    if (SGDISK_WRITE_BOOL_SHORT.has(letter)) { write = true; continue }
    if (SGDISK_WRITE_VALUE_SHORT.has(letter)) {
      write = true
      if (value.length === 2 && typeof args[i + 1] === 'string') i += 1
    }
  }
  if (write) {
    // `-P/--pretend` only reports what would be written: no operation and no candidate.
    if (pretend) { env.gap('unmodeled-command', options.origin); return }
    storageMutationFact(operands.length > 0 ? operands[operands.length - 1] : undefined, options, env)
    return
  }
  env.gap('unmodeled-command', options.origin) // print/verify and unmodeled forms stay gaps
}

function fdiskCommand(args, options, env) {
  let listing = false
  let unmodeled = false
  const operands = []
  for (let i = 0; i < args.length; i++) {
    const value = args[i]
    if (typeof value !== 'string') { unmodeled = true; continue }
    if (value.startsWith('-') && value !== '-') {
      if (['-l', '--list', '-s', '--size'].includes(value)) { listing = true; continue }
      if (['-b', '-C', '-H', '-S'].includes(value)) {
        if (i + 1 < args.length && typeof args[i + 1] === 'string') i += 1
        else unmodeled = true
        continue
      }
      unmodeled = true
      continue
    }
    operands.push(value)
  }
  if (listing || unmodeled || operands.length === 0) { env.gap('unmodeled-command', options.origin); return }
  storageMutationFact(operands[0], options, env)
}

function blkdiscardCommand(args, options, env) {
  let device
  for (let i = 0; i < args.length; i++) {
    const value = args[i]
    if (typeof value !== 'string') { device = undefined; break }
    if (value.startsWith('-') && value !== '-') {
      if (['-o', '--offset', '-l', '--length', '-p', '--step'].includes(value)) i += 1
      continue
    }
    device = value
    break
  }
  storageMutationFact(device, options, env)
}

// --- unshare: transparent namespace wrapper (DSR-031 决定 7) --------------------

/** util-linux `unshare` option classes (verified against `unshare(1)`, util-linux
 * 2.43). Namespace creation itself is NOT a decision fact: only the unwrapped
 * inner program is analyzed (D5 transparency). The `[=file]` namespace options
 * (`-m/--mount`, `-p/--pid`, …) only take an attached value and never consume the
 * next word, so a bare `--mount` is a boolean. `--monotonic`/`--boottime`,
 * `-R/--root`, `-w/--wd`, `--setgroups` and `--propagation` take a separate value. */
const UNSHARE_VALUE_SHORT = new Set(['-w', '-R', '-S', '-G', '-l'])
const UNSHARE_VALUE_LONG = new Set(['--wd', '--root', '--setgroups', '--propagation', '--map-user',
  '--map-users', '--map-group', '--map-groups', '--owner', '--setuid', '--setgid', '--load-interp',
  '--monotonic', '--boottime', '--whitelist-env'])
const UNSHARE_BOOL_SHORT = new Set(['-f', '-r', '-m', '-p', '-u', '-i', '-n', '-U', '-P', '-T', '-C',
  '-o', '-k', '-c', '-h', '-V'])
const UNSHARE_BOOL_LONG = new Set(['--fork', '--map-root-user', '--map-current-user', '--mount',
  '--pid', '--user', '--uts', '--ipc', '--net', '--cgroup', '--time', '--kill-child', '--mount-proc',
  '--mount-binfmt', '--map-auto', '--map-subids', '--keep-caps', '--forward-signals', '--clear-env',
  '--help', '--version'])

/** Index of the inner program token of `unshare [options] [program [args…]]`,
 * or args.length when no program operand is present, or -1 when an option cannot
 * be modeled (a gap — D5: the wrapper itself never adds a candidate or a deny). */
function unshareProgramIndex(args, options, env) {
  let i = 0
  while (i < args.length) {
    const value = args[i]
    if (typeof value !== 'string') { env.gap('unmodeled-command', options.origin); return -1 }
    if (value === '--') { i += 1; break }
    if (!value.startsWith('-') || value === '-') break
    // Help/version are lookups: the command printed by unshare never runs (D3).
    if (['-h', '--help', '-V', '--version'].includes(value)) { env.gap('unmodeled-command', options.origin); return -1 }
    if (value.startsWith('--')) {
      const eq = value.indexOf('=')
      const name = eq < 0 ? value : value.slice(0, eq)
      if (UNSHARE_VALUE_LONG.has(name)) {
        if (eq >= 0) { i += 1; continue }
        if (typeof args[i + 1] !== 'string') { env.gap('unmodeled-command', options.origin); return -1 }
        i += 2
        continue
      }
      if (UNSHARE_BOOL_LONG.has(name)) { i += 1; continue }
      env.gap('unmodeled-command', options.origin)
      return -1
    }
    // Short cluster: a value letter consumes the rest of the word or the next word.
    let advance = 1
    for (let k = 1; k < value.length; k++) {
      const letter = `-${value[k]}`
      if (UNSHARE_VALUE_SHORT.has(letter)) {
        if (value.slice(k + 1) === '') {
          if (typeof args[i + 1] !== 'string') { env.gap('unmodeled-command', options.origin); return -1 }
          advance = 2
        }
        break
      }
      if (!UNSHARE_BOOL_SHORT.has(letter)) { env.gap('unmodeled-command', options.origin); return -1 }
    }
    i += advance
  }
  return i
}

// --- outbound transfer surface (DSR-031 决定 6) --------------------------------

/** Cloud instance-metadata endpoints: access is a concrete exfiltration clue that
 * analysis cannot resolve into countable operations (`unverified-effect`). The list
 * covers the mainstream IMDS addresses (EC2/GCE/Azure/OCI, AWS IPv6, Alibaba), the
 * ECS task-role endpoint, EKS Pod Identity (IPv4 + IPv6) and the `metadata.goog`
 * short name (its own hostname, not a substring of `metadata.google.internal`).
 * Hosts compare exactly; the URL port is already dropped by `URL.hostname`. */
const METADATA_HOSTS = new Set([
  '169.254.169.254', 'fd00:ec2::254', 'metadata.google.internal', '100.100.100.200',
  '169.254.170.2', '169.254.170.23', 'fd00:ec2::23', 'metadata.goog',
])

/** Lower-cased URL host of a token, or null when no host is provable. A scheme-less
 * token is treated as http (curl/wget semantics) only when it has a dotted host shape;
 * a bare path/filename can never name a host. */
function urlHost(value) {
  if (typeof value !== 'string' || value === '' || /\s/u.test(value)) return null
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//iu.test(value)
    ? value
    : /^[A-Za-z0-9.-]+\.[A-Za-z0-9.-]+(?::\d+)?(?:[/?#]|$)/u.test(value) ? `http://${value}` : null
  if (candidate === null) return null
  try {
    const host = new URL(candidate).hostname
    return host ? host.replace(/^\[/u, '').replace(/\]$/u, '').toLowerCase() : null
  } catch {
    return null
  }
}

/** Local files a curl call reads and sends: `-T/--upload-file <file>` and the `@file`
 * payloads of `-d/--data*` and `-F/--form name=@file[;type=…]` (DSR-031 决定 6).
 * `@-` (stdin) and `@http(s)://…` never name a local read. */
const CURL_UPLOAD_FLAGS = new Set(['-T', '--upload-file'])
const CURL_DATA_FLAGS = new Set(['-d', '--data', '--data-binary', '--data-raw', '--data-urlencode'])
const CURL_FORM_FLAGS = new Set(['-F', '--form'])

function collectCurlUploads(args) {
  const files = []
  const addFile = (raw, index) => {
    if (typeof raw !== 'string' || raw === '' || raw === '-') return
    if (/^[a-z][a-z0-9+.-]*:\/\//iu.test(raw)) return // a remote URL, not a local read
    files.push({ value: raw, index })
  }
  const addAtFile = (raw, index) => {
    if (typeof raw !== 'string' || !raw.startsWith('@')) return // inline data, not a file
    let value = raw.slice(1)
    const semi = value.indexOf(';')
    if (semi >= 0) value = value.slice(0, semi) // drop `;type=…` / `;filename=…`
    addFile(value, index)
  }
  const addFormField = (raw, index) => {
    if (typeof raw !== 'string') return
    const eq = raw.indexOf('=')
    if (eq < 0) return
    addAtFile(raw.slice(eq + 1), index)
  }
  for (let i = 0; i < args.length; i++) {
    const value = args[i]
    if (typeof value !== 'string' || value === '-') continue
    if (value === '--') break // after the terminator every word is a URL, never an option
    if (value.startsWith('--')) {
      const eq = value.indexOf('=')
      const flag = eq < 0 ? value : value.slice(0, eq)
      if (CURL_UPLOAD_FLAGS.has(flag)) { addFile(eq < 0 ? args[++i] : value.slice(eq + 1), i); continue }
      if (CURL_DATA_FLAGS.has(flag)) { addAtFile(eq < 0 ? args[++i] : value.slice(eq + 1), i); continue }
      if (CURL_FORM_FLAGS.has(flag)) { addFormField(eq < 0 ? args[++i] : value.slice(eq + 1), i); continue }
      continue
    }
    // Attached short forms: `-Tfile`, `-d@file`, `-Fname=@file`.
    if (value.length > 2 && value.startsWith('-T')) { addFile(value.slice(2), i); continue }
    if (value.length > 2 && value.startsWith('-d')) { addAtFile(value.slice(2), i); continue }
    if (value.length > 2 && value.startsWith('-F')) { addFormField(value.slice(2), i); continue }
    if (CURL_UPLOAD_FLAGS.has(value)) { addFile(args[++i], i); continue }
    if (CURL_DATA_FLAGS.has(value)) { addAtFile(args[++i], i); continue }
    if (CURL_FORM_FLAGS.has(value)) { addFormField(args[++i], i); continue }
  }
  return files
}

/** `wget --post-file=<file>` / `--body-file=<file>` read a local body source. */
function collectWgetUploads(args) {
  const files = []
  for (let i = 0; i < args.length; i++) {
    const value = args[i]
    if (typeof value !== 'string') continue
    const eq = value.indexOf('=')
    const flag = (eq >= 0 ? value.slice(0, eq) : value).toLowerCase()
    if (flag !== '--post-file' && flag !== '--body-file') continue
    const assigned = eq >= 0 ? value.slice(eq + 1) : args[++i]
    if (typeof assigned !== 'string' || assigned === '' || assigned === '-') continue
    if (/^[a-z][a-z0-9+.-]*:\/\//iu.test(assigned)) continue
    files.push({ value: assigned, index: i })
  }
  return files
}

/** Emit the metadata-endpoint candidate (once) and then the local upload reads. */
function outboundTransferCommand(args, options, env, uploads) {
  for (const value of args) {
    const host = urlHost(value)
    if (host === null || !METADATA_HOSTS.has(host)) continue
    env.candidate('unverified-effect', `Cloud metadata endpoint access: ${host}`,
      [`${host} (cloud instance metadata)`], options.origin)
    break
  }
  if (uploads.length > 0) emitTargets('read-content', uploads, { ...options, patterns: [] }, env)
  // The rest of the curl/wget surface is not modeled; keep the existing coverage gap
  // (a gap never escalates — D1), and an ordinary download produces no candidate.
  env.gap('unmodeled-command', options.origin)
}

function curlCommand(args, options, env) {
  outboundTransferCommand(args, options, env, collectCurlUploads(args))
}

function wgetCommand(args, options, env) {
  outboundTransferCommand(args, options, env, collectWgetUploads(args))
}


/** Subcommands whose `--abort` discards an in-progress operation's state (DSR-031
 * 决定 8). The scope text is per subcommand: `rebase`/`am` abort provably discards
 * uncommitted changes, while `merge`/`cherry-pick`/`revert` abort resets the
 * operation state without guaranteeing that unrelated uncommitted changes are lost. */
const GIT_ABORT_SUBCOMMANDS = new Map([
  ['rebase', 'git rebase --abort discards uncommitted changes in the working tree'],
  ['am', 'git am --abort discards uncommitted changes in the working tree'],
  ['merge', 'git merge --abort restores the merge state; uncommitted changes may be lost'],
  ['cherry-pick', 'git cherry-pick --abort restores the sequencer state; uncommitted changes may be lost'],
  ['revert', 'git revert --abort restores the sequencer state; uncommitted changes may be lost'],
])

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
    // DSR-031 决定 8 (facts side): `<subcommand> --abort` is modeled as a Git state
    // restoration whose decision is delegated to the evidence layer
    // (`git-evidence` + `gitDir` markers). The facts layer never probes the
    // filesystem itself; every other sequencer form (`--continue`/`--skip`/`--quit`)
    // stays untouched. `knownScope` is mandatory: without it an `unknown` target
    // would be treated as unscoped and deny instead of confirming
    // (`data.git.restore`).
    if (GIT_ABORT_SUBCOMMANDS.has(cmd) && has('--abort')) {
      env.operation('git-restore', {
        kind: 'unknown',
        reason: 'git-evidence',
        knownScope: [GIT_ABORT_SUBCOMMANDS.get(cmd)],
      }, { ...options, context, details: { command: `${cmd}-abort`, args: rest, global } })
      return
    }
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
    patterns: unit.patterns, literalOperands: unit.literalOperands, heredocs: unit.heredocs, pipeline: unit.pipeline }
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
  // PowerShell is a dialect of the CMDLET/alias grammar only. After the PowerShell
  // branch above, these names are EXTERNAL programs and keep their own grammar; a
  // `!unit.powershell` gate here silently disabled that analysis and allowed real
  // deletions. `curl`/`wget` are no longer Invoke-WebRequest aliases in PowerShell 7;
  // the Windows PowerShell 5.1 alias difference is an existing dialect boundary.
  if (unit.cmdDialect === true && ['rmdir', 'rd', 'del', 'erase'].includes(name)) return cmdInline(name, args, options, env)
  if (deleting.has(name) || name === 'cp') return posixFileCommand(name, args, options, env)
  if (name === 'git') return gitCommand(args, options, env)
  if (name === 'find' && !unit.cmdDialect) return findCommand(args, options, env)
  if (name === 'xargs') return streamFedCommand('xargs', args, options, env)
  if (name === 'parallel') return streamFedCommand('parallel', args, options, env)
  if (name === 'shred') return shredCommand(args, options, env)
  if (name === 'rsync') return rsyncCommand(args, options, env)
  if (name === 'ssh' && !unit.cmdDialect) return sshCommand(args, options, env)
  // DSR-031 决定 7: `unshare` is a transparent wrapper. The inner program is
  // analyzed with the wrapper's arguments trimmed; the wrapper itself adds no
  // candidate and no denial, and a missing program operand is a plain gap.
  if (name === 'unshare' && !unit.cmdDialect) {
    const inner = unshareProgramIndex(args, options, env)
    if (inner < 0) return
    const program = args[inner]
    if (typeof program !== 'string') { env.gap('unmodeled-command', origin); return }
    return resolveCommand(program, args.slice(inner + 1), {
      ...unit,
      ...(Array.isArray(unit.patterns) && { patterns: unit.patterns.slice(inner + 1) }),
      ...(Array.isArray(unit.literalOperands) && { literalOperands: unit.literalOperands.slice(inner + 1) }),
    }, env)
  }
  if (name === 'curl' && !unit.cmdDialect) return curlCommand(args, options, env)
  if (name === 'wget' && !unit.cmdDialect) return wgetCommand(args, options, env)
  if (name === 'awk' && !unit.cmdDialect) return awkCommand(args, options, env)
  if (name === 'tar' && !unit.cmdDialect) return tarCommand(args, options, env)
  if (name === '7z' && !unit.cmdDialect) return sevenZipCommand(args, options, env)
  if (name === 'zip' && !unit.cmdDialect) return zipCommand(args, options, env)
  if (!unit.cmdDialect) {
    if (name === 'diskutil') return diskutilCommand(args, options, env)
    if (name === 'parted') return partedCommand(args, options, env)
    if (name === 'sgdisk') return sgdiskCommand(args, options, env)
    if (name === 'fdisk') return fdiskCommand(args, options, env)
    if (name === 'blkdiscard') return blkdiscardCommand(args, options, env)
  }
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
    if (targetIndex >= 0) {
      emitTargets('write-content', [{ value: args[targetIndex], index: targetIndex }], {
        ...options, details: { deviceMutation: true },
      }, env)
      // DSR-031 决定 10: a device write requested from a container is proven as an
      // operation, but the host-device identity cannot be probed from that domain.
      // Record the unproven identity so it cannot fall through as a silent allow.
      if (options.context?.domain === 'container') {
        env.candidate('unverified-effect', 'Device mutation inside a container cannot be verified against the host device', undefined, origin)
      }
    } else env.candidate('unverified-effect', 'Device utility target is unknown', undefined, origin)
    return
  }
  if (contentReaders.has(name)) return contentCommand(name, args, options, env)
  if (name === 'wsl' && windows) {
    const context = { domain: 'wsl', platform: 'linux' }
    // DSR-031 决定 1: when the post-wsl command is a POSIX shell receiver and this
    // call carries a heredoc that receiver reads as its stdin script, the body is
    // the script — analyzed in the wsl domain. `-c` and script-file forms keep the
    // argv path (the heredoc stays data there). A non-literal receiver keeps the
    // existing argv child / coverage gap.
    const emitWslProgram = (executable, argv) => {
      if (HEREDOC_SHELL_RECEIVERS.has(executable) &&
        emitHeredocShellChild(executable, argv, options, env, context)) return
      env.child({ source: { kind: 'argv', executable, args: argv },
        language: 'unknown', context, condition: unit.condition, origin })
    }
    // Management/query switches: wsl.exe performs the operation itself; no
    // distribution command line follows, so they stay a coverage gap (放行).
    const manageFlags = new Set(['-l', '--list', '-t', '--terminate', '--shutdown', '--running', '--import',
      '--export', '--mount', '--unmount', '--install', '--update', '--status', '--version',
      '-h', '--help', '-v', '--verbose'])
    for (let index = 0; index < args.length; index++) {
      const flag = args[index]
      if (flag === '--') {
        const rest = args.slice(index + 1)
        if (typeof rest[0] !== 'string') { env.gap('wsl-shell', origin); return }
        emitWslProgram(rest[0], rest.slice(1))
        return
      }
      if (flag === '-e' || flag === '--exec') {
        if (typeof args[index + 1] !== 'string') { env.gap('wsl-shell', origin); return }
        emitWslProgram(args[index + 1], args.slice(index + 2))
        return
      }
      if (typeof flag !== 'string') { env.gap('wsl-shell', origin); return }
      // `wsl --unregister <distro>` permanently deletes the distribution's data and
      // settings: a real irreversible deletion, confirmed on the command shape (D3).
      if (flag === '--unregister' || flag.startsWith('--unregister=')) {
        const distro = flag.startsWith('--unregister=') ? flag.slice('--unregister='.length)
          : args[index + 1]
        if (distro === undefined || distro === '') {
          // Bare call is a usage error: no operation, no fabricated confirmation.
          env.gap('wsl-shell', origin)
          return
        }
        if (typeof distro !== 'string') {
          // A dynamic distro name still identifies a real deletion; the command
          // shape stays the decision scope (same treatment as rsync's destination).
          env.operation('delete', {
            kind: 'unknown',
            reason: 'wsl-distro-remove',
            knownScope: ['wsl --unregister (unresolved distribution)'],
          }, options)
          return
        }
        env.operation('delete', {
          kind: 'unknown',
          reason: 'wsl-distro-remove',
          knownScope: [`wsl --unregister ${distro}`],
        }, options)
        return
      }
      if (manageFlags.has(flag)) { env.gap('wsl-shell', origin); return }
      if (['-d', '--distribution', '-u', '--user', '--cd'].includes(flag)) {
        const value = args[++index]
        if (typeof value !== 'string') { env.gap('wsl-context', origin); continue }
        if (flag === '-d' || flag === '--distribution') context.distribution = value
        else if (flag === '-u' || flag === '--user') context.user = value
        else if (value.startsWith('/')) context.cwd = value
        else env.gap('wsl-context', origin)
        continue
      }
      if (flag.startsWith('-')) { env.gap('wsl-shell', origin); return } // unmodeled switch
      // Without --exec the distribution shell still runs the command line: analyze it.
      emitWslProgram(flag, args.slice(index + 1))
      return
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
  // Heredoc-fed stdin scripts: a heredoc attached to a POSIX shell interpreter
  // is that interpreter's script text, quoted delimiter or not. Non-shell
  // receivers (cat, tee, python, sqlite3, …) keep the data-position behavior.
  if (!unit.powershell && !unit.cmdDialect && HEREDOC_SHELL_RECEIVERS.has(name) &&
    emitHeredocShellChild(name, args, options, env)) return
  const language = interpreters.get(name) ?? (/^python3\.\d+$/u.test(name) ? 'python' : undefined)
  if (language) return wrapper(language, args, options, env)
  // DSR-031 决定 10: docker run/exec payloads are intercepted before the remote
  // dispatcher so the image/container boundary is parsed here; other docker
  // subcommands (prune/rm/rmi/volume) stay with commands-remote.js. `docker` is an
  // external program in every dialect, PowerShell included.
  if (name === 'docker' && !unit.cmdDialect && dockerPayloadCommand(args, options, env)) return
  if (resolveRemoteCommand(name, args, options, env)) return
  env.gap(unit.cmdDialect === true ? 'cmd-inline' : 'unmodeled-command', origin)
}
