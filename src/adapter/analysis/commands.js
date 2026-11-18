import path from 'node:path'

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
  ['zsh', 'unknown'], ['fish', 'unknown'], ['cmd', 'unknown'],
])

function emitTargets(action, operands, options, env) {
  const { context, recursive = false, patterns = [] } = options
  const api = context.platform === 'win32' ? path.win32 : path.posix
  const known = operands.filter(({ value, index }) => typeof value === 'string' && !patterns[index])
  const usable = known.filter(({ value }) => api.isAbsolute(value) || api.isAbsolute(context.cwd ?? ''))
  if (recursive === true && ['delete', 'move-source'].includes(action)) {
    for (const { value } of usable) env.operation(action, { kind: 'subtree', root: value }, options)
  } else if (usable.length) {
    env.operation(action, { kind: 'exact', paths: usable.map(({ value }) => value) }, options)
  }
  for (const { value, index } of operands) {
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
  if (operands.some(({ value }) => value == null) || known.length > usable.length) {
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
  if (!action) return
  const preview = (action === 'git-clean' && flags.some((value) => typeof value === 'string' &&
    /^(?:--dry-run|-[a-zA-Z]*n[a-zA-Z]*)$/u.test(value))) ||
    (cmd === 'push' && (has('--dry-run') || has('-n')))
  env.operation(action, { kind: 'unknown', reason: 'git-evidence' }, {
    ...options, context, preview, details: { command: cmd, args: rest, global },
  })
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
  if (deleting.has(name) || name === 'cp') return posixFileCommand(name, args, options, env)
  if (name === 'git') return gitCommand(args, options, env)
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
  env.gap('unmodeled-command', origin)
}
