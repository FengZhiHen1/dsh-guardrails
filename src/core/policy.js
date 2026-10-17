// policy — confirmed local operation semantics and pure risk decisions.
// Boundary: no filesystem or process access; unknown effects remain allow.
// Reference: confirmed 2026-10-17 baseline, S-F1/S-F2 and absolute deny boundaries.

const CONTENT_ACTIONS = new Set(['read', 'write', 'delete', 'move', 'copy', 'worktree-remove', 'device-destroy'])
const READ_NAMES = new Set(['read', 'read_image', 'grep', 'cat', 'head', 'tail', 'less', 'more', 'get-content', 'gc', 'type', 'select-string'])
const WRITE_NAMES = new Set(['write', 'edit', 'set-content', 'add-content', 'clear-content', 'out-file', 'tee', 'truncate'])
const DELETE_NAMES = new Set(['delete', 'rm', 'rmdir', 'remove-item', 'ri', 'del', 'erase'])
const MOVE_NAMES = new Set(['move', 'mv', 'move-item', 'mi', 'rename-item', 'ren'])
const COPY_NAMES = new Set(['copy', 'cp', 'copy-item', 'cpi'])
const PS_VALUE_OPTIONS = new Set(['-path', '-literalpath', '-destination', '-value', '-encoding', '-filter', '-include', '-exclude', '-stream', '-erroraction', '-warningaction', '-pattern'])

function commandName(value) {
  if (typeof value !== 'string') return null
  return value.replace(/\\/g, '/').split('/').at(-1).toLowerCase().replace(/\.exe$/, '')
}

function operands(args, powershell, name) {
  const paths = []
  let literal = false
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]
    if (arg === null) { paths.push(null); continue }
    if (typeof arg !== 'string') throw new TypeError('guardrails: command arguments must be strings or null')
    if (!literal && arg === '--') { literal = true; continue }
    if (!literal && arg.startsWith('-')) {
      const option = arg.toLowerCase()
      if (powershell && PS_VALUE_OPTIONS.has(option)) {
        const value = args[++index]
        if (['-path', '-literalpath', '-destination'].includes(option)) paths.push(value ?? null)
      } else if (!powershell) {
        const takesValue = {
          head: ['-n', '--lines', '-c', '--bytes'], tail: ['-n', '--lines', '-c', '--bytes', '--pid', '-s', '--sleep-interval'],
          grep: ['-e', '--regexp', '-f', '--file', '-m', '--max-count', '-A', '-B', '-C', '--after-context', '--before-context', '--context'],
          truncate: ['-s', '--size', '-r', '--reference'],
        }
        if ((takesValue[name] ?? []).includes(arg)) index += 1
      }
      continue
    }
    paths.push(arg)
  }
  return paths
}

/** Convert explicit structured file-tool parameters into the shared command IR. */
export function structuredCommands(name, args = {}) {
  if (typeof name !== 'string' || !args || typeof args !== 'object') return []
  const short = name.split('.').at(-1)
  if (!['read', 'read_image', 'write', 'edit', 'grep', 'glob', 'delete', 'move', 'copy'].includes(short)) return []
  const target = args.file_path ?? args.path
  if (typeof target !== 'string') return []
  const paths = [target]
  if (typeof args.destination === 'string') paths.push(args.destination)
  return [{ name: short, args: paths, structured: true }]
}

/** Extract bounded literal operations without evaluating shell text.
 * @throws {TypeError} If parser IR is malformed.
 * @throws {RangeError} If the command budget is exceeded.
 */
export function extractOperations(commands = []) {
  if (!Array.isArray(commands)) throw new TypeError('guardrails: commands must be an array')
  if (commands.length > 2048) throw new RangeError('guardrails: command count exceeds analysis budget')
  const operations = []
  for (const command of commands) {
    if (!command || !Array.isArray(command.args) || command.args.length > 4096) throw new TypeError('guardrails: invalid command IR')
    const name = commandName(command.name)
    const args = command.args
    if (args.some((arg) => arg !== null && typeof arg !== 'string')) throw new TypeError('guardrails: invalid command argument')
    const lower = args.map((arg) => typeof arg === 'string' ? arg.toLowerCase() : null)
    const powershell = name?.includes('-') || ['gc', 'ri', 'mi', 'cpi', 'type', 'del', 'erase', 'ren'].includes(name)
    const recursive = lower.some((arg) => arg === '-recurse' || arg === '-recurse:$true' || arg === '--recursive' || (!powershell && /^-[a-z]*r[a-z]*$/i.test(arg ?? '')))
    const metadataOnly = lower.includes('--help') || lower.includes('--version')
      || (powershell && lower.some(arg => ['-whatif', '-whatif:$true', '-wi', '-wi:$true'].includes(arg)))
      || (name === 'wipefs' && lower.some((arg) => ['-n', '--no-act', '--help', '--version'].includes(arg)))
      || (name?.startsWith('mkfs.ext') && lower.includes('-n'))
    // Redirections still take effect even when the command body only prints help.
    if (metadataOnly) {
      for (const redirect of command.redirects ?? []) {
        if (/^(?:\d*|\*)>{1,2}$/.test(redirect.operator ?? '') && typeof redirect.target === 'string') {
          operations.push({ action: 'write', path: redirect.target, recursive: false })
        }
      }
      continue
    }
    const emit = (action, paths, extra = {}) => {
      for (const target of paths) {
        if (typeof target === 'string' && target.length > 0 && target.length <= 32768) {
          operations.push({ action, path: target, recursive, ...extra })
        }
      }
    }
    if (name === 'git') {
      // Only exact native worktree removal is covered; other Git rules remain candidates.
      let index = 0
      let gitCwd
      while (args[index] === '-C' && typeof args[index + 1] === 'string') {
        gitCwd = gitCwd ? `${gitCwd}/${args[index + 1]}` : args[index + 1]
        index += 2
      }
      if (args[index] === 'worktree' && args[index + 1] === 'remove') {
        emit('worktree-remove', operands(args.slice(index + 2), false), { recursive: true, cwd: gitCwd })
      }
    } else if (READ_NAMES.has(name)) {
      let paths = operands(args, powershell, name)
      if (['grep', 'select-string'].includes(name) && !command.structured) {
        // The first bare argument is the search pattern, not a file path.
        const patternOption = lower.some((arg) => ['-e', '--regexp', '-pattern'].includes(arg))
        if (!patternOption) paths = paths.slice(1)
      }
      emit('read', paths, { recursive: recursive || name === 'grep' || name === 'select-string' })
    } else if (WRITE_NAMES.has(name)) {
      const paths = operands(args, powershell, name)
      const explicitPaths = []
      for (let index = 0; index < args.length - 1; index += 1) {
        if (['-path', '-literalpath'].includes(lower[index])) explicitPaths.push(args[index + 1])
      }
      emit('write', explicitPaths.length ? explicitPaths : paths.slice(0, 1))
    } else if (DELETE_NAMES.has(name)) {
      emit('delete', operands(args, powershell, name))
    } else if (MOVE_NAMES.has(name) || COPY_NAMES.has(name)) {
      emit(MOVE_NAMES.has(name) ? 'move' : 'copy', operands(args, powershell, name), { recursive: MOVE_NAMES.has(name) || recursive })
    } else if (['clear-disk', 'initialize-disk', 'format-volume', 'remove-partition'].includes(name)) {
      if (!lower.includes('-whatif') && !lower.includes('-whatif:$true')) {
        const numberOption = name === 'format-volume' ? '-disknumber' : name === 'remove-partition' ? '-disknumber' : '-number'
        const numberIndex = lower.indexOf(numberOption)
        const driveIndex = lower.indexOf('-driveletter')
        const rawNumber = numberIndex >= 0 ? args[numberIndex + 1] : null
        const diskNumber = typeof rawNumber === 'string' && /^\d+$/.test(rawNumber) ? Number(rawNumber) : undefined
        const driveLetter = driveIndex >= 0 ? args[driveIndex + 1] : undefined
        if (diskNumber !== undefined || typeof driveLetter === 'string') {
          operations.push({ action: 'device-destroy', path: '', selector: { ...(diskNumber !== undefined ? { diskNumber } : {}), ...(typeof driveLetter === 'string' ? { driveLetter } : {}) } })
        }
      }
    } else if (name === 'dd') {
      const output = args.find((arg) => typeof arg === 'string' && arg.startsWith('of='))
      if (output) emit('device-destroy', [output.slice(3)], { whole: true })
    } else if (name === 'wipefs' || name === 'blkdiscard' || name === 'shred' || name === 'mkfs' || name?.startsWith('mkfs.')) {
      emit('device-destroy', operands(args, false), { whole: true })
    }
    for (const redirect of command.redirects ?? []) {
      if (typeof redirect?.operator !== 'string') continue
      if (/^(?:\d*|\*)>{1,2}$/.test(redirect.operator)) emit('write', [redirect.target])
      if (/^\d*</.test(redirect.operator) && !redirect.operator.includes('<<')) emit('read', [redirect.target])
    }
  }
  return operations
}

/** Decide from observed identities; deny dominates ask.
 * @throws {TypeError} If target observations are absent or malformed.
 */
export function evaluatePolicy({ targets } = {}) {
  if (!targets || !Array.isArray(targets.operations)) throw new TypeError('guardrails: target observations are required')
  let ask
  for (const operation of targets.operations) {
    if (!CONTENT_ACTIONS.has(operation.action)) continue
    const destructiveTree = operation.action === 'delete' && operation.recursive
    if (operation.action === 'device-destroy' && operation.identity === 'host-physical-device') {
      return { kind: 'deny', ruleId: 'ABS-01', reason: 'ABSOLUTE: confirmed destructive access to a real host physical disk or partition.' }
    }
    if (destructiveTree && operation.identity === 'host-system-tree') {
      return { kind: 'deny', ruleId: 'ABS-02', reason: 'ABSOLUTE: confirmed whole-tree destruction of the host OS root or core system structure.' }
    }
    if (destructiveTree && operation.gitSharedBody === true) {
      return { kind: 'deny', ruleId: 'ABS-03', reason: 'ABSOLUTE: confirmed direct destruction of the actual shared Git metadata body.' }
    }
    if (operation.protected === true || operation.containsProtected === true) {
      const ruleId = operation.action === 'worktree-remove' ? 'S-F2' : 'S-F1'
      ask ??= { kind: 'ask', ruleId, reason: `${ruleId}: this operation directly accesses or removes an actual protected file. Use runtime credential injection or a health check that reports only non-secret status when possible; approval applies only to this call.` }
    }
  }
  return ask ?? { kind: 'allow' }
}
