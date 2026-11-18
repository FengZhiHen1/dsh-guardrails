import { constants } from 'node:fs'
import { lstat, open } from 'node:fs/promises'
import path from 'node:path'
import { resolveCommand } from './commands.js'
import { createShellAnalyzer } from './shell.js'
import { createProgramAnalyzer } from './program.js'
import { inlineCredentialDecision } from '../../core/redaction.js'
import { textMentionsCredential } from '../../core/rules.js'

// Provisional limits keep analysis bounded while release measurements are pending.
const DEFAULT_LIMITS = Object.freeze({
  timeoutMs: 8_000,
  maxSourceBytes: 512 * 1024,
  maxInputBytes: 512 * 1024,
  maxTotalBytes: 2 * 1024 * 1024,
  maxOutputBytes: 8 * 1024 * 1024,
  maxDepth: 10,
  maxUnits: 32,
  maxFiles: 16,
  maxSteps: 150_000,
  maxOperations: 2_000,
  maxConcurrent: 3,
  maxQueue: 12,
})

class LocalBudgetError extends Error {}

function combineCondition(left, right) {
  if (left === 'unknown' || right === 'unknown') return 'unknown'
  if (left === 'possible' || right === 'possible') return 'possible'
  return 'certain'
}

function compareOrder(left, right) {
  for (let index = 0; index < Math.min(left.length, right.length); index++) {
    if (left[index] !== right[index]) return left[index] - right[index]
  }
  return left.length - right.length
}

const hostPaths = (platform) => platform === 'win32' ? path.win32 : path.posix

/** Content actions whose target can be an unresolved dynamic operand (R-04 scan gate). */
const TEXT_SCAN_ACTIONS = new Set(['read-content', 'copy-content', 'write-content', 'truncate-content', 'delete', 'move-source'])

/** Whether any content operation of this analysis carries an unresolved dynamic operand.
 * Metadata-only observations never qualify. */
function hasUnresolvedProtectedOperand(operations) {
  return operations.some((operation) => TEXT_SCAN_ACTIONS.has(operation.action) &&
    operation.target?.kind === 'unknown')
}

function decodeSource(bytes) {
  const utf16 = bytes[0] === 0xff && bytes[1] === 0xfe ? 'utf-16le'
    : bytes[0] === 0xfe && bytes[1] === 0xff ? 'utf-16be' : 'utf-8'
  try {
    const text = new TextDecoder(utf16, { fatal: true }).decode(bytes)
    return text.includes('\0') ? undefined : text
  } catch {
    return undefined
  }
}

async function readSource(filename, byteLimit, signal) {
  const before = await lstat(filename, { bigint: true })
  if (!before.isFile()) return { gap: 'non-regular-source' }
  if (before.size > byteLimit) return { gap: 'source-size' }
  const handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0))
  try {
    const actual = await handle.stat({ bigint: true })
    if (!actual.isFile() || actual.ino !== before.ino || actual.dev !== before.dev) return { gap: 'source-changed' }
    const bytes = Buffer.alloc(byteLimit + 1)
    let size = 0
    while (size < bytes.length) {
      signal.throwIfAborted()
      const { bytesRead } = await handle.read(bytes, size, bytes.length - size, size)
      if (!bytesRead) break
      size += bytesRead
    }
    if (size > byteLimit) return { gap: 'source-size' }
    const after = await handle.stat({ bigint: true })
    if (after.size !== actual.size || after.mtimeNs !== actual.mtimeNs || BigInt(size) !== actual.size) return { gap: 'source-changed' }
    const text = decodeSource(bytes.subarray(0, size))
    return text === undefined ? { gap: 'encoding-unknown' } : { text, size }
  } finally {
    await handle.close()
  }
}

function makePool(capacity, queueLimit) {
  let active = 0
  const queue = new Set()
  const release = () => {
    const next = queue.values().next().value
    if (next) {
      queue.delete(next)
      next()
    } else active--
  }
  return async (signal) => {
    signal.throwIfAborted()
    if (active < capacity) {
      active++
      return release
    }
    if (queue.size >= queueLimit) return undefined
    return new Promise((resolve, reject) => {
      const onAbort = () => {
        queue.delete(onReady)
        reject(signal.reason)
      }
      const onReady = () => {
        signal.removeEventListener('abort', onAbort)
        resolve(release)
      }
      queue.add(onReady)
      signal.addEventListener('abort', onAbort, { once: true })
    })
  }
}

/** Analyzes source through a shared budget. Parser adapters report facts and child units. */
export function createExecutionAnalyzer({ limits: overrides = {}, shell, program } = {}) {
  const limits = { ...DEFAULT_LIMITS, ...overrides }
  for (const key of Object.keys(DEFAULT_LIMITS)) {
    if (!Number.isSafeInteger(limits[key]) || limits[key] <= 0) throw new RangeError(`Invalid analysis limit: ${key}`)
  }
  const lifetime = new AbortController()
  const enter = makePool(limits.maxConcurrent, limits.maxQueue)
  const shellAnalyzer = shell ?? createShellAnalyzer({ limits })
  const programAnalyzer = program ?? createProgramAnalyzer({ limits })
  const providers = new Map([
    ['bash', shellAnalyzer], ['posix', shellAnalyzer], ['powershell', shellAnalyzer],
    ['python', programAnalyzer], ['javascript', programAnalyzer], ['typescript', programAnalyzer],
  ])

  async function analyze(input, { signal: callerSignal } = {}) {
    const timeout = AbortSignal.timeout(limits.timeoutMs)
    const deadline = performance.now() + limits.timeoutMs
    const deadlineMs = Date.now() + limits.timeoutMs
    const signal = AbortSignal.any([lifetime.signal, timeout, ...(callerSignal ? [callerSignal] : [])])
    const result = { status: 'complete', operations: [], candidates: [], gaps: [] }
    const frames = []
    const order = new WeakMap()
    // Source texts of the units actually analyzed this call (already budget-reserved
    // references, no extra retention): the credential text scan reads only these.
    const scannedTexts = []
    let sequence = 0
    let expired = false
    let count = 0
    let files = 0
    let bytes = 0
    let steps = 0
    let release
    let unit

    function gap(kind, origin = unit?.origin) {
      if (result.status === 'complete') result.status = 'partial'
      if (result.gaps.length < limits.maxOperations) {
        result.gaps.push({ kind, unitId: unit?.unitId, origin })
      }
    }

    function checkDeadline() {
      signal.throwIfAborted()
      if (performance.now() >= deadline) {
        expired = true
        throw new Error('Analysis deadline exceeded')
      }
    }

    function enqueue(source, depth, parent = unit) {
      if (depth > limits.maxDepth || count >= limits.maxUnits) {
        gap('unit-budget', source.origin)
        return
      }
      const index = ++count
      const origin = source.origin ?? parent?.origin ?? { entry: 'program' }
      frames.push({
        ...source, unitId: String(index), depth,
        language: source.language ?? 'unknown',
        context: source.context ?? parent?.context ?? { domain: 'unknown' },
        condition: combineCondition(parent?.condition, source.condition),
        order: [...(parent?.order ?? []), sequence++],
        origin: { ...origin, ...(parent && { parentUnitId: parent.unitId }) },
        ancestors: source.ancestors ?? parent?.ancestors ?? [],
      })
    }

    function reserve(size) {
      if (size > limits.maxSourceBytes || bytes + size > limits.maxTotalBytes) throw new LocalBudgetError('source-size')
      bytes += size
    }

    try {
      release = await enter(signal)
      if (!release) {
        result.status = 'fault'
        gap('queue-full', input.origin)
        return result
      }
      enqueue(input, 0)
      while (frames.length) {
        checkDeadline()
        unit = frames.shift()
        const scope = (origin) => ({ ...unit.origin, ...origin })
        const operation = (action, target, options = {}) => {
          if (result.operations.length >= limits.maxOperations) throw new LocalBudgetError('operation-budget')
          const fact = {
            action, target,
            context: options.context ?? unit.context,
            origin: scope(options.origin),
            condition: combineCondition(unit.condition, options.condition),
            recursive: options.recursive ?? false,
            preview: options.preview === true,
            ...(options.details && { details: options.details }),
          }
          order.set(fact, [...unit.order, sequence++])
          result.operations.push(fact)
        }
        const candidate = (kind, reason, knownScope, origin) => {
          if (result.candidates.length >= limits.maxOperations) throw new LocalBudgetError('candidate-budget')
          result.candidates.push({ kind, reason, knownScope, origin: scope(origin) })
        }
        const child = (input) => enqueue(input, unit.depth + 1)
        const env = {
          signal, gap, operation, candidate, child, deadline,
          get limits() {
            return { ...limits, deadline: deadlineMs, timeoutMs: Math.max(1, Math.ceil(deadline - performance.now())),
              maxSteps: Math.max(1, limits.maxSteps - steps) }
          },
          step(n = 1) {
            checkDeadline()
            steps += n
            if (steps > limits.maxSteps) throw new LocalBudgetError('step-budget')
          },
          command(executable, args, options) {
            env.step()
            if (inlineCredentialDecision([{ name: executable, args }])) result.inlineCredential = true
            resolveCommand(executable, args, { ...unit, ...options }, env)
          },
        }

        try {
          const source = unit.source
          if (source.kind === 'argv') {
            if (!Array.isArray(source.args)) throw new TypeError('Expected an argument vector')
            let size = typeof source.executable === 'string' ? Buffer.byteLength(source.executable) : 0
            for (const arg of source.args) {
              env.step()
              size += typeof arg === 'string' ? Buffer.byteLength(arg) + 1 : 1
              if (size > limits.maxSourceBytes) throw new LocalBudgetError('source-size')
            }
            reserve(size)
            env.command(source.executable, source.args)
            continue
          }
          const provider = providers.get(unit.language)
          if (!provider && source.kind !== 'package-script') {
            gap('no-provider')
            continue
          }
          if (source.kind === 'inline') {
            if (typeof source.text !== 'string') throw new TypeError('Non-text analysis input')
            reserve(Buffer.byteLength(source.text))
            scannedTexts.push(source.text)
            await provider.analyze(unit, env)
            continue
          }
          if (source.kind !== 'file' && source.kind !== 'package-script') throw new TypeError('Unsupported analysis source')
          if (unit.context.domain !== 'host' || (unit.context.platform && unit.context.platform !== process.platform)) {
            gap('source-domain')
            continue
          }
          const api = hostPaths(unit.context.platform ?? process.platform)
          if (!api.isAbsolute(source.path) && !api.isAbsolute(unit.context.cwd ?? '')) {
            gap('source-directory')
            continue
          }
          const filename = api.resolve(unit.context.cwd ?? api.parse(source.path).root, source.path)
          const key = JSON.stringify([filename, unit.language, source.script, unit.scriptArgs])
          if (unit.ancestors.includes(key)) {
            gap('source-cycle')
            continue
          }
          if (++files > limits.maxFiles) throw new LocalBudgetError('file-budget')
          let read
          try {
            read = await readSource(filename, Math.min(limits.maxSourceBytes, limits.maxTotalBytes - bytes), signal)
          } catch (error) {
            signal.throwIfAborted()
            if (typeof error?.code !== 'string') throw error
            gap('source-unreadable')
            continue
          }
          if (read.gap) {
            gap(read.gap)
            continue
          }
          reserve(read.size)
          scannedTexts.push(read.text)
          unit.ancestors = [...unit.ancestors, key]
          unit.origin = { ...unit.origin, file: filename }
          if (source.kind === 'package-script') {
            let contents
            try { contents = JSON.parse(read.text) } catch { gap('package-manifest'); continue }
            const text = Object.hasOwn(contents?.scripts ?? {}, source.script) ? contents.scripts[source.script] : undefined
            if (typeof text !== 'string') { gap('package-script'); continue }
            // Lifecycle scripts and custom script shells can run outside the declared body.
            gap('package-script-environment')
            if (unit.context.platform === 'win32') { gap('package-script-shell'); continue }
            child({ source: { kind: 'inline', text }, language: 'posix', context: { ...unit.context, cwd: api.dirname(filename) } })
            continue
          }
          await provider.analyze({ ...unit, source: { kind: 'inline', text: read.text } }, env)
        } catch (error) {
          if (!(error instanceof LocalBudgetError)) throw error
          gap(error.message)
        }
      }
      // Credential text scan (规则模型「凭据防泄露」R-04): only when this call carries an
      // unresolved dynamic operand on a content action, the actually analyzed source
      // texts are scanned; a hit only raises a confirmation. No plaintext enters the
      // result — the flag is a boolean.
      if (hasUnresolvedProtectedOperand(result.operations) &&
        scannedTexts.some((text) => textMentionsCredential(text))) {
        result.credentialTextMention = true
      }
      checkDeadline()
      return result
    } catch (error) {
      if (callerSignal?.aborted || lifetime.signal.aborted) throw error
      result.status = 'fault'
      gap(timeout.aborted || expired ? 'analysis-deadline' : 'analysis-failure')
      return result
    } finally {
      // A nested script's operations belong at its invocation position even though
      // they are analyzed after the parent syntax tree.
      result.operations.sort((left, right) => compareOrder(order.get(left), order.get(right)))
      release?.()
    }
  }

  return {
    analyze,
    async dispose() {
      lifetime.abort()
      await Promise.all([shellAnalyzer.dispose?.(), programAnalyzer.dispose?.()])
    },
  }
}
