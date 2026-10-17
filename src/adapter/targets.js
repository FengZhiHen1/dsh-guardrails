// targets — bounded local metadata observations for the pure policy.
// Boundary: never reads secret content or executes inspected commands.
// Only fixed read-only Git queries run; failures become explicit unknown facts.

import fs from 'node:fs/promises'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { extractOperations } from '../core/policy.js'
import { CRED_BASENAMES, CRED_BASENAME_PREFIXES, CRED_COMBOS } from '../core/rules.js'
import { matchWindowsDevice, observeWindowsDevices } from './windows-devices.js'

const runFile = promisify(execFile)
// Bound interactive analysis to 256 observations and 512 directory entries.
const MAX_OPERATIONS = 256
const MAX_ENTRIES = 512
const MAX_DEPTH = 8
const DEADLINE_MS = 1500

function comparable(value) {
  return process.platform === 'win32' ? value.toLowerCase() : value
}

function within(parent, child) {
  const relative = path.relative(comparable(parent), comparable(child))
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative))
}

async function metadata(target) {
  try {
    const [realPath, stat] = await Promise.all([fs.realpath(target), fs.stat(target)])
    return { state: 'known', path: realPath, stat }
  } catch (error) {
    return { state: 'unknown', code: error.code ?? error.name }
  }
}

function builtin(target, rules) {
  if (!rules.credentialsReadAsk) return false
  const parts = target.split(path.sep).filter(Boolean).map(comparable)
  const basename = parts.at(-1) ?? ''
  if (basename.endsWith('.pub')) return false
  if (CRED_BASENAMES.has(basename)) return true
  if (CRED_BASENAME_PREFIXES.some((prefix) => basename.startsWith(`${prefix}.`))) return true
  return CRED_COMBOS.some((combo) => combo.length <= parts.length && combo.every((part, index) => parts[parts.length - combo.length + index] === part))
}

async function gitCommon(cwd, signal, timeout) {
  try {
    const { stdout } = await runFile('git', ['-C', cwd, 'rev-parse', '--path-format=absolute', '--git-common-dir'], {
      shell: false, windowsHide: true, timeout, maxBuffer: 32768, signal,
      env: { ...process.env, GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0' },
    })
    const result = await metadata(stdout.trim())
    return result.state === 'known' && result.stat.isDirectory() ? result.path : null
  } catch (error) {
    if (signal?.aborted) throw signal.reason ?? error
    // No repository, unavailable Git, or exhausted query budget is unknown.
    return null
  }
}

async function systemTrees() {
  if (process.platform === 'win32') {
    const root = process.env.SystemRoot
    if (!root || !path.isAbsolute(root)) return []
    const system = await metadata(root)
    const kernel = await metadata(path.join(root, 'System32', 'ntoskrnl.exe'))
    if (system.state !== 'known' || kernel.state !== 'known' || !kernel.stat.isFile()) return []
    return [path.parse(system.path).root, system.path, path.join(system.path, 'System32')]
  }
  if (process.platform !== 'linux') return []
  // Container/chroot identity is not host identity. Ambiguous roots stay unknown.
  try {
    const handle = await fs.open('/proc/1/mountinfo', 'r')
    let mounts
    try {
      const buffer = Buffer.alloc(262145)
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0)
      if (bytesRead > 262144) return []
      mounts = buffer.toString('utf8', 0, bytesRead)
    } finally {
      await handle.close()
    }
    if (/ - overlay |\/docker\/|\/containers\/|\/kubepods\//.test(mounts)) return []
    const [initRoot, ownRoot] = await Promise.all([metadata('/proc/1/root'), metadata('/')])
    if (initRoot.state !== 'known' || ownRoot.state !== 'known' || initRoot.stat.ino !== ownRoot.stat.ino || initRoot.stat.dev !== ownRoot.stat.dev) return []
    return ['/', '/usr', '/etc', '/boot', '/bin', '/sbin', '/lib', '/lib64']
  } catch (error) {
    // Missing procfs or permission restrictions cannot prove host identity.
    if (typeof error.code !== 'string') throw error
    return []
  }
}

async function physicalDevice(info) {
  if (process.platform !== 'linux' || !info.stat.isBlockDevice()) return false
  if ((await systemTrees()).length === 0) return false
  const device = BigInt(info.stat.rdev)
  const major = Number(((device >> 8n) & 0xfffn) | ((device >> 32n) & 0xfffff000n))
  const minor = Number((device & 0xffn) | ((device >> 12n) & 0xffffff00n))
  const sys = await metadata(`/sys/dev/block/${major}:${minor}`)
  if (sys.state !== 'known' || sys.path.includes('/virtual/')) return false
  const hardware = await metadata(path.join(sys.path, 'device'))
  if (hardware.state === 'known') return true
  // A partition inherits the physical parent disk's hardware identity.
  const partition = await metadata(path.join(sys.path, 'partition'))
  if (partition.state !== 'known') return false
  return (await metadata(path.join(sys.path, '..', 'device'))).state === 'known'
}

/** Observe local identities, returning explicit unknowns.
 * @throws {Error} If input is invalid, the operation budget is exceeded, or cancelled.
 */
export async function observeTargets(options = {}) {
  const controller = new AbortController()
  const signal = AbortSignal.any([controller.signal, options.signal].filter(Boolean))
  let stop
  const interrupted = new Promise((_, reject) => {
    stop = () => reject(signal.reason ?? new Error('guardrails: observation cancelled'))
    if (signal.aborted) stop()
    else signal.addEventListener('abort', stop, { once: true })
  })
  // Native metadata requests cannot be aborted; callers still settle within this budget.
  const timer = setTimeout(() => controller.abort(new Error('guardrails: target observation deadline')), DEADLINE_MS)
  try { return await Promise.race([collectTargets({ ...options, signal }), interrupted]) }
  finally { clearTimeout(timer); signal.removeEventListener('abort', stop) }
}

async function collectTargets({ commands = [], cwd, rules, signal } = {}) {
  if (!rules || !Array.isArray(rules.sensitiveFiles)) throw new TypeError('guardrails: evaluated rules are required')
  const operations = extractOperations(commands)
  if (operations.length > MAX_OPERATIONS) throw new RangeError('guardrails: target observation budget exceeded')
  const started = Date.now()
  const output = []
  const base = typeof cwd === 'string' && path.isAbsolute(cwd) ? cwd : null
  const marks = []
  let marksUnknown = rules.sensitiveFiles.length > 1024 ? 'marked-file-budget' : undefined
  for (const marked of rules.sensitiveFiles.slice(0, 1024)) {
    if (signal?.aborted) throw signal.reason ?? new Error('guardrails: observation cancelled')
    if (Date.now() - started > DEADLINE_MS) { marksUnknown = 'marked-file-deadline'; break }
    const info = await metadata(marked)
    if (info.state === 'known' && info.stat.isFile()) marks.push(info.path)
  }
  const protectedFile = (info) => info.stat.isFile() && (marks.some((marked) => comparable(marked) === comparable(info.path)) || builtin(info.path, rules))
  let trees
  const commons = new Map()
  let windowsInventory
  for (const operation of operations) {
    if (signal?.aborted) throw signal.reason ?? new Error('guardrails: observation cancelled')
    const observed = { ...operation, state: 'unknown' }
    output.push(observed)
    if (Date.now() - started > DEADLINE_MS) { observed.unknown = 'budget'; continue }
    if (operation.selector) {
      windowsInventory ??= await observeWindowsDevices({ signal, timeout: DEADLINE_MS - (Date.now() - started) })
      const device = matchWindowsDevice(operation.selector, windowsInventory)
      if (device) Object.assign(observed, device, { state: 'known' })
      else observed.unknown = 'device-identity'
      continue
    }
    const localBase = operation.cwd && base ? path.resolve(base, operation.cwd) : base
    if (!path.isAbsolute(operation.path) && !localBase) { observed.unknown = 'cwd'; continue }
    // Wildcards, providers, remote shares and unresolved expansions are not literal local targets.
    if (/[*?\u0000]/.test(operation.path) || operation.path.startsWith('\\\\') || operation.path.startsWith('//') || /^[a-z]+:/i.test(operation.path) && !/^[a-z]:[\\/]/i.test(operation.path)) {
      observed.unknown = 'nonliteral-or-remote'; continue
    }
    const absolute = path.isAbsolute(operation.path) ? path.normalize(operation.path) : path.resolve(localBase, operation.path)
    if (['delete', 'move', 'worktree-remove'].includes(operation.action)) {
      try {
        if ((await fs.lstat(absolute)).isSymbolicLink()) {
          observed.unknown = 'link-entry-removal'; continue
        }
      } catch (error) {
        observed.unknown = error.code ?? error.name; continue
      }
    }
    const info = await metadata(absolute)
    if (info.state !== 'known') {
      observed.unknown = info.code
      if (['write', 'edit'].includes(operation.action) && rules.sensitiveFiles.some((marked) => comparable(path.normalize(marked)) === comparable(absolute))) {
        observed.protected = true
      }
      continue
    }
    observed.state = 'known'
    observed.realPath = info.path
    observed.protected = protectedFile(info)
    const treeEffect = operation.recursive || ['move', 'copy', 'worktree-remove'].includes(operation.action)
    if (info.stat.isDirectory() && treeEffect) {
      observed.containsProtected = marks.some((marked) => within(info.path, marked))
      if (!observed.containsProtected && rules.credentialsReadAsk && operation.action === 'worktree-remove') {
        const queue = [{ directory: info.path, depth: 0 }]
        let entries = 0
        while (queue.length && entries < MAX_ENTRIES && Date.now() - started <= DEADLINE_MS) {
          const current = queue.shift()
          let directory
          try { directory = await fs.opendir(current.directory) } catch (error) { observed.scanUnknown = error.code ?? error.name; continue }
          for await (const entry of directory) {
            if (++entries > MAX_ENTRIES || Date.now() - started > DEADLINE_MS) { observed.scanUnknown = 'budget'; break }
            if (entry.isSymbolicLink()) continue
            const entryPath = path.join(current.directory, entry.name)
            if (entry.isFile() && builtin(entryPath, rules)) { observed.containsProtected = true; break }
            if (entry.isDirectory() && entry.name !== '.git' && current.depth < MAX_DEPTH) queue.push({ directory: entryPath, depth: current.depth + 1 })
          }
          if (observed.containsProtected) break
        }
      }
    }
    if (operation.action === 'device-destroy' && await physicalDevice(info)) observed.identity = 'host-physical-device'
    if (operation.action === 'delete' && operation.recursive && info.stat.isDirectory()) {
      trees ??= await systemTrees()
      if (trees.some((tree) => comparable(tree) === comparable(info.path))) observed.identity = 'host-system-tree'
      const gitBase = localBase ?? path.dirname(info.path)
      if (!commons.has(gitBase)) commons.set(gitBase, await gitCommon(gitBase, signal, Math.max(1, DEADLINE_MS - (Date.now() - started))))
      let common = commons.get(gitBase)
      if (!common && Date.now() - started <= DEADLINE_MS) common = await gitCommon(path.dirname(info.path), signal, Math.max(1, DEADLINE_MS - (Date.now() - started)))
      if (common) observed.gitSharedBody = comparable(info.path) === comparable(common) || comparable(info.path) === comparable(path.join(common, 'objects'))
    }
  }
  return { operations: output, ...(marksUnknown ? { unknown: [marksUnknown] } : {}) }
}
