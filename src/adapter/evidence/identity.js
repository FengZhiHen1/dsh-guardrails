// identity.js — disaster-identity observation for the evidence adapter.
//
// The rule ids come from docs/technical-details/规则模型.md「规则目录」: only
// catastrophic identities may become an unconditional deny, so every conclusion here is
// fail-closed — an unproven or ambiguous probe yields NO identity, never a guessed one.
//
// Identity and resource boundaries:
// - Read-only probes only: realpath/stat, bounded /proc reads, a bounded read-only
//   `git rev-parse`. The analyzed command text is data; nothing here executes it and no
//   probe mutates state.
// - Every probe is bounded by the shared deadline, the shared scan budget (consume) and
//   the caller's signal. Native metadata calls cannot be aborted individually, so the
//   caller (index.js) wraps the whole collection in a deadline race.
// - Identity is domain-scoped: these host probes answer only for `domain: 'host'`
//   operations on the matching host platform. `domain: 'fs'` targets stay opaque and
//   other domains are never probed with host observation.
// - System-tree identity requires PROOF of real host identity (kernel image on Windows,
//   init-root identity on Linux); inside a container/chroot the same paths are ordinary
//   directories and yield no identity.

import fs from 'node:fs/promises'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { readChunksToEof } from '../mount-boundary.js'
import { matchWindowsDevice, observeWindowsDevices } from '../windows-devices.js'
import { comparable } from './internal.js'

const runFile = promisify(execFile)

export const RULES = Object.freeze({
  device: 'catastrophic.device',
  root: 'catastrophic.root',
  gitMetadata: 'catastrophic.git-metadata',
  gitHistory: 'catastrophic.git-history',
})

const MAX_MOUNTINFO_BYTES = 1 << 20

function withinDeadline(deadlineAt) {
  return !Number.isFinite(deadlineAt) || Date.now() <= deadlineAt
}

/** realpath + stat together; failures become an explicit unknown, never an identity. */
export async function metadataProbe(target, { signal } = {}) {
  try {
    const [realPath, stat] = await Promise.all([fs.realpath(target), fs.stat(target)])
    return { state: 'known', path: realPath, stat }
  } catch (error) {
    if (signal?.aborted) throw signal.reason ?? error
    return { state: 'unknown', code: error.code ?? error.name }
  }
}

/**
 * Observe the HOST system trees (OS root and core structure paths). Returns [] whenever
 * host identity cannot be proven — an empty result is "unproven", not "no system tree".
 * Windows: %SystemRoot% verified through the kernel image. Linux: /proc/1 root identity,
 * refusing container/overlay mounts. Both walks consume the shared budget.
 */
export async function observeSystemTrees({ signal, consume, deadlineAt } = {}) {
  const gate = () => {
    if (signal?.aborted || !withinDeadline(deadlineAt)) return false
    return typeof consume !== 'function' || consume() === true
  }
  if (process.platform === 'win32') {
    const root = process.env.SystemRoot
    if (!root || !path.isAbsolute(root) || !gate()) return []
    const system = await metadataProbe(root, { signal })
    const kernel = await metadataProbe(path.join(root, 'System32', 'ntoskrnl.exe'), { signal })
    // The kernel image proves this root is the real host OS tree, not a mounted copy.
    if (system.state !== 'known' || kernel.state !== 'known' || !kernel.stat.isFile()) return []
    return [path.parse(system.path).root, system.path, path.join(system.path, 'System32')]
  }
  if (process.platform !== 'linux') return []
  // Container/chroot identity is not host identity. Ambiguous roots stay unproven.
  try {
    if (!gate()) return []
    const handle = await fs.open('/proc/self/mountinfo', 'r')
    let body
    try {
      body = await readChunksToEof({
        read: (buffer, length, position) => handle.read(buffer, 0, length, position),
        consume, deadlineAt, signal, maxBytes: MAX_MOUNTINFO_BYTES,
      })
    } finally {
      try { await handle.close() } catch (error) { if (error?.code !== 'EBADF') throw error }
    }
    if (body === null) return []
    if (/ - overlay |\/docker\/|\/containers\/|\/kubepods\//.test(body)) return []
    if (!gate()) return []
    const [initRoot, ownRoot] = await Promise.all([metadataProbe('/proc/1/root', { signal }), metadataProbe('/', { signal })])
    if (initRoot.state !== 'known' || ownRoot.state !== 'known' || initRoot.stat.ino !== ownRoot.stat.ino || initRoot.stat.dev !== ownRoot.stat.dev) return []
    return ['/', '/usr', '/etc', '/boot', '/bin', '/sbin', '/lib', '/lib64']
  } catch (error) {
    if (signal?.aborted) throw signal.reason ?? error
    // Missing procfs or permission restrictions cannot prove host identity.
    if (typeof error?.code !== 'string') throw error
    return []
  }
}

/**
 * Pure matcher: true when a resolved target realpath IS one of the host system-tree
 * paths (whole-tree destruction). Equality only — deleting one file inside the tree is
 * a normal deletion, not a catastrophic identity. Case folds only on Windows, where both
 * sides are realpaths and folding cannot merge distinct directories.
 */
export function matchSystemTree(trees, realPath, windows = process.platform === 'win32') {
  if (!Array.isArray(trees) || typeof realPath !== 'string') return false
  const target = comparable(realPath, windows)
  return trees.some((tree) => comparable(tree, windows) === target)
}

function gitEnvironment() {
  const env = { ...process.env }
  for (const key of Object.keys(env)) if (key.startsWith('GIT_')) delete env[key]
  // A sanitized environment so GIT_* overrides cannot redirect the repository we probe.
  env.GIT_OPTIONAL_LOCKS = '0'
  env.GIT_TERMINAL_PROMPT = '0'
  return env
}

/**
 * Bounded read-only probe for the real Git common dir of `cwd` (the shared repository
 * body across worktrees). Returns the absolute real path, or null when there is no
 * repository, Git is unavailable, the probe timed out, or the answer cannot be verified.
 * `run` injects a controlled probe runner (tests); it receives the argv.
 */
export async function gitCommonDir({ cwd, signal, deadlineAt, run } = {}) {
  if (!withinDeadline(deadlineAt)) return null
  const argv = ['-C', cwd, 'rev-parse', '--path-format=absolute', '--git-common-dir']
  try {
    let stdout
    if (typeof run === 'function') {
      stdout = (await run(argv, { timeout: 5_000 })).stdout
    } else {
      ;({ stdout } = await runFile('git', argv, {
        shell: false, windowsHide: true,
        timeout: Math.max(1, Math.min(Number.isFinite(deadlineAt) ? deadlineAt - Date.now() : 5_000, 5_000)),
        maxBuffer: 32768, signal, env: gitEnvironment(),
      }))
    }
    const result = await metadataProbe(String(stdout).trim(), { signal })
    return result.state === 'known' && result.stat.isDirectory() ? result.path : null
  } catch (error) {
    if (signal?.aborted) throw signal.reason ?? error
    // No repository / unavailable Git / exhausted budget: unknown, never an identity.
    return null
  }
}

/** A Windows device namespace path addresses a physical disk or volume, not an entry. */
const WINDOWS_DEVICE_PATH = /^\\\\\.\\(?:PhysicalDrive(\d+)|([A-Za-z]):)$/u

/** True when a target may name real storage hardware and deserves a device probe. */
export function isDeviceNamespacePath(value, platform) {
  if (platform === 'win32') return /^\\\\\.\\/u.test(String(value))
  if (platform === 'linux') return String(value).startsWith('/dev/')
  return false
}

/**
 * Verified identity for a selector-shaped device fact ({diskNumber} | {driveLetter}):
 * identity counts only when the read-only Storage inventory proves a physical (non-
 * virtual, online) disk; otherwise the result is null and NO identity is recorded.
 */
export async function observeDeviceSelectorIdentity({ selector, windowsInventory, signal, deadlineAt } = {}) {
  if (process.platform !== 'win32' || !selector) return null
  const inventory = windowsInventory
    ?? await observeWindowsDevices({ signal, timeout: withinDeadline(deadlineAt) ? Math.max(1, deadlineAt - Date.now()) : 0 })
  const verdict = matchWindowsDevice(selector, inventory)
  return verdict?.identity === 'host-physical-device' ? 'host-physical-device' : null
}

/**
 * Disaster identity for a Windows device-namespace target. Identity counts only when the
 * read-only Storage inventory proves a physical (non-virtual, online) disk; otherwise the
 * result is null and NO identity is recorded (fail-closed).
 */
export async function observeDeviceIdentity({ target, windowsInventory, signal, deadlineAt } = {}) {
  if (process.platform !== 'win32') return null
  const match = WINDOWS_DEVICE_PATH.exec(String(target))
  if (!match) return null
  const selector = match[1] !== undefined ? { diskNumber: Number(match[1]) } : { driveLetter: match[2] }
  const inventory = windowsInventory
    ?? await observeWindowsDevices({ signal, timeout: withinDeadline(deadlineAt) ? Math.max(1, deadlineAt - Date.now()) : 0 })
  const verdict = matchWindowsDevice(selector, inventory)
  return verdict?.identity === 'host-physical-device' ? 'host-physical-device' : null
}

/**
 * Disaster identity for an exact Linux `/dev/*` target: a real block device backed by
 * hardware (not /virtual/), on a host whose identity the system-tree observation proved.
 * Anything unproven yields null (no identity).
 */
export async function observeLinuxBlockIdentity({ target, systemTrees, signal, consume, deadlineAt } = {}) {
  if (process.platform !== 'linux' || !Array.isArray(systemTrees) || systemTrees.length === 0) return null
  if (signal?.aborted || !withinDeadline(deadlineAt)) return null
  if (typeof consume === 'function' && consume() !== true) return null
  const info = await metadataProbe(target, { signal })
  if (info.state !== 'known' || !info.stat.isBlockDevice()) return null
  const device = BigInt(info.stat.rdev)
  const major = Number(((device >> 8n) & 0xfffn) | ((device >> 32n) & 0xfffff000n))
  const minor = Number((device & 0xffn) | ((device >> 12n) & 0xffffff00n))
  const sys = await metadataProbe(`/sys/dev/block/${major}:${minor}`, { signal })
  if (sys.state !== 'known' || sys.path.includes('/virtual/')) return null
  const hardware = await metadataProbe(path.join(sys.path, 'device'), { signal })
  if (hardware.state === 'known') return 'host-physical-device'
  // A partition inherits the physical parent disk's hardware identity.
  const partition = await metadataProbe(path.join(sys.path, 'partition'), { signal })
  if (partition.state !== 'known') return null
  const parent = await metadataProbe(path.join(sys.path, '..', 'device'), { signal })
  return parent.state === 'known' ? 'host-physical-device' : null
}
