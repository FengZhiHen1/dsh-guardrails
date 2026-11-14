// mount-boundary — Linux mount-boundary crossing check for recursive deletions.
//
// Purpose: the plan's st_dev walk guard misses SAME-DEVICE bind mounts (a bind mount
// presents the same device number as its source but is still a distinct filesystem
// view). This adapter reads /proc/self/mountinfo ONCE per plan (bounded snapshot) and
// answers whether deleting `absoluteTarget` could cross or remove a mountpoint:
//   - a mountpoint AT or INSIDE the deletion target (includes same-device bind mounts)
//   - a mountpoint crossed between the trusted `boundary` and an in-boundary target
//
// Boundary rules (contract §9): do NOT reject an explicit ordinary host path merely
// because an ancestor volume is a separate mount (e.g. /home being its own volume does
// not forbid deleting a specific file inside the workspace). Only an actual mountpoint
// at/inside the target, or a mount boundary crossed on the way from `boundary` to the
// target, is a crossing.
//
// Failure stance: on Linux, an unavailable / unreadable / malformed mount inventory is
// UNKNOWN and therefore unsafe (deny). Windows keeps existing metadata/junction behavior
// and returns safe without touching any Linux-only file.

import fs from 'node:fs/promises'

// Bound the read: /proc/self/mountinfo is small; refuse to trust an oversized body.
const MAX_MOUNTINFO_BYTES = 1 << 20 // 1 MiB
const MOUNTINFO_PATH = '/proc/self/mountinfo'
// mountinfo separator between the fixed fields and the optional fields.
const SEPARATOR = ' - '

/**
 * Decode the octal escapes the kernel uses inside mountinfo path fields:
 * \040 space, \011 tab, \012 newline, \134 backslash, and any \NNN generally.
 * Returns null on a malformed escape so the caller can treat the record as unknown.
 * @param {string} field
 * @returns {string | null}
 */
function decodeOctalEscapes(field) {
  if (typeof field !== 'string') return null
  let out = ''
  for (let index = 0; index < field.length; index += 1) {
    const char = field[index]
    if (char !== '\\') {
      out += char
      continue
    }
    const oct = field.slice(index + 1, index + 4)
    if (!/^[0-7]{3}$/.test(oct)) return null
    const code = Number.parseInt(oct, 8)
    if (code === 0 || code > 0xff) return null
    out += String.fromCharCode(code)
    index += 3
  }
  return out
}

/**
 * Parse /proc/self/mountinfo text into a list of mount records.
 * Each line is: id parent major:minor root mountpoint options... - fstype source superopts
 * Fields before the ` - ` separator are positional; `root` is field index 3 (also
 * octal-escaped) and the mountpoint is field index 4.
 *
 * Strictness (a silently dropped or accepted-bad line could hide a crossing):
 *   - empty/whitespace-only inventory => null (unknown; a real Linux mount table always
 *     has at least a kernel root `/` mount).
 *   - any malformed line, invalid numeric id/parent, non-absolute or NUL-bearing mountpoint
 *     => the whole inventory is null (unknown).
 *   - `id`/`parentId` must be non-negative safe integers; `major:minor` must be digits.
 *   - both `root` and `mountpoint` are octal-decoded.
 * @param {string} text
 * @returns {Array<{id:number,parentId:number,majorMinor:string,root:string,mountPoint:string,fsType:string}> | null}
 */
export function parseMountInfo(text) {
  if (typeof text !== 'string' || text.trim() === '') return null
  const mounts = []
  let sawRoot = false
  const lines = text.split('\n')
  for (const rawLine of lines) {
    const line = rawLine.trimEnd()
    if (line === '') continue
    const sepIndex = line.indexOf(SEPARATOR)
    if (sepIndex < 0) return null
    const left = line.slice(0, sepIndex).split(' ')
    const right = line.slice(sepIndex + SEPARATOR.length).split(' ')
    // left: id parent major:minor root mountpoint [options...] (>= 6 tokens)
    if (left.length < 6) return null
    // right: fstype source superopts (>= 3 tokens)
    if (right.length < 3) return null
    // Decimal, non-negative, safe integer ids. Number() accepts '', '0x1', '1e3', ' 1'
    // etc.; require a pure decimal string and a safe integer range.
    if (!/^\d+$/.test(left[0]) || !/^\d+$/.test(left[1])) return null
    const id = Number(left[0])
    const parentId = Number(left[1])
    if (!Number.isSafeInteger(id) || !Number.isSafeInteger(parentId)) return null
    const majorMinor = left[2]
    if (!/^\d+:\d+$/.test(majorMinor)) return null
    const root = decodeOctalEscapes(left[3])
    if (root === null || !root.startsWith('/')) return null
    const mountPoint = decodeOctalEscapes(left[4])
    if (mountPoint === null) return null
    // A mountpoint is an absolute path; reject relative/empty and any NUL the decoder let
    // through (defensive — decode already rejects \000).
    if (mountPoint === '' || mountPoint[0] !== '/' || mountPoint.includes('\u0000')) return null
    if (mountPoint === '/') sawRoot = true
    mounts.push({ id, parentId, majorMinor, root, mountPoint, fsType: right[0] })
  }
  // The kernel always presents at least the root mount; an inventory without any `/`
  // mount is incomplete/unknown rather than a trustworthy "no mounts".
  if (!Array.isArray(mounts) || mounts.length === 0 || !sawRoot) return null
  return mounts
}

/**
 * Pure crossing helper (exported for synthetic Windows-host tests; no platform IO).
 *
 * @param {Object} input
 * @param {string} input.target   absolute deletion target
 * @param {string} [input.boundary] trusted absolute workspace boundary (optional)
 * @param {Array<{mountPoint:string}>} input.mounts  parsed mount records
 * @param {{sep?:string, normalize?:(p:string)=>string}} [input.pathStyle]
 * @returns {{safe:boolean, reason?:string}}
 */
export function crossingDecision({ target, boundary, mounts, pathStyle }) {
  const sep = pathStyle?.sep ?? '/'
  const normalize = pathStyle?.normalize ?? ((value) => value)
  if (typeof target !== 'string' || target === '') return { safe: false, reason: 'mount-boundary: empty target' }
  if (!Array.isArray(mounts)) return { safe: false, reason: 'mount-boundary: mount inventory unavailable' }

  const absTarget = normalize(target)
  // Join/normalize a mountpoint with a path separator using the supplied style.
  const join = (base, child) => normalize(base === sep ? `${sep}${child}` : `${base}${sep}${child}`)
  const isInside = (parent, child) => {
    if (child === parent) return true
    const prefix = parent === sep ? sep : `${parent}${sep}`
    return child.startsWith(prefix)
  }

  for (const mount of mounts) {
    if (!mount || typeof mount.mountPoint !== 'string') return { safe: false, reason: 'mount-boundary: malformed mount record' }
    const mountPoint = normalize(mount.mountPoint)
    // A mountpoint at, or inside, the deletion target would be removed by a recursive
    // delete — this includes same-device bind mounts (the st_dev walk would miss them).
    if (isInside(absTarget, mountPoint)) {
      return {
        safe: false,
        reason: `mount-boundary: a mountpoint (${mount.mountPoint}, ${mount.fsType ?? 'unknown'}) is at or inside the deletion target; a recursive delete would remove or cross it. Delete each mount separately with explicit literal paths.`,
      }
    }
  }

  // Crossing between the trusted boundary and an in-boundary target: walk each ancestor
  // segment of the target below the boundary; if any is itself a mountpoint, the target
  // is reached only by crossing that mount. A target OUTSIDE the boundary is not the
  // plan's workspace concern here (it receives no exemption upstream) — do not invent a
  // crossing for it, and never reject merely because an ancestor volume exists.
  if (typeof boundary === 'string' && boundary !== '') {
    const absBoundary = normalize(boundary)
    if (!isInside(absBoundary, absTarget)) {
      // Explicitly addressed path outside the boundary: not a workspace crossing.
      return { safe: true }
    }
    const mountPoints = new Set(mounts.map((m) => normalize(m.mountPoint)))
    // Ancestors strictly between boundary (exclusive) and target (inclusive).
    const relative = absTarget.slice(absBoundary === sep ? sep.length : absBoundary.length + sep.length)
    const segments = relative.split(sep).filter((part) => part !== '' && part !== '.')
    let current = absBoundary
    for (const segment of segments) {
      current = join(current, segment)
      if (current === absTarget) break // the target's own mountpoint handled above
      if (mountPoints.has(current)) {
        return {
          safe: false,
          reason: `mount-boundary: the path crosses a mount boundary at ${current} between the workspace boundary and the deletion target; the recursive set cannot be proven. Address each mount with explicit literal paths.`,
        }
      }
    }
  }

  return { safe: true }
}

/**
 * Pre-IO gate for the mount snapshot: checks the shared budget, the absolute deadline and
 * an aborted signal BEFORE any filesystem read. Exported (pure, no IO) so the failure
 * stance is testable on any host. Returns {ok:true} to proceed, or {ok:false, reason}.
 * @param {{consume?:() => boolean, deadlineAt?:number, signal?:AbortSignal}} [options]
 * @returns {{ok:true} | {ok:false, reason:string}}
 */
export function evaluateSnapshotGate({ consume, deadlineAt, signal } = {}) {
  if (typeof consume === 'function') {
    // A budget function that throws is a PROGRAMMING error, not an exhausted budget: it
    // must surface (unknown semantics) rather than be silently converted to a deny, so a
    // broken caller is visible instead of masked. A legitimate "no budget" is `false`.
    const ok = consume()
    if (ok !== true) return { ok: false, reason: 'mount-boundary: shared observation budget exhausted; mount inventory unavailable' }
  }
  if (Number.isFinite(deadlineAt) && Date.now() > deadlineAt) {
    return { ok: false, reason: 'mount-boundary: deadline exceeded before mount inventory read' }
  }
  if (signal?.aborted) return { ok: false, reason: 'mount-boundary: cancelled before mount inventory read' }
  return { ok: true }
}

/**
 * Bounded read of /proc/self/mountinfo. Returns the parsed mounts, or null when the body
 * is unavailable, oversized, or malformed (which the caller treats as unknown/deny).
 * @param {AbortSignal} [signal]
 * @returns {Promise<Array | null>}
 */
/**
 * Read a stream to EOF through an injected reader, with per-iteration bounds. A single
 * read() is not guaranteed to reach EOF: a short read can end exactly on a line boundary,
 * silently omitting later data. So loop until read() reports 0 bytes (EOF) or the
 * accumulated body exceeds maxBytes. Before EACH read, re-check the shared budget
 * (consume), the absolute deadline and the signal. Returns the accumulated UTF-8 string,
 * or null on EOF-oversize / cancellation / exhausted budget / deadline.
 *
 * Exported (pure over an injected reader) so the read-integrity and failure boundaries are
 * testable on any host without a real procfs handle.
 * @param {Object} options
 * @param {(buffer:Buffer, length:number, position:number) => Promise<{bytesRead:number}>} options.read
 * @param {() => boolean} [options.consume]
 * @param {number} [options.deadlineAt]
 * @param {AbortSignal} [options.signal]
 * @param {number} [options.maxBytes]
 * @returns {Promise<string | null>}
 */
export async function readChunksToEof({ read, consume, deadlineAt, signal, maxBytes = MAX_MOUNTINFO_BYTES } = {}) {
  if (signal?.aborted) return null
  const chunks = []
  let total = 0
  let position = 0
  const chunk = Buffer.alloc(64 * 1024)
  for (;;) {
    // NOTE: a throwing consume is a programming error and is NOT caught here — it surfaces.
    if (typeof consume === 'function' && consume() !== true) return null
    if (Number.isFinite(deadlineAt) && Date.now() > deadlineAt) return null
    if (signal?.aborted) return null
    const { bytesRead } = await read(chunk, chunk.length, position)
    if (bytesRead === 0) break // EOF
    total += bytesRead
    if (total > maxBytes) return null // oversized: refuse to trust
    chunks.push(Buffer.from(chunk.subarray(0, bytesRead)))
    position += bytesRead
  }
  if (signal?.aborted) return null
  return Buffer.concat(chunks).toString('utf8')
}

/**
 * Bounded read of /proc/self/mountinfo to EOF, parsed. Returns the mounts, or null when
 * unavailable, oversized, cancelled, or malformed (caller treats null as deny).
 * @param {{consume?:() => boolean, deadlineAt?:number, signal?:AbortSignal}} [options]
 * @returns {Promise<Array | null>}
 */
async function readMountInfo({ consume, deadlineAt, signal } = {}) {
  if (signal?.aborted) return null
  let handle
  try {
    handle = await fs.open(MOUNTINFO_PATH, 'r')
  } catch {
    return null // no procfs / permission: unknown
  }
  try {
    const body = await readChunksToEof({
      read: (buffer, length, position) => handle.read(buffer, 0, length, position),
      consume, deadlineAt, signal, maxBytes: MAX_MOUNTINFO_BYTES,
    })
    if (body === null) return null
    return parseMountInfo(body)
  } catch {
    return null
  } finally {
    if (handle) {
      try {
        await handle.close()
      } catch (error) {
        // Tolerate only an already-closed handle; any other close error is real.
        if (error?.code !== 'EBADF') throw error
      }
    }
  }
}

/**
 * Create a mount-boundary checker with a bounded ONCE-per-plan snapshot on Linux.
 * @param {Object} [options]
 * @param {AbortSignal} [options.signal]
 * @param {number} [options.deadlineAt] absolute Date.now() deadline
 * @param {() => boolean} [options.consume] shared inventory budget; called before IO
 * @returns {{ check: (absoluteTarget: string, boundary?: string) => Promise<{safe:boolean, reason?:string}> }}
 */
export function createMountBoundary({ signal, deadlineAt, consume } = {}) {
  // Windows (and any non-Linux host): keep existing metadata/junction behavior; never
  // read Linux-only files. Nothing to prove here.
  if (process.platform !== 'linux') {
    return {
      async check() {
        return { safe: true }
      },
    }
  }

  let snapshotPromise = null

  async function snapshot() {
    if (snapshotPromise) return snapshotPromise
    snapshotPromise = (async () => {
      // Honor the shared budget / deadline / cancellation BEFORE any IO; an exhausted
      // budget or expired deadline cannot be proven safe.
      const gate = evaluateSnapshotGate({ consume, deadlineAt, signal })
      if (!gate.ok) return gate
      const mounts = await readMountInfo({ consume, deadlineAt, signal })
      if (signal?.aborted) return { ok: false, reason: 'mount-boundary: cancelled during mount inventory read' }
      if (!Array.isArray(mounts)) return { ok: false, reason: 'mount-boundary: mount inventory unavailable or malformed' }
      return { ok: true, mounts }
    })()
    return snapshotPromise
  }

  return {
    async check(absoluteTarget, boundary) {
      // Re-check the CURRENT deadline and cancellation on EVERY check (even when the mount
      // snapshot is already cached): a stale snapshot must never yield `safe` after the
      // plan deadline passed or the invocation was aborted. Budget is consumed only on the
      // first (real read) snapshot; ongoing checks must not re-charge it.
      if (signal?.aborted) return { safe: false, reason: 'mount-boundary: cancelled before mount-boundary check' }
      if (Number.isFinite(deadlineAt) && Date.now() > deadlineAt) {
        return { safe: false, reason: 'mount-boundary: deadline exceeded before mount-boundary check' }
      }
      const snap = await snapshot()
      if (!snap.ok) return { safe: false, reason: snap.reason }
      // Re-check after awaiting the (possibly cached) snapshot too.
      if (signal?.aborted) return { safe: false, reason: 'mount-boundary: cancelled during mount-boundary check' }
      if (Number.isFinite(deadlineAt) && Date.now() > deadlineAt) {
        return { safe: false, reason: 'mount-boundary: deadline exceeded during mount-boundary check' }
      }
      return crossingDecision({ target: absoluteTarget, boundary, mounts: snap.mounts })
    },
  }
}
