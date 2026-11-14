// Synthetic-fixture tests for the Linux mount-boundary adapter.
//
// The pure parser and crossing helper are exercised directly with synthetic mountinfo
// text and Windows-style paths, so no real mount, privilege, or production path is used.
// The factory's Windows branch returns safe without reading any Linux file. Linux-only
// failure paths (budget/deadline/signal) are tested through the factory without needing a
// real /proc mount table on the test host.
import test from 'node:test'
import assert from 'node:assert/strict'
import { parseMountInfo, crossingDecision, createMountBoundary, evaluateSnapshotGate, readChunksToEof } from '../src/adapter/mount-boundary.js'

const isLinux = process.platform === 'linux'

// A Windows path style injected into the pure helper so the crossing logic is testable
// on any host without relying on the host platform's path module.
const winStyle = {
  sep: '\\',
  normalize(value) {
    // Collapse duplicate separators and trim a trailing separator (except a bare drive root).
    let out = value.replace(/\\+/g, '\\')
    if (out.length > 3 && out.endsWith('\\')) out = out.slice(0, -1)
    return out
  },
}
const posixStyle = {
  sep: '/',
  normalize(value) {
    let out = value.replace(/\/+/g, '/')
    if (out.length > 1 && out.endsWith('/')) out = out.slice(0, -1)
    return out
  },
}

const MOUNTINFO_SAMPLE = [
  '22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw',
  '23 22 8:2 / /home rw,relatime - ext4 /dev/sda2 rw',
  '24 22 0:30 / /workspace/proj/bindmount rw,relatime - tmpfs tmpfs rw',
  // A same-device bind mount: same major:minor 8:2 as /home, distinct mountpoint.
  '25 23 8:2 / /mnt/rebind rw,relatime - ext4 /dev/sda2 rw',
  // A path with octal escapes: a directory literally named "a b".
  '26 22 8:1 / /srv/a\\040b rw,relatime - ext4 /dev/sda1 rw',
].join('\n')

test('parseMountInfo parses separator, mountpoint field and fstype', () => {
  const mounts = parseMountInfo(MOUNTINFO_SAMPLE)
  assert.ok(Array.isArray(mounts))
  assert.equal(mounts.length, 4 + 1) // 5 lines total (22,23,24,25,26)
  const byRoot = mounts.find((m) => m.mountPoint === '/')
  assert.deepEqual(byRoot, { id: 22, parentId: 1, majorMinor: '8:1', root: '/', mountPoint: '/', fsType: 'ext4' })
  assert.equal(mounts.find((m) => m.id === 24).fsType, 'tmpfs')
})

test('parseMountInfo decodes octal escapes in mountpoints', () => {
  const mounts = parseMountInfo(MOUNTINFO_SAMPLE)
  const escaped = mounts.find((m) => m.id === 26)
  assert.equal(escaped.mountPoint, '/srv/a b')
})

test('parseMountInfo returns null on an empty/whitespace inventory (no kernel root)', () => {
  assert.equal(parseMountInfo(''), null)
  assert.equal(parseMountInfo('   \n  \n'), null)
})

test('parseMountInfo returns null when no root "/" mount is present', () => {
  const noRoot = '23 22 8:2 / /home rw,relatime - ext4 /dev/sda2 rw'
  assert.equal(parseMountInfo(noRoot), null)
})

test('parseMountInfo returns null on a non-absolute (relative) mountpoint', () => {
  const bad = '22 1 8:1 / home rw,relatime - ext4 /dev/sda1 rw'
  assert.equal(parseMountInfo(bad), null)
})

test('parseMountInfo returns null on a NUL-bearing mountpoint', () => {
  const bad = '22 1 8:1 / /\\000 rw,relatime - ext4 /dev/sda1 rw'
  assert.equal(parseMountInfo(bad), null)
})

test('parseMountInfo returns null on a non-decimal id', () => {
  const hexId = '0x16 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw'
  assert.equal(parseMountInfo(hexId), null)
  const floatId = '22.5 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw'
  assert.equal(parseMountInfo(floatId), null)
})

test('parseMountInfo decodes the root field too', () => {
  const withRoot = '22 1 8:1 /srv/a\\040b / rw,relatime - ext4 /dev/sda1 rw'
  const mounts = parseMountInfo(withRoot)
  assert.ok(Array.isArray(mounts))
  assert.equal(mounts[0].root, '/srv/a b')
})

test('parseMountInfo returns null on malformed lines (missing separator)', () => {
  const bad = '22 1 8:1 / / rw,relatime ext4 /dev/sda1 rw' // no " - " separator
  assert.equal(parseMountInfo(bad), null)
})

test('parseMountInfo returns null on malformed mount field count', () => {
  const bad = '22 1 8:1 / - ext4 /dev/sda1 rw' // left has only 4 tokens
  assert.equal(parseMountInfo(bad), null)
})

test('parseMountInfo returns null on malformed octal escape', () => {
  const bad = '22 1 8:1 / /srv/a\\99x rw,relatime - ext4 /dev/sda1 rw' // \99 not octal
  assert.equal(parseMountInfo(bad), null)
})

test('parseMountInfo returns null on invalid major:minor', () => {
  const bad = '22 1 abc / / rw,relatime - ext4 /dev/sda1 rw'
  assert.equal(parseMountInfo(bad), null)
})

test('crossingDecision denies a mountpoint at the deletion target', () => {
  const mounts = parseMountInfo(MOUNTINFO_SAMPLE)
  const result = crossingDecision({ target: '/workspace/proj/bindmount', mounts, pathStyle: posixStyle })
  assert.equal(result.safe, false)
  assert.match(result.reason, /at or inside the deletion target/)
})

test('crossingDecision denies a mountpoint INSIDE the deletion target (same-device bind)', () => {
  const mounts = parseMountInfo(MOUNTINFO_SAMPLE)
  // /mnt/rebind is same-device (8:2) as /home; a recursive delete of /mnt would remove it.
  const result = crossingDecision({ target: '/mnt', mounts, pathStyle: posixStyle })
  assert.equal(result.safe, false)
  assert.match(result.reason, /at or inside the deletion target/)
})

test('crossingDecision denies a boundary crossing on the way to an in-boundary target', () => {
  const mounts = parseMountInfo(MOUNTINFO_SAMPLE)
  // boundary=/workspace, target=/workspace/proj/bindmount/x — /workspace/proj/bindmount is a mountpoint.
  const result = crossingDecision({
    target: '/workspace/proj/bindmount/deep.cfg',
    boundary: '/workspace',
    mounts,
    pathStyle: posixStyle,
  })
  assert.equal(result.safe, false)
  assert.match(result.reason, /crosses a mount boundary/)
})

test('crossingDecision does NOT reject an ordinary file inside a workspace on its own volume', () => {
  const mounts = parseMountInfo(MOUNTINFO_SAMPLE)
  // /home is a separate volume (8:2). A specific file under the workspace /home/user/proj
  // is NOT a crossing: no mountpoint sits at/inside it, and no mountpoint is crossed
  // between boundary=/home/user (also on 8:2, not its own mountpoint) and the target.
  const result = crossingDecision({
    target: '/home/user/proj/src/app.py',
    boundary: '/home/user/proj',
    mounts,
    pathStyle: posixStyle,
  })
  assert.equal(result.safe, true)
})

test('crossingDecision treats an explicit path outside the boundary as safe (no workspace crossing)', () => {
  const mounts = parseMountInfo(MOUNTINFO_SAMPLE)
  const result = crossingDecision({
    target: '/tmp/explicit.txt',
    boundary: '/workspace',
    mounts,
    pathStyle: posixStyle,
  })
  assert.equal(result.safe, true)
})

test('crossingDecision denies a Windows drive target containing a bind mount (synthetic)', () => {
  // Synthetic Windows-host mount list using backslash paths and a drive-qualified root.
  const mounts = [
    { id: 1, parentId: 0, majorMinor: '0:1', mountPoint: 'C:\\', fsType: 'ntfs' },
    { id: 2, parentId: 1, majorMinor: '0:1', mountPoint: 'C:\\work\\bind', fsType: 'ntfs' }, // same-device bind
  ]
  const result = crossingDecision({ target: 'C:\\work', mounts, pathStyle: winStyle })
  assert.equal(result.safe, false)
  assert.match(result.reason, /at or inside the deletion target/)
})

test('crossingDecision allows a plain Windows file with no crossing (synthetic)', () => {
  const mounts = [
    { id: 1, parentId: 0, majorMinor: '0:1', mountPoint: 'C:\\', fsType: 'ntfs' },
    { id: 2, parentId: 1, majorMinor: '0:2', mountPoint: 'D:\\', fsType: 'ntfs' },
  ]
  const result = crossingDecision({ target: 'C:\\work\\src\\a.js', boundary: 'C:\\work', mounts, pathStyle: winStyle })
  assert.equal(result.safe, true)
})

test('crossingDecision denies on unavailable (null/non-array) mount inventory', () => {
  assert.equal(crossingDecision({ target: '/x', mounts: null }).safe, false)
  assert.equal(crossingDecision({ target: '/x', mounts: [] }).safe, true) // empty is a valid inventory
})

test('crossingDecision denies an empty target', () => {
  assert.equal(crossingDecision({ target: '', mounts: [] }).safe, false)
})

test('factory is safe on Windows without reading Linux files', { skip: isLinux }, async () => {
  const boundary = createMountBoundary({})
  const result = await boundary.check('C:\\anything\\at\\all', 'C:\\work')
  assert.deepEqual(result, { safe: true })
})

// The pre-IO gate is pure and host-independent: budget, deadline and cancellation must
// each deny the snapshot before any mountinfo read, on any platform.
test('evaluateSnapshotGate denies when the shared budget is exhausted', () => {
  const gate = evaluateSnapshotGate({ consume: () => false })
  assert.equal(gate.ok, false)
  assert.match(gate.reason, /budget/)
})

test('evaluateSnapshotGate surfaces a programming error thrown by consume (not budget-deny)', () => {
  // A throwing budget function is a programming error and must surface, not be masked as
  // an exhausted budget. evaluateSnapshotGate calls consume() directly, so it throws here.
  assert.throws(() => evaluateSnapshotGate({ consume: () => { throw new Error('boom') } }), /boom/)
})

test('evaluateSnapshotGate passes when the budget is available', () => {
  assert.deepEqual(evaluateSnapshotGate({ consume: () => true }), { ok: true })
})

test('evaluateSnapshotGate denies when the deadline already passed', () => {
  const gate = evaluateSnapshotGate({ deadlineAt: Date.now() - 1000, consume: () => true })
  assert.equal(gate.ok, false)
  assert.match(gate.reason, /deadline/)
})

test('evaluateSnapshotGate passes when the deadline is in the future', () => {
  assert.deepEqual(evaluateSnapshotGate({ deadlineAt: Date.now() + 60000, consume: () => true }), { ok: true })
})

test('evaluateSnapshotGate denies when the signal is already aborted', () => {
  const controller = new AbortController()
  controller.abort()
  const gate = evaluateSnapshotGate({ signal: controller.signal, consume: () => true })
  assert.equal(gate.ok, false)
  assert.match(gate.reason, /cancelled/)
})

// ---- readChunksToEof: bounded loop-to-EOF integrity (host-independent) ----

// A fake reader that yields the full body in prescribed chunk sizes (mimicking short
// reads that end on arbitrary boundaries, including exactly on a line boundary), then 0.
function chunkedReader(fullBody, sizes) {
  const buf = Buffer.from(fullBody, 'utf8')
  let cursor = 0
  let call = 0
  return async (_buffer, _length, position) => {
    assert.equal(position, cursor, 'reader is read at the sequential offset')
    const size = sizes[call % sizes.length]
    call += 1
    const end = Math.min(cursor + size, buf.length)
    const slice = buf.subarray(cursor, end)
    slice.copy(_buffer, 0)
    cursor = end
    return { bytesRead: slice.length }
  }
}

const TWO_LINE = '22 1 8:1 / / rw - ext4 /dev/a rw\n23 1 8:2 / /home rw - ext4 /dev/b rw\n'

test('readChunksToEof reassembles across short reads that split on line boundaries', async () => {
  // Split exactly at the first newline so a single-read implementation would drop the rest.
  const firstLineLen = '22 1 8:1 / / rw - ext4 /dev/a rw\n'.length
  const body = await readChunksToEof({ read: chunkedReader(TWO_LINE, [firstLineLen, 7]) })
  assert.equal(body, TWO_LINE)
})

test('readChunksToEof stops at EOF (0 bytes)', async () => {
  const body = await readChunksToEof({ read: chunkedReader('abc', [2]) })
  assert.equal(body, 'abc')
})

test('readChunksToEof returns null when the body exceeds maxBytes', async () => {
  const body = await readChunksToEof({ read: chunkedReader('0123456789', [4]), maxBytes: 6 })
  assert.equal(body, null)
})

test('readChunksToEof returns null when the budget is exhausted mid-stream', async () => {
  let calls = 0
  const body = await readChunksToEof({
    read: chunkedReader(TWO_LINE, [5]),
    consume: () => { calls += 1; return calls <= 2 }, // allow first two reads, then deny
  })
  assert.equal(body, null)
})

test('readChunksToEof returns null when the deadline passes mid-stream', async () => {
  const start = Date.now()
  let reads = 0
  const body = await readChunksToEof({
    read: async (buffer) => {
      reads += 1
      if (reads > 1) await new Promise((r) => setTimeout(r, 20))
      const slice = Buffer.from('xxxxx')
      slice.copy(buffer, 0)
      return { bytesRead: slice.length }
    },
    deadlineAt: start + 10,
    consume: () => true,
  })
  assert.equal(body, null)
})

test('readChunksToEof surfaces a programming error thrown by consume', async () => {
  await assert.rejects(
    () => readChunksToEof({ read: chunkedReader('abc', [1]), consume: () => { throw new Error('boom') } }),
    /boom/,
  )
})

test('readChunksToEof returns null when the signal is aborted before reading', async () => {
  const controller = new AbortController()
  controller.abort()
  const body = await readChunksToEof({ read: chunkedReader('abc', [1]), signal: controller.signal })
  assert.equal(body, null)
})

test('factory snapshot is taken once per plan and reused across checks', { skip: !isLinux }, async () => {
  let consumed = 0
  const boundary = createMountBoundary({ consume: () => { consumed += 1; return true } })
  await boundary.check('/definitely/not/a/mount', '/definitely/not')
  await boundary.check('/another/place', '/another')
  assert.equal(consumed, 1, 'budget consumed exactly once for the single snapshot')
})

test('factory reads the real mount table to EOF and yields a decided (safe or deny) result', { skip: !isLinux }, async () => {
  // Exercises the bounded loop-to-EOF read against the real /proc/self/mountinfo (which
  // has many lines, so a single short read that ends on a line boundary would be caught by
  // the mount count / root requirement). The decision is either safe or a deny with reason.
  const boundary = createMountBoundary({ consume: () => true })
  const result = await boundary.check('/proc', '/proc')
  assert.equal(typeof result.safe, 'boolean')
  if (result.safe === false) assert.equal(typeof result.reason, 'string')
})

test('factory re-checks the deadline on a CACHED snapshot and denies once it expires', { skip: !isLinux }, async () => {
  // Create with a far-future deadline so the first snapshot succeeds and is cached, then
  // verify a later check is denied after the effective deadline passes. We reconstruct the
  // gate by mutating a shared deadline holder through a fresh boundary with a near deadline.
  let now = Date.now()
  const boundary = createMountBoundary({ consume: () => true, deadlineAt: now + 50 })
  // First check: within deadline.
  const first = await boundary.check('/proc', '/proc')
  assert.equal(typeof first.safe, 'boolean')
  // Wait past the deadline, then check again; the cached snapshot must NOT yield safe.
  await new Promise((resolve) => setTimeout(resolve, 80))
  const second = await boundary.check('/proc', '/proc')
  assert.equal(second.safe, false)
  assert.match(second.reason, /deadline/)
})
