// windows-devices — fixed read-only host disk inventory and identity matching.
// Boundary: no inspected command is executed; virtual and ambiguous disks stay unknown.

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const runFile = promisify(execFile)
const INVENTORY_SCRIPT = `$ErrorActionPreference='Stop'; $disks=@(Get-Disk | Select-Object Number,BusType,PartitionStyle,UniqueId,IsOffline); $partitions=@(Get-Partition | Select-Object DiskNumber,PartitionNumber,DriveLetter); ConvertTo-Json -Compress -Depth 4 -InputObject @{disks=$disks;partitions=$partitions}`
// Storage bus numeric values from MSFT_Disk; virtual/file-backed/unknown excluded.
const PHYSICAL_BUSES = new Set([1, 2, 3, 4, 6, 7, 8, 10, 11, 12, 17, 18, 19])
const PHYSICAL_NAMES = new Set(['scsi', 'atapi', 'ata', '1394', 'fibre channel', 'usb', 'raid', 'sas', 'sata', 'sd', 'mmc', 'nvme', 'scm', 'ufs'])

/** Match an exact disk/partition selector against a validated read-only inventory. */
export function matchWindowsDevice(selector, inventory) {
  if (!selector || !inventory || !Array.isArray(inventory.disks) || !Array.isArray(inventory.partitions)) return null
  if (inventory.disks.length > 256 || inventory.partitions.length > 2048) return null
  let diskNumber = selector.diskNumber
  if (selector.driveLetter !== undefined) {
    const letter = String(selector.driveLetter).replace(/:$/, '').toUpperCase()
    if (!/^[A-Z]$/.test(letter)) return null
    const matches = inventory.partitions.filter((partition) => typeof partition.DriveLetter === 'string' && partition.DriveLetter.toUpperCase() === letter)
    if (matches.length !== 1 || !Number.isSafeInteger(matches[0].DiskNumber)) return null
    diskNumber = matches[0].DiskNumber
  }
  if (!Number.isSafeInteger(diskNumber) || diskNumber < 0) return null
  const matches = inventory.disks.filter((disk) => disk.Number === diskNumber)
  if (matches.length !== 1) return null
  const disk = matches[0]
  const bus = typeof disk.BusType === 'string' ? disk.BusType.toLowerCase() : disk.BusType
  if (!PHYSICAL_BUSES.has(bus) && !PHYSICAL_NAMES.has(bus)) return null
  if (typeof disk.UniqueId !== 'string' || disk.UniqueId.trim().length === 0 || disk.IsOffline !== false) return null
  return { identity: 'host-physical-device', diskNumber }
}

/** Query Windows Storage CIM cmdlets with fixed source and bounded output.
 * @throws {Error} If the caller cancels the observation.
 */
export async function observeWindowsDevices({ signal, timeout = 1500 } = {}) {
  if (process.platform !== 'win32') return { state: 'unknown', reason: 'platform' }
  try {
    const { stdout } = await runFile('pwsh', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', INVENTORY_SCRIPT], {
      shell: false, windowsHide: true, timeout: Math.max(1, Math.min(timeout, 5000)), maxBuffer: 262144, signal,
    })
    const inventory = JSON.parse(stdout.replace(/^\uFEFF/, '').trim())
    if (!Array.isArray(inventory.disks) || !Array.isArray(inventory.partitions)) return { state: 'unknown', reason: 'inventory-schema' }
    return { state: 'known', ...inventory }
  } catch (error) {
    if (signal?.aborted) throw signal.reason ?? error
    return { state: 'unknown', reason: error.code ?? error.name }
  }
}
