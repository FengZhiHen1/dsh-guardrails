import test from 'node:test'
import assert from 'node:assert/strict'
import { matchWindowsDevice } from '../src/adapter/windows-devices.js'

const physical = { Number: 0, BusType: 17, UniqueId: 'synthetic-disk-id', IsOffline: false }
const inventory = { disks: [physical], partitions: [{ DiskNumber: 0, PartitionNumber: 1, DriveLetter: 'C' }] }

test('Windows physical disk matching requires exact identity and rejects virtual/unknown/offline', () => {
  assert.equal(matchWindowsDevice({ diskNumber: 0 }, inventory).identity, 'host-physical-device')
  assert.equal(matchWindowsDevice({ driveLetter: 'c:' }, inventory).diskNumber, 0)
  assert.equal(matchWindowsDevice({ diskNumber: 1 }, inventory), null)
  for (const patch of [{ BusType: 15 }, { BusType: 14 }, { BusType: 0 }, { UniqueId: '' }, { IsOffline: true }]) {
    assert.equal(matchWindowsDevice({ diskNumber: 0 }, { ...inventory, disks: [{ ...physical, ...patch }] }), null)
  }
  assert.equal(matchWindowsDevice({ driveLetter: 'C' }, { ...inventory, partitions: [...inventory.partitions, ...inventory.partitions] }), null)
})
