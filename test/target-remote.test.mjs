// Remote/cloud/DB/K8s destructive-command facts (F-26…F-32). The module is
// dispatched from commands.js before its unmodeled-command gap; here it is
// driven directly with the collector used by target-command.test.mjs, since
// the dispatch line itself belongs to the O1 owner. Every positive asserts the
// confirm-grade shape (delete + unknown + non-empty knownScope + details.remote);
// every negative asserts the anti-over-defense quartet: no hit, no operation,
// no candidate (the caller then only adds a gap and allows).

import assert from 'node:assert/strict'
import test from 'node:test'
import { resolveRemoteCommand } from '../src/adapter/analysis/commands-remote.js'

const OPTIONS = {
  context: { domain: 'host', platform: 'linux', cwd: '/fixture' },
  origin: { entry: 'fixture' },
  condition: 'certain',
}

function run(name, args) {
  const operations = []
  const candidates = []
  const gaps = []
  const hit = resolveRemoteCommand(name, args, OPTIONS, {
    // Mirrors index.js env.operation: it materializes the boolean fields.
    operation(action, target, options) {
      operations.push({ action, target, recursive: options.recursive ?? false,
        preview: options.preview === true, ...options })
    },
    candidate(kind, reason) { candidates.push({ kind, reason }) },
    gap(kind) { gaps.push(kind) },
    child() {},
  })
  return { hit, operations, candidates, gaps }
}

function assertConfirm(result, provider, scope) {
  assert.equal(result.hit, true)
  assert.equal(result.candidates.length, 0)
  assert.equal(result.gaps.length, 0)
  const operation = result.operations[0]
  assert.equal(result.operations.length, 1)
  assert.equal(operation.action, 'delete')
  assert.deepEqual(operation.target, { kind: 'unknown', reason: 'remote-target', knownScope: [scope] })
  assert.deepEqual(operation.details, { remote: { provider, scope } })
  assert.equal(operation.preview, false)
}

function assertFree(result) {
  assert.equal(result.hit, false, 'read-only/unknown form must not be modeled')
  assert.equal(result.operations.length, 0)
  assert.equal(result.candidates.length, 0)
  assert.equal(result.gaps.length, 0, 'this module emits nothing; the caller owns the gap')
}

// --- aws (F-26) ------------------------------------------------------------

test('aws destructive subcommands confirm with their command scope', () => {
  assertConfirm(run('aws', ['s3', 'rm', 's3://bucket', '--recursive']), 'aws', 's3://bucket/** (recursive)')
  assertConfirm(run('aws', ['s3', 'rm', 's3://bucket/key.txt']), 'aws', 's3://bucket/key.txt')
  assertConfirm(run('aws', ['s3', 'rb', 's3://bucket', '--force']), 'aws', 's3://bucket (bucket)')
  assertConfirm(run('aws', ['ec2', 'terminate-instances', '--instance-ids', 'i-123', 'i-456']),
    'aws', 'ec2 terminate-instances i-123 i-456')
  assertConfirm(run('aws', ['rds', 'delete-db-instance', '--db-instance-identifier', 'prod-db']),
    'aws', 'rds delete-db-instance prod-db')
  assertConfirm(run('aws', ['dynamodb', 'delete-table', '--table-name', 'users']),
    'aws', 'dynamodb delete-table users')
})

test('aws read-only and preview forms stay unmodeled', () => {
  assertFree(run('aws', ['s3', 'ls', 's3://bucket']))
  assertFree(run('aws', ['s3', 'cp', './a.txt', 's3://bucket/a.txt']))
  assertFree(run('aws', ['s3', 'sync', './dir', 's3://bucket/dir']))
  assertFree(run('aws', ['s3', 'rm', 's3://bucket', '--recursive', '--dryrun']))
  assertFree(run('aws', ['ec2', 'describe-instances']))
  assertFree(run('aws', ['--version']))
})

// --- gcp (F-27) ------------------------------------------------------------

test('gcloud/gsutil destructive subcommands confirm with their command scope', () => {
  assertConfirm(run('gcloud', ['compute', 'instances', 'delete', 'my-inst', '--quiet']), 'gcp', 'my-inst')
  assertConfirm(run('gcloud', ['sql', 'instances', 'delete', 'prod-db']), 'gcp', 'prod-db')
  assertConfirm(run('gcloud', ['container', 'clusters', 'delete', 'prod-gke', '--region=us-east1']), 'gcp', 'prod-gke')
  assertConfirm(run('gsutil', ['rm', '-r', 'gs://bucket']), 'gcp', 'gs://bucket/** (recursive)')
  assertConfirm(run('gsutil', ['rm', 'gs://bucket/object.txt']), 'gcp', 'gs://bucket/object.txt')
})

test('gcloud/gsutil read-only forms stay unmodeled', () => {
  assertFree(run('gcloud', ['compute', 'instances', 'list']))
  assertFree(run('gcloud', ['projects', 'list']))
  assertFree(run('gcloud', ['--version']))
  assertFree(run('gsutil', ['ls', 'gs://bucket']))
  assertFree(run('gsutil', ['cp', 'a.txt', 'gs://bucket/a.txt']))
})

// --- azure (F-28) ----------------------------------------------------------

test('az destructive subcommands confirm with their command scope', () => {
  assertConfirm(run('az', ['vm', 'delete', '-g', 'rg', '-n', 'vm1', '--yes']), 'azure', 'vm1 (resource group rg)')
  assertConfirm(run('az', ['group', 'delete', '-n', 'rg', '--no-wait']), 'azure', 'rg')
  assertConfirm(run('az', ['sql', 'db', 'delete', '-g', 'rg', '-s', 'srv', '-n', 'db']),
    'azure', 'db (resource group rg) (server srv)')
  assertConfirm(run('az', ['storage', 'account', 'delete', '--name', 'acc', '--resource-group', 'rg']),
    'azure', 'acc (resource group rg)')
})

test('az read-only forms stay unmodeled', () => {
  assertFree(run('az', ['vm', 'list']))
  assertFree(run('az', ['group', 'list']))
  assertFree(run('az', ['account', 'show']))
  assertFree(run('az', ['--help']))
})

// --- SQL shells (F-29) -----------------------------------------------------

test('psql/mysql/sqlite3 destructive statements confirm with the SQL object', () => {
  assertConfirm(run('psql', ['-c', 'DROP TABLE users']), 'postgres', 'SQL: DROP TABLE users')
  assertConfirm(run('psql', ['-c', 'drop database app']), 'postgres', 'SQL: drop database app')
  assertConfirm(run('psql', ['--command=TRUNCATE users']), 'postgres', 'SQL: TRUNCATE users')
  assertConfirm(run('psql', ['-c', 'DELETE FROM users']), 'postgres', 'SQL: DELETE FROM users')
  assertConfirm(run('mysql', ['-e', 'DROP SCHEMA app']), 'mysql', 'SQL: DROP SCHEMA app')
  assertConfirm(run('mysql', ['--execute', 'delete from sessions']), 'mysql', 'SQL: delete from sessions')
  assertConfirm(run('sqlite3', ['app.db', 'DROP TABLE users']), 'sqlite', 'SQL: DROP TABLE users')
})

test('psql/mysql/sqlite3 read-only and row-scoped statements stay unmodeled', () => {
  assertFree(run('psql', ['-c', 'SELECT 1']))
  assertFree(run('psql', ['-c', 'DELETE FROM t WHERE id=1']))
  assertFree(run('psql', ['-c', '\\dt']))
  assertFree(run('psql', ['--help']))
  assertFree(run('mysql', ['-e', 'SELECT * FROM users']))
  assertFree(run('mysql', ['-e', 'DELETE FROM t WHERE id=1']))
  assertFree(run('sqlite3', ['app.db', 'SELECT 1', 'DELETE FROM t WHERE x=2']))
})

// --- kubernetes (F-30) -----------------------------------------------------

test('kubectl delete confirms with its manifest or resource scope', () => {
  assertConfirm(run('kubectl', ['delete', 'namespace', 'prod']), 'k8s', 'namespace prod')
  assertConfirm(run('kubectl', ['delete', 'deployment', 'web', '--grace-period', '0']), 'k8s', 'deployment web')
  assertConfirm(run('kubectl', ['delete', '-f', 'manifest.yaml']), 'k8s', 'manifest.yaml')
  assertConfirm(run('kubectl', ['delete', 'pods', '--all']), 'k8s', 'pods --all')
  assertConfirm(run('kubectl', ['-n', 'prod', 'delete', 'pods', 'web-0']), 'k8s', 'pods web-0')
})

test('kubectl read-only and help forms stay unmodeled', () => {
  assertFree(run('kubectl', ['get', 'pods']))
  assertFree(run('kubectl', ['get', 'all']))
  assertFree(run('kubectl', ['describe', 'svc', 'web']))
  assertFree(run('kubectl', ['logs', 'pod-0']))
  assertFree(run('kubectl', ['--help']))
  assertFree(run('kubectl', ['delete', '-f', 'manifest.yaml', '--dry-run=client']))
})

// --- docker (F-31) ---------------------------------------------------------

test('docker destructive prune/remove forms confirm with their scope', () => {
  assertConfirm(run('docker', ['system', 'prune', '-af']), 'docker', 'docker system (prune)')
  assertConfirm(run('docker', ['volume', 'prune', '-a']), 'docker', 'docker volume (prune)')
  assertConfirm(run('docker', ['volume', 'rm', 'data-vol']), 'docker', 'volume data-vol')
  assertConfirm(run('docker', ['rmi', '-f', 'img:latest']), 'docker', 'image img:latest')
  assertConfirm(run('docker', ['rm', '-f', 'web-1']), 'docker', 'container web-1')
})

test('docker read-only forms stay unmodeled', () => {
  assertFree(run('docker', ['ps']))
  assertFree(run('docker', ['images']))
  assertFree(run('docker', ['container', 'ls']))
  assertFree(run('docker', ['--version']))
})

// --- terraform (F-32) ------------------------------------------------------

test('terraform destroy forms confirm with the state scope', () => {
  assertConfirm(run('terraform', ['destroy']), 'terraform', 'terraform state (destroy)')
  assertConfirm(run('terraform', ['destroy', '-auto-approve']), 'terraform', 'terraform state (destroy)')
  assertConfirm(run('terraform', ['apply', '-destroy', '-auto-approve']), 'terraform', 'terraform state (destroy via apply)')
})

test('terraform plan/validate/help stay unmodeled', () => {
  assertFree(run('terraform', ['plan']))
  assertFree(run('terraform', ['validate']))
  assertFree(run('terraform', ['apply', '-auto-approve']))
  assertFree(run('terraform', ['destroy', '-help']))
  assertFree(run('terraform', ['--version']))
})

// --- interface guard -------------------------------------------------------

test('unmodeled programs and malformed inputs produce nothing', () => {
  assertFree(run('make', ['clean']))
  assertFree(run('git', ['push', '--force']))
  assertFree(run('aws', [null, 'rm', 's3://bucket']))
  assertFree(run(null, ['rm', 's3://bucket']))
})
