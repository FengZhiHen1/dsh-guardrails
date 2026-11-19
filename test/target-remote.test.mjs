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
import { createExecutionAnalyzer } from '../src/adapter/analysis/index.js'
import { decide } from '../src/core/decision.js'

// Decision-level driver (same shape as test/over-defense.test.mjs, imported
// separately here): real analyzer + real decide, so every new matrix entry is
// checked against the actual confirm contract, not just the raw fact.
const ANALYSIS_CONTEXT = { domain: 'host', cwd: process.cwd(), platform: process.platform }
const EMPTY_INVENTORY = { kind: 'exact', count: 0, files: [], links: [], directories: [], roots: [], unknown: [] }
const analyzer = createExecutionAnalyzer()
test.after(() => analyzer.dispose())

async function evaluate(text, { language = 'bash' } = {}) {
  const analysis = await analyzer.analyze({
    source: { kind: 'inline', text }, language, context: ANALYSIS_CONTEXT, origin: { entry: 'target-remote' },
  })
  const decision = decide({
    analysisStatus: analysis.status,
    operations: analysis.operations,
    candidates: analysis.candidates,
    gaps: analysis.gaps,
    identities: [],
    inventory: EMPTY_INVENTORY,
    protectedHits: [],
    exemptions: [],
    issues: [],
  }, {})
  return { analysis, decision }
}

const OPTIONS = {
  context: { domain: 'host', platform: 'linux', cwd: '/fixture' },
  origin: { entry: 'fixture' },
  condition: 'certain',
}

function run(name, args, extraOptions = {}) {
  const operations = []
  const candidates = []
  const gaps = []
  const hit = resolveRemoteCommand(name, args, { ...OPTIONS, ...extraOptions }, {
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

test('aws batch analytics and log deletion confirm with their selector', () => {
  // DSR-032 second pass: batch/analytics long tail.
  assertConfirm(run('aws', ['glue', 'batch-delete-table', '--database-name', 'db',
    '--tables-to-delete', 'Name=t1']), 'aws', 'glue batch-delete-table Name=t1')
  assertConfirm(run('aws', ['glue', 'batch-delete-partition', '--database-name', 'db',
    '--table-name', 't', '--partitions-to-delete', 'Values=p1']),
  'aws', 'glue batch-delete-partition Values=p1')
  assertConfirm(run('aws', ['logs', 'delete-log-stream', '--log-group-name', 'lg',
    '--log-stream-name', 's1']), 'aws', 'logs delete-log-stream s1')
  assertConfirm(run('aws', ['athena', 'delete-data-catalog', '--name', 'cat1']),
    'aws', 'athena delete-data-catalog cat1')
})

test('aws athena TRUNCATE and DROP queries confirm with the SQL text', () => {
  assertConfirm(run('aws', ['athena', 'start-query-execution', '--query-string', 'TRUNCATE TABLE events']),
    'aws', 'athena: TRUNCATE TABLE events')
  assertConfirm(run('aws', ['athena', 'start-query-execution', '--query-string', 'DROP DATABASE analytics']),
    'aws', 'athena: DROP DATABASE analytics')
  assertFree(run('aws', ['athena', 'start-query-execution', '--query-string', 'SELECT 1']))
  assertFree(run('aws', ['athena', 'start-query-execution', '--query-string',
    'DELETE FROM t WHERE id = 1']))
})

test('aws read-only and preview forms stay unmodeled', () => {
  assertFree(run('aws', ['s3', 'ls', 's3://bucket']))
  assertFree(run('aws', ['s3', 'rm', 's3://bucket', '--recursive', '--dryrun']))
  assertFree(run('aws', ['ec2', 'describe-instances']))
  assertFree(run('aws', ['glue', 'get-tables', '--database-name', 'db']))
  assertFree(run('aws', ['logs', 'describe-log-streams', '--log-group-name', 'lg']))
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
  assertFree(run('gcloud', ['storage', 'ls', 'gs://bucket']))
  assertFree(run('gcloud', ['iam', 'roles', 'list', '--project', 'p']))
  assertFree(run('gcloud', ['dns', 'managed-zones', 'list']))
  assertFree(run('gcloud', ['bigtable', 'instances', 'list']))
  assertFree(run('gcloud', ['--version']))
  assertFree(run('gsutil', ['ls', 'gs://bucket']))
})

test('gcloud storage/Artifact Registry/IAM/DNS/Bigtable deletion confirms', () => {
  // DSR-032 second pass. `artifacts docker images delete` is the one four-token key.
  assertConfirm(run('gcloud', ['storage', 'rm', '-r', 'gs://bucket/dir']), 'gcp', 'gs://bucket/dir')
  assertConfirm(run('gcloud', ['storage', 'objects', 'delete', 'gs://bucket/key']), 'gcp', 'gs://bucket/key')
  assertConfirm(run('gcloud', ['firestore', 'databases', 'delete', 'db1', '--project', 'p']), 'gcp', 'db1')
  assertConfirm(run('gcloud', ['artifacts', 'docker', 'images', 'delete', 'us-docker.pkg.dev/p/r/img']),
    'gcp', 'us-docker.pkg.dev/p/r/img')
  assertConfirm(run('gcloud', ['artifacts', 'repositories', 'delete', 'repo1', '--location=us']), 'gcp', 'repo1')
  assertConfirm(run('gcloud', ['iam', 'roles', 'delete', 'role1', '--project', 'p']), 'gcp', 'role1')
  assertConfirm(run('gcloud', ['dns', 'managed-zones', 'delete', 'zone1']), 'gcp', 'zone1')
  assertConfirm(run('gcloud', ['bigtable', 'instances', 'delete', 'inst1']), 'gcp', 'inst1')
  // Already modeled in the first pass; kept here so the table stays one list.
  assertConfirm(run('gcloud', ['projects', 'delete', 'p1', '--quiet']), 'gcp', 'p1')
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
  assertFree(run('az', ['account', 'management-group', 'list']))
  assertFree(run('az', ['keyvault', 'show', '-n', 'kv1']))
  assertFree(run('az', ['acr', 'repository', 'list', '--name', 'reg1']))
  assertFree(run('az', ['ad', 'app', 'show', '--id', 'app1']))
  assertFree(run('az', ['--help']))
})

test('az purge/subscription/management-group/ACR/AD long tail confirms', () => {
  // DSR-032 second pass; `account management-group delete` is the four-token key
  // that must not fold into `group delete`.
  assertConfirm(run('az', ['keyvault', 'purge', '-n', 'kv1']), 'azure', 'kv1')
  assertConfirm(run('az', ['account', 'subscription', 'cancel', '--id', 'sub1']), 'azure', '(id sub1)')
  assertConfirm(run('az', ['account', 'management-group', 'delete', '--name', 'mg1']), 'azure', 'mg1')
  assertConfirm(run('az', ['acr', 'repository', 'delete', '--name', 'reg1', '--image', 'repo:tag']),
    'azure', 'reg1 (image repo:tag)')
  assertConfirm(run('az', ['ad', 'app', 'delete', '--id', 'app1']), 'azure', '(id app1)')
  assertConfirm(run('az', ['ad', 'sp', 'delete', '--id', 'sp1']), 'azure', '(id sp1)')
  assertConfirm(run('az', ['storage', 'blob', 'delete-batch', '--source', 'cont1', '--pattern', '*.log']),
    'azure', '(source cont1) (pattern *.log)')
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

test('kubectl apply --force is a delete-recreate over the manifest target', () => {
  // DSR-032 second pass: `--force` (not `--force-conflicts`) deletes and recreates.
  assertConfirm(run('kubectl', ['apply', '--force', '-f', 'deploy.yaml']), 'k8s', 'apply --force deploy.yaml')
  assertConfirm(run('kubectl', ['apply', '-k', 'overlays/prod', '--force']), 'k8s', 'apply --force overlays/prod')
  assertConfirm(run('kubectl', ['apply', '--force', '-f', 'a.yaml', '--prune']),
    'k8s', 'apply --prune --force a.yaml')
  // A dry run stays a preview even together with `--force`.
  assertFree(run('kubectl', ['apply', '-f', 'deploy.yaml', '--force', '--dry-run=client']))
  assertFree(run('kubectl', ['apply', '-f', 'deploy.yaml', '--dry-run=server', '--force']))
  // Plain apply and the server-side conflict flag are not deletion forms.
  assertFree(run('kubectl', ['apply', '-f', 'x.yaml']))
  assertFree(run('kubectl', ['apply', '-f', 'x.yaml', '--server-side', '--force-conflicts']))
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

test('compose down removes named volumes only with -v/--volumes', () => {
  // DSR-032 second pass: `down` alone removes containers; `-v`/`--volumes` (or a
  // down short-flag cluster containing `v`) removes the named volumes as well.
  assertConfirm(run('docker', ['compose', 'down', '-v']), 'docker', 'compose down --volumes')
  assertConfirm(run('docker', ['compose', 'down', '--volumes']), 'docker', 'compose down --volumes')
  assertConfirm(run('docker', ['compose', '-f', 'prod.yml', 'down', '-v']),
    'docker', 'compose down --volumes')
  assertConfirm(run('docker', ['compose', 'down', '-vt', '5']), 'docker', 'compose down --volumes')
  assertConfirm(run('docker-compose', ['down', '-v']), 'docker', 'docker-compose down --volumes')
  assertConfirm(run('docker-compose', ['down', '--volumes']), 'docker', 'docker-compose down --volumes')
  assertFree(run('docker', ['compose', 'down']))
  assertFree(run('docker', ['compose', '-f', 'prod.yml', 'down']))
  assertFree(run('docker', ['compose', 'ps']))
  assertFree(run('docker', ['compose', 'up', '-d']))
  assertFree(run('docker', ['compose', 'down', '-t', '5']))
  assertFree(run('docker-compose', ['down']))
  assertFree(run('docker-compose', ['ps']))
  assertFree(run('docker-compose', ['down', '--help']))
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

// --- DSR-032 second pass: redis / snowsql / databricks / supabase ----------

test('redis-cli shutdown is destructive only with NOSAVE', () => {
  assertConfirm(run('redis-cli', ['shutdown', 'nosave']), 'redis', 'redis: SHUTDOWN NOSAVE')
  assertConfirm(run('redis-cli', ['-n', '0', 'SHUTDOWN', 'NOSAVE']), 'redis', 'redis: SHUTDOWN NOSAVE')
  assertFree(run('redis-cli', ['shutdown']))
  assertFree(run('redis-cli', ['SHUTDOWN', 'SAVE']))
  assertFree(run('redis-cli', ['GET', 'k']))
  // The existing flush facts are untouched.
  assertConfirm(run('redis-cli', ['FLUSHALL']), 'redis', 'redis: FLUSHALL')
})

test('SQL text recognizes DDL objects beyond table/database/schema', () => {
  // DSR-032 second pass: warehouse/user/role were previously unmodeled.
  assertConfirm(run('snowsql', ['-q', 'DROP WAREHOUSE wh1']), 'snowflake', 'snowsql: DROP WAREHOUSE wh1')
  assertConfirm(run('snowsql', ['-q', 'drop user bob']), 'snowflake', 'snowsql: drop user bob')
  assertConfirm(run('snowsql', ['-q', 'DROP ROLE analyst']), 'snowflake', 'snowsql: DROP ROLE analyst')
  assertConfirm(run('snowsql', ['--query', 'DROP STAGE analytics.raw']),
    'snowflake', 'snowsql: DROP STAGE analytics.raw')
  assertConfirm(run('psql', ['-c', 'DROP VIEW public.active_users']), 'postgres', 'SQL: DROP VIEW public.active_users')
  assertConfirm(run('psql', ['-c', 'DROP MATERIALIZED VIEW public.mv']), 'postgres', 'SQL: DROP MATERIALIZED VIEW public.mv')
  assertFree(run('snowsql', ['-q', 'SELECT 1']))
  assertFree(run('psql', ['-c', 'DROP INDEX IF EXISTS users_email_idx']))
})

test('databricks fs rm and supabase storage rm confirm with their target', () => {
  assertConfirm(run('databricks', ['fs', 'rm', '-r', 'dbfs:/tmp/dataset']),
    'databricks', 'databricks fs rm dbfs:/tmp/dataset/** (recursive)')
  assertConfirm(run('databricks', ['fs', 'rm', 'dbfs:/tmp/file.parquet']),
    'databricks', 'databricks fs rm dbfs:/tmp/file.parquet')
  assertConfirm(run('databricks', ['-p', 'staging', 'fs', 'rm', '-r', 'dbfs:/tmp/x']),
    'databricks', 'databricks fs rm dbfs:/tmp/x/** (recursive)')
  assertFree(run('databricks', ['fs', 'ls', 'dbfs:/tmp']))
  assertFree(run('databricks', ['fs', 'rm']))
  assertConfirm(run('supabase', ['storage', 'rm', 'ss:///bucket/path/file.txt']),
    'supabase', 'supabase storage rm ss:///bucket/path/file.txt')
  assertFree(run('supabase', ['storage', 'ls', 'ss:///bucket']))
  assertFree(run('supabase', ['db', 'dump']))
})

// --- DSR-032 second pass: BigQuery / Pulumi / MinIO clients ----------------

test('bq rm and bq query confirm with their target or SQL text', () => {
  assertConfirm(run('bq', ['rm', '-r', 'my_dataset']), 'bigquery', 'bq rm my_dataset/** (recursive)')
  assertConfirm(run('bq', ['rm', '-t', 'my_dataset.my_table']), 'bigquery', 'bq rm my_dataset.my_table')
  assertConfirm(run('bq', ['query', 'TRUNCATE TABLE d.t']), 'bigquery', 'bq query: TRUNCATE TABLE d.t')
  assertConfirm(run('bq', ['--project_id', 'p', 'query', 'DROP TABLE d.t']), 'bigquery', 'bq query: DROP TABLE d.t')
  assertConfirm(run('bq', ['query', 'DELETE FROM d.t']), 'bigquery', 'bq query: DELETE FROM d.t')
  assertFree(run('bq', ['ls']))
  assertFree(run('bq', ['show', 'd.t']))
  assertFree(run('bq', ['query', 'SELECT 1']))
  assertFree(run('bq', ['query', 'DELETE FROM d.t WHERE id = 1']))
  assertFree(run('bq', ['query', '--dry_run', 'DROP TABLE d.t']))
  assertFree(run('bq', ['rm']))
})

test('pulumi stack rm confirms with the stack; stack ls stays free', () => {
  assertConfirm(run('pulumi', ['stack', 'rm', 'prod-old']), 'pulumi', 'pulumi stack rm prod-old')
  assertConfirm(run('pulumi', ['--cwd', './prod', 'stack', 'rm', 'prod-old', '--yes']),
    'pulumi', 'pulumi stack rm prod-old')
  // No operand removes the selected stack, the same shape as `terraform workspace delete`.
  assertConfirm(run('pulumi', ['stack', 'rm']), 'pulumi', 'pulumi stack rm (selected stack)')
  assertFree(run('pulumi', ['stack', 'ls']))
  assertFree(run('pulumi', ['stack', 'select', 'prod']))
  assertFree(run('pulumi', ['preview']))
  assertFree(run('pulumi', ['stack', 'rm', '--help']))
})

test('mc rb and mc rm confirm with the bucket or object target', () => {
  assertConfirm(run('mc', ['rb', 'myminio/bucket']), 'minio', 'mc rb myminio/bucket')
  assertConfirm(run('mc', ['rb', '--force', 'myminio/bucket']), 'minio', 'mc rb myminio/bucket')
  assertConfirm(run('mc', ['rm', 'myminio/bucket/obj.txt']), 'minio', 'mc rm myminio/bucket/obj.txt')
  assertConfirm(run('mc', ['--json', 'rm', '--recursive', '--force', '--dangerous', 'myminio/bucket']),
    'minio', 'mc rm myminio/bucket/** (recursive)')
  assertFree(run('mc', ['ls', 'myminio/bucket']))
  assertFree(run('mc', ['stat', 'myminio/bucket/obj']))
  assertFree(run('mc', ['cp', './a', 'myminio/bucket/']))
  assertFree(run('mc', ['rm']))
  assertFree(run('mc', ['--version']))
})

// --- interface guard -------------------------------------------------------

test('unmodeled programs and malformed inputs produce nothing', () => {
  assertFree(run('make', ['clean']))
  assertFree(run('git', ['push', '--force']))
  assertFree(run('aws', [null, 'rm', 's3://bucket']))
  assertFree(run(null, ['rm', 's3://bucket']))
})

// --- cloud-storage uploads: local read facts (DSR-031 决定 6) --------------

function assertRead(result, local) {
  assert.equal(result.hit, true)
  assert.equal(result.candidates.length, 0)
  assert.equal(result.gaps.length, 0)
  assert.equal(result.operations.length, 1)
  const operation = result.operations[0]
  assert.equal(operation.action, 'read-content')
  assert.deepEqual(operation.target, { kind: 'exact', paths: [local] })
  assert.equal(operation.preview, false)
}

test('an upload whose destination is remote reads the literal local source', () => {
  assertRead(run('aws', ['s3', 'cp', './secrets.txt', 's3://bucket/secrets.txt']), './secrets.txt')
  assertRead(run('aws', ['s3', 'sync', './config', 's3://bucket/config']), './config')
  assertRead(run('aws', ['s3', 'cp', '/home/u/.aws/credentials', 's3://bucket/c']), '/home/u/.aws/credentials')
  assertRead(run('gsutil', ['cp', './key.json', 'gs://bucket/key.json']), './key.json')
  assertRead(run('gsutil', ['rsync', '-r', './dir', 'gs://bucket/dir']), './dir')
  assertRead(run('gcloud', ['storage', 'cp', './creds', 'gs://bucket/creds']), './creds')
  assertRead(run('az', ['storage', 'blob', 'upload', '--file', './token.txt']), './token.txt')
  assertRead(run('az', ['storage', 'blob', 'upload', '-f', './token.txt']), './token.txt')
})

test('downloads, server-side copies, stdin and dynamic uploads stay free', () => {
  assertFree(run('aws', ['s3', 'cp', 's3://a', 's3://b']))
  assertFree(run('aws', ['s3', 'sync', 's3://bucket/dir', './local']))
  assertFree(run('aws', ['s3', 'cp', '-', 's3://bucket/x']))
  assertFree(run('aws', ['s3', 'cp', './a.txt', 's3://bucket/a.txt', '--dryrun']))
  assertFree(run('gsutil', ['cp', 'gs://bucket/key.json', './key.json']))
  assertFree(run('gcloud', ['storage', 'cp', 'gs://bucket/creds', './creds']))
  assertFree(run('az', ['storage', 'blob', 'upload', '--file', '-']))
  assertFree(run('aws', ['s3', 'cp', null, 's3://bucket/x']))
})

test('scp reads local sources only in the upload direction', () => {
  assertRead(run('scp', ['-r', './dir', 'host:/dst']), './dir')
  assertRead(run('scp', ['-P', '2222', './a', 'user@host:/b']), './a')
  assertRead(run('scp', ['C:\\data\\a.txt', 'host:/b']), 'C:\\data\\a.txt')
  // Second pass: `-i <file>` is authentication input with no outward transfer, so
  // it no longer adds an identity read. The upload source keeps its own fact, and
  // a download or a bare identity line produces nothing (was: identity read).
  const withIdentity = run('scp', ['-i', 'id_ed25519', '-o', 'StrictHostKeyChecking=no', './a', 'host:/b'])
  assert.deepEqual(withIdentity.operations.map((operation) => operation.target),
    [{ kind: 'exact', paths: ['./a'] }])
  assertFree(run('scp', ['-i', 'id_ed25519', 'host:/a', './b']))
  assertFree(run('scp', ['-i/tmp/id_rsa', 'host:/a']))
  assertFree(run('scp', ['file', '.']))
  assertFree(run('scp', ['host:/a', '/b']))
  assertFree(run('scp', ['-', 'user@host:/b']))
  assertFree(run('scp', ['-r', './a']))
})

// --- DSR-032 决定 5: transfer identity files and sftp batch mode ----------

test('sftp -i is authentication input and stays free', () => {
  // Second pass: the identity file is not modeled as a disclosure read; `-i -`
  // (stdin) and the interactive/help forms were already free.
  assertFree(run('sftp', ['-i', 'id_rsa', 'host']))
  assertFree(run('sftp', ['-i/tmp/id_ed25519', 'host']))
  assertFree(run('sftp', ['-i', '-', 'host']))
})

test('sftp batch mode is an unverified-effect candidate carrying the batch scope', () => {
  const direct = run('sftp', ['-b', 'batch.txt', 'host'])
  assert.equal(direct.hit, true)
  assert.equal(direct.operations.length, 0)
  assert.equal(direct.candidates.length, 1)
  assert.equal(direct.candidates[0].kind, 'unverified-effect')
  const attached = run('sftp', ['-bbatch.txt', 'host'])
  assert.equal(attached.candidates.length, 1)
  const stdinBatch = run('sftp', ['-b', '-', 'host'])
  assert.equal(stdinBatch.candidates.length, 1)
  const heredoc = run('sftp', ['host'], { heredocs: [{ operator: '<<', body: 'put secret.txt\nrm /data\n' }] })
  assert.equal(heredoc.candidates.length, 1)
  assert.equal(heredoc.operations.length, 0)
})

test('interactive and help sftp forms stay free', () => {
  assertFree(run('sftp', ['host']))
  assertFree(run('sftp', ['-V']))
  assertFree(run('sftp', ['-h']))
  assertFree(run('sftp', ['host', 'get', 'file']))
})

// --- rsync upload reads (routed through commands.js) ----------------------

const RSYNC_UPLOADS = [
  ['rsync -a ./src/ user@host:/dst/', ['./src/']],
  ['rsync -e "ssh -p 2222" ./a host:/b', ['./a']],
  ['rsync -r ./a ./b host:/dst/', ['./a', './b']],
]

test('rsync uploads produce allowed local read facts', async () => {
  for (const [command, paths] of RSYNC_UPLOADS) {
    const { analysis, decision } = await evaluate(command)
    assert.equal(decision.kind, 'allow',
      `${command}: expected allow, got ${decision.kind} ${decision.ruleId ?? ''}`)
    assert.deepEqual(analysis.candidates, [], `${command}: expected no candidates`)
    const reads = (analysis.operations ?? []).filter((operation) => operation.action === 'read-content')
    assert.deepEqual(reads.map((operation) => operation.target),
      paths.map((local) => ({ kind: 'exact', paths: [local] })), command)
    assert.ok(!analysis.operations.some((operation) => operation.action === 'delete'), command)
  }
})

test('local rsync stays fact-free and --delete keeps its own deletion fact', async () => {
  // Local -> local: no read fact and no deletion (no --delete).
  await assertDecisionAllow('rsync -a src/ dst/')
  // A local destination is not an upload: the existing --delete fact stays the
  // only fact (the deletion branch is untouched).
  const localDelete = await evaluate('rsync --delete ./src/ /abs/dst/')
  const deletes = localDelete.analysis.operations.filter((operation) => operation.action === 'delete')
  assert.equal(deletes.length, 1, 'the existing --delete branch must still fire')
  assert.deepEqual(deletes[0].target, { kind: 'subtree', root: '/abs/dst/' })
  assert.ok(!localDelete.analysis.operations.some((operation) => operation.action === 'read-content'),
    'a local destination must not produce an upload read fact')
  // A remote destination is the upload direction: the read fact fires and the
  // --delete fact names the remote scope.
  const remoteDelete = await evaluate('rsync --delete ./src/ user@host:/dst/')
  const uploadReads = remoteDelete.analysis.operations.filter((operation) =>
    operation.action === 'read-content')
  assert.deepEqual(uploadReads.map((operation) => operation.target),
    [{ kind: 'exact', paths: ['./src/'] }])
  assert.ok(remoteDelete.analysis.operations.some((operation) => operation.action === 'delete'),
    'the existing --delete fact must still be there next to the read fact')
  // DSR-031 任务 F：远端目的地按 unknown+knownScope 判定，不再当作宿主 subtree（D2 修正）。
  assert.equal(remoteDelete.decision.kind, 'confirm')
  assert.equal(remoteDelete.decision.ruleId, 'data.delete.dynamic')
})

// --- global options before the subcommand / usage errors / = selectors -----

test('global options before the subcommand are still modeled', () => {
  assertConfirm(run('gsutil', ['-m', 'rm', '-r', 'gs://b/p']), 'gcp', 'gs://b/p/** (recursive)')
  assertConfirm(run('gsutil', ['-u', 'proj', 'rm', '-r', 'gs://b/p']), 'gcp', 'gs://b/p/** (recursive)')
  assertConfirm(run('gsutil', ['-h', 'Cache-Control: no-store', 'rm', 'gs://b/k']), 'gcp', 'gs://b/k')
  assertConfirm(run('aws', ['--profile', 'prod', 'ec2', 'delete-volume', '--volume-ids', 'vol-1']),
    'aws', 'ec2 delete-volume vol-1')
  assertConfirm(run('aws', ['--output', 'json', 's3', 'rm', 's3://b/x']), 'aws', 's3://b/x')
  assertConfirm(run('gcloud', ['--project', 'p', 'compute', 'instances', 'delete', 'vm-1']), 'gcp', 'vm-1')
  assertConfirm(run('docker', ['--context', 'prod', 'volume', 'rm', 'pgdata']), 'docker', 'volume pgdata')
  assertConfirm(run('docker', ['-H', 'ssh://h', 'system', 'prune', '-af']), 'docker', 'docker system (prune)')
})

test('usage errors produce nothing; dynamic selectors still confirm', () => {
  // No selector/operand at all: usage error, allow with no fact (DSR-031 決定 5).
  assertFree(run('az', ['vm', 'delete']))
  assertFree(run('az', ['group', 'delete']))
  assertFree(run('aws', ['ec2', 'delete-volume']))
  assertFree(run('docker', ['volume', 'rm']))
  assertFree(run('docker', ['rm', '-f']))
  assertFree(run('gsutil', ['rm']))
  assertFree(run('terraform', ['state', 'rm']))
  assertFree(run('borg', ['delete']))
  // A dynamic selector is a real deletion attempt and stays confirmed.
  assertConfirm(run('aws', ['ec2', 'delete-volume', '--volume-ids', null]),
    'aws', 'ec2 delete-volume (selection not literal)')
  assertConfirm(run('az', ['vm', 'delete', '-n', null]), 'azure', 'vm delete (selection not literal)')
  assertConfirm(run('docker', ['volume', 'rm', null]), 'docker', 'docker volume rm (selection not literal)')
  assertConfirm(run('docker', ['rm', '-f', null]), 'docker', 'docker rm (selection not literal)')
  assertConfirm(run('gsutil', ['rm', '-r', null]), 'gcp', 'gsutil rm (selection not literal)')
  assertConfirm(run('terraform', ['state', 'rm', null]), 'terraform', 'terraform state rm (selection not literal)')
  assertConfirm(run('borg', ['delete', null]), 'borg', 'borg delete (selection not literal)')
})

test('selector flags accept the --flag=value form', () => {
  assertConfirm(run('aws', ['ec2', 'delete-volume', '--volume-ids=vol-1']), 'aws', 'ec2 delete-volume vol-1')
  assertConfirm(run('aws', ['rds', 'delete-db-instance', '--db-instance-identifier=db1']),
    'aws', 'rds delete-db-instance db1')
  assertConfirm(run('aws', ['dynamodb', 'delete-table', '--table-name=t1']), 'aws', 'dynamodb delete-table t1')
  assertConfirm(run('az', ['vm', 'delete', '--name=vm1', '--resource-group=rg']),
    'azure', 'vm1 (resource group rg)')
  assertConfirm(run('kubectl', ['delete', '--filename=manifest.yaml']), 'k8s', 'manifest.yaml')
  assertConfirm(run('gcloud', ['--project=p', 'compute', 'instances', 'delete', 'vm-1']), 'gcp', 'vm-1')
  assertConfirm(run('docker', ['--context=prod', 'volume', 'rm', 'pgdata']), 'docker', 'volume pgdata')
})

// --- decision-level matrix (DSR-031 决定 5) --------------------------------
// Every entry below runs through the real analyzer + real decide; the confirm
// must be the deletion family rule (`data.delete.dynamic`), never a deny.

async function assertDecisionConfirm(command) {
  const { analysis, decision } = await evaluate(command)
  assert.equal(decision.kind, 'confirm',
    `${command}: expected confirm, got ${decision.kind} ${decision.ruleId ?? ''}`)
  assert.equal(decision.ruleId, 'data.delete.dynamic', `${command}: unexpected rule ${decision.ruleId}`)
  assert.deepEqual(analysis.candidates, [], `${command}: expected no candidates`)
  const deletes = (analysis.operations ?? []).filter((operation) =>
    operation.action === 'delete' && operation.preview !== true)
  assert.ok(deletes.length >= 1, `${command}: expected a delete operation`)
  for (const operation of deletes) {
    assert.equal(operation.target.kind, 'unknown', `${command}: remote target stays unknown`)
    assert.equal(operation.target.reason, 'remote-target', `${command}: remote reason`)
    assert.ok(Array.isArray(operation.target.knownScope) && operation.target.knownScope.length > 0,
      `${command}: knownScope must be stated`)
    assert.ok(operation.details?.remote?.provider, `${command}: details.remote.provider`)
    assert.ok(operation.details?.remote?.scope, `${command}: details.remote.scope`)
  }
}

async function assertDecisionAllow(command) {
  const { analysis, decision } = await evaluate(command)
  assert.equal(decision.kind, 'allow', `${command}: expected allow, got ${decision.kind} ${decision.ruleId ?? ''}`)
  assert.deepEqual(analysis.candidates, [], `${command}: expected no candidates`)
  const effective = (analysis.operations ?? []).filter((operation) => operation.preview !== true)
  assert.deepEqual(effective, [], `${command}: expected no effective operations`)
}

const DECISION_GROUPS = [
  ['aws', [
    'aws ec2 delete-security-group --group-id sg-123',
    'aws ec2 delete-snapshot --snapshot-ids snap-1',
    'aws ec2 delete-volume --volume-ids vol-1',
    'aws ec2 deregister-image --image-ids ami-1',
    'aws ec2 delete-vpc --vpc-id vpc-1',
    'aws ec2 delete-key-pair --key-name kp1',
    'aws iam delete-user --user-name bob',
    'aws iam delete-role --role-name role1',
    'aws iam delete-policy --policy-arn arn:aws:iam::123:policy/p',
    'aws iam delete-access-key --access-key-id AKIA1',
    'aws s3api delete-bucket --bucket b1',
    'aws efs delete-file-system --file-system-id fs-1',
    'aws elasticache delete-cache-cluster --cache-cluster-id cc-1',
    'aws secretsmanager delete-secret --secret-id s1',
    'aws kms schedule-key-deletion --key-id k1',
    'aws sqs delete-queue --queue-url https://sqs/q',
    'aws sns delete-topic --topic-arn arn:aws:sns:t',
    'aws logs delete-log-group --log-group-name lg',
    'aws cloudformation delete-stack --stack-name st',
    'aws lambda delete-function --function-name fn',
    'aws ecr delete-repository --repository-name repo',
    'aws route53 delete-hosted-zone --id Z1',
    'aws rds delete-db-instance --db-instance-identifier db1',
    'aws rds delete-db-cluster --db-cluster-identifier c1',
    'aws dynamodb delete-table --table-name t1',
    'aws dynamodb delete-backup --backup-arn arn:aws:dynamodb:b',
    'aws ec2 terminate-instances --instance-ids i-1',
    'aws s3 rm s3://bucket --recursive',
    'aws s3 rb s3://bucket',
    'aws --profile prod ec2 delete-volume --volume-ids vol-1',
    'aws --output json s3 rm s3://b/x',
    'aws ec2 delete-volume --volume-ids=vol-2',
    'aws rds delete-db-instance --db-instance-identifier=db2',
    'aws dynamodb delete-table --table-name=t2',
    // DSR-032 决定 9: analytics / streaming / audit / object-store long tail.
    'aws eks delete-cluster --name prod-eks',
    'aws glue delete-database --name legacy',
    'aws glue delete-table --database-name db --name users',
    'aws glue delete-partition --database-name db --table-name t --partition-values p1',
    'aws glue delete-crawler --name crawler1',
    'aws glue delete-job --job-name etl',
    'aws athena start-query-execution --query-string "DROP TABLE analytics.events"',
    'aws athena start-query-execution --query-string "delete from analytics.events"',
    'aws redshift delete-cluster --cluster-identifier dw1',
    'aws kinesis delete-stream --stream-name events',
    'aws cloudtrail delete-trail --name org-trail',
    'aws s3api delete-object --bucket b1 --key k1',
    'aws s3api delete-objects --bucket b1 --delete file://list.json',
    'aws s3 sync --delete ./site s3://bucket/site',
    'aws ecr batch-delete-image --repository-name app --image-ids imageTag=latest',
    // DSR-032 second pass: batch analytics / log / catalog deletion.
    'aws glue batch-delete-table --database-name db --tables-to-delete Name=t1',
    'aws glue batch-delete-partition --database-name db --table-name t --partitions-to-delete Values=p1',
    'aws logs delete-log-stream --log-group-name lg --log-stream-name s1',
    'aws athena start-query-execution --query-string "TRUNCATE TABLE events"',
    'aws athena start-query-execution --query-string "DROP DATABASE analytics"',
    'aws athena delete-data-catalog --name cat1',
  ]],
  ['gcloud', [
    'gcloud compute instances delete inst1 --quiet',
    'gcloud compute disks delete disk1 --zone=us-east1-b',
    'gcloud compute snapshots delete snap1',
    'gcloud compute firewall-rules delete rule1',
    'gcloud compute networks delete net1',
    'gcloud compute instance-templates delete tmpl1',
    'gcloud compute images delete img1',
    'gcloud compute addresses delete addr1 --region=us-central1',
    'gcloud sql instances delete db1',
    'gcloud container clusters delete cl1 --region=us-central1',
    'gcloud storage buckets delete bucket1',
    'gcloud secrets delete secret1',
    'gcloud iam service-accounts delete sa@proj.iam.gserviceaccount.com',
    'gcloud projects delete proj1 --quiet',
    'gcloud functions delete fn1',
    'gcloud run services delete svc1 --region=us-central1',
    'gcloud pubsub topics delete topic1',
    'gcloud kms keys destroy key1 --location=global --keyring=kr',
    'gcloud logging sinks delete sink1',
    'gcloud deployment-manager deployments delete dep1',
    'gcloud bigquery datasets delete ds1',
    'gcloud bigquery tables delete ds1.tbl1',
    'gcloud spanner instances delete sp1',
    'gcloud redis instances delete r1 --region=us-central1',
    'gcloud --project p compute instances delete vm-2',
    'gcloud --project=p compute instances delete vm-3',
    'gcloud --quiet compute instances delete vm-4',
    'gcloud dataproc clusters delete dc1 --region=us-central1',
    // DSR-032 second pass.
    'gcloud storage rm -r gs://bucket/dir',
    'gcloud storage objects delete gs://bucket/key',
    'gcloud firestore databases delete db1',
    'gcloud artifacts docker images delete us-docker.pkg.dev/p/r/img',
    'gcloud artifacts repositories delete repo1',
    'gcloud iam roles delete role1',
    'gcloud dns managed-zones delete zone1',
    'gcloud bigtable instances delete inst1',
  ]],
  ['gsutil', [
    'gsutil rm -r gs://bucket',
    'gsutil rm gs://bucket/obj.txt',
    'gsutil rb gs://bucket',
    'gsutil -m rm -r gs://b/p',
    'gsutil -q rm gs://b/k',
    'gsutil -u proj rm -r gs://b/p',
    'gsutil -uproj rm gs://b/k',
    'gsutil -h "Cache-Control: no-store" rm gs://b/k',
  ]],
  ['az', [
    'az group delete -n rg --yes',
    'az vm delete -g rg -n vm1 --yes',
    'az sql db delete -g rg -s srv -n db1',
    'az storage account delete -n acc -g rg',
    'az keyvault delete -n kv1',
    'az keyvault key delete --vault-name kv1 --name key1',
    'az keyvault secret delete --vault-name kv1 --name sec1',
    'az webapp delete -g rg -n app1',
    'az functionapp delete -g rg -n fn1',
    'az aks delete -g rg -n cluster1',
    'az network nsg delete -g rg -n nsg1',
    'az network vnet delete -g rg -n vnet1',
    'az disk delete -g rg -n disk1',
    'az snapshot delete -g rg -n snap1',
    'az acr delete -n reg1',
    'az cosmosdb delete -g rg -n cosmos1',
    'az redis delete -g rg -n redis1',
    'az identity delete -g rg -n id1',
    'az role assignment delete --assignee a@b.com --role Contributor --scope /subscriptions/x',
    'az storage container delete --account-name acc -n cont1',
    'az storage blob delete --account-name acc --container-name cont1 --name blob1',
    'az vm delete --name=vm2 --resource-group=rg2',
    // DSR-032 second pass.
    'az keyvault purge -n kv1',
    'az account subscription cancel --id sub1',
    'az account management-group delete --name mg1',
    'az acr repository delete --name reg1 --image repo:tag',
    'az ad app delete --id app1',
    'az ad sp delete --id sp1',
    'az storage blob delete-batch --source cont1 --pattern "*.log"',
  ]],
  ['kubectl', [
    'kubectl delete namespace prod',
    'kubectl delete ns stage',
    'kubectl delete pvc data',
    'kubectl delete persistentvolumeclaim data',
    'kubectl delete pv pv1',
    'kubectl delete secret s1',
    'kubectl delete configmap cm1',
    'kubectl delete svc web',
    'kubectl delete deployment web',
    'kubectl delete statefulset db',
    'kubectl delete daemonset agent',
    'kubectl delete cronjob cj1',
    'kubectl delete job j1',
    'kubectl delete crd widgets.example.com',
    'kubectl delete -f manifest.yaml',
    'kubectl delete --filename=deploy.yaml',
    'kubectl delete pods --all',
    'kubectl replace --force -f deploy.yaml',
    'kubectl drain node1 --delete-emptydir-data',
    'kubectl drain node2 --force',
    'kubectl apply --prune -f deploy.yaml',
    'kubectl apply --prune -f ./manifests/',
    'kubectl delete pods --all-namespaces',
    'kubectl delete ns -A',
    // DSR-032 second pass: apply --force deletes and recreates.
    'kubectl apply --force -f deploy.yaml',
    'kubectl apply -k overlays/prod --force',
    'kubectl apply --force -f deploy.yaml --prune',
  ]],
  ['helm', [
    'helm uninstall rel1',
    'helm del rel2',
    'helm delete rel3',
    'helm rollback rel4',
    'helm rollback rel4 2',
  ]],
  ['docker', [
    'docker system prune -af',
    'docker system reset',
    'docker volume prune -a',
    'docker volume rm data-vol',
    'docker container prune -f',
    'docker image prune -a',
    'docker network prune -f',
    'docker builder prune -f',
    'docker rmi -f img:latest',
    'docker rm -f web-1',
    'docker --context prod volume rm pgdata',
    'docker -H ssh://h system prune -af',
    'docker --context=prod volume rm pgdata2',
    // DSR-032 second pass: compose down removes named volumes only with -v.
    'docker compose down -v',
    'docker compose down --volumes',
    'docker compose -f prod.yml down -v',
    'docker-compose down -v',
  ]],
  ['terraform', [
    'terraform destroy',
    'terraform destroy -auto-approve',
    'terraform apply -destroy',
    'terraform state rm aws_instance.foo',
    'terraform workspace delete prod',
  ]],
  ['database', [
    'psql -c "DROP TABLE users"',
    'psql -c "TRUNCATE users"',
    'psql -c "DELETE FROM users"',
    'mysql -e "DROP SCHEMA app"',
    'sqlite3 app.db "DROP TABLE users"',
    'mongosh --eval "db.dropDatabase()"',
    'mongosh --eval "db.users.drop()"',
    'mongosh --eval "db.users.deleteMany({})"',
    'mongosh --eval "db.sessions.remove({})"',
    'redis-cli FLUSHALL',
    'redis-cli -n 0 FLUSHDB',
    'redis-cli shutdown nosave',
    'redis-cli SHUTDOWN NOSAVE',
    'mysqladmin drop appdb',
    'dropdb appdb',
    'clickhouse-client -q "DROP TABLE events"',
  ]],
  ['gh', [
    'gh repo delete owner/repo --yes',
    'gh release delete v1.0.0 --yes',
    'gh api -X DELETE /repos/owner/repo',
    'gh api --method DELETE repos/owner/repo/contents/x',
  ]],
  ['restic', [
    'restic forget --prune --keep-last 3',
    'restic -r s3:bucket/repo forget --prune',
    'restic prune',
    'restic -r s3:bucket/repo prune',
  ]],
  ['borg', [
    'borg delete repo',
    'borg delete repo::archive',
    'borg prune',
  ]],
  ['rclone', [
    'rclone delete remote:path',
    'rclone purge remote:path',
    'rclone delete remote:path/sub --min-age 7d',
  ]],
  ['velero', [
    'velero backup delete b1',
    'velero backup delete --all --confirm',
    'velero backup delete b1 -n velero',
  ]],
  ['vault', [
    'vault kv metadata delete secret/foo',
    'vault kv metadata delete -mount=secret secret/foo',
  ]],
  ['doppler', [
    'doppler secrets delete API_KEY --yes',
    'doppler secrets delete DB_PASSWORD DB_USER --project p1 --config dev',
  ]],
  ['infisical', [
    'infisical secrets delete API_KEY',
    'infisical secrets delete API_KEY --env prod',
  ]],
  ['azcopy', [
    'azcopy remove https://acct.blob.core.windows.net/cont/blob',
    'azcopy sync --delete ./site https://acct.blob.core.windows.net/web',
  ]],
  ['supabase', [
    'supabase db reset',
    'supabase migration down',
    'supabase storage rm ss:///bucket/path/file.txt',
  ]],
  ['databricks', [
    'databricks bundle destroy',
    'databricks fs rm -r dbfs:/tmp/dataset',
    'databricks fs rm dbfs:/tmp/file.parquet',
  ]],
  ['snowflake', [
    'snowsql -q "DROP TABLE analytics.events"',
    'snowsql --query "TRUNCATE TABLE analytics.events"',
    'snowsql -q "DELETE FROM analytics.events"',
    // DSR-032 second pass: warehouse/user/role DDL objects.
    'snowsql -q "DROP WAREHOUSE wh1"',
    'snowsql -q "drop user bob"',
    'snowsql -q "DROP ROLE analyst"',
  ]],
  ['bigquery', [
    'bq rm -r my_dataset',
    'bq rm -t my_dataset.my_table',
    'bq query "TRUNCATE TABLE d.t"',
    'bq query "DROP TABLE d.t"',
    'bq query "DELETE FROM d.t"',
  ]],
  ['pulumi', [
    'pulumi stack rm prod-old',
    'pulumi --cwd ./prod stack rm prod-old --yes',
    'pulumi stack rm',
  ]],
  ['minio', [
    'mc rb myminio/bucket',
    'mc rb --force myminio/bucket',
    'mc rm myminio/bucket/obj.txt',
    'mc --json rm --recursive --force --dangerous myminio/bucket',
  ]],
]

const MIN_THREE = new Set(['aws', 'gcloud', 'gsutil', 'az', 'kubectl', 'helm', 'docker', 'terraform', 'database'])

for (const [provider, commands] of DECISION_GROUPS) {
  test(`decision matrix: ${provider} destructive subcommands confirm (>=3)`, async () => {
    // Round-one providers each cover >=3 forms; doppler/infisical expose a single
    // destructive subcommand (`secrets delete`), so their forms share that entry.
    assert.ok(commands.length >= (MIN_THREE.has(provider) ? 3 : 1), `${provider}: matrix entry count`)
    for (const command of commands) await assertDecisionConfirm(command)
  })
}

const ALLOW_SURFACE = [
  'aws s3 ls',
  'aws s3 cp s3://a s3://b',
  'aws ec2 describe-instances',
  'aws ec2 get-console-output --instance-id i-1',
  'aws secretsmanager list-secrets',
  'aws --profile prod s3 ls',
  'aws ec2 delete-volume',
  'gcloud compute instances list',
  'gcloud --project p compute instances list',
  'gcloud storage ls',
  'gsutil ls gs://b',
  'gsutil version',
  'gsutil -m ls gs://b',
  'gsutil rm',
  'az vm list',
  'az vm delete',
  'az group delete',
  'az group show -n g',
  'az keyvault secret show --name s --vault-name v',
  'kubectl get pods',
  'kubectl describe pvc data',
  'kubectl apply -f x.yaml',
  'kubectl replace -f x.yaml',
  'kubectl drain node3 --ignore-daemonsets',
  'kubectl delete --dry-run=client pod x',
  'helm list',
  'helm status x',
  'docker ps',
  'docker images',
  'docker volume ls',
  'docker volume create vol',
  'docker network inspect x',
  'docker --context prod ps',
  'docker volume rm',
  'docker rm -f',
  'terraform plan',
  'terraform state list',
  'terraform state rm',
  'terraform force-unlock 12345',
  'createdb appdb',
  'scp file .',
  'scp host:/a /b',
  'gh repo view owner/repo',
  'gh release list',
  'restic snapshots',
  'restic check',
  'restic forget --keep-last 3',
  'borg list',
  'borg delete',
  'rclone ls remote:path',
  'rclone lsd remote:path',
  'vault kv get secret/foo',
  'vault kv list secret/',
  'vault kv delete secret/foo',
  'vault delete secret/foo',
  'velero backup get',
  'psql -c "SELECT 1"',
  'psql -c "DELETE FROM t WHERE id=1"',
  'mysql -e "SHOW TABLES"',
  'mongosh --eval "db.stats()"',
  'redis-cli GET k',
  'redis-cli KEYS *',
  'sqlite3 app.db "SELECT 1"',
  // DSR-032 决定 9: read-only / query forms of the long-tail providers.
  'aws eks list-clusters',
  'aws glue get-databases',
  'aws glue get-table --database-name db --name t',
  'aws kinesis describe-stream --stream-name s',
  'aws cloudtrail describe-trails',
  'aws s3api list-objects --bucket b',
  'aws athena start-query-execution --query-string "SELECT 1"',
  'aws ecr describe-repositories',
  'aws s3 sync --delete ./site ./local',
  'gcloud dataproc clusters list',
  'azcopy list https://acct.blob.core.windows.net/cont',
  'azcopy copy ./a https://acct.blob.core.windows.net/cont/a',
  'kubectl apply -f deploy.yaml',
  'supabase db dump',
  'databricks bundle validate',
  'snowsql -q "SELECT 1"',
  'sftp host',
  'sftp -V',
  'sftp -h',
  // The transfer identity file is authentication input, not a disclosure read.
  'sftp -i id_rsa host',
  'scp -i id_ed25519 host:/data ./data',
  // DSR-032 second pass: read-only forms of the newly modeled subcommands.
  'gcloud storage ls',
  'gcloud iam roles list',
  'gcloud artifacts repositories list',
  'gcloud dns managed-zones list',
  'az keyvault show -n kv1',
  'az keyvault purge --help',
  'az account management-group list',
  'az acr repository list --name reg1',
  'aws glue get-tables --database-name db',
  'aws logs describe-log-streams --log-group-name lg',
  'aws athena start-query-execution --query-string "DELETE FROM t WHERE id = 1"',
  'kubectl apply -f deploy.yaml --force --dry-run=client',
  'kubectl apply -f deploy.yaml --server-side --force-conflicts',
  'docker compose ps',
  'docker compose down',
  'docker compose down -t 5',
  'docker-compose down',
  'docker-compose ps',
  'redis-cli shutdown',
  'redis-cli SHUTDOWN SAVE',
  'psql -c "DROP INDEX IF EXISTS users_email_idx"',
  'bq ls',
  'bq show my_dataset.my_table',
  'bq query "SELECT 1"',
  'bq query --dry_run "DROP TABLE d.t"',
  'pulumi stack ls',
  'pulumi stack select prod',
  'pulumi preview',
  'mc ls myminio/bucket',
  'mc stat myminio/bucket/obj',
  'mc cp ./a myminio/bucket/',
  'databricks fs ls dbfs:/tmp',
  'supabase storage ls ss:///bucket',
]

test('previews and read-only forms stay allow with no candidates and no effective operations', async () => {
  for (const command of ALLOW_SURFACE) await assertDecisionAllow(command)
})

const SCP_UPLOADS = [
  ['scp ./key user@host:/backup/key', ['./key']],
  ['scp -r ./dir host:/dst', ['./dir']],
  ['scp -P 2222 ./a ./b user@host:/dst/', ['./a', './b']],
  // Second pass: the `-i` identity file no longer adds a read fact, so the
  // uploaded archive is the only local read.
  ['scp -i id_ed25519 -o StrictHostKeyChecking=no ./archive.tgz user@host:/backup/',
    ['./archive.tgz']],
]

test('scp uploads only produce allowed local read facts (no candidates)', async () => {
  for (const [command, paths] of SCP_UPLOADS) {
    const { analysis, decision } = await evaluate(command)
    assert.equal(decision.kind, 'allow',
      `${command}: expected allow, got ${decision.kind} ${decision.ruleId ?? ''}`)
    assert.deepEqual(analysis.candidates, [], `${command}: expected no candidates`)
    const effective = (analysis.operations ?? []).filter((operation) => operation.preview !== true)
    assert.deepEqual(effective.map((operation) => operation.action), paths.map(() => 'read-content'), command)
    assert.deepEqual(effective.map((operation) => operation.target),
      paths.map((local) => ({ kind: 'exact', paths: [local] })), command)
  }
})

// The read fact above is what the evidence layer turns into a protected hit;
// here the hit is supplied literally to show the existing rule still answers.
test('the upload read fact reaches the existing credential.file.read rule', async () => {
  const { analysis } = await evaluate('aws s3 cp ./.aws/credentials s3://bucket/credentials')
  const read = (analysis.operations ?? []).find((operation) => operation.action === 'read-content')
  assert.ok(read, 'the upload must produce a read-content fact')
  assert.deepEqual(read.target, { kind: 'exact', paths: ['./.aws/credentials'] })
  const decision = decide({
    analysisStatus: analysis.status,
    operations: analysis.operations,
    candidates: analysis.candidates,
    gaps: analysis.gaps,
    identities: [],
    inventory: EMPTY_INVENTORY,
    protectedHits: [{ path: '/fixture/.aws/credentials', action: 'read-content' }],
    exemptions: [],
    issues: [],
  }, {})
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'credential.file.read')
})

// --- DSR-032 决定 5: decision-level transfer facts ------------------------

test('sftp batch mode confirms as execution.unverified-effect with its batch scope', async () => {
  const commands = [
    'sftp -b batch.txt host',
    'sftp -b - host',
    'sftp host <<EOF\nput id_rsa /tmp/\nEOF',
  ]
  for (const command of commands) {
    const { analysis, decision } = await evaluate(command)
    assert.equal(decision.kind, 'confirm',
      `${command}: expected confirm, got ${decision.kind} ${decision.ruleId ?? ''}`)
    assert.equal(decision.ruleId, 'execution.unverified-effect', command)
    assert.equal(analysis.candidates.length, 1, command)
    assert.equal(analysis.candidates[0].kind, 'unverified-effect', command)
    assert.ok(analysis.candidates[0].knownScope.length > 0, `${command}: candidate scope`)
    assert.deepEqual(analysis.operations, [], `${command}: batch mode emits no delete operation`)
  }
})

test('the transfer identity file produces no read fact of its own', async () => {
  // Second pass: `scp -i` / `sftp -i` authenticate with the key but do not read it
  // for disclosure, so the transfer itself yields no effective operation.
  for (const command of ['sftp -i id_rsa host', 'scp -i id_ed25519 host:/data ./data']) {
    const { analysis, decision } = await evaluate(command)
    assert.equal(decision.kind, 'allow', `${command}: expected allow, got ${decision.kind} ${decision.ruleId ?? ''}`)
    assert.deepEqual(analysis.candidates, [], command)
    assert.deepEqual((analysis.operations ?? []).filter((operation) => operation.preview !== true), [], command)
  }
  // The uploaded source keeps its read fact and stays reachable by the credential rule.
  const upload = await evaluate('scp -i id_ed25519 ./archive.tgz user@host:/backup/')
  assert.equal(upload.decision.kind, 'allow',
    `expected allow, got ${upload.decision.kind} ${upload.decision.ruleId ?? ''}`)
  assert.deepEqual(upload.analysis.candidates, [])
  assert.deepEqual((upload.analysis.operations ?? []).filter((operation) => operation.preview !== true)
    .map((operation) => operation.target), [{ kind: 'exact', paths: ['./archive.tgz'] }])
})
