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
  assertRead(run('scp', ['-i', 'id_ed25519', '-o', 'StrictHostKeyChecking=no', './a', 'host:/b']), './a')
  assertRead(run('scp', ['C:\\data\\a.txt', 'host:/b']), 'C:\\data\\a.txt')
  assertFree(run('scp', ['file', '.']))
  assertFree(run('scp', ['host:/a', '/b']))
  assertFree(run('scp', ['-', 'user@host:/b']))
  assertFree(run('scp', ['-r', './a']))
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
]

test('previews and read-only forms stay allow with no candidates and no effective operations', async () => {
  for (const command of ALLOW_SURFACE) await assertDecisionAllow(command)
})

const SCP_UPLOADS = [
  ['scp ./key user@host:/backup/key', ['./key']],
  ['scp -r ./dir host:/dst', ['./dir']],
  ['scp -P 2222 ./a ./b user@host:/dst/', ['./a', './b']],
  ['scp -i id_ed25519 -o StrictHostKeyChecking=no ./archive.tgz user@host:/backup/', ['./archive.tgz']],
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
