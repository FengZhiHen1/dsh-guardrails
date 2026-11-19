// commands-remote — cloud/database/K8s/container/IaC destructive command facts
// (adapter layer, one thin table per provider, all confirm-grade), plus the
// local-read facts of cloud-storage uploads (DSR-031 决定 5 / 决定 6).
//
// Interface (fixed by the team contract): `resolveRemoteCommand(name, args,
// options, env) => boolean`. commands.js calls this before its unmodeled-command
// gap; a `false` return lets the caller emit that gap and allow (D1/D3). Only an
// identified destructive subcommand with a non-empty literal resource scope
// produces an operation; read-only subcommands, previews (`--dryrun`/`--help`)
// and unknown forms produce nothing — no operation, no candidate. Scope text is
// the command's own resource range (bucket/URL/resource name/SQL object), never
// interpreted as a host path, so the evidence layer never probes it (D2).
//
// Cloud-storage uploads (`aws s3 cp|sync <local> s3://…`, `gsutil cp|rsync`,
// `gcloud storage cp`, `az storage blob upload --file`) and the transfer family
// (`scp <local> host:path`) instead produce a `read-content` fact for the literal
// local source, so the existing credential rule (`credential.file.read`) can see
// it. Downloads and server-side copies (`s3://` → `s3://`) produce nothing, and
// `-` (stdin) / dynamic operands never produce a fact.
//
// Backup / secret-source / platform deletion tools (gh, restic, borg, rclone,
// velero, vault, doppler, infisical) use the same remote-delete contract.

function emitRemoteDelete(provider, scope, options, env) {
  env.operation('delete', { kind: 'unknown', reason: 'remote-target', knownScope: [scope] }, {
    ...options, details: { remote: { provider, scope } },
  })
  return true
}

function emitRemoteRead(local, options, env) {
  env.operation('read-content', { kind: 'exact', paths: [local] }, { ...options })
  return true
}

/** Shared preview/help gate: a pure preview of the action produces nothing (D3). */
function isPreview(args) {
  return args.some((value) => typeof value === 'string' &&
    (value === '--dry-run' || value === '--dryrun' || value === '--help' ||
      value.startsWith('--dry-run=') || value.startsWith('--dryrun=')))
}

/** Literal value of `--flag value` / `--flag=value`; `undefined` when absent,
 * `null` when present with a non-literal value (DSR-032 决定 5/9 selectors). */
function flagValue(args, flag) {
  for (let index = 0; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string') continue
    if (value === flag) {
      const assigned = args[index + 1]
      return typeof assigned === 'string' ? assigned : null
    }
    if (value.startsWith(`${flag}=`)) {
      const assigned = value.slice(flag.length + 1)
      return assigned || null
    }
  }
  return undefined
}

const REMOTE_URL = /^[a-z0-9]+:\/\//iu

/**
 * Collect the positional operands of a `cp`/`sync`-style cloud command while
 * consuming the flags it knows. An unknown flag makes the operand set
 * ambiguous, so the command stays unmodeled (`null`, no fact, D1).
 */
function cloudOperands(args, start, { valueFlags, boolFlags }) {
  const operands = []
  for (let index = start; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string') return null
    if (value === '--') {
      for (let rest = index + 1; rest < args.length; rest++) {
        if (typeof args[rest] !== 'string') return null
        operands.push(args[rest])
      }
      return operands
    }
    if (value === '-' || !value.startsWith('-')) { operands.push(value); continue }
    const eq = value.indexOf('=')
    const flag = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
    if (eq >= 0) {
      if (valueFlags.has(flag) || boolFlags.has(flag)) continue
      return null
    }
    if (boolFlags.has(flag)) continue
    if (valueFlags.has(flag)) { index++; continue }
    return null
  }
  return operands
}

/**
 * `cp`/`sync`/`upload` direction rule: only a remote destination means this call
 * reads a local source. The last operand is the destination; every earlier
 * literal local source becomes a `read-content` fact. Returns true when at least
 * one fact was emitted.
 */
function emitCloudUpload(operands, scheme, options, env) {
  if (!Array.isArray(operands) || operands.length < 2) return false
  const destination = operands[operands.length - 1]
  if (typeof destination !== 'string' || !destination.toLowerCase().startsWith(scheme)) return false
  let emitted = false
  for (const source of operands.slice(0, -1)) {
    if (typeof source !== 'string') continue
    if (source === '-' || REMOTE_URL.test(source)) continue
    emitRemoteRead(source, options, env)
    emitted = true
  }
  return emitted
}

// --- aws -------------------------------------------------------------------

/**
 * aws destructive subcommands keyed by `<service> <subcommand>`. Each entry
 * names the selector flags whose values are the destroyed resource; the thin
 * table keeps every service on the same parse path.
 */
const AWS_DELETIONS = new Map([
  ['ec2 terminate-instances', { flags: ['--instance-ids', '--instance-id'], label: 'ec2 terminate-instances' }],
  ['ec2 delete-security-group', { flags: ['--group-id', '--group-name'], label: 'ec2 delete-security-group' }],
  ['ec2 delete-snapshot', { flags: ['--snapshot-ids', '--snapshot-id'], label: 'ec2 delete-snapshot' }],
  ['ec2 delete-volume', { flags: ['--volume-ids', '--volume-id'], label: 'ec2 delete-volume' }],
  ['ec2 deregister-image', { flags: ['--image-ids', '--image-id'], label: 'ec2 deregister-image' }],
  ['ec2 delete-vpc', { flags: ['--vpc-id'], label: 'ec2 delete-vpc' }],
  ['ec2 delete-key-pair', { flags: ['--key-name', '--key-pair-id'], label: 'ec2 delete-key-pair' }],
  ['iam delete-user', { flags: ['--user-name'], label: 'iam delete-user' }],
  ['iam delete-role', { flags: ['--role-name'], label: 'iam delete-role' }],
  ['iam delete-policy', { flags: ['--policy-arn'], label: 'iam delete-policy' }],
  ['iam delete-access-key', { flags: ['--access-key-id'], label: 'iam delete-access-key' }],
  ['s3api delete-bucket', { flags: ['--bucket'], label: 's3api delete-bucket' }],
  ['efs delete-file-system', { flags: ['--file-system-id'], label: 'efs delete-file-system' }],
  ['elasticache delete-cache-cluster', { flags: ['--cache-cluster-id'], label: 'elasticache delete-cache-cluster' }],
  ['secretsmanager delete-secret', { flags: ['--secret-id'], label: 'secretsmanager delete-secret' }],
  ['kms schedule-key-deletion', { flags: ['--key-id'], label: 'kms schedule-key-deletion' }],
  ['sqs delete-queue', { flags: ['--queue-url'], label: 'sqs delete-queue' }],
  ['sns delete-topic', { flags: ['--topic-arn'], label: 'sns delete-topic' }],
  ['logs delete-log-group', { flags: ['--log-group-name'], label: 'logs delete-log-group' }],
  ['cloudformation delete-stack', { flags: ['--stack-name'], label: 'cloudformation delete-stack' }],
  ['lambda delete-function', { flags: ['--function-name'], label: 'lambda delete-function' }],
  ['ecr delete-repository', { flags: ['--repository-name'], label: 'ecr delete-repository' }],
  ['route53 delete-hosted-zone', { flags: ['--id'], label: 'route53 delete-hosted-zone' }],
  ['rds delete-db-instance', { flags: ['--db-instance-identifier'], label: 'rds delete-db-instance' }],
  ['rds delete-db-cluster', { flags: ['--db-cluster-identifier'], label: 'rds delete-db-cluster' }],
  ['dynamodb delete-table', { flags: ['--table-name'], label: 'dynamodb delete-table' }],
  ['dynamodb delete-backup', { flags: ['--backup-arn'], label: 'dynamodb delete-backup' }],
  // DSR-032 决定 9: analytics / streaming / audit long tail (confirm grade).
  ['eks delete-cluster', { flags: ['--name'], label: 'eks delete-cluster' }],
  ['glue delete-database', { flags: ['--name'], label: 'glue delete-database' }],
  ['glue delete-table', { flags: ['--name'], label: 'glue delete-table' }],
  ['glue delete-partition', { flags: ['--partition-values'], label: 'glue delete-partition' }],
  ['glue delete-crawler', { flags: ['--name'], label: 'glue delete-crawler' }],
  ['glue delete-job', { flags: ['--job-name'], label: 'glue delete-job' }],
  ['redshift delete-cluster', { flags: ['--cluster-identifier'], label: 'redshift delete-cluster' }],
  ['kinesis delete-stream', { flags: ['--stream-name'], label: 'kinesis delete-stream' }],
  ['cloudtrail delete-trail', { flags: ['--name'], label: 'cloudtrail delete-trail' }],
  ['ecr batch-delete-image', { flags: ['--repository-name'], label: 'ecr batch-delete-image' }],
  // DSR-032 second pass: batch analytics/log deletion.
  ['glue batch-delete-table', { flags: ['--tables-to-delete'], label: 'glue batch-delete-table' }],
  ['glue batch-delete-partition',
    { flags: ['--partitions-to-delete'], label: 'glue batch-delete-partition' }],
  ['logs delete-log-stream', { flags: ['--log-stream-name'], label: 'logs delete-log-stream' }],
  ['athena delete-data-catalog', { flags: ['--name'], label: 'athena delete-data-catalog' }],
])

/** s3 `cp`/`sync` flags: known booleans and value-taking options. */
const AWS_S3_BOOL_FLAGS = new Set(['--recursive', '-r', '--quiet', '--no-progress', '--only-show-errors',
  '--delete', '--follow-symlinks', '--no-follow-symlinks', '--exact-timestamps', '--no-guess-mime-type',
  '--size-only', '--ignore-glacier-warnings', '--force-glacier-transfer', '--no-follow-symlinks'])
const AWS_S3_VALUE_FLAGS = new Set(['--acl', '--storage-class', '--sse', '--sse-kms-key-id', '--sse-c',
  '--sse-c-key', '--content-type', '--content-encoding', '--content-language', '--content-disposition',
  '--cache-control', '--expires', '--metadata', '--metadata-directive', '--website-redirect', '--exclude',
  '--include', '--profile', '--region', '--endpoint-url', '--expected-size', '--page-size',
  '--cli-read-timeout', '--cli-connect-timeout', '--source-region', '--checksum-algorithm',
  '--checksum-mode', '--ca-bundle', '--output', '--query', '--version-id', '--request-payer'])

/** Skip known provider-level options that may precede the service/subcommand.
 * Returns the index of the first token that is not a skipped global option, or
 * `null` when an unknown global option is present (the line stays a gap). */
function skipGlobalFlags(args, valueFlags, boolFlags) {
  let index = 0
  while (index < args.length) {
    const value = args[index]
    if (typeof value !== 'string') return null
    if (!value.startsWith('-') || value === '-') break
    const eq = value.indexOf('=')
    const flag = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
    if (boolFlags.has(flag)) { index++; continue }
    if (valueFlags.has(flag)) { index += eq < 0 ? 2 : 1; continue }
    return null
  }
  return index
}

const AWS_GLOBAL_VALUE_FLAGS = new Set(['--profile', '--region', '--output', '--endpoint-url', '--query',
  '--cli-read-timeout', '--cli-connect-timeout'])
const AWS_GLOBAL_BOOL_FLAGS = new Set(['--debug', '--no-paginate', '--no-verify-ssl', '--no-sign-request'])

/**
 * The destroyed-resource selector. `--flag value`, `--flag=value` and a bare
 * operand all select; a selector option with a dynamic value is still deletion
 * intent (`selection not literal`), while a call with no selector at all is a
 * usage error and produces nothing (DSR-031 決定 5).
 */
function awsDeleteEntry(entry, args) {
  let index = -1
  for (const flag of entry.flags) {
    index = args.findIndex((value) => typeof value === 'string' &&
      (value.toLowerCase() === flag || value.toLowerCase().startsWith(`${flag}=`)))
    if (index >= 0) break
  }
  const positionals = args.filter((value) => typeof value === 'string' && !value.startsWith('-'))
  if (index < 0) {
    if (positionals.length) return `${entry.label} ${positionals.join(' ')}`
    if (args.some((value) => value === null)) return `${entry.label} (selection not literal)`
    return null
  }
  const token = args[index]
  const eq = token.indexOf('=')
  if (eq >= 0) {
    const inline = token.slice(eq + 1)
    return inline ? `${entry.label} ${inline}` : `${entry.label} (selection not literal)`
  }
  const values = []
  for (let i = index + 1; i < args.length; i++) {
    const value = args[i]
    if (typeof value !== 'string') return `${entry.label} (selection not literal)`
    if (value.startsWith('-')) break
    values.push(value)
  }
  return values.length ? `${entry.label} ${values.join(' ')}` : `${entry.label} (selection not literal)`
}

function awsCommand(args, options, env) {
  if (isPreview(args)) return false
  const start = skipGlobalFlags(args, AWS_GLOBAL_VALUE_FLAGS, AWS_GLOBAL_BOOL_FLAGS)
  if (start === null) return false
  const rest = args.slice(start)
  const service = typeof rest[0] === 'string' ? rest[0].toLowerCase() : ''
  const sub = typeof rest[1] === 'string' ? rest[1].toLowerCase() : ''
  if (service === 's3') {
    const tail = rest.slice(2)
    if (sub === 'cp' || sub === 'sync') {
      const operands = cloudOperands(tail, 0, { valueFlags: AWS_S3_VALUE_FLAGS, boolFlags: AWS_S3_BOOL_FLAGS })
      let emitted = emitCloudUpload(operands, 's3://', options, env)
      // DSR-032 决定 9: `aws s3 sync --delete <local> s3://…` mirrors deletions
      // onto the remote destination. A local destination is left to the local
      // deletion surface, so it produces nothing here.
      if (sub === 'sync' && tail.some((value) => value === '--delete') && Array.isArray(operands) && operands.length) {
        const destination = operands[operands.length - 1]
        if (typeof destination === 'string' && destination.toLowerCase().startsWith('s3://')) {
          emitRemoteDelete('aws', `s3 sync --delete ${destination} (remote mirror)`, options, env)
          emitted = true
        }
      }
      return emitted
    }
    if (sub !== 'rm' && sub !== 'rb') return false
    const targets = tail.filter((value) => typeof value === 'string' && /^s3:\/\//iu.test(value))
    if (!targets.length) {
      if (tail.some((value) => value === null)) {
        return emitRemoteDelete('aws', `s3 ${sub} (selection not literal)`, options, env)
      }
      return false
    }
    if (sub === 'rb') {
      return emitRemoteDelete('aws', targets.map((url) => `${url} (bucket)`).join(' '), options, env)
    }
    const recursive = tail.includes('--recursive')
    const scope = recursive ? targets.map((url) => `${url}/** (recursive)`).join(' ') : targets.join(' ')
    return emitRemoteDelete('aws', scope, options, env)
  }
  // DSR-032 决定 9: object deletion names bucket and key literally. `--delete`
  // carries the key list JSON (the scope stays the addressed bucket); a call
  // without the selector is a usage error and stays free.
  if (service === 's3api' && (sub === 'delete-object' || sub === 'delete-objects')) {
    const tail = rest.slice(2)
    const bucket = flagValue(tail, '--bucket')
    if (sub === 'delete-object') {
      const key = flagValue(tail, '--key')
      if (typeof bucket === 'string' && typeof key === 'string') {
        return emitRemoteDelete('aws', `s3api delete-object ${bucket}/${key}`, options, env)
      }
      if (bucket === null || key === null) {
        return emitRemoteDelete('aws', 's3api delete-object (selection not literal)', options, env)
      }
      return false
    }
    if (typeof bucket === 'string') {
      if (flagValue(tail, '--delete') === undefined) return false
      return emitRemoteDelete('aws', `s3api delete-objects ${bucket}`, options, env)
    }
    if (bucket === null) return emitRemoteDelete('aws', 's3api delete-objects (selection not literal)', options, env)
    return false
  }
  // DSR-032 决定 9: an Athena query string is destructive only when its literal
  // text is DROP/TRUNCATE/DELETE without WHERE; anything else stays a gap.
  if (service === 'athena' && sub === 'start-query-execution') {
    const query = flagValue(rest.slice(2), '--query-string')
    if (typeof query !== 'string') return false
    const scopes = sqlDestructiveScopes([query])
    if (!scopes.length) return false
    for (const scope of scopes) {
      emitRemoteDelete('aws', `athena: ${scope.startsWith('SQL: ') ? scope.slice(5) : scope}`, options, env)
    }
    return true
  }
  const entry = AWS_DELETIONS.get(`${service} ${sub}`)
  if (!entry) return false
  const scope = awsDeleteEntry(entry, rest.slice(2))
  if (scope === null) return false
  return emitRemoteDelete('aws', scope, options, env)
}

// --- gcp -------------------------------------------------------------------

/**
 * gcloud subcommands modeled here (2- or 3-token keys). Every entry is a
 * deletion or an irreversible resource change (KMS destroy).
 */
const GCLOUD_DELETIONS = new Set([
  'compute instances delete',
  'compute disks delete',
  'compute snapshots delete',
  'compute firewall-rules delete',
  'compute networks delete',
  'compute instance-templates delete',
  'compute images delete',
  'compute addresses delete',
  'sql instances delete',
  'container clusters delete',
  'storage buckets delete',
  'secrets delete',
  'iam service-accounts delete',
  'projects delete',
  'functions delete',
  'run services delete',
  'pubsub topics delete',
  'kms keys destroy',
  'logging sinks delete',
  'deployment-manager deployments delete',
  'bigquery datasets delete',
  'bigquery tables delete',
  'dataproc clusters delete',
  'spanner instances delete',
  'redis instances delete',
  // DSR-032 second pass: storage/Artifact Registry/IAM/DNS/Bigtable long tail.
  'storage rm',
  'storage objects delete',
  'firestore databases delete',
  'artifacts docker images delete',
  'artifacts repositories delete',
  'iam roles delete',
  'dns managed-zones delete',
  'bigtable instances delete',
])
/** gcloud flags that take a value and may precede the resource name. */
const GCLOUD_VALUE_FLAGS = new Set(['--zone', '--region', '--location', '--project', '--configuration',
  '--format', '--filter', '--limit', '--page-size', '--sort-by', '--impersonate-service-account',
  '--account', '--billing-project', '--verbosity', '--content-type', '--cache-control', '--storage-class',
  '--encryption-key', '--decryption-key', '--continue-on-error', '--perf-trace-token', '--trace-token'])
const GCLOUD_BOOLEAN_FLAGS = new Set(['--quiet', '--no-quiet', '--async', '--recursive', '-r', '--all',
  '--no-clobber', '--preserve-acl', '--all-versions', '--gzip-in-flight', '--no-gzip-in-flight',
  '--delete-tags', '--delete-unmatched-destination-objects'])

function gcloudDeletionKey(args) {
  for (const length of [4, 3, 2]) {
    if (args.length < length) continue
    const key = args.slice(0, length)
      .map((value) => typeof value === 'string' ? value.toLowerCase() : '')
      .join(' ')
      .trim()
    if (GCLOUD_DELETIONS.has(key)) return { key, length }
  }
  return null
}

const GCLOUD_GLOBAL_VALUE_FLAGS = new Set(['--project', '--account', '--configuration', '--format',
  '--verbosity', '--flags-file'])
const GCLOUD_GLOBAL_BOOL_FLAGS = new Set(['--quiet', '-q'])

function gcloudCommand(args, options, env) {
  if (isPreview(args)) return false
  const start = skipGlobalFlags(args, GCLOUD_GLOBAL_VALUE_FLAGS, GCLOUD_GLOBAL_BOOL_FLAGS)
  if (start === null) return false
  const rest = args.slice(start)
  const first = typeof rest[0] === 'string' ? rest[0].toLowerCase() : ''
  const second = typeof rest[1] === 'string' ? rest[1].toLowerCase() : ''
  if (first === 'storage' && (second === 'cp' || second === 'rsync')) {
    const operands = cloudOperands(rest, 2, { valueFlags: GCLOUD_VALUE_FLAGS, boolFlags: GCLOUD_BOOLEAN_FLAGS })
    return emitCloudUpload(operands, 'gs://', options, env)
  }
  const match = gcloudDeletionKey(rest)
  if (!match) return false
  const names = []
  for (let index = match.length; index < rest.length; index++) {
    const value = rest[index]
    if (typeof value !== 'string') return false
    if (!value.startsWith('-')) { names.push(value); continue }
    const lower = value.toLowerCase()
    if (lower.includes('=')) continue
    if (GCLOUD_VALUE_FLAGS.has(lower)) { index++; continue }
    if (GCLOUD_BOOLEAN_FLAGS.has(lower)) continue
    return false
  }
  if (!names.length) return false
  return emitRemoteDelete('gcp', names.join(' '), options, env)
}

const GSUTIL_GLOBAL_BOOL_FLAGS = new Set(['-m', '-q', '-D', '-DD', '--version', '--help', '-n'])
const GSUTIL_GLOBAL_VALUE_FLAGS = new Set(['-u', '-p', '-o', '-h', '-a', '-i', '-s', '--project',
  '--user-project', '--acl', '--storage-class', '--content-type', '--cache-control', '--metadata',
  '--content-encoding', '--checksum', '--encryption-key', '--decryption-key', '--perf-trace-token',
  '--trace-token'])
const GSUTIL_BOOL_FLAGS = new Set(['-r', '-R', '--recursive', '-m', '-q', '-D', '--json', '-e'])
const GSUTIL_VALUE_FLAGS = new Set(['-a', '-h', '-s', '-o', '-u', '-i', '-p', '--project', '--acl',
  '--storage-class', '--content-type', '--cache-control', '--metadata', '--content-encoding', '--checksum',
  '--encryption-key', '--decryption-key', '--perf-trace-token', '--trace-token', '--user-project'])

/** `gsutil [global options] <command> …` — global options may precede the verb
 * (see the documented `-m`/`-q`/`-D`/`-u`/`-p`/`-o`/`-h`/`-a`/`-i`/`-s` forms,
 * attached or separated). An unknown option keeps the line a gap. */
function gsutilSubcommand(args) {
  let index = 0
  while (index < args.length) {
    const value = args[index]
    if (typeof value !== 'string') return null
    if (!value.startsWith('-') || value === '-') break
    if (GSUTIL_GLOBAL_BOOL_FLAGS.has(value)) { index++; continue }
    if (GSUTIL_GLOBAL_VALUE_FLAGS.has(value)) { index += 2; continue }
    const eq = value.indexOf('=')
    if (eq >= 0 && GSUTIL_GLOBAL_VALUE_FLAGS.has(value.slice(0, eq))) { index++; continue }
    if (value.length > 2 && GSUTIL_GLOBAL_VALUE_FLAGS.has(value.slice(0, 2))) { index++; continue }
    return null
  }
  if (index >= args.length) return null
  return { sub: args[index].toLowerCase(), index }
}

function gsutilCommand(args, options, env) {
  if (isPreview(args)) return false
  const parsed = gsutilSubcommand(args)
  if (!parsed) return false
  // `gsutil -n` is its dry-run switch; it must appear before the verb.
  if (args.slice(0, parsed.index).includes('-n')) return false
  const { sub, index } = parsed
  if (sub === 'help' || sub === 'version') return false
  const tail = args.slice(index + 1)
  if (sub === 'cp' || sub === 'rsync') {
    const operands = cloudOperands(tail, 0, { valueFlags: GSUTIL_VALUE_FLAGS, boolFlags: GSUTIL_BOOL_FLAGS })
    return emitCloudUpload(operands, 'gs://', options, env)
  }
  if (sub !== 'rm' && sub !== 'rb') return false
  const targets = tail.filter((value) => typeof value === 'string' && /^gs:\/\//iu.test(value))
  if (!targets.length) {
    if (tail.some((value) => value === null)) {
      return emitRemoteDelete('gcp', `gsutil ${sub} (selection not literal)`, options, env)
    }
    return false
  }
  if (sub === 'rb') {
    return emitRemoteDelete('gcp', targets.map((url) => `${url} (bucket)`).join(' '), options, env)
  }
  const recursive = tail.some((value) => value === '-r' || value === '-R' || value === '--recursive')
  const scope = targets.map((url) => recursive ? `${url}/** (recursive)` : url).join(' ')
  return emitRemoteDelete('gcp', scope, options, env)
}

// --- azure -----------------------------------------------------------------

function azRoles(extra = {}) {
  return {
    '-g': 'group', '--resource-group': 'group', '--resource-group-name': 'group',
    '-n': 'name', '--name': 'name',
    ...extra,
  }
}

const AZ_DELETIONS = new Map([
  ['vm delete', azRoles()],
  ['group delete', azRoles()],
  ['sql db delete', azRoles({ '-s': 'server', '--server': 'server' })],
  ['storage account delete', azRoles()],
  ['keyvault delete', azRoles()],
  ['keyvault purge', azRoles({ '--location': 'location' })],
  ['keyvault key delete', azRoles({ '--vault-name': 'vault' })],
  ['keyvault secret delete', azRoles({ '--vault-name': 'vault' })],
  ['webapp delete', azRoles()],
  ['functionapp delete', azRoles()],
  ['aks delete', azRoles()],
  ['network nsg delete', azRoles()],
  ['network vnet delete', azRoles()],
  ['disk delete', azRoles()],
  ['snapshot delete', azRoles()],
  ['acr delete', azRoles()],
  ['acr repository delete', azRoles({ '--registry': 'registry', '--repository': 'repository',
    '--image': 'image' })],
  ['cosmosdb delete', azRoles()],
  ['redis delete', azRoles()],
  ['identity delete', azRoles()],
  ['ad app delete', azRoles({ '--id': 'id' })],
  ['ad sp delete', azRoles({ '--id': 'id' })],
  ['account subscription cancel', azRoles({ '--id': 'id' })],
  ['account management-group delete', azRoles({ '--id': 'id' })],
  ['role assignment delete', azRoles({ '--assignee': 'assignee', '--assignee-object-id': 'assignee',
    '--role': 'role', '--scope': 'scope', '--ids': 'ids' })],
  ['storage container delete', azRoles({ '--account-name': 'account' })],
  ['storage blob delete', azRoles({ '--account-name': 'account', '--container-name': 'container' })],
  ['storage blob delete-batch', azRoles({ '--account-name': 'account', '--source': 'source',
    '--pattern': 'pattern' })],
])
const AZ_BOOLEAN_FLAGS = new Set(['-y', '--yes', '--no-wait', '--force', '--verbose', '--debug',
  '--only-show-errors', '--include-inherited', '--overwrite', '--recursive', '--delete-snapshots'])
const AZ_ROLE_ORDER = ['group', 'server', 'vault', 'account', 'container', 'registry', 'repository',
  'image', 'source', 'pattern', 'id', 'location', 'assignee', 'role', 'scope', 'ids']
const AZ_ROLE_LABELS = {
  group: 'resource group', server: 'server', vault: 'vault', account: 'account',
  container: 'container', registry: 'registry', repository: 'repository', image: 'image',
  source: 'source', pattern: 'pattern', id: 'id', location: 'location',
  assignee: 'assignee', role: 'role', scope: 'scope', ids: 'ids',
}

function azScope(key, name, qualifiers, dynamic) {
  const parts = []
  if (name.length) parts.push(name.join(' '))
  for (const role of AZ_ROLE_ORDER) {
    const values = qualifiers.get(role)
    if (values && values.length) parts.push(`(${AZ_ROLE_LABELS[role]} ${values.join(' ')})`)
  }
  if (parts.length) return parts.join(' ')
  return dynamic ? `${key} (selection not literal)` : `${key} (resource name not literal)`
}

/** `az storage blob upload --file <local>` reads its local source (DSR-031 6). */
function azUpload(args, options, env) {
  if (isPreview(args)) return false
  let local
  for (let index = 0; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string' || !value.startsWith('-')) continue
    const eq = value.indexOf('=')
    const flag = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
    if (flag !== '-f' && flag !== '--file') continue
    const assigned = eq < 0 ? args[++index] : value.slice(eq + 1)
    if (typeof assigned === 'string') local = assigned
  }
  if (typeof local !== 'string' || local === '-' || REMOTE_URL.test(local)) return false
  return emitRemoteRead(local, options, env)
}

function azCommand(args, options, env) {
  const tokens = args.slice(0, 4).map((value) => typeof value === 'string' ? value.toLowerCase() : '')
  if (tokens[0] === 'storage' && tokens[1] === 'blob' && tokens[2] === 'upload') {
    return azUpload(args.slice(3), options, env)
  }
  if (isPreview(args)) return false
  // Subcommands are `service [noun…] delete`; the longest literal key wins, so
  // `account management-group delete` is not folded into `group delete`.
  let key
  let roles
  let start = 0
  for (const length of [4, 3, 2]) {
    if (args.length < length) continue
    const slice = args.slice(0, length)
    if (!slice.every((value) => typeof value === 'string')) continue
    const candidate = slice.join(' ').toLowerCase()
    const found = AZ_DELETIONS.get(candidate)
    if (!found) continue
    key = candidate
    roles = found
    start = length
    break
  }
  if (!roles) return false
  const name = []
  const qualifiers = new Map()
  let dynamic = false
  for (let index = start; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string') { dynamic = true; continue }
    if (!value.startsWith('-')) { name.push(value); continue }
    const eq = value.indexOf('=')
    const flag = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
    const role = Object.hasOwn(roles, flag) ? roles[flag] : undefined
    if (role) {
      const assigned = eq < 0 ? args[++index] : value.slice(eq + 1)
      if (typeof assigned !== 'string') { dynamic = true; continue }
      if (role === 'name') name.push(assigned)
      else {
        if (!qualifiers.has(role)) qualifiers.set(role, [])
        qualifiers.get(role).push(assigned)
      }
      continue
    }
    if (eq >= 0) continue
    if (AZ_BOOLEAN_FLAGS.has(flag)) continue
    return false
  }
  // A bare `az … delete` with no selector is a usage error, not a deletion.
  if (!name.length && !qualifiers.size && !dynamic) return false
  return emitRemoteDelete('azure', azScope(key, name, qualifiers, dynamic), options, env)
}

// --- SQL shells ------------------------------------------------------------

const SQL_PROGRAMS = new Map([['psql', 'postgres'], ['mysql', 'mysql'], ['sqlite3', 'sqlite']])

/**
 * Irreversible SQL statements: `DROP <object>` for every schema-level object a
 * shell client can name (table/database/schema plus warehouse/user/role/stage/
 * function/… for warehouse dialects such as Snowflake), `TRUNCATE`, and
 * `DELETE` without a WHERE clause (DSR-032 second pass). Multiword object kinds
 * come first so `DROP MATERIALIZED VIEW` is not read as `DROP MATERIAL`.
 */
const SQL_DESTRUCTIVE_DDL =
  /^drop\s+(?:materialized\s+view|dynamic\s+table|external\s+table|network\s+policy|table|database|schema|warehouse|user|role|view|sequence|stage|function|procedure|policy|share|stream|task|pipe|integration|format)\b/iu

function sqlDestructiveScopes(statements) {
  const scopes = []
  for (const text of statements) {
    for (const raw of text.split(';')) {
      const sql = raw.trim()
      if (!sql) continue
      if (SQL_DESTRUCTIVE_DDL.test(sql) || /^truncate(?:\s+table)?\s+\S/iu.test(sql)) {
        scopes.push(`SQL: ${sql}`)
        continue
      }
      // DELETE is destructive only without a WHERE clause (row-scoped deletes stay free).
      const del = /^delete\s+from\s+(\S+)\s*([\s\S]*)$/iu.exec(sql)
      if (del && !/\bwhere\b/iu.test(del[2])) scopes.push(`SQL: ${sql}`)
    }
  }
  return scopes
}

function sqlCommand(name, provider) {
  return (args, options, env) => {
    if (isPreview(args)) return false
    const statements = []
    if (name === 'sqlite3') {
      // Positional operands after the database file are executed as SQL.
      const positionals = args.filter((value) => typeof value === 'string' && !value.startsWith('-'))
      statements.push(...positionals.slice(1))
    } else {
      const evalFlags = name === 'psql' ? ['-c', '--command'] : ['-e', '--execute']
      for (let index = 0; index < args.length; index++) {
        const value = args[index]
        if (typeof value !== 'string' || !value.startsWith('-')) continue
        const eq = value.indexOf('=')
        const flag = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
        if (!evalFlags.includes(flag)) continue
        const sql = eq < 0 ? args[++index] : value.slice(eq + 1)
        if (typeof sql === 'string') statements.push(sql)
      }
    }
    const scopes = sqlDestructiveScopes(statements)
    if (!scopes.length) return false
    for (const scope of scopes) emitRemoteDelete(provider, scope, options, env)
    return true
  }
}

// --- document / key-value database clients ---------------------------------

const MONGO_VALUE_FLAGS = new Set(['--eval', '-e', '--file', '--host', '--port', '--username', '-u',
  '--password', '-p', '--authenticationDatabase', '--authenticationMechanism', '--tlsCAFile',
  '--tlsCertificateKeyFile', '--tlsCertificateKeyFilePassword', '--quiet', '--norc', '--nodb', '--shell'])

function mongoDestructiveScopes(scripts) {
  const scopes = []
  for (const raw of scripts) {
    for (const part of String(raw).split(';')) {
      const stmt = part.trim()
      if (!stmt) continue
      if (/db\s*\.\s*dropDatabase\s*\(\s*\)/u.test(stmt) ||
        /db\s*\.\s*[A-Za-z_$][\w$]*\s*\.\s*drop\s*\(\s*\)/u.test(stmt) ||
        /db\s*\.\s*[A-Za-z_$][\w$]*\s*\.\s*(?:deleteMany|remove)\s*\(\s*(?:\{\s*\})?\s*\)/u.test(stmt)) {
        scopes.push(`mongo: ${stmt}`)
      }
    }
  }
  return scopes
}

function mongoCommand(args, options, env) {
  if (isPreview(args)) return false
  const scripts = []
  for (let index = 0; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string' || !value.startsWith('-')) continue
    const eq = value.indexOf('=')
    const flag = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
    if (flag !== '--eval' && flag !== '-e') continue
    const assigned = eq < 0 ? args[++index] : value.slice(eq + 1)
    if (typeof assigned === 'string') scripts.push(assigned)
  }
  const scopes = mongoDestructiveScopes(scripts)
  if (!scopes.length) return false
  for (const scope of scopes) emitRemoteDelete('mongo', scope, options, env)
  return true
}

const REDIS_BOOL_FLAGS = new Set(['-c', '--cluster', '--raw', '--no-raw', '--tls', '--insecure',
  '--no-auth-warning', '--scan', '--stat', '--bigkeys', '--memkeys', '--latency', '--lru-test'])
const REDIS_VALUE_FLAGS = new Set(['-h', '--host', '-p', '--port', '-s', '--socket', '-n', '--db',
  '-a', '--pass', '--user', '-u', '--uri', '-r', '--repeat', '-i', '--interval', '-t', '--timeout',
  '--tls-ca-cert', '--tls-ca-cert-dir', '--tls-cert', '--tls-key', '--sni', '--cacert', '--cert',
  '--key', '--pattern', '--count'])

function redisCommand(args, options, env) {
  if (isPreview(args)) return false
  let command
  let commandIndex = -1
  for (let index = 0; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string') return false
    if (value.startsWith('-')) {
      const eq = value.indexOf('=')
      const flag = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
      if (eq >= 0) continue
      if (REDIS_VALUE_FLAGS.has(flag)) { index++; continue }
      if (REDIS_BOOL_FLAGS.has(flag)) continue
      return false
    }
    command = value
    commandIndex = index
    break
  }
  if (typeof command !== 'string') return false
  const upper = command.toUpperCase()
  if (upper !== 'FLUSHALL' && upper !== 'FLUSHDB') {
    // `SHUTDOWN NOSAVE` exits without writing the RDB or the AOF: data since the
    // last save is lost. A plain `SHUTDOWN` saves first and stays free
    // (DSR-032 second pass).
    if (upper !== 'SHUTDOWN') return false
    const nosave = args.slice(commandIndex + 1).some((value) =>
      typeof value === 'string' && value.toLowerCase() === 'nosave')
    if (!nosave) return false
    return emitRemoteDelete('redis', 'redis: SHUTDOWN NOSAVE', options, env)
  }
  return emitRemoteDelete('redis', `redis: ${upper}`, options, env)
}

const MYSQLADMIN_VALUE_FLAGS = new Set(['-u', '--user', '-h', '--host', '-P', '--port', '-S', '--socket',
  '-i', '--sleep', '--protocol', '--default-character-set', '--connect-timeout', '--shutdown-timeout'])
const MYSQLADMIN_BOOL_FLAGS = new Set(['-p', '--password', '-w', '--wait', '-f', '--force', '-v',
  '--verbose', '--silent', '-s', '--relative', '-r', '--count', '-c'])

function mysqladminCommand(args, options, env) {
  if (isPreview(args)) return false
  const operands = []
  for (let index = 0; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string') return false
    if (!value.startsWith('-')) { operands.push(value); continue }
    const eq = value.indexOf('=')
    const flag = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
    if (eq >= 0) continue
    if (MYSQLADMIN_VALUE_FLAGS.has(flag)) { index++; continue }
    if (MYSQLADMIN_BOOL_FLAGS.has(flag)) continue
    return false
  }
  const command = operands[0]?.toLowerCase()
  if (command !== 'drop') return false
  const database = operands.slice(1).join(' ')
  if (!database) return false
  return emitRemoteDelete('mysql', `mysql: drop ${database}`, options, env)
}

const DROPDB_BOOL_FLAGS = new Set(['-w', '--no-password', '-e', '--echo', '-i', '--interactive',
  '--if-exists', '--force', '-V', '--version', '--help'])
const DROPDB_VALUE_FLAGS = new Set(['-h', '--host', '-p', '--port', '-U', '--username', '--maintenance-db',
  '--encoding', '--lc-collate', '--lc-ctype', '--template', '--owner', '-O', '--tablespace',
  '--connection-limit'])

function dropdbCommand(args, options, env) {
  if (isPreview(args)) return false
  const operands = []
  for (let index = 0; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string') return false
    if (!value.startsWith('-')) { operands.push(value); continue }
    const eq = value.indexOf('=')
    const flag = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
    if (eq >= 0) continue
    if (DROPDB_VALUE_FLAGS.has(flag)) { index++; continue }
    if (DROPDB_BOOL_FLAGS.has(flag)) continue
    return false
  }
  if (!operands.length) return false
  return emitRemoteDelete('postgres', `postgres: dropdb ${operands.join(' ')}`, options, env)
}

function clickhouseCommand(args, options, env) {
  if (isPreview(args)) return false
  let query
  for (let index = 0; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string') continue
    const eq = value.indexOf('=')
    const flag = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
    if (flag !== '-q' && flag !== '--query') continue
    const assigned = eq < 0 ? args[++index] : value.slice(eq + 1)
    if (typeof assigned === 'string') query = assigned
  }
  if (typeof query !== 'string') return false
  if (!/^\s*(?:drop|truncate)\b/iu.test(query)) return false
  return emitRemoteDelete('clickhouse', `clickhouse: ${query.trim()}`, options, env)
}

// --- kubernetes ------------------------------------------------------------

const KUBECTL_GLOBAL_VALUE_FLAGS = new Set(['-n', '--namespace', '--context', '--cluster', '--user',
  '--kubeconfig', '-s', '--server', '--request-timeout', '--profile', '--v'])
const KUBECTL_SUB_VALUE_FLAGS = new Set(['-n', '--namespace', '--context', '--cluster', '--user',
  '--kubeconfig', '-s', '--server', '-l', '--selector', '--field-selector', '-o', '--output',
  '--grace-period', '--timeout', '--wait', '--v'])
const KUBECTL_SUB_BOOLEAN_FLAGS = new Set(['-a', '--all', '--all-namespaces', '--force', '--now', '--ignore-not-found',
  '--cascade', '--recursive', '--raw', '--wait', '--openapi-patch', '--server-side', '--flush-backoff'])

function kubectlDelete(rest, options, env) {
  const names = []
  const files = []
  let all = false
  let allNamespaces = false
  for (let i = 0; i < rest.length; i++) {
    const value = rest[i]
    if (typeof value !== 'string') return false
    if (value === '--') {
      names.push(...rest.slice(i + 1).filter((item) => typeof item === 'string' && !item.startsWith('-')))
      break
    }
    if (!value.startsWith('-')) { names.push(value); continue }
    const lower = value.toLowerCase()
    if (lower === '--dry-run' || lower.startsWith('--dry-run=')) return false
    if (lower === '-f' || lower === '--filename' || lower.startsWith('--filename=')) {
      const file = lower.startsWith('--filename=') ? value.slice('--filename='.length) : rest[++i]
      if (typeof file !== 'string') return false
      files.push(file)
      continue
    }
    // `-A` is `--all-namespaces` and must be read before the lowercase `-a`
    // alias below would fold it into plain `--all` (DSR-032 决定 9).
    if (lower === '--all-namespaces' || value === '-A') { allNamespaces = true; continue }
    if (lower === '--all' || lower === '-a') { all = true; continue }
    if (lower.includes('=')) continue
    if (KUBECTL_SUB_VALUE_FLAGS.has(lower)) { i++; continue }
    if (KUBECTL_SUB_BOOLEAN_FLAGS.has(lower)) continue
    return false
  }
  if (!names.length && !files.length && !all && !allNamespaces) return false
  const scope = [names.join(' '), files.join(' '), all && '--all', allNamespaces && '--all-namespaces']
    .filter(Boolean).join(' ').trim()
  return emitRemoteDelete('k8s', scope || 'cluster resources (delete)', options, env)
}

const KUBECTL_APPLY_VALUE_FLAGS = new Set([...KUBECTL_SUB_VALUE_FLAGS, '-k', '--kustomize',
  '--prune-allowlist', '--prune-whitelist', '--field-manager', '--cache-dir', '--template', '--validate'])
const KUBECTL_APPLY_BOOLEAN_FLAGS = new Set([...KUBECTL_SUB_BOOLEAN_FLAGS, '--prune', '--server-dry-run',
  '--dry-run', '--openapi-patch', '--force-conflicts'])

/** `kubectl apply --prune` deletes the previously applied objects that are absent
 * from the new manifest set, and `kubectl apply --force` deletes and recreates
 * every object it updates (delete-recreate). Both are deletion facts whose scope
 * states the flag and the manifest target; `--dry-run` stays a preview
 * (DSR-032 决定 9 and the second pass). */
function kubectlApply(rest, options, env) {
  let prune = false
  let force = false
  const files = []
  for (let i = 0; i < rest.length; i++) {
    const value = rest[i]
    if (typeof value !== 'string') return false
    if (!value.startsWith('-')) continue
    const lower = value.toLowerCase()
    if (lower === '--dry-run' || lower.startsWith('--dry-run=') ||
      lower === '--server-dry-run' || lower.startsWith('--server-dry-run=')) return false
    if (lower === '--prune' || lower === '--prune=true') { prune = true; continue }
    if (lower === '--force' || lower === '--force=true') { force = true; continue }
    if (lower === '-f' || lower === '--filename' || lower.startsWith('--filename=')) {
      const file = lower.startsWith('--filename=') ? value.slice('--filename='.length) : rest[++i]
      if (typeof file !== 'string') return false
      files.push(file)
      continue
    }
    if (lower === '-k' || lower === '--kustomize' || lower.startsWith('--kustomize=')) {
      const dir = lower.startsWith('--kustomize=') ? value.slice('--kustomize='.length) : rest[++i]
      if (typeof dir !== 'string') return false
      files.push(dir)
      continue
    }
    if (lower.includes('=')) continue
    if (KUBECTL_APPLY_VALUE_FLAGS.has(lower)) { i++; continue }
    if (KUBECTL_APPLY_BOOLEAN_FLAGS.has(lower)) continue
    return false
  }
  if ((!prune && !force) || !files.length) return false
  const marker = [prune && '--prune', force && '--force'].filter(Boolean).join(' ')
  return emitRemoteDelete('k8s', `apply ${marker} ${files.join(' ')}`, options, env)
}

/** `kubectl replace --force -f <file>` deletes and recreates the manifest objects. */
function kubectlReplace(rest, options, env) {
  let force = false
  const files = []
  for (let i = 0; i < rest.length; i++) {
    const value = rest[i]
    if (typeof value !== 'string') return false
    if (!value.startsWith('-')) continue
    const lower = value.toLowerCase()
    if (lower === '--dry-run' || lower.startsWith('--dry-run=')) return false
    if (lower === '--force') { force = true; continue }
    if (lower === '-f' || lower === '--filename' || lower.startsWith('--filename=')) {
      const file = lower.startsWith('--filename=') ? value.slice('--filename='.length) : rest[++i]
      if (typeof file !== 'string') return false
      files.push(file)
      continue
    }
    if (lower.includes('=')) continue
    if (KUBECTL_SUB_VALUE_FLAGS.has(lower)) { i++; continue }
    if (KUBECTL_SUB_BOOLEAN_FLAGS.has(lower)) continue
    return false
  }
  if (!force || !files.length) return false
  return emitRemoteDelete('k8s', `replace --force ${files.join(' ')}`, options, env)
}

const KUBECTL_DRAIN_VALUE_FLAGS = new Set(['--timeout', '--grace-period', '--pod-selector', '--selector',
  '-l', '--chunk-size', '--delete-emptydir-data', '--skip-wait-for-delete-timeout'])
const KUBECTL_DRAIN_BOOLEAN_FLAGS = new Set(['--force', '--delete-emptydir-data', '--delete-local-data',
  '--ignore-daemonsets', '--disable-eviction', '--ignore-not-found'])

/** `kubectl drain` deletes node pods; modeled only in its explicitly destructive forms. */
function kubectlDrain(rest, options, env) {
  const names = []
  let force = false
  let emptyDir = false
  for (let i = 0; i < rest.length; i++) {
    const value = rest[i]
    if (typeof value !== 'string') return false
    if (!value.startsWith('-')) { names.push(value); continue }
    const lower = value.toLowerCase()
    if (lower === '--dry-run' || lower.startsWith('--dry-run=')) return false
    if (lower === '--force') { force = true; continue }
    if (lower === '--delete-emptydir-data' || lower === '--delete-local-data') { emptyDir = true; continue }
    if (lower.includes('=')) continue
    if (KUBECTL_DRAIN_VALUE_FLAGS.has(lower)) { i++; continue }
    if (KUBECTL_DRAIN_BOOLEAN_FLAGS.has(lower)) continue
    return false
  }
  if (!force && !emptyDir) return false
  return emitRemoteDelete('k8s', `drain ${names.join(' ') || '(node not literal)'}`, options, env)
}

function kubectlCommand(args, options, env) {
  let index = 0
  while (index < args.length) {
    const value = args[index]
    if (typeof value !== 'string') return false
    if (!value.startsWith('-')) break
    if (value.includes('=')) { index++; continue }
    const lower = value.toLowerCase()
    if (lower === '--help' || lower === '-h' || lower === '--version') return false
    if (KUBECTL_GLOBAL_VALUE_FLAGS.has(lower)) index += 2
    else return false
  }
  const sub = typeof args[index] === 'string' ? args[index].toLowerCase() : ''
  if (sub === 'replace') return kubectlReplace(args.slice(index + 1), options, env)
  if (sub === 'apply') return kubectlApply(args.slice(index + 1), options, env)
  if (sub === 'drain') return kubectlDrain(args.slice(index + 1), options, env)
  if (sub !== 'delete') return false
  return kubectlDelete(args.slice(index + 1), options, env)
}

// --- helm ------------------------------------------------------------------

const HELM_BOOL_FLAGS = new Set(['--wait', '--atomic', '--no-hooks', '--force', '--keep-history',
  '--reuse-values', '--cleanup-on-fail', '--devel', '--render-subchart-notes', '--skip-crds', '--help', '-h'])
const HELM_VALUE_FLAGS = new Set(['-n', '--namespace', '--kube-context', '--kubeconfig', '--timeout',
  '--description', '--max', '--set', '--set-string', '--set-file', '--values', '-f', '--version',
  '--repo', '--username', '--password', '--ca-file', '--cert-file', '--key-file', '--post-renderer'])

function helmReleases(args, start) {
  const names = []
  for (let index = start; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string') return null
    if (!value.startsWith('-')) { names.push(value); continue }
    const eq = value.indexOf('=')
    const flag = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
    if (eq >= 0) continue
    if (HELM_VALUE_FLAGS.has(flag)) { index++; continue }
    if (HELM_BOOL_FLAGS.has(flag)) continue
    return null
  }
  return names
}

function helmCommand(args, options, env) {
  if (isPreview(args)) return false
  const sub = typeof args[0] === 'string' ? args[0].toLowerCase() : ''
  if (sub === 'uninstall' || sub === 'del' || sub === 'delete') {
    const names = helmReleases(args, 1)
    if (!names || !names.length) return false
    return emitRemoteDelete('helm', `helm release ${names.join(' ')}`, options, env)
  }
  // `helm rollback` replaces the live release with an earlier revision; the
  // manifests dropped relative to the current revision are real deletions, so
  // it takes the same deletion fact (see the team report for the rationale).
  if (sub === 'rollback') {
    const names = helmReleases(args, 1)
    if (!names || !names.length) return false
    return emitRemoteDelete('helm', `helm rollback ${names[0]}`, options, env)
  }
  return false
}

// --- docker ----------------------------------------------------------------

function dockerPositionals(args) {
  return args.filter((value) => typeof value === 'string' && !value.startsWith('-'))
}

const DOCKER_GLOBAL_VALUE_FLAGS = new Set(['--context', '--host', '-h', '--config', '--log-level',
  '--tlscacert', '--tlscert', '--tlskey'])
const DOCKER_GLOBAL_BOOL_FLAGS = new Set(['--tls', '--tlsverify', '-d', '--debug'])

const COMPOSE_GLOBAL_VALUE_FLAGS = new Set(['-f', '--file', '-p', '--project-name', '--env-file', '--profile',
  '--project-directory', '--ansi', '--parallel'])
const COMPOSE_GLOBAL_BOOL_FLAGS = new Set(['--compatibility', '--verbose', '--no-ansi', '--tls',
  '--tlsverify', '--dry-run'])

/** `docker compose down` / `docker-compose down` removes containers only unless it
 * carries the volume switch: `-v`, `--volumes`, or a `down` short-flag cluster
 * containing `v` (`-vt`) then removes the named volumes and their data. A plain
 * `down`, `ps`, `up` and every other subcommand stay free (DSR-032 second pass). */
function composeDownVolumes(args, program, options, env) {
  let index = 0
  while (index < args.length) {
    const value = args[index]
    if (typeof value !== 'string') return false
    if (!value.startsWith('-')) break
    const eq = value.indexOf('=')
    const flag = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
    if (eq >= 0) { index++; continue }
    if (COMPOSE_GLOBAL_VALUE_FLAGS.has(flag)) { index += 2; continue }
    if (COMPOSE_GLOBAL_BOOL_FLAGS.has(flag)) { index++; continue }
    return false
  }
  const sub = typeof args[index] === 'string' ? args[index].toLowerCase() : ''
  if (sub !== 'down') return false
  let volumes = false
  for (let cursor = index + 1; cursor < args.length; cursor++) {
    const value = args[cursor]
    if (typeof value !== 'string') return false
    if (value === '--volumes' || value === '--volumes=true') { volumes = true; continue }
    if (value.startsWith('--')) continue
    if (/^-[A-Za-z]+$/u.test(value) && value.slice(1).includes('v')) volumes = true
  }
  if (!volumes) return false
  return emitRemoteDelete('docker', `${program} down --volumes`, options, env)
}

function dockerComposeCommand(args, options, env) {
  if (isPreview(args)) return false
  return composeDownVolumes(args, 'docker-compose', options, env)
}

function dockerCommand(args, options, env) {
  if (isPreview(args)) return false
  const start = skipGlobalFlags(args, DOCKER_GLOBAL_VALUE_FLAGS, DOCKER_GLOBAL_BOOL_FLAGS)
  if (start === null) return false
  const rest = args.slice(start)
  const first = typeof rest[0] === 'string' ? rest[0].toLowerCase() : ''
  const second = typeof rest[1] === 'string' ? rest[1].toLowerCase() : ''
  if (first === 'compose') return composeDownVolumes(rest.slice(1), 'compose', options, env)
  if (first === 'system' && second === 'prune') return emitRemoteDelete('docker', 'docker system (prune)', options, env)
  if (first === 'system' && second === 'reset') return emitRemoteDelete('docker', 'docker system (reset)', options, env)
  if (first === 'volume' && second === 'prune') return emitRemoteDelete('docker', 'docker volume (prune)', options, env)
  // `docker volume create` is additive; it must never produce a deletion fact.
  if (first === 'volume' && second === 'create') return false
  if ((first === 'container' || first === 'image' || first === 'network' || first === 'builder') &&
    second === 'prune') {
    return emitRemoteDelete('docker', `docker ${first} (prune)`, options, env)
  }
  if (first === 'volume' && second === 'rm') {
    const tail = rest.slice(2)
    const volumes = dockerPositionals(tail)
    if (volumes.length) return emitRemoteDelete('docker', `volume ${volumes.join(' ')}`, options, env)
    // No volume operand at all is a usage error; a dynamic operand still expresses
    // a real deletion attempt (DSR-031 決定 5).
    if (tail.some((value) => value === null)) {
      return emitRemoteDelete('docker', 'docker volume rm (selection not literal)', options, env)
    }
    return false
  }
  // `rmi`/`rm` are modeled only in their scripted, non-interactive `-f` form.
  if ((first === 'rmi' || first === 'rm') && rest.some((value) => value === '-f' || value === '--force')) {
    const tail = rest.slice(1)
    const targets = dockerPositionals(tail)
    const label = first === 'rmi' ? 'image' : 'container'
    if (targets.length) return emitRemoteDelete('docker', `${label} ${targets.join(' ')}`, options, env)
    if (tail.some((value) => value === null)) {
      return emitRemoteDelete('docker', `docker ${first} (selection not literal)`, options, env)
    }
    return false
  }
  return false
}

// --- terraform -------------------------------------------------------------

function terraformCommand(args, options, env) {
  // Help/version probes are read-only wherever they appear in the line.
  if (args.some((value) => ['--help', '-help', '-h', '--version', '-version', '-v'].includes(value))) return false
  let index = 0
  while (index < args.length) {
    const value = args[index]
    if (typeof value !== 'string') return false
    if (!value.startsWith('-')) break
    if (value.includes('=')) { index++; continue }
    return false
  }
  const sub = typeof args[index] === 'string' ? args[index].toLowerCase() : ''
  if (sub === 'destroy') return emitRemoteDelete('terraform', 'terraform state (destroy)', options, env)
  if (sub === 'state' && typeof args[index + 1] === 'string' && args[index + 1].toLowerCase() === 'rm') {
    const tail = args.slice(index + 2)
    const addresses = tail.filter((value) => typeof value === 'string' && !value.startsWith('-'))
    if (addresses.length) {
      return emitRemoteDelete('terraform', `terraform state rm ${addresses.join(' ')}`, options, env)
    }
    // No address is a usage error; a dynamic address is still deletion intent.
    if (tail.some((value) => value === null)) {
      return emitRemoteDelete('terraform', 'terraform state rm (selection not literal)', options, env)
    }
    return false
  }
  if (sub === 'workspace' && typeof args[index + 1] === 'string' && args[index + 1].toLowerCase() === 'delete') {
    const name = typeof args[index + 2] === 'string' && !args[index + 2].startsWith('-') ? args[index + 2] : ''
    return emitRemoteDelete('terraform',
      name ? `terraform workspace delete ${name}` : 'terraform workspace delete (current workspace)',
      options, env)
  }
  if (sub === 'apply' && args.some((value) => typeof value === 'string' && value.toLowerCase() === '-destroy')) {
    return emitRemoteDelete('terraform', 'terraform state (destroy via apply)', options, env)
  }
  // `force-unlock` releases a stale lock only; it destroys nothing.
  return false
}

// --- transfers (scp) -------------------------------------------------------

const SCP_BOOL_FLAGS = new Set(['-r', '-p', '-q', '-v', '-C', '-3', '-4', '-6', '-B', '-T', '-O', '-X',
  '-x', '-A', '-d', '-s'])
const SCP_VALUE_FLAGS = new Set(['-P', '-i', '-o', '-F', '-l', '-S', '-c', '-J', '-D'])

/** `[user@]host:path` and `[ipv6]:path`; a Windows drive prefix stays local. */
function isRemoteSpec(value) {
  if (typeof value !== 'string') return false
  if (/^[A-Za-z]:[\\/]/u.test(value)) return false
  if (value.startsWith('[')) {
    const close = value.indexOf(']')
    return close > 1 && value[close + 1] === ':'
  }
  const colon = value.indexOf(':')
  if (colon <= 0) return false
  const host = value.slice(0, colon)
  return !host.includes('/') && !host.includes('\\')
}

/**
 * Value of `-b` in an sftp command line, separated or attached.
 * `undefined` when absent, `null` when present with a non-literal value, and
 * `'-'` when explicitly stdin (DSR-032 决定 5).
 */
function transferFlagValue(args, short, long) {
  for (let index = 0; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string') continue
    if (value === '--') return undefined
    if (value === short || (long && value === long)) {
      const assigned = args[index + 1]
      return typeof assigned === 'string' ? assigned : null
    }
    if (long && value.startsWith(`${long}=`)) {
      const assigned = value.slice(long.length + 1)
      return assigned || null
    }
    if (!long || !value.startsWith('--')) {
      if (value.startsWith(short) && value.length > short.length) return value.slice(short.length)
    }
  }
  return undefined
}

function scpOperands(args) {
  const operands = []
  for (let index = 0; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string') return null
    if (value === '--') {
      for (let rest = index + 1; rest < args.length; rest++) {
        if (typeof args[rest] !== 'string') return null
        operands.push(args[rest])
      }
      return operands
    }
    if (value === '-' || !value.startsWith('-')) { operands.push(value); continue }
    if (SCP_BOOL_FLAGS.has(value)) continue
    if (SCP_VALUE_FLAGS.has(value)) { index++; continue }
    // Attached short forms: `-P22`, `-i~/.ssh/id_ed25519`, `-oOption=value`, `-rp`.
    if (value.length > 2 && !value.startsWith('--')) {
      if (SCP_VALUE_FLAGS.has(value.slice(0, 2))) continue
      if ([...value.slice(1)].every((letter) => SCP_BOOL_FLAGS.has(`-${letter}`))) continue
    }
    return null
  }
  return operands
}

/**
 * `scp` reads its local sources in the upload direction; that read is a
 * `read-content` fact and the caller's credential rule decides what happens
 * next. The `-i` identity file is ordinary authentication input with no
 * outward transfer, so it produces nothing (the first pass modeled it as a
 * read; CSN exempts the same form).
 */
function scpCommand(args, options, env) {
  if (isPreview(args)) return false
  const operands = scpOperands(args)
  if (!operands || operands.length < 2) return false
  if (!isRemoteSpec(operands[operands.length - 1])) return false
  let emitted = false
  for (const source of operands.slice(0, -1)) {
    if (typeof source !== 'string' || source === '-' || isRemoteSpec(source)) continue
    emitRemoteRead(source, options, env)
    emitted = true
  }
  return emitted
}

/**
 * `sftp` batch mode executes commands that may upload credentials or delete
 * remote files, so an explicit `-b <batchfile>` (or `-b -` / a heredoc feeding
 * stdin) is an `unverified-effect` candidate whose scope names the batch. An
 * interactive `sftp host` stays a gap. `-i <file>` is authentication input and
 * produces no read fact, matching `scp`.
 */
function sftpCommand(args, options, env) {
  if (isPreview(args)) return false
  if (args.some((value) => typeof value === 'string' &&
    (value === '-V' || value === '-h' || value === '--version' || value === '--help'))) return false
  const batch = transferFlagValue(args, '-b', '--batchfile')
  let batchScope
  if (typeof batch === 'string') batchScope = batch === '-' ? 'sftp batch (stdin)' : `sftp batch ${batch}`
  else if (batch === null) batchScope = 'sftp batch (batchfile not literal)'
  else {
    const heredocs = Array.isArray(options.heredocs)
      ? options.heredocs.filter((entry) => typeof entry?.body === 'string' && entry.body !== '')
      : []
    if (heredocs.length) batchScope = 'sftp batch (stdin heredoc)'
  }
  if (batchScope) {
    env.candidate('unverified-effect', 'SFTP batch may upload credentials or delete remote files',
      [batchScope], options.origin)
    return true
  }
  return false
}

// --- azcopy / data-warehouse clients (DSR-032 决定 9) ----------------------

const AZCOPY_VALUE_FLAGS = new Set(['--log-level', '--output-type', '--output-level', '--cap-mbps', '--cmd',
  '--from-to', '--include-pattern', '--exclude-pattern', '--include-path', '--exclude-path',
  '--include-regex', '--exclude-regex', '--list-of-files', '--block-size-mb', '--trusted-microsoft-suffixes',
  '--s2s-preserve-access-tier', '--s2s-detect-source-changed'])
const AZCOPY_BOOL_FLAGS = new Set(['-r', '--recursive', '--delete', '--version', '-h', '--help', '--overwrite',
  '--put-md5', '--check-md5', '--preserve-smb-permissions', '--preserve-permissions', '--decompress'])

/** `azcopy remove <remote>` and `azcopy sync --delete <src> <remote dst>` destroy
 * remote data; `azcopy list`/`copy` and local destinations stay free. */
function azcopyCommand(args, options, env) {
  if (isPreview(args)) return false
  let index = 0
  while (index < args.length) {
    const value = args[index]
    if (typeof value !== 'string') return false
    if (!value.startsWith('-')) break
    if (value === '-h' || value === '--help' || value === '--version') return false
    const eq = value.indexOf('=')
    const flag = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
    if (eq >= 0) { index++; continue }
    if (AZCOPY_VALUE_FLAGS.has(flag)) { index += 2; continue }
    if (AZCOPY_BOOL_FLAGS.has(flag)) { index++; continue }
    return false
  }
  const sub = typeof args[index] === 'string' ? args[index].toLowerCase() : ''
  const tail = args.slice(index + 1)
  if (sub === 'remove') {
    const names = collectNames(tail, 0, AZCOPY_VALUE_FLAGS, AZCOPY_BOOL_FLAGS)
    if (!names) return false
    const remote = names.filter((name) => typeof name === 'string' && REMOTE_URL.test(name))
    if (!remote.length) return false
    return emitRemoteDelete('azcopy', `azcopy remove ${remote.join(' ')}`, options, env)
  }
  if (sub !== 'sync') return false
  if (!tail.some((value) => typeof value === 'string' && value.toLowerCase() === '--delete')) return false
  const names = collectNames(tail, 0, AZCOPY_VALUE_FLAGS, AZCOPY_BOOL_FLAGS)
  if (!names || names.length < 2) return false
  const destination = names[names.length - 1]
  if (typeof destination !== 'string' || !REMOTE_URL.test(destination)) return false
  return emitRemoteDelete('azcopy', `azcopy sync --delete ${names.join(' ')} (remote mirror)`, options, env)
}

const SUPABASE_VALUE_FLAGS = new Set(['--project-ref', '--workdir', '--db-url'])
const SUPABASE_BOOL_FLAGS = new Set(['--linked', '--local', '--experimental', '--yes', '-y', '--debug'])

function supabaseCommand(args, options, env) {
  if (isPreview(args)) return false
  const first = typeof args[0] === 'string' ? args[0].toLowerCase() : ''
  const second = typeof args[1] === 'string' ? args[1].toLowerCase() : ''
  if (first === 'db' && second === 'reset') return emitRemoteDelete('supabase', 'supabase db reset', options, env)
  if (first === 'migration' && second === 'down') return emitRemoteDelete('supabase', 'supabase migration down', options, env)
  // DSR-032 second pass: `supabase storage rm` deletes storage objects.
  if (first === 'storage' && second === 'rm') {
    const names = collectNames(args, 2, SUPABASE_VALUE_FLAGS, SUPABASE_BOOL_FLAGS)
    if (!names || !names.length) return false
    return emitRemoteDelete('supabase', `supabase storage rm ${names.join(' ')}`, options, env)
  }
  return false
}

const DATABRICKS_VALUE_FLAGS = new Set(['-p', '--profile', '-t', '--target', '--host', '--token',
  '--cluster-id', '-c', '--config-file', '-o', '--output', '--log-file', '--log-level', '--debug-level',
  '--progress-format'])
const DATABRICKS_BOOL_FLAGS = new Set(['--debug', '--verbose'])
const DATABRICKS_FS_VALUE_FLAGS = new Set()
const DATABRICKS_FS_BOOL_FLAGS = new Set(['-r', '--recursive'])

function databricksCommand(args, options, env) {
  if (isPreview(args)) return false
  const start = skipGlobalFlags(args, DATABRICKS_VALUE_FLAGS, DATABRICKS_BOOL_FLAGS)
  if (start === null) return false
  const rest = args.slice(start)
  const first = typeof rest[0] === 'string' ? rest[0].toLowerCase() : ''
  const second = typeof rest[1] === 'string' ? rest[1].toLowerCase() : ''
  if (first === 'bundle' && second === 'destroy') {
    return emitRemoteDelete('databricks', 'databricks bundle destroy', options, env)
  }
  // DSR-032 second pass: `databricks fs rm` deletes DBFS / Unity Catalog Volume data.
  if (first === 'fs' && second === 'rm') {
    const tail = rest.slice(2)
    const names = collectNames(tail, 0, DATABRICKS_FS_VALUE_FLAGS, DATABRICKS_FS_BOOL_FLAGS)
    if (!names || !names.length) return false
    const recursive = tail.some((value) => value === '-r' || value === '--recursive')
    const scope = names.map((name) => recursive ? `${name}/** (recursive)` : name).join(' ')
    return emitRemoteDelete('databricks', `databricks fs rm ${scope}`, options, env)
  }
  return false
}

/** `snowsql -q "<sql>"`: only a literal DROP/TRUNCATE/DELETE-without-WHERE query
 * is destructive; anything else stays a gap. */
function snowsqlCommand(args, options, env) {
  if (isPreview(args)) return false
  const queries = []
  for (let index = 0; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string' || !value.startsWith('-')) continue
    const eq = value.indexOf('=')
    const flag = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
    if (flag !== '-q' && flag !== '--query') continue
    const assigned = eq < 0 ? args[++index] : value.slice(eq + 1)
    if (typeof assigned === 'string') queries.push(assigned)
  }
  const scopes = sqlDestructiveScopes(queries)
  if (!scopes.length) return false
  for (const scope of scopes) {
    emitRemoteDelete('snowflake', `snowsql: ${scope.startsWith('SQL: ') ? scope.slice(5) : scope}`, options, env)
  }
  return true
}

// --- bq / pulumi / mc (DSR-032 second pass) ---------------------------------

const BQ_VALUE_FLAGS = new Set(['-p', '--project_id', '--project-id', '--location', '--format', '--api',
  '--headless', '--max_rows', '--max_rows_per_page', '--job_id', '--apilog', '--job_property',
  '--service_account', '--service_account_credential_file', '--discovery_file', '--iam_token',
  '--dataset_id', '--table_id', '--use_legacy_sql'])
const BQ_BOOL_FLAGS = new Set(['-q', '--quiet', '--synchronous', '--batch', '--debug',
  '--enable_reservation', '--fingerprint_job_id'])
const BQ_RM_BOOL_FLAGS = new Set([...BQ_BOOL_FLAGS, '-f', '--force', '-r', '--recursive', '-t', '--table',
  '-d', '--dataset', '--transfer_config', '--reservation'])

/** `bq rm [-r] <dataset|table>` and `bq query "<destructive SQL>"`. `bq ls`,
 * `bq show`, `bq query "SELECT …"` and every `--dry_run` stay free. */
function bqCommand(args, options, env) {
  if (isPreview(args)) return false
  if (args.some((value) => typeof value === 'string' &&
    (value === '--dry_run' || value.startsWith('--dry_run=') ||
      value === '--dry-run' || value.startsWith('--dry-run=')))) return false
  const start = skipGlobalFlags(args, BQ_VALUE_FLAGS, BQ_BOOL_FLAGS)
  if (start === null) return false
  const rest = args.slice(start)
  const sub = typeof rest[0] === 'string' ? rest[0].toLowerCase() : ''
  if (sub === 'rm') {
    const tail = rest.slice(1)
    const names = collectNames(tail, 0, BQ_VALUE_FLAGS, BQ_RM_BOOL_FLAGS)
    if (!names || !names.length) return false
    const recursive = tail.some((value) => value === '-r' || value === '--recursive')
    const scope = names.map((name) => recursive ? `${name}/** (recursive)` : name).join(' ')
    return emitRemoteDelete('bigquery', `bq rm ${scope}`, options, env)
  }
  if (sub !== 'query') return false
  // `bq query` takes the statement as a positional operand; stdin-fed SQL
  // (`bq query < file.sql`) is not literal here and stays a gap.
  const names = collectNames(rest.slice(1), 0, BQ_VALUE_FLAGS, BQ_BOOL_FLAGS)
  if (!names || !names.length) return false
  const scopes = sqlDestructiveScopes([names.join(' ')])
  if (!scopes.length) return false
  for (const scope of scopes) {
    emitRemoteDelete('bigquery', `bq query: ${scope.startsWith('SQL: ') ? scope.slice(5) : scope}`, options, env)
  }
  return true
}

const PULUMI_VALUE_FLAGS = new Set(['-s', '--stack', '--cwd', '-C', '--color', '--logfile', '--logflow',
  '--logtostderr', '--logverbose', '--profiling', '--otel', '--tracing'])
const PULUMI_BOOL_FLAGS = new Set(['-y', '--yes', '-f', '--force', '--preserve-config', '--remove',
  '--non-interactive', '--json', '-v', '--verbose', '-d', '--debug', '-t', '--trace', '-h', '--help'])

/** `pulumi stack rm [stack]` removes the stack and its history; a stack named by
 * `-s/--stack` or by the positional operand. `pulumi stack ls` stays free. */
function pulumiCommand(args, options, env) {
  if (isPreview(args)) return false
  const start = skipGlobalFlags(args, PULUMI_VALUE_FLAGS, PULUMI_BOOL_FLAGS)
  if (start === null) return false
  const rest = args.slice(start)
  if (typeof rest[0] !== 'string' || rest[0].toLowerCase() !== 'stack') return false
  if (typeof rest[1] !== 'string' || rest[1].toLowerCase() !== 'rm') return false
  const names = collectNames(rest.slice(2), 0, PULUMI_VALUE_FLAGS, PULUMI_BOOL_FLAGS)
  if (!names) return false
  if (!names.length) return emitRemoteDelete('pulumi', 'pulumi stack rm (selected stack)', options, env)
  return emitRemoteDelete('pulumi', `pulumi stack rm ${names.join(' ')}`, options, env)
}

const MC_VALUE_FLAGS = new Set(['-C', '--config-dir', '--limit-upload', '--limit-download', '--older-than',
  '--newer-than', '--storage-class', '--attr', '--encrypt-key', '--exclude', '--include'])
const MC_BOOL_FLAGS = new Set(['-q', '--quiet', '--no-color', '--json', '--debug', '-r', '--recursive',
  '--force', '--dangerous', '--versions', '--bypass', '--watch', '-w', '--insecure'])

/** `mc rb <alias/bucket>` removes a bucket; `mc rm [-r] <target>` removes objects.
 * `mc ls`, `mc cp`, `mc stat` and the other read/copy verbs stay free. */
function mcCommand(args, options, env) {
  if (isPreview(args)) return false
  if (args.some((value) => value === '--version' || value === '--help' || value === '-h')) return false
  const start = skipGlobalFlags(args, MC_VALUE_FLAGS, MC_BOOL_FLAGS)
  if (start === null) return false
  const rest = args.slice(start)
  const sub = typeof rest[0] === 'string' ? rest[0].toLowerCase() : ''
  if (sub !== 'rb' && sub !== 'rm') return false
  const tail = rest.slice(1)
  const names = collectNames(tail, 0, MC_VALUE_FLAGS, MC_BOOL_FLAGS)
  if (!names || !names.length) return false
  const recursive = sub === 'rm' && tail.some((value) => value === '-r' || value === '--recursive')
  const scope = recursive ? `${names.join(' ')}/** (recursive)` : names.join(' ')
  return emitRemoteDelete('minio', `mc ${sub} ${scope}`, options, env)
}

// --- shared flag/operand helpers -------------------------------------------

function flagName(value) {
  const eq = value.indexOf('=')
  const raw = eq < 0 ? value : value.slice(0, eq)
  return raw.startsWith('--') ? raw.toLowerCase() : raw
}

/** Positional operands while consuming the flags this table knows (`null` when unsure). */
function collectNames(args, start, valueFlags, boolFlags) {
  const names = []
  for (let index = start; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string') return null
    if (value === '-' || !value.startsWith('-')) { names.push(value); continue }
    const eq = value.indexOf('=')
    const flag = flagName(value)
    if (eq >= 0) {
      if (valueFlags.has(flag) || boolFlags.has(flag)) continue
      return null
    }
    if (boolFlags.has(flag)) continue
    if (valueFlags.has(flag)) { index++; continue }
    return null
  }
  return names
}

// --- gh (GitHub CLI) -------------------------------------------------------

const GH_VALUE_FLAGS = new Set(['-R', '--repo', '--hostname', '--git-protocol'])
const GH_BOOL_FLAGS = new Set(['--yes', '-y', '--cleanup-tag', '--verbose', '--debug'])

function ghTargets(args, start) {
  const names = []
  for (let index = start; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string') return null
    if (value === '-' || !value.startsWith('-')) { names.push(value); continue }
    const eq = value.indexOf('=')
    const flag = flagName(value)
    if (eq >= 0) {
      if (GH_BOOL_FLAGS.has(flag)) continue
      if (!GH_VALUE_FLAGS.has(flag)) return null
      const assigned = value.slice(eq + 1)
      if (!assigned) return null
      if (flag === '-R' || flag === '--repo') names.push(assigned)
      continue
    }
    if (GH_BOOL_FLAGS.has(flag)) continue
    if (GH_VALUE_FLAGS.has(flag)) {
      const assigned = args[++index]
      if (typeof assigned !== 'string') return null
      if (flag === '-R' || flag === '--repo') names.push(assigned)
      continue
    }
    return null
  }
  return names
}

const GH_API_VALUE_FLAGS = new Set(['-H', '--header', '-f', '--raw-field', '-F', '--field', '--input',
  '--jq', '-q', '--template', '-t', '--hostname', '--cache', '--cache-ttl'])
const GH_API_BOOL_FLAGS = new Set(['--paginate', '--slurp', '--silent', '-i', '--include', '--verbose'])

/** `gh api -X DELETE <path>` deletes the addressed resource; an ambiguous parse is a gap. */
function ghApiCommand(rest, options, env) {
  let method
  const positionals = []
  for (let index = 0; index < rest.length; index++) {
    const value = rest[index]
    if (typeof value !== 'string') return false
    if (value === '-' || !value.startsWith('-')) { positionals.push(value); continue }
    if (value.length > 2 && value.startsWith('-X') && !value.includes('=')) {
      method = value.slice(2).toUpperCase()
      continue
    }
    const eq = value.indexOf('=')
    const flag = flagName(value)
    if (flag === '-X' || flag === '--method') {
      const assigned = eq < 0 ? rest[++index] : value.slice(eq + 1)
      if (typeof assigned !== 'string') return false
      method = assigned.toUpperCase()
      continue
    }
    if (eq >= 0) {
      if (GH_API_VALUE_FLAGS.has(flag)) continue
      return false
    }
    if (GH_API_BOOL_FLAGS.has(flag)) continue
    if (GH_API_VALUE_FLAGS.has(flag)) { index++; continue }
    return false
  }
  if (method !== 'DELETE') return false
  const endpoint = positionals[0]
  if (typeof endpoint !== 'string' || !endpoint) return false
  return emitRemoteDelete('gh', `gh api -X DELETE ${endpoint}`, options, env)
}

function ghCommand(args, options, env) {
  if (isPreview(args)) return false
  const first = typeof args[0] === 'string' ? args[0].toLowerCase() : ''
  const second = typeof args[1] === 'string' ? args[1].toLowerCase() : ''
  if (first === 'api') return ghApiCommand(args.slice(1), options, env)
  if (first === 'repo' && second === 'delete') {
    const names = ghTargets(args, 2)
    if (!names || !names.length) return false
    return emitRemoteDelete('gh', `gh repo delete ${names[0]}`, options, env)
  }
  if (first === 'release' && second === 'delete') {
    const names = ghTargets(args, 2)
    if (!names || !names.length) return false
    return emitRemoteDelete('gh', `gh release delete ${names[0]}`, options, env)
  }
  return false
}

// --- backup tools (restic, borg, rclone, velero) ---------------------------

const RESTIC_VALUE_FLAGS = new Set(['-r', '--repo', '--repository-file', '--password-file', '-p',
  '--key-hint', '--cacert', '--capath', '--tls-client-cert', '--limit-download', '--limit-upload',
  '--pack-size', '--option', '--host', '--tag', '--keep-last', '--keep-hourly', '--keep-daily',
  '--keep-weekly', '--keep-monthly', '--keep-yearly', '--keep-within', '--keep-within-hourly',
  '--keep-within-daily', '--keep-within-weekly', '--keep-within-monthly', '--keep-within-yearly',
  '--keep-tag'])
const RESTIC_BOOL_FLAGS = new Set(['--json', '--verbose', '-v', '--quiet', '--no-lock', '--compact',
  '--repair', '--prune'])

function resticCommand(args, options, env) {
  if (isPreview(args) || args.includes('-n')) return false
  let index = 0
  let repo
  while (index < args.length) {
    const value = args[index]
    if (typeof value !== 'string') return false
    if (!value.startsWith('-')) break
    if (value === '-r' || value === '--repo') {
      const assigned = args[index + 1]
      if (typeof assigned === 'string') repo = assigned
      index += 2
      continue
    }
    if (value.startsWith('--repo=')) { repo = value.slice('--repo='.length); index++; continue }
    if (RESTIC_BOOL_FLAGS.has(flagName(value)) || value === '--prune') { index++; continue }
    if (RESTIC_VALUE_FLAGS.has(flagName(value))) { index += 2; continue }
    return false
  }
  const sub = typeof args[index] === 'string' ? args[index].toLowerCase() : ''
  const suffix = repo ? ` (repo ${repo})` : ''
  if (sub === 'prune') return emitRemoteDelete('restic', `restic prune${suffix}`, options, env)
  if (sub === 'forget') {
    const pruning = args.some((value) => typeof value === 'string' &&
      (value === '--prune' || value.startsWith('--prune=')))
    if (!pruning) return false
    return emitRemoteDelete('restic', `restic forget --prune${suffix}`, options, env)
  }
  return false
}

const BORG_BOOL_FLAGS = new Set(['-v', '--verbose', '--debug', '--show-rc', '--info', '--warning',
  '--error', '--critical', '--progress', '--bypass-lock', '--stats', '--list', '--dry-run', '-n'])
const BORG_VALUE_FLAGS = new Set(['--remote-path', '--remote-user', '--rsh', '--umask', '--lock-wait',
  '--log-json'])

function borgCommand(args, options, env) {
  if (isPreview(args) || args.includes('-n')) return false
  let index = 0
  while (index < args.length) {
    const value = args[index]
    if (typeof value !== 'string') return false
    if (!value.startsWith('-')) break
    if (BORG_BOOL_FLAGS.has(value)) { index++; continue }
    if (BORG_VALUE_FLAGS.has(value)) { index += 2; continue }
    return false
  }
  const sub = typeof args[index] === 'string' ? args[index].toLowerCase() : ''
  if (sub === 'prune') return emitRemoteDelete('borg', 'borg prune', options, env)
  if (sub === 'delete') {
    const tail = args.slice(index + 1)
    const names = collectNames(tail, 0, BORG_VALUE_FLAGS, BORG_BOOL_FLAGS)
    if (names && names.length) return emitRemoteDelete('borg', `borg delete ${names[0]}`, options, env)
    // No repository operand is a usage error; a dynamic one is deletion intent.
    if (tail.some((value) => value === null)) {
      return emitRemoteDelete('borg', 'borg delete (selection not literal)', options, env)
    }
    return false
  }
  return false
}

const RCLONE_VALUE_FLAGS = new Set(['--config', '--log-file', '--log-level', '--stats', '--stats-unit',
  '--transfers', '--checkers', '--bwlimit', '--max-age', '--min-age', '--max-size', '--min-size',
  '--include', '--exclude', '--filter', '--files-from', '--user-agent', '--header', '--ca-cert',
  '--client-cert', '--client-key', '--timeout', '--contimeout', '--retries', '--low-level-retries',
  '--dump', '--drive-chunk-size', '--s3-chunk-size', '--tpslimit', '--tpslimit-burst',
  '--multi-thread-streams'])
const RCLONE_BOOL_FLAGS = new Set(['-v', '--verbose', '-q', '--quiet', '-P', '--progress', '-n',
  '--dry-run', '--checksum', '--update', '--ignore-existing', '--ignore-errors', '--fast-list',
  '--immutable', '--no-traverse'])

function rcloneCommand(args, options, env) {
  if (isPreview(args) || args.includes('-n')) return false
  let index = 0
  while (index < args.length) {
    const value = args[index]
    if (typeof value !== 'string') return false
    if (!value.startsWith('-')) break
    if (RCLONE_BOOL_FLAGS.has(value)) { index++; continue }
    if (RCLONE_VALUE_FLAGS.has(value)) { index += 2; continue }
    return false
  }
  const sub = typeof args[index] === 'string' ? args[index].toLowerCase() : ''
  if (sub !== 'delete' && sub !== 'purge') return false
  const names = collectNames(args, index + 1, RCLONE_VALUE_FLAGS, RCLONE_BOOL_FLAGS)
  const target = names ? names[0] : undefined
  if (typeof target !== 'string' || !isRemoteSpec(target)) return false
  return emitRemoteDelete('rclone', `rclone ${sub} ${target}`, options, env)
}

const VELERO_VALUE_FLAGS = new Set(['-n', '--namespace', '--kubeconfig', '--context', '--server', '--token',
  '--cert-file', '--key-file', '--ca-cert-file', '--client-cert', '--client-key', '--request-timeout',
  '-l', '--selector', '--log-level', '-v', '--v', '-o', '--output'])
const VELERO_BOOL_FLAGS = new Set(['--all', '--force', '--confirm', '--help'])

function veleroCommand(args, options, env) {
  if (isPreview(args)) return false
  let index = 0
  while (index < args.length) {
    const value = args[index]
    if (typeof value !== 'string') return false
    if (!value.startsWith('-')) break
    if (VELERO_BOOL_FLAGS.has(value)) { index++; continue }
    if (VELERO_VALUE_FLAGS.has(value)) { index += 2; continue }
    return false
  }
  const first = typeof args[index] === 'string' ? args[index].toLowerCase() : ''
  const second = typeof args[index + 1] === 'string' ? args[index + 1].toLowerCase() : ''
  if (first !== 'backup' || second !== 'delete') return false
  const names = collectNames(args, index + 2, VELERO_VALUE_FLAGS, VELERO_BOOL_FLAGS)
  if (!names) return false
  const all = args.includes('--all')
  if (!names.length && !all) return false
  const parts = ['velero backup delete']
  if (names.length) parts.push(names.join(' '))
  if (all) parts.push('--all')
  return emitRemoteDelete('velero', parts.join(' '), options, env)
}

// --- secret stores (vault, doppler, infisical) -----------------------------

const VAULT_VALUE_FLAGS = new Set(['-mount', '--mount', '-format', '--format', '-address', '--address',
  '-namespace', '--namespace', '-token', '--token', '-version', '--version', '-versions', '--versions',
  '-field', '--field', '-ca-cert', '--ca-cert', '-client-cert', '--client-cert', '-client-key',
  '--client-key', '-request-timeout', '-output'])
const VAULT_BOOL_FLAGS = new Set(['-tls-skip-verify', '--tls-skip-verify', '-non-interactive',
  '--non-interactive', '-help', '--help'])

function vaultCommand(args, options, env) {
  if (isPreview(args)) return false
  const a0 = typeof args[0] === 'string' ? args[0].toLowerCase() : ''
  const a1 = typeof args[1] === 'string' ? args[1].toLowerCase() : ''
  const a2 = typeof args[2] === 'string' ? args[2].toLowerCase() : ''
  // D3: `vault kv delete` and `vault delete` are recoverable on a KV v2 mount
  // (`vault kv undelete`), and the command line cannot prove the backend is v1.
  // They stay a coverage gap (allow). Only metadata deletion is irreversible.
  if (a0 !== 'kv' || a1 !== 'metadata' || a2 !== 'delete') return false
  const paths = collectNames(args, 3, VAULT_VALUE_FLAGS, VAULT_BOOL_FLAGS)
  if (!paths || !paths.length) return false
  return emitRemoteDelete('vault', `vault kv metadata delete ${paths.join(' ')}`, options, env)
}

const DOPPLER_VALUE_FLAGS = new Set(['-p', '--project', '-c', '--config', '--token', '--api-host',
  '--config-file'])
const DOPPLER_BOOL_FLAGS = new Set(['--yes', '-y', '--no-interactive', '--raw', '--only-names',
  '--no-check-version', '--silent'])

const INFISICAL_VALUE_FLAGS = new Set(['-e', '--env', '--projectId', '--project-id', '--path', '--token',
  '--domain', '--workspaceId', '--workspace-id', '--secretPath'])
const INFISICAL_BOOL_FLAGS = new Set(['--plain', '--silent', '--raw', '--recursive', '-r', '--yes', '-y',
  '--no-interactive'])

function dopplerCommand(args, options, env) {
  if (isPreview(args)) return false
  const first = typeof args[0] === 'string' ? args[0].toLowerCase() : ''
  const second = typeof args[1] === 'string' ? args[1].toLowerCase() : ''
  if (first !== 'secrets' || second !== 'delete') return false
  const names = collectNames(args, 2, DOPPLER_VALUE_FLAGS, DOPPLER_BOOL_FLAGS)
  if (!names || !names.length) return false
  return emitRemoteDelete('doppler', `doppler secrets delete ${names.join(' ')}`, options, env)
}

function infisicalCommand(args, options, env) {
  if (isPreview(args)) return false
  const first = typeof args[0] === 'string' ? args[0].toLowerCase() : ''
  const second = typeof args[1] === 'string' ? args[1].toLowerCase() : ''
  if (first !== 'secrets' || second !== 'delete') return false
  const names = collectNames(args, 2, INFISICAL_VALUE_FLAGS, INFISICAL_BOOL_FLAGS)
  if (!names || !names.length) return false
  return emitRemoteDelete('infisical', `infisical secrets delete ${names.join(' ')}`, options, env)
}

// --- dispatch --------------------------------------------------------------

const REMOTE_PROGRAMS = new Map([
  ['aws', awsCommand],
  ['gcloud', gcloudCommand],
  ['gsutil', gsutilCommand],
  ['az', azCommand],
  ['psql', sqlCommand('psql', 'postgres')],
  ['mysql', sqlCommand('mysql', 'mysql')],
  ['sqlite3', sqlCommand('sqlite3', 'sqlite')],
  ['mongosh', mongoCommand],
  ['mongo', mongoCommand],
  ['redis-cli', redisCommand],
  ['mysqladmin', mysqladminCommand],
  ['dropdb', dropdbCommand],
  ['clickhouse-client', clickhouseCommand],
  ['kubectl', kubectlCommand],
  ['helm', helmCommand],
  ['docker', dockerCommand],
  ['docker-compose', dockerComposeCommand],
  ['terraform', terraformCommand],
  ['pulumi', pulumiCommand],
  ['scp', scpCommand],
  ['sftp', sftpCommand],
  ['azcopy', azcopyCommand],
  ['bq', bqCommand],
  ['mc', mcCommand],
  ['supabase', supabaseCommand],
  ['databricks', databricksCommand],
  ['snowsql', snowsqlCommand],
  ['gh', ghCommand],
  ['restic', resticCommand],
  ['borg', borgCommand],
  ['rclone', rcloneCommand],
  ['velero', veleroCommand],
  ['vault', vaultCommand],
  ['doppler', dopplerCommand],
  ['infisical', infisicalCommand],
])

/** Model destructive subcommands of remote/cloud tools (F-26…F-32).
 * Returns true when an operation was emitted; false otherwise. */
export function resolveRemoteCommand(name, args, options, env) {
  if (typeof name !== 'string' || !Array.isArray(args)) return false
  const handler = REMOTE_PROGRAMS.get(name.toLowerCase())
  if (!handler) return false
  return handler(args, options, env) === true
}
