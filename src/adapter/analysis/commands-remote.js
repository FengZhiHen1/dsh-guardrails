// commands-remote — cloud/database/K8s/container/IaC destructive command facts
// (adapter layer, one thin table per provider, all confirm-grade).
//
// Interface (fixed by the team contract): `resolveRemoteCommand(name, args,
// options, env) => boolean`. commands.js calls this before its unmodeled-command
// gap; a `false` return lets the caller emit that gap and allow (D1/D3). Only an
// identified destructive subcommand with a non-empty literal resource scope
// produces an operation; read-only subcommands, previews (`--dryrun`/`--help`)
// and unknown forms produce nothing — no operation, no candidate. Scope text is
// the command's own resource range (bucket/URL/resource name/SQL object), never
// interpreted as a host path, so the evidence layer never probes it (D2).

function emitRemoteDelete(provider, scope, options, env) {
  env.operation('delete', { kind: 'unknown', reason: 'remote-target', knownScope: [scope] }, {
    ...options, details: { remote: { provider, scope } },
  })
  return true
}

// --- aws -------------------------------------------------------------------

/** aws s3 rm/rb plus the highest-risk single-resource service deletions. */
const AWS_DELETIONS = new Map([
  ['ec2 terminate-instances', { flag: '--instance-ids', label: 'ec2 terminate-instances' }],
  ['rds delete-db-instance', { flag: '--db-instance-identifier', label: 'rds delete-db-instance' }],
  ['dynamodb delete-table', { flag: '--table-name', label: 'dynamodb delete-table' }],
])

function awsPositionalValues(args, start, stop = () => false) {
  const values = []
  for (let index = start; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string') continue
    if (value.startsWith('-')) continue
    if (stop(value)) break
    values.push(value)
  }
  return values
}

function awsCommand(args, options, env) {
  const service = typeof args[0] === 'string' ? args[0].toLowerCase() : ''
  const sub = typeof args[1] === 'string' ? args[1].toLowerCase() : ''
  if (service === 's3') {
    if (sub !== 'rm' && sub !== 'rb') return false
    // `--dryrun` is a preview of the deletion; leave the command unmodeled (D3).
    if (args.some((value) => value === '--dryrun' || value === '--dry-run')) return false
    const targets = args.filter((value) => typeof value === 'string' && /^s3:\/\//iu.test(value))
    if (!targets.length) return false
    if (sub === 'rb') {
      return emitRemoteDelete('aws', targets.map((url) => `${url} (bucket)`).join(' '), options, env)
    }
    const recursive = args.includes('--recursive')
    const scope = recursive ? targets.map((url) => `${url}/** (recursive)`).join(' ') : targets.join(' ')
    return emitRemoteDelete('aws', scope, options, env)
  }
  const entry = AWS_DELETIONS.get(`${service} ${sub}`)
  if (!entry) return false
  // The resource selector follows its flag; anything before it is irrelevant.
  const index = args.findIndex((value) => typeof value === 'string' &&
    value.toLowerCase() === entry.flag)
  const values = index < 0 ? [] : awsPositionalValues(args, index + 1, (value) => value.startsWith('--'))
  const scope = values.length
    ? `${entry.label} ${values.join(' ')}`
    : `${entry.label} (resource selector not literal)`
  return emitRemoteDelete('aws', scope, options, env)
}

// --- gcp -------------------------------------------------------------------

/** gcloud subcommands modeled here; unknown flag or value-following form → false. */
const GCLOUD_DELETIONS = new Set(['compute instances delete', 'sql instances delete', 'container clusters delete'])
/** gcloud flags that take a value and may precede the resource name. */
const GCLOUD_VALUE_FLAGS = new Set(['--zone', '--region', '--project', '--configuration', '--format',
  '--filter', '--limit', '--page-size', '--sort-by', '--impersonate-service-account'])
const GCLOUD_BOOLEAN_FLAGS = new Set(['--quiet', '--no-quiet'])

function gcloudCommand(args, options, env) {
  const key = args.slice(0, 3).map((value) => typeof value === 'string' ? value.toLowerCase() : '').join(' ').trim()
  if (!GCLOUD_DELETIONS.has(key)) return false
  const names = []
  for (let index = 3; index < args.length; index++) {
    const value = args[index]
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

function gsutilCommand(args, options, env) {
  if (typeof args[0] !== 'string' || args[0].toLowerCase() !== 'rm') return false
  const recursive = args.some((value) => value === '-r' || value === '-R' || value === '--recursive')
  const targets = args.filter((value) => typeof value === 'string' && /^gs:\/\//iu.test(value))
  if (!targets.length) return false
  const scope = targets.map((url) => recursive ? `${url}/** (recursive)` : url).join(' ')
  return emitRemoteDelete('gcp', scope, options, env)
}

// --- azure -----------------------------------------------------------------

const AZ_DELETIONS = new Map([
  ['vm delete', { '-g': 'group', '--resource-group': 'group', '--resource-group-name': 'group',
    '-n': 'name', '--name': 'name' }],
  ['group delete', { '-n': 'name', '--name': 'name' }],
  ['sql db delete', { '-g': 'group', '--resource-group': 'group', '--resource-group-name': 'group',
    '-n': 'name', '--name': 'name', '-s': 'server', '--server': 'server' }],
  ['storage account delete', { '-n': 'name', '--name': 'name', '-g': 'group',
    '--resource-group': 'group', '--resource-group-name': 'group' }],
])
const AZ_BOOLEAN_FLAGS = new Set(['-y', '--yes', '--no-wait', '--force', '--verbose', '--debug', '--only-show-errors'])

function azCommand(args, options, env) {
  const tokens = args.slice(0, 3).map((value) => typeof value === 'string' ? value.toLowerCase() : '')
  // Subcommands are `service [noun] delete`: try the three-token path first.
  const key3 = tokens.slice(0, 3).join(' ').trim()
  const key2 = tokens.slice(0, 2).join(' ').trim()
  const roles = AZ_DELETIONS.get(key3) ?? AZ_DELETIONS.get(key2)
  const key = AZ_DELETIONS.has(key3) ? key3 : key2
  if (!roles) return false
  const start = AZ_DELETIONS.has(key3) ? 3 : 2
  const name = []
  let group
  let server
  for (let index = start; index < args.length; index++) {
    const value = args[index]
    if (typeof value !== 'string') return false
    if (!value.startsWith('-')) { name.push(value); continue }
    const eq = value.indexOf('=')
    const flag = (eq < 0 ? value : value.slice(0, eq)).toLowerCase()
    const role = Object.hasOwn(roles, flag) ? roles[flag] : undefined
    if (role) {
      const assigned = eq < 0 ? args[++index] : value.slice(eq + 1)
      if (typeof assigned !== 'string') return false
      if (role === 'name') name.push(assigned)
      else if (role === 'group') group = assigned
      else server = assigned
      continue
    }
    if (eq >= 0) continue
    if (AZ_BOOLEAN_FLAGS.has(flag)) continue
    return false
  }
  const scope = name.length
    ? [name.join(' '), group && `(resource group ${group})`, server && `(server ${server})`].filter(Boolean).join(' ')
    : `${key} (resource name not literal)`
  return emitRemoteDelete('azure', scope, options, env)
}

// --- SQL shells ------------------------------------------------------------

const SQL_PROGRAMS = new Map([['psql', 'postgres'], ['mysql', 'mysql'], ['sqlite3', 'sqlite']])

function sqlDestructiveScopes(statements) {
  const scopes = []
  for (const text of statements) {
    for (const raw of text.split(';')) {
      const sql = raw.trim()
      if (!sql) continue
      if (/^drop\s+(?:table|database|schema)\b/iu.test(sql) || /^truncate(?:\s+table)?\s+\S/iu.test(sql)) {
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

// --- kubernetes ------------------------------------------------------------

const KUBECTL_GLOBAL_VALUE_FLAGS = new Set(['-n', '--namespace', '--context', '--cluster', '--user',
  '--kubeconfig', '-s', '--server', '--request-timeout', '--profile', '--v'])
const KUBECTL_SUB_VALUE_FLAGS = new Set(['-n', '--namespace', '--context', '--cluster', '--user',
  '--kubeconfig', '-s', '--server', '-l', '--selector', '--field-selector', '-o', '--output',
  '--grace-period', '--timeout', '--wait', '--v'])
const KUBECTL_SUB_BOOLEAN_FLAGS = new Set(['-a', '--all', '--force', '--now', '--ignore-not-found',
  '--cascade', '--recursive', '--raw', '--wait', '--openapi-patch', '--server-side', '--flush-backoff'])

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
  if (args[index] !== 'delete') return false
  const names = []
  const files = []
  let all = false
  for (let i = index + 1; i < args.length; i++) {
    const value = args[i]
    if (typeof value !== 'string') return false
    if (value === '--') {
      names.push(...args.slice(i + 1).filter((item) => typeof item === 'string' && !item.startsWith('-')))
      break
    }
    if (!value.startsWith('-')) { names.push(value); continue }
    const lower = value.toLowerCase()
    if (lower === '--dry-run' || lower.startsWith('--dry-run=')) return false
    if (lower === '-f' || lower === '--filename' || lower.startsWith('--filename=')) {
      const file = lower.startsWith('--filename=') ? value.slice('--filename='.length) : args[++i]
      if (typeof file !== 'string') return false
      files.push(file)
      continue
    }
    if (lower === '--all' || lower === '-a') { all = true; continue }
    if (lower.includes('=')) continue
    if (KUBECTL_SUB_VALUE_FLAGS.has(lower)) { i++; continue }
    if (KUBECTL_SUB_BOOLEAN_FLAGS.has(lower)) continue
    return false
  }
  if (!names.length && !files.length && !all) return false
  const scope = [names.join(' '), files.join(' '), all && '--all'].filter(Boolean).join(' ').trim()
  return emitRemoteDelete('k8s', scope || 'cluster resources (delete)', options, env)
}

// --- docker ----------------------------------------------------------------

function dockerPositionals(args) {
  return args.filter((value) => typeof value === 'string' && !value.startsWith('-'))
}

function dockerCommand(args, options, env) {
  const first = typeof args[0] === 'string' ? args[0].toLowerCase() : ''
  const second = typeof args[1] === 'string' ? args[1].toLowerCase() : ''
  if (first === 'system' && second === 'prune') return emitRemoteDelete('docker', 'docker system (prune)', options, env)
  if (first === 'volume' && second === 'prune') return emitRemoteDelete('docker', 'docker volume (prune)', options, env)
  if (first === 'volume' && second === 'rm') {
    const volumes = dockerPositionals(args.slice(2))
    const scope = volumes.length ? `volume ${volumes.join(' ')}` : 'docker volume rm (volume name not literal)'
    return emitRemoteDelete('docker', scope, options, env)
  }
  // `rmi`/`rm` are modeled only in their scripted, non-interactive `-f` form.
  if ((first === 'rmi' || first === 'rm') && args.some((value) => value === '-f' || value === '--force')) {
    const targets = dockerPositionals(args.slice(1))
    const label = first === 'rmi' ? 'image' : 'container'
    const scope = targets.length ? `${label} ${targets.join(' ')}` : `docker ${first} (${label} reference not literal)`
    return emitRemoteDelete('docker', scope, options, env)
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
  if (sub === 'apply' && args.some((value) => typeof value === 'string' && value.toLowerCase() === '-destroy')) {
    return emitRemoteDelete('terraform', 'terraform state (destroy via apply)', options, env)
  }
  return false
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
  ['kubectl', kubectlCommand],
  ['docker', dockerCommand],
  ['terraform', terraformCommand],
])

/** Model destructive subcommands of remote/cloud tools (F-26…F-32).
 * Returns true when an operation was emitted; false otherwise. */
export function resolveRemoteCommand(name, args, options, env) {
  if (typeof name !== 'string' || !Array.isArray(args)) return false
  const handler = REMOTE_PROGRAMS.get(name.toLowerCase())
  if (!handler) return false
  return handler(args, options, env) === true
}
