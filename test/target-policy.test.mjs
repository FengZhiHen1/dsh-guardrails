// Target-policy unit tests for src/core/decision.js — the single pure decision point
// (需求 v2 three-tier judgment, 规则模型 rule catalog + 操作到规则的映射 + 配置模型,
// 执行分析 operation facts, DSR-025/026/027). Tests assert the contract, not legacy
// behavior: catastrophic priority, R-07 tiers, checks-vs-gaps boundary, per-rule config
// and one-time allowances, protective config fallback, and the fixed render block with
// credential redaction.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  ALLOW_THRESHOLD,
  CATASTROPHIC_RULES,
  CHECK_FAILED_RULE,
  decide,
  isProtectedPath,
  normalizePolicy,
  renderDecision,
} from '../src/core/decision.js'

/** Minimal complete evidence: a fully analyzed call with no deletions and no risks. */
const CLEAN = {
  analysisStatus: 'complete',
  operations: [],
  candidates: [],
  gaps: [],
  identities: [],
  inventory: null,
  protectedHits: [],
  exemptions: [],
  issues: [],
}

// ---------------------------------------------------------------------------
// normalizePolicy — protective fallback (R-20)
// ---------------------------------------------------------------------------

test('normalizePolicy: defaults for empty and missing config', () => {
  for (const config of [undefined, null, {}]) {
    const policy = normalizePolicy(config)
    assert.deepEqual(policy.sensitiveFiles, [])
    assert.equal(policy.builtinSensitiveAsk, true)
    assert.equal(policy.askTimeoutMs, 120000)
    assert.equal(policy.alwaysAsk, true) // protective default (keep asking when approvals are off)
    assert.deepEqual(policy.rules, {})
    assert.deepEqual(policy.allowOnce, [])
    assert.equal(policy.tightenOnly, true) // protective default (受保护项始终生效)
    assert.deepEqual(policy.configIssues, [])
  }
  // Non-object config degrades to protective defaults with a reported issue (R-20).
  for (const config of ['nope', 42, []]) {
    const policy = normalizePolicy(config)
    assert.deepEqual(policy.sensitiveFiles, [])
    assert.equal(policy.builtinSensitiveAsk, true)
    assert.deepEqual(policy.configIssues, [{ code: 'config-not-object', count: 1 }])
  }
})

test('normalizePolicy: alwaysAsk defaults to true; a non-boolean is reported and keeps the protective default', () => {
  assert.equal(normalizePolicy({}).alwaysAsk, true)
  assert.equal(normalizePolicy({ alwaysAsk: false }).alwaysAsk, false)
  const invalid = normalizePolicy({ alwaysAsk: 'yes' })
  assert.equal(invalid.alwaysAsk, true)
  assert.deepEqual(invalid.configIssues, [{ code: 'always-ask-invalid', count: 1 }])
})

test('normalizePolicy: valid values pass through; tightenOnly true accepted', () => {
  const profile = normalizePolicy({
    sensitiveFiles: ['/workspace/secrets/token', 'C:/proj/.env.production'],
    builtinSensitiveAsk: false,
    askTimeoutMs: 5000,
    tightenOnly: true,
    rules: { 'data.delete.bulk': { enabled: true, allowlist: ['/tmp/cache'] } },
  })
  assert.deepEqual(profile.sensitiveFiles, ['/workspace/secrets/token', 'C:/proj/.env.production'])
  assert.equal(profile.builtinSensitiveAsk, false)
  assert.equal(profile.askTimeoutMs, 5000)
  assert.equal(profile.tightenOnly, true)
  assert.deepEqual(profile.rules['data.delete.bulk'], { enabled: true, allowlist: ['/tmp/cache'] })
  assert.deepEqual(profile.configIssues, [])

  // allowOnce is trusted per invocation only: accepted in call-scoped mode.
  const call = normalizePolicy({ ...profile, allowOnce: ['data.delete.bulk'] }, { callScoped: true })
  assert.deepEqual(call.allowOnce, ['data.delete.bulk'])
  assert.deepEqual(call.configIssues, [])
})

test('normalizePolicy: invalid values degrade per field while valid restrictive markers survive', () => {
  const policy = normalizePolicy({
    sensitiveFiles: ['/good/marked/file', 'relative/path', '/glob/*/bad', ''],
    builtinSensitiveAsk: 'no',
    askTimeoutMs: -1,
    rules: {
      'data.delete.bulk': { enabled: 'false', allowlist: ['bad', '/tmp/ok'] },
      'data.git.clean': 'nonsense',
      'data.delete.bulkk': { enabled: false }, // id outside the documented catalog
      [CHECK_FAILED_RULE]: { enabled: false }, // closed rule: not configurable
      'catastrophic.root': { enabled: false }, // catastrophic: not configurable
    },
    allowOnce: ['data.delete.bulk', ''], // profile mode: rejected wholesale
    tightenOnly: 'false',
  })
  // Valid restrictive markers retained; invalid ones skipped with issues.
  assert.deepEqual(policy.sensitiveFiles, ['/good/marked/file'])
  assert.equal(policy.builtinSensitiveAsk, true) // protective default
  assert.equal(policy.askTimeoutMs, 120000)
  // Invalid enabled flag skipped, valid allowlist kept (lead ruling: keep valid entries).
  assert.deepEqual(policy.rules['data.delete.bulk'], { allowlist: ['/tmp/ok'] })
  assert.equal(policy.rules['data.git.clean'], undefined)
  assert.equal(policy.rules['data.delete.bulkk'], undefined)
  assert.equal(policy.rules[CHECK_FAILED_RULE], undefined)
  assert.equal(policy.rules['catastrophic.root'], undefined)
  assert.deepEqual(policy.allowOnce, []) // never from a profile
  // Invalid tightenOnly leans restrictive.
  assert.equal(policy.tightenOnly, true)
  const codes = policy.configIssues.map((issue) => issue.code)
  for (const expected of [
    'sensitive-files-dropped', 'builtin-sensitive-ask-invalid', 'ask-timeout-invalid',
    'rule-enabled-invalid', 'rule-override-invalid', 'rule-override-unknown-id',
    'rule-override-not-configurable', 'allow-once-not-profile-key', 'tighten-only-invalid',
  ]) {
    assert.ok(codes.includes(expected), `missing config issue code ${expected}`)
  }
  const dropped = policy.configIssues.find((issue) => issue.code === 'sensitive-files-dropped')
  assert.equal(dropped.count, 3)
})

test('normalizePolicy: explicit tightenOnly false is rejected and recorded, never relaxes', () => {
  const policy = normalizePolicy({ tightenOnly: false })
  assert.equal(policy.tightenOnly, true)
  assert.deepEqual(policy.configIssues, [{ code: 'tighten-only-false-rejected', count: 1 }])
})

test('normalizePolicy: allowOnce is catalog-restricted even in call-scoped mode', () => {
  const call = normalizePolicy({
    allowOnce: ['data.delete.bulk', CHECK_FAILED_RULE, 'data.delete.bulkk', ''],
  }, { callScoped: true })
  assert.deepEqual(call.allowOnce, ['data.delete.bulk'])
  const codes = call.configIssues.map((issue) => issue.code)
  assert.ok(codes.includes('allow-once-not-configurable'))
  assert.ok(codes.includes('allow-once-unknown-id'))
  assert.ok(codes.includes('allow-once-dropped'))
})

test('normalizePolicy: rules dictionary stays a clean plain object under prototype keys', () => {
  const config = JSON.parse('{"rules":{"__proto__":{"enabled":false},"data.delete.bulk":{"enabled":false}}}')
  const policy = normalizePolicy(config)
  assert.deepEqual(Object.keys(policy.rules), ['data.delete.bulk'])
  assert.equal(Object.getPrototypeOf(policy.rules), Object.prototype)
  assert.equal(Object.getPrototypeOf({}).polluted, undefined)
  assert.ok(policy.configIssues.some((issue) => issue.code === 'rule-override-unknown-id'))
})

test('normalizePolicy: askTimeoutMs 0 maps to the bounded default, never unlimited', () => {
  assert.equal(normalizePolicy({ askTimeoutMs: 0 }).askTimeoutMs, 120000)
  assert.equal(normalizePolicy({ askTimeoutMs: 3600000 }).askTimeoutMs, 3600000)
  assert.equal(normalizePolicy({ askTimeoutMs: 3600001 }).askTimeoutMs, 120000)
})

test('normalizePolicy: unknown keys reported and ignored, guards unaffected (R-20)', () => {
  const policy = normalizePolicy({ trustedDirs: ['/tmp'], sensitiveFiles: [] })
  assert.deepEqual(policy.configIssues, [{ code: 'unknown-config-key', detail: 'trustedDirs', count: 1 }])
  assert.deepEqual(policy.sensitiveFiles, [])
})

test('normalizePolicy: idempotent on its own output', () => {
  const once = normalizePolicy({ sensitiveFiles: ['/a'], tightenOnly: true, rules: { 'data.delete.bulk': { enabled: false } } })
  const twice = normalizePolicy(once)
  assert.deepEqual(twice.sensitiveFiles, once.sensitiveFiles)
  assert.equal(twice.tightenOnly, true)
  assert.deepEqual(twice.rules['data.delete.bulk'], once.rules['data.delete.bulk'])
  assert.deepEqual(twice.configIssues, [])
  // Call-scoped allowOnce survives idempotent re-normalization for the same call.
  const callOnce = normalizePolicy({ ...once, allowOnce: ['data.delete.bulk'] }, { callScoped: true })
  const callTwice = normalizePolicy(callOnce, { callScoped: true })
  assert.deepEqual(callTwice.allowOnce, ['data.delete.bulk'])
  assert.deepEqual(callTwice.configIssues, [])
})

// ---------------------------------------------------------------------------
// isProtectedPath — builtin + marked protection for the evidence adapter
// ---------------------------------------------------------------------------

test('isProtectedPath: builtin credential basenames with platform case semantics', () => {
  const policy = normalizePolicy({})
  assert.equal(isProtectedPath('C:/Users/me/.ssh/id_rsa', policy, 'win32'), true)
  assert.equal(isProtectedPath('C:/Users/Me/.SSH/ID_RSA', policy, 'win32'), true) // folded
  assert.equal(isProtectedPath('/home/me/.ssh/id_rsa', policy, 'linux'), true)
  assert.equal(isProtectedPath('/home/me/.SSH/ID_RSA', policy, 'linux'), false) // strict
  assert.equal(isProtectedPath('/home/me/.SSH/ID_RSA', policy, undefined), true) // unknown folds
})

test('isProtectedPath: dotenv names stay free; hive prefixes, combos, .pub exclusion keep their semantics', () => {
  const policy = normalizePolicy({})
  // R-05: ordinary unmarked .env names are not builtin protected paths.
  assert.equal(isProtectedPath('D:/proj/.env.dev.local', policy, 'win32'), false)
  assert.equal(isProtectedPath('D:/proj/.env', policy, 'win32'), false)
  assert.equal(isProtectedPath('D:/proj/.env.example', policy, 'win32'), false)
  // DSR-018 list survivors stay protected.
  assert.equal(isProtectedPath('C:/Users/me/.npmrc', policy, 'win32'), true)
  assert.equal(isProtectedPath('C:/Windows/System32/config/SAM', policy, 'win32'), true)
  assert.equal(isProtectedPath('C:/Users/me/NTUSER.DAT.LOG1', policy, 'win32'), true)
  assert.equal(isProtectedPath('/home/me/.ssh/id_rsa.pub', policy, 'linux'), false)
})

test('isProtectedPath: builtinSensitiveAsk gates builtin names but never marked paths', () => {
  const marked = normalizePolicy({ builtinSensitiveAsk: false, sensitiveFiles: ['/etc/app/token'] })
  assert.equal(isProtectedPath('/home/me/.npmrc', marked, 'linux'), false)
  assert.equal(isProtectedPath('/etc/app/token', marked, 'linux'), true)
  const markedWindows = normalizePolicy({ builtinSensitiveAsk: false, sensitiveFiles: ['C:/Apps/Secret'] })
  assert.equal(isProtectedPath('c:/apps/secret', markedWindows, 'win32'), true)
  assert.equal(isProtectedPath('C:/Apps/secret', markedWindows, 'linux'), false)
})

test('isProtectedPath: malformed input and unmarked paths are not protected', () => {
  const policy = normalizePolicy({ sensitiveFiles: ['/a'] })
  assert.equal(isProtectedPath('', policy, 'win32'), false)
  assert.equal(isProtectedPath(null, policy, 'win32'), false)
  assert.equal(isProtectedPath('/a/b/ordinary.txt', policy, 'linux'), false)
})

// ---------------------------------------------------------------------------
// decide — catastrophic priority
// ---------------------------------------------------------------------------

test('decide: catastrophic identity denies first and is never waivable', () => {
  const evidence = {
    ...CLEAN,
    identities: [{ ruleId: 'catastrophic.device', path: '\\\\.\\PHYSICALDRIVE0', action: 'delete' }],
    issues: [{ kind: 'inventory', reason: 'failed' }],
    inlineCredential: true,
  }
  const policy = normalizePolicy({
    rules: { 'catastrophic.device': { enabled: false } },
    allowOnce: ['catastrophic.device'],
    tightenOnly: true,
  })
  const decision = decide(evidence, policy)
  assert.equal(decision.kind, 'deny')
  assert.equal(decision.ruleId, 'catastrophic.device')
  assert.deepEqual(decision.ruleIds, ['catastrophic.device'])
  assert.match(decision.reason, /cannot be approved/)
})

test('decide: catastrophic beats confirm hits and multiple identities list all rule ids', () => {
  const evidence = {
    ...CLEAN,
    identities: [
      { ruleId: 'catastrophic.git-metadata', path: 'E:/repo/.git', action: 'delete' },
      { ruleId: 'catastrophic.root', path: 'C:/', action: 'delete' },
    ],
    protectedHits: [{ path: 'C:/Users/me/.ssh/id_rsa', action: 'read-content' }],
  }
  const decision = decide(evidence, {})
  assert.equal(decision.kind, 'deny')
  assert.equal(decision.ruleId, 'catastrophic.root') // stable catalog order
  assert.deepEqual(decision.ruleIds, ['catastrophic.root', 'catastrophic.git-metadata'])
})

test('decide: git-history-destroy operation is catastrophic; preview is not', () => {
  const live = decide({ ...CLEAN, operations: [{ action: 'git-history-destroy', target: { kind: 'unknown', reason: 'x', knownScope: [] }, preview: false }] }, {})
  assert.equal(live.kind, 'deny')
  assert.equal(live.ruleId, 'catastrophic.git-history')
  const preview = decide({ ...CLEAN, operations: [{ action: 'git-history-destroy', target: { kind: 'unknown', reason: 'x', knownScope: [] }, preview: true }] }, {})
  assert.equal(preview.kind, 'allow')
})

// ---------------------------------------------------------------------------
// decide — closed operational failures (checks vs gaps)
// ---------------------------------------------------------------------------

test('decide: fault status, issues, and unreliable inventory deny under check-failed', () => {
  const fault = decide({ ...CLEAN, analysisStatus: 'fault' }, {})
  assert.equal(fault.kind, 'deny')
  assert.equal(fault.ruleId, CHECK_FAILED_RULE)

  const issue = decide({ ...CLEAN, issues: [{ kind: 'identity', reason: 'lstat failed', path: 'E:/x' }] }, {})
  assert.equal(issue.kind, 'deny')
  assert.equal(issue.ruleId, CHECK_FAILED_RULE)
  assert.match(issue.trigger, /identity/)

  const unreliable = decide({ ...CLEAN, inventory: { kind: 'unreliable', count: 3 } }, {})
  assert.equal(unreliable.kind, 'deny')
  assert.equal(unreliable.ruleId, CHECK_FAILED_RULE)

  const missingStatus = decide({ operations: [], candidates: [] }, {})
  assert.equal(missingStatus.kind, 'deny')
  assert.equal(missingStatus.ruleId, CHECK_FAILED_RULE)

  const missingEvidence = decide(null, {})
  assert.equal(missingEvidence.kind, 'deny')
  assert.equal(missingEvidence.ruleId, CHECK_FAILED_RULE)
})

test('decide: check-failed is non-configurable and yields to catastrophic priority', () => {
  const policy = normalizePolicy({ rules: { [CHECK_FAILED_RULE]: { enabled: false } }, allowOnce: [CHECK_FAILED_RULE] })
  const denied = decide({ ...CLEAN, analysisStatus: 'fault' }, policy)
  assert.equal(denied.kind, 'deny')
  assert.equal(denied.ruleId, CHECK_FAILED_RULE)

  const withIdentity = decide({
    ...CLEAN,
    analysisStatus: 'fault',
    identities: [{ ruleId: 'catastrophic.root', path: 'C:/', action: 'delete' }],
  }, {})
  assert.equal(withIdentity.ruleId, 'catastrophic.root')
})

test('decide: partial coverage with gaps but no candidates stays allow (DSR-027)', () => {
  const decision = decide({
    ...CLEAN,
    analysisStatus: 'partial',
    gaps: [{ kind: 'no-analyzer', unitId: 'u1', origin: {} }],
  }, {})
  assert.equal(decision.kind, 'allow')
  assert.equal(decision.gaps.length, 1)
})

test('decide: deletion operations without inventory deny as a check failure', () => {
  const decision = decide({
    ...CLEAN,
    operations: [{ action: 'delete', target: { kind: 'exact', paths: ['E:/a.txt'] }, recursive: false, preview: false }],
  }, {})
  assert.equal(decision.kind, 'deny')
  assert.equal(decision.ruleId, CHECK_FAILED_RULE)
  assert.match(decision.trigger, /no inventory/)
})

// ---------------------------------------------------------------------------
// decide — R-07 deletion tiers
// ---------------------------------------------------------------------------

const deleteOps = (paths) => paths.map((path) => ({
  action: 'delete',
  target: { kind: 'exact', paths: [path] },
  recursive: false,
  preview: false,
}))

test('decide: exact inventory within threshold allows as data.delete.ordinary', () => {
  const evidence = {
    ...CLEAN,
    operations: deleteOps(['E:/a', 'E:/b', 'E:/c']),
    inventory: { kind: 'exact', count: 3, files: ['E:/a', 'E:/b', 'E:/c'], links: [], directories: [], roots: ['E:/'], unknown: [] },
  }
  const decision = decide(evidence, {})
  assert.equal(decision.kind, 'allow')
  assert.equal(decision.ruleId, 'data.delete.ordinary')
})

test('decide: exact inventory beyond threshold confirms data.delete.bulk', () => {
  const files = Array.from({ length: ALLOW_THRESHOLD + 5 }, (_, index) => `E:/f${index}`)
  const evidence = {
    ...CLEAN,
    operations: deleteOps(files),
    inventory: { kind: 'exact', count: files.length, files, links: [], directories: [], roots: ['E:/'], unknown: [] },
  }
  const decision = decide(evidence, {})
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'data.delete.bulk')
  assert.equal(decision.scope.count, files.length) // structured value kept for recheck
})

test('decide: lower-bound inventory never proves the threshold, confirms bulk', () => {
  const evidence = {
    ...CLEAN,
    operations: deleteOps(['E:/dir']),
    inventory: { kind: 'lower-bound', count: 2, files: ['E:/one'], links: [], directories: [], roots: ['E:/dir'], unknown: [] },
  }
  const decision = decide(evidence, {})
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'data.delete.bulk')
})

test('decide: exact count plus unobserved range is treated as incomplete, confirms bulk', () => {
  const evidence = {
    ...CLEAN,
    operations: deleteOps(['E:/a']),
    inventory: { kind: 'exact', count: 1, files: ['E:/a'], links: [], directories: [], roots: ['E:/'], unknown: ['E:/rest (not observed)'] },
  }
  const decision = decide(evidence, {})
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'data.delete.bulk')
})

test('decide: unknown and pattern deletion targets confirm data.delete.dynamic with provable scope', () => {
  const evidence = {
    ...CLEAN,
    operations: [
      { action: 'delete', target: { kind: 'unknown', reason: 'unresolved variable $t', knownScope: ['E:/build'] }, recursive: 'unknown', preview: false },
      { action: 'delete', target: { kind: 'pattern', base: 'E:/logs', pattern: '*.tmp' }, recursive: true, preview: false },
    ],
    inventory: { kind: 'exact', count: 0, files: [], links: [], directories: [], roots: [], unknown: [] },
  }
  const decision = decide(evidence, {})
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'data.delete.dynamic')
  assert.ok(decision.scope.knownScope.includes('E:/build'))
  assert.ok(decision.scope.notes.some((note) => note.includes('*.tmp')))
})

test('decide: dynamic deletion without a verifiable scope cannot be confirmed', () => {
  const result = decide({ ...CLEAN,
    operations: [{ action: 'delete', target: { kind: 'unknown', reason: 'dynamic target' } }],
    inventory: { kind: 'exact', count: 0, files: [], links: [], directories: [], roots: [], unknown: ['dynamic target'] },
  }, {})
  assert.equal(result.kind, 'deny')
  assert.equal(result.ruleId, 'data.delete.dynamic')
})

test('decide: recursion-unproven exact target confirms dynamic', () => {
  const evidence = {
    ...CLEAN,
    operations: [{ action: 'delete', target: { kind: 'exact', paths: ['E:/maybe-dir'] }, recursive: 'unknown', preview: false }],
    inventory: { kind: 'exact', count: 0, files: [], links: [], directories: [], roots: [], unknown: [] },
  }
  const decision = decide(evidence, {})
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'data.delete.dynamic')
})

test('decide: uniformly git deletion maps to data.git.* rules and move to data.move.source', () => {
  const git = decide({
    ...CLEAN,
    operations: [{ action: 'git-clean', target: { kind: 'exact', paths: ['E:/r/a'] }, recursive: false, preview: false }],
    inventory: { kind: 'exact', count: 1, files: ['E:/r/a'], links: [], directories: [], roots: [], unknown: [] },
  }, {})
  assert.equal(git.kind, 'allow')
  assert.equal(git.ruleId, 'data.git.clean')

  const gitBulk = decide({
    ...CLEAN,
    operations: [{ action: 'git-worktree-remove', target: { kind: 'subtree', root: 'E:/wt' }, recursive: true, preview: false }],
    inventory: { kind: 'exact', count: 40, files: ['E:/wt/f'], links: [], directories: [], roots: ['E:/wt'], unknown: [] },
  }, {})
  assert.equal(gitBulk.kind, 'confirm')
  assert.equal(gitBulk.ruleId, 'data.git.worktree')

  const move = decide({
    ...CLEAN,
    operations: [{ action: 'move-source', target: { kind: 'exact', paths: ['E:/s1'] }, recursive: false, preview: false }],
    inventory: { kind: 'exact', count: 1, files: ['E:/s1'], links: [], directories: [], roots: [], unknown: [] },
  }, {})
  assert.equal(move.kind, 'allow')
  assert.equal(move.ruleId, 'data.move.source')
})

test('decide: gitRisk escalates to data.git.worktree confirmation even within threshold', () => {
  const evidence = {
    ...CLEAN,
    operations: [{ action: 'git-worktree-remove', target: { kind: 'subtree', root: 'E:/wt' }, recursive: true, preview: false }],
    inventory: { kind: 'exact', count: 2, files: ['E:/wt/a'], links: [], directories: [], roots: ['E:/wt'], unknown: [] },
    gitRisk: { paths: ['E:/wt'], reason: 'worktree has uncommitted changes' },
  }
  const decision = decide(evidence, {})
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'data.git.worktree')
  assert.ok(decision.scope.knownScope.includes('E:/wt'))
})

// ---------------------------------------------------------------------------
// decide — credential rules
// ---------------------------------------------------------------------------

test('decide: protected content ops confirm per rule; metadata-only never does', () => {
  const read = decide({
    ...CLEAN,
    protectedHits: [{ path: 'C:/Users/me/.ssh/id_rsa', action: 'read-content' }],
  }, {})
  assert.equal(read.kind, 'confirm')
  assert.equal(read.ruleId, 'credential.file.read')

  const copy = decide({ ...CLEAN, protectedHits: [{ path: '/a/.env', action: 'copy-content' }] }, {})
  assert.equal(copy.ruleId, 'credential.file.read')

  const mutate = decide({
    ...CLEAN,
    protectedHits: [
      { path: '/a/.env', action: 'delete' },
      { path: '/b/token', action: 'truncate-content' },
      { path: '/c/.npmrc', action: 'move-source' },
    ],
  }, {})
  assert.equal(mutate.kind, 'confirm')
  assert.equal(mutate.ruleId, 'credential.file.mutate')
  assert.equal(mutate.scope.protected.length, 3)

  const metadata = decide({ ...CLEAN, protectedHits: [{ path: '/a/.env', action: 'metadata' }] }, {})
  assert.equal(metadata.kind, 'allow')
})

test('decide: unknown action on a protected path fails safe into the mutate rule', () => {
  const decision = decide({ ...CLEAN, protectedHits: [{ path: '/a/.env', action: 'mysterious' }] }, {})
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'credential.file.mutate')
})

test('decide: inline credential denies correctively (R-11)', () => {
  const decision = decide({ ...CLEAN, inlineCredential: true }, {})
  assert.equal(decision.kind, 'deny')
  assert.equal(decision.ruleId, 'credential.inline')
})

// ---------------------------------------------------------------------------
// decide — credential text scan (R-04 凭据防泄露)
// ---------------------------------------------------------------------------

test('decide: credentialTextMention confirms credential.file.read for a read-face call', () => {
  const decision = decide({
    ...CLEAN,
    operations: [{ action: 'read-content', target: { kind: 'unknown', reason: 'unresolved variable $t' }, preview: false }],
    credentialTextMention: true,
  }, {})
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'credential.file.read')
  assert.ok(decision.scope.notes.some((note) => note.includes('credential name referenced in text')))
})

test('decide: a mutate operation upgrades the text-scan hit to credential.file.mutate', () => {
  const decision = decide({
    ...CLEAN,
    operations: [
      { action: 'read-content', target: { kind: 'unknown', reason: 'unresolved variable $t', knownScope: ['E:/build'] }, preview: false },
      { action: 'delete', target: { kind: 'unknown', reason: 'unresolved variable $t', knownScope: ['E:/build'] }, preview: false },
    ],
    inventory: { kind: 'exact', count: 0, files: [], links: [], directories: [], roots: [], unknown: [] },
    credentialTextMention: true,
  }, {})
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'credential.file.mutate')
  assert.deepEqual(decision.ruleIds, ['data.delete.dynamic', 'credential.file.mutate'])
})

test('decide: no flag or false flag never produces the text-scan confirmation', () => {
  const readFace = { ...CLEAN, operations: [{ action: 'read-content', target: { kind: 'unknown', reason: 'u' } }] }
  assert.equal(decide(readFace, {}).kind, 'allow')
  assert.equal(decide({ ...readFace, credentialTextMention: false }, {}).kind, 'allow')
  // Metadata operations are not in the mutate set: they never upgrade the rule.
  const metadataOnly = {
    ...CLEAN,
    operations: [{ action: 'metadata', target: { kind: 'unknown', reason: 'u' } }],
    credentialTextMention: true,
  }
  const decision = decide(metadataOnly, {})
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'credential.file.read')
})

test('decide: protectedHits already carrying the same rule suppresses the duplicate text-scan hit', () => {
  const decision = decide({
    ...CLEAN,
    operations: [{ action: 'read-content', target: { kind: 'unknown', reason: 'u' } }],
    protectedHits: [{ path: 'C:/Users/me/.npmrc', action: 'read-content' }],
    credentialTextMention: true,
  }, {})
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'credential.file.read')
  assert.deepEqual(decision.ruleIds, ['credential.file.read'])
})

test('decide: the text-scan hit is not waivable by allowOnce or rule config', () => {
  const evidence = {
    ...CLEAN,
    operations: [{ action: 'read-content', target: { kind: 'unknown', reason: 'u' } }],
    credentialTextMention: true,
  }
  const decision = decide(evidence, normalizePolicy({ allowOnce: ['credential.file.read'], rules: { 'credential.file.read': { enabled: false } } }))
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'credential.file.read')
})

test('decide: credential confirm priority over deletion confirms, merged into one request', () => {
  const files = Array.from({ length: 30 }, (_, index) => `E:/f${index}`)
  const decision = decide({
    ...CLEAN,
    operations: deleteOps(files),
    inventory: { kind: 'exact', count: 30, files, links: [], directories: [], roots: ['E:/'], unknown: [] },
    protectedHits: [{ path: 'E:/f0', action: 'delete' }],
  }, {})
  assert.equal(decision.kind, 'confirm')
  assert.equal(decision.ruleId, 'credential.file.mutate')
  assert.deepEqual(decision.ruleIds, ['credential.file.mutate', 'data.delete.bulk'])
  assert.ok(decision.scope.protected.length === 1 && decision.scope.count === 30)
})

// ---------------------------------------------------------------------------
// decide — execution candidates (lead rulings)
// ---------------------------------------------------------------------------

test('decide: unverified-effect confirms with proven scope, denies without', () => {
  const confirmed = decide({
    ...CLEAN,
    candidates: [{ kind: 'unverified-effect', reason: 'rm -rf inside eval string', knownScope: ['/tmp/build'] }],
  }, {})
  assert.equal(confirmed.kind, 'confirm')
  assert.equal(confirmed.ruleId, 'execution.unverified-effect')
  assert.ok(confirmed.scope.knownScope.includes('/tmp/build'))

  const denied = decide({
    ...CLEAN,
    candidates: [{ kind: 'unverified-effect', reason: 'destructive clue without facts' }],
  }, {})
  assert.equal(denied.kind, 'deny')
  assert.equal(denied.ruleId, 'execution.unverified-effect')
})

test('decide: dynamic-execution confirms with proven scope, denies without; allow only with no candidate', () => {
  const confirmed = decide({
    ...CLEAN,
    candidates: [{ kind: 'dynamic-execution', reason: '& $cmd', knownScope: ['C:/scripts/run.ps1'] }],
  }, {})
  assert.equal(confirmed.kind, 'confirm')
  assert.equal(confirmed.ruleId, 'execution.dynamic-command')

  const denied = decide({ ...CLEAN, candidates: [{ kind: 'dynamic-execution', reason: '& $cmd' }] }, {})
  assert.equal(denied.kind, 'deny')
  assert.equal(denied.ruleId, 'execution.dynamic-command')

  // Unknown candidate kind fails safe into unverified-effect semantics.
  const unknownKind = decide({ ...CLEAN, candidates: [{ kind: 'mystery', reason: 'r' }] }, {})
  assert.equal(unknownKind.kind, 'deny')
  assert.equal(unknownKind.ruleId, 'execution.unverified-effect')

  // Gaps plus a candidate never allow: the candidate decides.
  const gapAndCandidate = decide({
    ...CLEAN,
    analysisStatus: 'partial',
    gaps: [{ kind: 'no-analyzer', unitId: 'u1' }],
    candidates: [{ kind: 'unverified-effect', reason: 'clue' }],
  }, {})
  assert.equal(gapAndCandidate.kind, 'deny')
})

// ---------------------------------------------------------------------------
// decide — per-rule config and one-time contract
// ---------------------------------------------------------------------------

test('decide: enabled=false removes a confirm hit; catastrophic unaffected', () => {
  const files = Array.from({ length: 25 }, (_, index) => `E:/f${index}`)
  const evidence = {
    ...CLEAN,
    operations: deleteOps(files),
    inventory: { kind: 'exact', count: 25, files, links: [], directories: [], roots: ['E:/'], unknown: [] },
  }
  const waived = decide(evidence, normalizePolicy({ rules: { 'data.delete.bulk': { enabled: false } } }))
  assert.equal(waived.kind, 'allow')
  assert.deepEqual(waived.waived, ['data.delete.bulk'])

  const kept = decide(evidence, normalizePolicy({ rules: { 'data.delete.other': { enabled: false } } }))
  assert.equal(kept.kind, 'confirm')
})

test('decide: allowlist waives only when every target is listed and nothing is unobserved', () => {
  const evidence = {
    ...CLEAN,
    operations: deleteOps(['E:/cache/a', 'E:/cache/b']),
    inventory: { kind: 'exact', count: 25, files: ['E:/cache/a'], links: [], directories: [], roots: ['E:/cache'], unknown: [] },
  }
  const full = decide(evidence, normalizePolicy({
    rules: { 'data.delete.bulk': { allowlist: ['E:/cache/a', 'E:/cache/b', 'E:/cache'] } },
  }))
  assert.equal(full.kind, 'allow')

  const partial = decide(evidence, normalizePolicy({
    rules: { 'data.delete.bulk': { allowlist: ['E:/cache/a'] } },
  }))
  assert.equal(partial.kind, 'confirm')

  const withUnknown = decide({
    ...evidence,
    inventory: { ...evidence.inventory, unknown: ['E:/more'] },
  }, normalizePolicy({
    rules: { 'data.delete.bulk': { allowlist: ['E:/cache/a', 'E:/cache/b', 'E:/cache'] } },
  }))
  assert.equal(withUnknown.kind, 'confirm') // unobserved range defeats the waiver
})

test('decide: allowOnce waives once for the current call; adapter consumes the id', () => {
  const evidence = {
    ...CLEAN,
    operations: deleteOps(['E:/x']),
    inventory: { kind: 'exact', count: 30, files: ['E:/x'], links: [], directories: [], roots: ['E:/'], unknown: [] },
  }
  const decision = decide(evidence, { allowOnce: ['data.delete.bulk'] })
  assert.equal(decision.kind, 'allow')
  assert.deepEqual(decision.waived, ['data.delete.bulk'])
})

test('decide: tightenOnly is true by default and permanently locks credential rules', () => {
  const evidence = { ...CLEAN, protectedHits: [{ path: '/a/.env', action: 'read-content' }] }
  const locked = decide(evidence, normalizePolicy({
    tightenOnly: true,
    rules: { 'credential.file.read': { enabled: false } },
    allowOnce: ['credential.file.read'],
  }))
  assert.equal(locked.kind, 'confirm')
  assert.equal(locked.ruleId, 'credential.file.read')

  // The default policy carries no tightenOnly key; credential rules still stay
  // locked (受保护项始终生效), so there is no unlock path for them at all.
  const defaultLocked = decide(evidence, normalizePolicy({
    rules: { 'credential.file.read': { enabled: false } },
    allowOnce: ['credential.file.read'],
  }))
  assert.equal(defaultLocked.kind, 'confirm')
  assert.equal(defaultLocked.ruleId, 'credential.file.read')

  const dataWaived = decide({
    ...CLEAN,
    operations: deleteOps(Array.from({ length: 21 }, (_, index) => `E:/f${index}`)),
    inventory: { kind: 'exact', count: 21, files: ['E:/f0'], links: [], directories: [], roots: ['E:/'], unknown: [] },
  }, normalizePolicy({ tightenOnly: true, rules: { 'data.delete.bulk': { enabled: false } } }))
  assert.equal(dataWaived.kind, 'allow')
})

test('decide: catastrophic identity survives tightenOnly and any config', () => {
  const decision = decide({
    ...CLEAN,
    identities: [{ ruleId: 'catastrophic.device', path: '\\\\.\\PHYSICALDRIVE0', action: 'delete' }],
  }, normalizePolicy({ tightenOnly: true, allowOnce: ['catastrophic.device'], rules: { 'catastrophic.device': { enabled: false } } }))
  assert.equal(decision.kind, 'deny')
})

// ---------------------------------------------------------------------------
// decide — combine and shape
// ---------------------------------------------------------------------------

test('decide: deny outranks confirm; clean evidence allows; decision is pure (no aliasing)', () => {
  const evidence = {
    ...CLEAN,
    candidates: [{ kind: 'unverified-effect', reason: 'clue' }],
    protectedHits: [{ path: '/a/.env', action: 'read-content' }],
  }
  const decision = decide(evidence, {})
  assert.equal(decision.kind, 'deny')
  assert.deepEqual(decision.ruleIds, ['execution.unverified-effect'])
  // input evidence untouched
  assert.equal(evidence.protectedHits.length, 1)
  assert.equal(evidence.candidates.length, 1)
})

test('decide: read-only operations and allow-graded evidence allow without rule hits', () => {
  const decision = decide({
    ...CLEAN,
    operations: [{ action: 'read-content', target: { kind: 'exact', paths: ['E:/notes.txt'] }, recursive: false, preview: false }],
  }, {})
  assert.equal(decision.kind, 'allow')
  assert.equal(decision.ruleId, undefined)
})

// ---------------------------------------------------------------------------
// renderDecision — fixed block + redaction
// ---------------------------------------------------------------------------

test('renderDecision: deny block drops an empty scope line instead of "not captured"', () => {
  const decision = decide({ ...CLEAN, inlineCredential: true }, {})
  const text = renderDecision(decision)
  const lines = text.split('\n')
  assert.equal(lines.length, 5)
  assert.match(lines[0], /^\[GUARDRAILS\] DENY credential\.inline \(credential\)$/)
  assert.match(lines[1], /^Why:     /)
  assert.match(lines[2], /^Trigger: /)
  assert.match(lines[3], /^Effect:  /)
  assert.match(lines[4], /^Next:    /)
  assert.doesNotMatch(text, /not captured/)
  assert.doesNotMatch(text, /^Scope:/m)
})

test('renderDecision: check-failed carries the real gap code in Trigger and omits an empty Scope', () => {
  const decision = decide({
    ...CLEAN,
    analysisStatus: 'fault',
    gaps: [{ code: 'GUARD_PATCH_PARSE_FAILED' }],
  }, {})
  assert.equal(decision.kind, 'deny')
  assert.equal(decision.ruleId, CHECK_FAILED_RULE)
  assert.match(decision.trigger, /codes: GUARD_PATCH_PARSE_FAILED/)
  const text = renderDecision(decision)
  assert.match(text, /Trigger: .*GUARD_PATCH_PARSE_FAILED/)
  assert.doesNotMatch(text, /not captured/)
  assert.doesNotMatch(text, /^Scope:/m)
})

test('every deny block declares "Nothing was executed" exactly once', () => {
  const catastrophic = decide({ ...CLEAN, identities: [{ ruleId: 'catastrophic.device', path: '\\\\.\\PHYSICALDRIVE0', action: 'delete' }] }, {})
  const catText = renderDecision(catastrophic)
  assert.match(catText, /Next:    Nothing was executed\. /)
  assert.equal((catText.match(/Nothing was executed\./g) ?? []).length, 1)

  const unknownStage = renderDecision({
    kind: 'deny',
    ruleId: CHECK_FAILED_RULE,
    reason: 'execution.check-failed (stage SOME_UNKNOWN_STAGE): x',
    trigger: 'check failure: SOME_UNKNOWN_STAGE',
  })
  assert.match(unknownStage, /Next:    Nothing was executed\. /)
  assert.equal((unknownStage.match(/Nothing was executed\./g) ?? []).length, 1)

  const checkFailed = decide({ ...CLEAN, analysisStatus: 'fault' }, {})
  const checkText = renderDecision(checkFailed)
  assert.match(checkText, /Next:    Nothing was executed\. Retry with a clearer/)
  assert.equal((checkText.match(/Nothing was executed\./g) ?? []).length, 1)
})

test('renderDecision: a GUARD_SCOPE_CHANGED stage replaces the generic effect and next', () => {
  const text = renderDecision({
    kind: 'deny',
    ruleId: CHECK_FAILED_RULE,
    reason: 'execution.check-failed (stage GUARD_SCOPE_CHANGED): the confirmed scope changed',
    trigger: 'check failure: GUARD_SCOPE_CHANGED; codes: GUARD_SCOPE_CHANGED',
    scope: { knownScope: ['E:/build'] },
  })
  assert.match(text, /Effect:  The operation or its target set changed between the confirmation and dispatch/)
  assert.match(text, /Next:    Nothing was executed\. Re-issue the call and confirm the scope shown at that time\./)
  assert.doesNotMatch(text, /A required check did not finish/)
})

test('renderDecision: confirm block names the rule and lists scope', () => {
  const decision = decide({ ...CLEAN, protectedHits: [{ path: '/a/.env', action: 'delete' }] }, {})
  const lines = renderDecision(decision).split('\n')
  assert.match(lines[0], /^\[GUARDRAILS\] CONFIRM credential\.file\.mutate \(credential\)$/)
  assert.match(renderDecision(decision), /Scope:.*\/a\/\.env/)
  assert.match(renderDecision(decision), /Next:/)
})

test('renderDecision: bulk scope states at least 21 and never a precise total', () => {
  const files = Array.from({ length: 35 }, (_, index) => `E:/f${index}`)
  const decision = decide({
    ...CLEAN,
    operations: deleteOps(files),
    inventory: { kind: 'exact', count: 35, files, links: [], directories: [], roots: ['E:/'], unknown: [] },
  }, {})
  const text = renderDecision(decision)
  assert.match(text, /at least 21/)
  assert.doesNotMatch(text, /35/)
})

test('renderDecision: redacts credential-like strings in Trigger and Scope, allow renders null', () => {
  const decision = decide({
    ...CLEAN,
    candidates: [{ kind: 'unverified-effect', reason: 'token sk-abcdefghijklmnopqrstuvwxyz012345 passed around', knownScope: ['/tmp'] }],
  }, {})
  const text = renderDecision(decision)
  assert.match(text, /\[REDACTED(?::[a-z]+)?\]/)
  assert.doesNotMatch(text, /sk-abcdefghijklmnopqrstuvwxyz012345/)

  assert.equal(renderDecision({ kind: 'allow', ruleId: 'data.delete.ordinary' }), null)
  assert.equal(renderDecision(null), null)
  assert.equal(renderDecision(undefined), null)
})

test('renderDecision: check-failed block uses the stable id and execution category', () => {
  const decision = decide({ ...CLEAN, analysisStatus: 'fault' }, {})
  const lines = renderDecision(decision).split('\n')
  assert.match(lines[0], /^\[GUARDRAILS\] DENY execution\.check-failed \(execution\)$/)
})
