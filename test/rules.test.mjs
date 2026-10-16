// V2 target-model tests: narrow builtin credential list + user-marked files.
// The lists live in rules.js (single maintenance point); these tests pin the
// narrow V2 shape so the retired V1 breadth (directory segments, key suffixes,
// browser/DPAPI combos) cannot creep back silently. Run: node --test test/

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  CRED_BASENAMES,
  CRED_COMBOS,
  RULE_KEYS,
  evaluateRules,
} from '../src/core/rules.js'
import { pathTargetsCredentials } from '../src/core/path-check.js'

test('V2 builtin list is the narrow file-level set (DSR-015)', () => {
  // Named credential files only.
  for (const name of ['id_rsa', 'id_ed25519', '.npmrc', '.netrc', '.git-credentials', '.pgpass', '.pypirc']) {
    assert.ok(CRED_BASENAMES.has(name), `${name} must stay in the builtin list`)
  }
  // The retired V1 breadth must NOT be reachable through the basename list.
  for (const retired of ['.pem', '.key', '.p12']) {
    assert.equal(
      [...CRED_BASENAMES].some((n) => n.endsWith(retired)),
      false,
      `suffix-style matching (${retired}) must stay retired`,
    )
  }
  // AWS credentials and the system hives are the only combos.
  assert.deepEqual(
    CRED_COMBOS.map((c) => c.join('/')).sort(),
    ['.aws/credentials', 'system32/config/sam', 'system32/config/security', 'system32/config/system'],
  )
})

test('retired V1 rule families no longer match (behavioral ablation)', () => {
  // Directory segments: a bare credential DIRECTORY is no longer a target —
  // only named files inside it are.
  assert.equal(pathTargetsCredentials('C:/Users/me/.ssh'), false)
  assert.equal(pathTargetsCredentials('C:/Users/me/.ssh/config'), false, 'ssh config stays free (DSR-013 intent, now trivially)')
  assert.equal(pathTargetsCredentials('C:/Users/me/.kube/config'), false, 'mixed-use files are user-mark territory')
  assert.equal(pathTargetsCredentials('C:/Users/me/.gnupg'), false)
  // Key suffixes: retired from matching.
  assert.equal(pathTargetsCredentials('C:/keys/prod.pem'), false)
  assert.equal(pathTargetsCredentials('C:/keys/prod.key'), false)
  assert.equal(pathTargetsCredentials('C:/Users/me/.ssh/campfire-hk.pem'), false)
  // Browser profiles / DPAPI combos: retired.
  assert.equal(pathTargetsCredentials('C:/Users/me/AppData/Local/Google/Chrome/User Data/Default/Cookies'), false)
  assert.equal(pathTargetsCredentials('C:/Users/me/AppData/Roaming/Microsoft/Protect/x'), false)
  // Mixed-use carriers: retired (user marks them explicitly).
  assert.equal(pathTargetsCredentials('C:/Users/me/.docker/config.json'), false)
  assert.equal(pathTargetsCredentials('C:/Users/me/.config/gcloud/legacy_credentials/x.json'), false)
})

test('builtin list still covers the named credential files end-to-end', () => {
  assert.equal(pathTargetsCredentials('C:/Users/me/.ssh/id_rsa'), true)
  assert.equal(pathTargetsCredentials('C:/Users/me/.ssh/id_ed25519'), true)
  assert.equal(pathTargetsCredentials('C:/Users/me/.git-credentials'), true)
  assert.equal(pathTargetsCredentials('C:/Users/me/.netrc'), true)
  assert.equal(pathTargetsCredentials('C:/Users/me/.npmrc'), true)
  assert.equal(pathTargetsCredentials('C:/Users/me/ntuser.dat'), true)
  // Hive transaction logs carry the same data as the hive.
  assert.equal(pathTargetsCredentials('C:/Users/me/ntuser.dat.LOG1'), true)
  assert.equal(pathTargetsCredentials('C:/Users/me/usrclass.dat.LOG2'), true)
  assert.equal(pathTargetsCredentials('C:/Users/me/ntuser.dat.regtrans-ms'), true)
  // The AWS shared-credentials file (combo, not a basename).
  assert.equal(pathTargetsCredentials('C:/Users/me/.aws/credentials'), true)
  // System hives.
  assert.equal(pathTargetsCredentials('C:/Windows/System32/config/SAM'), true)
  assert.equal(pathTargetsCredentials('C:/Windows/System32/config/SYSTEM'), true)
  // Public half of a key pair stays free.
  assert.equal(pathTargetsCredentials('C:/Users/me/.ssh/id_rsa.pub'), false)
  // Case-insensitive.
  assert.equal(pathTargetsCredentials('C:/Users/me/.SSH/ID_RSA'), true)
})

test('DSH-managed credential files stay on the list (DSR-003 intent)', () => {
  assert.equal(pathTargetsCredentials('C:/Users/FengZhiHen/.dsh/.credentials.yaml'), true)
  assert.equal(pathTargetsCredentials('C:/Users/FengZhiHen/.dsh/.auteur-media-secret'), true)
  // But .dsh itself remains a non-credential directory.
  assert.equal(pathTargetsCredentials('C:/Users/FengZhiHen/.dsh/sessions/abc/session.jsonl.zstd'), false)
})

// ---------- V2 config evaluation ----------

test('RULE_KEYS is exactly the V2 pair', () => {
  assert.deepEqual(RULE_KEYS, ['sensitiveFiles', 'credentialsReadAsk'])
})

test('evaluateRules: defaults (empty marks, builtin list on)', () => {
  assert.deepEqual(evaluateRules({}), { sensitiveFiles: [], credentialsReadAsk: true })
  assert.deepEqual(evaluateRules(undefined), { sensitiveFiles: [], credentialsReadAsk: true })
})

test('evaluateRules: accepts explicit values', () => {
  assert.deepEqual(
    evaluateRules({ sensitiveFiles: ['E:/p/.env.production'], credentialsReadAsk: false }),
    { sensitiveFiles: ['E:/p/.env.production'], credentialsReadAsk: false },
  )
})

test('evaluateRules: mount-time validation fails loudly', () => {
  assert.throws(() => evaluateRules(null), /must be an object/)
  assert.throws(() => evaluateRules([]), /must be an object/)
  assert.throws(() => evaluateRules({ bogus: true }), /unknown config key/)
  assert.throws(() => evaluateRules({ credentialsReadAsk: 'yes' }), /must be a boolean/)
  assert.throws(() => evaluateRules({ sensitiveFiles: 'E:/p/.env' }), /must be an array/)
  assert.throws(() => evaluateRules({ sensitiveFiles: ['.env'] }), /absolute file paths/)
  assert.throws(() => evaluateRules({ sensitiveFiles: ['E:/p', ''] }), /non-empty strings/)
})
