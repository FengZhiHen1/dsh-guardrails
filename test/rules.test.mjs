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
  // The confirmed combos: AWS credentials, system hives, and the 2026-11 CLI/cloud
  // credential carriers (exact trailing segment combinations, never directories).
  assert.deepEqual(
    CRED_COMBOS.map((c) => c.join('/')).sort(),
    [
      '.aws/credentials', '.azure/accessToken.json', '.azure/accessTokens.json', '.config/gcloud/access_tokens.db',
      '.config/gcloud/application_default_credentials.json', '.config/gcloud/credentials.db',
      '.config/gh/hosts.yml', '.docker/config.json', '.kube/config',
      'system32/config/sam', 'system32/config/security', 'system32/config/system',
    ],
  )
})

test('retired V1 rule families no longer match (behavioral ablation)', () => {
  // Directory segments: a bare credential DIRECTORY is no longer a target —
  // only named files inside it are.
  assert.equal(pathTargetsCredentials('C:/Users/me/.ssh'), false)
  assert.equal(pathTargetsCredentials('C:/Users/me/.ssh/config'), false, 'ssh config stays free (DSR-013 intent, now trivially)')
  assert.equal(pathTargetsCredentials('C:/Users/me/.gnupg'), false)
  // Key suffixes: retired from matching.
  assert.equal(pathTargetsCredentials('C:/keys/prod.pem'), false)
  assert.equal(pathTargetsCredentials('C:/keys/prod.key'), false)
  assert.equal(pathTargetsCredentials('C:/Users/me/.ssh/campfire-hk.pem'), false)
  // Browser profiles / DPAPI combos: retired.
  assert.equal(pathTargetsCredentials('C:/Users/me/AppData/Local/Google/Chrome/User Data/Default/Cookies'), false)
  assert.equal(pathTargetsCredentials('C:/Users/me/AppData/Roaming/Microsoft/Protect/x'), false)
  // quality-floor: ignore unstaged-ref Synthetic path fixture; this file is neither read nor executed.
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

// ---------- 2026-11 confirmed additions (F-25) ----------

test('confirmed 2026-11 combo additions match their exact files', () => {
  for (const path of [
    'C:/Users/me/.kube/config',
    'C:/Users/me/.docker/config.json',
    'C:/Users/me/.config/gh/hosts.yml',
    'C:/Users/me/.config/gcloud/application_default_credentials.json',
    'C:/Users/me/.config/gcloud/credentials.db',
    'C:/Users/me/.config/gcloud/access_tokens.db',
    'C:/Users/me/.azure/accessTokens.json',
    'C:/Users/me/.azure/accessToken.json',
  ]) {
    assert.equal(pathTargetsCredentials(path), true, path)
    // Case-insensitive on Windows paths.
    assert.equal(pathTargetsCredentials(path.replace('/me/', '/ME/').replace(/\.config/iu, '.CONFIG')), true, path)
  }
  // POSIX compares exactly, so the manifest keeps the canonical camelCase spellings.
  assert.equal(pathTargetsCredentials('/home/u/.azure/accessToken.json'), true)
  assert.equal(pathTargetsCredentials('/home/u/.azure/accessTokens.json'), true)
  assert.equal(pathTargetsCredentials('/home/u/.azure/accesstoken.json'), false)
})

test('confirmed 2026-11 combo additions keep near-misses and non-carriers free', () => {
  // Trailing segment combination must be exact: extra/renamed/dropped segments miss.
  for (const path of [
    'C:/Users/me/notes/.kube/readme.md',
    'C:/Users/me/.kube/config.bak',
    'C:/Users/me/.kube',
    'C:/Users/me/.docker/config.json.bak',
    'C:/Users/me/.docker/docker.json',
    'C:/Users/me/.config/gh/hosts.yml.bak',
    'C:/Users/me/.config/gh/hosts.yaml',
    // legacy_credentials is a DIRECTORY: the directory itself and the per-account
    // ADC files under it are not builtin carriers (R-04 file-level list); the real
    // adc.json files are protected only by a user sensitiveFiles mark.
    'C:/Users/me/.config/gcloud/legacy_credentials',
    'C:/Users/me/.config/gcloud/legacy_credentials/me/adc.json',
    'C:/Users/me/.config/gcloud/legacy_credentials/x.json',
    'C:/Users/me/.azure/token.json',
    'C:/Users/me/.azure/accessTokens.json.bak',
    'C:/Users/me/app/.kube/config.orig',
  ]) {
    assert.equal(pathTargetsCredentials(path), false, path)
  }
  // Explicitly ruled-out entries stay out (Leader ruling, R-04).
  assert.equal(pathTargetsCredentials('C:/Users/me/.aws/config'), false)
  assert.equal(pathTargetsCredentials('C:/Users/me/.config/hub'), false)
  assert.equal(pathTargetsCredentials('C:/Users/me/.kube'), false)
  assert.equal(pathTargetsCredentials('C:/Users/me/.ssh'), false)
})

test('.my.cnf is the only new basename; extension-style names stay retired', () => {
  assert.equal(pathTargetsCredentials('C:/Users/me/.my.cnf'), true)
  assert.equal(pathTargetsCredentials('/home/me/.my.cnf'), true)
  assert.equal(pathTargetsCredentials('C:/Users/me/my.cnf'), false, 'without the leading dot it is not the carrier')
  assert.equal(pathTargetsCredentials('C:/Users/me/.my.cnf.bak'), false)
  assert.equal(pathTargetsCredentials('C:/Users/me/app/config/.my.cnf.bak2'), false)
  // No extension class entered the basename list.
  assert.equal([...CRED_BASENAMES].some((n) => n.endsWith('.cnf') && n !== '.my.cnf'), false)
  assert.equal(CRED_BASENAMES.has('.pem'), false)
  assert.equal(CRED_BASENAMES.has('.key'), false)
})

test('DSH-managed credential files stay on the list (DSR-003 intent)', () => {
  // quality-floor: ignore unstaged-ref Synthetic path fixture; this file is neither read nor executed.
  assert.equal(pathTargetsCredentials('C:/Users/FengZhiHen/.dsh/.credentials.yaml'), true)
  assert.equal(pathTargetsCredentials('C:/Users/FengZhiHen/.dsh/.auteur-media-secret'), true)
  // But .dsh itself remains a non-credential directory.
  assert.equal(pathTargetsCredentials('C:/Users/FengZhiHen/.dsh/sessions/abc/session.jsonl.zstd'), false)
})

// ---------- R-05: ordinary unmarked .env files are not protected ----------

test('dotenv files are NOT builtin credential carriers (R-05)', () => {
  // Protection for .env-style files comes only from a Profile sensitiveFiles mark.
  for (const name of ['.env', '.env.local', '.env.production.local', '.env.development.local']) {
    assert.equal(CRED_BASENAMES.has(name), false, name)
    assert.equal(pathTargetsCredentials(`C:/Users/me/app/${name}`), false, name)
  }
  // The DSR-018 list survivors stay protected.
  assert.equal(pathTargetsCredentials('C:/Users/me/.npmrc'), true)
  assert.equal(pathTargetsCredentials('C:/Users/me/.pypirc'), true)
  assert.equal(pathTargetsCredentials('C:/Users/me/.netrc'), true)
  assert.equal(pathTargetsCredentials('C:/Users/me/.pgpass'), true)
  assert.equal(pathTargetsCredentials('C:/Users/me/.git-credentials'), true)
  assert.equal(pathTargetsCredentials('C:/Users/FengZhiHen/.dsh/.credentials.yaml'), true)
  assert.equal(pathTargetsCredentials('C:/Users/FengZhiHen/.dsh/.auteur-media-secret'), true)
  assert.equal(pathTargetsCredentials('C:/Users/me/.ssh/id_rsa'), true)
  assert.equal(pathTargetsCredentials('C:/Users/me/.ssh/id_ed25519'), true)
})

test('.env templates and near-miss dotenv names are not carriers either', () => {
  for (const name of ['.env.example', '.env.sample', '.env.template', '.envrc', '.env.local.bak', 'env', '.environment', '.env.', '.env..local']) {
    assert.equal(CRED_BASENAMES.has(name), false, name)
    assert.equal(pathTargetsCredentials(`C:/Users/me/app/${name}`), false, name)
  }
})

// ---------- V2 config evaluation ----------

test('RULE_KEYS is exactly the V2 pair + the plugin-owned timeout bound', () => {
  assert.deepEqual(RULE_KEYS, ['sensitiveFiles', 'builtinSensitiveAsk', 'askTimeoutMs'])
})

test('evaluateRules: defaults (empty marks, builtin list on)', () => {
  assert.deepEqual(evaluateRules({}), { sensitiveFiles: [], builtinSensitiveAsk: true, askTimeoutMs: 120_000 })
  assert.deepEqual(evaluateRules(undefined), { sensitiveFiles: [], builtinSensitiveAsk: true, askTimeoutMs: 120_000 })
})

test('evaluateRules: accepts explicit values', () => {
  assert.deepEqual(
    evaluateRules({ sensitiveFiles: ['E:/p/.env.production'], builtinSensitiveAsk: false }),
    { sensitiveFiles: ['E:/p/.env.production'], builtinSensitiveAsk: false, askTimeoutMs: 120_000 },
  )
})

test('evaluateRules: mount-time validation fails loudly', () => {
  assert.throws(() => evaluateRules(null), /must be an object/)
  assert.throws(() => evaluateRules([]), /must be an object/)
  assert.throws(() => evaluateRules({ bogus: true }), /unknown config key/)
  assert.throws(() => evaluateRules({ builtinSensitiveAsk: 'yes' }), /must be a boolean/)
  assert.throws(() => evaluateRules({ sensitiveFiles: 'E:/p/.env' }), /must be an array/)
  assert.throws(() => evaluateRules({ sensitiveFiles: ['.env'] }), /absolute file paths/)
  assert.throws(() => evaluateRules({ sensitiveFiles: ['E:/p', ''] }), /non-empty strings/)
  assert.throws(() => evaluateRules({ askTimeoutMs: 1.5 }), /askTimeoutMs/)
  assert.throws(() => evaluateRules({ askTimeoutMs: 3_600_001 }), /askTimeoutMs/)
  assert.throws(() => evaluateRules({ askTimeoutMs: '3000' }), /askTimeoutMs/)
})
