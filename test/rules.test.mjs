// Denylist-driven unit tests: every entry of the data tables in lib/rules.js
// gets an automatic positive case (path matches) through pathTargetsCredentials,
// plus adjacent negative cases for env suffixes and text-reference regexes.
// Adding a denylist entry only touches lib/rules.js — these tests cover it.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  CRED_BASENAME_PREFIXES,
  CRED_BASENAMES,
  CRED_COMBOS,
  CRED_DIR_SEGMENTS,
  CRED_SUFFIXES,
  CRED_TEXT_REFERENCE,
  ENV_REFERENCE,
  GIT_DIR_REFERENCE,
  evaluateRules,
  isSensitiveEnvName,
} from '../lib/rules.js'
import { pathTargetsCredentials } from '../lib/path-check.js'

test('denylist-driven: every CRED_BASENAMES entry matches anywhere', () => {
  for (const name of CRED_BASENAMES) {
    assert.equal(pathTargetsCredentials(`C:/Users/me/${name}`), true, name)
    assert.equal(pathTargetsCredentials(`E:/repo/sub/${name}`), true, name)
  }
})

test('denylist-driven: every CRED_BASENAME_PREFIXES entry matches hive logs too', () => {
  for (const prefix of CRED_BASENAME_PREFIXES) {
    assert.equal(pathTargetsCredentials(`C:/Users/me/${prefix}`), true, prefix)
    assert.equal(pathTargetsCredentials(`C:/Users/me/${prefix}.LOG1`), true, prefix)
    assert.equal(pathTargetsCredentials(`C:/Users/me/${prefix}.regtrans-ms`), true, prefix)
  }
})

test('denylist-driven: every CRED_SUFFIXES entry matches as basename suffix', () => {
  for (const suffix of CRED_SUFFIXES) {
    assert.equal(pathTargetsCredentials(`C:/Users/me/secret${suffix}`), true, suffix)
  }
})

test('denylist-driven: every CRED_DIR_SEGMENTS entry matches at any depth', () => {
  for (const seg of CRED_DIR_SEGMENTS) {
    assert.equal(pathTargetsCredentials(`C:/Users/me/${seg}/anything`), true, seg)
    assert.equal(pathTargetsCredentials(`C:/a/${seg}/b/file.txt`), true, seg)
  }
})

test('denylist-driven: every CRED_COMBOS entry matches as adjacent segments', () => {
  for (const combo of CRED_COMBOS) {
    assert.equal(pathTargetsCredentials(`C:/Users/me/${combo.join('/')}/x`), true, combo.join('/'))
  }
})

test('credentials: non-matching paths stay allowed', () => {
  assert.equal(pathTargetsCredentials('C:/Users/me/.ssh-key-pair-docs/id_rsa_example.txt'), false)
  assert.equal(pathTargetsCredentials('E:/repo/readme.md'), false)
  assert.equal(pathTargetsCredentials('E:/repo/.env.example'), false)
})

test('env names: sensitive vs safe suffixes', () => {
  for (const sensitive of ['.env', '.env.local', '.env.production', '.env.prod.extra']) {
    assert.equal(isSensitiveEnvName(sensitive), true, sensitive)
  }
  for (const safe of [
    '.env.example', '.env.sample', '.env.template', '.env.dist', '.env.default',
    'README.md', '.envs', 'env.local',
  ]) {
    assert.equal(isSensitiveEnvName(safe), false, safe)
  }
})

test('text references: credential names/dirs, .pub excluded', () => {
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content ~/.ssh/id_rsa'), true)
  assert.equal(CRED_TEXT_REFERENCE.test('Get-ChildItem .aws/credentials'), true)
  assert.equal(CRED_TEXT_REFERENCE.test('Copy-Item .config/gcloud/application_default_credentials.json .'), true)
  // Inside a credential dir the .pub file is still blocked (dir segment hits);
  // outside it the .pub basename alone does not trigger.
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content ~/.ssh/id_rsa.pub'), true)
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content ~/id_rsa.pub'), false)
  assert.equal(CRED_TEXT_REFERENCE.test('Get-ChildItem .dsh'), false)
  assert.equal(CRED_TEXT_REFERENCE.test('git status'), false)
})

test('text references: range-B credential names and combos', () => {
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content C:/Users/me/.git-credentials'), true)
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content C:/Users/me/ntuser.dat'), true)
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content C:/Users/me/ntuser.dat.LOG1'), true)
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content C:/pagefile.sys'), true)
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content C:/Windows/System32/config/SAM'), true)
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content C:/Windows/System32/config/SYSTEM'), true)
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content C:/Users/me/AppData/Local/Microsoft/Credentials/a'), true)
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content C:/Users/me/AppData/Roaming/Microsoft/Protect/a'), true)
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content C:/Users/me/AppData/Local/Google/Chrome/User Data/Default/Cookies'), true)
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content C:/Users/me/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/cookies.sqlite'), true)
  // Adjacent-only: listing the config dir itself or plain system reads stay free.
  assert.equal(CRED_TEXT_REFERENCE.test('Get-ChildItem C:/Windows/System32/config'), false)
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content C:/ProgramData/app/config.ini'), false)
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content C:/Windows/System32/win.ini'), false)
})

test('text references: env regex excludes $env:NAME (lastIndex-safe)', () => {
  const match = (s) => {
    ENV_REFERENCE.lastIndex = 0
    return ENV_REFERENCE.test(s)
  }
  assert.equal(match('echo $env:FOO'), false)
  assert.equal(match('Get-Content .env'), true)
  assert.equal(match('Get-Content .env.example'), true) // text match; name check decides
  assert.equal(match('Get-Content .env.example'), true) // repeated call stays stable
})

test('text references: git dir as a standalone word', () => {
  assert.equal(GIT_DIR_REFERENCE.test('Get-Content .git/config'), true)
  assert.equal(GIT_DIR_REFERENCE.test('Get-ChildItem .git'), true)
  assert.equal(GIT_DIR_REFERENCE.test('git status'), false)
  assert.equal(GIT_DIR_REFERENCE.test('$env:USERPROFILE/.gitconfig'), false)
})

test('text references: .dsh carries no reference rule', () => {
  assert.equal(CRED_TEXT_REFERENCE.test('Get-Content .dsh/sessions/x/y.jsonl.zstd'), false)
  assert.equal(CRED_TEXT_REFERENCE.test('Get-ChildItem .dsh/sessions'), false)
})

test('evaluateRules: all categories default on (normalized leaves)', () => {
  assert.deepEqual(evaluateRules({}), {
    env: { read: true, modify: true },
    git: { read: true, modify: true },
    credentials: { read: true, modify: true, list: true },
    destructive: { git: true, machine: true, eval: true, cli: true, bulk: true, target: true },
    system: { write: true },
    unverifiable: true,
  })
})

test('evaluateRules: v1 boolean categories remain valid (whole category on/off)', () => {
  assert.deepEqual(evaluateRules({ env: false }).env, { read: false, modify: false })
  assert.deepEqual(evaluateRules({ env: false }).git, { read: true, modify: true })
  assert.deepEqual(evaluateRules({ credentials: false }).credentials, { read: false, modify: false, list: false })
  assert.deepEqual(evaluateRules({ destructive: false }).destructive, {
    git: false, machine: false, eval: false, cli: false, bulk: false, target: false,
  })
  assert.deepEqual(evaluateRules({ system: false }).system, { write: false })
  assert.equal(evaluateRules({ unverifiable: false }).unverifiable, false)
})

test('evaluateRules: object form toggles leaves independently, absent leaves default true', () => {
  const r = evaluateRules({
    env: { read: false },
    credentials: { list: false },
    destructive: { cli: false },
  })
  assert.deepEqual(r.env, { read: false, modify: true })
  assert.deepEqual(r.credentials, { read: true, modify: true, list: false })
  assert.deepEqual(r.destructive, {
    git: true, machine: true, eval: true, cli: false, bulk: true, target: true,
  })
})

test('evaluateRules: invalid config fails the mount with actionable errors', () => {
  assert.throws(() => evaluateRules({ env: 'no' }), /must be a boolean or an object/)
  assert.throws(() => evaluateRules({ system: 1 }), /must be a boolean or an object/)
  assert.throws(() => evaluateRules({ env: { bogus: true } }), /unknown "env" config key/)
  assert.throws(() => evaluateRules({ destructive: { cito: true } }), /unknown "destructive" config key/)
  assert.throws(() => evaluateRules({ env: { read: 'no' } }), /must be a boolean/)
  assert.throws(() => evaluateRules({ destructive: { cli: 1 } }), /must be a boolean/)
  assert.throws(() => evaluateRules({ unverifiable: 'no' }), /must be a boolean/)
  assert.throws(() => evaluateRules({ bogusKey: true }), /unknown config key/)
  assert.throws(() => evaluateRules(null), /must be an object/)
  assert.throws(() => evaluateRules([]), /must be an object/)
  // valid shapes keep working
  assert.deepEqual(evaluateRules(undefined), evaluateRules({}))
  assert.equal(evaluateRules({ env: true }).env.read, true)
  assert.equal(evaluateRules({ env: true, git: true, destructive: true, credentials: true, system: true }).env.read, true)
})
