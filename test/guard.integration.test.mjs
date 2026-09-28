// Integration matrix: drives the plugin's tools.guard hook through a mock ctx
// (no filesystem, no network). This is the semantic-preservation anchor for
// the lib/ refactor — every case must behave identically to the pre-refactor
// single-file implementation. Run with: node --test test/

import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as guardrails from '../index.js'

function makeGuard(config = {}, settings) {
  let handler
  // Mirror the real ctx.sandboxPolicy shape (DSR-007): resolve() derives the
  // workspace root from the calling session's immutable header.cwd.
  const sandboxPolicy = {
    resolve: ({ session } = {}) => ({ workspaceRoot: session?.header?.cwd ?? 'E:/FallbackRoot' }),
  }
  const ctx = {
    get: (key) => (key === 'sandboxPolicy' ? sandboxPolicy : undefined),
    effect: (fn) => fn(),
    inject: (name, consumer) => {
      const deps = Array.isArray(name) ? name : [name]
      if (deps.includes('settings') && settings !== undefined) consumer({ ...ctx, settings })
    },
    tools: {
      guard: (h) => {
        handler = h
      },
    },
  }
  guardrails.apply(ctx, config)
  return (name, args, cwd = 'E:/Project/DSH_Plugins') =>
    handler({ name, arguments: args, agent: { session: { header: { cwd } } } })
}

const guard = makeGuard()
const blocked = (r) => typeof r === 'string' && r.startsWith('[guardrails] Blocked')
const allowed = (r) => r === undefined
const pwsh = (command) => guard('pwsh', { command })
const read = (file_path) => guard('read', { file_path })
const write = (file_path) => guard('write', { file_path })
const glob = (path) => guard('glob', { path })
const grep = (path) => guard('grep', { path })

test('listing .dsh is allowed (mixed directory, not a credential dir)', () => {
  assert.equal(allowed(pwsh('Get-ChildItem .dsh')), true)
  assert.equal(allowed(pwsh('ls ~/.dsh')), true)
  assert.equal(allowed(pwsh('Test-Path .dsh')), true)
  assert.equal(allowed(pwsh('Get-ChildItem .dsh/sessions')), true)
})

test('listing .git / .env is allowed (metadata does not leak content)', () => {
  assert.equal(allowed(pwsh('Get-ChildItem .git')), true)
  assert.equal(allowed(pwsh('dir .env')), true)
})

test('listing pure credential dirs stays blocked (existence is sensitive)', () => {
  assert.equal(blocked(pwsh('Get-ChildItem .ssh')), true)
  assert.equal(blocked(pwsh('Get-ChildItem ~/.aws')), true)
  assert.equal(blocked(pwsh('Get-ChildItem .kube/config')), true)
})

test('content reads of sensitive targets stay blocked', () => {
  assert.equal(blocked(pwsh('Get-Content .env')), true)
  assert.equal(blocked(pwsh('cat .git/config')), true)
  assert.equal(blocked(pwsh('Get-Content .ssh/id_rsa')), true)
  assert.equal(blocked(pwsh('Select-String .env -Pattern "TOKEN"')), true)
})

test('writes and deletes of sensitive targets stay blocked', () => {
  assert.equal(blocked(pwsh('Set-Content .env TOKEN=1')), true)
  assert.equal(blocked(pwsh('rm -rf .')), true)
})

test('list piped to remove is blocked (destructive rule, target-independent)', () => {
  assert.equal(blocked(pwsh('Get-ChildItem .dsh | Remove-Item')), true)
  assert.equal(blocked(pwsh('Get-ChildItem .dsh -Recurse | Remove-Item')), true)
})

test('redirect to a sensitive file keeps full rules', () => {
  assert.equal(blocked(pwsh('Get-ChildItem .dsh > .env')), true)
})

test('mixed commands keep full conservative rules', () => {
  assert.equal(blocked(pwsh('Get-ChildItem .dsh; Get-Content .env')), true)
})

test('credential-name filtering stays blocked even when listing', () => {
  assert.equal(blocked(pwsh('Get-ChildItem ~ -Filter id_rsa*')), true)
})

test('path-level: .dsh paths are not intercepted; credentials inside .dsh still are', () => {
  assert.equal(blocked(read('C:/Users/FengZhiHen/.dsh/.credentials.yaml')), true)
  assert.equal(blocked(read('C:/Users/FengZhiHen/.dsh/.auteur-media-secret')), true)
  assert.equal(blocked(read('C:/Users/FengZhiHen/.dsh/sessions/abc/session.jsonl.zstd')), false)
  assert.equal(blocked(read('.dsh/skills/some-skill/SKILL.md')), false)
  assert.equal(blocked(read('.env.example')), false)
  assert.equal(blocked(write('.dsh/sessions/abc/session.jsonl.zstd')), false)
})

test('path-level: glob only blocks pure credential targets', () => {
  assert.equal(blocked(glob('.ssh/**')), true)
  assert.equal(blocked(glob('.dsh/**')), false)
  assert.equal(blocked(glob('.dsh/sessions/**')), false)
})

test('grep on .dsh paths is allowed (no sessions rule)', () => {
  assert.equal(blocked(grep('.dsh/sessions')), false)
})

test('sessions config key is removed; .dsh stays allowed with unknown-key failure', () => {
  assert.equal(blocked(read('C:/Users/FengZhiHen/.dsh/sessions/abc/x')), false)
  assert.throws(() => makeGuard({ sessions: false }), /unknown config key/)
})

test('credentials rule remains toggleable', () => {
  const lax = makeGuard({ credentials: false })
  assert.equal(allowed(lax('pwsh', { command: 'Get-Content .ssh/id_rsa' })), true)
})

test('system area: writes blocked, reads and listings allowed (W0)', () => {
  assert.equal(blocked(write('C:/Windows/System32/drivers/etc/hosts')), true)
  assert.equal(blocked(read('C:/Windows/System32/drivers/etc/hosts')), false)
  assert.equal(blocked(glob('C:/Windows/**')), false)
  assert.equal(blocked(pwsh('Set-Content C:\\Windows\\x y')), true)
  assert.equal(blocked(pwsh('Remove-Item "C:\\Program Files\\x" -Recurse')), true)
  assert.equal(blocked(pwsh('Copy-Item a.txt C:\\ProgramData\\x')), true)
  assert.equal(blocked(pwsh('echo x > C:\\Windows\\foo.txt')), true)
  assert.equal(blocked(pwsh('cd C:\\Windows; Set-Content x y')), true)
  assert.equal(blocked(pwsh('Get-Content C:\\Windows\\win.ini')), false)
  assert.equal(blocked(pwsh('Get-ChildItem C:\\Windows')), false)
})

test('drive-root deletion is blocked through the guard', () => {
  assert.equal(blocked(pwsh('Remove-Item C:\\ -Recurse -Force')), true)
  assert.equal(blocked(pwsh('Remove-Item D:/ -Recurse')), true)
  assert.equal(blocked(pwsh('rm -rf /')), true)
  assert.equal(blocked(pwsh('Remove-Item C:\\* -Recurse')), true)
})

test('range-B credential reads stay blocked through pwsh and tools', () => {
  assert.equal(blocked(pwsh('Get-Content C:/Windows/System32/config/SAM')), true)
  assert.equal(blocked(pwsh('Get-Content C:/Users/me/.git-credentials')), true)
  assert.equal(blocked(read('C:/Users/me/AppData/Local/Google/Chrome/User Data/Default/Cookies')), true)
  assert.equal(blocked(read('C:/Users/me/ntuser.dat')), true)
})

test('system rule is toggleable via config', () => {
  const lax = makeGuard({ system: false })
  assert.equal(allowed(lax('write', { file_path: 'C:/Windows/x' })), true)
  assert.equal(allowed(lax('pwsh', { command: 'Set-Content C:\\Windows\\x y' })), true)
})

test('op-level leaves: env read/modify toggle independently (tools and pwsh)', () => {
  const readOff = makeGuard({ env: { read: false } })
  assert.equal(allowed(readOff('read', { file_path: '.env' })), true)
  assert.equal(blocked(readOff('write', { file_path: '.env' })), true)
  assert.equal(allowed(readOff('pwsh', { command: 'Get-Content .env' })), true)
  assert.equal(blocked(readOff('pwsh', { command: 'Set-Content .env x' })), true)
  const modifyOff = makeGuard({ env: { modify: false } })
  assert.equal(blocked(modifyOff('read', { file_path: '.env' })), true)
  assert.equal(allowed(modifyOff('write', { file_path: '.env' })), true)
  assert.equal(blocked(modifyOff('pwsh', { command: 'Get-Content .env' })), true)
  assert.equal(allowed(modifyOff('pwsh', { command: 'Set-Content .env x' })), true)
})

test('op-level leaves: credentials list toggles independently of read', () => {
  const lax = makeGuard({ credentials: { list: false } })
  assert.equal(allowed(lax('glob', { path: '.ssh/**' })), true)
  assert.equal(allowed(lax('pwsh', { command: 'Get-ChildItem .ssh' })), true)
  assert.equal(blocked(lax('read', { file_path: '.ssh/id_rsa' })), true)
  assert.equal(blocked(lax('pwsh', { command: 'Get-Content .ssh/id_rsa' })), true)
  const modOff = makeGuard({ credentials: { modify: false } })
  assert.equal(allowed(modOff('write', { file_path: '.ssh/x' })), true)
  assert.equal(blocked(modOff('read', { file_path: '.ssh/id_rsa' })), true)
})

test('op-level leaves: destructive sub-families gate independently (cli off)', () => {
  const lax = makeGuard({ destructive: { cli: false } })
  assert.equal(allowed(lax('pwsh', { command: 'kubectl delete ns prod' })), true)
  assert.equal(allowed(lax('pwsh', { command: 'docker system prune -a' })), true)
  assert.equal(blocked(lax('pwsh', { command: 'rm -rf .' })), true)
  assert.equal(blocked(lax('pwsh', { command: 'shutdown -s -t 0' })), true)
})

test('unverifiable fail-safe gate is toggleable (default on)', () => {
  const lax = makeGuard({ unverifiable: false })
  assert.equal(allowed(lax('pwsh', { command: 'Get-Content $($x)' })), true)
  assert.equal(blocked(guard('pwsh', { command: 'Get-Content $($x)' })), true)
})

test('DSR-009: incident replay blocked end-to-end; ablation of chain+misuse opens it again', () => {
  const incident =
    "$in = 'E:/Project/Demo/1-保研准备/inbox'; " +
    'Move-Item -LiteralPath "$in/*" -Destination E:/Project/Demo/library/行政/保研; ' +
    'Remove-Item -LiteralPath "$in" -Recurse -Force; ' +
    'Get-ChildItem -Recurse E:/Project/Demo/library/行政/保研 | Measure-Object Length -Sum'
  assert.equal(blocked(pwsh(incident)), true)
  // single-layer removals keep the other layer (independent gating)
  assert.equal(blocked(makeGuard({ destructive: { misuse: false } })('pwsh', { command: incident })), true)
  assert.equal(blocked(makeGuard({ destructive: { chain: false } })('pwsh', { command: incident })), true)
  // both new layers off → the resolved plain-directory deletion passes
  const loose = makeGuard({ destructive: { chain: false, misuse: false } })
  assert.equal(allowed(loose('pwsh', { command: incident })), true)
})

test('DSR-010: citing a sensitive name is not a reference to it', () => {
  // The 2026-09-27 regression: a commit message quoting this guard's own deny
  // text (which contains ".git") was blocked, so recording a gate result with
  // `git commit` failed until the message was moved out of the command line.
  assert.equal(
    allowed(pwsh('git commit -m "docs: quote [guardrails] references the .git directory"')),
    true,
  )
  assert.equal(allowed(pwsh('git commit -m "fix: load .env earlier"')), true)
  assert.equal(allowed(pwsh('git commit -m "docs: keep .ssh out of the repo"')), true)
  assert.equal(allowed(pwsh('git commit --message "the .git dir"')), true)
  assert.equal(allowed(pwsh('Write-Output "see .git for history"')), true)
  assert.equal(allowed(pwsh("$n -notmatch '\\.git'")), true)
})

test('DSR-010: real sensitive-path references stay blocked end-to-end', () => {
  assert.equal(blocked(pwsh('Get-Content .git/config')), true)
  assert.equal(blocked(pwsh("Get-Content '.git/config'")), true)
  assert.equal(blocked(pwsh('Get-Content "C:\\Program Files\\repo\\.git\\config"')), true)
  assert.equal(blocked(pwsh("Remove-Item '.git' -Recurse -Force")), true)
  assert.equal(blocked(pwsh('Remove-Item -Recurse -Force .git')), true)
  assert.equal(blocked(pwsh('git cat-file --git-dir=.git -p HEAD')), true)
  assert.equal(blocked(pwsh('Get-Content .env')), true)
  assert.equal(blocked(pwsh("Get-Content '.env'")), true)
  assert.equal(blocked(pwsh('Get-Content C:\\Users\\me\\.ssh\\id_rsa')), true)
  // a citation does not launder a real reference sitting beside it
  assert.equal(blocked(pwsh('git commit -m "see .git" -- .env')), true)
})
