// Defense-layer tests (report 2026-08-17, sections 4.1/4.2):
//   - evaluable $(...) splicing and same-command variable assignments are
//     resolved to literals, so hidden sensitive names are caught
//   - unverifiable dynamic targets on content/removal verbs are blocked;
//     non-content verbs with dynamic expressions stay allowed
//   - Select-Object / Sort-Object / Where-Object join the metadata whitelist;
//     piped bulk deletes through filters/scriptblocks stay blocked
// Run with: node --test test/

import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as guardrails from '../index.js'
import { assessUnverifiable, resolveCommandLiterals } from '../lib/command.js'

function makeGuard(config = {}) {
  let handler
  const ctx = {
    get: () => undefined,
    effect: (fn) => fn(),
    tools: {
      guard: (h) => {
        handler = h
      },
    },
  }
  guardrails.apply(ctx, config)
  return (name, args, cwd = 'E:/Project/DSH_Plugins') =>
    handler({ name, arguments: args, agent: { session: { meta: { cwd } } } })
}

const guard = makeGuard()
const blocked = (r) => typeof r === 'string' && r.startsWith('[guardrails] Blocked')
const allowed = (r) => r === undefined
const pwsh = (command) => guard('pwsh', { command })

// ---------- literal reconstruction (unit) ----------

test('resolveCommandLiterals: evaluable $() splicing and assignments', () => {
  assert.equal(resolveCommandLiterals("Get-Content .e$('nv')"), 'Get-Content .env')
  assert.equal(resolveCommandLiterals("Get-Content .d$('sh')/sessions/x"), 'Get-Content .dsh/sessions/x')
  assert.equal(resolveCommandLiterals("$g='git'; & $g status"), "$g='git'; & git status")
  assert.equal(resolveCommandLiterals("$p = '.env'; Get-Content $p"), "$p = '.env'; Get-Content .env")
  assert.equal(resolveCommandLiterals("$p='.env'; Get-Content \"$p\""), "$p='.env'; Get-Content \".env\"")
  assert.equal(resolveCommandLiterals("$('Get-Content') .env"), 'Get-Content .env')
})

test('resolveCommandLiterals: single quotes, $env:, unknown vars, backticks stay literal', () => {
  assert.equal(resolveCommandLiterals("Get-Content '$p'"), "Get-Content '$p'")
  assert.equal(resolveCommandLiterals('Get-Content "$env:TEMP\\x.txt"'), 'Get-Content "$env:TEMP\\x.txt"')
  assert.equal(resolveCommandLiterals('Get-Content $unknown\\x.txt'), 'Get-Content $unknown\\x.txt')
  assert.equal(resolveCommandLiterals('Set-Content "`$p" v'), 'Set-Content "`$p" v')
})

test('resolveCommandLiterals: non-evaluable subexpressions stay verbatim', () => {
  assert.equal(resolveCommandLiterals('Get-Content $(Get-Location)\\x.txt'), 'Get-Content $(Get-Location)\\x.txt')
  assert.equal(resolveCommandLiterals('Get-Content "$(Join-Path . x)"'), 'Get-Content "$(Join-Path . x)"')
})

test('assessUnverifiable: dynamic command / content-verb target / metadata pass', () => {
  assert.equal(assessUnverifiable('$(Get-Command git) status') !== null, true)
  assert.equal(assessUnverifiable('Get-Content $(Get-Location)\\x.txt') !== null, true)
  assert.equal(assessUnverifiable('Remove-Item "$(Get-Location)\\*"') !== null, true)
  assert.equal(assessUnverifiable('Get-ChildItem $(Get-Location)'), null)
  assert.equal(assessUnverifiable('Get-Content .env'), null)
})

// ---------- guard-level: report 4.1 probes ----------

test('evaluable $() splicing cannot hide sensitive names (env read/write)', () => {
  assert.equal(blocked(pwsh("Get-Content .e$('nv')")), true)
  assert.equal(blocked(pwsh("Set-Content .e$('nv') 'TOKEN=fake'")), true)
  assert.equal(blocked(pwsh("Select-String .e$('nv') -Pattern 'TOKEN'")), true)
})

test('evaluable $() splicing cannot hide credentials', () => {
  assert.equal(allowed(pwsh("Get-Content .d$('sh')/sessions/probe.jsonl")), true) // .dsh has no rule
  assert.equal(blocked(pwsh("Get-Content .s$('sh')/i$('d_rsa')")), true)
})

test('evaluable $() splicing cannot hide destructive intent', () => {
  assert.equal(blocked(pwsh("rm -r .$('')")), true)
})

test('same-command variable assignments are resolved', () => {
  assert.equal(blocked(pwsh("$g='git'; & $g reset --hard")), true)
  assert.equal(allowed(pwsh("$g='git'; & $g status")), true)
  assert.equal(blocked(pwsh("$p='.env'; Get-Content $p")), true)
  assert.equal(blocked(pwsh("$p='.ssh'; Get-ChildItem $p")), true)
  assert.equal(blocked(pwsh("$p='.env'; Get-Content \"$p\"")), true)
})

test('double-quoted interpolation with hidden names is resolved', () => {
  assert.equal(blocked(pwsh("$p='.git'; Get-Content \"$p/config\"")), true)
})

// ---------- guard-level: unverifiable dynamic targets ----------

test('dynamic targets are blocked for content/removal verbs', () => {
  assert.equal(blocked(pwsh('Get-Content $(Get-Location)\\x.txt')), true)
  assert.equal(blocked(pwsh('Set-Content "$(Join-Path . x)" v')), true)
  assert.equal(blocked(pwsh('Remove-Item "$(Get-Location)\\*"')), true)
  assert.equal(blocked(pwsh('$(Get-Command git) status')), true)
  assert.equal(blocked(pwsh('Copy-Item $(Resolve-Path .) x')), true)
})

test('non-content verbs with dynamic expressions stay allowed', () => {
  assert.equal(allowed(pwsh('Get-ChildItem $(Get-Location)')), true)
  assert.equal(allowed(pwsh('Get-Content "$env:TEMP\\x.txt"')), true)
  assert.equal(allowed(pwsh('foreach ($i in 1..3) { Remove-Item "file$i.txt" }')), true)
})

// ---------- guard-level: report 4.2 metadata verbs ----------

test('Select/Sort/Where keep a pure listing allowed', () => {
  assert.equal(allowed(pwsh('Get-ChildItem .git | Select-Object Name')), true)
  assert.equal(allowed(pwsh('Get-ChildItem .git | Sort-Object Name')), true)
  assert.equal(allowed(pwsh("Get-ChildItem .git | Where-Object { $_.Name -eq 'config' }")), true)
  assert.equal(allowed(pwsh('Get-ChildItem .dsh | Where-Object { $_.Name }')), true)
})

test('a content verb anywhere demotes the whole command to full rules', () => {
  assert.equal(blocked(pwsh('Get-Content .env | Select-Object -First 1')), true)
  assert.equal(blocked(pwsh('Get-ChildItem .ssh | Select-Object Name')), true)
})

test('piped bulk deletes through filters/scriptblocks stay blocked', () => {
  assert.equal(blocked(pwsh('Get-ChildItem . | Where-Object { $_.Length -gt 1 } | Remove-Item')), true)
  assert.equal(blocked(pwsh('Get-ChildItem . | Select-Object -First 1 | Remove-Item')), true)
  assert.equal(blocked(pwsh('Get-ChildItem . | Sort-Object Name | Remove-Item')), true)
  assert.equal(blocked(pwsh('Get-ChildItem . | ForEach-Object { Remove-Item $_.FullName }')), true)
  assert.equal(allowed(pwsh('Get-ChildItem . | Where-Object { $_.Length -gt 1 }')), true)
})
