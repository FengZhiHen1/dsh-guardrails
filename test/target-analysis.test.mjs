import assert from 'node:assert/strict'
import test from 'node:test'
import { createExecutionAnalyzer } from '../src/adapter/analysis/index.js'

const context = { domain: 'host', cwd: process.cwd(), platform: process.platform }
const invoke = (executable, args, cwd = context.cwd) => ({
  source: { kind: 'argv', executable, args }, language: 'unknown',
  context: { ...context, cwd }, origin: { entry: 'fixture' },
})

function createFixture(t, overrides = {}) {
  const analysis = createExecutionAnalyzer(overrides)
  t.after(() => analysis.dispose())
  return analysis
}

test('shares command semantics across direct argument vectors and source adapters', async (t) => {
  const shell = { analyze(_unit, env) { env.command('rm', ['--', 'one.txt']) } }
  const analyzer = createFixture(t, { shell })
  const direct = await analyzer.analyze(invoke('rm', ['--', 'one.txt']))
  const indirect = await analyzer.analyze({ source: { kind: 'inline', text: 'fixture' }, language: 'bash', context, origin: { entry: 'fixture' } })
  assert.deepEqual(indirect.operations, direct.operations)
  assert.equal(direct.operations[0].action, 'delete')
  assert.deepEqual(direct.operations[0].target, { kind: 'exact', paths: ['one.txt'] })
})

test('interpreter script-file bodies are not read (RR-5)', async (t) => {
  let called = false
  const analyzer = createFixture(t, { program: { analyze() { called = true } } })
  const result = await analyzer.analyze(invoke('python', ['fixture.py']))
  assert.equal(called, false)
  assert.equal(result.status, 'partial')
  assert.ok(result.gaps.some((gap) => gap.kind === 'script-file-body-not-analyzed'))
})

test('analysis preserves prior facts when a nested provider is unavailable', async (t) => {
  const shell = { analyze(_unit, env) {
    env.command('rm', ['--', 'one.txt'])
    env.command('ruby', ['fixture.rb'])
  } }
  const analyzer = createFixture(t, { shell })
  const result = await analyzer.analyze({ source: { kind: 'inline', text: 'fixture' }, language: 'bash', context })
  assert.equal(result.status, 'partial')
  assert.equal(result.operations.length, 1)
  assert.equal(result.candidates.length, 0)
  assert.ok(result.gaps.some((gap) => gap.kind === 'no-provider'))
})

test('operations from child units retain their invocation order and condition', async (t) => {
  const analyzer = createFixture(t, {
    shell: { analyze(_unit, env) {
      env.operation('write-content', { kind: 'exact', paths: ['before.txt'] })
      env.child({ language: 'python', source: { kind: 'inline', text: 'fixture' }, condition: 'possible' })
      env.operation('write-content', { kind: 'exact', paths: ['after.txt'] })
    } },
    program: { analyze(_unit, env) { env.operation('delete', { kind: 'exact', paths: ['nested.txt'] }) } },
  })
  const result = await analyzer.analyze({ source: { kind: 'inline', text: 'fixture' }, language: 'bash', context })
  assert.deepEqual(result.operations.map(({ target }) => target.paths[0]), ['before.txt', 'nested.txt', 'after.txt'])
  assert.equal(result.operations[1].condition, 'possible')
})

test('uses one unit budget across language boundaries', async (t) => {
  const analyzer = createFixture(t, { limits: { maxUnits: 1 } })
  const result = await analyzer.analyze(invoke('python', ['-c', 'pass']))
  assert.equal(result.status, 'partial')
  assert.equal(result.gaps[0].kind, 'unit-budget')
})

test('a provider crash yields fault instead of an empty successful analysis', async (t) => {
  const analyzer = createFixture(t, { program: { analyze() { throw new Error('raw diagnostic') } } })
  const result = await analyzer.analyze(invoke('python', ['-c', 'pass']))
  assert.equal(result.status, 'fault')
  assert.deepEqual(result.operations, [])
  assert.doesNotMatch(JSON.stringify(result), /raw diagnostic/)
})

test('read-only text carrying deletion syntax does not produce an operation', async (t) => {
  const analyzer = createFixture(t)
  const result = await analyzer.analyze(invoke('grep', ['rm -rf may be mentioned here']))
  assert.equal(result.status, 'complete')
  assert.equal(result.operations.length, 0)
})

// --- credential text scan (规则模型「凭据防泄露」R-04) ---------------------------------

test('credential text scan fires with an unresolved operand and a protected basename', async (t) => {
  const shell = { analyze(_unit, env) { env.operation('delete', { kind: 'unknown', reason: 'unresolved variable $t' }) } }
  const analyzer = createFixture(t, { shell })
  const hit = await analyzer.analyze({ source: { kind: 'inline', text: 'copy C:/Users/me/.npmrc somewhere' }, language: 'bash', context })
  assert.equal(hit.status, 'complete')
  assert.equal(hit.credentialTextMention, true)
})

test('credential text scan matches a private key header but never an unmarked .env name', async (t) => {
  const shell = { analyze(_unit, env) { env.operation('read-content', { kind: 'unknown', reason: 'unresolved variable $t' }) } }
  const analyzer = createFixture(t, { shell })
  const keyHeader = await analyzer.analyze({ source: { kind: 'inline', text: 'Get-Content -----BEGIN RSA PRIVATE KEY-----' }, language: 'powershell', context })
  assert.equal(keyHeader.credentialTextMention, true)
  const envMiss = await analyzer.analyze({ source: { kind: 'inline', text: 'copy C:/app/.env somewhere' }, language: 'bash', context })
  assert.equal(envMiss.credentialTextMention, undefined)
  const templateMiss = await analyzer.analyze({ source: { kind: 'inline', text: 'copy C:/app/.env.example somewhere' }, language: 'bash', context })
  assert.equal(templateMiss.credentialTextMention, undefined)
})

test('an exact operand alone does not trigger the credential text scan', async (t) => {
  const shell = { analyze(_unit, env) { env.operation('delete', { kind: 'exact', paths: ['one.txt'] }) } }
  const analyzer = createFixture(t, { shell })
  const miss = await analyzer.analyze({ source: { kind: 'inline', text: 'copy C:/Users/me/.npmrc somewhere' }, language: 'bash', context })
  assert.equal(miss.credentialTextMention, undefined)
})

test('inline source text participates in the credential text scan', async (t) => {
  const program = { analyze(_unit, env) { env.operation('delete', { kind: 'unknown', reason: 'unresolved target' }) } }
  const analyzer = createFixture(t, { program })
  const result = await analyzer.analyze(invoke('python', ['-c', 'shutil.copy("C:/Users/me/.npmrc", out)']))
  assert.equal(result.status, 'complete')
  assert.equal(result.credentialTextMention, true)
})

// --- win32 embedded shell texts route through the cmd lexer (F-22) --------------

test('embedded shell text on win32 is analyzed instead of no-provider', async (t) => {
  const program = { analyze(_unit, env) {
    env.child({
      source: { kind: 'inline', text: 'del C:\\fixture\\x.txt & rmdir /s /q build' },
      language: 'unknown', context: { domain: 'host', platform: 'win32', cwd: 'C:\\fixture' },
    })
  } }
  const analyzer = createFixture(t, { program })
  const result = await analyzer.analyze({
    source: { kind: 'inline', text: 'fixture' }, language: 'python',
    context: { domain: 'host', platform: 'win32', cwd: 'C:\\fixture' }, origin: { entry: 'fixture' },
  })
  assert.equal(result.status, 'complete')
  assert.ok(!result.gaps.some((gap) => gap.kind === 'no-provider'))
  assert.deepEqual(result.operations[0].target, { kind: 'exact', paths: ['C:\\fixture\\x.txt'] })
  assert.deepEqual(result.operations[1].target, { kind: 'subtree', root: 'build' })
})

test('an unknown-dialect inline unit off win32 keeps its no-provider gap', async (t) => {
  const analyzer = createFixture(t)
  const result = await analyzer.analyze({
    source: { kind: 'inline', text: 'rm -rf /tmp/x' }, language: 'unknown',
    context: { domain: 'host', platform: 'linux' }, origin: { entry: 'fixture' },
  })
  assert.ok(result.gaps.some((gap) => gap.kind === 'no-provider'))
  assert.equal(result.operations.length, 0)
})

test('cmd /c payload from shell text reaches the cmd lexer end to end', async (t) => {
  const analyzer = createFixture(t)
  const result = await analyzer.analyze({
    source: { kind: 'inline', text: 'cmd /c del C:/x/a.txt' }, language: 'bash',
    context: { domain: 'host', platform: 'win32', cwd: 'C:\\x' }, origin: { entry: 'fixture' },
  })
  assert.equal(result.operations[0]?.action, 'delete')
  assert.deepEqual(result.operations[0]?.target, { kind: 'exact', paths: ['C:/x/a.txt'] })
  assert.ok(result.gaps.some((gap) => gap.kind === 'cmd-inline'))
})

// --- non-host domain deletions (F-33, D2) ----------------------------------------

test('wsl -e deletions avoid the host inventory and list the domain scope', async (t) => {
  const analyzer = createFixture(t)
  const result = await analyzer.analyze(invoke('wsl.exe', ['--exec', 'rm', '-rf', '/tmp/x']))
  assert.equal(result.status, 'complete')
  assert.equal(result.operations[0]?.action, 'delete')
  assert.deepEqual(result.operations[0]?.target, { kind: 'unknown', reason: 'non-host-domain', knownScope: ['wsl: /tmp/x (recursive)'] })
  assert.ok(!result.gaps.some((gap) => gap.kind === 'no-provider'))
})

test('wsl shells without --exec keep their coverage gap (regression guard)', async (t) => {
  const analyzer = createFixture(t)
  const result = await analyzer.analyze(invoke('wsl.exe', ['ls', '/tmp']))
  assert.ok(result.gaps.some((gap) => gap.kind === 'wsl-shell'))
  assert.equal(result.operations.length, 0)
})
