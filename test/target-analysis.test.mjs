import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
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

test('a scoped file entry is read as data and preserves child origin', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'guardrails-analysis-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const filename = path.join(root, 'fixture.py')
  await writeFile(filename, 'parse as data only')
  const analyzer = createFixture(t, { program: { analyze(unit, env) {
    assert.equal(unit.source.text, 'parse as data only')
    env.operation('delete', { kind: 'exact', paths: ['one.txt'] })
  } } })
  const result = await analyzer.analyze(invoke('python', ['fixture.py'], root))
  assert.equal(result.status, 'complete')
  assert.equal(result.operations[0].origin.file, filename)
  assert.equal(result.operations[0].origin.parentUnitId, '1')
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
