// Scoped tests for the Python content-access facts (read-content / write-content)
// emitted by python-ast-helper.py. Synthetic inline sources only; the analyzer
// never executes the source and these tests create no files. This file stands
// alone so it can cherry-pick without overlap with target-program.test.mjs.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createProgramAnalyzer } from '../src/adapter/analysis/program.js'

const explicitPython = process.env.DSH_GUARDRAILS_PYTHON || undefined

function makeEnv({ limits, signal } = {}) {
  const facts = []
  let steps = 0
  const env = {
    signal,
    limits: limits ?? { timeoutMs: 10000, maxInputBytes: 1 << 20, maxOutputBytes: 8388608, maxSteps: 20000 },
    command: (executable, args, options) => facts.push({ t: 'command', executable, args, ...options }),
    operation: (action, target, options) => facts.push({ t: 'operation', action, target, ...options }),
    child: (input) => facts.push({ t: 'child', input }),
    gap: (kind, origin) => facts.push({ t: 'gap', kind, origin }),
    candidate: (kind, reason, knownScope, origin) => facts.push({ t: 'candidate', kind, reason, knownScope, origin }),
    step: (count = 1) => { steps += count },
  }
  return { env, facts, steps: () => steps }
}

function unit(language, text, extra = {}) {
  return {
    unitId: 'u1',
    source: { kind: 'inline', text },
    language,
    context: { domain: 'host', cwd: 'C:\\synthetic\\work', platform: 'win32' },
    origin: { tool: 'run_code' },
    ...extra,
  }
}

const operations = facts => facts.filter(f => f.t === 'operation')
const gaps = facts => facts.filter(f => f.t === 'gap')

const analyzer = createProgramAnalyzer({ pythonExecutable: explicitPython })
test.after(() => analyzer.dispose())

let pythonReady = false
let pythonSkipReason = 'python runtime unavailable'
test.before(async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', 'x = 1\n'), env)
  pythonReady = !gaps(facts).some(g => g.kind === 'no-python-runtime')
})

const pyTest = (name, fn) => test(name, async (t) => { if (!pythonReady) return t.skip(pythonSkipReason); await fn(t) })

pyTest('builtins.open with default mode reports read-content with literal path', async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "open('C:/synthetic/work/config.txt')\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 1)
  assert.equal(ops[0].action, 'read-content')
  assert.deepEqual(ops[0].target, { kind: 'exact', paths: ['C:/synthetic/work/config.txt'] })
  assert.equal(ops[0].details, 'mode: r')
  assert.equal(ops[0].condition, 'certain')
})

pyTest('explicit r/rb stay read-content', async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "open('C:/synthetic/work/a.bin', 'rb')\nopen('C:/synthetic/work/b.txt', mode='rt')\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 2)
  assert.ok(ops.every(op => op.action === 'read-content'))
  assert.equal(ops[0].details, 'mode: rb')
  assert.equal(ops[1].details, 'mode: rt')
})

pyTest('w/a/x/+ report write-content with the literal mode preserved', async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "open('C:/synthetic/work/a.txt', 'w')\nopen('C:/synthetic/work/b.log', 'ab')\nopen('C:/synthetic/work/c.tmp', 'x')\nopen('C:/synthetic/work/d.txt', 'r+')\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 4)
  assert.ok(ops.every(op => op.action === 'write-content'))
  assert.deepEqual(ops.map(op => op.details), ['mode: w', 'mode: ab', 'mode: x', 'mode: r+'])
})

pyTest('keyword mode and joined literal target are preserved', async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "base = 'C:/synthetic/work'\nopen(base + '/state.json', mode='w+b')\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 1)
  assert.equal(ops[0].action, 'write-content')
  assert.deepEqual(ops[0].target, { kind: 'exact', paths: ['C:/synthetic/work/state.json'] })
  assert.equal(ops[0].details, 'mode: w+b')
})

pyTest('io.open and imported aliases reach the content facts', async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "import io\nio.open('C:/synthetic/work/a.txt', 'a')\nfrom io import open as iopen\niopen('C:/synthetic/work/b.txt')\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 2)
  assert.equal(ops[0].action, 'write-content')
  assert.equal(ops[1].action, 'read-content')
})

pyTest('non-literal mode reports a bounded gap and no action claim', async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "open('C:/synthetic/work/a.txt', mode_flag)\n"), env)
  assert.equal(operations(facts).length, 0)
  assert.ok(gaps(facts).some(g => g.kind === 'content-mode-unknown'))
})

pyTest('invalid mode characters report a bounded gap and no action claim', async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "open('C:/synthetic/work/a.txt', 'zz')\n"), env)
  assert.equal(operations(facts).length, 0)
  assert.ok(gaps(facts).some(g => g.kind === 'content-mode-unknown'))
})

pyTest('dynamic target reports a bounded gap and no action claim', async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "open(user_supplied)\n"), env)
  assert.equal(operations(facts).length, 0)
  assert.ok(gaps(facts).some(g => g.kind === 'content-target-unknown'))
})

pyTest('nested open is possible, not certain', async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "if flag:\n    open('C:/synthetic/work/a.txt', 'w')\n"), env)
  assert.equal(operations(facts)[0].condition, 'possible')
})

pyTest('Path.read_text/read_bytes report read-content; write_text/write_bytes write-content', async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "from pathlib import Path\nPath('C:/synthetic/work/a.txt').read_text()\nPath('C:/synthetic/work/a.bin').read_bytes()\nPath('C:/synthetic/work/b.txt').write_text('fixture')\nPath('C:/synthetic/work/b.bin').write_bytes(b'x')\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 4)
  assert.deepEqual(ops.map(op => op.action), ['read-content', 'read-content', 'write-content', 'write-content'])
  assert.deepEqual(ops[0].target, { kind: 'exact', paths: ['C:/synthetic/work/a.txt'] })
  assert.match(ops[3].details, /write_bytes/)
})

pyTest('Path.open follows the mode default and literals', async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "from pathlib import Path\nPath('C:/synthetic/work/a.txt').open()\nPath('C:/synthetic/work/b.txt').open('w')\nPath('C:/synthetic/work/c.txt').open(mode='a')\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 3)
  assert.deepEqual(ops.map(op => op.action), ['read-content', 'write-content', 'write-content'])
  assert.equal(ops[0].details, 'mode: r (open)')
  assert.equal(ops[2].details, 'mode: a (open)')
})

pyTest('Path value receiver from a verified constant is preserved', async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "from pathlib import Path\ntarget = Path('C:/synthetic/work/state.json')\ntarget.write_text('fixture')\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 1)
  assert.deepEqual(ops[0].target, { kind: 'exact', paths: ['C:/synthetic/work/state.json'] })
})

pyTest('unverified Path receiver reports a bounded gap and no action claim', async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "from pathlib import Path\nPath(user_supplied).read_text()\n"), env)
  assert.equal(operations(facts).length, 0)
  assert.ok(gaps(facts).some(g => g.kind === 'content-target-unknown'))
})

pyTest('content facts do not disturb delete-sink analysis in the same unit', async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "import os\nopen('C:/synthetic/work/a.txt')\nos.remove('C:/synthetic/work/b.txt')\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 2)
  assert.deepEqual(ops.map(op => op.action), ['read-content', 'delete'])
})

test('pure-computation python still reports no content facts', async (t) => {
  if (!pythonReady) return t.skip(pythonSkipReason)
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', 'value = 40 + 2\n'), env)
  assert.equal(operations(facts).length, 0)
  assert.equal(gaps(facts).length, 0)
})
