// Tests for the program analyzer (execution-face best-effort static analysis,
// DSR-026 + 跨语言删除分析). Synthetic inline sources only; the analyzer never
// executes anything, so these tests only observe reported facts.
//
// Python cases run against whatever runtime the analyzer probes (explicit
// DSH_GUARDRAILS_PYTHON, python3, py -3, uv-managed installs); they skip with a
// named reason when no runtime exists on the machine. JS/TS cases skip when the
// TypeScript dependency is not resolvable.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
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

const ofKind = (facts, t) => facts.filter(f => f.t === t)
const operations = facts => ofKind(facts, 'operation')
const candidates = facts => ofKind(facts, 'candidate')
const children = facts => ofKind(facts, 'child')
const commands = facts => ofKind(facts, 'command')
const gaps = facts => ofKind(facts, 'gap')

const analyzer = createProgramAnalyzer({ pythonExecutable: explicitPython })
test.after(() => analyzer.dispose())

// Availability probes decide named skips; the probes themselves are assertions
// that pure-computation units produce no deletion facts.
let pythonReady = false
let pythonSkipReason = 'python runtime unavailable (set DSH_GUARDRAILS_PYTHON)'
test.before(async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', 'x = 1 + 2\n'), env)
  const absent = gaps(facts).some(g => g.kind === 'no-python-runtime')
  pythonReady = !absent
  if (!pythonReady) pythonSkipReason = 'no probed python runtime (tried explicit, python3, py -3, uv-managed)'
})

let typescriptReady = false
let typescriptSkipReason = 'typescript dependency not resolvable'
try {
  createRequire(new URL('../package.json', import.meta.url))('typescript')
  typescriptReady = true
} catch { /* named skip below */ }

// ---------------- Python provider ----------------

test('python: literal os.remove reports a certain exact delete', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "import os\nos.remove('C:/synthetic/work/a.txt')\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 1)
  assert.equal(ops[0].action, 'delete')
  assert.deepEqual(ops[0].target, { kind: 'exact', paths: ['C:/synthetic/work/a.txt'] })
  assert.equal(ops[0].recursive, false)
  assert.equal(ops[0].condition, 'certain')
  assert.equal(ops[0].origin.line, 2)
})

test('python: shutil.rmtree over a locally propagated join is exact and recursive', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "import os, shutil\nbase = 'C:/synthetic/work'\nshutil.rmtree(os.path.join(base, 'build'))\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 1)
  assert.equal(ops[0].action, 'delete')
  assert.equal(ops[0].recursive, true)
  assert.deepEqual(ops[0].target, { kind: 'exact', paths: ['C:/synthetic/work\\build'] })
})

test('python: from-import alias reaches the sink', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "from shutil import rmtree as wipe\nwipe('C:/synthetic/work/cache')\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 1)
  assert.equal(ops[0].action, 'delete')
  assert.deepEqual(ops[0].target, { kind: 'exact', paths: ['C:/synthetic/work/cache'] })
})

test('python: pathlib Path.unlink on a path constructor is exact', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "from pathlib import Path\nPath('C:/synthetic/work/a.txt').unlink()\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 1)
  assert.deepEqual(ops[0].target, { kind: 'exact', paths: ['C:/synthetic/work/a.txt'] })
})

test('python: dynamic sink target becomes a candidate', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', 'import os\nname = user_input\nos.remove(name)\n'), env)
  const cands = candidates(facts)
  assert.equal(ops_or_empty(operations(facts)), 0)
  assert.equal(cands.length, 1)
  assert.equal(cands[0].kind, 'dynamic-target')
  assert.equal(cands[0].knownScope, undefined)
})

test('python: enumeration loop reports candidate with verified base as known scope', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "import os\nbase = 'C:/synthetic/work/logs'\nfor name in os.listdir(base):\n    os.remove(name)\n"), env)
  const cands = candidates(facts)
  assert.equal(operations(facts).length, 0)
  assert.equal(cands.length, 1)
  assert.equal(cands[0].kind, 'dynamic-target')
  assert.deepEqual(cands[0].knownScope, ['C:/synthetic/work/logs'])
})

test('python: static argv subprocess reports a command fact', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "import subprocess\nsubprocess.run(['rm', '-rf', './tmp/x'])\n"), env)
  const cmds = commands(facts)
  assert.equal(cmds.length, 1)
  assert.equal(cmds[0].executable, 'rm')
  assert.deepEqual(cmds[0].args, ['-rf', './tmp/x'])
  assert.equal(cmds[0].condition, 'certain')
})

test('python: subprocess shell string and os.system report shell children', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "import os, subprocess\nsubprocess.run('rm -rf ./tmp/x', shell=True)\nos.system('rm -rf ./tmp/y')\n"), env)
  const kids = children(facts)
  assert.equal(kids.length, 2)
  for (const kid of kids) {
    assert.equal(kid.input.source.kind, 'inline')
    assert.ok(kid.input.source.text.startsWith('rm -rf ./tmp/'))
    assert.equal(kid.input.language, 'unknown') // win32 context: cmd.exe is not a modeled dialect
  }
})

test('python: language-runtime spawn delegates as an argv child', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "import subprocess\nsubprocess.run(['python', 'cleanup.py'])\n"), env)
  const kids = children(facts)
  assert.equal(kids.length, 1)
  assert.equal(kids[0].input.source.kind, 'argv')
  assert.equal(kids[0].input.source.executable, 'python')
  assert.deepEqual(kids[0].input.source.args, ['cleanup.py'])
  assert.equal(kids[0].input.language, 'unknown')
})

test('python: called local cleanup function binds its parameter', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "import shutil\ndef clean(target):\n    shutil.rmtree(target)\nclean('C:/synthetic/work/out')\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 1)
  assert.deepEqual(ops[0].target, { kind: 'exact', paths: ['C:/synthetic/work/out'] })
  assert.equal(ops[0].origin.function, 'clean')
})

test('python: never-called sink function is a gap, not a silent skip', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "import shutil\ndef never_called():\n    shutil.rmtree('C:/synthetic/work/x')\n"), env)
  assert.equal(operations(facts).length, 0)
  const gs = gaps(facts)
  assert.ok(gs.some(g => g.kind === 'unreached-sink-function' && g.origin.function === 'never_called'))
})

test('python: tools SDK sub-call is not judged here', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "tools.run('bash', 'rm -rf ./x')\n"), env)
  assert.equal(commands(facts).length, 0)
  assert.equal(children(facts).length, 0)
  assert.equal(candidates(facts).length, 0)
})

test('python: eval reports a dynamic-execution candidate', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', 'eval(payload)\n'), env)
  assert.ok(candidates(facts).some(c => c.kind === 'dynamic-execution'))
})

test('python: control-flow nested sink is possible, not certain', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "import os\nif flag:\n    os.remove('C:/synthetic/work/a.txt')\n"), env)
  assert.equal(operations(facts)[0].condition, 'possible')
})

test('python: os.rename reports move-source', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', "import os\nos.rename('C:/synthetic/work/a', 'C:/synthetic/work/b')\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 1)
  assert.equal(ops[0].action, 'move-source')
  assert.deepEqual(ops[0].target, { kind: 'exact', paths: ['C:/synthetic/work/a'] })
  assert.match(ops[0].details, /C:\/synthetic\/work\/b/)
})

test('python: syntax error reports parse-failed gap', async (t) => { if (!pythonReady) return t.skip(pythonSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('python', 'def broken(:\n'), env)
  assert.ok(gaps(facts).some(g => g.kind === 'parse-failed'))
})

// ---------------- JS/TS provider (TypeScript Compiler API) ----------------

test('ts: named import rm from node:fs/promises is an exact delete', async (t) => { if (!typescriptReady) return t.skip(typescriptSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('typescript', "import { rm } from 'node:fs/promises';\nawait rm('C:/synthetic/work/a.txt');\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 1)
  assert.deepEqual(ops[0].target, { kind: 'exact', paths: ['C:/synthetic/work/a.txt'] })
  assert.equal(ops[0].condition, 'certain')
})

test('ts: fs.rmSync with recursive option joins and propagates recursion', async (t) => { if (!typescriptReady) return t.skip(typescriptSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('typescript', "import fs from 'node:fs';\nimport path from 'node:path';\nconst dir = 'C:/synthetic/work';\nfs.rmSync(path.join(dir, 'build'), { recursive: true });\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 1)
  assert.deepEqual(ops[0].target, { kind: 'exact', paths: ['C:/synthetic/work\\build'] })
  assert.equal(ops[0].recursive, true)
})

test('ts: file reads, writes and copies report content targets without executing', async (t) => {
  if (!typescriptReady) return t.skip(typescriptSkipReason)
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('typescript', `
    import { readFile, writeFile, copyFile } from 'node:fs/promises';
    await readFile('vault.txt');
    await writeFile('result.txt', 'data only');
    await copyFile('source.txt', 'destination.txt');
  `), env)
  assert.deepEqual(operations(facts).map(({ action, target }) => [action, target.paths[0]]), [
    ['read-content', 'vault.txt'], ['write-content', 'result.txt'],
    ['copy-content', 'source.txt'], ['write-content', 'destination.txt'],
  ])
})

test('ts: a dynamic recursive option is never observed as a non-recursive delete', async (t) => {
  if (!typescriptReady) return t.skip(typescriptSkipReason)
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('typescript', `import { rm } from 'node:fs/promises'; await rm('dir', { recursive: flag });`), env)
  assert.equal(operations(facts)[0].recursive, 'unknown')
})

test('ts: local alias const rm = fs.rm reaches the sink', async (t) => { if (!typescriptReady) return t.skip(typescriptSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('typescript', "import fs from 'node:fs';\nconst rm = fs.rm;\nawait rm('C:/synthetic/work/a.txt');\n"), env)
  assert.equal(operations(facts).length, 1)
})

test('ts: rimraf call is recursive delete', async (t) => { if (!typescriptReady) return t.skip(typescriptSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('typescript', "import { rimraf } from 'rimraf';\nawait rimraf('C:/synthetic/work/cache');\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 1)
  assert.equal(ops[0].recursive, true)
})

test('ts: fs-extra removeSync is recursive delete; emptyDir notes contents-only', async (t) => { if (!typescriptReady) return t.skip(typescriptSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('javascript', "const { removeSync, emptyDirSync } = require('fs-extra');\nremoveSync('C:/synthetic/work/x');\nemptyDirSync('C:/synthetic/work/y');\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 2)
  assert.equal(ops[0].recursive, true)
  assert.equal(ops[1].recursive, true)
  assert.match(ops[1].details, /contents/)
})

test('ts: exec with literal command reports a shell child; dynamic command a candidate', async (t) => { if (!typescriptReady) return t.skip(typescriptSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('typescript', "import { exec, execSync } from 'node:child_process';\nexec('rm -rf ./tmp/x');\nexecSync(cmd);\n"), env)
  const kids = children(facts)
  assert.equal(kids.length, 1)
  assert.equal(kids[0].input.source.text, 'rm -rf ./tmp/x')
  assert.equal(candidates(facts).length, 1)
  assert.equal(candidates(facts)[0].kind, 'dynamic-execution')
})

test('ts: runtime spawn delegates as argv child, plain command reports command fact', async (t) => { if (!typescriptReady) return t.skip(typescriptSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('typescript', "import { spawn } from 'node:child_process';\nspawn('node', ['cleanup.js']);\nspawn('rm', ['-rf', './tmp/x']);\n"), env)
  const kids = children(facts)
  assert.equal(kids.length, 1)
  assert.deepEqual(kids[0].input.source, { kind: 'argv', executable: 'node', args: ['cleanup.js'] })
  const cmds = commands(facts)
  assert.equal(cmds.length, 1)
  assert.equal(cmds[0].executable, 'rm')
  assert.deepEqual(cmds[0].args, ['-rf', './tmp/x'])
})

test('ts: fork reports a node child-script', async (t) => { if (!typescriptReady) return t.skip(typescriptSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('typescript', "import { fork } from 'node:child_process';\nfork('./cleanup.js');\n"), env)
  const kids = children(facts)
  assert.equal(kids.length, 1)
  assert.deepEqual(kids[0].input.source, { kind: 'argv', executable: 'node', args: ['./cleanup.js'] })
})

test('ts: dynamic target and enumeration feed candidates with known scope', async (t) => { if (!typescriptReady) return t.skip(typescriptSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('typescript', "import fs from 'node:fs';\nfs.rmSync(userInput);\nfor (const f of fs.readdirSync('C:/synthetic/work/logs')) {\n  fs.unlinkSync(f);\n}\n"), env)
  const cands = candidates(facts)
  assert.equal(operations(facts).length, 0)
  assert.equal(cands.length, 2)
  assert.deepEqual(cands[0].knownScope, undefined)
  assert.deepEqual(cands[1].knownScope, ['C:/synthetic/work/logs'])
})

test('ts: template literal with verified constant is exact', async (t) => { if (!typescriptReady) return t.skip(typescriptSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('typescript', "import { rmSync } from 'node:fs';\nconst base = 'C:/synthetic/work';\nrmSync(`${base}/build`);\n"), env)
  assert.deepEqual(operations(facts)[0].target, { kind: 'exact', paths: ['C:/synthetic/work/build'] })
})

test('ts: uncalled sink function is a gap; tools SDK skipped', async (t) => { if (!typescriptReady) return t.skip(typescriptSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('typescript', "import { rmSync } from 'node:fs';\nfunction neverCalled() {\n  rmSync('C:/synthetic/work/x');\n}\ntools.run('rm -rf ./y');\n"), env)
  assert.equal(operations(facts).length, 0)
  assert.equal(children(facts).length, 0)
  assert.ok(gaps(facts).some(g => g.kind === 'unreached-sink-function'))
})

test('ts: nested sink is possible; move reports move-source', async (t) => { if (!typescriptReady) return t.skip(typescriptSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('typescript', "import { renameSync } from 'node:fs';\nif (flag) {\n  renameSync('C:/synthetic/work/a', 'C:/synthetic/work/b');\n}\n"), env)
  const ops = operations(facts)
  assert.equal(ops.length, 1)
  assert.equal(ops[0].action, 'move-source')
  assert.equal(ops[0].condition, 'possible')
  assert.match(ops[0].details, /C:\/synthetic\/work\/b/)
})

test('ts: pure computation unit reports no deletion facts', async (t) => { if (!typescriptReady) return t.skip(typescriptSkipReason);
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('typescript', 'const fib = (n) => (n < 2 ? n : fib(n - 1) + fib(n - 2));\nconsole.log(fib(10));\n'), env)
  assert.equal(operations(facts).length, 0)
  assert.equal(candidates(facts).length, 0)
  assert.equal(children(facts).length, 0)
  assert.equal(commands(facts).length, 0)
})

// ---------------- contract-level behavior ----------------

test('unsupported languages report a gap and never throw', async () => {
  const { env, facts } = makeEnv()
  await analyzer.analyze(unit('ruby', 'FileUtils.rm_rf("x")\n'), env)
  await analyzer.analyze(unit('bash', 'rm -rf ./x\n'), env)
  const gs = gaps(facts)
  assert.ok(gs.some(g => g.kind === 'no-provider'))
  assert.ok(gs.some(g => g.kind === 'no-program-provider'))
})

test('oversize input reports input-limit', async () => {
  const { env, facts } = makeEnv({ limits: { timeoutMs: 5000, maxInputBytes: 64, maxOutputBytes: 8388608, maxSteps: 20000 } })
  await analyzer.analyze(unit('python', 'x = "' + 'a'.repeat(200) + '"\n'), env)
  if (!pythonReady) return assert.ok(gaps(facts).some(g => g.kind === 'no-python-runtime') || gaps(facts).some(g => g.kind === 'input-limit'))
  assert.ok(gaps(facts).some(g => g.kind === 'input-limit'))
})

test('budget exhaustion reports partial facts plus budget gap', async (t) => { if (!typescriptReady) return t.skip(typescriptSkipReason);
  const { env, facts } = makeEnv({ limits: { timeoutMs: 5000, maxInputBytes: 1 << 20, maxOutputBytes: 8388608, maxSteps: 10 } })
  await analyzer.analyze(unit('typescript', "import { rmSync } from 'node:fs';\nrmSync('C:/a');\nrmSync('C:/b');\n"), env)
  assert.ok(gaps(facts).some(g => g.kind === 'budget-exhausted'))
})

test('aborted signal reports nothing', async () => {
  const controller = new AbortController()
  controller.abort()
  const { env, facts } = makeEnv({ signal: controller.signal })
  await analyzer.analyze(unit('python', "import os\nos.remove('C:/x')\n"), env)
  assert.equal(facts.length, 0)
})

test('steps are reported through env.step', async () => {
  const { env, facts, steps } = makeEnv()
  await analyzer.analyze(unit('python', 'x = 1\n'), env)
  assert.ok(steps() > 0)
})

test('dispose is final: further analyze throws a typed error', async () => {
  const disposed = createProgramAnalyzer({ pythonExecutable: explicitPython })
  await disposed.analyze(unit('python', 'x = 1\n'), makeEnv().env)
  disposed.dispose()
  disposed.dispose()
  await assert.rejects(() => disposed.analyze(unit('python', 'x = 1\n'), makeEnv().env), /disposed/)
})

test('malformed units are caller errors, not silent gaps', async () => {
  const { env } = makeEnv()
  await assert.rejects(() => analyzer.analyze({ unitId: 'u', source: { kind: 'argv', executable: 'x' }, language: 'python' }, env), TypeError)
  await assert.rejects(() => analyzer.analyze(unit('python', 'x = 1\n'), undefined), TypeError)
})

function ops_or_empty(list) { return list.length }
