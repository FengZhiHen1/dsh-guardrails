// verify/run-verify.mjs — full verification for dsh-guardrails:
//   1. unit + integration + lifecycle tests (node --test test/)
//   2. coverage report (node --test --experimental-test-coverage)
//   3. composition assertions against the installed profiles
//      (test and web: exactly one guardrails row resolving to dsh-guardrails;
//       web dependency spec must be a release form, never a source link)
//   4. test-profile boot smoke (publish gate): boot the real test profile
//      with the plugin mounted and assert it stays alive (no crash, no
//      "did not activate" / load failures) before terminating it.
//   5. clean-install smoke: npm pack → install the tarball into a temp dir →
//      import and basic-apply the installed package (no source tree, no
//      monorepo siblings).
// The real-session behavior check stays manual: restart the test profile
// afterwards and exercise actual interception behavior.
//
// Environment: DSH_HARNESS_ROOT (default E:/Project/Open_Source/deepseek-harness)
// and DSH_HOME (default ~/.dsh). Run from the package root.

import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { homedir, tmpdir } from 'node:os'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..')
// Glob form: `node --test <dir>` fails to resolve directories on Windows.
const TESTS = join(ROOT, 'test', '*.test.mjs')
const HARNESS = process.env.DSH_HARNESS_ROOT ?? 'E:/Project/Open_Source/deepseek-harness'
// 部署校验一律用全局 CLI（AGENTS.md 红线）：源码检出的 apps/cli/lib 可能
// 过期（workspace 包的 lib 未随 src 重建——例如 credentials-local 曾为旧
// 平面布局解析器），只有显式设置 DSH_HARNESS_ROOT 时才使用源码检出 launcher
//（开发者自担构建新鲜度；参考用途：跑 DSH 自身 tests）。
const LAUNCHER = process.env.DSH_HARNESS_ROOT
  ? join(HARNESS, 'apps', 'cli', 'lib', 'bin.js')
  : 'C:/nvm4w/nodejs/node_modules/@deepseek-ai/dsh/lib/bin.js'
const DSH_HOME = process.env.DSH_HOME ?? join(homedir(), '.dsh')
// npm invoked as `node <npm-cli.js>`: `npm.cmd` cannot be spawned directly.
const NPM_CLI = join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')

let failures = 0
function step(name, ok, detail = '') {
  console.log(`${ok ? '✓' : '✗'} ${name}${detail ? ` — ${detail}` : ''}`)
  if (!ok) failures += 1
}
function run(args, cwd, env = process.env) {
  return spawnSync(process.execPath, args, { cwd, encoding: 'utf8', env })
}
function runNpm(args, cwd) {
  return spawnSync(process.execPath, [NPM_CLI, ...args], { cwd, encoding: 'utf8' })
}

// 1. unit + integration
const tests = run(['--test', TESTS], ROOT)
step('单元 + 集成测试', tests.status === 0)
if (tests.status !== 0) {
  process.stdout.write(tests.stdout ?? '')
  process.stderr.write(tests.stderr ?? '')
}

// 2. coverage gate: parse the "all files" line of the text report and assert
// the line-coverage threshold (≥80%) automatically.
const COVERAGE_THRESHOLD = 80
const cov = run(['--test', '--experimental-test-coverage', TESTS], ROOT)
step('覆盖率报告生成', cov.status === 0)
if (cov.status === 0) {
  const all = `${cov.stdout ?? ''}\n${cov.stderr ?? ''}`
  const lines = all.split('\n')
  const table = lines.filter((l) => /^\s*ℹ (?:file|all files|-+)/.test(l))
  console.log('--- 覆盖率摘要 ---')
  console.log(table.join('\n'))
  const allFiles = lines.find((l) => /^\s*ℹ all files\s*\|/.test(l))
  const match = allFiles ? allFiles.match(/\|\s*([\d.]+)/) : null
  const linePct = match ? Number(match[1]) : NaN
  step(
    `覆盖率门禁：行覆盖 ≥${COVERAGE_THRESHOLD}%`,
    Number.isFinite(linePct) && linePct >= COVERAGE_THRESHOLD,
    Number.isFinite(linePct) ? `${linePct}%` : '无法解析',
  )
}

// 3. composition assertions
if (!existsSync(LAUNCHER)) {
  step('组合断言', false, `launcher 不存在：${LAUNCHER}（设置 DSH_HARNESS_ROOT）`)
} else {
  const env = { ...process.env, DSH_HOME }
  // A stable profile must never mount source: the dependency spec must be a
  // release form (registry range or a tarball), never `link:`/`file:` into a
  // source directory, and the resolved node_modules entry must not be a
  // junction/symlink back to source.
  const webManifestPath = join(DSH_HOME, 'profiles', 'web', 'package.json')
  const webDep = existsSync(webManifestPath)
    ? JSON.parse(readFileSync(webManifestPath, 'utf8')).dependencies?.['dsh-guardrails']
    : undefined
  const releaseSpec = typeof webDep === 'string'
    && !webDep.startsWith('link:')
    && (webDep.startsWith('^') || webDep.startsWith('~') || /\.tgz$/.test(webDep)
      || /^github:/.test(webDep) || /^git\+https:\/\//.test(webDep))
  for (const profile of ['test', 'web']) {
    const dump = run([LAUNCHER, '--profile', profile, '--dump-config'], HARNESS, env)
    const out = `${dump.stdout ?? ''}\n${dump.stderr ?? ''}`
    const rowCount = (out.match(/id: guardrails/g) ?? []).length
    const resolved = /name: dsh-guardrails/.test(out)
    step(`组合：${profile} 恰一行且解析自 dsh-guardrails`, rowCount === 1 && resolved, `行数=${rowCount}`)
  }
  step(
    '组合：web 依赖为发布物形态（registry 范围、tarball 或 github: 钉 ref，非源码直挂）',
    releaseSpec === true,
    `spec=${webDep ?? '未找到'}`,
  )
}

// 4. test-profile boot smoke (publish gate): the plugin must not crash a real
// DSH boot. Boots the installed launcher against the test profile on an
// ephemeral port (--port 0) without opening a browser; the process must stay
// alive for the whole warm-up window and print no activation/load errors.
const BOOT_SMOKE_WAIT_MS = 30_000
const BOOT_ERROR_MARK = /did not activate|failed to load|duplicate loader entry id|fatal load failure|invalid config|host preparation failed|plugin tree failed to load/
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
async function bootSmoke() {
  // SSH 变量非空 → web-runtime 跳过默认浏览器交接（--no-open 在
  // `-profile` 透传形态下易被 launcher/commander 误解析，交给环境开关）。
  const env = { ...process.env, DSH_HOME, SSH_CONNECTION: '1', SSH_TTY: '1' }
  if (!existsSync(LAUNCHER)) return { ok: false, detail: `launcher 不存在：${LAUNCHER}（设置 DSH_HARNESS_ROOT）` }
  const child = spawn(
    process.execPath,
    // 第一个 `--` 由 launcher 消耗（apps/cli/src/args.ts），`--port 0` 送达应用。
    [LAUNCHER, '--profile', 'test', '--', '--port', '0'],
    { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] },
  )
  let out = ''
  let err = ''
  child.stdout.on('data', (d) => { out += d })
  child.stderr.on('data', (d) => { err += d })
  let exited = null
  child.on('exit', (code, signal) => { exited = { code, signal } })
  await sleep(BOOT_SMOKE_WAIT_MS)
  let terminatedByUs = false
  if (exited === null) {
    terminatedByUs = true
    child.kill('SIGTERM')
    await new Promise((resolve) => child.once('close', resolve))
  }
  const all = `${out}\n${err}`
  const bad = BOOT_ERROR_MARK.test(all)
  if (terminatedByUs) {
    // 跑满了整个窗口才由我们终止：启动未崩溃。错误标记仍然门禁。
    return {
      ok: !bad,
      detail: `test profile 启动存活 ≥${BOOT_SMOKE_WAIT_MS / 1000}s${bad ? '，但输出含错误标记' : ' 且无错误标记'}`,
    }
  }
  return {
    ok: false,
    detail: `test profile 启动提前退出（code=${exited.code} signal=${exited.signal}）：${err.slice(0, 300)}`,
  }
}
{
  const smoke = await bootSmoke()
  step('发布门禁：test profile 启动冒烟（无崩溃）', smoke.ok, smoke.detail)
}

// 5. clean-install smoke: pack → install into a temp dir → import + apply.
if (!existsSync(NPM_CLI)) {
  step('发布：干净目录安装 + 导入冒烟', false, `npm CLI 不可用（${NPM_CLI}）`)
} else {
  const packDir = mkdtempSync(join(tmpdir(), 'dsh-guardrails-pack-'))
  const pack = runNpm(['pack', '--silent', '--pack-destination', packDir], ROOT)
  if (pack.status !== 0) {
    step('发布：干净目录安装 + 导入冒烟', false, `npm pack 失败：${pack.stderr ?? ''}`)
    rmSync(packDir, { recursive: true, force: true })
  } else {
    const tarball = join(packDir, (pack.stdout ?? '').trim())
    const installDir = mkdtempSync(join(tmpdir(), 'dsh-guardrails-smoke-'))
    try {
      writeFileSync(
        join(installDir, 'package.json'),
        JSON.stringify({ name: 'guardrails-smoke', private: true }),
      )
      const install = runNpm(
        ['install', '--no-save', '--no-audit', '--no-fund', '--loglevel=error', tarball],
        installDir,
      )
      const installedRoot = join(installDir, 'node_modules', 'dsh-guardrails')
      const filesOk =
        existsSync(join(installedRoot, 'index.js')) &&
        existsSync(join(installedRoot, 'client.js')) &&
        existsSync(join(installedRoot, 'lib', 'command.js')) &&
        existsSync(join(installedRoot, 'cordis.patch.yml'))
      const importRun = run(
        [
          '--input-type=module',
          '-e',
          "import('dsh-guardrails').then(m => { if (typeof m.name !== 'string' || typeof m.apply !== 'function' || typeof m.Config !== 'function') process.exit(2) })",
        ],
        installDir,
      )
      const importOk = importRun.status === 0
      step(
        '发布：干净目录安装 + 导入冒烟',
        install.status === 0 && filesOk && importOk,
        install.status !== 0
          ? `npm install 失败：${install.stderr ?? ''}`
          : importOk
            ? 'tarball 可独立安装并导入'
            : `导入冒烟失败（exit ${importRun.status}）：${(importRun.stderr ?? '').slice(0, 300)}`,
      )
    } finally {
      rmSync(installDir, { recursive: true, force: true })
      rmSync(packDir, { recursive: true, force: true })
    }
  }
}

console.log(
  failures === 0
    ? '\n全部通过。冒烟（手动）：重启 test profile 后验证真实拦截行为。'
    : `\n${failures} 项失败`,
)
process.exit(failures === 0 ? 0 : 1)
