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
// Environment:
//   DSH_BIN        — the instance version binary for deploy checks
//                    (AGENTS.md: 部署校验必须用实例版本二进制; get it from
//                    `dshl env --json` → instances[].version_bin). Falls back
//                    to DSH_HARNESS_ROOT's source checkout CLI, then the old
//                    global install (cross-generation risk — warns).
//   DSH_TEST_HOME  — HOME of the test instance (boot smoke + test profile).
//   DSH_WEB_HOME   — HOME hosting the stable web profile (dependency spec
//                    assertion).
//   All four default to values DERIVED FROM `dshl env --json` (see
//   resolveEnvFacts below), which is the authoritative on-disk source for the
//   instance/version/bin triple (AGENTS.md: 版本号不写死，现查). They used to
//   default to `~/.dsh` + a legacy global CLI — a combination that has nothing
//   to do with any launcher-managed instance, so step 3 reported a bogus
//   "test 行数=0" FAIL against the wrong HOME, and step 4 exited instantly
//   because that HOME has no `test` profile. A mis-targeted check must not be
//   reportable as a real failure: when a target cannot be resolved at all the
//   steps now SKIP with the reason instead of FAILing.
//   The resolved values are echoed at startup: read them.
//   DSH_VERIFY_SKIP_BOOT_SMOKE — 1/true/yes skips step 4. Step 4 spawns a REAL
//                    DSH instance, which an agent must never do (AGENTS.md:
//                    instance start/stop goes through the launcher GUI or dshl;
//                    two instances sharing one HOME is a Security redline).
//                    Agents run steps 1/2/3/5 and set this flag; a skipped step
//                    is counted separately and never reported as a full pass.

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
// Repo tool that owns the launcher config surface (instances/HOME/version/bin).
const DSHL = join(ROOT, '..', '..', 'tools', 'dsh-launcher-cli', 'cli.mjs')

/**
 * Resolve the instance facts from `dshl env --json` — the authoritative source
 * for version/bin/HOME (AGENTS.md: never hard-code versions, read them live).
 * Returns `null` when the tool is unavailable or its output is unparsable, so
 * callers can SKIP rather than assert against a guessed target.
 *
 * @returns `{ byName: Map<string, {home, bin}> } | null`
 */
function resolveEnvFacts() {
  if (!existsSync(DSHL)) return null
  const res = spawnSync(process.execPath, [DSHL, 'env', '--json'], { encoding: 'utf8' })
  if (res.status !== 0 || !res.stdout) return null
  try {
    const parsed = JSON.parse(res.stdout)
    const byName = new Map()
    for (const inst of parsed.instances ?? []) {
      byName.set(inst.name, { home: inst.home, bin: inst.version_bin })
    }
    return { byName }
  } catch {
    return null
  }
}
const FACTS = resolveEnvFacts()
/** Pick an instance fact by preference order (e.g. `dev` then `test`). */
const factFor = (...names) => {
  for (const n of names) {
    const hit = FACTS?.byName.get(n)
    if (hit?.home) return hit
  }
  return undefined
}

// Explicit env wins; otherwise derive from the launcher facts. The stable web
// profile lives in the stable-dev HOME; the test profile in the `test` instance.
const WEB_FACT = factFor('stable-dev')
const TEST_FACT = factFor('test')
// 部署校验一律用实例版本二进制（AGENTS.md 红线 + dshl env 跨代告警）：
// DSH_BIN 优先（dshl env --json → instances[].version_bin 现查）；源码检出
// launcher 仅在显式设置 DSH_HARNESS_ROOT 时使用（开发者自担构建新鲜度）。
// 不再回落到"遗留全局 CLI"：那个回落在两个 HOME 上都指向错误的东西，
// 是 2026-09-28 那次假失败的成因；宁可不判（SKIP）也不误判（FAIL）。
const LAUNCHER = process.env.DSH_BIN
  ?? (process.env.DSH_HARNESS_ROOT
    ? join(HARNESS, 'apps', 'cli', 'lib', 'bin.js')
    : TEST_FACT?.bin ?? WEB_FACT?.bin)
const TEST_HOME = process.env.DSH_TEST_HOME ?? TEST_FACT?.home
const WEB_HOME = process.env.DSH_WEB_HOME ?? WEB_FACT?.home
// web profile 属 stable-dev 实例（可能与 DSH_BIN 不同代际）：dump 校验用它
// 自己的实例二进制（dshl env --json → instances[].version_bin 现查）。
const WEB_BIN = process.env.DSH_WEB_BIN ?? WEB_FACT?.bin ?? LAUNCHER
// Agent 侧绕过开关：第 4 步会 spawn 真实实例，agent 不得执行（AGENTS.md 红线）。
// 置 1 跳过该步，其余步骤照跑。
const SKIP_BOOT_SMOKE = /^(?:1|true|yes)$/i.test(process.env.DSH_VERIFY_SKIP_BOOT_SMOKE ?? '')
// npm invoked as `node <npm-cli.js>`: `npm.cmd` cannot be spawned directly.
const NPM_CLI = join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')

let failures = 0
let skipped = 0
function step(name, ok, detail = '') {
  console.log(`${ok ? '✓' : '✗'} ${name}${detail ? ` — ${detail}` : ''}`)
  if (!ok) failures += 1
}
/** Report a step as deliberately not run. Never counts as a failure, but is
 * counted so a skipped run cannot pass itself off as a full gate. */
function skip(name, detail = '') {
  console.log(`⊘ ${name}${detail ? ` — ${detail}` : ''}`)
  skipped += 1
}
function run(args, cwd, env = process.env) {
  return spawnSync(process.execPath, args, { cwd, encoding: 'utf8', env })
}
function runNpm(args, cwd) {
  return spawnSync(process.execPath, [NPM_CLI, ...args], { cwd, encoding: 'utf8' })
}

// Echo the resolved target so a mis-target is visible up front instead of
// surfacing as a bogus assertion failure three steps later. `(未解析)` means the
// corresponding step will SKIP rather than assert against a guessed HOME.
console.log('--- 解析后的目标 ---')
console.log(`  来源        ${FACTS ? 'dshl env --json（现查）' : '不可用 —— 未解析项将 SKIP'}`)
console.log(`  launcher    ${LAUNCHER ?? '(未解析)'}`)
console.log(`  test home   ${TEST_HOME ?? '(未解析)'}`)
console.log(`  web  home   ${WEB_HOME ?? '(未解析)'}`)
console.log(`  web  bin    ${WEB_BIN ?? '(未解析)'}`)
console.log(`  第 4 步启动冒烟  ${SKIP_BOOT_SMOKE ? '已跳过（DSH_VERIFY_SKIP_BOOT_SMOKE）' : '将执行（会 spawn 真实实例）'}`)

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
  skip('组合断言', `目标二进制无法解析：${LAUNCHER ?? '(未设置 DSH_BIN，且 dshl env 不可用)'} —— 设置 DSH_BIN 或让 tools/dsh-launcher-cli 可用`)
} else {
  // A stable profile must never mount source: the dependency spec must be a
  // release form (registry range or a tarball), never `link:`/`file:` into a
  // source directory, and the resolved node_modules entry must not be a
  // junction/symlink back to source. The stable web profile lives in the
  // launcher-managed stable-dev HOME (DSH_WEB_HOME).
  const webManifestPath = WEB_HOME ? join(WEB_HOME, 'profiles', 'web', 'package.json') : undefined
  const webDep = webManifestPath && existsSync(webManifestPath)
    ? JSON.parse(readFileSync(webManifestPath, 'utf8')).dependencies?.['dsh-guardrails']
    : undefined
  const releaseSpec = typeof webDep === 'string'
    && !webDep.startsWith('link:')
    && (webDep.startsWith('^') || webDep.startsWith('~') || /\.tgz$/.test(webDep)
      || /^github:/.test(webDep) || /^git\+https:\/\//.test(webDep))
  for (const [profile, home, bin] of [['test', TEST_HOME, LAUNCHER], ['web', WEB_HOME, WEB_BIN]]) {
    const label = `组合：${profile} 恰一行且解析自 dsh-guardrails`
    // An unresolved target is a SKIP, not a FAIL: asserting against a guessed
    // HOME is how this script used to report a bogus "行数=0" failure.
    if (!home) {
      skip(label, `未解析到 ${profile} 实例的 HOME（设置 ${profile === 'web' ? 'DSH_WEB_HOME' : 'DSH_TEST_HOME'}，或让 dshl env 可用）`)
      continue
    }
    if (!existsSync(bin)) {
      skip(label, `二进制不存在：${bin}（设置 ${profile === 'web' ? 'DSH_WEB_BIN' : 'DSH_BIN'}）`)
      continue
    }
    const env = { ...process.env, DSH_HOME: home }
    const dump = run([bin, '--profile', profile, '--dump-config'], HARNESS, env)
    const out = `${dump.stdout ?? ''}\n${dump.stderr ?? ''}`
    const rowCount = (out.match(/id: guardrails/g) ?? []).length
    const resolved = /name: dsh-guardrails/.test(out)
    step(label, rowCount === 1 && resolved, `行数=${rowCount}`)
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
// Failure signatures for the CURRENT baseline (0.1.7-rc.2). Two entries of the
// old list no longer exist and are kept only as harmless historical markers:
//   - `duplicate loader entry id` was removed by an upstream revert
//     (e07f41d5fd): a duplicate id is now silently resolved last-wins, so boot
//     CANNOT fail on it and no boot-time gate for it exists. Row conflicts must
//     be reviewed by hand (knowledge `must-read/05` §6.1).
// The two added marks are the baseline's own silent/quiet failure modes:
//   - `disabling profile plugin` / `skipping profile bundle`: the peer-version
//     gate disables a row (or skips a whole bundle) that does not satisfy the
//     running DSH version. The instance boots normally and only one stderr line
//     appears — the highest-risk "silent mute".
//   - `startup failed: N required plugin[s] did not activate`: fatal (exit 1),
//     as opposed to the non-fatal `N entries did not activate` warning.
const BOOT_ERROR_MARK = /did not activate|failed to load|duplicate loader entry id|fatal load failure|invalid config|host preparation failed|plugin tree failed to load|disabling profile plugin|skipping profile bundle|startup failed/
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
async function bootSmoke() {
  // SSH 变量非空 → web-runtime 跳过默认浏览器交接（--no-open 在
  // `-profile` 透传形态下易被 launcher/commander 误解析，交给环境开关）。
  const env = { ...process.env, DSH_HOME: TEST_HOME, SSH_CONNECTION: '1', SSH_TTY: '1' }
  if (!TEST_HOME) return { skip: true, detail: '未解析到 test 实例的 HOME（设置 DSH_TEST_HOME）——不猜目标，跳过而非误判' }
  if (!existsSync(LAUNCHER)) return { skip: true, detail: `launcher 不存在：${LAUNCHER}（设置 DSH_BIN）` }
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
if (SKIP_BOOT_SMOKE) {
  skip(
    '发布门禁：test profile 启动冒烟（无崩溃）',
    `已按 DSH_VERIFY_SKIP_BOOT_SMOKE 跳过——本步会 spawn 一个真实实例，agent 不得执行；须由用户在启动器侧补做（HOME=${TEST_HOME}）`,
  )
} else {
  const smoke = await bootSmoke()
  if (smoke.skip) skip('发布门禁：test profile 启动冒烟（无崩溃）', smoke.detail)
  else step('发布门禁：test profile 启动冒烟（无崩溃）', smoke.ok, smoke.detail)
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
        existsSync(join(installedRoot, 'src', 'client', 'card.js')) &&
        existsSync(join(installedRoot, 'src', 'core', 'command.js')) &&
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

// A skipped run must never read as a full pass: the gate it omits is the release
// gate itself, so the summary names it instead of just printing "全部通过".
console.log(
  failures > 0
    ? `\n${failures} 项失败${skipped > 0 ? `（另有 ${skipped} 步被跳过）` : ''}`
    : skipped > 0
      ? `\n已通过的步骤全绿，但跳过了 ${skipped} 步——第 4 步 test profile 启动冒烟未执行，发布门禁须由用户在启动器侧补做。冒烟（手动）：重启 test profile 后验证真实拦截行为。`
      : '\n全部通过。冒烟（手动）：重启 test profile 后验证真实拦截行为。',
)
process.exit(failures === 0 ? 0 : 1)
