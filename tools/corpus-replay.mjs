// tools/corpus-replay.mjs — replay real agent pwsh commands through the live
// judgment core, and report what the guard would do to each of them.
//
// WHY THIS EXISTS (and why it is not a unit test):
//   DSR-012 was diagnosed by decoding the session logs of a live DSH HOME and
//   re-running 9062 real pwsh commands through the then-current rules: 478 were
//   denied, 413 of them as "the command itself is computed", and 397 of those
//   were a bare double-quoted OUTPUT statement. That corpus is the only reason
//   the false positive was found — the unit suite was green the whole time.
//   A unit test cannot carry it: the corpus lives in a user HOME (never to be
//   committed per AGENTS.md Security), drifts with the retention window, and
//   its absolute numbers change every run. So the corpus is a FORENSIC TOOL,
//   run on demand, and its findings get promoted into test/ as assertions.
//
// WHAT IT REPLACES: the ~15 `tmp/guardrails-*.mjs` probes that each re-implemented
//   session-log walking, zstd frame decoding and command extraction. tmp/ is
//   gitignored, so those were lost on every cleanup.
//
// USAGE (read-only; never writes to the HOME it reads):
//   node tools/corpus-replay.mjs --home <DSH_HOME> [options]
//
//   --home <path>      Session root to read (a DSH HOME; sessions/ below it).
//                      REQUIRED. Get it from `dshl env --json` → instances[].home.
//   --base <path>      Workspace root used as the judgment base (default
//                      E:/Project/DSH_Plugins). Only affects rules that compare
//                      against the workspace root — see the note at `base`.
//   --days <n>         Only sessions modified in the last n days (default 4).
//   --limit <n>        Cap the number of commands replayed (0 = all).
//   --show <n>         Print up to n sample commands per class (default 3).
//   --class <name>     Only report this class (repeatable). See CLASSES below.
//   --json             Emit machine-readable JSON instead of the text report.
//   --baseline <file>  Compare against an earlier --json snapshot (see below).
//
// BASELINE MODE (the point of the tool):
//   # before a rule change
//   node tools/corpus-replay.mjs --home <HOME> --json > before.json
//   # after the rule change
//   node tools/corpus-replay.mjs --home <HOME> --json --baseline before.json
//
//   It replays the SAME command set against the SAME base and reports, per
//   class, which commands flipped. Every newly-blocked command must be
//   justified: a block added to a legitimate command is a false positive
//   shipped to the user.
//
//   ⚠ The comparison is only meaningful while the corpus is unchanged. If the
//   command count differs between the two snapshots the tool says so loudly and
//   still reports, because the window (`--days`) or the HOME may have moved.
//
//   For an A/B against a PREVIOUS VERSION of the core, the honest method is not
//   a flag here: `git stash` the change, save a --json snapshot, unstash, and
//   compare. That is what DSR-012 did (tmp/guardrails-oldvsnew.mjs).
//
// SAFETY: strictly read-only. It opens session logs for reading and nothing
//   else. It does NOT boot an instance, does NOT touch a profile, and must not
//   be pointed at a HOME to make it "do" anything: agent-driven instance
//   start/stop goes through the launcher or `dshl` (AGENTS.md redline).
//
// PACKAGING: deliberately absent from package.json `files`, so it is not
//   published to npm — it is a maintainer tool, not plugin behavior.
//
// Exit code: 0 on success (including "commands were denied" — that is data,
//   not a failure), 2 on usage/IO errors.

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { zstdDecompressSync } from 'node:zlib'

import { checkCommand } from '../src/core/check-command.js'
import { evaluateRules } from '../src/core/rules.js'

// ---------- session-log decoding (DSH physical frame contract) ----------
// Frame boundary: magic 28 B5 2F FD. Each frame is zstd-compressed and the
// payload is the concatenation of the decompressed frames — see
// knowledge/v0.1.7-rc.2/host/25-session-log-jsonl-zstd.md §4. Do not "fix" this
// by decompressing the whole file: multi-frame logs would yield only the first.

const MAGIC = Buffer.from([0x28, 0xb5, 0x2f, 0xfd])

/** Decode a multi-frame zstd session log into its JSONL text. */
export function decodeZstdFrames(path) {
  const buf = readFileSync(path)
  const starts = []
  for (let i = 0; i + 4 <= buf.length; i += 1) {
    if (buf.compare(MAGIC, 0, 4, i, i + 4) === 0) starts.push(i)
  }
  if (starts.length === 0) throw new Error('no zstd frames found')
  const out = []
  for (let k = 0; k < starts.length; k += 1) {
    const from = starts[k]
    const to = k + 1 < starts.length ? starts[k + 1] : buf.length
    out.push(zstdDecompressSync(buf.subarray(from, to)))
  }
  return Buffer.concat(out).toString('utf8')
}

/** Every session log under a HOME, newest first, within the retention window. */
export function collectSessionFiles(home, days) {
  const cutoff = Date.now() - days * 24 * 3600 * 1000
  const files = []
  const walk = (dir, depth) => {
    if (depth > 3) return
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return // a missing sessions/ dir is not an error: report zero commands
    }
    for (const e of entries) {
      const p = join(dir, e.name)
      if (e.isDirectory()) walk(p, depth + 1)
      else if (/^session.*\.jsonl(\.zstd)?$/.test(e.name)) {
        try {
          if (statSync(p).mtimeMs >= cutoff) files.push(p)
        } catch {
          /* unreadable file: skip */
        }
      }
    }
  }
  walk(join(home, 'sessions'), 0)
  return files
}

/** Distinct pwsh command strings in the decoded logs, insertion-ordered. */
export function collectCommands(files) {
  const cmds = new Set()
  for (const f of files) {
    let text
    try {
      text = f.endsWith('.zstd') ? decodeZstdFrames(f) : readFileSync(f, 'utf8')
    } catch {
      continue // a corrupt or mid-write log must not abort the whole replay
    }
    for (const line of text.split('\n')) {
      if (!line.includes('"tool/call"')) continue
      let row
      try {
        row = JSON.parse(line)
      } catch {
        continue
      }
      if (row.data?.name !== 'pwsh') continue
      let args = row.data.arguments
      if (typeof args === 'string') {
        try {
          args = JSON.parse(args)
        } catch {
          continue
        }
      }
      if (typeof args?.command === 'string' && args.command) cmds.add(args.command)
    }
  }
  return [...cmds]
}

// ---------- classification ----------
// Mirrors the layer that fired, so a regression can be attributed to a rule
// rather than to "the guard blocked something". Keep in sync with
// src/core/deny-messages.js: a new message shape that does not match any branch
// here falls through to `other`, which is deliberately a signal to update this
// table.

const CLASSIFIERS = [
  ['unverifiable:command', 'the command itself is computed'],
  ['unverifiable:target', 'the target path is computed'],
  ['text-ref:git', 'references the .git'],
  ['text-ref:env', 'references a sensitive .env'],
  ['text-ref:cred', 'references a credential'],
  ['system-write', 'system area'],
  ['misuse:bracket', '[ ] in a wildcard'],
  ['misuse:literal', '-Literal*'],
  ['chain', 'chained after a move/copy'],
  ['bulk', 'piped to Remove-Item'],
  ['eval:dotnet', '.NET File/Directory'],
]

export function classify(reason) {
  if (!reason) return ''
  for (const [name, needle] of CLASSIFIERS) {
    if (reason.includes(needle)) return name
  }
  return 'destructive:other'
}

export const CLASS_NAMES = [...CLASSIFIERS.map(([n]) => n), 'destructive:other']

// ---------- replay ----------

/** Replay every command through the live core; returns per-class tallies. */
export function replay(commands, base, rules) {
  const byClass = new Map()
  const samples = new Map()
  const verdicts = new Map()
  for (const cmd of commands) {
    const reason = checkCommand(base, cmd, rules)
    verdicts.set(cmd, reason ?? null)
    if (!reason) continue
    const cls = classify(reason)
    byClass.set(cls, (byClass.get(cls) ?? 0) + 1)
    if (!samples.has(cls)) samples.set(cls, [])
    if (samples.get(cls).length < 3) samples.get(cls).push(cmd)
  }
  return { byClass, samples, verdicts }
}

// ---------- CLI ----------

const DEFAULT_BASE = 'E:/Project/DSH_Plugins'

const parseArgs = (argv) => {
  const opts = {
    home: undefined,
    base: DEFAULT_BASE,
    days: 4,
    limit: 0,
    show: 3,
    classes: [],
    json: false,
    baseline: undefined,
  }
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]
    const next = () => {
      i += 1
      if (i >= argv.length) throw new Error(`${a} requires a value`)
      return argv[i]
    }
    if (a === '--help' || a === '-h') opts.help = true
    else if (a === '--home') opts.home = next()
    else if (a === '--base') opts.base = next()
    else if (a === '--days') opts.days = Number(next())
    else if (a === '--limit') opts.limit = Number(next())
    else if (a === '--show') opts.show = Number(next())
    else if (a === '--class') opts.classes.push(next())
    else if (a === '--json') opts.json = true
    else if (a === '--baseline') opts.baseline = next()
    else throw new Error(`unknown option: ${a}`)
  }
  if (!Number.isFinite(opts.days) || opts.days < 0) throw new Error('--days must be >= 0')
  return opts
}

const USAGE = `usage: node tools/corpus-replay.mjs --home <DSH_HOME> [--base <root>] [--days n] [--limit n] [--show n] [--class name] [--json] [--baseline file.json]

Read-only forensic replay of real pwsh commands through the live judgment core.
It never boots an instance and never writes to the HOME it reads.`

const preview = (cmd, n = 200) =>
  (cmd.length > n ? cmd.slice(0, n) + ' …' : cmd).replace(/\n/g, ' ; ')

function main(argv) {
  let opts
  try {
    opts = parseArgs(argv)
  } catch (e) {
    console.error(`error: ${e.message}\n\n${USAGE}`)
    return 2
  }
  if (opts.help) {
    console.log(USAGE)
    return 0
  }
  if (!opts.home) {
    console.error(`error: --home is required (get it from \`dshl env --json\` → instances[].home)\n\n${USAGE}`)
    return 2
  }

  const files = collectSessionFiles(opts.home, opts.days)
  let commands = collectCommands(files)
  if (opts.limit > 0) commands = commands.slice(0, opts.limit)

  // The judgment base only matters for rules that compare against the workspace
  // root (system-area writes, drive-root deletes). Session logs do not record
  // the cwd of each call, so one representative root is the honest choice; it
  // is echoed in the output rather than passed off as per-call.
  const base = opts.base
  const rules = evaluateRules({})
  const { byClass, samples, verdicts } = replay(commands, base, rules)
  const denied = [...verdicts.values()].filter(Boolean).length

  const payload = {
    home: opts.home,
    days: opts.days,
    base,
    files: files.length,
    commands: commands.length,
    denied,
    deniedPct: commands.length ? Number(((100 * denied) / commands.length).toFixed(2)) : 0,
    classes: Object.fromEntries(
      [...byClass.entries()].sort((a, b) => b[1] - a[1]),
    ),
    samples: Object.fromEntries([...samples.entries()]),
  }

  // The baseline comparison runs first so `--json --baseline` still reports the
  // drift instead of short-circuiting on the JSON dump.
  let before
  if (opts.baseline) {
    try {
      before = JSON.parse(readFileSync(opts.baseline, 'utf8'))
    } catch (e) {
      console.error(`error: cannot read baseline ${opts.baseline}: ${e.message}`)
      return 2
    }
  }

  if (opts.json) {
    payload.baseline = opts.baseline
      ? {
          file: opts.baseline,
          commands: before.commands,
          denied: before.denied,
          sameCorpus: before.commands === commands.length,
          classDelta: Object.fromEntries(
            CLASS_NAMES.filter(
              (cls) => (before.classes?.[cls] ?? 0) !== (byClass.get(cls) ?? 0),
            ).map((cls) => [cls, (byClass.get(cls) ?? 0) - (before.classes?.[cls] ?? 0)]),
          ),
        }
      : undefined
    console.log(JSON.stringify(payload, null, 2))
    return 0
  }

  console.log('session files          :', files.length)
  console.log('distinct pwsh commands :', commands.length)
  console.log('denied                 :', denied, `(${payload.deniedPct}%)`)
  console.log('judgment base          :', base, '(single representative root — logs carry no per-call cwd)')

  const wanted = opts.classes.length ? opts.classes : CLASS_NAMES
  console.log('\nclass'.padEnd(24), 'count'.padStart(6), 'share'.padStart(7))
  for (const cls of wanted) {
    const n = byClass.get(cls) ?? 0
    if (opts.classes.length === 0 && n === 0) continue
    const share = denied ? `${((100 * n) / denied).toFixed(1)}%` : '-'
    console.log(cls.padEnd(24), String(n).padStart(6), share.padStart(7))
  }

  if (opts.show > 0) {
    console.log('\n--- samples per class ---')
    for (const cls of wanted) {
      for (const cmd of (samples.get(cls) ?? []).slice(0, opts.show)) {
        console.log(`[${cls}] ${preview(cmd)}`)
      }
    }
  }

  if (before) {
    console.log('\n=== baseline comparison ===')
    console.log('baseline commands      :', before.commands)
    console.log('current commands       :', commands.length)
    if (before.commands !== commands.length) {
      console.log(
        '⚠ corpus size differs — the window or HOME moved, so per-command flips below are partial.',
      )
    }
    console.log('baseline denied        :', before.denied)
    console.log('current denied         :', denied)
    console.log('\nclass'.padEnd(24), 'before', 'after', 'delta')
    for (const cls of CLASS_NAMES) {
      const b = before.classes?.[cls] ?? 0
      const a = byClass.get(cls) ?? 0
      if (b === 0 && a === 0) continue
      console.log(cls.padEnd(24), String(b).padStart(6), String(a).padStart(5), String(a - b).padStart(6))
    }
    console.log(
      '\n⚠ Verify every newly-blocked command is genuine before shipping: a block added to a',
      '\n  legitimate command is a false positive delivered to the user.',
    )
  }

  return 0
}

if (import.meta.url === `file:///${process.argv[1].replace(/\\/g, '/')}`) {
  process.exit(main(process.argv.slice(2)))
}
