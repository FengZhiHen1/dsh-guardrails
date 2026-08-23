// lib/command.js — PowerShell command-text lexing, verb classification,
// listing-mode detection, sensitive text-reference detection, and system-area
// (W0) write detection. Depends on lib/rules.js for the text-reference
// regexes and lib/path-check.js for path resolution/system-area tests.

import {
  ENV_REFERENCE,
  GIT_DIR_REFERENCE,
  isSensitiveEnvName,
} from './rules.js'
import { isSystemAreaPath, resolvePath } from './path-check.js'

export const normalizeCommand = (word) => word.toLowerCase().replace(/-/g, '')

// Lex a command string into word/sep tokens and $(...) subexpressions.
// Pure static analysis: nothing is executed.
export function tokenizePwsh(command) {
  const tokens = []
  const nested = []
  let word = ''
  let i = 0
  const n = command.length
  const flush = () => {
    if (word) {
      tokens.push({ kind: 'word', value: word })
      word = ''
    }
  }
  while (i < n) {
    const c = command[i]
    if (c === "'" || c === '"') {
      const quote = c
      i += 1
      let content = ''
      while (i < n && command[i] !== quote) {
        if (command[i] === '`' && i + 1 < n) {
          content += command[i + 1]
          i += 2
          continue
        }
        content += command[i]
        i += 1
      }
      i += 1
      word += content
      continue
    }
    if (c === '`') {
      if (i + 1 < n) {
        word += command[i + 1]
        i += 2
        continue
      }
      i += 1
      continue
    }
    if (c === '$' && command[i + 1] === '(') {
      let depth = 1
      let j = i + 2
      while (j < n && depth > 0) {
        if (command[j] === '(') depth += 1
        else if (command[j] === ')') depth -= 1
        j += 1
      }
      const inner = command.slice(i + 2, j - 1)
      if (inner) nested.push(inner)
      word += '$(x)'
      i = j
      continue
    }
    if (c === ';' || c === '\n' || c === '\r' || c === '|' || c === '&') {
      flush()
      if ((c === '&' && command[i + 1] === '&') || (c === '|' && command[i + 1] === '|')) i += 1
      tokens.push({ kind: 'sep', value: c })
      i += 1
      continue
    }
    if (/\s/.test(c)) {
      flush()
      i += 1
      continue
    }
    word += c
    i += 1
  }
  flush()
  return { tokens, nested }
}

// Split tokens into fragments at separators, keeping the separator values.
export function splitFragments(tokens) {
  const fragments = []
  const seps = []
  let current = []
  for (const t of tokens) {
    if (t.kind === 'sep') {
      if (current.length) {
        fragments.push(current)
        current = []
      }
      seps.push(t.value)
      continue
    }
    current.push(t.value)
  }
  if (current.length) fragments.push(current)
  return { fragments, seps }
}

// Resolve the head command of a fragment, skipping $var, `&`, and `.` prefixes.
export function unwrapFragment(words) {
  let index = 0
  while (
    index < words.length &&
    (/^\$[A-Za-z_]/.test(words[index]) || words[index] === '&' || words[index] === '.')
  ) {
    index += 1
  }
  const raw = words[index]
  if (!raw) return undefined
  return { cmd: normalizeCommand(raw), args: words.slice(index + 1) }
}

// Metadata/listing verbs: they may mention sensitive paths without reading
// content. Only pure credential targets still block them. Formatting/filter
// verbs (Select-Object / Sort-Object / Where-Object) are the idiomatic way to
// shape a listing output, so they belong to the same whitelist; a content
// verb anywhere in the command still demotes the whole command to full rules.
export const METADATA_CMDS = new Set([
  'getchilditem', 'gci', 'ls', 'dir', 'getitem', 'gi',
  'testpath', 'resolvepath', 'getlocation', 'gl', 'pwd',
  'splitpath', 'joinpath',
  'selectobject', 'select', 'sortobject', 'sort', 'whereobject', 'where',
])

// ---- shared command-state helpers (used by destructive analysis and the
// system-area write check; the cd chain is simulated identically in both) ----

// Characters that make a path unverifiable at static-analysis time.
export const DYNAMIC_PATTERN = /[$`*?]/

export const CD_CMDS = new Set(['cd', 'setlocation', 'sl', 'pushd'])

export const firstTarget = (words) =>
  words.find((w) => w !== '--' && !w.startsWith('-') && !/^\/[a-zA-Z]+$/.test(w))

// Advance a { dir, known } cwd state through one cd-family command. Unknown
// states (dynamic targets, ~, bare pushd, popd) keep `known: false` so
// relative targets are evaluated against the fallback root instead.
export function applyCwdCommand(state, cmd, args) {
  if (cmd === 'popd') return { ...state, known: false }
  if (!CD_CMDS.has(cmd)) return state
  const target = firstTarget(args)
  if (target === undefined) {
    return cmd === 'pushd' ? { ...state, known: false } : { dir: '', known: false }
  }
  if (DYNAMIC_PATTERN.test(target) || target.startsWith('~')) {
    return { ...state, known: false }
  }
  return { dir: resolvePath(state.dir, target), known: true }
}

// A command is listing-only when every fragment's head command is a metadata
// verb, with no $(...) subexpression and no redirect (in PowerShell `>` is
// exclusively a redirect). Anything else keeps the full conservative rules.
export function isListingOnly(command) {
  if (command.includes('>')) return false
  const { tokens, nested } = tokenizePwsh(command)
  if (nested.length > 0) return false
  const { fragments } = splitFragments(tokens)
  if (fragments.length === 0) return false
  return fragments.every((words) => {
    const invocation = unwrapFragment(words)
    return invocation !== undefined && METADATA_CMDS.has(invocation.cmd)
  })
}

export function commandReferencesSensitiveEnv(command) {
  for (const m of command.matchAll(ENV_REFERENCE)) {
    if (isSensitiveEnvName(m[1])) return true
  }
  return false
}

// Content-sensitive reference detection, in the original check order:
// env → git. Returns the first matching category or null. Credentials are
// intentionally separate: they are checked in every mode. `.dsh` (incl.
// session history) is not a content-sensitive target (see DSR-003 revisit).
export function detectContentSensitiveRef(command) {
  if (commandReferencesSensitiveEnv(command)) return 'env'
  if (GIT_DIR_REFERENCE.test(command)) return 'git'
  return null
}

// ---------- literal reconstruction ----------
// PowerShell evaluates $(...) subexpressions and interpolates variables
// before a command runs, so a guard that only sees the raw text can be
// bypassed by hiding a sensitive name inside an evaluable subexpression
// (e.g. `.e$('nv')`) or a same-command variable (`$p='.env'; Get-Content $p`).
// This scanner rewrites those constructs into their literal values so every
// downstream check (text references, listing classification, destructive
// analysis) sees the real command. Each pwsh tool call runs in a fresh
// process (no state persists between calls), so resolving same-command
// assignments fully closes variable indirection. Non-evaluable subexpressions
// (variables, commands, mixed expressions) are kept verbatim; the caller's
// assessUnverifiable gate then treats them conservatively on content/removal
// verbs. `$env:NAME` and single-quoted spans are never touched.
export function resolveCommandLiterals(command) {
  const n = command.length
  const vars = new Map()
  let out = ''
  let i = 0

  const isIdentStart = (c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c === '_'
  const isIdentChar = (c) => isIdentStart(c) || (c >= '0' && c <= '9')
  const isSpace = (c) => c === ' ' || c === '\t' || c === '\n' || c === '\r'
  const copyRaw = (from, to) => { out += command.slice(from, to) }

  // Value of a quoted literal in `str` starting at j, or null. Single quotes
  // support the `''` escape; double quotes qualify only when free of `$` and
  // backtick (no interpolation or escapes), which is enough for every bypass
  // shape.
  const readQuotedValue = (str, j) => {
    const quote = str[j]
    let k = j + 1
    let value = ''
    if (quote === "'") {
      while (k < str.length) {
        const c = str[k]
        if (c === "'") {
          if (str[k + 1] === "'") { value += "'"; k += 2; continue }
          return { value, end: k + 1 }
        }
        value += c
        k += 1
      }
      return null
    }
    while (k < str.length) {
      const c = str[k]
      if (c === '`' || c === '$') return null
      if (c === '"') return { value, end: k + 1 }
      value += c
      k += 1
    }
    return null
  }

  // Index just past the `)` closing a `$(` whose opening paren sits at
  // `start - 1`... scanning begins at `start` (the first char after `(`) with
  // depth 1. Quote-aware: parens inside quotes do not count.
  const subexpressionEnd = (start) => {
    let depth = 1
    let k = start
    let quote = null
    while (k < n) {
      const c = command[k]
      if (quote !== null) {
        if (quote === "'") {
          if (c === "'") {
            if (command[k + 1] === "'") { k += 2; continue }
            quote = null
          }
        } else if (c === '`') {
          k += 2
          continue
        } else if (c === '"') {
          quote = null
        }
        k += 1
        continue
      }
      if (c === "'" || c === '"') { quote = c; k += 1; continue }
      if (c === '(') { depth += 1; k += 1; continue }
      if (c === ')') {
        depth -= 1
        if (depth === 0) return k
        k += 1
        continue
      }
      k += 1
    }
    return -1
  }

  // Value of a pure-literal subexpression body: quoted strings joined by
  // `+` (whitespace allowed). Anything else is not statically evaluable.
  const evaluateSubexpression = (inner) => {
    let j = 0
    let value = ''
    let saw = false
    while (true) {
      while (j < inner.length && isSpace(inner[j])) j += 1
      if (j >= inner.length) return saw ? value : null
      const r = readQuotedValue(inner, j)
      if (!r) return null
      value += r.value
      saw = true
      j = r.end
      while (j < inner.length && isSpace(inner[j])) j += 1
      if (j >= inner.length) return value
      if (inner[j] !== '+') return null
      j += 1
    }
  }

  // Resolve one `$` construct; returns the new index (or -1 to fall through).
  // Handles: `$(...)` (evaluate or keep verbatim), `$env:NAME` (keep),
  // `$name = 'literal'` assignments (register), `$name` uses (substitute
  // when known, keep otherwise). `j` points at the `$`.
  while (i < n) {
    const c = command[i]

    if (c === "'") {
      // Single-quoted span: fully literal, copy verbatim.
      let k = i + 1
      while (k < n) {
        if (command[k] === "'") {
          if (command[k + 1] === "'") { k += 2; continue }
          break
        }
        k += 1
      }
      const end = Math.min(k + 1, n)
      copyRaw(i, end)
      i = end
      continue
    }

    if (c === '"') {
      // Double-quoted span: interpolate like PowerShell (backtick escapes).
      copyRaw(i, i + 1)
      let k = i + 1
      while (k < n && command[k] !== '"') {
        const q = command[k]
        if (q === '`') { copyRaw(k, k + 2); k += 2; continue }
        if (q === '$' && command[k + 1] === '(') {
          const end = subexpressionEnd(k + 2)
          if (end < 0) { copyRaw(k, n); k = n; break }
          const value = evaluateSubexpression(command.slice(k + 2, end))
          if (value !== null) { out += value; k = end + 1; continue }
          copyRaw(k, end + 1)
          k = end + 1
          continue
        }
        if (q === '$' && isIdentStart(command[k + 1] ?? '')) {
          let m = k + 1
          while (m < n && isIdentChar(command[m])) m += 1
          if (command[m] === ':') { copyRaw(k, m + 1); k = m + 1; continue }
          const v = vars.get(command.slice(k + 1, m))
          if (v !== undefined) { out += v; k = m; continue }
          copyRaw(k, m)
          k = m
          continue
        }
        copyRaw(k, k + 1)
        k += 1
      }
      if (k < n) {
        copyRaw(k, k + 1)
        i = k + 1
      } else {
        i = n
      }
      continue
    }

    if (c === '`') {
      copyRaw(i, Math.min(i + 2, n))
      i += 2
      continue
    }

    if (c === '$' && command[i + 1] === '(') {
      const end = subexpressionEnd(i + 2)
      if (end < 0) { copyRaw(i, n); i = n; continue }
      const value = evaluateSubexpression(command.slice(i + 2, end))
      if (value !== null) { out += value; i = end + 1; continue }
      copyRaw(i, end + 1)
      i = end + 1
      continue
    }

    if (c === '$' && isIdentStart(command[i + 1] ?? '')) {
      let m = i + 1
      while (m < n && isIdentChar(command[m])) m += 1
      if (command[m] === ':') { copyRaw(i, m + 1); i = m + 1; continue }
      const name = command.slice(i + 1, m)
      // `$name = 'literal'` assignment (whitespace allowed around `=`).
      let s = m
      while (s < n && isSpace(command[s])) s += 1
      if (command[s] === '=' && command[s + 1] !== '=') {
        let t = s + 1
        while (t < n && isSpace(command[t])) t += 1
        const r = readQuotedValue(command, t)
        if (r) {
          vars.set(name, r.value)
          copyRaw(i, r.end)
          i = r.end
          continue
        }
      }
      const v = vars.get(name)
      if (v !== undefined) { out += v; i = m; continue }
      copyRaw(i, m)
      i = m
      continue
    }

    copyRaw(i, i + 1)
    i += 1
  }
  return out
}

// Verbs whose target is file content or file state (read/write/remove/copy/
// move/rename/create/append): a dynamically computed target under these verbs
// cannot be verified, so it is conservatively blocked. Metadata verbs
// (Get-ChildItem / Test-Path / Get-Item / ...) are deliberately excluded —
// listing stays allowed unless a sensitive literal appears in the text.
export const CONTENT_VERBS = new Set([
  'getcontent', 'gc', 'cat', 'type', 'more', 'selectstring', 'sls',
  'setcontent', 'sc', 'addcontent', 'ac', 'clearcontent',
  'outfile', 'of',
  'removeitem', 'rm', 'ri', 'del', 'erase', 'rmdir', 'rd',
  'copyitem', 'cp', 'moveitem', 'mi', 'renameitem', 'rni', 'ren',
  'setitem', 'si', 'newitem', 'ni',
])

// Unverifiable-target gate: after literal reconstruction, any remaining
// `$(...)` is a dynamically computed expression. When such an expression is
// the command itself, or appears in an argument of a content/removal verb,
// the target cannot be statically verified — block conservatively (the same
// intent rephrased differently remains unverifiable). Returns { text } or
// null. Category-independent: it is a fail-safe, not a per-category rule.
export function assessUnverifiable(resolved) {
  const { tokens } = tokenizePwsh(resolved)
  const { fragments } = splitFragments(tokens)
  for (const words of fragments) {
    const invocation = unwrapFragment(words)
    if (!invocation) continue
    if (invocation.cmd.includes('$(')) {
      return {
        text: 'the command itself is computed from a dynamic expression and cannot be verified',
      }
    }
    if (CONTENT_VERBS.has(invocation.cmd) && invocation.args.some((a) => a.includes('$('))) {
      return {
        text: 'the target path is computed from a dynamic expression and cannot be verified',
      }
    }
  }
  return null
}

// ---- system-area (W0) write detection (DSR-001/DSR-005) ----
// Writes into Windows system areas are blocked; reads and listings stay
// allowed. The path-level rules cover the write/edit tools; this covers the
// pwsh channel: write-class verbs and redirects whose static targets resolve
// into a system prefix, with cd-chain simulation so
// `cd C:\Windows; Set-Content x y` cannot hide the write.

export const WRITE_VERBS = new Set([
  'setcontent', 'sc', 'addcontent', 'ac', 'clearcontent',
  'outfile', 'of',
  'removeitem', 'rm', 'ri', 'del', 'erase', 'rmdir', 'rd',
  'setitem', 'si', 'newitem', 'ni',
  'copyitem', 'cp', 'moveitem', 'mi', 'renameitem', 'rni', 'ren',
])

const MOVE_COPY_VERBS = new Set(['copyitem', 'cp', 'moveitem', 'mi'])

// Write targets to test for one fragment. For copy/move only the destination
// matters (explicit -Destination value, else the last positional arg — the
// PowerShell default destination); all other write verbs treat every
// positional path arg as a write target.
function systemWriteCandidates(cmd, args) {
  const positional = args.filter((a) => !a.startsWith('-') && !/^\/[a-zA-Z]+$/.test(a))
  if (MOVE_COPY_VERBS.has(cmd)) {
    const out = []
    for (let i = 0; i + 1 < args.length; i += 1) {
      const flag = normalizeCommand(args[i])
      if (flag === 'destination' || flag === 'dest') out.push(args[i + 1])
    }
    const last = positional[positional.length - 1]
    if (last !== undefined) out.push(last)
    return out
  }
  return positional
}

// Returns { path } for the first static target that resolves into a system
// area, or null. Dynamic targets are left to the unverifiable gate.
export function assessSystemWrite(rootBase, command) {
  const { tokens } = tokenizePwsh(command)
  const { fragments } = splitFragments(tokens)
  let cwdState = { dir: rootBase, known: true }
  for (const words of fragments) {
    const invocation = unwrapFragment(words)
    if (!invocation) continue
    const { cmd, args } = invocation
    if (cmd === 'popd' || CD_CMDS.has(cmd)) {
      cwdState = applyCwdCommand(cwdState, cmd, args)
      continue
    }
    const candidates = WRITE_VERBS.has(cmd) ? systemWriteCandidates(cmd, args) : []
    // Redirect targets: `> C:\Windows\x`, `>>C:\Windows\x`, `2>C:\Windows\x`,
    // and a standalone `>`/`2>` word followed by the target.
    for (const word of words) {
      const m = /^(?:\d+)?>+(\S.*)$/.exec(word)
      if (m) candidates.push(m[1])
    }
    for (let i = 0; i + 1 < words.length; i += 1) {
      if (/^(?:\d+)?>+$/.test(words[i])) candidates.push(words[i + 1])
    }
    for (const candidate of candidates) {
      if (!candidate || DYNAMIC_PATTERN.test(candidate)) continue
      const base = cwdState.known ? cwdState.dir : rootBase
      if (isSystemAreaPath(resolvePath(base, candidate))) return { path: candidate }
    }
  }
  return null
}

// ---- verb → operation class + command-level content class (DSR-006) ----

// Classify a normalized command name by operation class: 'list' for metadata
// verbs, 'modify' for write/delete verbs, 'read' for content-read verbs,
// undefined for anything unknown (caller treats 'unknown' as fail-closed).
export function classifyVerb(cmd) {
  if (METADATA_CMDS.has(cmd)) return 'list'
  if (WRITE_VERBS.has(cmd)) return 'modify'
  if (CONTENT_VERBS.has(cmd)) return 'read'
  return undefined
}

// Operation class of a whole command, for op-level rule gating:
// - a `>` (write-only redirect in PowerShell) or any modify-class verb
//   demotes the whole command to 'modify';
// - a `$(...)` subexpression or an unknown verb yields 'unknown'
//   (fail-closed: full rules — same conservative rejection as isListingOnly);
// - content-read verbs yield 'read';
// - otherwise (all metadata) 'list'.
export function assessContentClass(command) {
  const { tokens, nested } = tokenizePwsh(command)
  if (nested.length > 0) return 'unknown'
  if (command.includes('>')) return 'modify'
  const { fragments } = splitFragments(tokens)
  let sawRead = false
  for (const words of fragments) {
    const invocation = unwrapFragment(words)
    if (!invocation) continue
    const cls = classifyVerb(invocation.cmd)
    if (cls === 'modify') return 'modify'
    if (cls === 'read') sawRead = true
    else if (cls === undefined) return 'unknown'
  }
  return sawRead ? 'read' : 'list'
}
