// cmd.js — bounded cmd.exe inline-text analysis (adapter layer, win32 hosts).
//
// Scope (coverage contract F-09..F-11 and the win32 embedded-shell route): cmd.exe
// text reaches this module from two entry points — `cmd /c <text>` command facts
// emitted by the shell layer and embedded shell texts of interpreter inline sources
// whose dialect is honestly `unknown` on a win32 host. This module only SPLITS the
// text into segments and TOKENIZES each segment; it never interprets cmd.exe
// semantics itself. Segments are re-emitted as command facts through env.command,
// so the shared command catalog (commands.js) stays the single sink recognizer.
//
// Anything the lexer cannot prove keeps the existing `cmd-inline` gap and is
// allowed with a diagnostic (D1/D3: a coverage gap never escalates to a rejection):
// `%VAR%` expansion, the for/if/goto/set/call keyword family, caret escapes,
// redirections, unbalanced quotes and over-budget segments.

const MAX_CMD_SEGMENTS = 256
const MAX_CMD_TOKENS = 64

// Segment-level keywords: the statement is control flow or shell state, not a
// plain command — the whole segment stays a gap. Checked on the first token only.
const CMD_KEYWORDS = new Set(['for', 'if', 'goto', 'call', 'set', 'setlocal', 'endlocal', 'shift', 'rem'])

/** Split cmd text on unquoted `&`, `|` and line breaks into bounded segments.
 * Both sides of `&`/`&&`/`||` and every line execute, so a split is exact. */
function splitSegments(text) {
  const segments = []
  let current = ''
  let quoted = false
  for (const ch of text) {
    if (ch === '"') {
      quoted = !quoted
      current += ch
    } else if (!quoted && (ch === '&' || ch === '|')) {
      segments.push(current)
      current = ''
    } else if (ch === '\n' || ch === '\r') {
      segments.push(current)
      current = ''
      quoted = false
    } else {
      current += ch
    }
    if (segments.length > MAX_CMD_SEGMENTS) return null
  }
  segments.push(current)
  return segments
}

/** Tokenize one segment on unquoted whitespace. Returns null for anything the
 * lexer cannot prove (see module header). */
function tokenize(segment) {
  const tokens = []
  let current = ''
  let quoted = false
  for (const ch of segment) {
    if (ch === '"') {
      quoted = !quoted
      continue
    }
    if (!quoted && (ch === '<' || ch === '>' || ch === '^')) return null
    if (!quoted && /\s/u.test(ch)) {
      if (current !== '') tokens.push(current)
      current = ''
      continue
    }
    current += ch
  }
  if (quoted) return null // unbalanced quotes
  if (current !== '') tokens.push(current)
  if (tokens.length === 0 || tokens.length > MAX_CMD_TOKENS) return null
  for (const token of tokens) {
    if (/%[^%]*%/u.test(token)) return null // %VAR% expansion is unprovable
  }
  if (CMD_KEYWORDS.has(tokens[0].toLowerCase())) return null
  return tokens
}

/** Analyze one inline cmd.exe text unit (provider-style entry for the pipeline). */
export function analyzeCmdInline(unit, env) {
  resolveCmdText(unit.source.text, { origin: unit.origin, condition: unit.condition }, env)
}

/** Split and tokenize cmd text, re-emitting each segment as a command fact. */
export function resolveCmdText(text, { origin, condition }, env) {
  const segments = typeof text === 'string' ? splitSegments(text) : null
  if (segments === null) {
    env.gap('cmd-inline', origin)
    return
  }
  let index = 0
  for (const segment of segments) {
    env.step?.()
    index += 1
    if (index > MAX_CMD_SEGMENTS) {
      env.gap('cmd-inline', origin)
      return
    }
    const tokens = tokenize(segment)
    if (tokens === null) {
      env.gap('cmd-inline', origin)
      continue
    }
    const [name, ...rest] = tokens
    env.command(name, rest, {
      origin: origin && typeof origin === 'object' ? { ...origin, commandIndex: index - 1, commandName: name } : origin,
      condition: condition ?? 'certain',
      cmdDialect: true,
      // cmd.exe does not expand wildcards itself: the invoked program does, so a
      // wildcard token is marked exactly like an unquoted POSIX glob word.
      patterns: rest.map((value) => /[*?]/u.test(value)),
    })
  }
}
