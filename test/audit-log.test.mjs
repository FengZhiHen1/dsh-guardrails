// R-16 audit-log diagnosability (v1.7.0): a denial must be attributable after
// the fact from the instance log alone.
//
// The 2026-09-29 false-positive hunt stalled on this: the audit line cap was
// 140 characters while the deny-message prefix already consumed 112, so every
// entry showed ~28 characters of command and each one looked like it began with
// an assignment. Worse, the command-text reference classes (`.env` / `.git` /
// credentials) name a CATEGORY without ever quoting the command, so those
// denials could not be attributed at all without re-reading session logs.
//
// The contract these tests pin:
//   - one pwsh denial = ONE log entry of TWO lines: the bounded rationale, plus
//     a `denied input:` line carrying the judged command;
//   - the judged input is verbatim up to 400 characters, marked with `…` when
//     cut;
//   - path channels are deliberately EXCLUDED — their reasons already quote the
//     offending path, so a second line would only duplicate it;
//   - nothing is logged for an allowed call, and a denial is never logged twice.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as guardrails from '../index.js'

const BASE = 'E:/Project/DSH_Plugins'
const DENIED_PREFIX = '[guardrails] denied pwsh: '
const INPUT_PREFIX = '[guardrails] denied input: '
// Both audit fields are capped at AUDIT_LINE_MAX characters, with the ellipsis
// appended on top when the text is cut.
const AUDIT_LINE_MAX = 400

function makeGuard() {
  let handler
  const ctx = {
    get: (k) =>
      k === 'sandboxPolicy' ? { resolve: () => ({ workspaceRoot: BASE }) } : undefined,
    effect: (fn) => fn(),
    inject: () => {},
    tools: { guard: (h) => { handler = h } },
  }
  guardrails.apply(ctx, {})
  return (name, args) =>
    handler({ name, arguments: args, agent: { session: { header: { cwd: BASE } } } })
}

/**
 * Run one tool call with console.log captured. The original logger is restored
 * in `finally`, so a failing assertion can never leave the runner's own output
 * muted for the rest of the file.
 */
function captureLog(fn) {
  const calls = []
  const original = console.log
  console.log = (...args) => {
    calls.push(args.join(' '))
  }
  try {
    fn()
  } finally {
    console.log = original
  }
  return calls
}

/** The `denied input:` payload of a single-entry pwsh denial. */
const inputPayload = (calls) => {
  assert.equal(calls.length, 1)
  const lines = calls[0].split('\n')
  assert.equal(lines.length, 2)
  assert.ok(lines[1].startsWith(INPUT_PREFIX))
  return lines[1].slice(INPUT_PREFIX.length)
}

test('a pwsh denial logs the bounded rationale plus the judged input', () => {
  const calls = captureLog(() => makeGuard()('pwsh', { command: 'Get-Content .env' }))
  assert.equal(calls.length, 1) // exactly one entry per denial
  const lines = calls[0].split('\n')
  assert.equal(lines.length, 2)
  assert.ok(lines[0].startsWith(DENIED_PREFIX))
  // The rationale is capped too: a later raise of the deny-message prefix must
  // not silently push the command out of the log again.
  assert.equal(lines[0].slice(DENIED_PREFIX.length).length <= AUDIT_LINE_MAX + 1, true)
  assert.equal(inputPayload(calls), 'Get-Content .env') // verbatim, no truncation
})

test('the judged input is cut at the cap and marked with an ellipsis', () => {
  const command = 'Get-Content ' + 'x/'.repeat(300) + '.env'
  assert.ok(command.length > AUDIT_LINE_MAX)
  const calls = captureLog(() => makeGuard()('pwsh', { command }))
  const payload = inputPayload(calls)
  assert.equal(payload.length, AUDIT_LINE_MAX + 1)
  assert.ok(payload.endsWith('…'))
})

test('a multi-line command logs as one single-line entry', () => {
  // Whitespace is collapsed so the whole command stays on one line — otherwise
  // the second line of a multi-line command would read as a log entry of its
  // own and break line-oriented log scraping.
  const calls = captureLog(() => makeGuard()('pwsh', { command: 'Get-Content\n\t .env' }))
  const payload = inputPayload(calls)
  assert.equal(payload.includes('\n'), false)
  assert.equal(payload, 'Get-Content .env')
})

test('the input line is what makes a category-only denial attributable', () => {
  // The reference classes name a category; without the input line the log says
  // only "references a sensitive .env file" and names nothing.
  const calls = captureLog(() => makeGuard()('pwsh', { command: 'Get-Content .env' }))
  const rationale = calls[0].split('\n')[0]
  assert.match(rationale, /references a sensitive \.env file/)
  assert.equal(rationale.includes('Get-Content'), false) // rationale quotes no command
  assert.equal(inputPayload(calls), 'Get-Content .env') // the input line does
})

test('path channels log a single line: their reason already quotes the path', () => {
  for (const [name, args, quoted] of [
    ['read', { file_path: '.env' }, '.env'],
    ['write', { file_path: '.env' }, '.env'],
    ['edit', { file_path: '.env' }, '.env'],
    ['glob', { path: '.ssh/**' }, '.ssh/**'],
  ]) {
    const calls = captureLog(() => makeGuard()(name, args))
    assert.equal(calls.length, 1, name)
    assert.equal(calls[0].includes('denied input'), false, name)
    assert.equal(calls[0].includes('\n'), false, name)
    assert.ok(calls[0].includes(`"${quoted}"`), `${name} must quote ${quoted}`)
  }
})

test('an allowed call logs nothing at all', () => {
  const calls = captureLog(() => makeGuard()('pwsh', { command: 'Get-ChildItem .dsh' }))
  assert.deepEqual(calls, [])
})

test('two denials produce two entries (no coalescing, no duplication)', () => {
  const guard = makeGuard()
  const calls = captureLog(() => {
    guard('pwsh', { command: 'Get-Content .env' })
    guard('pwsh', { command: 'Get-Content .env.local' })
  })
  assert.equal(calls.length, 2)
  assert.equal(inputPayload([calls[0]]), 'Get-Content .env')
  assert.equal(inputPayload([calls[1]]), 'Get-Content .env.local')
})
