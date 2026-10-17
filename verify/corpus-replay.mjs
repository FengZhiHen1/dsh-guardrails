// Replay untrusted command text as parser data only; never dispatch a shell tool.
import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createShellParsers } from '../src/adapter/parsers/index.mjs'
import { extractOperations, evaluatePolicy } from '../src/core/policy.js'
import { inlineCredentialDecision, redactText } from '../src/core/redaction.js'

/** Replay a bounded corpus using only official parsers and pure policy functions.
 * @throws {Error} If the corpus exceeds its budget or has an invalid shape.
 */
export async function replayCorpus(data) {
const cases = Array.isArray(data) ? data : data.cases ?? data.commandCases ?? []
if (!Array.isArray(cases) || cases.length > 10000) throw new Error('Corpus must contain at most 10000 cases')
const parser = createShellParsers()
const results = []
function matches(actual, expected) {
  if (Array.isArray(expected)) return Array.isArray(actual) && actual.length === expected.length && expected.every((value, index) => matches(actual[index], value))
  if (expected && typeof expected === 'object') return actual && Object.entries(expected).every(([key, value]) => matches(actual[key], value))
  return actual === expected
}
try {
  for (const entry of cases) {
    if (entry.replay === false || !['powershell', 'pwsh', 'bash'].includes(entry.dialect) || (entry.expectedKind && !['allow', 'ask', 'deny', 'deny-correction'].includes(entry.expectedKind))) {
      results.push({ id: entry.id, status: 'not-run', mismatches: [], reason: 'Unsupported or explicitly excluded case' }); continue
    }
    let actualKind = 'allow'
    let ruleId
    let parsed
    let errorCode
    try {
      const source = entry.declaredLimit ? Array.from({ length: 2100 }, (_, index) => `echo ${index}`).join(entry.dialect === 'bash' ? '\n' : ';') : entry.source
      parsed = await parser.parse(entry.dialect, source)
      // These facts are deliberately synthetic; no target is observed on disk.
      const operations = extractOperations(parsed.commands).map(operation => ({ ...operation, ...entry.syntheticTargets }))
      let decision = evaluatePolicy({ targets: { operations } })
      const inline = inlineCredentialDecision(parsed.commands)
      if (decision.kind !== 'deny' && inline) decision = inline
      actualKind = decision.kind
      ruleId = decision.ruleId
    } catch (error) { actualKind = 'deny'; errorCode = error.code ?? error.name }
    const mismatches = []
    const expectedKind = entry.expectedKind === 'deny-correction' ? 'deny' : entry.expectedKind
    if (['allow', 'ask', 'deny'].includes(expectedKind) && expectedKind !== actualKind) mismatches.push('decision')
    if (entry.expectedRule && entry.expectedRule !== ruleId) mismatches.push('rule')
    const expectSyntaxFailure = entry.expectedDecision === 'refuse-parse'
    if (expectSyntaxFailure && !errorCode) mismatches.push('expected-parser-failure')
    if (entry.expectedCommands && !parsed && !expectSyntaxFailure) mismatches.push('parser')
    for (const expected of expectSyntaxFailure ? [] : entry.expectedCommands ?? []) {
      const { expectedArgsAnyOf, ...fields } = expected
      if (!parsed?.commands.some(command => matches(command, fields) && (!expectedArgsAnyOf || expectedArgsAnyOf.some(arg => command.args.includes(arg))))) mismatches.push('command')
    }
    for (const absent of entry.absentCommands ?? []) if (parsed?.commands.some(command => matches(command, absent))) mismatches.push('absent-command')
    for (const unknown of entry.expectedUnknown ?? []) {
      const present = unknown === 'dynamic target' ? parsed?.unknown.includes('Dynamic command or argument') : parsed?.unknown.includes(unknown)
      if (!present) mismatches.push('unknown')
    }
    results.push({ id: entry.id, actualKind, ruleId, errorCode, mismatches, commands: parsed?.commands, unknown: parsed?.unknown })
  }
  for (const entry of data.textCases ?? []) {
    if (entry.replay === false || typeof entry.expectedChanged !== 'boolean') {
      results.push({ id: entry.id, status: 'not-run', mismatches: [], reason: 'No independent definite oracle' }); continue
    }
    const output = redactText(entry.text)
    results.push({ id: entry.id, changed: output.changed, mismatches: output.changed === entry.expectedChanged ? [] : ['redaction'] })
  }
} finally { await parser.dispose() }
const failed = results.filter(result => result.mismatches.length)
return { safety: 'Parser and pure policy only; no source command executed and no filesystem target observed.', total: results.length, checked: results.filter(result => result.status !== 'not-run').length, skipped: results.filter(result => result.status === 'not-run').length, mismatched: failed.length, results }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [inputPath, outputPath] = process.argv.slice(2)
  if (!inputPath || !outputPath) throw new Error('Usage: node verify/corpus-replay.mjs input.json output.json')
  const report = await replayCorpus(JSON.parse(await readFile(resolve(inputPath), 'utf8')))
  await writeFile(resolve(outputPath), JSON.stringify(report, null, 2) + '\n')
  console.log(JSON.stringify({ total: report.total, checked: report.checked, skipped: report.skipped, mismatched: report.mismatched, report: resolve(outputPath) }))
  process.exitCode = report.mismatched ? 1 : 0
}
