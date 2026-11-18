// Replay historical credential text as data. Current execution and policy
// expectations live in the target suites, with their own evidence fixtures.
import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { redactText } from '../src/core/redaction.js'

export function replayCredentialCorpus(data) {
  if (!Array.isArray(data?.textCases) || data.textCases.length > 10_000) {
    throw new TypeError('Expected a bounded array of credential text cases')
  }
  const results = data.textCases.map((entry) => {
    if (entry.replay === false || typeof entry.expectedChanged !== 'boolean') {
      return { id: entry.id, status: 'not-run', mismatches: [] }
    }
    const { changed } = redactText(entry.text)
    return { id: entry.id, changed, mismatches: changed === entry.expectedChanged ? [] : ['redaction'] }
  })
  const skipped = results.filter((entry) => entry.status === 'not-run').length
  const mismatched = results.filter((entry) => entry.mismatches.length).length
  return { total: results.length, checked: results.length - skipped, skipped, mismatched, results }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [inputPath, outputPath] = process.argv.slice(2)
  if (!inputPath || !outputPath) throw new Error('Usage: node verify/corpus-replay.mjs <credential-cases.json> <output.json>')
  const report = replayCredentialCorpus(JSON.parse(await readFile(resolve(inputPath), 'utf8')))
  await writeFile(resolve(outputPath), JSON.stringify(report, null, 2) + '\n')
  console.log(JSON.stringify({ total: report.total, checked: report.checked, skipped: report.skipped, mismatched: report.mismatched }))
  process.exitCode = report.mismatched ? 1 : 0
}
