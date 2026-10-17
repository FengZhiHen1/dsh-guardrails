// Every source string stays parser data; no command executor is imported here.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { replayCorpus } from '../verify/corpus-replay.mjs'

for (const [file, expectedTotal, expectedChecked] of [
  ['policy-cases.json', 91, 91], ['parser-cases.json', 115, 115], ['credential-cases.json', 151, 87],
]) {
  test(`stable parse-only corpus: ${file}`, { timeout: 60000 }, async t => {
    const data = JSON.parse(await readFile(new URL(`./fixtures/review-corpus/${file}`, import.meta.url), 'utf8'))
    const report = await replayCorpus(data)
    assert.equal(report.total, expectedTotal)
    assert.equal(report.checked, expectedChecked, 'Undecided and observation-only examples must not count as passes')
    const ids = report.results.map(result => result.id)
    assert.equal(new Set(ids).size, ids.length, 'Each oracle has a stable unique ID')
    for (const result of report.results) {
      await t.test(result.id, { skip: result.status === 'not-run' ? result.reason : false }, () => {
        assert.deepEqual(result.mismatches, [], JSON.stringify(result))
      })
    }
  })
}

test('gate scenario catalogue separates executed assertions from review-only gaps', async () => {
  const data = JSON.parse(await readFile(new URL('./fixtures/review-corpus/gate-cases.json', import.meta.url), 'utf8'))
  assert.equal(data.cases.length, 28)
  assert.equal(new Set(data.cases.map(entry => entry.id)).size, 28)
  for (const entry of data.cases) {
    assert.ok(entry.stateSequence.length)
    assert.equal(typeof entry.expectedGuardOutcome, 'string')
    assert.equal(typeof entry.designClause, 'string')
    assert.equal(typeof entry.evidence, 'string')
  }
})
