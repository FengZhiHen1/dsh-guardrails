import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { replayCredentialCorpus } from '../verify/corpus-replay.mjs'

test('credential corpus retains independent masking expectations', async () => {
  const source = await readFile(new URL('./fixtures/review-corpus/credential-cases.json', import.meta.url), 'utf8')
  const report = replayCredentialCorpus(JSON.parse(source))
  assert.ok(report.checked > 0)
  assert.equal(report.mismatched, 0, JSON.stringify(report.results.filter((entry) => entry.mismatches.length)))
  const ids = report.results.map(({ id }) => id)
  assert.equal(new Set(ids).size, ids.length)
})
