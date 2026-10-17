// Source verification never starts a DSH instance or changes a deployment HOME.
// Live activation, UI and startup evidence are recorded separately.
import { spawnSync } from 'node:child_process'
import { readdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const root = fileURLToPath(new URL('../', import.meta.url))
let failures = 0
function run(args) {
  const result = spawnSync(process.execPath, args, { cwd: root, stdio: 'inherit', timeout: 120000 })
  if (result.error) throw result.error
  if (result.status !== 0) failures += 1
}
async function syntax(directory) {
  for (const entry of await readdir(path.join(root, directory), { withFileTypes: true })) {
    const relative = path.join(directory, entry.name)
    if (entry.isDirectory()) await syntax(relative)
    else if (/\.(?:mjs|js)$/.test(entry.name)) run(['--check', relative])
  }
}
run(['--check', 'index.js'])
await syntax('src')
if (!process.argv.includes('--syntax-only')) run(['--test', 'test/*.test.mjs'])
console.log(`Source verification: ${failures ? 'FAIL' : 'PASS'}. No instance started; live deployment gate is separate.`)
process.exitCode = failures ? 1 : 0
