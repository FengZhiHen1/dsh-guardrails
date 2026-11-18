// 反过度防御与新增覆盖面的判定级回归（DSR-029 / 合同 §9.C）。
// 两类断言：
//   1) 正常用法必须 allow：无候选、无非 preview 操作；
//   2) 新增破坏形态必须 confirm（不得 deny）。
// 断言走真实分析器 + 真实 decide，不 mock 判定。

import test from 'node:test'
import os from 'node:os'
import path from 'node:path'
import assert from 'node:assert/strict'

import { createExecutionAnalyzer } from '../src/adapter/analysis/index.js'
import { decide } from '../src/core/decision.js'

const context = { domain: 'host', cwd: process.cwd(), platform: process.platform }
const EMPTY_INVENTORY = { kind: 'exact', count: 0, files: [], links: [], directories: [], roots: [], unknown: [] }

const analyzer = createExecutionAnalyzer()
test.after(() => analyzer.dispose())

async function evaluate(text, { language = 'bash', inventory = null } = {}) {
  const analysis = await analyzer.analyze({
    source: { kind: 'inline', text }, language, context, origin: { entry: 'over-defense' },
  })
  const decision = decide({
    analysisStatus: analysis.status,
    operations: analysis.operations,
    candidates: analysis.candidates,
    gaps: analysis.gaps,
    identities: [],
    inventory,
    protectedHits: [],
    exemptions: [],
    issues: [],
  }, {})
  return { analysis, decision }
}

function assertAllowed(name, { analysis, decision }) {
  assert.equal(decision.kind, 'allow', `${name}: expected allow, got ${decision.kind} ${decision.ruleId ?? ''}`)
  assert.deepEqual(analysis.candidates, [], `${name}: expected no candidates`)
  const effective = (analysis.operations ?? []).filter((operation) => operation.preview !== true)
  assert.deepEqual(effective, [], `${name}: expected no effective operations`)
}

function assertConfirmed(name, { analysis, decision }, ruleId) {
  assert.equal(decision.kind, 'confirm', `${name}: expected confirm, got ${decision.kind} ${decision.ruleId ?? ''}`)
  if (ruleId) assert.equal(decision.ruleId, ruleId, `${name}: unexpected rule`)
}

const ORDINARY = [
  ['git status', 'bash'],
  ['git checkout -b newfeat', 'bash'],
  ['git checkout main', 'bash'],
  ['git switch main', 'bash'],
  ['git switch -c feat', 'bash'],
  ['git branch -d merged-branch', 'bash'],
  ['git branch', 'bash'],
  ['git branch newfeat', 'bash'],
  ['git tag v1.2.0', 'bash'],
  ['git tag -l', 'bash'],
  ['git reflog', 'bash'],
  ['git rm -r --cached .', 'bash'],
  ['git reset', 'bash'],
  ['git reset --soft HEAD~1', 'bash'],
  ['git merge --ff-only main', 'bash'],
  ["find . -name '*.ts'", 'bash'],
  ['find /tmp -maxdepth 1 -type d', 'bash'],
  ['find . -name "*.log" -print', 'bash'],
  ['rsync -a src/ dst/', 'bash'],
  ['kubectl get pods', 'bash'],
  ['kubectl describe svc web', 'bash'],
  ['aws s3 ls', 'bash'],
  ['aws s3 cp a s3://b', 'bash'],
  ['psql -c "SELECT 1"', 'bash'],
  ['psql -c "DELETE FROM t WHERE id=1"', 'bash'],
  ['docker ps', 'bash'],
  ['docker images', 'bash'],
  ['gcloud compute instances list', 'bash'],
  ['az vm list', 'bash'],
  ['az account show', 'bash'],
  ['terraform plan', 'bash'],
  ['terraform validate', 'bash'],
  ['wsl ls', 'bash'],
  ['wsl git status', 'bash'],
  ['wsl -e ls /tmp', 'bash'],
  ['wsl --terminate Ubuntu', 'bash'],
  ['wsl --unregister', 'bash'],
  ['npm run build', 'bash'],
  ['node --check x.js', 'bash'],
  ['sudo ls', 'bash'],
  ['timeout 5 sleep 1', 'bash'],
  ['nohup make', 'bash'],
  ['env FOO=1 make', 'bash'],
  ['command echo hi', 'bash'],
  ['printf x | xargs echo', 'bash'],
  ['parallel ls ::: a b', 'bash'],
  ['shred --help', 'bash'],
  ['rsync --help', 'bash'],
  ['aws s3 rm s3://b --recursive --dryrun', 'bash'],
  ['rsync -n --delete src/ dst/', 'bash'],
  ['ssh host ls', 'bash'],
  ['ssh host git status', 'bash'],
  ['ssh-keygen -l', 'bash'],
  ['ssh -V', 'bash'],
  ['ssh host', 'bash'],
  ['tar -czf out.tgz src/', 'bash'],
  ['tar -tzf out.tgz', 'bash'],
  ['diskutil list', 'bash'],
  ['parted -l', 'bash'],
  ['fdisk -l', 'bash'],
  ['sgdisk -p /dev/sda', 'bash'],
  ["awk '{print $1}'", 'bash'],
  ["awk -F: '{print $1}' /etc/passwd", 'bash'],
]

test('ordinary usage stays allowed (no candidates, no effective operations)', async () => {
  for (const [command, language] of ORDINARY) {
    assertAllowed(command, await evaluate(command, { language }))
  }
})

// Heredoc bodies stay data whenever the receiver is not a shell interpreter; the
// file redirect in front of the heredoc is asserted separately from assertAllowed.
test('heredoc text to data receivers never executes as commands', async () => {
  for (const [text, language] of [
    ["bash <<'EOF'\necho hi\nEOF", 'bash'],
    ["cat > notes.txt <<'EOF'\nrm -rf /\nEOF", 'bash'],
  ]) {
    const { analysis, decision } = await evaluate(text, { language })
    assert.equal(decision.kind, 'allow', `${text}: expected allow, got ${decision.kind} ${decision.ruleId ?? ''}`)
    assert.deepEqual(analysis.candidates, [], `${text}: expected no candidates`)
    assert.ok(!analysis.operations.some((operation) =>
      operation.action === 'delete' || operation.action === 'move-source'), `${text}: no deletion may be derived`)
  }
})

test('Remove-Item with an explicit single path stays allowed under the 20-entry threshold', async () => {
  const result = await evaluate('Remove-Item -LiteralPath a.txt', {
    language: 'powershell',
    inventory: { ...EMPTY_INVENTORY, count: 1, files: ['a.txt'] },
  })
  assert.equal(result.decision.kind, 'allow')
})

test('Remove-Item -WhatIf and preview flags remain inert', async () => {
  for (const [command, language] of [
    ['Remove-Item -LiteralPath a.txt -WhatIf', 'powershell'],
    ['Remove-Item -LiteralPath a.txt -Recurse -Force -WhatIf', 'powershell'],
  ]) {
    const { analysis, decision } = await evaluate(command, { language })
    assert.equal(decision.kind, 'allow', `${command}: ${decision.kind}`)
    assert.deepEqual(analysis.candidates, [], `${command}: candidates`)
  }
})

const NEW_COVERAGE = [
  ['wsl -d Ubuntu bash -lc \'set -e; dst=$HOME/repos/x; rsync -a --delete /mnt/e/src/ "$dst/"\'', 'bash', 'data.delete.dynamic'],
  ['wsl -d Ubuntu bash -lc \'rsync -a --delete /mnt/e/src/ "$dst/"\'', 'bash', 'data.delete.dynamic'],
  ['rsync -a --delete /mnt/e/src/ "$dst/"', 'bash', 'data.delete.dynamic'],
  ['wsl -d Ubuntu rm -rf /tmp/x', 'bash', 'data.delete.dynamic'],
  ['wsl --unregister Ubuntu', 'bash', 'data.delete.dynamic'],
  ['find . -name "*.log" -delete', 'bash', 'data.delete.dynamic'],
  ['printf "%s\\n" a | xargs rm -rf', 'bash', 'data.delete.dynamic'],
  ['parallel rm -rf ::: a b', 'bash', 'data.delete.dynamic'],
  ['rsync -a --delete src/ dst/', 'bash', 'data.delete.bulk', { ...EMPTY_INVENTORY, count: 25, directories: ['dst/'] }],
  ['git branch -D feature', 'bash', 'data.git.restore'],
  ['git tag -d v1', 'bash', 'data.git.restore'],
  ['aws s3 rm s3://bucket --recursive', 'bash', 'data.delete.dynamic'],
  ['gcloud compute instances delete my-inst --quiet', 'bash', 'data.delete.dynamic'],
  ['az group delete -n rg --yes', 'bash', 'data.delete.dynamic'],
  ['psql -c "DROP TABLE users"', 'bash', 'data.delete.dynamic'],
  ['kubectl delete namespace prod', 'bash', 'data.delete.dynamic'],
  ['docker system prune -af', 'bash', 'data.delete.dynamic'],
  ['terraform destroy -auto-approve', 'bash', 'data.delete.dynamic'],
  ['wsl -e rm -rf /tmp/x', 'bash', 'data.delete.dynamic'],
  ['cmd /c rmdir /s /q build', 'bash', 'data.delete.bulk', { ...EMPTY_INVENTORY, count: 25, directories: ['build'] }],
  ['ssh host rm -rf /srv/x', 'bash', 'data.delete.dynamic'],
  ["ssh -p 22 user@host 'rm -rf /srv/x'", 'bash', 'data.delete.dynamic'],
  ["ssh host bash <<'EOF'\nrm -rf /srv/x\nEOF", 'bash', 'data.delete.dynamic'],
  ['tar --remove-files -czf out.tgz src/', 'bash', 'data.delete.bulk', { ...EMPTY_INVENTORY, count: 25, directories: ['src/'] }],
]

test('git restore-family forms are decided by git evidence, never denied outright', async () => {
  for (const command of ['git checkout -- src/a.js', 'git checkout HEAD -- src/app.ts', 'git restore src/app.ts']) {
    const result = await evaluate(command, { language: 'bash', inventory: EMPTY_INVENTORY })
    assert.notEqual(result.decision.kind, 'deny', command + ': must not deny on git evidence alone')
    assert.ok(['allow', 'confirm'].includes(result.decision.kind), command + ': unexpected kind')
    assert.deepEqual(result.analysis.candidates, [], command + ': candidates')
  }
})

test('tilde operands expand to the home directory before the target is judged', async () => {
  const { analysis } = await evaluate('rm -rf ~/proj', { language: 'bash' })
  const target = analysis.operations[0]?.target
  assert.ok(target, 'rm -rf ~/proj must produce a delete operation')
  const paths = target.kind === 'exact' ? target.paths : [target.root]
  assert.equal(paths.length, 1)
  assert.equal(paths[0], path.join(os.homedir(), 'proj'))
})

test('new destructive forms confirm with an enumerated scope (never deny on coverage gaps)', async () => {
  for (const [command, language, ruleId, inventory] of NEW_COVERAGE) {
    const result = await evaluate(command, { language, inventory: inventory ?? EMPTY_INVENTORY })
    assertConfirmed(command, result, ruleId)
    assert.ok(result.decision.scope, `${command}: confirm must carry a scope`)
  }
})

test('ssh heredoc payload and awk system() reach their deletion facts', async () => {
  const ssh = await evaluate("ssh host bash <<'EOF'\nrm -rf /srv/x\nEOF", { language: 'bash', inventory: EMPTY_INVENTORY })
  const sshOp = ssh.analysis.operations.find((operation) => operation.action === 'delete')
  assert.ok(sshOp, 'the ssh heredoc body must produce a delete operation')
  assert.equal(sshOp.context.domain, 'ssh')
  assertConfirmed('ssh heredoc payload', ssh, 'data.delete.dynamic')
  const awk = await evaluate("awk 'BEGIN{system(\"rm -rf /tmp/x\")}'", { language: 'bash', inventory: EMPTY_INVENTORY })
  const awkOp = awk.analysis.operations.find((operation) => operation.action === 'delete')
  assert.ok(awkOp, 'the awk system() literal must produce a delete operation')
  assert.deepEqual(awk.analysis.candidates, [])
  assert.notEqual(awk.decision.kind, 'deny')
})

test('tar --remove-files and the storage erase tools produce their declared facts', async () => {
  const tar = await evaluate('tar --remove-files -czf out.tgz a.txt b.txt', { language: 'bash', inventory: EMPTY_INVENTORY })
  const tarOps = tar.analysis.operations.filter((operation) => operation.action === 'delete')
  assert.deepEqual(tarOps.map((operation) => operation.target), [
    { kind: 'exact', paths: ['a.txt'] },
    { kind: 'exact', paths: ['b.txt'] },
  ], 'tar --remove-files must delete the named source members')
  assert.notEqual(tar.decision.kind, 'deny')
  const erase = await evaluate('sgdisk --zap-all /dev/sda', { language: 'bash', inventory: EMPTY_INVENTORY })
  const eraseOp = erase.analysis.operations.find((operation) => operation.action === 'write-content')
  assert.ok(eraseOp, 'sgdisk --zap-all must produce a storage mutation fact')
  assert.deepEqual(eraseOp.target, { kind: 'exact', paths: ['/dev/sda'] }, 'the device path stays enumerable for the identity probes')
  assert.deepEqual(eraseOp.details, { deviceMutation: true })
  assert.deepEqual(erase.analysis.candidates, [])
})

test('the incident rsync line names the command shape and the unresolved destination in its scope', async () => {
  const { decision } = await evaluate('rsync -a --delete /mnt/e/src/ "$dst/"', { language: 'bash', inventory: EMPTY_INVENTORY })
  assert.equal(decision.kind, 'confirm')
  const rendered = JSON.stringify(decision.scope)
  assert.ok(rendered.includes('rsync --delete'), `scope must name the command shape: ${rendered}`)
  assert.ok(rendered.includes('unresolved destination'), `scope must mark the destination unresolved: ${rendered}`)
})

test('wsl management switches and literal rsync tiers keep their behavior', async () => {
  for (const command of ['wsl --list --verbose', 'wsl --status', 'wsl --version']) {
    assertAllowed(command, await evaluate(command, { language: 'bash' }))
  }
  const literal = await evaluate('rsync -a --delete src/ /tmp/build/', { language: 'bash', inventory: EMPTY_INVENTORY })
  assert.equal(literal.decision.kind, 'allow')
  assert.deepEqual(literal.analysis.candidates, [])
  assert.equal(literal.analysis.operations[0].target.kind, 'subtree')
})
