// decision — the single pure policy decision point (架构重构设计「单一策略决策点」).
//
// Contract sources (this file implements the target contract, not legacy behavior):
//   docs/需求.md                        — three-tier判定 (deny/confirm/allow), R-02..R-20
//   docs/technical-details/规则模型.md   — rule catalog, 判定顺序, 操作到规则的映射,
//                                         删除分档, 配置模型, 确认语义, 失败分类, block format
//   docs/technical-details/执行分析.md   — operation facts (action/target/condition/preview)
//   docs/technical-details/架构重构设计.md — decision point I/O and recheck contract
//   DSR-025/026/027                     — multi-face safety net, best-effort execution
//                                         analysis, unified analysis contract
//
// Boundary: pure functions only. No filesystem, process or network access; no DSH
// runtime objects; imports are limited to sibling core modules (rules.js credential
// name lists, redaction.js redactText, path-check.js lexical helpers) and node:path.
//
// Exports:
//   normalizePolicy(config)           – sanitize one config object into the effective
//                                       policy snapshot. Protective fallback (R-20):
//                                       invalid values and unknown keys are reported and
//                                       skipped, valid restrictive markers are retained;
//                                       never throws.
//   decide(evidence, effectivePolicy) – pure three-way decision:
//                                       { kind, ruleId?, ruleIds?, reason?, trigger?,
//                                         scope?, gaps?, issues?, waived? }
//                                       (trigger/waived/issues are local extensions of the
//                                       架构重构设计 output table: trigger feeds the fixed
//                                       block's Trigger line, waived lists rule ids whose
//                                       hit was removed by per-rule config so the adapter
//                                       can consume one-time allowances, issues carry
//                                       check-failure detail for logging).
//   renderDecision(decision)          – fixed five-line block for deny/confirm (规则模型
//                                       失败分类与提示格式); returns null for allow (the
//                                       fixed block is defined for deny/confirm only;
//                                       coverage diagnostics ride on decision.gaps).
//                                       Why/Trigger/Scope are redacted via redactText
//                                       before anything is returned.
//   isProtectedPath(path, policy, platform) – builtin/marked protection match used by the
//                                       evidence adapter to build protectedHits.
//   ALLOW_THRESHOLD, CATASTROPHIC_RULES, CHECK_FAILED_RULE, NONCONFIGURABLE_RULES
//
// Evidence→rule mapping implemented here (规则模型「操作到规则的映射」+ lead rulings
// 2026-11-18):
//   identities with a catastrophic ruleId, or a non-preview operation with action
//     `git-history-destroy`            → deny catastrophic.* first, short-circuiting all
//                                        other judgment; never waivable.
//   analysisStatus fault / missing, any issues entry, or an unreliable inventory
//                                     → deny execution.check-failed (one stable,
//                                        non-configurable id for closed operational
//                                        failures; catastrophic hits keep priority).
//   candidates kind `unverified-effect` → execution.unverified-effect;
//   candidates kind `dynamic-execution` → execution.dynamic-command;
//                                        a provable scope (non-empty knownScope) confirms,
//                                        otherwise the candidate denies. Allow happens only
//                                        when there is no candidate at all (gaps alone never
//                                        upgrade — DSR-027).
//   protectedHits content actions      → credential.file.read (read-content/copy-content)
//                                        or credential.file.mutate (write/truncate/delete/
//                                        move-source and any unrecognized action, failing
//                                        safe); `metadata` hits never confirm (R-04).
//   credentialTextMention              → confirm credential.file.read or .mutate (R-04
//                                        credential text scan: a protected credential name
//                                        was matched in analyzed text while an unresolved
//                                        dynamic operand existed; mutate when the call has
//                                        a write/truncate/delete/move-source operation).
//                                        Skipped when protectedHits already produced a hit
//                                        under the same rule id.
//   deletion operations (delete/move-source/git-*) with unknown or pattern targets, or
//     unproven recursion               → data.delete.dynamic (family rule when the call is
//                                        uniformly git or move), listing provable scope.
//   otherwise the aggregate inventory decides the deletion tier: exact count within
//     ALLOW_THRESHOLD                  → allow (data.delete.ordinary / family rule);
//     exact count beyond the threshold, or a lower bound → confirm data.delete.bulk
//                                        (family rule when uniform); rendered scope says
//                                        "at least 21" and never claims a precise total.
//   gitRisk                            → confirm data.git.worktree (R-06 dirty-worktree
//                                        upgrade; lead ruling).
//   inlineCredential                   → deny credential.inline (corrective, R-11).
//
// Configuration contract (规则模型「配置模型」+ lead rulings 2026-11-18): rules.<id>.enabled
// / rules.<id>.allowlist are restricted to the documented CONFIGURABLE_RULES catalog and
// waive a non-catastrophic hit; allowOnce is a trusted per-invocation input only — a
// profile cannot carry it (the adapter passes it for the current call and consumes the id
// after the call proceeds); tightenOnly locks credential.* hits (灾难身份与受保护项始终
// 生效) while catastrophic and execution.check-failed are never configurable at all.
// configIssues entries are structured {code, count, detail?} with stable sanitized codes
// so the Host can aggregate warning counts per (code, detail) without parsing text.
// Allowlist entries are exact absolute paths: a hit is waived only when every known target
// of the hit is allowlisted and nothing in the hit's scope is unobserved, so an allowlist
// can never waive an unenumerable deletion.

import { CRED_BASENAMES, CRED_BASENAME_PREFIXES, CRED_COMBOS, PUBLIC_KEY_SUFFIX } from './rules.js'
import { redactText } from './redaction.js'
import { isAbsolutePath, segmentsOf, slash } from './path-check.js'
import path from 'node:path'

// ---------------------------------------------------------------------------
// Catalog constants
// ---------------------------------------------------------------------------

/** R-07: non-exempt entries within this threshold proceed; beyond it, confirm. */
export const ALLOW_THRESHOLD = 20

/** Catastrophic identities (R-03). Deny unconditionally; never configurable. */
export const CATASTROPHIC_RULES = new Set([
  'catastrophic.device',
  'catastrophic.root',
  'catastrophic.git-metadata',
  'catastrophic.git-history',
])
const CATASTROPHIC_ORDER = [...CATASTROPHIC_RULES]

/** Closed operational failures share one stable, non-configurable id (lead ruling). */
export const CHECK_FAILED_RULE = 'execution.check-failed'
export const NONCONFIGURABLE_RULES = new Set([...CATASTROPHIC_RULES, CHECK_FAILED_RULE])

const DELETION_ACTIONS = new Set(['delete', 'move-source', 'git-clean', 'git-restore', 'git-worktree-remove'])
const GIT_OP_RULES = {
  'git-clean': 'data.git.clean',
  'git-restore': 'data.git.restore',
  'git-worktree-remove': 'data.git.worktree',
}
const GIT_ACTIONS = new Set(Object.keys(GIT_OP_RULES))
const READ_CONTENT_ACTIONS = new Set(['read-content', 'copy-content'])
const MUTATE_CONTENT_ACTIONS = new Set(['write-content', 'truncate-content', 'delete', 'move-source'])
/** R-04 credential text scan: any of these operations upgrades the scan hit to mutate. */
const TEXT_SCAN_MUTATE_ACTIONS = new Set(['write-content', 'truncate-content', 'delete', 'move-source'])

/** Confirm/deny primary-rule selection order when several hits coexist (规则模型:
 * one merged confirmation; denies keep their own trigger reasons). */
const CONFIRM_PRIORITY = [
  'credential.file.read',
  'credential.file.mutate',
  'data.delete.dynamic',
  'data.delete.bulk',
  'data.git.clean',
  'data.git.restore',
  'data.git.worktree',
  'data.move.source',
  'execution.unverified-effect',
  'execution.dynamic-command',
]
const DENY_PRIORITY = ['credential.inline', 'execution.unverified-effect', 'execution.dynamic-command']

/** Per-rule Effect/Next lines for the fixed block (intent drives Next). */
const RULE_META = {
  'catastrophic.device': {
    effect: 'Stops irreversible destruction of a real host physical disk or volume.',
    next: 'Do not target a physical device or volume from this environment; address specific files instead.',
  },
  'catastrophic.root': {
    effect: 'Stops wholesale destruction of the host OS root or a core system structure.',
    next: 'Target a specific, non-system path instead.',
  },
  'catastrophic.git-metadata': {
    effect: 'Stops direct destruction of the real shared Git metadata body.',
    next: 'Use explicit Git commands; never delete .git contents directly.',
  },
  'catastrophic.git-history': {
    effect: 'Stops Git history destruction.',
    next: 'Do not rewrite or destroy Git history. To remove a tag: `git tag -d <name>` locally, or `git push origin --delete refs/tags/<name>` remotely. Deleting a branch is also refused here; do not attempt it.',
  },
  'data.delete.ordinary': {
    effect: 'Verified the non-exempt deletion set is enumerable and within the 20-entry allow threshold.',
    next: 'Proceed; keep deletion targets literal and enumerable.',
  },
  'data.delete.bulk': {
    effect: 'Counts non-exempt deletion targets before dispatch; the set exceeds the 20-entry allow threshold.',
    next: 'Verify the expected set first, then delete at most 20 non-exempt entries per call and re-issue for the rest.',
  },
  'data.delete.dynamic': {
    effect: 'Counts deletion targets before dispatch; the target set cannot be enumerated.',
    next: 'Rewrite the deletion with explicit literal paths (no wildcards or unresolved values) so the target set is enumerable.',
  },
  'data.move.source': {
    effect: 'Counts the source entries this move would remove; move sources follow the deletion tiers.',
    next: 'Move at most 20 sources per call with literal paths, or use copy if the source must remain.',
  },
  'data.git.clean': {
    effect: 'Counts what this Git cleanup would remove before dispatch.',
    next: 'Verify with git status first; clean at most 20 entries per call with explicit paths.',
  },
  'data.git.restore': {
    effect: 'Counts what this Git restore would remove before dispatch.',
    next: 'Restore explicit paths only and verify with git status first.',
  },
  'data.git.worktree': {
    effect: 'Checks the worktree state and what its removal would delete.',
    next: 'Commit or stash local changes first, or remove the worktree through explicit Git commands.',
  },
  'credential.file.read': {
    effect: 'Requires a one-time, time-limited confirmation before protected file content is read, exported or copied.',
    next: 'Use runtime credential injection or a check that reports only non-secret status; approval applies only to this call.',
  },
  'credential.file.mutate': {
    effect: 'Requires a one-time, time-limited confirmation before a protected file is written, cleared, deleted or moved.',
    next: 'Do not modify credential files through agent tools; approval applies only to this call, or ask the user to make the change manually.',
  },
  'credential.inline': {
    effect: 'Stops an inline credential literal from spreading into command arguments and persisted tool input.',
    next: 'Use a credential reference, an environment variable, stdin, or the authenticated configuration of the tool instead.',
  },
  'execution.dynamic-command': {
    effect: 'Identified an execution entry that would run an unresolved program or payload.',
    next: 'Use a literal program name and enumerable arguments; avoid executing values as commands.',
  },
  'execution.unverified-effect': {
    effect: 'Found a concrete destructive clue that analysis could not resolve into countable operations.',
    next: 'Rewrite the operation with explicit literal targets, or run it through a supported runtime so it can be analyzed.',
  },
  'execution.check-failed': {
    effect: 'A required check did not finish, so the call cannot be proven safe.',
    next: 'Retry with a clearer, fully literal command; report the failure if it persists.',
  },
}
const GENERIC_META = {
  effect: 'The guard requires a decision on this invocation.',
  next: 'Use explicit literal paths and supported commands.',
}

/** Per-stage Effect/Next overrides for gate faults. The concrete stage code stays in
 * the fixed block's `(stage CODE)` marker; when it matches, these replace the
 * catalog rule's generic Effect/Next so the refusal explains what actually happened.
 * Pure string table: no I/O, no DSH objects. */
const STAGE_META = {
  GUARD_SCOPE_CHANGED: {
    effect: 'The operation or its target set changed between the confirmation and dispatch (files, script or manifest contents, or the analysis itself).',
    next: 'Nothing was executed. Re-issue the call and confirm the scope shown at that time.',
  },
  GUARD_RECHECK_FAILED: {
    effect: 'The post-confirmation re-check failed, so the call was not dispatched.',
    next: 'Nothing was executed. Retry once; report it if it repeats.',
  },
  GUARD_REAPPROVAL_UNRESOLVED: {
    effect: 'The scope changed again after a second confirmation, so the call was not dispatched.',
    next: 'Nothing was executed. Re-issue the call and confirm the current scope.',
  },
  ANALYSIS_UNAVAILABLE: {
    effect: 'The safety analysis could not read this call (unsupported or unparsable command or target).',
    next: 'Nothing was executed. Retry with a literal command; report it if it persists.',
  },
  GUARD_INVALID_SHELL_INPUT: {
    effect: 'The tool argument carrying command text was missing or not a string, so the call was not dispatched.',
    next: 'Pass the command as one string for the shell tool; if it comes from a file, read it first and pass the literal text.',
  },
  GUARD_WORKDIR_UNRESOLVED: {
    effect: 'The relative working directory has no resolvable base, so the call was not dispatched.',
    next: 'Use an absolute working directory (or an absolute path in the command).',
  },
  GUARD_PATCH_PARSE_FAILED: {
    effect: 'The patch or target could not be parsed, so the call was not dispatched.',
    next: 'Nothing was executed. Provide a parseable patch or an absolute base path.',
  },
  GUARD_TARGET_BASE_UNKNOWN: {
    effect: 'The patch or target could not be parsed, so the call was not dispatched.',
    next: 'Nothing was executed. Provide a parseable patch or an absolute base path.',
  },
  ANALYSIS_CANCELLED: {
    effect: 'The call was cancelled before it could be dispatched.',
    next: 'Nothing was executed. Re-issue the call when it is still needed.',
  },
  ANALYSIS_DISPOSED: {
    effect: 'Guardrails was unloaded while this call was being checked.',
    next: 'Nothing was executed. Retry after the plugin is reloaded; report it if it repeats.',
  },
  ANALYSIS_MISSING: {
    effect: 'No completed safety check existed for this exact call, so it was not dispatched.',
    next: 'Nothing was executed. Re-issue the call; report it if it repeats.',
  },
}

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

const PATH_LENGTH_MAX = 32768
const ARRAY_CAP = 8192
const LIST_DISPLAY_CAP = 8

const FOLD_PLATFORMS = new Set(['win32', 'windows', 'win'])
const STRICT_PLATFORMS = new Set(['posix', 'linux', 'darwin', 'unix', 'mac', 'macos', 'freebsd', 'openbsd', 'netbsd'])

/** Windows folds path case; POSIX does not. An unknown platform folds: a wrong fold can
 * only produce an extra confirmation, while a wrong strict compare could miss a real
 * protected file. */
function foldsCase(platform) {
  if (typeof platform !== 'string' || platform.length === 0) return true
  const key = platform.toLowerCase()
  if (FOLD_PLATFORMS.has(key)) return true
  if (STRICT_PLATFORMS.has(key)) return false
  return true
}

/** Strip trailing slashes (keeping the bare root) after slash normalization. */
function normalizedKey(value) {
  const slashed = slash(value)
  const trimmed = slashed.replace(/\/+$/, '')
  return trimmed === '' && slashed.startsWith('/') ? '/' : trimmed
}
const strictKey = (value) => normalizedKey(path.posix.normalize(slash(value)))
const foldKey = (value) => strictKey(value).toLowerCase()

/** Compare key for paths whose platform is not known: Windows-shaped paths fold, POSIX
 * shapes stay strict (same semantics as path-check normCompare). */
function shapeKey(value) {
  const key = strictKey(value)
  return /^[a-z]:\//i.test(key) || key.startsWith('//') ? key.toLowerCase() : key
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function asString(value, fallback = '') {
  return typeof value === 'string' ? value : fallback
}

/** Copy a string list with a hard cap; the boolean reports truncation so callers can
 * treat completeness as unproven. */
function copyStrings(value, cap = ARRAY_CAP) {
  if (!Array.isArray(value)) return [[], false]
  const items = []
  let truncated = false
  for (const entry of value) {
    if (typeof entry !== 'string') continue
    if (items.length >= cap) { truncated = true; break }
    items.push(entry)
  }
  return [items, truncated]
}

/** A marked/allowlist path: bounded, absolute, wildcard-free exact file path
 * (same acceptance shape as 规则模型 sensitiveFiles). */
function validExactPath(value) {
  return typeof value === 'string' && value.trim() !== '' && value.length <= PATH_LENGTH_MAX &&
    !value.includes('\0') && !/[*?]/.test(value) && isAbsolutePath(value)
}

// ---------------------------------------------------------------------------
// normalizePolicy — protective config sanitization (R-20), never throws
// ---------------------------------------------------------------------------

const ASK_TIMEOUT_DEFAULT = 120_000
const ASK_TIMEOUT_MAX = 3_600_000
const MARKED_LIST_MAX = 1024
const ALLOW_ONCE_MAX = 64
const DETAIL_MAX = 64
const KNOWN_POLICY_KEYS = new Set([
  'sensitiveFiles', 'builtinSensitiveAsk', 'askTimeoutMs', 'alwaysAsk', 'rules', 'allowOnce', 'tightenOnly', 'configIssues',
])

/** Documented configurable rule ids (规则模型 rule catalog). Per-rule config and
 * allowOnce accept only these ids; catastrophic.* and execution.check-failed are never
 * configurable. Restricting the dictionary to this fixed set also keeps prototype keys
 * such as `__proto__` out of policy.rules (plain-object assignments only, serializable). */
export const CONFIGURABLE_RULES = new Set([
  'data.delete.ordinary', 'data.delete.bulk', 'data.delete.dynamic', 'data.move.source',
  'data.git.clean', 'data.git.restore', 'data.git.worktree',
  'credential.file.read', 'credential.file.mutate', 'credential.inline',
  'execution.unverified-effect', 'execution.dynamic-command',
])

const clampDetail = (value) => {
  const text = typeof value === 'string' ? value : String(value ?? '')
  return text.length > DETAIL_MAX ? `${text.slice(0, DETAIL_MAX)}…` : text
}

/** Aggregated config-issue collector: entries are {code, count, detail?} with stable
 * codes, so the Host can count sanitized warnings per (code, detail) without parsing
 * text. Raw config values are never echoed; only capped identifiers appear in detail. */
function issueCollector() {
  const map = new Map()
  return {
    add(code, detail, count = 1) {
      const key = `${code}|${detail ?? ''}`
      const entry = map.get(key)
      if (entry) entry.count += count
      else map.set(key, { code, ...(detail === undefined ? {} : { detail }), count })
    },
    list() { return [...map.values()] },
  }
}

/**
 * Sanitize one configuration object into the effective policy snapshot. Invalid values
 * and unknown keys are reported in configIssues and skipped (protective fallback, R-20);
 * valid restrictive markers and overrides are retained. Never throws. Idempotent.
 *
 * `allowOnce` is trusted per-invocation input, not a profile key: profile mode (default)
 * reports and ignores it so a profile cannot create a standing bypass repeated on every
 * call; `{ callScoped: true }` (the adapter's per-call snapshot, used by decide) accepts
 * and sanitizes it. Rule ids are restricted to CONFIGURABLE_RULES in both places.
 */
export function normalizePolicy(config, options = {}) {
  const callScoped = options.callScoped === true
  const issues = issueCollector()
  const policy = {
    sensitiveFiles: [],
    builtinSensitiveAsk: true,
    askTimeoutMs: ASK_TIMEOUT_DEFAULT,
    alwaysAsk: true,
    rules: {},
    allowOnce: [],
    tightenOnly: true,
    configIssues: [],
  }
  const finish = () => {
    policy.configIssues = issues.list()
    return policy
  }
  if (config === undefined || config === null) return finish()
  if (!isPlainObject(config)) {
    issues.add('config-not-object')
    return finish()
  }
  for (const key of Object.keys(config)) {
    if (!KNOWN_POLICY_KEYS.has(key)) issues.add('unknown-config-key', clampDetail(key))
  }

  // sensitiveFiles: keep every valid restrictive marker, drop unusable entries.
  if (config.sensitiveFiles !== undefined) {
    if (!Array.isArray(config.sensitiveFiles)) {
      issues.add('sensitive-files-not-array')
    } else {
      let dropped = 0
      for (const entry of config.sensitiveFiles) {
        if (policy.sensitiveFiles.length >= MARKED_LIST_MAX) { dropped += 1; continue }
        if (!validExactPath(entry)) { dropped += 1; continue }
        if (!policy.sensitiveFiles.includes(entry)) policy.sensitiveFiles.push(entry)
      }
      if (dropped > 0) issues.add('sensitive-files-dropped', undefined, dropped)
    }
  }

  // builtinSensitiveAsk: protective default is true (keep asking).
  if (config.builtinSensitiveAsk !== undefined) {
    if (typeof config.builtinSensitiveAsk === 'boolean') policy.builtinSensitiveAsk = config.builtinSensitiveAsk
    else issues.add('builtin-sensitive-ask-invalid')
  }

  // alwaysAsk: protective default is true (keep asking when approvals are disabled).
  // An invalid value is reported and the protective default is kept.
  if (config.alwaysAsk !== undefined) {
    if (typeof config.alwaysAsk === 'boolean') policy.alwaysAsk = config.alwaysAsk
    else issues.add('always-ask-invalid')
  }

  // askTimeoutMs: bounded; 0 maps to the default, never to unlimited waiting.
  if (config.askTimeoutMs !== undefined) {
    const value = config.askTimeoutMs
    if (Number.isInteger(value) && value >= 0 && value <= ASK_TIMEOUT_MAX) {
      policy.askTimeoutMs = value === 0 ? ASK_TIMEOUT_DEFAULT : value
    } else {
      issues.add('ask-timeout-invalid')
    }
  }

  // rules.<id>: per-rule switches restricted to the documented catalog; ids outside it
  // (including prototype keys and closed rules) are dropped and reported.
  if (config.rules !== undefined) {
    if (!isPlainObject(config.rules)) {
      issues.add('rules-not-object')
    } else {
      for (const [id, raw] of Object.entries(config.rules)) {
        if (NONCONFIGURABLE_RULES.has(id)) {
          issues.add('rule-override-not-configurable', clampDetail(id))
          continue
        }
        if (!CONFIGURABLE_RULES.has(id)) {
          issues.add('rule-override-unknown-id', clampDetail(id))
          continue
        }
        if (!isPlainObject(raw)) {
          issues.add('rule-override-invalid', clampDetail(id))
          continue
        }
        const entry = {}
        if (raw.enabled !== undefined) {
          if (typeof raw.enabled === 'boolean') entry.enabled = raw.enabled
          else issues.add('rule-enabled-invalid', clampDetail(id))
        }
        if (raw.allowlist !== undefined) {
          if (!Array.isArray(raw.allowlist)) {
            issues.add('rule-allowlist-invalid', clampDetail(id))
          } else {
            const list = []
            let dropped = 0
            for (const item of raw.allowlist) {
              if (list.length >= MARKED_LIST_MAX) { dropped += 1; continue }
              if (!validExactPath(item)) { dropped += 1; continue }
              if (!list.includes(item)) list.push(item)
            }
            if (dropped > 0) issues.add('rule-allowlist-dropped', clampDetail(id), dropped)
            if (list.length > 0) entry.allowlist = list
          }
        }
        // Safe assignment: id is a member of the fixed catalog, never a prototype key.
        if (Object.keys(entry).length > 0) policy.rules[id] = entry
      }
    }
  }

  // allowOnce: one-time allowances for the current call; see the function contract. An
  // empty array is the normalized-policy default and stays silent in profile mode, so
  // feeding a normalized policy back is idempotent.
  if (config.allowOnce !== undefined && !(Array.isArray(config.allowOnce) && config.allowOnce.length === 0)) {
    if (!callScoped) {
      issues.add('allow-once-not-profile-key')
    } else if (!Array.isArray(config.allowOnce)) {
      issues.add('allow-once-not-array')
    } else {
      let dropped = 0
      for (const item of config.allowOnce) {
        if (policy.allowOnce.length >= ALLOW_ONCE_MAX) { dropped += 1; continue }
        if (typeof item !== 'string' || item.trim() === '') { dropped += 1; continue }
        if (NONCONFIGURABLE_RULES.has(item)) {
          issues.add('allow-once-not-configurable', clampDetail(item))
          continue
        }
        if (!CONFIGURABLE_RULES.has(item)) {
          issues.add('allow-once-unknown-id', clampDetail(item))
          continue
        }
        if (!policy.allowOnce.includes(item)) policy.allowOnce.push(item)
      }
      if (dropped > 0) issues.add('allow-once-dropped', undefined, dropped)
    }
  }

  // tightenOnly: protective default is true (项目层覆盖只能收紧、不能放松). An explicit
  // false cannot relax protected items, so it keeps the default and is reported.
  if (config.tightenOnly !== undefined) {
    if (config.tightenOnly === true) policy.tightenOnly = true
    else if (config.tightenOnly === false) issues.add('tighten-only-false-rejected')
    else issues.add('tighten-only-invalid')
  }
  return finish()
}

// ---------------------------------------------------------------------------
// isProtectedPath — builtin/marked protection match for the evidence adapter
// ---------------------------------------------------------------------------

/** Builtin credential-carrier basename match (lists owned by rules.js). */
function matchesBuiltin(rawPath, fold) {
  const segs = segmentsOf(rawPath)
  const base = segs[segs.length - 1]
  if (!base) return false
  const baseKey = fold ? base.toLowerCase() : base
  if (baseKey.endsWith(PUBLIC_KEY_SUFFIX)) return false
  if (CRED_BASENAMES.has(baseKey)) return true
  if (CRED_BASENAME_PREFIXES.some((prefix) => baseKey.startsWith(`${prefix}.`))) return true
  const tail = fold ? segs.map((segment) => segment.toLowerCase()) : segs
  return CRED_COMBOS.some((combo) => combo.length <= tail.length &&
    combo.every((part, index) => tail[tail.length - combo.length + index] === part))
}

function matchesMarked(rawPath, sensitiveFiles, fold) {
  if (sensitiveFiles.length === 0) return false
  const key = fold ? foldKey(rawPath) : strictKey(rawPath)
  return sensitiveFiles.some((marked) => (fold ? foldKey(marked) : strictKey(marked)) === key)
}

/**
 * True when the path is a protected file under the given policy: a builtin
 * credential-carrier basename (gated by builtinSensitiveAsk) or a user-marked exact path
 * (always effective; project config must never relax these under tightenOnly).
 * `platform` selects case semantics: win32/windows folds, posix/linux/darwin compares
 * strictly, anything unknown folds (protective direction).
 */
export function isProtectedPath(rawPath, rawPolicy, platform) {
  if (typeof rawPath !== 'string' || rawPath.length === 0 || rawPath.length > PATH_LENGTH_MAX || rawPath.includes('\0')) return false
  const policy = normalizePolicy(rawPolicy)
  const fold = foldsCase(platform)
  if (policy.builtinSensitiveAsk && matchesBuiltin(rawPath, fold)) return true
  return matchesMarked(rawPath, policy.sensitiveFiles, fold)
}

// ---------------------------------------------------------------------------
// Evidence readers — lenient per field, fail-safe per field
// ---------------------------------------------------------------------------

function readOperations(value) {
  if (!Array.isArray(value)) return []
  const ops = []
  for (const raw of value.slice(0, ARRAY_CAP)) {
    if (!isPlainObject(raw)) continue
    const action = asString(raw.action)
    if (!action) continue
    ops.push({
      action,
      target: readTarget(raw.target),
      recursive: raw.recursive === true ? true : raw.recursive === false ? false : 'unknown',
      preview: raw.preview === true,
    })
  }
  return ops
}

function readTarget(raw) {
  if (!isPlainObject(raw)) return { kind: 'unknown', reason: 'malformed target expression', knownScope: [] }
  if (raw.kind === 'exact') {
    const [paths] = copyStrings(raw.paths)
    if (paths.length === 0) return { kind: 'unknown', reason: 'exact target carried no paths', knownScope: [] }
    return { kind: 'exact', paths }
  }
  if (raw.kind === 'subtree') {
    const root = asString(raw.root)
    if (!root) return { kind: 'unknown', reason: 'subtree root unresolved', knownScope: [] }
    return { kind: 'subtree', root }
  }
  if (raw.kind === 'pattern') {
    const base = asString(raw.base)
    const pattern = asString(raw.pattern)
    if (!base && !pattern) return { kind: 'unknown', reason: 'pattern target carried no base or pattern', knownScope: [] }
    return { kind: 'pattern', base, pattern }
  }
  return {
    kind: 'unknown',
    reason: asString(raw.reason, 'unresolved target'),
    knownScope: copyStrings(raw.knownScope)[0],
  }
}

function readCandidates(value) {
  if (!Array.isArray(value)) return []
  const out = []
  for (const raw of value.slice(0, ARRAY_CAP)) {
    if (!isPlainObject(raw)) continue
    const kind = asString(raw.kind)
    if (!kind) continue
    out.push({
      kind,
      reason: asString(raw.reason, `${kind} candidate without a stated reason`),
      knownScope: copyStrings(raw.knownScope)[0],
    })
  }
  return out
}

function readIdentities(value) {
  if (!Array.isArray(value)) return []
  const out = []
  for (const raw of value.slice(0, ARRAY_CAP)) {
    if (!isPlainObject(raw)) continue
    const ruleId = asString(raw.ruleId)
    if (!ruleId) continue
    out.push({ ruleId, path: asString(raw.path), action: asString(raw.action) })
  }
  return out
}

/** Absent inventory stays absent (a read-only call needs none); a present-but-invalid
 * inventory degrades to `unreliable`, which denies. */
function readInventory(raw) {
  if (raw === undefined || raw === null) return null
  let kind = raw.kind === 'exact' || raw.kind === 'lower-bound' ? raw.kind : 'unreliable'
  let count = raw.count
  if (typeof count !== 'number' || !Number.isFinite(count) || count < 0 || count > Number.MAX_SAFE_INTEGER) {
    kind = 'unreliable'
    count = undefined
  } else {
    count = Math.floor(count)
  }
  const [files] = copyStrings(raw.files)
  const [links] = copyStrings(raw.links)
  const [directories] = copyStrings(raw.directories)
  const [roots] = copyStrings(raw.roots)
  const [unknown] = copyStrings(raw.unknown)
  return {
    kind,
    count,
    files,
    links,
    directories,
    roots,
    unknown,
    fingerprint: asString(raw.fingerprint) || undefined,
  }
}

function readProtectedHits(value) {
  if (!Array.isArray(value)) return []
  const out = []
  for (const raw of value.slice(0, ARRAY_CAP)) {
    if (!isPlainObject(raw)) continue
    const path = asString(raw.path)
    const action = asString(raw.action)
    if (!path && !action) continue
    out.push({ path: path || '(unresolved path)', action: action || 'unknown' })
  }
  return out
}

function readIssues(value) {
  if (!Array.isArray(value)) return []
  const out = []
  for (const raw of value.slice(0, ARRAY_CAP)) {
    if (!isPlainObject(raw)) continue
    const kind = asString(raw.kind)
    const reason = asString(raw.reason)
    const path = asString(raw.path)
    if (!kind && !reason && !path) continue
    out.push({ kind, reason, path: path || undefined })
  }
  return out
}

function readGaps(value) {
  if (!Array.isArray(value)) return []
  return value.filter(isPlainObject).slice(0, ARRAY_CAP)
}

function readGitRisk(raw) {
  if (!isPlainObject(raw)) return null
  const [paths] = copyStrings(raw.paths)
  const reason = asString(raw.reason, 'git evidence reported an unresolved risk')
  if (paths.length === 0 && raw.reason === undefined) return null
  return { paths, reason }
}

// ---------------------------------------------------------------------------
// Scope construction
// ---------------------------------------------------------------------------

function emptyScope() {
  return {
    identities: [],
    protected: [],
    count: undefined,
    countKind: undefined,
    files: [],
    links: [],
    directories: [],
    roots: [],
    unknown: [],
    knownScope: [],
    notes: [],
    issues: [],
    exemptCount: undefined,
    fingerprint: undefined,
  }
}

function pushUnique(list, value, cap = ARRAY_CAP) {
  if (value && !list.includes(value) && list.length < cap) list.push(value)
}

function mergeScopes(scopes) {
  const merged = emptyScope()
  for (const scope of scopes) {
    if (!scope) continue
    for (const identity of scope.identities ?? []) merged.identities.push(identity)
    for (const hit of scope.protected ?? []) merged.protected.push(hit)
    if (merged.count === undefined && scope.count !== undefined) {
      merged.count = scope.count
      merged.countKind = scope.countKind
    }
    for (const key of ['files', 'links', 'directories', 'roots', 'unknown', 'knownScope', 'notes']) {
      for (const item of scope[key] ?? []) pushUnique(merged[key], item)
    }
    for (const issue of scope.issues ?? []) merged.issues.push(issue)
    if (merged.exemptCount === undefined && scope.exemptCount !== undefined) merged.exemptCount = scope.exemptCount
    if (!merged.fingerprint && scope.fingerprint) merged.fingerprint = scope.fingerprint
  }
  return merged
}

// ---------------------------------------------------------------------------
// decide — pure three-way decision
// ---------------------------------------------------------------------------

function checkFailedDeny(stages, issues, gaps) {
  const scope = emptyScope()
  scope.issues = issues ?? []
  const gapCodes = [...new Set((Array.isArray(gaps) ? gaps : [])
    .map((gap) => gap?.code)
    .filter((value) => typeof value === 'string' && value !== ''))]
  const base = stages.length ? stages.join('; ') : 'check failure'
  return {
    kind: 'deny',
    ruleId: CHECK_FAILED_RULE,
    ruleIds: [CHECK_FAILED_RULE],
    reason: 'A required check did not finish, so the call cannot be proven safe.',
    trigger: `${base}${gapCodes.length > 0 ? `; codes: ${gapCodes.join(',')}` : ''}`,
    scope,
    gaps: gaps ?? [],
    issues: issues ?? [],
  }
}

function collectCatastrophic(identities, operations) {
  const hits = []
  for (const identity of identities) {
    if (CATASTROPHIC_RULES.has(identity.ruleId)) hits.push(identity)
  }
  // A history-destroying Git subcommand is itself catastrophic identity (R-03): the
  // command fact alone is high confidence, the filesystem identity layer cannot add more.
  for (const op of operations) {
    if (op.action === 'git-history-destroy' && !op.preview) {
      const firstPath = op.target.kind === 'exact' ? op.target.paths[0] : op.target.kind === 'subtree' ? op.target.root : ''
      hits.push({ ruleId: 'catastrophic.git-history', path: firstPath ?? '', action: op.action })
    }
  }
  if (hits.length === 0) return null
  hits.sort((a, b) => CATASTROPHIC_ORDER.indexOf(a.ruleId) - CATASTROPHIC_ORDER.indexOf(b.ruleId))
  return hits
}

function catastrophicDecision(hits, gaps) {
  const ruleIds = [...new Set(hits.map((hit) => hit.ruleId))]
  const scope = emptyScope()
  scope.identities = hits.map((hit) => ({ ruleId: hit.ruleId, path: hit.path, action: hit.action }))
  const primary = hits[0]
  const reasons = {
    'catastrophic.device': 'Absolute deny: a real host physical disk or volume would be destroyed. Catastrophic identity cannot be approved, configured away, or waived.',
    'catastrophic.root': 'Absolute deny: the host OS root or a core system structure would be destroyed wholesale. Catastrophic identity cannot be approved, configured away, or waived.',
    'catastrophic.git-metadata': 'Absolute deny: the real shared Git metadata body would be destroyed directly. Catastrophic identity cannot be approved, configured away, or waived.',
    'catastrophic.git-history': 'Absolute deny: a Git history-destroying subcommand was identified. Catastrophic identity cannot be approved, configured away, or waived.',
  }
  return {
    kind: 'deny',
    ruleId: primary.ruleId,
    ruleIds,
    reason: reasons[primary.ruleId] ?? reasons['catastrophic.root'],
    trigger: `identity ${primary.ruleId} at ${primary.path || '(unresolved path)'} (${primary.action || 'operation'})`,
    scope,
    gaps: gaps ?? [],
  }
}

/** Closed operational failures deny unconditionally (规则模型 failure table + lead
 * ruling): analyzer crash / protocol damage / deadline miss, any forensic issue, an
 * unreliable inventory, or deletion operations without any inventory. */
function collectCheckFailures(status, issues, inventory, operations, gaps) {
  const stages = []
  if (status === 'fault') {
    // Name the real cause, not a hard-coded crash/protocol/deadline guess (N4).
    const gapCode = (Array.isArray(gaps) ? gaps : [])
      .map((gap) => gap?.code)
      .find((code) => typeof code === 'string' && code !== '')
    const issueKind = issues.length > 0 && typeof issues[0].kind === 'string' && issues[0].kind !== ''
      ? issues[0].kind
      : undefined
    if (gapCode) stages.push(`check failure: ${gapCode}`)
    else if (issueKind) stages.push(`check failure: ${issueKind}`)
    else stages.push('analysis fault (crash, protocol damage, or deadline miss)')
  }
  for (const issue of issues) stages.push(issue.kind ? `check failed at ${issue.kind}` : 'check failed')
  if (inventory && inventory.kind === 'unreliable') {
    stages.push('inventory unreliable (count or scope could not be established)')
  }
  const deletionOps = operations.filter((op) => DELETION_ACTIONS.has(op.action) && !op.preview)
  if (deletionOps.length > 0 && !inventory) {
    stages.push('no inventory was delivered for deletion operations')
  }
  if (stages.length === 0) return null
  return { stages }
}

function buildCredentialHits(protectedHits) {
  const hits = []
  const groups = new Map()
  for (const hit of protectedHits) {
    // Metadata-only observation of a protected path never confirms (R-04). An
    // unrecognized action on a protected path fails safe into the mutate rule.
    if (hit.action === 'metadata') continue
    const ruleId = READ_CONTENT_ACTIONS.has(hit.action)
      ? 'credential.file.read'
      : 'credential.file.mutate'
    if (!groups.has(ruleId)) groups.set(ruleId, [])
    groups.get(ruleId).push(hit)
  }
  const reasons = {
    'credential.file.read': 'Protected file content would be read, exported or copied. A one-time, time-limited confirmation listing the files is required; approval applies only to this call.',
    'credential.file.mutate': 'A protected file would be written, cleared, deleted or moved. A one-time, time-limited confirmation listing the files is required; approval applies only to this call.',
  }
  for (const [ruleId, entries] of groups) {
    const scope = emptyScope()
    scope.protected = entries.map((entry) => ({ path: entry.path, action: entry.action }))
    const paths = entries.map((entry) => entry.path)
    hits.push({
      ruleId,
      outcome: 'confirm',
      reason: reasons[ruleId],
      trigger: `${entries.length} protected file hit(s): ${paths.slice(0, 3).join('; ')}`,
      scope,
      targets: paths,
      unobserved: false,
    })
  }
  return hits
}

/** Credential text scan hit (规则模型「凭据防泄露」R-04): analyzed command or script text
 * referenced a protected credential name while an unresolved dynamic operand existed.
 * Confirm only, never downgrade; the hit lists no enumerable target and is marked
 * unobserved, so a path allowlist can never waive it. */
function buildCredentialTextHits(operations, flagged) {
  if (flagged !== true) return []
  const ruleId = operations.some((op) => TEXT_SCAN_MUTATE_ACTIONS.has(op.action))
    ? 'credential.file.mutate'
    : 'credential.file.read'
  const scope = emptyScope()
  scope.notes.push('unresolved dynamic operand; credential name referenced in text')
  return [{
    ruleId,
    outcome: 'confirm',
    reason: 'Analyzed command or script text referenced a protected credential name while an unresolved dynamic operand existed. A one-time, time-limited confirmation is required; approval applies only to this call.',
    trigger: 'credential basename or private-key header matched in analyzed text (unresolved dynamic operand present)',
    scope,
    targets: [],
    unobserved: true,
  }]
}

/** Deletion-tier family rule: a uniformly git or move call keeps its catalog rule,
 * anything mixed uses the generic data rule for the given tier
 * (fallbackKind: 'allow' | 'bulk' | 'dynamic'). */
function deletionFamilyRule(operations, fallbackKind) {
  const actionable = operations.filter((op) => DELETION_ACTIONS.has(op.action) && !op.preview)
  const allGit = actionable.length > 0 && actionable.every((op) => GIT_ACTIONS.has(op.action))
  const allMove = actionable.every((op) => op.action === 'move-source')
  if (allGit) return GIT_OP_RULES[actionable[0].action]
  if (allMove) return 'data.move.source'
  return fallbackKind === 'allow' ? 'data.delete.ordinary' : fallbackKind === 'dynamic' ? 'data.delete.dynamic' : 'data.delete.bulk'
}

function buildDeletionHit(operations, inventory, gitRisk) {
  const delOps = operations.filter((op) => DELETION_ACTIONS.has(op.action) && !op.preview)
  const hits = []
  const dynamicOps = delOps.filter((op) => {
    // Git supplies its path set through evidence, after the syntax analysis.
    if (Object.hasOwn(GIT_OP_RULES, op.action) && op.target.reason === 'git-evidence' &&
      inventory && (inventory.unknown.length === 0 || gitRisk?.paths.length)) return false
    return op.target.kind === 'unknown' || op.target.kind === 'pattern' || op.recursive === 'unknown'
  })

  if (dynamicOps.length > 0) {
    // Unknown, wildcard, or recursion-unproven targets: the deletion cannot be counted
    // (R-07). Directory contents must not stand in for an unknown target's scope.
    const ruleId = deletionFamilyRule(dynamicOps, 'dynamic')
    const scope = emptyScope()
    scope.files = inventory?.files ?? []
    scope.links = inventory?.links ?? []
    scope.directories = inventory?.directories ?? []
    scope.roots = [...(inventory?.roots ?? [])]
    scope.unknown = inventory?.unknown ?? []
    const targets = []
    let unscoped = false
    for (const op of dynamicOps) {
      if (op.target.kind === 'unknown' && !op.target.knownScope?.length) unscoped = true
      for (const known of op.target.knownScope ?? []) pushUnique(scope.knownScope, known)
      if (op.target.kind === 'pattern') {
        const label = `pattern ${op.target.pattern || '(unresolved pattern)'} under ${op.target.base || '(unresolved base)'}`
        pushUnique(scope.notes, label)
        if (op.target.base) pushUnique(scope.roots, op.target.base)
      } else if (op.target.kind === 'unknown') {
        pushUnique(scope.notes, op.target.reason)
      } else {
        for (const known of op.target.paths ?? []) pushUnique(scope.knownScope, known)
        pushUnique(scope.notes, 'recursion unproven for an otherwise known target')
      }
      if (op.target.kind === 'exact') for (const known of op.target.paths ?? []) targets.push(known)
      for (const known of op.target.knownScope ?? []) targets.push(known)
    }
    hits.push({
      ruleId,
      outcome: unscoped ? 'deny' : 'confirm',
      reason: unscoped ? 'At least one deletion target has no verifiable scope.'
        : 'Deletion targets cannot be fully enumerated. Confirm the documented scope and its unknown remainder.',
      trigger: asString(dynamicOps[0].target.reason, 'deletion target not enumerable'),
      scope,
      // A dynamic deletion always has an unobserved remainder, so a path allowlist can
      // never prove completeness here; only enabled/allowOnce may waive it.
      targets,
      unobserved: true,
    })
  } else if (delOps.length > 0 && inventory) {
    const scope = emptyScope()
    scope.files = inventory.files
    scope.links = inventory.links
    scope.directories = inventory.directories
    scope.roots = inventory.roots
    scope.unknown = inventory.unknown
    scope.count = inventory.count
    scope.countKind = inventory.kind
    const targets = [...inventory.files, ...inventory.links, ...inventory.directories, ...inventory.roots]
    // An exact count with unobserved ranges is not a proof of completeness.
    const unobserved = inventory.unknown.length > 0
    if (inventory.kind === 'exact' && inventory.count <= ALLOW_THRESHOLD && !unobserved) {
      hits.push({
        ruleId: deletionFamilyRule(delOps, 'allow'),
        outcome: 'allow',
        reason: 'The non-exempt deletion set is enumerable and within the 20-entry allow threshold.',
        trigger: `deletion inventory (${inventory.kind})`,
        scope,
        targets,
        unobserved,
      })
    } else {
      const ruleId = deletionFamilyRule(delOps, 'bulk')
      hits.push({
        ruleId,
        outcome: 'confirm',
        reason: 'The non-exempt deletion set exceeds the 20-entry allow threshold (or its completeness is unproven). Confirm with the deletion scope before this call proceeds; confirmation is not a standing deletion authorization and targets are re-inventoried after approval.',
        trigger: 'non-exempt deletion inventory exceeds the allow threshold',
        scope,
        targets,
        unobserved: unobserved || inventory.kind === 'lower-bound',
      })
    }
  }

  // gitRisk (R-06 dirty worktree, git evidence risk) escalates its call to a
  // scope-checked confirmation under data.git.worktree.
  if (gitRisk) {
    const scope = emptyScope()
    for (const known of gitRisk.paths) pushUnique(scope.knownScope, known)
    pushUnique(scope.notes, gitRisk.reason)
    hits.push({
      ruleId: 'data.git.worktree',
      outcome: 'confirm',
      reason: 'Git evidence reports a risk for this call (for example a worktree with uncommitted or untracked changes). Confirm with the affected paths before this call proceeds; approval applies only to this call.',
      trigger: `git risk: ${gitRisk.reason.slice(0, 160)}`,
      scope,
      targets: gitRisk.paths,
      unobserved: false,
    })
  }
  return hits
}

function buildCandidateHits(candidates) {
  const hits = []
  for (const candidate of candidates) {
    const ruleId = candidate.kind === 'dynamic-execution' ? 'execution.dynamic-command' : 'execution.unverified-effect'
    const provable = candidate.knownScope.length > 0
    const scope = emptyScope()
    for (const known of candidate.knownScope) pushUnique(scope.knownScope, known)
    pushUnique(scope.notes, candidate.reason)
    hits.push({
      ruleId,
      outcome: provable ? 'confirm' : 'deny',
      reason: provable
        ? 'An identified execution risk could not be resolved into countable operations. Confirm with the checkable scope; the unresolved part is stated explicitly.'
        : 'An identified execution risk has no checkable scope, so it cannot be confirmed; deny instead of guessing.',
      trigger: candidate.reason.slice(0, 200),
      scope,
      targets: candidate.knownScope,
      unobserved: !provable,
    })
  }
  return hits
}

/** Per-rule waiver (规则模型 配置模型): enabled=false removes the hit, a path allowlist
 * removes it when every known target matches and nothing is unobserved, allowOnce
 * removes it for the current call. Catastrophic and check-failed hits are never waived;
 * under tightenOnly, credential.* (受保护项) stays effective. */
function waiveHit(hit, policy) {
  if (NONCONFIGURABLE_RULES.has(hit.ruleId)) return false
  if (policy.tightenOnly && hit.ruleId.startsWith('credential.')) return false
  const config = policy.rules[hit.ruleId]
  if (config) {
    if (config.enabled === false) return true
    if (config.allowlist && config.allowlist.length > 0 && hit.targets.length > 0 && !hit.unobserved) {
      const keys = new Set(config.allowlist.map((entry) => shapeKey(entry)))
      const allListed = hit.targets.every((target) => keys.has(shapeKey(target)))
      if (allListed) return true
    }
  }
  if (policy.allowOnce.includes(hit.ruleId)) return true
  return false
}

function pickPrimary(hits, priority) {
  let primary = hits[0]
  for (const ruleId of priority) {
    const found = hits.find((hit) => hit.ruleId === ruleId)
    if (found) { primary = found; break }
  }
  return primary
}

/**
 * The single policy decision point. Pure: no I/O, no DSH objects; `effectivePolicy` may
 * be a raw config object or an already-normalized policy (normalization is idempotent).
 * Catastrophic identity denies first and short-circuits everything; closed operational
 * failures deny under the stable check-failed id; the remaining hits merge per
 * 拒绝 > 确认 > 放行, with per-rule waivers applied before combining.
 */
export function decide(evidence, effectivePolicy) {
  try {
    if (!isPlainObject(evidence)) {
      return checkFailedDeny(['missing result'], [], [])
    }
    // Trusted per-call snapshot: the adapter owns allowOnce for this invocation.
    const policy = normalizePolicy(effectivePolicy, { callScoped: true })
    const status = evidence.analysisStatus === 'complete' || evidence.analysisStatus === 'partial'
      ? evidence.analysisStatus
      : 'fault'
    const operations = readOperations(evidence.operations)
    const candidates = readCandidates(evidence.candidates)
    const identities = readIdentities(evidence.identities)
    const inventory = readInventory(evidence.inventory)
    const protectedHits = readProtectedHits(evidence.protectedHits)
    const issues = readIssues(evidence.issues)
    const gaps = readGaps(evidence.gaps)
    const gitRisk = readGitRisk(evidence.gitRisk)
    const inlineCredential = evidence.inlineCredential === true

    // 1. Catastrophic identity first; it short-circuits all other judgment and survives
    //    every later failure or waiver.
    const catastrophic = collectCatastrophic(identities, operations)
    if (catastrophic) return catastrophicDecision(catastrophic, gaps)

    // 2. Closed operational failures deny under the stable non-configurable id.
    const failures = collectCheckFailures(status, issues, inventory, operations, gaps)
    if (failures) return checkFailedDeny(failures.stages, issues, gaps)

    // 3..6. Collect hits.
    const hits = []
    if (inlineCredential) {
      hits.push({
        ruleId: 'credential.inline',
        outcome: 'deny',
        reason: 'A recognizable real credential is inlined in command parameters and would spread into persisted tool input. Use a credential reference, environment variable, stdin, or the authenticated configuration of the tool instead.',
        trigger: 'inline credential literal in command parameters',
        scope: emptyScope(),
        targets: [],
        unobserved: false,
      })
    }
    hits.push(...buildCredentialHits(protectedHits))
    hits.push(...buildDeletionHit(operations, inventory, gitRisk))
    hits.push(...buildCandidateHits(candidates))
    // R-04 credential text scan: adds one confirm hit unless protectedHits already
    // produced a hit under the same rule id (只升不降; no duplicate request).
    for (const hit of buildCredentialTextHits(operations, evidence.credentialTextMention)) {
      if (!hits.some((existing) => existing.ruleId === hit.ruleId)) hits.push(hit)
    }

    // 7. Apply per-rule waivers, then combine per 拒绝 > 确认 > 放行.
    const kept = []
    const waived = []
    for (const hit of hits) (waiveHit(hit, policy) ? waived : kept).push(hit)
    const denies = kept.filter((hit) => hit.outcome === 'deny')
    const confirms = kept.filter((hit) => hit.outcome === 'confirm')
    const allowances = kept.filter((hit) => hit.outcome === 'allow')

    const waivedRuleIds = [...new Set(waived.map((hit) => hit.ruleId))]

    if (denies.length > 0) {
      const primary = pickPrimary(denies, DENY_PRIORITY)
      return {
        kind: 'deny',
        ruleId: primary.ruleId,
        ruleIds: [...new Set(denies.map((hit) => hit.ruleId))],
        reason: primary.reason,
        trigger: primary.trigger,
        scope: mergeScopes(denies.map((hit) => hit.scope)),
        gaps,
        ...(waivedRuleIds.length > 0 ? { waived: waivedRuleIds } : {}),
      }
    }
    if (confirms.length > 0) {
      const primary = pickPrimary(confirms, CONFIRM_PRIORITY)
      return {
        kind: 'confirm',
        ruleId: primary.ruleId,
        ruleIds: [...new Set(confirms.map((hit) => hit.ruleId))],
        reason: primary.reason,
        trigger: primary.trigger,
        scope: mergeScopes(confirms.map((hit) => hit.scope)),
        gaps,
        ...(waivedRuleIds.length > 0 ? { waived: waivedRuleIds } : {}),
      }
    }
    const allowance = allowances[0]
    return {
      kind: 'allow',
      ...(allowance ? { ruleId: allowance.ruleId } : {}),
      gaps,
      ...(waivedRuleIds.length > 0 ? { waived: waivedRuleIds } : {}),
    }
  } catch {
    // Internal anomaly: deny the analyzed call and keep the reason free of raw values
    // (safe diagnostics; renderDecision redacts the block anyway).
    return checkFailedDeny(['internal decision error'], [], [])
  }
}

// ---------------------------------------------------------------------------
// renderDecision — fixed block + redaction
// ---------------------------------------------------------------------------

function categoryOf(ruleId) {
  const category = String(ruleId).split('.')[0]
  return ['catastrophic', 'data', 'credential', 'execution'].includes(category) ? category : 'check'
}

function redact(value) {
  return typeof value === 'string' ? redactText(value).text : ''
}

/** Collapse to one line, then truncate (redaction happens before truncation so no
 * partial credential tail can survive). */
function clamp(value, limit) {
  const line = value.replace(/\s+/g, ' ').trim()
  return line.length > limit ? `${line.slice(0, limit)}…` : line
}

function renderList(items) {
  const shown = items.slice(0, LIST_DISPLAY_CAP).join('; ')
  return items.length > LIST_DISPLAY_CAP ? `${shown}; …` : shown
}

/** Human-readable scope: entry lists without totals (R-07 forbids claiming a precise
 * total or atomicity), counts phrased as bounds, unknown parts stated explicitly. */
function scopeText(scope) {
  if (!scope) return 'not captured'
  const parts = []
  if (scope.identities && scope.identities.length > 0) {
    parts.push(`identities: ${renderList(scope.identities.map((hit) => `${hit.ruleId} at ${hit.path || '(unresolved)'} (${hit.action || 'operation'})`))}`)
  }
  if (scope.protected && scope.protected.length > 0) {
    parts.push(`protected files: ${renderList(scope.protected.map((hit) => `${hit.path} (${hit.action})`))}`)
  }
  if (scope.count !== undefined) {
    if (scope.countKind === 'exact') {
      parts.push(scope.count > ALLOW_THRESHOLD
        ? `non-exempt entries: at least ${ALLOW_THRESHOLD + 1} (threshold exceeded)`
        : `non-exempt entries: ${scope.count}`)
    } else {
      parts.push(`non-exempt entries: at least ${scope.count} (lower bound)`)
    }
  }
  const listMembers = [
    ['files', 'entries'],
    ['links', 'links'],
    ['directories', 'directories'],
    ['roots', 'roots'],
    ['knownScope', 'known scope'],
    ['unknown', 'unobserved'],
  ]
  for (const [key, label] of listMembers) {
    if (Array.isArray(scope[key]) && scope[key].length > 0) parts.push(`${label}: ${renderList(scope[key])}`)
  }
  if (Array.isArray(scope.notes) && scope.notes.length > 0) parts.push(`notes: ${renderList(scope.notes)}`)
  if (Array.isArray(scope.issues) && scope.issues.length > 0) {
    parts.push(`failed checks: ${renderList(scope.issues.map((issue) => issue.kind || issue.reason || 'unspecified stage'))}`)
  }
  if (scope.exemptCount !== undefined) parts.push(`rebuildable-exempt entries observed: ${scope.exemptCount}`)
  return parts.length > 0 ? parts.join('; ') : 'not captured'
}

/**
 * Render one decision into the fixed block (规则模型 失败分类与提示格式). Deny/confirm
 * return the block; allow returns null — the fixed block is defined for rejections and
 * confirmations only, and coverage diagnostics ride on decision.gaps for the adapter to
 * log. Why/Trigger/Scope are redacted with the shared credential redactor before output.
 */
export function renderDecision(decision) {
  if (!isPlainObject(decision)) return null
  if (decision.kind === 'allow') return null
  if (decision.kind !== 'deny' && decision.kind !== 'confirm') return null
  const ruleId = typeof decision.ruleId === 'string' && decision.ruleId ? decision.ruleId : CHECK_FAILED_RULE
  // A gate stage marker `(stage CODE)` in the reason overrides the catalog effect/next.
  const stageMatch = typeof decision.reason === 'string' ? /\(stage ([A-Z0-9_]+)\)/.exec(decision.reason) : null
  const stage = stageMatch && STAGE_META[stageMatch[1]] ? stageMatch[1] : undefined
  const meta = stage ? STAGE_META[stage] : (RULE_META[ruleId] ?? GENERIC_META)
  const header = `[GUARDRAILS] ${decision.kind === 'deny' ? 'DENY' : 'CONFIRM'} ${ruleId} (${categoryOf(ruleId)})`
  const why = clamp(redact(decision.reason) || 'The invocation requires a guard decision.', 320)
  const trigger = clamp(redact(decision.trigger), 240)
  const scope = clamp(redact(scopeText(decision.scope)), 720)
  const lines = [header, `Why:     ${why}`]
  // Empty coverage lines are dropped instead of claiming "not captured".
  if (trigger && trigger !== 'not captured') lines.push(`Trigger: ${trigger}`)
  lines.push(`Effect:  ${meta.effect}`)
  if (scope && scope !== 'not captured') lines.push(`Scope:   ${scope}`)
  // Every denial states plainly that nothing ran; confirmations follow their own copy.
  const next = decision.kind === 'deny' && !meta.next.startsWith('Nothing was executed.')
    ? `Nothing was executed. ${meta.next}`
    : meta.next
  lines.push(`Next:    ${next}`)
  return lines.join('\n')
}
