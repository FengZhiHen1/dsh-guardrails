// diagnostics — pure, English, structured tool-return messages for the guard gate.
// Boundary: no filesystem/process/network access; it only reshapes already-computed
// decisions into the fixed five-line block the agent reads. Credentials are masked with the
// shared redactor before anything is returned.
//
// Block shape (the agent must not have to guess):
//   [GUARDRAILS] DENY|ASK <RULE-ID> (<layer>)
//   Why: <the concrete reason, naming the token/expression>
//   Trigger: <the actual command/argument/expression, truncated, credentials masked>
//   Effect: <what the gate had to check/count, and why it could not finish>
//   Next: <the minimal viable alternative>
//   <DELETION_DOCTRINE>  (final line, deletion-related rules only)

import { DELETION_DOCTRINE, CLEARER } from './deletion-intent.js'
import { redactText } from './redaction.js'

const TRIGGER_LIMIT = 200
const WHITESPACE = /\s+/g

/** Layer per rule family. */
function layerOf(ruleId) {
  if (/^ABS-/.test(ruleId)) return 'L1'
  if (ruleId === 'DEL-12' || ruleId === 'DEL-13') return 'L1'
  if (/^DEL-/.test(ruleId)) return 'L2'
  if (ruleId === 'S-F1' || ruleId === 'S-F2') return 'Approval'
  return 'Analysis'
}

/** Per-rule Effect/Next. Exact ids first, then family fallbacks. */
const RULE_META = {
  'ABS-01': { effect: 'Stop destruction of a real host physical disk or partition.', next: 'Do not target a physical device from this environment.' },
  'ABS-02': { effect: 'Stop whole-tree destruction of the host OS root or a core system structure.', next: 'Target a specific, non-system path instead.' },
  'ABS-03': { effect: 'Stop direct destruction of the shared Git metadata body.', next: 'Use explicit Git commands; never delete .git contents.' },
  'DEL-01': { effect: 'Count the exact files/links this call would remove before dispatch; the set exceeds the 20-entry limit.', next: 'Verify the expected set first; delete at most 20 entries per separate call and re-issue for the rest.' },
  'DEL-14': { effect: 'Count the source files this move would remove; the set exceeds the 20-entry limit.', next: 'Move at most 20 sources per call, or use copy if the source must remain.' },
  'DEL-02': { effect: 'Count the exact delete target set before dispatch; a dynamic, wildcard or unknown target cannot be counted.', next: 'Use explicit literal paths with no wildcard or unresolved variable, as one standalone command.' },
  'DEL-03': { effect: 'Count the deletion on the correct filesystem namespace; this dialect/domain cannot be inventoried from the host.', next: 'Reissue as a PowerShell Remove-Item -LiteralPath with a drive-qualified path, or delete inside that domain with its own inventory.' },
  'DEL-04': { effect: 'Count the real files reachable through the target; a parent is a symbolic link so the real set is unproven.', next: 'Delete the real path directly instead of deleting through a link.' },
  'DEL-05': { effect: 'Count a recursive set that must stay within one filesystem/mount.', next: 'Delete a smaller explicit path that stays within one mount.' },
  'DEL-06': { effect: 'Read the target subtree to count it; the metadata could not be inspected.', next: 'Retry against a readable literal path.' },
  'DEL-07': { effect: 'Finish the inventory within the analysis budget; the count cannot be proven <= 20.', next: 'Delete a smaller set per call.' },
  'DEL-08': { effect: 'Prove a deterministic target set; the target shape (link/dotdot/trailing separator/non-recursive directory/special file) is ambiguous.', next: 'Use one literal path with unambiguous recursive semantics.' },
  'DEL-10': { effect: 'Locate the target relative to a provable working directory.', next: 'Use an absolute literal path.' },
  'DEL-11': { effect: 'Finish the inventory before dispatch; the call was cancelled.', next: 'Retry the call.' },
  'DEL-12': { effect: 'Refuse whole-root deletion.', next: 'Target a specific literal path below the root.' },
  'DEL-13': { effect: 'Refuse treating Git metadata as ordinary files.', next: 'Remove worktrees/repositories through explicit Git commands.' },
  'DI-UNKNOWN-SEMANTICS': { effect: 'Prove the invocation has no unenumerable deletion side effect before dispatch.', next: 'Rewrite as explicit literal command(s): split statements, avoid assigning/state-changing forms in the same call, and use the read tool for read-only work.' },
  'DI-DYNAMIC-COMMAND': { effect: 'Resolve the command name before dispatch; a dynamic name is an unanalysable execution channel.', next: 'Use a literal program name; avoid & $var and iex.' },
  'DI-INLINE-CODE': { effect: 'Enumerate the target set of the inline program; inline code cannot be counted.', next: 'Put the program in a file, or use an explicit literal command for the exact target.' },
  'DI-UNSUPPORTED-COMMAND': { effect: 'Prove the command has no unenumerable deletion; this family can delete or run arbitrary programs.', next: 'Use an explicit literal delete/move command for the exact target.' },
  'DI-DYNAMIC-ARGUMENT': { effect: 'Count the deletion/move target; a dynamic argument cannot be enumerated.', next: 'Use a literal path (assign the literal to a variable first if needed).' },
  'DI-GIT-REFUSE': { effect: 'Protect repository history from an irreversible Git operation.', next: 'Avoid destructive git flags; operate on explicit paths instead.' },
  'S-F1': { effect: 'Confirm access/removal of an actual protected, credential-bearing file.', next: 'Use runtime credential injection or a status-only health check; approval applies only to this call.' },
  'S-F2': { effect: 'Confirm removal of a protected worktree resource.', next: 'Use runtime credential injection or a status-only health check; approval applies only to this call.' },
  'UNKNOWN_TOOL': { effect: 'Prove the tool has no filesystem deletion side effects.', next: 'Use a checked tool (read/write/edit/delete/pwsh/bash) for the exact operation, or request an adapter.' },
  'OPAQUE_CODE': { effect: 'Enumerate a program\'s runtime filesystem/process/network side effects.', next: 'Call a checked tool for the exact target instead of running an opaque program.' },
  'UNSUPPORTED_DELETE': { effect: 'Count one literal delete target.', next: 'Pass a single literal local path (no wildcards, dynamic values, or extra arguments).' },
  'UNSUPPORTED_TRANSFER': { effect: 'Count one literal transfer source so its removal can be counted.', next: 'Pass a single literal local source path.' },
  'PLAN_CHANGED': { effect: 'Ensure the counted target set is the set actually dispatched.', next: 'Re-issue the deletion after the target set is stable.' },
  'ANALYSIS_CANCELLED': { effect: 'Complete analysis before dispatch.', next: 'Retry the call.' },
  'R-M2': { effect: 'Stop an inline credential literal from spreading into persisted tool input.', next: 'Use a credential reference, environment variable, stdin, or the tool\'s authenticated configuration.' },
}

const FAMILY_META = {
  'DEL-GIT-': { effect: 'Count the entries this git action would remove before dispatch.', next: 'Verify the expected set first; remove at most 20 entries per separate call.' },
  'DI-': { effect: 'Prove the invocation has no unenumerable deletion side effect.', next: 'Use a clearer, supported command with explicit literal paths and supported options.' },
  'ANALYSIS_': { effect: 'Complete analysis before dispatch.', next: 'Retry the call with valid syntax and available parsers.' },
}

function metaFor(ruleId) {
  if (RULE_META[ruleId]) return RULE_META[ruleId]
  for (const [prefix, meta] of Object.entries(FAMILY_META)) {
    if (ruleId.startsWith(prefix)) return meta
  }
  return {
    effect: 'Prove the call has no unenumerable deletion side effect.',
    next: 'Use a clearer, supported command with explicit literal paths and supported options.',
  }
}

/** Extract a `[TAG]`/`[guardrails:TAG]` rule id from a legacy reason, and the body after it. */
function splitTag(reason) {
  const match = typeof reason === 'string' ? /^\[(?:guardrails:)?([A-Za-z0-9_-]+)\]\s*([\s\S]*)$/.exec(reason) : null
  if (!match) return { ruleId: undefined, body: typeof reason === 'string' ? reason : '' }
  return { ruleId: match[1], body: match[2] }
}

/** Remove the shared trailing sentences (doctrine, then CLEARER) from a Why body. */
function cleanWhy(ruleId, body) {
  let why = body.trim()
  if (ruleId && why.startsWith(`${ruleId}:`)) why = why.slice(ruleId.length + 1).trim()
  if (DELETION_DOCTRINE && why.endsWith(DELETION_DOCTRINE)) why = why.slice(0, -DELETION_DOCTRINE.length).trim()
  if (CLEARER && why.endsWith(CLEARER)) why = why.slice(0, -CLEARER.length).trim()
  return why.length > 0 ? why : 'The invocation cannot be proven free of an unenumerable deletion side effect.'
}

/** Redact then compact whitespace so a trigger stays on one line within the limit. */
function renderTrigger(text) {
  const safe = redactText(String(text)).text.replace(WHITESPACE, ' ').trim()
  return safe.length > TRIGGER_LIMIT ? `${safe.slice(0, TRIGGER_LIMIT)}...` : safe
}

/** One-line description of what the tool call was actually trying to do. */
function triggerOf(execution, unknown) {
  const name = execution && typeof execution.name === 'string' ? execution.name : 'tool'
  const args = execution && execution.arguments && typeof execution.arguments === 'object' ? execution.arguments : {}
  let subject
  if (typeof args.command === 'string') subject = `command=${args.command}`
  else if (typeof args.text === 'string') subject = `text=${args.text}`
  else if (typeof args.file_path === 'string') subject = `file_path=${args.file_path}`
  else if (typeof args.path === 'string') subject = `path=${args.path}`
  else if (typeof args.url === 'string') subject = `url=${args.url}`
  else {
    try { subject = JSON.stringify(args) } catch { subject = '' }
  }
  let trigger = `${name} ${subject}`.trim()
  const detail = Array.isArray(unknown) ? unknown.filter((entry) => typeof entry === 'string') : []
  if (detail.length > 0) trigger += ` | unresolved: ${detail.join('; ')}`
  return renderTrigger(trigger)
}

function isDeletionRelated(ruleId, reason) {
  if (typeof reason === 'string' && reason.includes(DELETION_DOCTRINE)) return true
  if (/^DEL-/.test(ruleId)) return true
  if (/^ABS-/.test(ruleId)) return true
  if (ruleId === 'S-F1' || ruleId === 'S-F2') return true
  return /^DI-(?:UNKNOWN-SEMANTICS|DYNAMIC-ARGUMENT|DYNAMIC-COMMAND|UNSUPPORTED-COMMAND|GIT-REFUSE|INLINE-CODE|NONSCRIPT-SCOPE|REDIRECTION|NO-TARGET|MALFORMED|PREVIEW-|PROVIDER-PATH|AMBIGUOUS-DIALECT|STOP-PARSING|UNTRUSTED-PATH|NATIVE-PROGRAM|UNSUPPORTED-OPTION)/.test(ruleId)
}

/**
 * Render one guard decision into the fixed block.
 * @param {{kind:string, ruleId?:string, reason?:string, unknown?:string[], execution?:object}} input
 * @returns {string}
 */
export function renderGuardrailMessage({ kind, ruleId, reason, unknown = [], execution } = {}) {
  const tagged = splitTag(reason)
  const resolvedRule = ruleId || tagged.ruleId || 'DENIED'
  const decision = kind === 'ask' ? 'ASK' : 'DENY'
  const meta = metaFor(resolvedRule)
  const why = cleanWhy(resolvedRule, tagged.body)
  const trigger = triggerOf(execution, unknown)
  const lines = [
    `[GUARDRAILS] ${decision} ${resolvedRule} (${layerOf(resolvedRule)})`,
    `Why: ${why}`,
    `Trigger: ${trigger}`,
    `Effect: ${meta.effect}`,
    `Next: ${meta.next}`,
  ]
  if (isDeletionRelated(resolvedRule, reason)) lines.push(DELETION_DOCTRINE)
  return redactText(lines.join('\n')).text
}

/**
 * Classify an unknown diagnostic string into a coarse kind. Used to reason about which
 * unknowns are non-deletion noise (assignments, dynamic arguments) versus analysis limits.
 */
export function classifyUnknown(text) {
  const value = typeof text === 'string' ? text : ''
  if (/^E[A-Z][A-Z0-9]*$/.test(value)) return 'errno'
  if (/^State-changing command\b/.test(value)) return 'state-changing'
  if (/^(?:Bash assignment changes state|PowerShell (?:environment )?variable assignment changes state)/.test(value)) return 'assignment'
  if (/^Dynamic command or argument/.test(value)) return 'dynamic-argument'
  if (/^PowerShell member\/type expression/.test(value)) return 'member-expression'
  if (/^PowerShell .*construct can execute/.test(value)) return 'executable-construct'
  if (/budget|Budget|deadline/i.test(value)) return 'budget'
  if (/^wsl\b|WSL/i.test(value)) return 'wsl'
  if (/link-entry-removal|nonliteral-or-remote|device-identity|^cwd$/.test(value)) return 'target-observation'
  return 'other'
}

export default renderGuardrailMessage
