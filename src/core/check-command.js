// check-command — the full pwsh command judgment pipeline.
//
// Boundary: pure composition of the core passes (literal reconstruction →
// listing/content classification → text references → W0 system write →
// unverifiable fail-safe → destructive analysis, recursing into embedded
// subexpressions); no DSH imports.
// Reference: docs/technical-details/命令文本分析.md; DSR-002/005/006/007/012.

import { CRED_TEXT_REFERENCE } from './rules.js'
import {
  assessContentClass,
  assessSystemWrite,
  assessUnverifiable,
  detectContentSensitiveRef,
  isListingOnly,
  maskTextSpans,
  resolveCommandLiterals,
  tokenizePwsh,
} from './command.js'
import { assessDestructive } from './destructive.js'
import {
  COMMAND_REFERENCE_REASON,
  credentialBashReason,
  destructiveReason,
  leafEnabled,
  systemBashReason,
  unverifiableReason,
} from './deny-messages.js'

/**
 * Bound on the subexpression nesting this pipeline recurses through. Each level
 * costs one full pass, and adversarial input can nest arbitrarily; PowerShell
 * text produced by a model never approaches this, so the cap only ever fires on
 * pathological input — where stopping early is the conservative direction
 * because the outer pass already sees the (still unverifiable) text.
 */
const MAX_SUBEXPRESSION_DEPTH = 8

/**
 * Judge one pwsh command against every defense layer.
 * Literal reconstruction runs first: evaluable `$(...)` splicing and
 * same-command variable assignments are rewritten to their values so every
 * downstream check sees the real command (each pwsh call runs in a fresh
 * process, so no variable can persist across calls).
 *
 * Subexpressions are judged as commands in their own right, because that is
 * what PowerShell does with them regardless of where they were written. This is
 * what closes the interpolated-string channel: the lexer collects `$(...)` from
 * double-quoted spans too, so `Write-Output "$(Get-Content .env)"` and
 * `"$(Remove-Item C:\Windows -Recurse)"` reach the text-reference, system-write
 * and destructive passes instead of being read as inert string content.
 *
 * @param base - judgment base directory (resolved workspace root; DSR-007).
 * @param command - raw command text from the tool call.
 * @param rules - op-level leaves from `evaluateRules`.
 * @param depth - internal recursion depth; callers omit it.
 * @returns the deny message when blocked, `undefined` when allowed.
 */
export function checkCommand(base, command, rules, depth = 0) {
  const resolved = resolveCommandLiterals(command)
  const listingOnly = isListingOnly(resolved)
  const contentClass = assessContentClass(resolved)
  // Citations of a sensitive name (prose, or a text/pattern parameter value) are
  // blanked for the text-reference checks only; every other pass sees the real
  // command (DSR-010).
  const cited = maskTextSpans(resolved)
  if (!listingOnly) {
    const category = detectContentSensitiveRef(cited)
    if (category !== null && leafEnabled(rules[category], contentClass)) {
      return COMMAND_REFERENCE_REASON[category]()
    }
  }
  if (leafEnabled(rules.credentials, contentClass) && CRED_TEXT_REFERENCE.test(cited)) {
    return credentialBashReason()
  }
  if (!listingOnly) {
    // W0 system-area writes (write verbs / redirects / cd chains).
    if (rules.system.write) {
      const systemHit = assessSystemWrite(base, resolved)
      if (systemHit) return systemBashReason(systemHit.path)
    }
    // Unverifiable-target gate (category-independent fail-safe): after
    // reconstruction, a remaining $(...) as the command itself or in a
    // content/removal verb argument means the target is computed at run
    // time — it cannot be verified, so block conservatively.
    if (rules.unverifiable) {
      const hit = assessUnverifiable(resolved)
      if (hit) return unverifiableReason(hit.text, command)
    }
  }
  const hit = assessDestructive(base, resolved, rules.destructive)
  if (hit) return destructiveReason(hit.text, command)
  if (depth >= MAX_SUBEXPRESSION_DEPTH) return undefined
  for (const nested of tokenizePwsh(resolved).nested) {
    const nestedHit = checkCommand(base, nested, rules, depth + 1)
    if (nestedHit) return nestedHit
  }
  return undefined
}
