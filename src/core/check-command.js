// check-command — the full pwsh command judgment pipeline.
//
// Boundary: pure composition of the core passes (literal reconstruction →
// listing/content classification → text references → W0 system write →
// unverifiable fail-safe → destructive analysis); no DSH imports.
// Reference: docs/technical-details/命令文本分析.md; DSR-002/005/006/007.

import { CRED_TEXT_REFERENCE } from './rules.js'
import {
  assessContentClass,
  assessSystemWrite,
  assessUnverifiable,
  detectContentSensitiveRef,
  isListingOnly,
  resolveCommandLiterals,
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
 * Judge one pwsh command against every defense layer.
 * Literal reconstruction runs first: evaluable `$(...)` splicing and
 * same-command variable assignments are rewritten to their values so every
 * downstream check sees the real command (each pwsh call runs in a fresh
 * process, so no variable can persist across calls).
 *
 * @param base - judgment base directory (resolved workspace root; DSR-007).
 * @param command - raw command text from the tool call.
 * @param rules - op-level leaves from `evaluateRules`.
 * @returns the deny message when blocked, `undefined` when allowed.
 */
export function checkCommand(base, command, rules) {
  const resolved = resolveCommandLiterals(command)
  const listingOnly = isListingOnly(resolved)
  const contentClass = assessContentClass(resolved)
  if (!listingOnly) {
    const category = detectContentSensitiveRef(resolved)
    if (category !== null && leafEnabled(rules[category], contentClass)) {
      return COMMAND_REFERENCE_REASON[category]()
    }
  }
  if (leafEnabled(rules.credentials, contentClass) && CRED_TEXT_REFERENCE.test(resolved)) {
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
  return undefined
}
