// check-command — the full pwsh command judgment pipeline.
//
// Boundary: pure composition of the core passes (literal reconstruction →
// listing/content classification → text references → W0 system write →
// unverifiable fail-safe → destructive analysis, recursing into embedded
// subexpressions); no DSH imports.
// Reference: docs/technical-details/命令文本分析.md; DSR-002/005/006/007/012.

import { CRED_TEXT_REFERENCE, CRED_TEXT_REFERENCE_STRICT } from './rules.js'
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
 * costs one full pass, and adversarial input can nest arbitrarily — but nesting
 * is *attacker-controlled*, so the bound must never be the thing that lets a
 * command through. Reaching it fails CLOSED (see the cap branch in
 * {@link checkCommand}); it is a work bound, not a trust boundary.
 *
 * Measured on 26,764 real commands (7-day `stable-dev` corpus): nesting depth is
 * 0 for 21,280, 1 for 5,420, 2 for 64, and never higher. So a legitimate command
 * does not approach this bound, and failing closed here costs ~no false
 * positives — while the previous "stop early and allow" cost a real bypass
 * (verified: 9 wrapped levels of `Write-Output "$( ... )"` around a system-area
 * write executed the write and was judged clean).
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
  // The DSR-013 read-only exceptions apply only when this command cannot write:
  // `'modify'` (a write verb or a `>` redirect) uses the strict reference set, so
  // `Set-Content ~/.ssh/config x` stays blocked while `Get-Content` passes. The
  // `'unknown'` class is fail-closed and therefore also gets the strict set.
  const credReference = contentClass === 'read' || contentClass === 'list'
    ? CRED_TEXT_REFERENCE
    : CRED_TEXT_REFERENCE_STRICT
  if (leafEnabled(rules.credentials, contentClass) && credReference.test(cited)) {
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
  const nested = tokenizePwsh(resolved).nested
  if (depth >= MAX_SUBEXPRESSION_DEPTH) {
    // Fail CLOSED at the work bound. Stopping early is only safe if the passes
    // above are guaranteed to have seen whatever the un-expanded nesting hides —
    // and that guarantee does NOT hold. The text-reference and destructive passes
    // do scan the whole string, but the system-write pass (and any other
    // fragment+path pass) resolves a *parsed* write target, and at depth >= 1 the
    // top-level fragment is just `writeoutput`. Measured consequence of the old
    // "return undefined" here: `Write-Output "$( ... )"` nested 9 deep around a
    // system-area write was ALLOWED, and PowerShell really does execute it.
    // Nesting depth is chosen by the author of the command, so a deeper nest must
    // not be a way to be judged clean.
    //
    // Gated by `unverifiable` (DSR-006: every defense layer stays configurable).
    // It is the same semantic as that gate — "this cannot be verified statically,
    // so refuse" — and reusing the key avoids adding config surface that would
    // then need its own schema, settings card and tests. Turning `unverifiable`
    // off therefore also accepts this risk, which is the profile owner's call.
    if (rules.unverifiable && nested.length > 0) {
      return unverifiableReason(
        `the command nests subexpressions deeper than the ${MAX_SUBEXPRESSION_DEPTH}-level analysis bound`,
        command,
      )
    }
    return undefined
  }
  for (const inner of nested) {
    const nestedHit = checkCommand(base, inner, rules, depth + 1)
    if (nestedHit) return nestedHit
  }
  return undefined
}
