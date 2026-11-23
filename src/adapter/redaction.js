// Cordis post-decision composition and the independent PTC durable-log copy.
// A projection is masked in place only when it can be masked safely; any other
// value, meta, error text, or context that may carry a credential is withheld.

import { redactContent, redactText } from '../core/redaction.js'

// Bounded traversal: hostile or unexpectedly large values cannot stall the hook.
const MAX_DEPTH = 32
const MAX_ARRAY_ITEMS = 65536
const MAX_OBJECT_KEYS = 65536
const MAX_STRING_LENGTH = 8 * 1024 * 1024
const WITHHELD = '[Guardrails] This result was withheld: it contained a recognizable credential that could not be masked without breaking the tool output schema.'
const WITHHELD_ERROR = '[Guardrails] This error result was withheld: it contained a recognizable credential.'
const WITHHELD_CONTEXT = '[Guardrails] This result was withheld: its attached context could not be proven free of credentials.'
const LOG_WITHHELD_TEXT = '[Guardrails] log content withheld'
const LOG_BLOCK_TYPES = new Set(['text', 'reasoning', 'image', 'file', 'tool-call', 'tool-addition', 'tool-removal'])
const REDACTED_INFO = { name: 'Guardrails', code: 'REDACTED' }

function plainStringSchema(schema) {
  if (schema?.type !== 'string') return false
  // Only annotations may accompany type: no enum, const, composition, or constraints.
  return Object.keys(schema).every(key => ['type', 'description', 'title', 'default', 'examples'].includes(key))
}

/** Check one in-place string replacement, calling each projector exactly once. */
function safeStringReplacement(tool, exec, value) {
  if (!plainStringSchema(tool?.output?.schema)) return false
  if (tool.projectContent || tool.finalizeContent) return false
  try {
    const rendered = tool.output.render(exec.arguments, value)
    if (!Array.isArray(rendered) || rendered.some(block => block?.type !== 'text' || typeof block.text !== 'string')) return false
    if (unsafe(rendered)) return false
    if (typeof tool.output.presentationMeta === 'function') {
      if (scan(tool.output.presentationMeta(exec.arguments, value)) !== 'clean') return false
    }
    return true
  } catch (error) {
    // A replacement rejected by a tool projector is unsupported; retain its value.
    // Never forward a projector error message, which may itself contain a secret.
    return false
  }
}

/** A candidate projection's meta must be clean under the same tri-state scan. */
function candidateMetaSafe(tool, exec, value) {
  if (typeof tool?.output?.presentationMeta !== 'function') return true
  try {
    return scan(tool.output.presentationMeta(exec.arguments, value)) === 'clean'
  } catch (error) {
    return false
  }
}

function plainObject(value) {
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

/** Tri-state bounded scan: 'hit' redacts, 'clean' is safe, 'unknown' is unsafe.
 * Depth, size, and non-JSON object kinds cannot be proven clean, so they withhold.
 */
function containsMaskable(value, depth, seen) {
  if (typeof value === 'string') {
    if (value.length > MAX_STRING_LENGTH) return 'unknown'
    return redactText(value).changed ? 'hit' : 'clean'
  }
  if (value === undefined || value === null) return 'clean'
  if (typeof value === 'number' || typeof value === 'boolean') return 'clean'
  if (typeof value !== 'object') return 'unknown'
  // A value already reached at a shallower depth was fully scanned there.
  if (seen.has(value)) return 'clean'
  if (depth >= MAX_DEPTH) return 'unknown'
  seen.add(value)
  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY_ITEMS) return 'unknown'
    let result = 'clean'
    for (let index = 0; index < value.length; index++) {
      const found = containsMaskable(value[index], depth + 1, seen)
      if (found === 'hit') return 'hit'
      if (found === 'unknown') result = 'unknown'
    }
    return result
  }
  if (!plainObject(value)) return 'unknown'
  const keys = Object.keys(value)
  if (keys.length > MAX_OBJECT_KEYS) return 'unknown'
  let result = 'clean'
  for (const key of keys) {
    const found = containsMaskable(value[key], depth + 1, seen)
    if (found === 'hit') return 'hit'
    if (found === 'unknown') result = 'unknown'
  }
  return result
}

function scan(value) {
  return containsMaskable(value, 0, new Set())
}

function unsafe(value) {
  return scan(value) !== 'clean'
}

/** Replace the whole result with a fixed explanation; the raw value is never echoed. */
function withheldDecision(text) {
  return { kind: 'block', feedback: [{ type: 'text', text }] }
}

/** Mask a content projection, or report it unprovable so the caller can withhold. */
function maskContent(content) {
  let masked
  try {
    masked = redactContent(content)
  } catch (error) {
    return undefined
  }
  return unsafe(masked) ? undefined : masked
}

/** Result contexts are merged by the runtime and cannot be replaced, so any
 * non-clean message (including source/summary or non-text blocks) withholds.
 */
function resultContextsSafe(result) {
  const contexts = result.additionalContexts
  if (contexts === undefined) return true
  if (!Array.isArray(contexts)) return false
  return scan(contexts) === 'clean'
}

/** Keep clean context messages; drop any message that cannot be proven clean. */
function safeContexts(decision) {
  if (!Object.hasOwn(decision, 'additionalContexts')) return decision
  const contexts = decision.additionalContexts
  if (!Array.isArray(contexts)) return { ...decision, additionalContexts: [] }
  let changed = false
  const kept = []
  for (const message of contexts) {
    if (scan(message) !== 'clean') {
      changed = true
      continue
    }
    kept.push(message)
  }
  return changed ? { ...decision, additionalContexts: kept } : decision
}

function logWithheldBlock() {
  return { type: 'text', text: LOG_WITHHELD_TEXT }
}

/** Redact every string in one log node. Any non-JSON value, cycle, or bound
 * makes the whole block unprovable; `undefined` means "replace with placeholder".
 */
function redactLogNode(value, depth, seen) {
  if (typeof value === 'string') {
    if (value.length > MAX_STRING_LENGTH) return undefined
    const redacted = redactText(value)
    return redacted.changed ? { value: redacted.text, changed: true } : { value, changed: false }
  }
  if (value === null) return { value, changed: false }
  if (typeof value === 'number') return Number.isFinite(value) ? { value, changed: false } : undefined
  if (typeof value === 'boolean') return { value, changed: false }
  if (typeof value !== 'object') return undefined
  if (seen.has(value)) return undefined
  if (depth >= MAX_DEPTH) return undefined
  seen.add(value)
  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY_ITEMS) return undefined
    const clone = new Array(value.length)
    let changed = false
    for (let index = 0; index < value.length; index++) {
      const item = redactLogNode(value[index], depth + 1, seen)
      if (item === undefined) return undefined
      clone[index] = item.value
      changed = changed || item.changed
    }
    seen.delete(value)
    return { value: changed ? clone : value, changed }
  }
  if (!plainObject(value)) return undefined
  const keys = Object.keys(value)
  if (keys.length > MAX_OBJECT_KEYS) return undefined
  const clone = Object.getPrototypeOf(value) === null ? Object.create(null) : {}
  let changed = false
  for (const key of keys) {
    const item = redactLogNode(value[key], depth + 1, seen)
    if (item === undefined) return undefined
    clone[key] = item.value
    changed = changed || item.changed
  }
  seen.delete(value)
  return { value: changed ? clone : value, changed }
}

/** Mask one log block; unknown block kinds and unprovable shapes become a placeholder. */
function redactLogBlock(block) {
  try {
    if (!block || typeof block !== 'object' || Array.isArray(block)) return logWithheldBlock()
    if (typeof block.type !== 'string' || !LOG_BLOCK_TYPES.has(block.type)) return logWithheldBlock()
    const redacted = redactLogNode(block, 0, new Set())
    return redacted === undefined ? logWithheldBlock() : redacted.value
  } catch (error) {
    return logWithheldBlock()
  }
}

/** Deep-mask a durable PTC log projection; the contract requires a ContentBlock[]. */
function redactLogContent(content) {
  if (!Array.isArray(content)) return [logWithheldBlock()]
  try {
    return content.map(redactLogBlock)
  } catch (error) {
    return [logWithheldBlock()]
  }
}

/** Mask a value in place only under a schema the mask still satisfies; else withhold it.
 * The tool resolver is lazy: unchanged values never touch the registry.
 */
function resolveValue(decision, value, exec, executable) {
  if (typeof value === 'string') {
    const replacement = redactText(value)
    if (!replacement.changed) return decision
    return safeStringReplacement(executable(), exec, replacement.text)
      ? { ...decision, value: replacement.text }
      : withheldDecision(WITHHELD)
  }
  return scan(value) === 'clean' ? decision : withheldDecision(WITHHELD)
}

/** Install effect-owned post-result and PTC log masking; return the exact disposer. */
export function installRedaction(ctx) {
  return ctx.effect(() => {
    const post = ctx.on('tools/post-execute', async (exec, result, next) => {
      const decision = await next()
      const executable = () => ctx.tools.executable(exec.name, exec.agent, exec.toolSet)

      // Another hook's block decision becomes the error result: only its own
      // feedback, info, and contexts can leak.
      if (decision.kind === 'block') {
        let resolved = decision
        const feedback = maskContent(decision.feedback)
        if (feedback === undefined) resolved = { ...resolved, feedback: [{ type: 'text', text: WITHHELD }] }
        else if (feedback !== decision.feedback) resolved = { ...resolved, feedback }
        if (resolved.info !== undefined && unsafe(resolved.info)) resolved = { ...resolved, info: REDACTED_INFO }
        return safeContexts(resolved)
      }

      // Tool-supplied contexts are merged into the final result and cannot be
      // replaced through a post-execute decision, so anything unprovable withholds.
      if (!resultContextsSafe(result)) return withheldDecision(WITHHELD_CONTEXT)

      // A failed result keeps its error text durably (PTC and UI), so unsafe error
      // text or info withholds the whole result instead of rewriting the error.
      if (result.isError) {
        if (unsafe(result.error?.message) || unsafe(result.error?.info) || unsafe(result.meta)) {
          return withheldDecision(WITHHELD_ERROR)
        }
        // Defense in depth: a failed result must never carry a credential-bearing
        // value. The current runtime rejects such a replacement, but an upstream
        // hook or a future runtime must not be able to leak it.
        if (Object.hasOwn(result, 'value') && unsafe(result.value)) return withheldDecision(WITHHELD_ERROR)
        if (Object.hasOwn(decision, 'value') && unsafe(decision.value)) return withheldDecision(WITHHELD_ERROR)
        if (Object.hasOwn(decision, 'value')) {
          // A clean replacement is left to the runtime, which currently rejects it.
          return decision
        }
        const source = Object.hasOwn(decision, 'content') ? decision.content : result.content
        const masked = maskContent(source)
        if (masked === undefined) return withheldDecision(WITHHELD_ERROR)
        return safeContexts(masked === source ? decision : { ...decision, content: masked })
      }

      if (Object.hasOwn(decision, 'value')) {
        const resolved = resolveValue(decision, decision.value, exec, executable)
        if (resolved !== decision) return resolved
        // The runtime re-derives the projection from this value, so its candidate
        // meta must also be provably clean before the value is accepted as-is.
        if (!candidateMetaSafe(executable(), exec, decision.value)) return withheldDecision(WITHHELD)
        return safeContexts(decision)
      }

      // A content-only replacement still exposes result.value to PTC programs.
      if (Object.hasOwn(decision, 'content')) {
        if (unsafe(decision.value) || unsafe(result.value) || unsafe(result.meta)) {
          return withheldDecision(WITHHELD)
        }
        const masked = maskContent(decision.content)
        if (masked === undefined) return withheldDecision(WITHHELD)
        return safeContexts(masked === decision.content ? decision : { ...decision, content: masked })
      }

      const resolved = resolveValue(decision, result.value, exec, executable)
      if (resolved !== decision) return resolved
      if (unsafe(result.meta)) return withheldDecision(WITHHELD)
      const masked = maskContent(result.content)
      if (masked === undefined) return withheldDecision(WITHHELD)
      return safeContexts(masked === result.content ? decision : { ...decision, content: masked })
    }, { prepend: true })
    const log = ctx.on('tools/ptc-dispatch-log', async (_dispatch, next) => {
      let content
      try {
        content = await next()
      } catch (error) {
        // The runtime otherwise falls back to logging the original content.
        return [logWithheldBlock()]
      }
      return redactLogContent(content)
    }, { prepend: true })
    return () => { log(); post() }
  })
}
