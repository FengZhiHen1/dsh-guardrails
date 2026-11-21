// Cordis post-decision composition and the independent PTC durable-log copy.
// A value is masked in place only when its tool schema accepts the mask; otherwise
// the result is withheld, so no raw credential and no invalid-output echo reaches the model.

import { redactContent, redactText } from '../core/redaction.js'

// Bounded traversal: hostile or unexpectedly large values cannot stall the hook.
const MAX_DEPTH = 8
const MAX_ARRAY_ITEMS = 1024
const MAX_OBJECT_KEYS = 1024
const MAX_STRING_LENGTH = 1024 * 1024
const WITHHELD = '[Guardrails] This result was withheld: it contained a recognizable credential that could not be masked without breaking the tool output schema.'

function plainStringSchema(schema) {
  if (schema?.type !== 'string') return false
  // Only annotations may accompany type: no enum, const, composition, or constraints.
  return Object.keys(schema).every(key => ['type', 'description', 'title', 'default', 'examples'].includes(key))
}

function safeStringProjection(tool, exec, value) {
  if (!plainStringSchema(tool?.output?.schema)) return false
  if (tool.projectContent || tool.finalizeContent) return false
  try {
    const rendered = tool.output.render(exec.arguments, value)
    if (!Array.isArray(rendered) || rendered.some(block => block?.type !== 'text' || typeof block.text !== 'string')) return false
    if (redactContent(rendered) !== rendered) return false
    if (tool.output.presentationMeta) {
      const meta = tool.output.presentationMeta(exec.arguments, value)
      if (redactText(JSON.stringify(meta) ?? '').changed) return false
    }
    return true
  } catch (error) {
    // A replacement rejected by a tool projector is unsupported; retain its value.
    // Never forward a projector error message, which may itself contain a secret.
    return false
  }
}

function plainObject(value) {
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

/** Report whether a bounded scan finds any string that would be redacted.
 * Portions beyond a bound are unscanned; a hit inside the bounds still withholds.
 */
function containsMaskable(value, depth, seen) {
  if (typeof value === 'string') {
    return value.length <= MAX_STRING_LENGTH && redactText(value).changed
  }
  if (value === null || typeof value !== 'object') return false
  if (depth >= MAX_DEPTH) return false
  if (seen.has(value)) return false
  seen.add(value)
  if (Array.isArray(value)) {
    const limit = Math.min(value.length, MAX_ARRAY_ITEMS)
    for (let index = 0; index < limit; index++) {
      if (containsMaskable(value[index], depth + 1, seen)) return true
    }
    return false
  }
  if (!plainObject(value)) return false
  const keys = Object.keys(value)
  const limit = Math.min(keys.length, MAX_OBJECT_KEYS)
  for (let index = 0; index < limit; index++) {
    if (containsMaskable(value[keys[index]], depth + 1, seen)) return true
  }
  return false
}

/** Replace the whole result with a fixed explanation; the raw value is never echoed. */
function withheldDecision() {
  return { kind: 'block', feedback: [{ type: 'text', text: WITHHELD }] }
}

/** Mask a value in place only under a schema the mask still satisfies; else withhold it.
 * The tool resolver is lazy: unchanged values never touch the registry.
 */
function resolveValue(decision, value, exec, executable) {
  if (typeof value === 'string') {
    const replacement = redactText(value)
    if (!replacement.changed) return decision
    return safeStringProjection(executable(), exec, replacement.text)
      ? { ...decision, value: replacement.text }
      : withheldDecision()
  }
  return containsMaskable(value, 0, new Set()) ? withheldDecision() : decision
}

/** Install effect-owned post-result and PTC log masking; return the exact disposer. */
export function installRedaction(ctx) {
  return ctx.effect(() => {
    const post = ctx.on('tools/post-execute', async (exec, result, next) => {
      const decision = await next()
      const executable = () => ctx.tools.executable(exec.name, exec.agent, exec.toolSet)
      if (decision.kind === 'block') {
        const feedback = redactContent(decision.feedback)
        return feedback === decision.feedback ? decision : { ...decision, feedback }
      }
      if (Object.hasOwn(decision, 'value')) {
        // A failed call keeps its current value contract unchanged (known residual).
        if (result.isError) return decision
        return resolveValue(decision, decision.value, exec, executable)
      }
      if (Object.hasOwn(decision, 'content')) {
        const content = redactContent(decision.content)
        return content === decision.content ? decision : { ...decision, content }
      }
      if (!result.isError) {
        const resolved = resolveValue(decision, result.value, exec, executable)
        if (resolved !== decision) return resolved
      }
      const content = redactContent(result.content)
      return content === result.content ? decision : { ...decision, content }
    }, { prepend: true })
    const log = ctx.on('tools/ptc-dispatch-log', async (_dispatch, next) => redactContent(await next()), { prepend: true })
    return () => { log(); post() }
  })
}
