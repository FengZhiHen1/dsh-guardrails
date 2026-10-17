// Cordis post-decision composition and the independent PTC durable-log copy.
// Canonical object values, metadata, and structured failures retain their contracts.

import { redactContent, redactText } from '../core/redaction.js'

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

/** Install effect-owned post-result and PTC log masking; return the exact disposer. */
export function installRedaction(ctx) {
  return ctx.effect(() => {
    const post = ctx.on('tools/post-execute', async (exec, result, next) => {
      const decision = await next()
      if (decision.kind === 'block') {
        const feedback = redactContent(decision.feedback)
        return feedback === decision.feedback ? decision : { ...decision, feedback }
      }
      if (Object.hasOwn(decision, 'value')) {
        if (result.isError || typeof decision.value !== 'string') return decision
        const replacement = redactText(decision.value)
        if (!replacement.changed) return decision
        const tool = ctx.tools.get(exec.name, exec.agent)
        return safeStringProjection(tool, exec, replacement.text) ? { ...decision, value: replacement.text } : decision
      }
      if (Object.hasOwn(decision, 'content')) {
        const content = redactContent(decision.content)
        return content === decision.content ? decision : { ...decision, content }
      }
      if (!result.isError && typeof result.value === 'string') {
        const replacement = redactText(result.value)
        if (replacement.changed && safeStringProjection(ctx.tools.get(exec.name, exec.agent), exec, replacement.text)) {
          return { ...decision, value: replacement.text }
        }
      }
      const content = redactContent(result.content)
      return content === result.content ? decision : { ...decision, content }
    }, { prepend: true })
    const log = ctx.on('tools/ptc-dispatch-log', async (_dispatch, next) => redactContent(await next()), { prepend: true })
    return () => { log(); post() }
  })
}
