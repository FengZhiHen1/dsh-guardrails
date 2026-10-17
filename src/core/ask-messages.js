// ask-messages — the model-facing reason texts for pre-execute `ask` decisions.
//
// Boundary: pure string rendering, no imports; keep every template free of any
// file content — the reason names the action and the target path only, never
// reads or quotes the sensitive file (DSR-015).

/** Why the gate asked, as one word for the audit line. */
const HIT_LABEL = {
  credentials: '内置凭据名单',
  marked: '用户标记的敏感文件',
}

/**
 * Render the ask reason. The text is audited to the session log as part of the
 * approval/asked event, so it stays bounded and path-only.
 */
export function askMessage(hit, rawPath, toolName) {
  const target = String(rawPath).replace(/\s+/g, ' ').trim().slice(0, 200)
  return [
    `[guardrails] ${toolName} 的目标命中${HIT_LABEL[hit] ?? hit}：${target}`,
    '本次读取需要用户一次性批准（allow-once）；拒绝或不可用时不执行。',
  ].join('\n')
}

/**
 * Render the model-facing reason for a plugin-owned ask timeout (DSR-016).
 *
 * Bounded and path-only like the ask text: the timeout is a "nobody answered"
 * outcome, so the model must know it was an automatic refusal — not a human
 * "no" — and must not retry the same read in a loop.
 */
export function timeoutMessage(toolName, timeoutMs, hit) {
  const seconds = timeoutMs >= 1000 ? `${Math.round(timeoutMs / 100) / 10}s` : `${timeoutMs}ms`
  return [
    `[guardrails] ${toolName} 的审批在 ${seconds} 内无人处理，已自动拒绝（超时）；该调用未执行。`,
    `这是自动拒绝，不是用户拒绝——不要用同一参数反复重试；需要该内容时请让用户在场后重新发起（命中类别：${HIT_LABEL[hit] ?? hit}）。`,
  ].join('\n')
}

