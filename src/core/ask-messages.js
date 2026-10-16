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
