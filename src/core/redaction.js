// Local credential recognition and corrective inline-use decisions.
// Only recognizable credential formats are masked; opaque entropy is not evidence.

const MARKER = '[REDACTED]'
const PLACEHOLDER = /^(?:your[-_]?|example|sample|placeholder|dummy|test[-_]?|replace|insert|redacted|x{6,}|0{6,})/i
const PROVIDER = /\b(?:sk-(?:(?:proj|ant-api\d+)-)?[A-Za-z0-9_-]{32,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{24,}|AIza[A-Za-z0-9_-]{35}|npm_[A-Za-z0-9]{36,})\b/g
const BEARER = /\bBearer[ \t]+([A-Za-z0-9._~+/-]{20,}={0,2})(?![A-Za-z0-9._~+/-])/gi
const JWT = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{16,}$/
function maskPem(text, kinds) {
  const markers = /-----(BEGIN|END) ((?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----/g
  const parts = []
  let cursor = 0
  let start
  // Each marker and each candidate body is visited once, even for malformed input.
  for (const marker of text.matchAll(markers)) {
    if (marker[1] === 'BEGIN') {
      start = marker
      continue
    }
    if (!start || start[2] !== marker[2]) continue
    const body = text.slice(start.index + start[0].length, marker.index).replace(/\s/g, '')
    if (body.length >= 32 && /^[A-Za-z0-9+/=]+$/.test(body)) {
      parts.push(text.slice(cursor, start.index), MARKER)
      cursor = marker.index + marker[0].length
      kinds.add('pem')
    }
    start = undefined
  }
  return parts.length ? parts.join('') + text.slice(cursor) : text
}

function placeholder(value) {
  return PLACEHOLDER.test(value) || /(?:example|placeholder|your[_-]?(?:api[_-]?)?(?:key|token))/i.test(value)
}

function jwtCredential(value) {
  try {
    const [header, payload] = value.split('.')
    const decodedHeader = JSON.parse(Buffer.from(header, 'base64url').toString('utf8'))
    const decodedPayload = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))
    return decodedHeader !== null && typeof decodedHeader === 'object'
      && typeof decodedHeader.alg === 'string' && decodedHeader.alg !== 'none'
      && decodedPayload !== null && typeof decodedPayload === 'object' && !Array.isArray(decodedPayload)
  } catch (error) {
    if (error instanceof SyntaxError) return false
    throw error
  }
}

/** Mask recognized credential spans, retaining no prefix or suffix.
 * @throws {TypeError} If input is not text.
 */
export function redactText(text) {
  if (typeof text !== 'string') throw new TypeError('redactText requires a string')
  const uncolored = text.replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
  if (uncolored !== text) {
    const redacted = redactText(uncolored)
    if (redacted.changed) return redacted
  }
  const kinds = new Set()
  const replace = (kind, accepted = () => true) => value => {
    if (placeholder(value) || !accepted(value)) return value
    kinds.add(kind)
    return MARKER
  }
  // Each recognizer scans the finite input once; no truncation can expose a tail.
  let output = maskPem(text, kinds)
  output = output.replace(BEARER, (whole, token) => {
    if (placeholder(token)) return whole
    kinds.add('bearer')
    return `Bearer ${MARKER}`
  })
  output = output.replace(/[A-Za-z0-9_.-]+/g, value => JWT.test(value) ? replace('jwt', jwtCredential)(value) : value)
  output = output.replace(PROVIDER, replace('provider', value => {
    const body = value.replace(/^(?:sk-(?:(?:proj|ant-api\d+)-)?|gh[pousr]_|github_pat_|glpat-|xox[baprs]-|AIza|npm_)/, '')
    return !placeholder(body)
  }))
  return { text: output, changed: output !== text, kinds: [...kinds] }
}

/** Replace text blocks while preserving other blocks and fields.
 * @throws {TypeError} If input is not an array of content blocks.
 */
export function redactContent(content) {
  if (!Array.isArray(content)) throw new TypeError('redactContent requires content blocks')
  let changed = false
  const blocks = content.map(block => {
    if (block?.type !== 'text' || typeof block.text !== 'string') return block
    const redacted = redactText(block.text)
    if (!redacted.changed) return block
    changed = true
    return { ...block, text: redacted.text }
  })
  return changed ? blocks : content
}

/** Deny credential literals used in an execution or transmission command AST. */
export function inlineCredentialDecision(commands) {
  if (!Array.isArray(commands)) return undefined
  for (const command of commands) {
    const name = String(command?.name ?? '').replace(/^.*[\\/]/, '').replace(/\.exe$/i, '').toLowerCase()
    if (!/^(?:curl|wget|invoke-restmethod|invoke-webrequest|irm|iwr|ssh|scp|docker|npm|pnpm|gh|git)$/.test(name)) continue
    const args = command.args ?? []
    if (!Array.isArray(args)) continue
    if (name === 'git' && !args.some(value => typeof value === 'string' && /^(?:clone|fetch|push|pull|ls-remote|remote)$/.test(value))) continue
    if (/^(?:docker|npm|pnpm|gh)$/.test(name) && !args.some(value => typeof value === 'string' && /^(?:login|auth|token|publish|api|--password|--password=|--auth-token)(?:.*)?$/.test(value))) continue
    for (const value of args) {
      if (typeof value !== 'string' || !redactText(value).changed) continue
      return {
        kind: 'deny', ruleId: 'R-M2',
        reason: '[guardrails:R-M2] Inline credential would spread through command arguments and persisted tool input. Use a credential reference, environment variable, stdin, or the tool’s authenticated configuration instead; retry without the literal credential.',
      }
    }
  }
  return undefined
}
