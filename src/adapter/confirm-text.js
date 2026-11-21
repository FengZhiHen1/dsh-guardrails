// confirm-text — human, single-paragraph confirmation copy for the shared card.
//
// The shared approval card renders one plain paragraph and does not support
// Markdown or line breaks. The technical `verdict.scope` string uses internal
// field names (`non-exempt entries`, `entries`, `directories`, `roots`,
// `unobserved`, flags…); this adapter-only module turns it into a short,
// semicolon-separated human sentence (en + zh) without dropping information.
//
// Rules: parse `; ` segments shaped `key: value`; keep unknown keys in an
// "other" clause; fall back to the raw scope text when parsing fails; never
// throw; truncate long lists (not the whole paragraph) while keeping the
// "and N total" count. Purely presentational — it never changes a decision.

const LIST_KEYS = new Set([
  'entries', 'files', 'links', 'directories', 'roots', 'known scope', 'unknown',
  'unobserved', 'protected files', 'identities', 'failed checks', 'non-exempt entries',
])

const ZH_KEY = {
  'non-exempt entries': '非豁免条目',
  'entries': '目标',
  'files': '文件',
  'links': '链接',
  'directories': '目录',
  'roots': '根目录',
  'known scope': '已知范围',
  'unknown': '未观察',
  'unobserved': '未观察',
  'notes': '说明',
  'identities': '身份',
  'protected files': '受保护文件',
  'failed checks': '失败检查',
}

const EN_KEY = {
  'non-exempt entries': 'non-exempt entries',
  'entries': 'targets',
  'files': 'files',
  'links': 'links',
  'directories': 'directories',
  'roots': 'roots',
  'known scope': 'known scope',
  'unknown': 'unobserved',
  'unobserved': 'unobserved',
  'notes': 'notes',
  'identities': 'identities',
  'protected files': 'protected files',
  'failed checks': 'failed checks',
}

const ACTION_ZH = {
  'read-content': '读取内容',
  'copy-content': '复制内容',
  'write-content': '写入内容',
  'truncate-content': '清空内容',
  'delete': '删除',
  'move-source': '移动',
  'metadata': '查看元数据',
  'git-clean': 'Git 清理',
  'git-restore': 'Git 恢复',
  'git-worktree-remove': '移除工作树',
}

/** Parse a technical scope string into keyed segments; continuation text after a
 * list key rejoins that key's value (so `entries: a; b; c` stays one list). */
function parseScopeSegments(text) {
  if (typeof text !== 'string' || text.trim() === '') return { ok: false, segments: [] }
  const segments = []
  for (const part of text.split('; ')) {
    const match = /^([A-Za-z][A-Za-z0-9 _-]*):\s*(.*)$/.exec(part)
    if (match) {
      segments.push({ key: match[1].trim().toLowerCase(), label: match[1].trim(), value: match[2].trim() })
      continue
    }
    const previous = segments[segments.length - 1]
    if (previous && LIST_KEYS.has(previous.key)) {
      previous.value = previous.value ? `${previous.value}; ${part.trim()}` : part.trim()
    } else {
      segments.push({ key: '', label: '', value: part.trim() })
    }
  }
  return { ok: segments.some((segment) => segment.key !== ''), segments }
}

const splitList = value => String(value ?? '').split('; ').map((entry) => entry.trim()).filter(Boolean)

function unique(items) {
  const out = []
  for (const item of items) if (item && !out.includes(item)) out.push(item)
  return out
}

function countZh(value) {
  const text = String(value ?? '').trim()
  const atLeast = /at least\s+(\d+)/i.exec(text)
  if (atLeast) return `至少 ${atLeast[1]}`
  const leading = /^\d+/.exec(text)
  return leading ? leading[0] : (text || '若干')
}

function countEn(value) {
  const text = String(value ?? '').trim()
  const atLeast = /at least\s+(\d+)/i.exec(text)
  if (atLeast) return `at least ${atLeast[1]}`
  const leading = /^\d+/.exec(text)
  return leading ? leading[0] : (text || 'some')
}

/** English singular/plural for the entry noun based on the leading count. */
function entryWordEn(value) {
  const text = String(value ?? '').trim()
  const atLeast = /at least\s+(\d+)/i.exec(text)
  const leading = /^\d+/.exec(text)
  const number = atLeast ? atLeast[1] : (leading ? leading[0] : undefined)
  return number === '1' ? 'entry' : 'entries'
}

function formatZhList(items, max) {
  const list = unique(items)
  if (list.length === 0) return ''
  if (list.length <= max) return list.join('、')
  return `${list.slice(0, max).join('、')} 等共 ${list.length} 项`
}

function formatEnList(items, max) {
  const list = unique(items)
  if (list.length === 0) return ''
  if (list.length <= max) return list.join(', ')
  return `${list.slice(0, max).join(', ')}, and ${list.length} total`
}

/** Extract the `.git` path from an unobserved "would also be destroyed" note. */
function gitDestroyPath(value) {
  if (typeof value !== 'string' || !/\.git|git metadata/i.test(value)) return ''
  const cleaned = value.replace(/\s*would also be destroyed.*$/i, '').trim()
  const at = /\bat\s+(.+)$/i.exec(cleaned)
  if (at) return at[1].trim()
  const parenthesized = /\(([^)]*)\)/.exec(value)
  return parenthesized ? parenthesized[1] : ''
}

/** Drop the English boilerplate but keep meaning for a non-git unobserved note. */
function unobservedZh(value) {
  return String(value)
    .replace(/\s*would also be destroyed\s*/i, ' ')
    .replace(/\bgit metadata\b/gi, 'Git 元数据')
    .replace(/^(.+?)\s+at\s+(.+)$/i, '$1（$2）')
    .trim()
}

/** Translate known action tokens inside parentheses for Chinese display. */
function translateActionsZh(value) {
  return String(value).replace(/\s*\(([a-z][a-z-]*)\)/g, (match, action) => (
    ACTION_ZH[action] ? `（${ACTION_ZH[action]}）` : match
  ))
}

function humanScopeZh(segments) {
  const parts = []
  for (const segment of segments) {
    if (!segment.key) {
      if (segment.value) parts.push(segment.value)
      continue
    }
    const label = ZH_KEY[segment.key] ?? segment.label ?? segment.key
    const value = translateActionsZh(segment.value)
    if (value) parts.push(`${label}：${value}`)
  }
  return parts.join('；')
}

function humanScopeEn(segments) {
  const parts = []
  for (const segment of segments) {
    if (!segment.key) {
      if (segment.value) parts.push(segment.value)
      continue
    }
    const label = EN_KEY[segment.key] ?? segment.label ?? segment.key
    const value = String(segment.value).replace(/\s*would also be destroyed\s*/i, ' ').trim()
    if (value) parts.push(`${label}: ${value}`)
  }
  return parts.join('; ')
}

function deleteClauses(segments) {
  let countRaw = ''
  let gitPath = ''
  const targets = []
  const dirs = []
  const rawFlags = []
  const other = []
  for (const segment of segments) {
    if (!segment.key) {
      if (segment.value) rawFlags.push(segment.value)
      continue
    }
    switch (segment.key) {
      case 'non-exempt entries':
        countRaw = segment.value
        break
      case 'entries':
      case 'files':
      case 'links':
      case 'known scope':
        targets.push(...splitList(segment.value))
        break
      case 'directories':
      case 'roots':
        // roots and directories that repeat each other are de-duplicated in display.
        dirs.push(...splitList(segment.value))
        break
      case 'unobserved':
      case 'unknown':
        for (const item of splitList(segment.value)) {
          const path = gitDestroyPath(item)
          if (path && !gitPath) gitPath = path
          else rawFlags.push(unobservedZh(item))
        }
        break
      case 'notes':
        rawFlags.push(...splitList(segment.value))
        break
      default:
        other.push(`${segment.label || segment.key}: ${segment.value}`)
    }
  }
  // Known flag: `git-metadata-inside-tree` is redundant when the .git destruction
  // note already covers it; otherwise it becomes a human "includes Git metadata".
  let includesGitMetadata = false
  const flags = []
  for (const flag of rawFlags) {
    if (flag === 'git-metadata-inside-tree') {
      if (gitPath) continue
      includesGitMetadata = true
      continue
    }
    flags.push(flag)
  }
  return { countRaw, gitPath, includesGitMetadata, targets, dirs, flags, other }
}

function renderDeleteZh(segments, ruleIds, limits) {
  const { countRaw, gitPath, includesGitMetadata, targets, dirs, flags, other } = deleteClauses(segments)
  const head = `删除 ${countZh(countRaw)} 个条目（规则 ${ruleIds.join(',')}）`
  const clauses = []
  const shownTargets = formatZhList(targets, limits.targets)
  if (shownTargets) clauses.push(`目标：${shownTargets}`)
  const shownDirs = formatZhList(dirs, limits.dirs)
  if (shownDirs) clauses.push(`涉及目录：${shownDirs}`)
  if (gitPath) clauses.push(`另将销毁：.git 元数据（${gitPath}）`)
  if (includesGitMetadata) clauses.push('范围内含 Git 元数据')
  const shownFlags = formatZhList(flags, limits.flags)
  if (shownFlags) clauses.push(`其他标记：${shownFlags}`)
  const shownOther = formatZhList(other, limits.other)
  if (shownOther) clauses.push(`其他：${shownOther}`)
  const tail = clauses.length > 0 ? `${head}。${clauses.join('；')}` : head
  return `需要确认（仅本次）：${tail}。批准只对本次调用有效。`
}

function renderDeleteEn(segments, ruleIds, limits) {
  const { countRaw, gitPath, includesGitMetadata, targets, dirs, flags, other } = deleteClauses(segments)
  const head = `delete ${countEn(countRaw)} ${entryWordEn(countRaw)} (rule ${ruleIds.join(',')})`
  const clauses = []
  const shownTargets = formatEnList(targets, limits.targets)
  if (shownTargets) clauses.push(`Targets: ${shownTargets}`)
  const shownDirs = formatEnList(dirs, limits.dirs)
  if (shownDirs) clauses.push(`directories: ${shownDirs}`)
  if (gitPath) clauses.push(`also destroys: Git metadata (${gitPath})`)
  if (includesGitMetadata) clauses.push('also includes Git metadata')
  const shownFlags = formatEnList(flags, limits.flags)
  if (shownFlags) clauses.push(`other flags: ${shownFlags}`)
  const shownOther = formatEnList(other, limits.other)
  if (shownOther) clauses.push(`other: ${shownOther}`)
  const tail = clauses.length > 0 ? `${head}. ${clauses.join('; ')}` : head
  return `Confirmation required (this call only): ${tail}. The approval applies to this call only.`
}

const LIMIT_START = { targets: 6, dirs: 3, flags: 6, other: 4 }
const MAX_LENGTH = 600

/** Build with shrinking list caps until it fits, then hard-cap as a last resort. */
function renderLimited(render, segments, ruleIds) {
  let limits = { ...LIMIT_START }
  let out = render(segments, ruleIds, limits)
  while (out.length > MAX_LENGTH &&
    (limits.targets > 1 || limits.dirs > 1 || limits.flags > 1 || limits.other > 0)) {
    limits = {
      targets: Math.max(1, limits.targets - 1),
      dirs: Math.max(1, limits.dirs - 1),
      flags: Math.max(1, limits.flags - 1),
      other: Math.max(0, limits.other - 1),
    }
    out = render(segments, ruleIds, limits)
  }
  return out.length > MAX_LENGTH ? `${out.slice(0, MAX_LENGTH)}…` : out
}

const DELETE_PREFIXES = ['data.delete.', 'data.git.', 'data.move.']

/**
 * Human single-paragraph confirmation copy for one verdict scope.
 * @returns {{ en: string, zh: string }} never throws, never empty.
 */
export function confirmSummary(scopeText, ruleIds) {
  const ids = Array.isArray(ruleIds) ? ruleIds.map(String).filter(Boolean) : []
  const raw = typeof scopeText === 'string' ? scopeText.trim() : ''
  const parsed = parseScopeSegments(raw)
  if (!parsed.ok) {
    // Unparseable scope: keep the raw text as one paragraph, never undefined.
    const human = raw || '该操作'
    const humanEn = raw || 'this operation'
    return {
      zh: `需要确认（仅本次）：${human}（规则 ${ids.join(',')}）。批准只对本次调用有效。`,
      en: `Confirmation required (this call only): ${humanEn} (rule ${ids.join(',')}). The approval applies to this call only.`,
    }
  }
  const isDelete = ids.some((id) => DELETE_PREFIXES.some((prefix) => id.startsWith(prefix)))
  if (isDelete) {
    const zh = renderLimited(renderDeleteZh, parsed.segments, ids)
    const en = renderLimited(renderDeleteEn, parsed.segments, ids)
    return { zh, en }
  }
  const zhScope = humanScopeZh(parsed.segments)
  const enScope = humanScopeEn(parsed.segments)
  return {
    zh: `需要确认（仅本次）：${zhScope || raw || '该操作'}（规则 ${ids.join(',')}）。批准只对本次调用有效。`,
    en: `Confirmation required (this call only): ${enScope || raw || 'this operation'} (rule ${ids.join(',')}). The approval applies to this call only.`,
  }
}
