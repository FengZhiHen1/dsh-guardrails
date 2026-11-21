// confirm-text — human, single-paragraph confirmation copy for the shared card.
//
// The shared approval card renders one plain paragraph and does not support
// Markdown or line breaks. The technical `verdict.scope` string uses internal
// field names (`non-exempt entries`, `entries`, `directories`, `roots`,
// `unobserved`, flags…); this adapter-only module turns it into a short,
// semicolon-separated human sentence (en + zh) without leaking internal tokens.
//
// Rules: parse `; ` segments shaped `key: value`; keep unknown keys out of the
// user-facing summary (they stay in the audit reason); fall back to the raw scope
// text when parsing fails; never throw; truncate long lists (not the whole
// paragraph) while keeping the "and N total" count. Purely presentational — it
// never changes a decision.

const LIST_KEYS = new Set([
  'entries', 'files', 'links', 'directories', 'roots', 'known scope', 'unknown',
  'unobserved', 'protected files', 'identities', 'failed checks', 'non-exempt entries', 'notes',
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

const ACTION_EN = {
  'read-content': 'read',
  'copy-content': 'copy',
  'write-content': 'write',
  'truncate-content': 'truncate',
  'move-source': 'move',
  'metadata': 'inspect metadata',
  'git-clean': 'git clean',
  'git-restore': 'git restore',
  'git-worktree-remove': 'remove worktree',
}

/** Known scope notes translated for the card; unknown notes keep their raw text
 * but are labelled as original wording so a user can still tell what they are. */
const ZH_NOTE = {
  'unresolved dynamic operand; credential name referenced in text': '动态操作数无法解析；文本中出现凭据名',
  'recursion unproven for an otherwise known target': '已知目标未能证明递归范围',
  'a preceding write in the same call can change this target set before it executes': '同一次调用中前置写入可能改变目标集',
  'stdin stream': '标准输入流',
  'merge state / uncommitted changes': '合并状态 / 未提交改动',
}

/** Parse a technical scope string into keyed segments; continuation text after a
 * list key rejoins that key's value (so `entries: a; b; c` stays one list). A
 * Windows drive path (`C:\x` / `C:/x`) is ALWAYS a list continuation, never a
 * `key: value` pair, so the second and later Windows targets cannot be dropped. */
function parseScopeSegments(text) {
  if (typeof text !== 'string' || text.trim() === '') return { ok: false, segments: [] }
  const segments = []
  const appendContinuation = (part) => {
    const previous = segments[segments.length - 1]
    if (previous && LIST_KEYS.has(previous.key)) {
      previous.value = previous.value ? `${previous.value}; ${part}` : part
    } else {
      segments.push({ key: '', label: '', value: part })
    }
  }
  for (const part of text.split('; ')) {
    // A drive-letter path must never be read as `C:` key (H1).
    if (/^[A-Za-z]:[\\/]/.test(part)) {
      appendContinuation(part)
      continue
    }
    const match = /^([A-Za-z][A-Za-z0-9 _-]*):\s*(.*)$/.exec(part)
    if (match && !(match[1].length === 1 && /^[A-Za-z]$/.test(match[1]))) {
      segments.push({ key: match[1].trim().toLowerCase(), label: match[1].trim(), value: match[2].trim() })
      continue
    }
    appendContinuation(part)
  }
  return { ok: segments.some((segment) => segment.key !== ''), segments }
}

const splitList = value => String(value ?? '')
  .split('; ')
  .map((entry) => entry.trim())
  .filter((entry) => entry && entry !== '…' && entry !== '...')

function unique(items) {
  const out = []
  for (const item of items) if (item && !out.includes(item)) out.push(item)
  return out
}

/** The numeric total from a count value (`21` or `at least 21`), else undefined. */
function numericCount(countRaw) {
  const text = String(countRaw ?? '').trim()
  if (!text) return undefined
  const atLeast = /at least\s+(\d+)/i.exec(text)
  if (atLeast) return Number(atLeast[1])
  const leading = /^\d+/.exec(text)
  return leading ? Number(leading[0]) : undefined
}

/** Render a list. `totalOverride` (a real count) wins over the shown length so a
 * truncated `renderList` (`a; b; …`) still reports the true total, never the ellipsis. */
function formatZhList(items, max, totalOverride) {
  const list = unique(items)
  const total = Number.isFinite(totalOverride) && totalOverride > list.length ? totalOverride : list.length
  if (total === 0) return ''
  if (total === list.length && list.length <= max) return list.join('、')
  const shown = list.slice(0, max)
  return `${shown.join('、')}${shown.length > 0 ? ' ' : ''}等共 ${total} 项`
}

function formatEnList(items, max, totalOverride) {
  const list = unique(items)
  const total = Number.isFinite(totalOverride) && totalOverride > list.length ? totalOverride : list.length
  if (total === 0) return ''
  if (total === list.length && list.length <= max) return list.join(', ')
  const shown = list.slice(0, max)
  return `${shown.join(', ')}${shown.length > 0 ? ', ' : ''}and ${total} total`
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

/** Entry-count phrase for the dedicated move/worktree cards (empty when absent). */
function countPhraseZh(countRaw) {
  const text = String(countRaw ?? '').trim()
  if (!text) return ''
  const atLeast = /at least\s+(\d+)/i.exec(text)
  if (atLeast) return `至少 ${atLeast[1]} 个条目`
  const leading = /^\d+/.exec(text)
  return leading ? `${leading[0]} 个条目` : ''
}

function countPhraseEn(countRaw) {
  const text = String(countRaw ?? '').trim()
  if (!text) return ''
  const atLeast = /at least\s+(\d+)/i.exec(text)
  if (atLeast) return `at least ${atLeast[1]} entries`
  const leading = /^\d+/.exec(text)
  return leading ? `${leading[0]} ${entryWordEn(text)}` : ''
}

/** Chinese delete head without stray spaces: 若干 / 至少 N / N. */
function deleteHeadZh(countRaw) {
  const text = String(countRaw ?? '').trim()
  if (!text) return '将删除若干条目'
  const atLeast = /at least\s+(\d+)/i.exec(text)
  if (atLeast) return `将删除至少 ${atLeast[1]} 个条目`
  const leading = /^\d+/.exec(text)
  return leading ? `将删除 ${leading[0]} 个条目` : '将删除若干条目'
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

function translateActionsZh(value) {
  return String(value).replace(/\s*\(([a-z][a-z-]*)\)/g, (match, action) => (
    ACTION_ZH[action] ? `（${ACTION_ZH[action]}）` : match
  ))
}

function translateActionsEn(value) {
  return String(value).replace(/\s*\(([a-z][a-z-]*)\)/g, (match, action) => (
    ACTION_EN[action] ? ` (${ACTION_EN[action]})` : match
  ))
}

/** One note translated for Chinese display (known map first). */
function noteZhValue(note) {
  return ZH_NOTE[note] ?? ZH_NOTE[note.trim()] ?? undefined
}

/** Split a notes value into known notes using greedy longest matching, so a
 * compound known note (`a; b`) is never broken into two unknown fragments. */
function splitNotes(value) {
  const whole = String(value ?? '').trim()
  if (!whole) return []
  const parts = whole.split('; ').map((note) => note.trim()).filter(Boolean)
  const notes = []
  let index = 0
  while (index < parts.length) {
    let matched = false
    for (let end = parts.length; end > index; end -= 1) {
      const candidate = parts.slice(index, end).join('; ')
      if (noteZhValue(candidate)) {
        notes.push(candidate)
        index = end
        matched = true
        break
      }
    }
    if (!matched) {
      notes.push(parts[index])
      index += 1
    }
  }
  return notes
}

function renderNotesZh(notes) {
  const mapped = []
  const unknown = []
  for (const note of notes) {
    const known = noteZhValue(note)
    if (known) mapped.push(known)
    else if (note) unknown.push(note)
  }
  const parts = []
  if (mapped.length > 0) parts.push(`说明：${mapped.join('；')}`)
  for (const note of unknown) parts.push(`说明（原文）：${note}`)
  return parts.join('；')
}

function renderNotesEn(notes) {
  const list = unique(notes)
  return list.length > 0 ? `Note: ${list.join('; ')}` : ''
}

function humanScopeZh(segments) {
  const parts = []
  for (const segment of segments) {
    if (!segment.key) {
      if (segment.value) parts.push(segment.value)
      continue
    }
    if (segment.key === 'notes') {
      const notes = renderNotesZh(splitNotes(segment.value))
      if (notes) parts.push(notes)
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
    if (segment.key === 'notes') {
      const notes = renderNotesEn(splitNotes(segment.value))
      if (notes) parts.push(notes)
      continue
    }
    const label = EN_KEY[segment.key] ?? segment.label ?? segment.key
    const value = translateActionsEn(String(segment.value).replace(/\s*would also be destroyed\s*/i, ' ').trim())
    if (value) parts.push(`${label}: ${value}`)
  }
  return parts.join('; ')
}

/** Shared extraction for delete-family scopes. Unknown flags/keys stay out of the
 * card (they remain in the audit reason); `notes` are carried for the card. */
function deleteClauses(segments) {
  let countRaw = ''
  let gitPath = ''
  const targets = []
  const dirs = []
  const rawFlags = []
  const notes = []
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
        notes.push(...splitNotes(segment.value))
        break
      default:
        rawFlags.push(`${segment.label || segment.key}: ${segment.value}`)
    }
  }
  // Known flag: `git-metadata-inside-tree` is redundant when the .git destruction
  // note already covers it; otherwise it becomes a human "includes Git metadata".
  let includesGitMetadata = false
  for (const flag of rawFlags) {
    if (flag === 'git-metadata-inside-tree') {
      if (gitPath) continue
      includesGitMetadata = true
    }
  }
  return { countRaw, gitPath, includesGitMetadata, targets, dirs, notes }
}

function renderDeleteZh(segments, ruleIds, limits) {
  const { countRaw, gitPath, includesGitMetadata, targets, dirs, notes } = deleteClauses(segments)
  const head = `${deleteHeadZh(countRaw)}（规则 ${ruleIds.join(',')}）`
  const clauses = []
  const shownTargets = formatZhList(targets, limits.targets, numericCount(countRaw))
  if (shownTargets) clauses.push(`目标：${shownTargets}`)
  const shownDirs = formatZhList(dirs, limits.dirs)
  if (shownDirs) clauses.push(`涉及目录：${shownDirs}`)
  if (gitPath) clauses.push(`另将销毁：.git 元数据（${gitPath}）`)
  if (includesGitMetadata) clauses.push('范围内含 Git 元数据')
  const noteText = renderNotesZh(notes)
  if (noteText) clauses.push(noteText)
  const tail = clauses.length > 0 ? `${head}。${clauses.join('；')}` : head
  return `需要你确认（仅本次）：${tail}。批准只对本次调用有效。`
}

function renderDeleteEn(segments, ruleIds, limits) {
  const { countRaw, gitPath, includesGitMetadata, targets, dirs, notes } = deleteClauses(segments)
  const head = `it will delete ${countEn(countRaw)} ${entryWordEn(countRaw)} (rule ${ruleIds.join(',')})`
  const clauses = []
  const shownTargets = formatEnList(targets, limits.targets, numericCount(countRaw))
  if (shownTargets) clauses.push(`Targets: ${shownTargets}`)
  const shownDirs = formatEnList(dirs, limits.dirs)
  if (shownDirs) clauses.push(`directories: ${shownDirs}`)
  if (gitPath) clauses.push(`also destroys: Git metadata (${gitPath})`)
  if (includesGitMetadata) clauses.push('also includes Git metadata')
  const noteText = renderNotesEn(notes)
  if (noteText) clauses.push(noteText)
  const tail = clauses.length > 0 ? `${head}. ${clauses.join('; ')}` : head
  return `Confirmation needed (this call only): ${tail}. The approval applies to this call only.`
}

function worktreeNoteZh(notes) {
  const mapped = notes.map((note) => noteZhValue(note) ?? `原文：${note}`)
  return mapped.join('；')
}

function worktreeNoteEn(notes) {
  return notes.join('; ')
}

function renderWorktreeZh(segments, ruleIds, limits) {
  const { countRaw, targets, dirs, notes } = deleteClauses(segments)
  const noteText = worktreeNoteZh(notes)
  const countText = countPhraseZh(countRaw)
  const extras = []
  const shownTargets = formatZhList(targets, limits.targets)
  if (shownTargets) extras.push(`目标：${shownTargets}`)
  const shownDirs = formatZhList(dirs, limits.dirs)
  if (shownDirs) extras.push(`涉及目录：${shownDirs}`)
  const listText = extras.length > 0 ? `${extras.join('；')}；` : ''
  return `需要你确认（仅本次）：将移除 Git 工作树${noteText ? `（${noteText}）` : ''}${countText ? `，涉及 ${countText}` : ''}。${listText}批准只对本次调用有效。`
}

function renderWorktreeEn(segments, ruleIds, limits) {
  const { countRaw, targets, dirs, notes } = deleteClauses(segments)
  const noteText = worktreeNoteEn(notes)
  const countText = countPhraseEn(countRaw)
  const extras = []
  const shownTargets = formatEnList(targets, limits.targets)
  if (shownTargets) extras.push(`Targets: ${shownTargets}`)
  const shownDirs = formatEnList(dirs, limits.dirs)
  if (shownDirs) extras.push(`directories: ${shownDirs}`)
  const listText = extras.length > 0 ? `${extras.join('; ')}. ` : ''
  return `Confirmation needed (this call only): it will remove a Git worktree${noteText ? ` (${noteText})` : ''}${countText ? `, affecting ${countText}` : ''}. ${listText}The approval applies to this call only.`
}

function renderMoveZh(segments, ruleIds, limits) {
  const { countRaw, targets, dirs, notes } = deleteClauses(segments)
  const countText = countPhraseZh(countRaw)
  const noteText = renderNotesZh(notes)
  const extras = []
  const shownTargets = formatZhList(targets, limits.targets)
  if (shownTargets) extras.push(`目标：${shownTargets}`)
  const shownDirs = formatZhList(dirs, limits.dirs)
  if (shownDirs) extras.push(`涉及目录：${shownDirs}`)
  const listText = extras.length > 0 ? `${extras.join('；')}。` : ''
  return `需要你确认（仅本次）：将移动这些来源（原位置不再保留）${countText ? `，涉及 ${countText}` : ''}。${listText}${noteText ? `${noteText}。` : ''}批准只对本次调用有效。`
}

function renderMoveEn(segments, ruleIds, limits) {
  const { countRaw, targets, dirs, notes } = deleteClauses(segments)
  const countText = countPhraseEn(countRaw)
  const noteText = renderNotesEn(notes)
  const extras = []
  const shownTargets = formatEnList(targets, limits.targets)
  if (shownTargets) extras.push(`Targets: ${shownTargets}`)
  const shownDirs = formatEnList(dirs, limits.dirs)
  if (shownDirs) extras.push(`directories: ${shownDirs}`)
  const listText = extras.length > 0 ? `${extras.join('; ')}. ` : ''
  return `Confirmation needed (this call only): it will move these sources (the original locations will not remain)${countText ? `, affecting ${countText}` : ''}. ${listText}${noteText ? `${noteText}. ` : ''}The approval applies to this call only.`
}

const LIMIT_START = { targets: 6, dirs: 3 }
const MAX_LENGTH = 600

/** Build with shrinking list caps until it fits, then hard-cap as a last resort. */
function renderLimited(render, segments, ruleIds) {
  let limits = { ...LIMIT_START }
  let out = render(segments, ruleIds, limits)
  while (out.length > MAX_LENGTH && (limits.targets > 1 || limits.dirs > 1)) {
    limits = {
      targets: Math.max(1, limits.targets - 1),
      dirs: Math.max(1, limits.dirs - 1),
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
      zh: `需要你确认（仅本次）：${human}（规则 ${ids.join(',')}）。批准只对本次调用有效。`,
      en: `Confirmation needed (this call only): ${humanEn} (rule ${ids.join(',')}). The approval applies to this call only.`,
    }
  }
  const isDelete = ids.some((id) => DELETE_PREFIXES.some((prefix) => id.startsWith(prefix)))
  if (isDelete) {
    if (ids.includes('data.git.worktree')) {
      return {
        zh: renderLimited(renderWorktreeZh, parsed.segments, ids),
        en: renderLimited(renderWorktreeEn, parsed.segments, ids),
      }
    }
    if (ids.includes('data.move.source')) {
      return {
        zh: renderLimited(renderMoveZh, parsed.segments, ids),
        en: renderLimited(renderMoveEn, parsed.segments, ids),
      }
    }
    return {
      zh: renderLimited(renderDeleteZh, parsed.segments, ids),
      en: renderLimited(renderDeleteEn, parsed.segments, ids),
    }
  }
  const zhScope = humanScopeZh(parsed.segments)
  const enScope = humanScopeEn(parsed.segments)
  return {
    zh: `需要你确认（仅本次）：${zhScope || raw || '该操作'}（规则 ${ids.join(',')}）。批准只对本次调用有效。`,
    en: `Confirmation needed (this call only): ${enScope || raw || 'this operation'} (rule ${ids.join(',')}). The approval applies to this call only.`,
  }
}
