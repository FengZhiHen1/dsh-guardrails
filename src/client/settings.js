// Native plugin configuration: edit exact files, save once, then confirm acceptance.
// DSH owns navigation, accepted values, revisions, persistence and theme.
window.__ModuleLoader__.load({
  id: 'dsh-guardrails',
  factory(require) {
    const React = require('react')
    // Platform seed (not a dynamic plugin row): resolve the shared primitives here,
    // never vendor a second copy or list it under dsh.client.external.
    const { Button } = require('@deepseek-ai/dsh-client-ui-primitives')
    const h = React.createElement
    const dictionaries = {
      zh: {
        summary: '限制灾难性操作，审批敏感文件访问，并遮罩可识别凭据。',
        files: '敏感文件', filesHint: '每行一个完整文件路径。读取、修改、删除或移动这些文件需要单次批准。仅填写文件路径，不支持目录规则、通配符或相对路径。',
        empty: '尚未添加自定义文件；内置凭据文件保护可独立开启。',
        builtin: '内置凭据文件保护', builtinHint: '对已识别的私钥、凭据文件等内容操作请求批准。关闭后，自定义敏感文件清单仍生效。',
        timeout: '审批等待时间', seconds: '秒', timeoutHint: '默认 120 秒，最长 3600 秒。超时或取消后拒绝本次操作，迟到的批准不再生效。',
        loading: '正在读取配置…', unavailable: '当前无法读取此插件配置。请确认插件已启用并重新打开此页。',
        readOnly: '当前连接只允许查看配置。', save: '保存设置', saving: '正在保存…', saved: '设置已保存并生效。',
        failed: '保存未成功，输入已保留。配置可能已在别处修改，请重新打开此页后核对并重试。',
        pathError: '请填写最多 1024 个绝对文件路径；不支持通配符，每个路径最长 32768 个字符。',
        timeoutError: '请输入大于 0 且不超过 3600 的秒数，精度最多为毫秒。',
        scope: '保护范围', scopeBody: '对已识别的物理设备销毁、宿主系统整树破坏及共享 Git 核心数据破坏直接拒绝；敏感文件操作限时审批；普通操作默认允许。',
        limits: '能力与边界', limitsBody: '仅保护经 DSH 工具发起且可识别的操作。动态路径、脚本内部及目录切换后的相对路径可能无法完整分析。可识别的凭据文本会自动遮罩，但结构化结果、错误与元数据仍可能保留原文。',
      },
      en: {
        summary: 'Block recognized catastrophic operations, approve sensitive-file access and mask recognizable credentials.',
        files: 'Sensitive files', filesHint: 'One absolute file path per line. Reading, changing, deleting or moving these files requires one-time approval. Directory rules, wildcards and relative paths are unsupported.',
        empty: 'No custom files added. Built-in credential-file protection works independently.',
        builtin: 'Built-in credential-file protection', builtinHint: 'Request approval for content operations on recognized private keys and credential files. Turning this off keeps your custom sensitive-file list active.',
        timeout: 'Approval wait', seconds: 'seconds', timeoutHint: 'Default: 120 seconds. Maximum: 3600 seconds. Timeout or cancellation refuses the operation; late approval cannot authorize it.',
        loading: 'Loading settings…', unavailable: 'Settings are unavailable. Confirm the plugin is enabled and reopen this page.',
        readOnly: 'This connection can only view settings.', save: 'Save settings', saving: 'Saving…', saved: 'Settings saved and applied.',
        failed: 'Save failed; your input is retained. Settings may have changed elsewhere. Reopen this page, review the values and retry.',
        pathError: 'Enter up to 1024 absolute file paths without wildcards, each at most 32768 characters.',
        timeoutError: 'Enter seconds greater than 0 and at most 3600, with at most millisecond precision.',
        scope: 'Protection scope', scopeBody: 'Recognized physical-device destruction, host system tree destruction and shared Git core destruction are refused. Sensitive-file operations require bounded approval. Ordinary operations are allowed by default.',
        limits: 'Capabilities and limits', limitsBody: 'Protection covers recognizable operations dispatched through DSH tools. Dynamic paths, script internals and relative paths after directory changes may not be fully analyzed. Recognizable credential text is masked, but structured results, errors and metadata may retain original text.',
      },
    }
    const css = `
.gr-settings{display:flex;flex-direction:column;gap:24px;color:var(--dsw-alias-label-primary);font:inherit;max-width:680px}
.gr-settings .gr-field{display:flex;flex-direction:column;gap:8px;min-width:0}
.gr-settings label,.gr-settings h3{font-size:13px;font-weight:500;margin:0}
.gr-settings .gr-help{font-size:12px;line-height:1.6;color:var(--dsw-alias-label-secondary);margin:0;overflow-wrap:anywhere}
.gr-settings textarea,.gr-settings input[type=number]{box-sizing:border-box;border:1px solid var(--dsw-alias-border-l2);border-radius:6px;background:var(--dsw-alias-bg-base);color:inherit;font:inherit;font-size:13px;padding:8px 10px;max-width:100%}
.gr-settings textarea{width:100%;resize:vertical;min-height:110px;line-height:1.6}
.gr-settings .gr-check,.gr-settings .gr-number{display:flex;align-items:center;gap:8px;font-size:13px}
.gr-settings input[type=checkbox]{accent-color:var(--dsw-alias-brand-primary);width:16px;height:16px;margin:0;flex-shrink:0}
.gr-settings input[type=number]{width:120px}
.gr-settings .gr-footer{display:flex;align-items:center;flex-wrap:wrap;gap:12px}
.gr-settings textarea:disabled,.gr-settings input:disabled{background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-secondary);cursor:not-allowed}
.gr-settings :is(input,textarea,summary):focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:2px}
.gr-settings .gr-error{font-size:12px;line-height:1.6;color:var(--dsw-alias-state-error-primary);margin:0}
.gr-settings [aria-invalid=true]{border-color:var(--dsw-alias-state-error-primary)}
.gr-settings .gr-scope{border-top:1px solid var(--dsw-alias-border-l1);padding-top:20px;display:flex;flex-direction:column;gap:8px}
.gr-settings details{font-size:12px;color:var(--dsw-alias-label-secondary);line-height:1.6}
.gr-settings summary{cursor:pointer;padding:4px 0;width:fit-content}
.gr-settings details p{padding-top:4px}
`
    // Defensive: a served section can lag the schema, so never assume field shapes.
    function toDraft(value) {
      const files = Array.isArray(value?.sensitiveFiles) ? value.sensitiveFiles.filter(entry => typeof entry === 'string') : []
      const builtin = typeof value?.credentialsReadAsk === 'boolean' ? value.credentialsReadAsk : true
      const timeout = Number.isInteger(value?.askTimeoutMs) && value.askTimeoutMs > 0 ? value.askTimeoutMs : 120000
      return { files: files.join('\n'), builtin, seconds: String(timeout / 1000) }
    }
    function parseDraft(draft) {
      const sensitiveFiles = draft.files.split(/\r?\n/).filter(line => line.trim() !== '')
      const seconds = Number(draft.seconds)
      const milliseconds = Math.round(seconds * 1000)
      if (!draft.seconds.trim() || !Number.isFinite(seconds) || seconds <= 0 || seconds > 3600 || Math.abs(milliseconds - seconds * 1000) > 0.000001) return { error: 'timeoutError' }
      if (sensitiveFiles.length > 1024 || sensitiveFiles.some(path => path.length > 32768 || /[\0*?]/.test(path) || !(/^[A-Za-z]:[\\/]/.test(path) || path.startsWith('/') || path.startsWith('\\\\')))) return { error: 'pathError' }
      return { value: { sensitiveFiles, credentialsReadAsk: draft.builtin, askTimeoutMs: milliseconds } }
    }
    function Editor({ settingsForm: form, t }) {
      const [snapshot, setSnapshot] = React.useState(() => form.getSnapshot())
      const [edit, setEdit] = React.useState(null)
      const [outcome, setOutcome] = React.useState('idle')
      const busy = React.useRef(false)
      const mounted = React.useRef(true)
      const uid = React.useId()
      React.useEffect(() => {
        mounted.current = true
        const sync = () => setSnapshot(form.getSnapshot())
        sync()
        const off = form.subscribe(sync)
        return () => { mounted.current = false; off() }
      }, [form])
      if (snapshot.status === 'loading') return h('p', { role: 'status' }, t('loading'))
      if (snapshot.status !== 'ready' || snapshot.value === undefined) return h('p', { role: 'status' }, t('unavailable'))
      const baseline = toDraft(snapshot.value)
      const draft = edit?.draft ?? baseline
      const parsed = parseDraft(draft)
      const dirty = edit !== null && (draft.files !== baseline.files || draft.builtin !== baseline.builtin || draft.seconds !== baseline.seconds)
      const locked = !snapshot.writable || outcome === 'saving'
      function change(key, value) {
        setEdit(previous => ({ revision: previous?.revision ?? snapshot.revision, draft: { ...(previous?.draft ?? baseline), [key]: value } }))
        setOutcome('idle')
      }
      async function save(event) {
        event.preventDefault()
        if (busy.current || !snapshot.writable) return
        if (!dirty) { setOutcome('saved'); return }
        if (parsed.error || !Number.isInteger(edit?.revision)) return
        busy.current = true
        setOutcome('saving')
        try {
          const accepted = await form.mutate(Object.entries(parsed.value).map(([key, value]) => ({ op: 'set', path: [key], value })), edit.revision)
          if (mounted.current) { setOutcome(accepted ? 'saved' : 'failed'); if (accepted) setEdit(null) }
        } catch (error) {
          // Transport diagnostics may contain config values; show only safe localized feedback.
          if (mounted.current) setOutcome('failed')
        }
        finally { busy.current = false }
      }
      const note = (key, id) => h('p', { className: 'gr-help', id }, t(key))
      return h('form', { className: 'gr-settings', onSubmit: save, 'aria-busy': outcome === 'saving' },
        !snapshot.writable ? note('readOnly') : null,
        h('style', null, css),
        h('div', { className: 'gr-field' },
          h('label', { htmlFor: uid + '-files' }, t('files')),
          note('filesHint', uid + '-files-help'),
          h('textarea', { id: uid + '-files', rows: 5, value: draft.files, disabled: locked, spellCheck: false, 'aria-describedby': uid + '-files-help', 'aria-invalid': parsed.error === 'pathError', onChange: event => change('files', event.target.value) }),
          !draft.files.trim() ? note('empty') : null),
        h('div', { className: 'gr-field' },
          h('label', { className: 'gr-check' }, h('input', { type: 'checkbox', checked: draft.builtin, disabled: locked, 'aria-describedby': uid + '-builtin-help', onChange: event => change('builtin', event.target.checked) }), t('builtin')),
          note('builtinHint', uid + '-builtin-help')),
        h('div', { className: 'gr-field' },
          h('label', { htmlFor: uid + '-wait' }, t('timeout')),
          h('div', { className: 'gr-number' }, h('input', { id: uid + '-wait', type: 'number', min: 0.001, max: 3600, step: 0.001, value: draft.seconds, disabled: locked, 'aria-describedby': uid + '-wait-help', 'aria-invalid': parsed.error === 'timeoutError', onChange: event => change('seconds', event.target.value) }), h('span', null, t('seconds'))),
          note('timeoutHint', uid + '-wait-help')),
        edit && parsed.error ? h('p', { role: 'alert', className: 'gr-error' }, t(parsed.error)) : null,
        h('div', { className: 'gr-footer' }, h(Button, { variant: 'primary', type: 'submit', disabled: locked }, t(outcome === 'saving' ? 'saving' : 'save')),
          h('span', { role: 'status', className: outcome === 'failed' ? 'gr-error' : 'gr-help' }, t(outcome === 'saved' ? 'saved' : outcome === 'failed' ? 'failed' : ''))),
        h('div', { className: 'gr-scope' }, h('h3', null, t('scope')), note('scopeBody'), h('details', null, h('summary', null, t('limits')), note('limitsBody'))))
    }
    return {
      inject: ['slots', 'locale', 'configForms'], toDraft, parseDraft,
      apply(ctx) {
        for (const [language, dictionary] of Object.entries(dictionaries)) ctx.effect(() => ctx.locale.register('guardrails-settings', language, dictionary))
        ctx.slots.inject('plugins.row.config', () => ctx.slots.register({
          name: 'plugins.row.config', key: 'dsh-guardrails#guardrails', locale: 'guardrails-settings',
          inject: () => ({ settingsForm: ctx.configForms.get('guardrails') }),
        }, props => props.view === 'summary' ? props.t('summary') : h(Editor, { settingsForm: props.settingsForm, t: props.t })))
      },
    }
  },
})
