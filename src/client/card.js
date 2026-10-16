/* dsh-guardrails — browser half (plugin configuration page).
 *
 * Lazy-CJS bundle format of the DSH client module system (packages/client/
 * modules): script execution only registers the factory via
 * `window.__ModuleLoader__.load`; the module body (this card's React
 * component) materializes when the loader imports this package's `/client`.
 * There is no build step for this plugin (no bundler, no `dist/`): this file
 * is the shipped artifact, so it may only `require` bare specifiers the shell
 * seeds, and everything lives in this one file.
 *
 * V2 wiring (knowledge v0.2.0-rc.2 `client/15` §4, `host/07` §1-§3; DSR-015):
 *   - The Plugins page owns the configuration slots: `plugins.item`,
 *     `plugins.bundle.config` (keyed by package name) and `plugins.row.config`
 *     (keyed by `<package name>#<row id>`).
 *   - This bundle's configuration belongs to its loader ROW (`id: guardrails`
 *     in cordis.patch.yml), so it registers into `plugins.row.config` under
 *     `dsh-guardrails#guardrails`; that row then gains a 「配置」 control.
 *   - Reads/writes go through `ctx.configForms.get(ns)`. A settings namespace
 *     IS the loader entry id, so NS is `guardrails` — NOT the package name.
 *   - Registration is kept alive only while the Host serves that namespace
 *     (`configForms.whileServed`), so a deployment without the row shows no
 *     trace of this page.
 *
 * Form model (unchanged from DSR-011): the staged draft, the revision fence,
 * the read-back after a save, and discard-on-unmount are all owned by the
 * official `SettingsFormModel` / `SettingsForm`. What stays self-drawn: the
 * boolean toggle (official primitives ship no boolean field helper) and the
 * path-list editor (a plain textarea whose draft text is the canonical
 * newline-joined serialization of the `sensitiveFiles` array).
 */
window.__ModuleLoader__.load({
	id: 'dsh-guardrails',
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
		const React = require('react');
		const h = React.createElement;
		// Static UI library seeded by the shell. The official staged form and
		// the two controls this page draws on top of it.
		const primitives = require('@deepseek-ai/dsh-client-ui-primitives');
		const { SettingsForm, SettingsFormModel, Checkbox, Tag } = primitives;

		// Settings namespace = the loader entry id of this bundle's row
		// (`id: guardrails` in cordis.patch.yml), NOT the package name.
		const NS = 'guardrails';
		// `plugins.row.config` is keyed by `<package name>#<row id>`.
		const ROW_KEY = 'dsh-guardrails#guardrails';

		// ---------- the V2 config model ----------
		// Mirrors src/core/rules.js RULE_KEYS. The Host half refuses unknown
		// keys loudly, so a drift here would surface as a rejected save rather
		// than a silent no-op; test/config-page.test.mjs pins the parity
		// mechanically by importing the core module.
		const FIELDS = ['sensitiveFiles', 'credentialsReadAsk'];

		const isAbsolutePath = (p) => /^[A-Za-z]:[\\/]/.test(p) || p.startsWith('/');

		/** Mirrors the Host's reject rules: absolute, no globs/wildcards. */
		const isMarkablePath = (p) => isAbsolutePath(p) && !/[*?]/.test(p);

		/** Canonical draft text for the path list: one absolute path per line. */
		const formatPaths = (value) =>
			Array.isArray(value) ? value.map((p) => String(p).trim()).filter(Boolean).join('\n') : '';

		/**
		 * Read a path-list draft back; undefined = not a value the Host accepts.
		 * Mirrors the Host's own validation (src/core/rules.js): every non-empty
		 * line must be an absolute path. Checking it locally keeps an invalid
		 * draft visibly invalid instead of failing at save time.
		 */
		const parsePaths = (text) => {
			const paths = String(text).split('\n').map((p) => p.trim()).filter(Boolean);
			if (paths.some((p) => !isMarkablePath(p))) return undefined;
			return { kind: 'set', value: paths };
		};

		/**
		 * Path-list spec: the draft text is one absolute path per line.
		 */
		const pathsSpec = {
			field: 'sensitiveFiles',
			format: formatPaths,
			parse: parsePaths,
		};

		/**
		 * Boolean spec, text `'true'`/`'false'` — the same shape the official
		 * `settingsNumberField` uses (text in, structured write out). Only
		 * these two texts are accepted: the control below can produce nothing
		 * else, so accepting on/off/1/0 would be unfounded guessing.
		 */
		const boolSpec = (field) => ({
			field,
			format: (value) => (value === true ? 'true' : 'false'),
			parse: (text) => {
				const normalized = String(text).trim().toLowerCase();
				if (normalized === 'true') return { kind: 'set', value: true };
				if (normalized === 'false') return { kind: 'set', value: false };
				return undefined;
			},
		});

		/** Every field this page edits — the two top-level keys of the Config schema. */
		const SPECS = [pathsSpec, boolSpec('credentialsReadAsk')];

		/** The form frame's copy (official SettingsFormLabels; five keys, all required). */
		const LABELS = {
			unavailable: '本 profile 未提供该配置项（插件行未激活或设置面只读），当前按插件行配置工作。',
			readOnly: '当前 profile 的设置面只读，无法保存。',
			saveFailed: '保存未生效：Host 未接受（校验未通过或版本冲突），已回读当前生效值；草稿保留，请调整后重试。',
			save: '保存',
			saving: '保存中…',
		};
		const OVERRIDDEN = '已覆盖';
		const RESET = '重置';

		// ---------- tokens & geometry ----------
		// DSH theme tokens only (--dsw-alias-*); radii come from --dsw-radius-*.
		const T = {
			bgLayer2: 'var(--dsw-alias-bg-layer-2)',
			borderL1: 'var(--dsw-alias-border-l1)',
			borderL2: 'var(--dsw-alias-border-l2)',
			labelPrimary: 'var(--dsw-alias-label-primary)',
			labelSecondary: 'var(--dsw-alias-label-secondary)',
			labelTertiary: 'var(--dsw-alias-label-tertiary)',
			stateError: 'var(--dsw-alias-state-error-primary)',
		};
		const R = {
			sm: 'var(--dsw-radius-sm)',
			md: 'var(--dsw-radius-md)',
		};

		const style = {
			row: { padding: '10px 0', borderTop: `1px solid ${T.borderL1}` },
			head: { display: 'flex', alignItems: 'baseline', gap: '10px', flexWrap: 'wrap' },
			title: { flex: 'none', margin: 0, fontSize: 13, fontWeight: 500, color: T.labelPrimary, lineHeight: 1.5 },
			leaves: { flex: 1, display: 'flex', flexWrap: 'wrap', justifyContent: 'flex-end', gap: '2px 12px' },
			leaf: { display: 'inline-flex', alignItems: 'center', fontSize: 12, color: T.labelSecondary },
			badge: { display: 'inline-flex', alignItems: 'center', gap: 8, flex: 'none' },
			reset: { font: 'inherit', border: 'none', background: 'none', cursor: 'pointer', color: T.labelSecondary, fontSize: 12, padding: 0 },
			hint: { margin: '1px 0 0', fontSize: 12, color: T.labelTertiary, lineHeight: 1.5 },
			hintInvalid: { margin: '1px 0 0', fontSize: 12, color: T.stateError, lineHeight: 1.5 },
			textarea: {
				display: 'block', width: '100%', boxSizing: 'border-box', marginTop: 8,
				minHeight: 72, resize: 'vertical', font: 'inherit', fontSize: 12,
				lineHeight: 1.6, color: T.labelPrimary,
				background: T.bgLayer2, border: `1px solid ${T.borderL2}`, borderRadius: R.sm,
				padding: '6px 8px', outline: 'none',
			},
			textareaInvalid: { borderColor: T.stateError },
			note: { margin: '12px 0 0', fontSize: 12, color: T.labelTertiary, lineHeight: 1.6 },
		};

		const disabledStyle = (disabled) => (disabled ? { opacity: 0.4, cursor: 'default' } : {});

		/** The builtin-list toggle row (a single boolean). */
		function CredentialsRow({ field, writable, busy, onSet, onReset }) {
			const disabled = !writable || busy;
			return h('div', { style: { ...style.row, borderTop: 'none' } },
				h('div', { style: style.head },
					h('h4', { style: style.title }, '内置凭据名单读取审批'),
					h('div', { style: style.leaves },
						h(Checkbox, {
							className: style.leaf,
							label: '启用',
							checked: field.text === 'true',
							disabled,
							onChange: onSet,
						}),
					),
					field.overridden
						? h('span', { style: style.badge },
							h(Tag, { tone: 'neutral' }, OVERRIDDEN),
							h('button', {
								type: 'button',
								disabled,
								onClick: () => onReset('credentialsReadAsk'),
								style: { ...style.reset, ...disabledStyle(disabled) },
							}, RESET),
						)
						: null,
				),
				h('p', { style: style.hint },
					'SSH 具名私钥、.npmrc/.netrc/.git-credentials 等注册表令牌、Windows Hive 与转储文件的内容读取触发一次性审批；'
					+ '关闭后整类交给 Auto Review（不再额外审批）。',
				),
			);
		}

		/** The user-marked sensitive-files editor (one absolute path per line). */
		function SensitiveFilesRow({ field, writable, busy, onEdit, onReset }) {
			const disabled = !writable || busy;
			const invalid = field.text.trim() !== '' && parsePaths(field.text) === undefined;
			return h('div', { style: style.row },
				h('div', { style: style.head },
					h('h4', { style: style.title }, '标记的敏感文件'),
					field.overridden
						? h('span', { style: style.badge },
							h(Tag, { tone: 'neutral' }, OVERRIDDEN),
							h('button', {
								type: 'button',
								disabled,
								onClick: () => onReset('sensitiveFiles'),
								style: { ...style.reset, ...disabledStyle(disabled) },
							}, RESET),
						)
						: null,
				),
				h('textarea', {
					style: { ...style.textarea, ...(invalid ? style.textareaInvalid : {}) },
					spellCheck: false,
					placeholder: '每行一个绝对路径，例如 E:/Project/app/.env.production',
					value: field.text,
					disabled,
					onChange: (event) => onEdit(event.target.value),
				}),
				h('p', { style: invalid ? style.hintInvalid : style.hint },
					invalid
						? '存在无效行（相对路径、通配符等）；只接受精确的绝对文件路径，保存会被拒绝。'
						: '命中的文件在内容读取（read / read_image / 单文件 grep）时请求一次性审批；标记不是预先批准，删除该行即取消。',
				),
			);
		}

		/**
		 * The row's configuration page.
		 *
		 * Owner contract of `plugins.row.config` (knowledge `client/15` §4;
		 * PluginManagerPage): the page asks for `view: 'summary'` for the row's
		 * one-liner and `view: 'page'` for the body under the row's own title,
		 * and renders the body inside its own <section>.
		 */
		function GuardCard({ view, useGuardrailForm, edit, resetField, save, discard }) {
			// Snapshot via the renderer-bound selector hook from the `hooks`
			// compartment; the page's `form` prop is a one-time snapshot.
			const state = useGuardrailForm((s) => s);

			// The page draws the row's title, icon and crumb itself; the summary
			// word stays the page's business, so only the body renders here.
			if (view === 'summary') {
				return h('span', null, '敏感文件内容读取的原生一次性审批（内置凭据名单 + 用户标记文件）；其余操作交给 DSH 原生 Auto Review');
			}

			const busy = state.saving === true;
			const writable = state.writable === true;

			return h(SettingsForm, { labels: LABELS, state, onSave: save, onDiscard: discard },
				h(CredentialsRow, {
					field: state.credentialsReadAsk,
					writable,
					busy,
					onSet: (next) => edit('credentialsReadAsk', next ? 'true' : 'false'),
					onReset: resetField,
				}),
				h(SensitiveFilesRow, {
					field: state.sensitiveFiles,
					writable,
					busy,
					onEdit: (text) => edit('sensitiveFiles', text),
					onReset: resetField,
				}),
				h('p', { style: style.note },
					'本插件不再硬拒绝任何调用：命中即请求 DSH 原生一次性审批（批准一次仅放行对应调用，拒绝/超时/不可用则不执行）；'
					+ '普通 .env、写改删、shell 命令与目录级搜索交给原生 Auto Review。'
					+ '修改在本地暂存，点「保存」统一写入本 profile 的行配置（cordis.patch.yml）并立即生效；离开本页则丢弃草稿。',
				),
			);
		}

		/**
		 * Bridge the official form model onto this row's `ConfigForm`.
		 * Mirrors the official `ShellCardController`
		 * (ui-settings-shell/src/client/shell-card-controller.ts): one
		 * `SettingsFormModel` over the served namespace, a `bind(projection)`
		 * store for the component, and `actions()` as the edit face.
		 */
		function createController(scope) {
			const form = new SettingsFormModel(scope, SPECS);
			const store = form.bind(() => projection(form));
			return { form, inject: () => ({ hooks: { guardrailForm: store }, ...form.actions() }) };
		}

		/** The snapshot the component reads through `useGuardrailForm`. */
		function projection(form) {
			const state = { ...form.shell() };
			for (const spec of SPECS) state[spec.field] = form.field(spec.field);
			return state;
		}

		/** Cordis client plugin: the entry id the Host half registers. */
		const name = 'dsh-guardrails';
		// `configForms` supplies the per-namespace form; `slots` registers the
		// page. `settingsScope` is gone from the client context entirely.
		const inject = ['slots', 'configForms'];

		function apply(ctx) {
			const scope = ctx.configForms.get(NS);
			// One controller per mount; its model subscribes to the Host snapshot,
			// so it is released with this fiber.
			const controller = createController(scope);
			ctx.effect(() => () => controller.form.dispose(), 'dsh-guardrails: settings form model');
			// Reactivity contract (knowledge `client/15` §4): the `hooks`
			// compartment is RESERVED — the renderer consumes each member as a
			// `use<Name>` selector hook and never passes `hooks` into props.
			//
			// Register into the Plugins page only while the Host serves this
			// namespace, so a profile without the row shows no trace of the page.
			// The row's own page gains a 「配置」 control from this key.
			ctx.effect(() => ctx.configForms.whileServed([NS], () => ctx.slots.inject('plugins.row.config', () => ctx.slots.register({
				name: 'plugins.row.config',
				key: ROW_KEY,
				inject: () => controller.inject(),
			}, GuardCard))));
		}

		exports.name = name;
		exports.inject = inject;
		exports.apply = apply;
		return module.exports;
	},
});
