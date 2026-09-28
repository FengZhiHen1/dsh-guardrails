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
 * v0.1.7 wiring (knowledge `client/15` §4.1, `host/07` §1-§3):
 *   - `settings.plugin.item` and `ctx.settingsScope` NO LONGER EXIST (source
 *     grep: both are zero-hit on the current baseline). The Plugins page owns
 *     the configuration slots: `plugins.item` (OFFICIAL settings pages only),
 *     `plugins.bundle.config` (keyed by package name) and `plugins.row.config`
 *     (keyed by `<package name>#<row id>`).
 *   - This bundle's configuration belongs to its loader ROW (`id: guardrails`
 *     in cordis.patch.yml), so it registers into `plugins.row.config` under
 *     `dsh-guardrails#guardrails`; that row then gains a 「配置」 control.
 *   - Reads/writes go through `ctx.configForms.get(ns)`. A settings namespace
 *     IS the loader entry id, so NS is `guardrails` — NOT the package name
 *     `dsh-guardrails` (which was the old, plugin-chosen namespace).
 *   - Registration is kept alive only while the Host serves that namespace
 *     (`configForms.whileServed`), so a deployment without the row shows no
 *     trace of this page.
 *
 * Form model (DSR-011, 2026-09-28): the staged draft, the revision fence, the
 * read-back after a save, and discard-on-unmount are all owned by the official
 * `SettingsFormModel` / `SettingsForm`; this file no longer hand-writes any of
 * it. That earlier hand-written shell (a collapsible card with its own header,
 * chevron, 「未保存」 pill and 「放弃」 button) diverged from the official
 * pages, which render a bare `<SettingsForm>` — the Plugins page already draws
 * the row's title, icon and crumb above this body.
 *
 * What stays self-drawn, and why: the leaf-toggle grid. Official field
 * primitives are text (`SettingsValueField`) and write-only secret
 * (`SettingsSecretField`) only — `settingsNumberField`/`settingsTextField` are
 * the whole spec-helper set, with no boolean control. So the toggles are drawn
 * with the official `Checkbox`, and each category rides the official model as
 * ONE field whose draft text is the canonical serialization of its leaf object
 * (see `categorySpec`). Round-tripping through text is what lets a structured
 * value use the official plan/parse/fence machinery unchanged.
 *
 * Card chrome follows the official geometry: tokens via --dsw-alias-*,
 * radii via --dsw-radius-*. Only whole-round pills stay literal (999), which is
 * what the official Tag/Switch styles do too.
 */
window.__ModuleLoader__.load({
	id: 'dsh-guardrails',
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
		const React = require('react');
		const h = React.createElement;
		// Static UI library seeded by the shell. The official staged form, the
		// spec helper set, and the two controls this page draws on top of them.
		const primitives = require('@deepseek-ai/dsh-client-ui-primitives');
		const { SettingsForm, SettingsFormModel, Checkbox, Tag } = primitives;

		// Settings namespace = the loader entry id of this bundle's row
		// (`id: guardrails` in cordis.patch.yml), NOT the package name: v0.1.7
		// dropped the plugin-chosen namespace in favour of the entry id.
		const NS = 'guardrails';
		// `plugins.row.config` is keyed by `<package name>#<row id>`.
		const ROW_KEY = 'dsh-guardrails#guardrails';

		// ---------- the rule model ----------
		// Mirrors CATEGORY_LEAF_KEYS in src/core/rules.js. The Host half refuses
		// unknown keys loudly, so a drift here would surface as a rejected save
		// rather than a silent no-op; test/config-page.test.mjs pins the parity
		// mechanically by importing the core module.
		const CATEGORIES = {
			env: ['read', 'modify'],
			git: ['read', 'modify'],
			credentials: ['read', 'modify', 'list'],
			system: ['write'],
			destructive: ['git', 'machine', 'eval', 'cli', 'bulk', 'target', 'chain', 'misuse'],
		};
		const CATEGORY_LABEL = {
			env: '.env 文件访问',
			git: '.git 内部访问',
			credentials: '凭据文件访问',
			system: '系统区写入',
			destructive: '破坏性命令',
		};
		const CATEGORY_HINT = {
			env: '敏感环境文件（.env 等）的内容读/写',
			git: '.git 目录内部的内容读/写',
			credentials: '凭据文件/目录的读、写与列举',
			system: 'Windows 系统区的写入（读与列举不受限）',
			destructive: '按子族细分的高风险命令（机器级/git/CLI/批删/目标/链删/参数误用）',
		};
		const LEAF_LABEL = {
			read: '读', modify: '写', list: '列举', write: '写入',
			git: 'git 高危', machine: '机器级', eval: '不可信执行',
			cli: '数据 CLI', bulk: '管道批删', target: '删除目标',
			chain: '无门控链删', misuse: '参数误用',
		};
		// The category-independent fail-safe (a single boolean, not a leaf set).
		const UNVERIFIABLE = 'unverifiable';
		const UNVERIFIABLE_LABEL = '动态目标 fail-safe';
		const UNVERIFIABLE_HINT = '命令重建后仍含动态 $() 目标时的保守拦截（慎关：检测力下降）';

		// ---------- value <-> draft text ----------
		// A category is stored as a boolean (whole category on/off, v1-compatible)
		// or as an object of op-level leaves; src/core/rules.js normalizes both.
		// The draft text is the CANONICAL serialization so that an edit which
		// returns a category to its stored state produces the stored text again
		// (the official model decides "is this dirty?" by comparing texts).
		const isPlainObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

		/** Expand any accepted category value into a leaf object. Absent ⇒ all on. */
		const toLeaves = (value, keys) => {
			if (value === undefined || value === null) return Object.fromEntries(keys.map((k) => [k, true]));
			if (typeof value === 'boolean') return Object.fromEntries(keys.map((k) => [k, value]));
			if (!isPlainObject(value)) return Object.fromEntries(keys.map((k) => [k, true]));
			return Object.fromEntries(keys.map((k) => [k, value[k] !== false]));
		};

		/** Canonical text: `true` / `false` when uniform, else the leaf JSON. */
		const formatCategory = (value, keys) => {
			const leaves = toLeaves(value, keys);
			const on = keys.every((k) => leaves[k] === true);
			if (on) return 'true';
			const off = keys.every((k) => leaves[k] === false);
			return off ? 'false' : JSON.stringify(leaves);
		};

		/** Read a category draft back; undefined = not a value this field accepts. */
		const parseCategory = (text, keys) => {
			const trimmed = String(text).trim();
			if (trimmed === 'true') return { kind: 'set', value: true };
			if (trimmed === 'false') return { kind: 'set', value: false };
			let parsed;
			try {
				parsed = JSON.parse(trimmed);
			} catch (_error) {
				return undefined;
			}
			if (!isPlainObject(parsed)) return undefined;
			// Mirror the Host's own validation (src/core/rules.js evaluateCategory):
			// it refuses unknown keys AND non-boolean leaves. Accepting a leaf here
			// that the Host refuses would turn a locally-visible "invalid draft"
			// into a save that crosses the wire only to be rejected.
			if (Object.keys(parsed).some((k) => !keys.includes(k))) return undefined;
			if (keys.some((k) => parsed[k] !== undefined && typeof parsed[k] !== 'boolean')) return undefined;
			const leaves = toLeaves(parsed, keys);
			const on = keys.every((k) => leaves[k] === true);
			const off = keys.every((k) => leaves[k] === false);
			return { kind: 'set', value: on ? true : off ? false : leaves };
		};

		/** The leaf object a category's current draft text stands for. */
		const leavesOfText = (text, keys) => {
			const write = parseCategory(text, keys);
			return toLeaves(write === undefined ? undefined : write.value, keys);
		};

		/** One category's spec: the whole leaf set is a single staged field. */
		const categorySpec = (field) => ({
			field,
			format: (value) => formatCategory(value, CATEGORIES[field]),
			parse: (text) => parseCategory(text, CATEGORIES[field]),
		});

		/**
		 * Boolean spec, text `'true'`/`'false'` — the same shape the official
		 * `settingsNumberField` uses (text in, structured write out), because the
		 * primitive set has no boolean field helper. Only these two texts are
		 * accepted: the control below can produce nothing else, so accepting
		 * on/off/1/0 would be unfounded guessing.
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

		/** Every field this page edits — the six top-level keys of the Config schema. */
		const SPECS = [
			...Object.keys(CATEGORIES).map(categorySpec),
			boolSpec(UNVERIFIABLE),
		];

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
			bgLayer3: 'var(--dsw-alias-bg-layer-3)',
			bgModulePlatform: 'var(--dsw-alias-bg-module-platform)',
			borderL1: 'var(--dsw-alias-border-l1)',
			borderL2: 'var(--dsw-alias-border-l2)',
			brand: 'var(--dsw-alias-brand-primary)',
			error: 'var(--dsw-alias-state-error-primary)',
			labelPrimary: 'var(--dsw-alias-label-primary)',
			labelSecondary: 'var(--dsw-alias-label-secondary)',
			labelTertiary: 'var(--dsw-alias-label-tertiary)',
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
			// The official Checkbox renders its own label; this only places the
			// <label> element the primitive returns.
			leaf: { display: 'inline-flex', alignItems: 'center', fontSize: 12, color: T.labelSecondary },
			badge: { display: 'inline-flex', alignItems: 'center', gap: 8, flex: 'none' },
			reset: { font: 'inherit', border: 'none', background: 'none', cursor: 'pointer', color: T.labelSecondary, fontSize: 12, padding: 0 },
			hint: { margin: '1px 0 0', fontSize: 12, color: T.labelTertiary, lineHeight: 1.5 },
			note: { margin: '12px 0 0', fontSize: 12, color: T.labelTertiary, lineHeight: 1.6 },
		};

		const disabledStyle = (disabled) => (disabled ? { opacity: 0.4, cursor: 'default' } : {});

		/**
		 * One category: its title, one official Checkbox per operation leaf, and
		 * its reset. A checkbox toggle does not write: it stages the whole leaf
		 * set as this field's draft text, exactly like typing into a value field.
		 */
		function CategoryRow({ cat, keys, field, writable, busy, first, onToggleLeaf, onReset }) {
			const disabled = !writable || busy;
			const leaves = leavesOfText(field.text, keys);
			return h('div', { style: first ? { ...style.row, borderTop: 'none' } : style.row },
				h('div', { style: style.head },
					h('h4', { style: style.title }, CATEGORY_LABEL[cat] || cat),
					h('div', { style: style.leaves }, keys.map((leaf) =>
						h(Checkbox, {
							key: leaf,
							className: style.leaf,
							label: LEAF_LABEL[leaf] || leaf,
							checked: leaves[leaf] === true,
							disabled,
							onChange: (next) => onToggleLeaf(cat, leaf, next),
						}),
					)),
					field.overridden
						? h('span', { style: style.badge },
							h(Tag, { tone: 'neutral' }, OVERRIDDEN),
							h('button', {
								type: 'button',
								disabled,
								onClick: () => onReset(cat),
								style: { ...style.reset, ...disabledStyle(disabled) },
							}, RESET),
						)
						: null,
				),
				h('p', { style: style.hint }, CATEGORY_HINT[cat] || ''),
			);
		}

		/** The category-independent fail-safe row (a single boolean toggle). */
		function UnverifiableRow({ field, writable, busy, onSet, onReset }) {
			const disabled = !writable || busy;
			return h('div', { style: style.row },
				h('div', { style: style.head },
					h('h4', { style: style.title }, UNVERIFIABLE_LABEL),
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
								onClick: () => onReset(UNVERIFIABLE),
								style: { ...style.reset, ...disabledStyle(disabled) },
							}, RESET),
						)
						: null,
				),
				h('p', { style: style.hint }, UNVERIFIABLE_HINT),
			);
		}

		/**
		 * The row's configuration page.
		 *
		 * Owner contract of `plugins.row.config` (knowledge `client/15` §4.1;
		 * PluginManagerPage.tsx:491-495): the page asks for `view: 'summary'` for
		 * the row's one-liner and `view: 'page'` for the body under the row's own
		 * title, and renders the body inside its own <section>.
		 */
		function GuardCard({ view, useGuardrailForm, edit, resetField, save, discard }) {
			// Snapshot via the renderer-bound selector hook from the `hooks`
			// compartment; the page's `form` prop is a one-time snapshot.
			const state = useGuardrailForm((s) => s);

			// The page draws the row's title, icon and crumb itself; the summary
			// word stays the page's business, so only the body renders here.
			if (view === 'summary') {
				return h('span', null, 'AI 工具调用对敏感文件（.env/.git/凭据）、系统区写入与破坏性命令的拦截开关');
			}

			const busy = state.saving === true;
			const writable = state.writable === true;

			/** Stage a leaf toggle: the whole leaf set becomes this field's draft. */
			const toggleLeaf = (cat, leaf, next) => {
				const keys = CATEGORIES[cat];
				const leaves = { ...leavesOfText(state[cat].text, keys), [leaf]: next };
				edit(cat, formatCategory(leaves, keys));
			};

			const rows = Object.keys(CATEGORIES).map((cat, index) =>
				h(CategoryRow, {
					key: cat,
					cat,
					keys: CATEGORIES[cat],
					field: state[cat],
					writable,
					busy,
					first: index === 0,
					onToggleLeaf: toggleLeaf,
					onReset: resetField,
				}),
			);

			return h(SettingsForm, { labels: LABELS, state, onSave: save, onDiscard: discard },
				rows,
				h(UnverifiableRow, {
					field: state[UNVERIFIABLE],
					writable,
					busy,
					onSet: (next) => edit(UNVERIFIABLE, next ? 'true' : 'false'),
					onReset: resetField,
				}),
				h('p', { style: style.note },
					'修改在本地暂存，点「保存」统一写入本 profile 的行配置（cordis.patch.yml）并立即生效于后续判定；'
					+ '「重置」清除对应项的用户覆盖、回落插件行默认；离开本页则丢弃草稿。',
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
			// Reactivity contract (knowledge `client/15` §4.1): the `hooks`
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
