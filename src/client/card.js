/* dsh-guardrails — browser half (settings card).
 *
 * Lazy-CJS bundle format of the DSH client module system (packages/client/
 * modules): script execution only registers the factory via
 * `window.__ModuleLoader__.load`; the module body (this card's React
 * component) materializes when the loader imports this package's `/client`.
 * The "插件配置" tab declares the keyed `settings.plugin.item` slot; the card
 * below is registered under its own namespace key — the same value the Host
 * half registers through the settings service (`dsh-guardrails`) — and the
 * tab pairs the two without knowing what the namespace means.
 *
 * The card renders its own chrome and form (cross-plugin value imports are
 * rejected by the bundle-purity gate, so the official PluginCard shell is
 * unavailable): it reads the bound settings scope's snapshot (resolved value /
 * base / user layers, revision, writability) and writes fields through the
 * scope, whose revision fencing is owned by the DSH settings surface.
 *
 * Form semantics follow the official PluginCard staged-draft model
 * (knowledge/15 §4.1, production parity: dsh-skill-manager card.jsx): edits
 * land in a local draft; one 保存 commits every dirty field in a single
 * scope.mutate() (atomic, one revision fence); 放弃 discards the draft;
 * a dirty header pill marks unsaved state; a successful save collapses the
 * card, a rejected write keeps the draft plus the footer diagnostic. Per-row
 * 重置 stays immediate (clears the user override, not an edit).
 *
 * Card chrome follows the official PluginCard geometry (knowledge/15 §4.1):
 * li > button.header (名称/描述/折叠箭头) > body (border-top + margin 0 16px)
 * > footer (border-top, 放弃/保存), tokens via --dsw-alias-*, chevron from
 * @deepseek-ai/dsh-client-ui-primitives (the shell-seeded static UI library;
 * icon guarded so a missing icon never fails the card). Interactive states
 * replicate PluginCard.module.css in inline-style form: disabled = opacity
 * .4 + default cursor, discard hover deepens, focus = brand outline.
 */
window.__ModuleLoader__.load({
	id: 'dsh-guardrails',
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
		const React = require('react');
		const { useState } = React;
		const h = React.createElement;
		// Static UI library seeded by the shell; guard the icon so a missing
		// glyph degrades to a text chevron instead of failing the card.
		const primitives = require('@deepseek-ai/dsh-client-ui-primitives');
		const ChevronIcon = typeof primitives.IconChevronDownOutline14 === 'function'
			? primitives.IconChevronDownOutline14
			: null;

		const NS = 'dsh-guardrails';
		const CATEGORIES = {
			env: ['read', 'modify'],
			git: ['read', 'modify'],
			credentials: ['read', 'modify', 'list'],
			system: ['write'],
			destructive: ['git', 'machine', 'eval', 'cli', 'bulk', 'target'],
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
			destructive: '按子族细分的高风险命令（机器级/git/CLI/批删/目标）',
		};
		const LEAF_LABEL = {
			read: '读', modify: '写', list: '列举', write: '写入',
			git: 'git 高危', machine: '机器级', eval: '不可信执行',
			cli: '数据 CLI', bulk: '管道批删', target: '删除目标',
		};
		// All six top-level fields in fixed order (save-op assembly + equality).
		const FIELDS = ['env', 'git', 'credentials', 'system', 'destructive', 'unverifiable'];

		const leafDefaults = (keys) => Object.fromEntries(keys.map((k) => [k, true]));

		// Resolved value may be boolean (v1 category form) or a leaf object;
		// normalize to leaf objects for the toggle UI. Key order is fixed by
		// construction, so JSON comparison below is stable.
		const normalized = (value) => {
			const v = typeof value === 'object' && value !== null ? value : {};
			const out = {};
			for (const [cat, keys] of Object.entries(CATEGORIES)) {
				const raw = v[cat];
				if (raw === true || raw === undefined) out[cat] = leafDefaults(keys);
				else if (raw === false) out[cat] = Object.fromEntries(keys.map((k) => [k, false]));
				else out[cat] = Object.fromEntries(keys.map((k) => [k, raw[k] !== false]));
			}
			out.unverifiable = v.unverifiable !== false;
			return out;
		};
		// Drafts spread only from normalized() output, so key order never
		// diverges and JSON equality is exact.
		const equalValue = (a, b) => JSON.stringify(a) === JSON.stringify(b);

		// DSH 原生主题 token（--dsw-alias-*，ui-theme 定义）— 几何对齐
		// PluginCard.module.css（knowledge/15 §4.1）。
		const T = {
			bgLayer2: 'var(--dsw-alias-bg-layer-2)',
			bgLayer3: 'var(--dsw-alias-bg-layer-3)',
			bgModulePlatform: 'var(--dsw-alias-bg-module-platform)',
			borderL2: 'var(--dsw-alias-border-l2)',
			brand: 'var(--dsw-alias-brand-primary)',
			error: 'var(--dsw-alias-state-error-primary)',
			labelPrimary: 'var(--dsw-alias-label-primary)',
			labelSecondary: 'var(--dsw-alias-label-secondary)',
			labelTertiary: 'var(--dsw-alias-label-tertiary)',
			labelDimmed: 'var(--dsw-alias-label-dimmed)',
		};

		// Card chrome geometry (PluginCard.module.css parity).
		const cardShell = {
			listStyle: 'none',
			border: `1px solid ${T.borderL2}`,
			borderRadius: 12,
			background: T.bgLayer3,
			transition: 'border-color .16s, background .16s',
		};
		const cardShellOpen = { background: T.bgLayer2, borderColor: T.labelDimmed };
		const headerStyle = {
			width: '100%',
			appearance: 'none',
			border: 0,
			background: 'none',
			font: 'inherit',
			color: 'inherit',
			textAlign: 'left',
			cursor: 'pointer',
			display: 'flex',
			alignItems: 'center',
			gap: 12,
			padding: '14px 16px',
			borderRadius: 12,
		};
		const headTextStyle = { flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 4 };
		const nameStyle = { fontSize: 15, fontWeight: 600, lineHeight: 1.4, color: T.labelPrimary };
		const descriptionStyle = { fontSize: 13, lineHeight: 1.5, color: T.labelTertiary };
		const dirtyPillStyle = {
			flex: 'none',
			borderRadius: 999,
			padding: '1px 8px',
			fontSize: 11,
			lineHeight: '17px',
			fontWeight: 500,
			whiteSpace: 'nowrap',
			background: T.bgModulePlatform,
			color: T.labelSecondary,
		};
		const bodyStyle = { borderTop: `1px solid ${T.borderL2}`, margin: '0 16px', paddingBottom: 8 };

		const style = {
			row: { padding: '8px 0', borderTop: `1px solid ${T.borderL2}` },
			head: { display: 'flex', alignItems: 'baseline', gap: '10px', flexWrap: 'wrap' },
			title: { flex: 'none', margin: 0, fontSize: '13px', fontWeight: 500, color: T.labelPrimary, lineHeight: 1.5 },
			leaves: { flex: 1, display: 'flex', flexWrap: 'wrap', justifyContent: 'flex-end', gap: '2px 12px' },
			leaf: { display: 'inline-flex', alignItems: 'center', gap: '5px', fontSize: '12px', color: T.labelSecondary },
			checkbox: { accentColor: T.brand, width: 13, height: 13, margin: 0 },
			hint: { margin: '1px 0 0', fontSize: '12px', color: T.labelTertiary, lineHeight: 1.5 },
			reset: { flex: 'none', font: 'inherit', border: 'none', background: 'none', cursor: 'pointer', color: T.labelSecondary, fontSize: '12px', padding: 0 },
			note: { margin: '10px 0 0', fontSize: '12px', color: T.labelTertiary, lineHeight: 1.6 },
			footer: { display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 8, padding: '12px 0 4px', borderTop: `1px solid ${T.borderL2}` },
			failText: { flex: 1, minWidth: 0, margin: 0, fontSize: 12, lineHeight: 1.5, color: T.error },
			resetAll: { marginRight: 'auto', font: 'inherit', border: 'none', background: 'none', cursor: 'pointer', color: T.labelSecondary, fontSize: '12px', padding: 0 },
		};

		/** Collapse chevron: the shell-seeded icon, or a text glyph when absent. */
		function Chevron({ open }) {
			return ChevronIcon
				? h(ChevronIcon, {
					style: {
						flex: 'none',
						color: T.labelTertiary,
						transition: 'transform .16s',
						transform: open ? 'rotate(180deg)' : undefined,
					},
				})
				: h('span', { style: { flex: 'none', color: T.labelTertiary, fontSize: 12 } }, open ? '▾' : '▸');
		}

		/** Card header: name, description, the unsaved pill, and the chevron. */
		function CardHeader({ open, dirty, onToggle }) {
			return h('button', {
				type: 'button',
				'aria-expanded': open,
				'aria-label': `${open ? '收起' : '展开'}: 权限守护`,
				onClick: onToggle,
				style: headerStyle,
			},
				h('span', { style: headTextStyle },
					h('span', { style: nameStyle }, '权限守护'),
					h('span', { style: descriptionStyle }, 'AI 工具调用对敏感文件（.env/.git/凭据）、系统区写入与破坏性命令的拦截开关'),
				),
				dirty ? h('span', { style: dirtyPillStyle }, '未保存') : null,
				h(Chevron, { open }),
			);
		}

		/** One category row: title, inline leaf toggles, and the row reset. */
		function CategoryRow({ cat, keys, value, overridden, writable, busy, first, onToggleLeaf, onReset }) {
			const toggles = keys.map((leaf) =>
				h('label', { key: leaf, style: style.leaf },
					h('input', {
						type: 'checkbox',
						style: style.checkbox,
						disabled: !writable || busy,
						checked: value[leaf] === true,
						onChange: (event) => onToggleLeaf(cat, leaf, event.target.checked),
					}),
					h('span', null, LEAF_LABEL[leaf] || leaf),
				),
			);
			// Body already carries the card's top border; first row drops its own.
			return h('div', { style: first ? { ...style.row, borderTop: 'none' } : style.row },
				h('div', { style: style.head },
					h('h4', { style: style.title }, CATEGORY_LABEL[cat] || cat),
					h('div', { style: style.leaves }, toggles),
					h('button', {
						type: 'button',
						style: { ...style.reset, opacity: writable && !busy && overridden ? 1 : 0.4, cursor: writable && !busy && overridden ? 'pointer' : 'default' },
						disabled: !writable || busy || !overridden,
						onClick: () => onReset(cat),
					}, '重置'),
				),
				h('p', { style: style.hint }, CATEGORY_HINT[cat] || ''),
			);
		}

		/** The category-independent unverifiable fail-safe row (single toggle). */
		function UnverifiableRow({ value, overridden, writable, busy, onSet, onReset }) {
			return h('div', { style: style.row },
				h('div', { style: style.head },
					h('h4', { style: style.title }, '动态目标 fail-safe'),
					h('div', { style: style.leaves },
						h('label', { style: style.leaf },
							h('input', {
								type: 'checkbox',
								style: style.checkbox,
								disabled: !writable || busy,
								checked: value === true,
								onChange: (event) => onSet(event.target.checked),
							}),
							h('span', null, '启用'),
						),
					),
					h('button', {
						type: 'button',
						style: { ...style.reset, opacity: writable && !busy && overridden ? 1 : 0.4, cursor: writable && !busy && overridden ? 'pointer' : 'default' },
						disabled: !writable || busy || !overridden,
						onClick: () => onReset('unverifiable'),
					}, '重置'),
				),
				h('p', { style: style.hint }, '命令重建后仍含动态 $() 目标时的保守拦截（慎关：检测力下降）'),
			);
		}

		/** Footer: failure diagnostic + reset-all + discard/save (PluginCard parity). */
		function Footer({ failed, blocked, busy, anyOverridden, hoverDiscard, focusEl, onDiscard, onSave, onResetAll, onHoverDiscard, onFocus }) {
			const focusOutline = (el) => (focusEl === el ? { outline: `2px solid ${T.brand}`, outlineOffset: 1 } : {});
			const resetAllUsable = !busy && anyOverridden;
			return h('div', { style: style.footer },
				failed ? h('p', { style: style.failText }, failed) : null,
				h('button', {
					type: 'button',
					style: { ...style.resetAll, opacity: resetAllUsable ? 1 : 0.4, cursor: resetAllUsable ? 'pointer' : 'default' },
					disabled: !resetAllUsable,
					onClick: onResetAll,
				}, '全部重置'),
				h('button', {
					type: 'button',
					disabled: blocked,
					onClick: onDiscard,
					onMouseEnter: () => onHoverDiscard(true),
					onMouseLeave: () => onHoverDiscard(false),
					onFocus: () => onFocus('discard'),
					onBlur: () => onFocus(null),
					style: {
						appearance: 'none',
						border: `1px solid ${!blocked && hoverDiscard ? T.labelDimmed : T.borderL2}`,
						borderRadius: 8,
						padding: '5px 14px',
						font: 'inherit',
						fontSize: 13,
						lineHeight: 1.5,
						cursor: blocked ? 'default' : 'pointer',
						background: 'none',
						color: !blocked && hoverDiscard ? T.labelPrimary : T.labelSecondary,
						opacity: blocked ? 0.4 : 1,
						...focusOutline('discard'),
					},
				}, '放弃'),
				h('button', {
					type: 'button',
					disabled: blocked,
					onClick: onSave,
					onFocus: () => onFocus('save'),
					onBlur: () => onFocus(null),
					style: {
						appearance: 'none',
						border: '1px solid transparent',
						borderRadius: 8,
						padding: '5px 14px',
						font: 'inherit',
						fontSize: 13,
						lineHeight: 1.5,
						cursor: blocked ? 'default' : 'pointer',
						background: T.labelPrimary,
						color: T.bgLayer3,
						opacity: blocked ? 0.4 : 1,
						...focusOutline('save'),
					},
				}, busy ? '保存中…' : '保存'),
			);
		}

		/** Card component: one per namespace, staging the leaf toggles into one save. */
		function GuardCard({ scope }) {
			const [open, setOpen] = useState(false);
			// null draft = untouched (the authoritative value shows through);
			// a non-null draft is the user's uncommitted edit overlay.
			const [draft, setDraft] = useState(null);
			const [busy, setBusy] = useState(false);
			const [failed, setFailed] = useState(null);
			const [hoverDiscard, setHoverDiscard] = useState(false);
			const [focusEl, setFocusEl] = useState(null);
			const snapshot = React.useSyncExternalStore(scope.subscribe, scope.getSnapshot);

			const shell = open ? { ...cardShell, ...cardShellOpen } : cardShell;
			const ready = snapshot && snapshot.status === 'ready';
			const current = normalized(ready ? snapshot.value : undefined);
			const shown = draft ?? current;
			const dirty = draft !== null && !equalValue(draft, current);
			const overridden = ready && typeof snapshot.user === 'object' && snapshot.user !== null ? snapshot.user : {};
			const writable = ready && snapshot.writable === true;
			const blocked = !dirty || busy || !writable;

			const header = h(CardHeader, { open, dirty, onToggle: () => setOpen(!open) });
			if (!ready) {
				return h('li', { style: shell },
					header,
					open ? h('div', { style: bodyStyle },
						h('p', { style: { ...style.note, padding: '12px 0 0' } }, snapshot && snapshot.status === 'unavailable'
							? '当前会话不提供设置服务，配置来自插件行（启动时生效）。'
							: '正在加载配置…'),
					) : null,
				);
			}

			const toggleLeaf = (cat, leaf, checked) => {
				const base = draft ?? current;
				setDraft({ ...base, [cat]: { ...base[cat], [leaf]: checked } });
				setFailed(null);
			};
			const toggleUnverifiable = (checked) => {
				setDraft({ ...(draft ?? current), unverifiable: checked });
				setFailed(null);
			};
			/** Staged save: every dirty field in ONE atomic scope.mutate. */
			const save = async () => {
				if (blocked || draft === null) return;
				setBusy(true);
				setFailed(null);
				const ops = [];
				for (const field of FIELDS) {
					if (JSON.stringify(draft[field]) !== JSON.stringify(current[field])) {
						ops.push({ op: 'set', path: [field], value: draft[field] });
					}
				}
				try {
					if (ops.length > 0) await scope.mutate(ops);
					// Host validate rejection resolves normally and rolls the
					// snapshot back (settings-scope recovery read) — confirm the
					// committed value actually matches the draft.
					const fresh = scope.getSnapshot();
					const committed = fresh && fresh.status === 'ready' ? normalized(fresh.value) : current;
					if (!equalValue(committed, draft)) {
						setFailed('保存被 Host 校验拒绝，已回滚为当前生效值；草稿保留，请调整后重试。');
						return;
					}
					setDraft(null);
					setOpen(false); // official PluginCard: collapse after a settled save
				} catch (error) {
					setFailed(`写入失败（请求未达 Host）：${error && error.message ? error.message : String(error)}`);
				} finally {
					setBusy(false);
				}
			};
			const discard = () => {
				setDraft(null);
				setFailed(null);
			};
			/** Immediate row reset: clears the user override, then re-syncs the draft. */
			const resetField = async (field) => {
				if (!writable || busy) return;
				setBusy(true);
				setFailed(null);
				try {
					await scope.unset(field);
					const fresh = scope.getSnapshot();
					const committed = fresh && fresh.status === 'ready' ? normalized(fresh.value) : null;
					if (committed) {
						setDraft((d) => {
							if (d === null) return d;
							const next = { ...d, [field]: committed[field] };
							return equalValue(next, committed) ? null : next;
						});
					}
				} catch (error) {
					setFailed(`重置失败（请求未达 Host）：${error && error.message ? error.message : String(error)}`);
				} finally {
					setBusy(false);
				}
			};
			/** Immediate reset-all: clears every user override in one mutation. */
			const resetAll = async () => {
				if (!writable || busy) return;
				setBusy(true);
				setFailed(null);
				try {
					await scope.mutate(FIELDS.map((field) => ({ op: 'unset', path: [field] })));
					setDraft(null);
				} catch (error) {
					setFailed(`重置失败（请求未达 Host）：${error && error.message ? error.message : String(error)}`);
				} finally {
					setBusy(false);
				}
			};

			const rows = Object.entries(CATEGORIES).map(([cat, keys], index) =>
				h(CategoryRow, {
					key: cat,
					cat,
					keys,
					value: shown[cat],
					overridden: overridden[cat] !== undefined,
					writable,
					busy,
					first: index === 0,
					onToggleLeaf: toggleLeaf,
					onReset: resetField,
				}),
			);

			return h('li', { style: shell },
				header,
				open ? h('div', { style: bodyStyle },
					rows,
					h(UnverifiableRow, {
						value: shown.unverifiable,
						overridden: overridden.unverifiable !== undefined,
						writable,
						busy,
						onSet: toggleUnverifiable,
						onReset: resetField,
					}),
					h('p', { style: style.note },
						'修改在本地暂存，点「保存」统一写入用户设置文档（settings.yaml）并立即生效于后续判定；「重置」清除对应项的用户覆盖、回落插件行默认。',
					),
					h(Footer, {
						failed,
						blocked,
						busy,
						anyOverridden: Object.keys(overridden).length > 0,
						hoverDiscard,
						focusEl,
						onDiscard: discard,
						onSave: save,
						onResetAll: resetAll,
						onHoverDiscard: setHoverDiscard,
						onFocus: setFocusEl,
					}),
				) : null,
			);
		}

		/** Cordis client plugin: names must match the Host half's namespace. */
		const name = 'dsh-guardrails';
		const inject = ['slots', 'settingsScope'];

		function apply(ctx) {
			const scope = ctx.settingsScope.bind({ namespace: NS });
			// The inject face is registered WITHOUT the reserved `hooks` key: the
			// renderer consumes that compartment (each member becomes a use<Name>
			// selector hook and `hooks` never reaches the component's props).
			// A plain member passes through verbatim (the skill-manager card uses
			// the same shape), and its object identity is kept so the uSES
			// subscribe side stays referentially stable across renders.
			const face = {
				scope: {
					getSnapshot: () => scope.getSnapshot(),
					subscribe: (listener) => scope.subscribe(listener),
					set: (field, value) => scope.set(field, value),
					unset: (field) => scope.unset(field),
					mutate: (ops) => scope.mutate(ops),
				},
			};
			ctx.slots.inject('settings.plugin.item', function* () {
				yield ctx.slots.register({
					name: 'settings.plugin.item',
					key: NS,
					inject: () => face,
				}, GuardCard);
			});
		}

		exports.name = name;
		exports.inject = inject;
		exports.apply = apply;
		return module.exports;
	},
});
