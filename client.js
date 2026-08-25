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
 * rejected by the bundle-purity gate): it reads the bound settings scope's
 * snapshot (resolved value / base / user layers, revision, writability) and
 * writes fields through the scope, whose revision fencing is owned by the
 * DSH settings surface.
 */
window.__ModuleLoader__.load({
	id: 'dsh-guardrails',
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
		const React = require('react');

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

		const leafDefaults = (keys) => Object.fromEntries(keys.map((k) => [k, true]));
		const DEFAULT_VALUE = {
			env: leafDefaults(CATEGORIES.env),
			git: leafDefaults(CATEGORIES.git),
			credentials: leafDefaults(CATEGORIES.credentials),
			system: leafDefaults(CATEGORIES.system),
			destructive: leafDefaults(CATEGORIES.destructive),
			unverifiable: true,
		};
		const RESET_ALL = {
			env: null, git: null, credentials: null, system: null, destructive: null, unverifiable: null,
		};

		// Resolved value may be boolean (v1 category form) or a leaf object;
		// normalize to leaf objects for the toggle UI.
		const normalized = (value) => {
			const v = typeof value === 'object' && value !== null ? value : {};
			const out = { unverifiable: v.unverifiable !== false };
			for (const [cat, keys] of Object.entries(CATEGORIES)) {
				const raw = v[cat];
				if (raw === true || raw === undefined) out[cat] = leafDefaults(keys);
				else if (raw === false) out[cat] = Object.fromEntries(keys.map((k) => [k, false]));
				else out[cat] = Object.fromEntries(keys.map((k) => [k, raw[k] !== false]));
			}
			return out;
		};

		const style = {
			card: { padding: '12px 0' },
			row: { padding: '10px 0', borderTop: '1px solid var(--dsw-alias-border-l2, #e5e7eb)' },
			head: { display: 'flex', alignItems: 'center', gap: '8px' },
			title: { flex: 1, margin: 0, fontSize: '13px', fontWeight: 500, color: 'var(--dsw-alias-label-primary, #111827)', lineHeight: 1.5 },
			hint: { margin: '2px 0 0', fontSize: '12px', color: 'var(--dsw-alias-label-tertiary, #9ca3af)', lineHeight: 1.5 },
			leaf: { display: 'flex', alignItems: 'center', gap: '6px', marginTop: '6px', fontSize: '12px', color: 'var(--dsw-alias-label-secondary, #4b5563)' },
			leafLabel: { minWidth: '52px' },
			reset: { font: 'inherit', border: 'none', background: 'none', cursor: 'pointer', color: 'var(--dsw-alias-label-secondary, #4b5563)', fontSize: '12px', padding: 0 },
			resetAll: { display: 'block', margin: '12px 0 0', font: 'inherit', border: 'none', background: 'none', cursor: 'pointer', color: 'var(--dsw-alias-label-secondary, #4b5563)', fontSize: '12px', padding: 0 },
			note: { margin: '10px 0 0', fontSize: '12px', color: 'var(--dsw-alias-label-tertiary, #9ca3af)', lineHeight: 1.6 },
		};

		/** Card component: one per namespace, rendering the leaf toggles. */
		function GuardCard({ scope }) {
			const snapshot = React.useSyncExternalStore(scope.subscribe, scope.getSnapshot);
			if (!snapshot || snapshot.status !== 'ready') {
				return React.createElement('div', { style: style.note }, snapshot && snapshot.status === 'unavailable'
					? '当前会话不提供设置服务，配置来自插件行（启动时生效）。'
					: '正在加载配置…');
			}
			const value = normalized(snapshot.value);
			const overridden = typeof snapshot.user === 'object' && snapshot.user !== null ? snapshot.user : {};
			const writable = snapshot.writable === true;
			const setField = (field, fieldValue) => { scope.set(field, fieldValue).catch(() => {}); };
			const clearField = (field) => { scope.unset(field).catch(() => {}); };

			const rows = Object.entries(CATEGORIES).map(([cat, keys]) => {
				const rowValue = value[cat] || leafDefaults(keys);
				const isOverridden = overridden[cat] !== undefined;
				const toggles = keys.map((leaf) =>
					React.createElement('label', { key: leaf, style: style.leaf },
						React.createElement('input', {
							type: 'checkbox',
							disabled: !writable,
							checked: rowValue[leaf] === true,
							onChange: (event) => {
								const next = { ...rowValue, [leaf]: event.target.checked };
								setField(cat, next);
							},
						}),
						React.createElement('span', { style: style.leafLabel }, LEAF_LABEL[leaf] || leaf),
					),
				);
				return React.createElement('div', { key: cat, style: style.row },
					React.createElement('div', { style: style.head },
						React.createElement('h4', { style: style.title }, CATEGORY_LABEL[cat] || cat),
						React.createElement('button', {
							type: 'button',
							style: style.reset,
							disabled: !writable || !isOverridden,
							onClick: () => clearField(cat),
						}, '重置'),
					),
					React.createElement('p', { style: style.hint }, CATEGORY_HINT[cat] || ''),
					toggles,
				);
			});

			const unverifiableRow = React.createElement('label', { key: 'unverifiable', style: style.row },
				React.createElement('div', { style: style.head },
					React.createElement('h4', { style: style.title }, '动态目标 fail-safe'),
					React.createElement('button', {
						type: 'button',
						style: style.reset,
						disabled: !writable || overridden.unverifiable === undefined,
						onClick: () => clearField('unverifiable'),
					}, '重置'),
				),
				React.createElement('p', { style: style.hint }, '命令重建后仍含动态 $() 目标时的保守拦截（慎关：检测力下降）'),
				React.createElement('label', { style: style.leaf },
					React.createElement('input', {
						type: 'checkbox',
						disabled: !writable,
						checked: value.unverifiable === true,
						onChange: (event) => setField('unverifiable', event.target.checked),
					}),
					React.createElement('span', { style: style.leafLabel }, '启用'),
				),
			);

			return React.createElement('div', { style: style.card },
				rows,
				unverifiableRow,
				React.createElement('button', {
					type: 'button',
					style: style.resetAll,
					disabled: !writable || Object.keys(overridden).length === 0,
					onClick: () => { for (const field of Object.keys(RESET_ALL)) clearField(field); },
				}, '全部重置为默认'),
				React.createElement('p', { style: style.note },
					'配置写入用户设置文档（settings.yaml），立即生效于后续判定；标记为「已覆盖」的项可单独重置回插件行默认。',
				),
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
