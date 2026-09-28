# Changelog

## 1.6.0（当前，未发布）

### 破坏性变更：适配 DSH `0.1.7-rc.2`（新基线 settings / client 模型换代）

> 用户决策：**执行方案 B（单轨适配 0.1.7-rc.2）**，放弃对 `0.1.2-rc.1` 及更早运行时的兼容（web 稳定实例随后升级）。判定依据均为本机机械取证，非文档字面引用。

- **Host settings 接线整体重写**（旧 API 在新基线**零命中**）：`ctx.settings.installSection(...)` 已从 `dsh-settings` 删除（0.1.7-rc.2 只有 `SettingsForms`）。改为 v0.1.7 官方模型——六个 Config 字段全部加 `.volatile()`，`apply` 内 `ctx.inject(['settings'], sctx => sctx.effect(() => sctx.settings.configure({ auto: false }, ctx.fiber)))` 声明自绘页面策略，guard 在**每次判定时**经 `readConfig()` 读 `ref.get()` 活值。⇒ 设置页保存即提交进运行中的 fiber：**无重挂载、无 `onChange` 回调、无 base-layer 注册**。旧模型里"用户设置文档覆盖 base 层 / provider 卸载回落 entry"的语义随之消失（volatile 引用是唯一真相）。
- **Client 接线整体重写**：`ctx.settingsScope.bind({...})` 与 `settings.plugin.item` 在新基线**零命中**（后者已由 `plugins.*` 七件套取代）。改为 `ctx.configForms.get(NS)` 读写 + `ctx.configForms.whileServed([NS], …)` 按需挂载，注册槽位为 **`plugins.row.config`**（key = `dsh-guardrails#guardrails`，行页面由此多出「配置」控件）。反应性改走保留舱 `hooks`（每个成员成为 `use<Name>` selector hook），因为页面传入的 `form` prop 是一次性 `{state, mutate}` 快照，不含 `subscribe`。
- **settings 命名空间改名**：v0.1.7 起命名空间 = **loader 条目 id**，故 `SETTINGS_NS` 由插件自选的 `dsh-guardrails` 改为 **`guardrails`**（与 `cordis.patch.yml` 的行 id 一致）。在 profile 里给该行改名会移动命名空间并使卡片脱钩。
- **图标名迁移**：新 `ui-primitives` 的 190 个图标导出取消了尺寸后缀（旧 75 个全部消失），`IconChevronDownOutline14` → **`IconChevronDownOutlineRegular`**（尺寸改走 `size` prop）。旧名在现代码中 `undefined`，卡片的 typeof 守卫会静默退化为文本箭头。
- **`dsh.client.inject` 修正**：移除 `@deepseek-ai/dsh-client-runtime`（**两代部署树中均不存在**——1.x 遗留名，已改名 `dsh-client-modules`），加入真实依赖 `...-ui-plugin-manager`。
- **peer 范围抬到目标运行时**：`cordis ^4.0.4` / `dsh-settings ^0.1.7-rc.2` / `schemastery ^3.18.4`。0.1.7-rc.2 新增 **peer 版本不兼容门禁**：`@deepseek-ai/dsh*` peer 不满足运行中版本时**整行被自动置 `disabled: true`、插件根本不加载**，实例照常启动、只在 stderr 留一行（最高危的静默变哑）。判定语义为 `semver.satisfies(rt, range, { includePrerelease: true })`。
- **devDependencies 的 schemastery 同步抬到 `^3.18.4`**：`.volatile()` 在 3.18.2 **不存在**（实测 0 命中；3.18.4 为 28 处），旧版会让 `Config` 在 import 期直接抛错。

### ⚠️ 部署顺序是硬性的（实测复核）

在 `0.1.2-rc.1` 等旧运行时上，本版本**整行不加载**（`Config` 在 import 期调用 `.volatile()` → `TypeError: s.volatile is not a function`，已实跑复现），**不是"只少了配置页"**——旧实例上的硬拦截会静默失效。⇒ **先把实例升到 `0.1.7-rc.2`，再挂载/更新本版本**。

### 文档更正（旧表述在新基线反向失真）

- 删除 README / 需求 R-12 / 部署.md 中「重复 insert 导致整个 profile 启动失败（`duplicate loader entry id`）」的表述——该守卫**已被上游 revert 删除**（`dsh-v0.1.7-rc.2` 源码 0 命中，提交 `e07f41d5fd`），重复 id 改为**静默后者胜出**；`--dump-config` 层两代都不做重复 id 判别，核对只能人工按层级进行。
- README / 规则模型 / DSR-008 中 `settings.yaml` 相关表述更新为「本 profile 的 `cordis.patch.yml`」（`settings-file` 提供方与 `settings.yaml` 已删除，遗留文件由 settings 服务导入后改名为 `settings.yaml.imported`）。
- 新增「版本基线」节，写明**不兼容 0.1.2-rc.1 及更早运行时**，以及该结论的三条机械证据。

### 误报修复：引用敏感名不再被当成访问它（DSR-010）

- **现象（实测复现）**：三个文本引用检查（`GIT_DIR_REFERENCE`/`ENV_REFERENCE`/`CRED_TEXT_REFERENCE`）按文本出现判定，于是命令里**引用**敏感名也被硬阻断——`git commit -m "…this shell command references the .git directory…"`（引用的正是本插件自己的拒绝原文）、`git commit -m "fix: load .env earlier"`、`git commit -m "docs: keep .ssh out of the repo"`、`Write-Output "see .git for history"` 全被拦。⇒ 用 `git commit` 记录一份引用了守卫拒绝原文的说明，会被自己的守卫拦住，本轮实测即撞上。
- **修复**：新增 `maskTextSpans()`（`src/core/command.js`），在**仅这三个文本引用检查**之前把"引用位置"抹成等长空白（偏移不变）：① 引号内**含空白且不含路径分隔符**的分段——含空白、不含分隔符只可能指名当前目录下的单个文件名，而 `.git` 本身不含空白，故该分段不可能是 `.git` 目录；② 文本/模式参数的值（`-match` 族与 `-m`/`-Message`/`-Title`/`-Description`/`-Subject`/`-Body`/`-Comment`）。**路径能力参数一律不豁免**（`-Path`/`-LiteralPath`/`-Filter`/`-Include`/`-Exclude`/`-Pattern`/`-Value`/`-Destination`），含 `"C:\Program Files\x\.git\config"`、`'.git/config'`、`Remove-Item -Recurse -Force .git`、`git cat-file --git-dir=.git` 在内的真实路径引用全部照旧拦截。
- 决策与安全性论证见 [DSR-010](docs/decisions/DSR-010-文本引用豁免.md)；机制见 `technical-details/命令文本分析.md`「引用豁免」。
- **已知残余误伤（有意 fail-closed）**：`-Pattern` 的值不豁免（`Select-String -Pattern '\.git'` 仍拦）；无空白且不含分隔符的散文分段不豁免（单独的 `'\.git'` 仍拦）。

### 测试与验证

- 测试 115 → 120：`config.test.mjs` 重写为 volatile 契约（默认值经 `ref.get()` 断言、**六字段全部 volatile** 的显式断言、非法值仍挂载失败）；`settings.test.mjs` 重写为 v0.1.7 模型（`configure` 页面策略、提交后即时生效、提交一字段不扰动其他字段、无 settings 服务按行配置、非 volatile 手写配置仍可判定）。
- 测试 120 → 138：`command.test.mjs` +6（`maskTextSpans` 的散文分段 / 含分隔符分段不豁免 / 参数值豁免 / 路径能力参数不豁免 / 偏移不变 / 抹除与否决定引用判定），`guard.integration.test.mjs` +2（DSR-010 引用放行 6 例、真实敏感路径仍拦 10 例，含 `git commit -m "see .git" -- .env` 证明引用不会给旁边的真引用洗白）。
- 行覆盖 98.22%（门禁 ≥80%）；分层门禁通过（core 6 文件）；`node --check` 全绿；tarball 干净安装 + 导入冒烟通过。
- **test 实测门禁（2026-09-27，测试实例 `0.1.7-rc.2`）已通过并在 DSR-010 之前完成**：`--dump-config` 184 行无重复 id、启动无 `N entries did not activate`／无 `startup failed`／无 `disabling profile plugin`、功能冒烟实测拦截（`tool/result` `isError: true` + 实例日志 `[guardrails] denied pwsh`）、UI 卡片由用户浏览器确认可见可配。⚠️ **该门禁覆盖的是 DSR-010 之前的代码**；本次改的是 pwsh 命令文本判定，**发布/挂载 web 前须重跑门禁**（需重启测试实例）。
- ⚠️ `verify/run-verify.mjs` 的**第 4 步（test profile 启动冒烟）会自行 spawn 一个真实实例** ⇒ **agent 不得运行该脚本的完整流程**（AGENTS.md 红线：实例启停一律走启动器 GUI 或 `dshl`）。agent 侧只可跑第 1/2/3/5 步；第 3 步的 `--dump-config` 组合断言须显式给 `DSH_TEST_HOME`/`DSH_WEB_HOME`，否则会落到遗留的全局 HOME 而误报"test 行数=0"。

## 1.5.0（已发布）

### 安全增强（DSR-009——2026-09-10 用户数据误删事故复盘入闸）

- **`destructive.chain`（无门控链删）**：同一 pwsh 调用内 move/copy/rename（源消耗型 mutator）之后经**无错误门**分隔符（`;`/换行/裸`&`）接带爆炸半径标志（`-Recurse`/`-Force`/`-r`/`-f`、del/rd `/s`）的删除 → 硬阻断。事故形态 `Move-Item -LiteralPath "$in\*" …; Remove-Item "$in" -Recurse -Force` 的放大器：前句静默失败（非终止错误）时删除面对的是**从未被搬空的唯一副本目录**。`a && 删除`（`&&` 链直接门控）与 mutator 自带 `-EA Stop` 视为已设门放行；控制流级门（`try/catch`/`if ($?)`）不建模、按误伤方向拦。
- **`destructive.misuse`（参数误用）**：① `-Literal*` 参数值含 `*`/`?`——`-LiteralPath` 不展开通配符，NTFS 不可能存在此类文件名，语句必败且非终止（事故引信），deny 消息直接教授 `-Path`/精确名两种正解；② removal/mutator 动词的通配解析目标（位置参数/`-Path`）含 `[ ]`——FileSystem provider 按单字符通配类解析（`x[1].md` 亦匹配 `x1.md`），会命中从未指名的文件；`-Include`/`-Exclude`/`-Filter` 值豁免。
- **词法分隔符保真**：`tokenizePwsh` 的 `&&`/`||` 保留双字符原值（旧实现压扁为 `&`/`|`，"有无错误门"在词法层即丢失——chain 判定的前提）。连带修正：`||` 不再被 `eval`（管道进 shell）与 `bulk`（管道批删）误认为管道（`||` 本就不是管道）。
- **显式接受的边界（无状态重申）**：跨回合（分离调用）的"删上一回合 move 落点"不判——会话级 move journal 方案经评估**否决**（状态生命周期/别名等价/误伤论证成本与单一收益不成比例，DSR-009 方向 B），由顶层 AGENTS.md 破坏性命令纪律规程补偿；approval 档维持 DSR-006 否决。
- 配置叶子 6 → 8（`destructive: { …, chain, misuse }`，缺省开，独立可关）；设置卡片、Config schema、`evaluateRules` 随 `CATEGORY_LEAF_KEYS` 自动扩展。
- README：拦截语义、配置示例、已知限制（无状态边界/脚本文件不可见/`[ ]` 的 Windows 语义）同步。

### 测试与验证

- 测试 110 → 115：misuse 正反例、chain 门控矩阵（`&&` 门/EA Stop 门/无门）、事故命令复演 + 双层独立 ablation、`&&`/`||` 词法保真；既有断言同步（rules/config 叶子表、command 分隔符用例）。
- 行覆盖 97.91%（门禁 ≥80%）；`check` 全绿；tarball 干净安装 + 导入冒烟通过；web/web-next `--dump-config` 恰一行基线不变。test profile 启动冒烟按 AGENTS.md 红线留待用户经启动器执行（agent 不起进程）。

## 1.4.0（未发布）

### 修复

- **判定基准目录来源失效（DSR-007）**：旧实现读 `session.meta.cwd`，而 0.1.2-rc.1 的 `Session` 公开面只有 `header`（`meta` 仅是 `create()` 的输入选项）——读取链恒为 `undefined`，base 静默落到部署 fallback 根（DSH 进程启动目录），相对路径判定坐标系错误。改为与官方工具链同一身份：`sandboxPolicy.resolve({ session }).workspaceRoot`（规范化 `session.header.cwd`；agentless 回落部署根；无 sandbox-policy 服务降级为 `''`）。新增 `test/base-dir.test.mjs` 锁定调用形状与降级分支。
- **设置写入静默吞异常**（质量地板 error）：浏览器半侧 `scope.set/unset` 的裸 `.catch(() => {})` 改为 `console.warn` 留痕——写入失败非致命（快照不动，用户可见未生效），但绝不无声。

### 变更

- **结构对齐 core/adapter 单包分层约定**（仓库 0.1.2-rc.1 知识库硬性约定）：`lib/` 四模块迁 `src/core/` 并拆出 `check-command.js`（pwsh 判定管线）与 `deny-messages.js`（文案 + leaf 门控）两个纯模块，core 共六模块（禁 `@deepseek-ai/*` import，仓库分层门禁从空转变为实质生效）；入口迁 `src/adapter/host.js`，包根 `index.js` 变为薄转发；浏览器半侧迁 `src/client/card.js`（`exports["./client"]` 直指，无构建管线不变）。
- **settings 接线改官方 `installSection`**（0.1.2-rc.1 消费方首选 API）：删除手写 register/effect 回落逻辑；entry config 原样注册为 base 层（原为归一化叶子后注册——resolved 值语义不变，`describe` 的 base 显示形状随官方语义）。
- **`assessDestructive` 按六子族拆分**（git/machine/eval/cli/bulk/target，与 DSR-006 配置叶子一一同构），主函数降为调度循环；`GuardCard` 拆子组件（Chevron/CardHeader/CategoryRow/UnverifiableRow）。
- **包元数据对齐（核心包声明按危险类别归位）**：`peerDependencies` 新增 `@deepseek-ai/cordis ^4.0.2` 与 `@deepseek-ai/dsh-settings ^0.1.2-rc.1`（二者不在装载期 import，故无需 devDependencies）；`@deepseek-ai/schemastery` 由 `dependencies` 改判 `peerDependencies ^3.18.2`（范围写法对齐上游 `dsh-settings`）并新增 `devDependencies` 同项——`src/adapter/host.js` 装载期 `import z from '@deepseek-ai/schemastery'`，裸 node 单测必须能解析它，而 profile 侧因自身 `autoInstallPeers: false` 不会把副本装回来。**危险等级分两类，本插件原先只落在较轻的那类上**：`cordis` 与携带 service key 的 `@deepseek-ai/dsh-*` 用 module-local `Symbol()` 作身份（实测 `@deepseek-ai/dsh-tools` lib 内 `const key = Symbol()`），出现第二份物理副本即致命、**版本相同也致命**——本插件对 `cordis`、`dsh-settings` 一直是 peer，未触雷；`schemastery` 的跨边界身份是 `Symbol.for("schemastery")` / `Symbol.for("ValidationError")`（全局注册表 ⇒ 副本之间同一身份），双副本**不产生身份分裂**（实测私装 3.18.1 与安装树 3.18.2 并存数日、工具调用正常），故 schemastery 这项**属清理（少一份冗余拷贝、消除未来版本漂移）而非修 bug**。生态里两种写法并存而非对错之别：`dshmarket`、`deepseek-harness-background` 走 peer，DSH 一方 18 个包（`dsh-llm`、`dsh-tools`、全部 `dsh-tool-*`…）写在 `dependencies`。分类判据见知识库 `04` §7。启动器依赖自检（doctor）会报这类副本，但其判定逻辑拿库自身版本比 DSH 发布版本，**报出来不等于会出事**。`engines.node` 升 `^22.19.0 || >=24`（0.1.2-rc.1 基线）。
- **设置卡片改统一保存模型（官方 PluginCard 暂存草稿语义，knowledge/15 §4.1）**：叶子开关不再即点即写——编辑进本地草稿，「保存」经单次 `scope.mutate()` 原子提交全部脏字段（一个 revision 围栏），「放弃」丢弃草稿；header 显示「未保存」pill，保存成功自动折叠，被拒保留草稿并显示 footer 诊断（对齐 skill-manager 生产范例）；行内「重置」保持即时语义（清除用户覆盖，非编辑操作）。
- **卡片紧凑化**：类别行改为"标题 + 叶子复选框横排 + 行内重置"两行结构（原每叶子一行竖排），复选框用品牌色 token；标题去包名括号（「权限守护」）。
- **verify 对齐部署现实**：组合断言与启动冒烟改用 `DSH_BIN` 指定的实例版本二进制（AGENTS.md 跨代红线；缺省回落遗留全局 CLI 时打印告警）；双 HOME 支持（`DSH_TEST_HOME`/`DSH_WEB_HOME`，web dump 用 `DSH_WEB_BIN`——web profile 属 stable-dev 实例，跨代各自用所属实例二进制）；tarball 冒烟断言更新为 `src/` 布局。
- 全部公开符号 JSDoc 化（code-craft 注释标准）；质量地板 0 error（warning 仅余 client 卡片 UI 几何软指标）。

### 测试与验证

- 测试 105 → 110：新增 `test/base-dir.test.mjs`（5 例）；settings 测试按 `installSection` mock 语义重写；全部 mock 的 session 形状修正为 `header.cwd`（真实形状）。
- 行覆盖 97.87%（门禁 ≥80%）。

## 1.3.0（未发布）

### 修复

- **设置卡片渲染崩溃（slot 注入面协议踩保留键）**：`client.js` 原先按 `inject: () => ({ hooks })` 注册，DSH 渲染器把注入面中**保留键 `hooks`**（成员须为 `{ getSnapshot, subscribe }` 的 `HostObservable` 对）消费成 `use<成员名>` 选择器 hook，`hooks` 键本身不会出现在组件 props——`GuardCard({ hooks })` 解构得到 `undefined`，`hooks.subscribe` 抛 `TypeError`，keyed 条目被渲染器 `reportEntryError` 一次性 abdicate，「插件配置」页无痕（刷新重崩，无任何部署层报错）。改为与 skill-manager 同构的平铺面（`inject: () => face`，`face.scope` 一次性创建、引用稳定），组件按 `{ scope }` 消费。
- **cordis 4.x 兼容：`ctx.inject()` 不再接受裸字符串依赖名**（dsh 内置 `@deepseek-ai/cordis@4.0.1` 的 `Inject` 只接受数组/对象，裸字符串会在 `Inject.resolve` 的 `Reflect.has` 上抛 `TypeError: Reflect.has called on non-object`，导致 profile 启动失败）。`apply()` 内的 settings 注入改为数组形式 `ctx.inject(['settings'], ...)`；`test/settings.test.mjs` 的 mock 同步按 cordis 4.x 语义接收数组/字符串两种形态。
- **设置卡片外观对齐官方 PluginCard 几何**：卡片从"裸表单"（纯 div + 内联 style，无折叠壳）改为与官方同构的折叠卡片——`li > button.header（名称/描述/折叠箭头，`aria-expanded` + 本地 `useState` 展开/收起）> body（border-top + margin 0 16px）`；主题 token 全部使用 `--dsw-alias-*`（ui-theme），几何对齐 `PluginCard.module.css`；折叠箭头复用 `@deepseek-ai/dsh-client-ui-primitives` 的 `IconChevronDownOutline14`（缺失时降级为文本箭头，绝不让整卡渲染失败），`dsh.client.inject` 相应补 `@deepseek-ai/dsh-client-ui-primitives`（shell-seeded static UI library，无需 client entry）。写入仍为即时模型（无暂存表单，故无保存/放弃 footer）。

### 变更

- **设置页配置入口（官方 settings 卡片范式）**：配置现在可出现在 设置 → 插件 → **插件配置**——
  - Host 半侧注册 `dsh-guardrails` settings 命名空间：插件行 config 作为 **base 层**，用户设置文档覆盖它，**提交即热生效**（settings 服务卸载时回落行配置，无 settings 服务时完全按行配置工作）；
  - 浏览器半侧新增 `client.js`（DSH client 模块系统的惰性 CJS bundle）：向 `settings.plugin.item` 按同名 key 注册卡片（每个防御层叶子开关 + 已覆盖标记/重置 + 写回 `settings.yaml`），与 Host 命名空间自动配对；
  - `package.json`：`exports["./client"]`、`dsh.client`（platform web，inject runtime/ui-settings）、`files` 加入 `client.js`。
- 版本 1.3.0。

### 测试与验证

- 新增 `test/settings.test.mjs`：命名空间注册与 base 层、用户覆盖热生效（含 v1 布尔形态归一化）、provider 卸载回落 entry、无 settings 服务兼容。
- `verify` 冒烟断言加入 `client.js` 随包检查。

## 1.2.0（未发布）

### 变更

- **配置入口按 DSH 官方范式（0.1.1）**：插件导出 Schemastery `Config` schema（新增运行时依赖 `@deepseek-ai/schemastery`），loader 在 `apply` 前验证行内 `config` 块并填充默认值（默认全开）——非法类型在加载期报 `ValidationError` 并挂载失败；插件形态改为官方具名导出（`name` / `inject` / `Config` / `apply`，移除 default export）。
- **bundle 行不再显式列默认值**：默认值只属于 plugin config boundary（schema 的 `.default()`），`cordis.patch.yml` 行只保留 `id`/`name`；未知键/未知子键仍由 `evaluateRules` 拒绝（schema 对象对未知键透传）。

### 测试与验证

- 新增 `test/config.test.mjs`：schema 默认值填充、对象形式缺省子键补全、非法类型拒绝。
- 冒烟断言更新为具名导出形态（`name`/`apply`/`Config`）。

### 发布与开源

- 开源协议：MIT（`LICENSE`，Copyright © 2026 FengZhiHen1）；`package.json` 补充 `license` 与 `repository` 字段。
- 源码仓库：`github.com/FengZhiHen1/dsh-guardrails`；web profile 改由 `github:` 钉 ref 的 git 依赖安装（发布物形态，非源码直挂）。

## 1.1.0（未发布）

### 变更

- **防御层全量配置化（DSR-006）**：所有防御层改为叶子级可配——类别键接受布尔（= 整类开/关）或对象（= 按操作/子族细分，子键缺省继承 true），缺省全开：
  - 操作级叶子：`env`/`git` 为 `{ read, modify }`，`credentials` 为 `{ read, modify, list }`，`system` 为 `{ write }`；
  - `destructive` 由总开关拆为六个独立子族 `{ git, machine, eval, cli, bulk, target }`（分组：git 高危 / 机器级与清空 / 不可信执行 / 数据破坏 CLI / 管道批删 / 删除目标分析）；
  - 新增 `unverifiable` 键（动态 `$()` 目标 fail-safe，缺省开——由"不可关"改为可关，README 标注风险）；
  - 命令文本层按动词分类（`classifyVerb` → read/modify/list）匹配对应操作叶子，与路径层语义一致。
- **向后兼容**：v1 五键布尔写法继续有效（等价于对应类别全开/全关）；非法配置（未知键、未知子键、非布尔、非对象、数组）挂载即失败。

### 测试与验证

- 新增叶子矩阵用例：`evaluateRules` 归一化/布尔兼容/非法值、`classifyVerb`/`assessContentClass`、destructive 六子族独立门控、集成层 op 级叶子与 `unverifiable` 开关。
- 覆盖率门禁维持 → `npm run verify` 全绿。

## 1.0.0（未发布）

### 变更

- **sessions 类别移除**：`.dsh` 目录（含 `sessions/` 会话历史）不再被拦截，读/写/改/删与列举全部放行（配置键 `sessions` 随之移除，传入即报 unknown key）。凭据文件名单（`.dsh` 下的 `.credentials.yaml`、`.auteur-media-secret` 等）不受影响。

### 安全增强
- **system 类别（W0，DSR-001/DSR-005 落地）**：写入 Windows 系统区（`C:\Windows`/`C:\Program Files`/`C:\Program Files (x86)`/`C:\ProgramData`/`C:\Recovery`、用户启动目录、PowerShell Profile）硬阻断；读与列举放行。覆盖 write/edit 工具与 pwsh 写类动词/重定向/cd 链。
- **credentials 范围 B 名单**：新增 `.git-credentials`、`NTUSER.DAT`（含事务日志）、`UsrClass.dat`、`pagefile.sys`、`hiberfil.sys`、浏览器资料（Chrome/Edge/Firefox）、Windows 凭据/DPAPI（`Microsoft\Credentials`、`Microsoft\Protect`）、系统 Hive（`System32\config\SAM`/`SECURITY`/`SYSTEM`）；命令文本引用同步扩充。
- **绝对盘根删除拦截**：`Remove-Item C:\`/`D:\`/`/` 及 `C:\*` 通配形态、`rd C:\ /s /q` 等不再放行；`$pwd\*` 形态并入工作区根删除判定。

### 配置与健壮性
- 新增 `system` 配置键（缺省全开）；`cordis.patch.yml` 显式列出全部六个开关。
- **配置校验**：未知键、非布尔值、非对象配置在挂载时失败并给出可操作错误（不再静默强转）。
- `package.json` 声明 `engines.node >= 20`。

### 测试与验证
- 新增生命周期测试（mount/dispose/remount ×20、HMR 重放、双挂载不静默去重、非法配置挂载失败）。
- verify 新增 tarball 干净目录安装 + 导入冒烟；组合断言覆盖 test/web 各恰一行。
- 覆盖率：行 96.07% / 分支 93.07% / 函数 93.75%（门禁 ≥80%）。

### 文档
- README 补充覆盖工具清单、系统区矩阵、已知限制与边界、常见错误与排查；同步 web 部署现状（dist tarball 过渡形态）。
- 设计文档同步：rule-model 范围 B 标记已实现、engineering 模块职责/依赖图/测试矩阵更新、DSR-001 实现状态注记。
