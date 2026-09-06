# Changelog

## 1.4.0（当前，未发布）

### 修复

- **判定基准目录来源失效（DSR-007）**：旧实现读 `session.meta.cwd`，而 0.1.2-rc.1 的 `Session` 公开面只有 `header`（`meta` 仅是 `create()` 的输入选项）——读取链恒为 `undefined`，base 静默落到部署 fallback 根（DSH 进程启动目录），相对路径判定坐标系错误。改为与官方工具链同一身份：`sandboxPolicy.resolve({ session }).workspaceRoot`（规范化 `session.header.cwd`；agentless 回落部署根；无 sandbox-policy 服务降级为 `''`）。新增 `test/base-dir.test.mjs` 锁定调用形状与降级分支。
- **设置写入静默吞异常**（质量地板 error）：浏览器半侧 `scope.set/unset` 的裸 `.catch(() => {})` 改为 `console.warn` 留痕——写入失败非致命（快照不动，用户可见未生效），但绝不无声。

### 变更

- **结构对齐 core/adapter 单包分层约定**（仓库 0.1.2-rc.1 知识库硬性约定）：`lib/` 四模块迁 `src/core/` 并拆出 `check-command.js`（pwsh 判定管线）与 `deny-messages.js`（文案 + leaf 门控）两个纯模块，core 共六模块（禁 `@deepseek-ai/*` import，仓库分层门禁从空转变为实质生效）；入口迁 `src/adapter/host.js`，包根 `index.js` 变为薄转发；浏览器半侧迁 `src/client/card.js`（`exports["./client"]` 直指，无构建管线不变）。
- **settings 接线改官方 `installSection`**（0.1.2-rc.1 消费方首选 API）：删除手写 register/effect 回落逻辑；entry config 原样注册为 base 层（原为归一化叶子后注册——resolved 值语义不变，`describe` 的 base 显示形状随官方语义）。
- **`assessDestructive` 按六子族拆分**（git/machine/eval/cli/bulk/target，与 DSR-006 配置叶子一一同构），主函数降为调度循环；`GuardCard` 拆子组件（Chevron/CardHeader/CategoryRow/UnverifiableRow）。
- **包元数据对齐**：`peerDependencies` 新增 `@deepseek-ai/cordis ^4.0.2` 与 `@deepseek-ai/dsh-settings ^0.1.2-rc.1`（共享宿主安装树同一实例的元数据约定；纯 JS 无类型编译，不进 devDependencies）；`engines.node` 升 `^22.19.0 || >=24`（0.1.2-rc.1 基线）。
- **verify 对齐部署现实**：组合断言与启动冒烟改用 `DSH_BIN` 指定的实例版本二进制（AGENTS.md 跨代红线；缺省回落遗留全局 CLI 时打印告警）；双 HOME 支持（`DSH_TEST_HOME`/`DSH_WEB_HOME`，缺省回落 `DSH_HOME`）；tarball 冒烟断言更新为 `src/` 布局。
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
