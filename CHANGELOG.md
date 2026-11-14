# Changelog

本文件记录面向用户的可见变更：每个版本列出新增、变更、修复与移除的行为。内部验证过程、测试日志与环境取证不入此处。版本号序列按时间保留；`3.x` 为版本线重置前的历史（均未发布）。

## 0.2.0

### 灾难性删除标准、git 分级与框架工具放宽（v4）

- **口径调整**：插件只防**灾难性删除**，分三级——L1 直接拒绝（物理设备、宿主系统整树、`.git` 元数据、销毁 git 历史的子命令）；L2 可识别命令行删除计数，≤20 放行、>20 拒绝；L3 其余一律放行。不再声称“拦截所有删除”。
- **未知程序名放行**：`Test-Path`/`Copy-Item`/`New-Item`/`whoami` 等未建模程序不再因名字拒绝。执行通道（`env/xargs/sudo/start/source`、WSL、无法分析的 shell 脚本、动态命令文本）仍拒绝。
- **git 分级与证据计数**：`git` 从命令名拒绝表移除，改由 `assessGit` 分类——允许 `status/log/add/commit/branch/switch/merge/rebase/fetch/pull/reflog/rev-parse`、`worktree add|list|prune`、`branch -D`、`tag -d`、裸 `gc`；立即拒绝 `stash clear|drop`、`gc --prune=now`、`filter-branch`、`filter-repo`、`push --force/-f/--delete/--mirror`、无路径的 `reset --hard`、`reflog expire --expire=now --all`（`DI-GIT-REFUSE`）。`git clean`（非 `-n`）/`restore <paths>`/`worktree remove <path>` 接入 `git-evidence` 模块计数：clean 与 restore >20 拒绝；worktree remove 要求工作树干净（零未跟踪/未提交改动）、非分离 HEAD、非主 worktree、可重建之外的可忽略条目 ≤20；证据模块不可用一律 fail-closed。git 的 allow 命令不进入通用文件扫描。
- **框架工具放宽**：`create_worktree`、`terminal_open`、**全部** `plugin_manager` 动作放行。
- **`terminal_send` 就地解析**：其 `text` 按平台方言作为命令行分析——可识别删除照常计数/拒绝，无法分析的文本拒绝；`run_code` 仍整体拒绝。
- **`copy` 放行 / `move` 计源删除**：`copy` 不删源、不进删除门禁；`move` 的源删除按 L2 计数，>20 拒绝。
- **边界口径**：工作区之外的删除同样进入 L2 计数（>20 拒绝），不因“在边界外”本身拒绝；物理设备/系统树/`.git` 的 L1 保留。
- 设置页保护范围与能力边界文案按灾难标准改写（中英一致）。决策见 [DSR-020](docs/decisions/DSR-020-灾难性删除标准.md)。

### 语言运行时放行、shell 脚本分析与统一删除强提示（v3）

- **放行语言运行时脚本**：`node/nodejs/python/python3/py/perl/ruby/php/deno/bun/uv` 作为不透明脚本运行器直接允许（不产生删除操作、不计数）。内联代码开关（`node -e/--eval/-p/--print/-i`、`python -c`、`perl -e/-E`、`ruby -e`、`php -r`、stdin `-`）仍以 `DI-INLINE-CODE` 拒绝。
- **shell 脚本文件 AST 分析**：`bash/sh/dash/zsh <脚本文件>` 与 `pwsh/powershell -File <脚本文件>` 在字面路径、存在、常规非链接文件、≤1MiB、编码可判定（UTF-8（含 BOM）、UTF-16LE BOM）时读取文本按该方言解析并计数其内删除；缺失/非常规/过大/编码未知/`source`/`eval`/动态构造→unknown 拒绝。不支持 `./x.sh` 路径限定可执行或 `cmd /c file.bat`。既有 `bash -c`/`pwsh -Command` 语义不变。
- **统一删除强提示**（`DELETION_DOCTRINE`）：所有删除相关的拒绝与受保护文件审批附加同一句英文强提示——要求先列明并核对确切文件集，无法枚举即不得删除。
- 设置页保护范围文案更新：删除需先计数、>20 未白名单拒绝；语言运行时脚本放行；shell 脚本在可分析时按其内容计数、无法证明时拒绝。

### 二次收紧：白名单证据化、挂载边界、预览与边界细化

- 白名单从「形态匹配即减计数」改为**形态匹配 + 证据证明**双重通过才减计数（新增 `disposable-evidence` 证据适配器）：要求可信项目边界精确段包含、非归档/依赖域、非链接逃逸、Git 未跟踪且状态可证、以及配对再生源（Python `.py`、Maven `.java`、TS 有限子集）。未通过一律照常计数。
- **取消 Cargo 依赖产物自动豁免**：`target/*/deps/*` 照常计数；`Cargo.toml` 仅保留为项目边界 marker。TypeScript 明确**有限子集**支持（显式 `tsBuildInfoFile` 与 `rootDir+outDir` 官方公式；仅 `outFile` 无覆盖时照常计数）。
- 新增**挂载边界**适配器：Linux 用 `/proc/self/mountinfo` 有界一次快照，拒绝删除目标处/内部的挂载点（含同设备 bind 挂载）与 boundary→target 跨越；挂载清单不可用/畸形/过期→拒绝。Windows 保留既有 metadata/junction 行为。
- 新增**真实 `Remove-Item -WhatIf` 预览**语义：预览命令不进入删除清单/数量门禁，但仍做路径/凭据扫描；混合调用中真实删除部分仍全量计数；`-Confirm` 非预览。
- 新增**纯 provider/path 谓词**（`isUnsupportedProviderPath`）：拒绝 `Registry:`/`Variable:`/`FileSystem::`/`http:`/裸 `C:foo` 等非本地文件系统路径，在解析前统一拒绝。
- **项目边界与执行 cwd 分离**；边界包含按精确段、区分大小写比较；共享单一扫描预算，超预算拒绝；非法文件名（U+FFFD / 非 well-formed）整次清单拒绝，不漏计。

### 严格删除门禁与固定文件级白名单

- 新增**执行前删除计数与 20 文件硬门禁**：整次调用内统计未命中白名单的常规文件 + 删除的链接条目，目录去重单独报告；`<=20` 完整枚举，`>20` 硬拒绝，不声称精确总数或并发原子。
- 新增**严格未知/不透明拒绝**：未知命令/效果、不透明 shell/解释器/脚本、未知可执行、Git hooks/aliases、分页器、`-exec`、启动/profile 文件、重定向与副作用显式拒绝；未审查工具默认拒绝。
- 新增 **WSL/跨域删除拒绝**：不假设 `/mnt/X` 映射；Windows 上的 bash 删除域无法对应到 Node 路径时要求改用 literal 的 `Remove-Item`。
- 新增**固定文件级白名单**（Python 字节码、pytest、mypy、Maven class、TypeScript buildinfo 等）：只识别常规文件、不读内容、不整树豁免、不支持用户自加；命中只减计数不减保护。
- 新增决策 DSR-019，明确并发与授权边界：审批/自报/dry-run 不构成删除授权，审批后重新计数。

## 0.1.1

- 声明口径统一：`engines.dsh` 由缺省改为 `>=0.2.1-rc.2 <0.3.0-0`；`@deepseek-ai/dsh-settings` peer 同步为同一区间。
- 行为零变化：不改运行期代码。兼容面覆盖 `0.2.1-rc.2` 与 `0.2.2-rc.1`；上限 `<0.3.0-0` 表示未对 0.3 作承诺。

## 0.1.0（版本线重置，未发布）

- 版本线从 3.2.1 重置为 0.1.0：DSH 仍处 0.2.1-rc.2 预发布，插件暂不承诺跨宿主版本的 API/配置稳定性；0.x 内破坏性变更升 minor，兼容功能/修复升 patch。
- 当前源码包含此前未发布的 3.2.0 配置键改名与 3.2.1 设置页改动；旧 3.x 条目保留为历史。
- 插件卡片与设置页头部使用包图标：36×36 双色盾牌 `icon.svg`（纯静态元数据）。

## 3.2.1（未发布）

- 设置页移除内容宽度 680px 上限，改为跟随 Plugins 页内容列（最大 960px）。
- 设置页优先简洁：字段长说明收进标签旁的 info 展开器，可见区只保留短提示与校验错误。

## 3.2.0（未发布）

- 配置键 `credentialsReadAsk` 更名为 `builtinSensitiveAsk`：旧名把范围说窄成“凭据”、动作说窄成“读”，而名单实际包含系统凭据库与分页/休眠文件。不提供别名，旧键按 `unknown config key` 在挂载时显式失败。决定见 [DSR-018](docs/decisions/DSR-018-内置敏感文件名单改名.md)。
- 设置页文案对齐：字段「敏感文件」改为「自定义敏感文件」，开关改为「内置敏感文件」。

## 3.1.0（适配 DSH 0.2.1-rc.2，未发布）

- 目标运行时升级到 `0.2.1-rc.2`：`@deepseek-ai/dsh-settings` peer 下限抬到 `^0.2.1-rc.2`；0.2.0 及更早会被 peer 门禁禁用。
- 设置页改用官方 `plugins.row.config` + `ctx.configForms.get('guardrails')`：订阅 Host 快照、读取 revision/writable、一次 `mutate` 提交三字段；字段几何、保存键与文案对齐官方 `SettingsForm`/`fields`；只用主题 token，不引用 Harness Client 包。
- `run_code` 适配 0.2.1 的 Agent `ctx`/`workingDirectory` 契约；仅测试夹具适配，生产防护语义不变。

## 3.0.0（实施中、未发布）

- 方案对应计划包版本 3.0.0：从 ask-only/依赖 Auto Review 改为 Full Access 下 `Deny > Ask > Allow`；官方持久 pwsh helper + 固定官方 shfmt v3.12.0 typed AST，目标 Windows x64、Linux x64/arm64，不保留自研 tokenizer 回退。决定见 [DSR-017](docs/decisions/DSR-017-官方AST与最终硬门禁.md)。
- 异步 pre-execute 分析，以同 execution 对象 WeakMap 关联，同步 guard 做最终门禁；解析器/协议/关联结果故障 fail-closed。
- `sensitiveFiles` 保持 Profile 精确文件；审批自有默认 120000 ms，legacy `0` 映射 120000 ms。
- 候选 Git/链删/云/数据库/容器/系统逐命令矩阵不默认启用。

## 2.1.0（未发布）

**新增：插件自有审批超时**（`askTimeoutMs`），决策见 [DSR-016](docs/decisions/DSR-016-插件自有审批超时.md)——收窄 DSR-015 的 T-A 边界（全局等待上限仍属上游，本插件只约束自己发起的 ask）。

- 配置新增 `askTimeoutMs`（整数毫秒，默认 `0` = 关闭，上限 3600000，全 `.volatile()`）；`0` 时仍返回原生 `{ kind: 'ask' }`，行为零变化。
- `> 0` 时插件自己调用 `approval.request`：到点 abort，客户端弹窗随 `signal` 收起，工具调用以明确的自动拒绝结束（文案明示“不是用户拒绝、不要反复重试”）。
- 审批层失败改为 **fail-closed**；判定层异常仍 fail-open（DSR-015 不变）。
- 配置页新增「审批超时（毫秒）」行（数字输入 + 本地校验 + 覆盖/重置徽标）。

## 2.0.0（未发布）

**不兼容重构：从「guard 硬阻断」到「pre-execute 原生审批」的职责收缩**，决策见 [DSR-015](docs/decisions/DSR-015-审批式敏感读与职责收缩.md)。

- **不再拒绝任何调用**：删除 `ctx.tools.guard` 钩子与全部 deny 路径；对敏感文件**内容读取**返回 `tools/pre-execute` `{ kind: 'ask' }`，由 DSH 原生一次性审批（allow-once）决定。
- **规则收缩为两层**：内置窄凭据名单 + 用户标记的精确绝对路径（`sensitiveFiles`）。
- **退役类别**：`.env` 全局拦截、`.git` 内部拦截、系统区写、破坏性命令子族、`unverifiable` fail-safe、目录段/密钥后缀/浏览器/DPAPI 规则——上下文相关判断交 DSH 原生 Auto Review 与 OS 权限。
- **触发面收窄为读取**：`read`/`read_image`/单文件 `grep`；`glob`、目录级搜索、一切写改删不触发。
- **配置换代**：`sensitiveFiles: string[]` + `credentialsReadAsk: boolean`，两字段全 `.volatile()`；v1 的六键配置不再被接受。

## 1.7.0

### 安全修复：深度上界曾可致「系统区写」绕过（DSR-012 后果条更正）

- **原判被实测推翻**：子表达式展开深度上限的注释原称“停止展开是保守方向，因为外层已看见文本”。实测证明该论断只对全文本正则类成立，对片段解析类不成立——`Set-Content <系统区路径>` 经多层 `Write-Output "$( ... )"` 包裹可绕过；到界现改为 **fail-closed**。
- 误伤实测：真实命令语料中嵌套深度 ≥ 上限的条目为 0，新增误伤 0。

### 安全修复：私钥后缀进入命令文本通道（DSR-014）

- **缺口**：后缀规则此前只在路径层，文本层没有，故密钥搬出 `.ssh` 后命令文本通道可放行。
- **决定**：新增文本后缀匹配（含 `.pem/.p12/.pfx/.ppk`，有意排除 `.key` 以避免属性访问误报）；两套引用集都含该分支，`.pub` 照旧排除。

### SSH 可用性：`~/.ssh/config` 读放行 + 别名引导（DSR-013）

- **问题**：凭据目录段规则把 `.ssh` 下一切文件当密钥物质，堵死了“用别名”的正路，且把配置读取与密钥物质混为一谈。
- **决定**：新增具名最小例外——`~/.ssh/config` 在**读/列举**通道放行；`id_rsa`、`*.pem`、`known_hosts`、`config.bak`、`sub/config`、`glob ~/.ssh`、写通道、`.kube/config` 全部维持拦截。读写通道同宽，避免从 pwsh 通道溜过。

### 误报修复：裸引号输出语句不再被当成动态命令（DSR-012）

- **现象**：真实语料中大量以裸双引号插值字符串打头的输出语句被误判“命令名动态”而拦截。
- **根因**：命令名动态判定存在范畴错误——裸引号串是输出语句，不是命令位置。
- **同批补上方向相反的漏防**：双引号内 `$(...)` 子表达式曾逃过内容引用、系统区写、破坏性三层，修复为递归跑全部规则。
- **效果**：被拦率显著下降，新增误伤 0。

### 修复：审计日志此前无法定位命令

- 审计行上限过短，拒绝消息前缀占满后日志里命令几乎不可见；改为更长上限并对 pwsh 追加独立 `denied input:` 行。

## 1.6.0（未发布）

### 破坏性变更：适配 DSH `0.1.7-rc.2`（新基线 settings / client 模型换代）

- **Host settings 接线整体重写**：改为全 `.volatile()` 字段 + `settings.configure({ auto: false })` 声明自绘页面，guard 每次判定读活值。
- **Client 接线整体重写**：改为 `ctx.configForms` 读写 + `plugins.row.config` 槽位注册。
- **settings 命名空间改名**：命名空间 = loader 条目 id，由 `dsh-guardrails` 改为 `guardrails`。
- **`dsh.client.inject` 修正**：移除不存在的旧 runtime 名，加入真实依赖。
- **peer 范围抬到目标运行时**：`cordis` / `dsh-settings` / `schemastery` 同步；旧运行时不满足时整行自动禁用（不静默降级）。
- **部署顺序是硬性的**：旧运行时上 `Config` 在 import 期调用 `.volatile()` 会抛错、整行不加载；必须先把实例升到 `0.1.7-rc.2`，再挂载/更新本版本。

### 误报修复：引用敏感名不再被当成访问它（DSR-010）

- **现象**：文本引用检查按文本出现判定，于是命令里**引用**敏感名（如提交信息里写着 `.git`/`.env`/`.ssh`）也被误拦。
- **修复**：新增 `maskTextSpans()`，仅对散文分段与文本/模式参数值做引用豁免；路径能力参数一律不豁免，真实路径引用照旧拦截。

## 1.5.0

### 安全增强（DSR-009——用户数据误删事故复盘入闸）

- **无门控链删**：同一调用内 move/copy/rename 之后经无错误门分隔符接带爆炸半径标志的删除 → 硬阻断（`&&` 链或 `-EA Stop` 视为已设门放行）。
- **参数误用**：`-Literal*` 参数值含通配符、或 removal/mutator 的位置/`-Path` 目标含 `[ ]` 通配类 → 拒绝并给出正解。
- **词法分隔符保真**：`&&`/`||` 保留双字符原值，避免“有无错误门”在词法层丢失。
- 配置叶子 6 → 8（`destructive` 增加 `chain`、`misuse`，缺省开、独立可关）。

## 1.4.0（未发布）

### 修复

- **判定基准目录来源失效（DSR-007）**：旧实现读会话公开面不存在的字段，base 静默落到部署 fallback 根；改为与官方工具链同一身份的 `sandboxPolicy.resolve().workspaceRoot`。
- **设置写入静默吞异常**：浏览器半侧写入失败的裸 `.catch(() => {})` 改为 `console.warn` 留痕。

### 变更

- **结构对齐 core/adapter 单包分层约定**：领域逻辑迁 `src/core/`（禁 `@deepseek-ai/*` import），入口迁 `src/adapter/host.js`，浏览器半侧迁 `src/client/card.js`。
- **设置卡片改统一保存模型**：叶子开关编辑进本地草稿，「保存」原子提交全部脏字段，「放弃」丢弃草稿。
- **包元数据对齐（核心包声明按危险类别归位）**：`cordis` 与携带 service key 的 `@deepseek-ai/dsh-*` 用 module-local 身份、必须 peer；`schemastery` 用全局注册表身份、可 deps。

## 1.3.0（未发布）

### 修复

- **设置卡片渲染崩溃**：注入面误用保留键导致组件解构 `undefined`；改为与官方同构的平铺面。
- **cordis 4.x 兼容**：`ctx.inject()` 不再接受裸字符串依赖名，改为数组形式。
- **设置卡片外观对齐官方 PluginCard 几何**：折叠卡片 + 主题 token，图标缺失时降级为文本箭头。

### 变更

- **设置页配置入口（官方 settings 卡片范式）**：配置可出现在 设置 → 插件 → 插件配置；Host 注册命名空间 + 浏览器半侧注册卡片。

## 1.2.0（未发布）

### 变更

- **配置入口按 DSH 官方范式**：导出 Schemastery `Config` schema，loader 在 `apply` 前验证并填充默认值；插件形态改为官方具名导出。
- **bundle 行不再显式列默认值**：默认值只属于 schema 的 `.default()`。

### 发布与开源

- 开源协议 MIT；源码仓库 `github.com/FengZhiHen1/dsh-guardrails`。

## 1.1.0（未发布）

### 变更

- **防御层全量配置化（DSR-006）**：所有防御层改为叶子级可配——类别键接受布尔（整类开关）或对象（按操作/子族细分，缺省全开）；`destructive` 拆为 git/machine/eval/cli/bulk/target 六子族；新增 `unverifiable` 键。
- **向后兼容**：v1 五键布尔写法继续有效；非法配置挂载即失败。

## 1.0.0（未发布）

### 变更

- **sessions 类别移除**：`.dsh` 目录（含会话历史）不再被拦截，读写改删与列举全部放行；凭据文件名单不受影响。

### 安全增强

- **system 类别（W0）**：写入 Windows 系统区（`C:\Windows` 等）、用户启动目录、PowerShell Profile 硬阻断；读与列举放行。
- **credentials 范围 B 名单**：扩充 `.git-credentials`、注册表 Hive、分页/休眠文件、浏览器资料与 DPAPI 等；命令文本引用同步扩充。
- **绝对盘根删除拦截**：盘根删除及通配形态不再放行；工作区根删除并入判定。
