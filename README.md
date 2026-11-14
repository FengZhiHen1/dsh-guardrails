# dsh-guardrails — DSH 工具安全防护

在 Full Access 下为 DSH 受管 AI 工具提供 `Deny / Ask / Allow` 防护，不依赖 Auto Review 的模型判定。本插件只防**灾难性删除**，对可识别的命令行删除做「执行前计数 + 超 20 文件硬拒绝」，并引入固定的文件级白名单（形态匹配 + 证据双通过才减计数）。源码与隔离 Runtime 验证通过，详见[验证记录](docs/verification/2026-11-14-delete-gate.md)。live 激活已在验收环境复验；UI 显示、稳定环境部署与 Linux/跨平台实跑尚未完成。

## 兼容性

目标运行时兼容区间声明为 `>=0.2.1-rc.2 <0.3.0-0`；**本轮验证基线为 `0.2.2-rc.2`**，其他版本（含 `0.2.1-rc.2`、`0.2.2-rc.1`）未复验，不声称已覆盖。`@deepseek-ai/dsh-settings` peer 与 `engines.dsh` 使用同一区间。更低版本会被 peer 门禁禁用，不再假装可运行。Node 版本按 `engines`。

## 使用边界

插件只防**灾难性删除**，分三级：**L1 直接拒绝**（物理设备、宿主系统整树、`.git` 元数据、销毁 git 历史的 git 子命令）；**L2 计数**（可识别的命令行删除，≤20 放行、>20 拒绝）；**L3 其余放行**。它**不声称拦截所有删除**——只拦可识别的命令行删除，程序内部副作用与绕过 DSH 工具通道的调用不在覆盖内。

- 高置信灾难性目标使用绝对 Deny；有可靠危险证据和可执行替代方式时使用纠正型 Deny；可授权的敏感文件内容操作使用限时、单次原生审批。
- **L2 计数**：可识别的命令行删除（含工作区之外的目标、`move` 的源删除）统计未命中白名单的常规文件 + 链接条目，目录去重单独报告；`<=20` 完整枚举，`>20` 硬拒绝（可早停「至少 21」，`DEL-01`/`DEL-14`）并要求核实预期、分批删除。
- **L3 放行**：未建模程序（`Test-Path`/`Copy-Item`/`New-Item`/`whoami` 等）、`copy`、`create_worktree`、`terminal_open`、全部 `plugin_manager` 动作、常规 git 操作（`status/log/add/commit/...`）放行。**语言运行时脚本**（`node/python/perl/ruby/php/deno/bun/uv`）作为不透明脚本运行器直接允许（不计数），其内联代码开关（`node -e`、`python -c` 等）仍拒绝。
- **执行通道与灾难模式仍拒绝**：目的是执行任意命令文本的通道（无法分析的 shell 脚本、动态命令文本、`env/xargs/sudo/start/source`、WSL 包装）在无法分析时拒绝；`run_code` 整体拒绝（载荷是程序而非命令行）。`terminal_send` 的 `text` 就地按平台方言分析（Windows PowerShell / 其他 POSIX），可识别删除照常计数、无法分析则拒绝。`.git` 元数据路径、provider 路径、物理设备等灾难模式即使程序名未知也拒绝。
- **git 分级**：`git` 由 `assessGit` 分类，销毁历史的子命令（`stash clear/drop`、`gc --prune=now`、`filter-branch`、`filter-repo`、`push --force/-f/--delete/--mirror`、无路径 `reset --hard`、`reflog expire --expire=now --all`）立即拒绝（`DI-GIT-REFUSE`）；`clean`/`restore <paths>`/`worktree remove <path>` 经 `git-evidence` 计数（>20 拒绝；worktree remove 要求工作树干净、非分离 HEAD、可重建之外的可忽略条目 ≤20）；证据不可用一律 fail-closed（`DEL-GIT-UNKNOWN`）。git allow 命令不进入通用文件扫描。
- **文件级白名单只减计数、不减保护**：Python 字节码、pytest、mypy、Maven class、TS buildinfo；命中须「形态匹配 + 证据证明」双通过才减计数。Cargo 取消自动豁免（仅保留 `Cargo.toml` 为边界 marker）。只识别常规文件、不读内容、不整树豁免；受保护文件与绝对 Deny 始终生效。
- `sensitiveFiles` 来自 Profile 的精确文件标记；普通未标记 `.env` 不因名字特殊保护。内置名单开关为 `builtinSensitiveAsk`，覆盖私钥、工具凭据文件、系统凭据库与分页/休眠文件的内容读、导出、写、删、移动；元数据列举和正常间接认证不因此 Ask。
- 对受管结果中的高置信凭据默认完整遮罩，不为遮罩增加审批。Native/PTC 的真实出口范围仍在验证，不能承诺全部结构化结果、日志或历史会话零泄漏。

只承诺进入 DSH `ctx.tools` 管线的调用；用户手工命令、外部同权限程序、远端执行和外部脚本内部副作用不构成完整覆盖。`run_code` 一律拒绝；`terminal_send` 的文本就地分析、无法分析则拒绝。真正边界是「不经 `ctx.tools` 直接调用 runtime service」。审批、agent 自报或 dry-run 都不构成删除授权；检查与执行间存在 FS 并发竞态，不声称 `<=20` 执行原子。需要强隔离时仍依赖 OS 身份与权限。

## 当前技术路线

PowerShell 使用微软官方 `Parser.ParseInput`，由惰性持久 `pwsh` helper 提供事实；Bash 使用固定本地官方 `shfmt v3.12.0` 的 typed JSON AST，首版二进制目标为 Windows x64、Linux x64/arm64。平台交付目标不等于已经在各平台运行通过。

异步 `tools/pre-execute` 完成官方 AST、递归包装解包、删除意图判定、执行前删除清单与必要审批，将结果绑定同一次 `ToolExecution` 对象的 WeakMap；同步 `ctx.tools.guard` 做最终硬门禁。必检调用遇到解析器、协议或关联结果故障时 fail-closed，不使用旧自研 tokenizer 回退；解析层只负责报告 Unknown，策略层（`assessCommands`）对任何非空 Unknown 都拒绝——只要无法排除删除副作用就拒绝，覆盖旧的 Unknown-Allow 默认。

## 配置契约

以下配置已通过 schema 与测试验证（见[本轮验证记录](docs/verification/2026-11-14-delete-gate.md)）；设置页的保存交互仍待用户页面走查。

| 字段 | 默认 | 含义 |
|---|---|---|
| `sensitiveFiles` | `[]` | Profile 中精确绝对文件路径；不接受相对路径或通配符，不是目录保护白名单 |
| `builtinSensitiveAsk` | `true` | 内置敏感文件名单（私钥、工具凭据文件、系统凭据库、分页与休眠文件）的内容操作审批开关 |
| `askTimeoutMs` | `120000` | Guardrails 自有审批等待上限，毫秒；legacy `0` 映射为 `120000`，不再无限等待 |

只接受本次 `allowed-once`；拒绝、取消、超时、不可用、异常或会话 `approval: never` 均不执行。超时只约束本插件主动发起的审批，不修改全局 DSH 审批机制。删除数量上限固定为 20，不提供可配置阈值；白名单为内置固定集合，不接受用户自加。

配置页面使用官方 `plugins.row.config` 入口，并通过 `ctx.configForms` 读取活值与提交写入；字段与保存键按官方 `SettingsForm`/`fields` 的几何复制（未修改或输入非法时禁用保存），只用主题 token，不引用 Harness Client 包。字段长说明优先收进标签旁的 info 展开器；敏感文件每行一个；审批时间以秒显示、毫秒保存；空清单不关闭内置保护。修改暂存到点击保存，失败保留输入，提交绑定开始编辑时的配置修订号。

## 文档与验证

从 [文档入口](docs/README.md) 阅读当前需求与机制；灾难性删除标准（L1/L2/L3）见 [DSR-020](docs/decisions/DSR-020-灾难性删除标准.md)，删除计数与未知拒绝取舍见 [DSR-019](docs/decisions/DSR-019-删除计数与不确定执行拒绝.md)，官方 AST 架构见 [DSR-017](docs/decisions/DSR-017-官方AST与最终硬门禁.md)，命名变更见 [DSR-018](docs/decisions/DSR-018-内置敏感文件名单改名.md)。DSR-001 至 DSR-016 保持历史原文。

验证命令为 `node verify/run-verify.mjs`（源码语法与测试）；使用 `DSH_RUNTIME_PATH` 指向现场运行时，可同时执行真实 ToolRuntime/ApprovalService/PTC bridge 测试。源码与隔离 Runtime 验证通过，详见[验证记录](docs/verification/2026-11-14-delete-gate.md)。live 激活已在验收环境复验；UI 显示、稳定环境部署与 Linux/跨平台实跑**尚未完成**，以验证记录为准。旧解析语料回归只代表旧解析路径，不代表新策略全部测试通过。

## 安装与许可

按 DSH bundle 交付；稳定环境只使用发布包或钉 ref 的 `github:` 依赖，须先通过实测门禁。本轮未发布、未修改稳定环境配置，也未提交推送。

[MIT License](LICENSE)，源码仓库：<https://github.com/FengZhiHen1/dsh-guardrails>。
