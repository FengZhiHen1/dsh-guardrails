# dsh-guardrails — DSH 工具安全防护

在 Full Access 下为 DSH 受管 AI 工具提供 `Deny / Ask / Allow` 防护，不依赖 Auto Review 的模型判定。源码已重构为官方双 Shell AST 与最终硬门禁，包版本 **3.2.0，尚未发布**；本轮适配 DSH `0.2.1-rc.2`。“V2”是本轮设计资料的方案名，不代表包版本仍为 2.x。

## 兼容性

目标运行时为 DSH `0.2.1-rc.2`；`@deepseek-ai/dsh-settings` peer 下限为 `^0.2.1-rc.2`。0.2.0 及更早版本会被 peer 门禁禁用，不再假装可运行：0.2.1 的配置页依赖 `ctx.configForms` 与新的 `run_code` Agent 上下文契约。Node 版本按 `engines`。

## 使用边界

- 高置信灾难性目标使用绝对 Deny；有可靠危险证据和可执行替代方式时使用纠正型 Deny；可授权的敏感文件内容操作使用限时、单次原生审批。
- 普通文件、缓存、生成目录、局部 Git 清理和正常非强制 Worktree 回收默认 Allow。候选 Git、链式删除、云资源、数据库、容器与系统命令矩阵**不默认启用**。
- `sensitiveFiles` 来自 Profile 的精确文件标记；普通未标记 `.env` 不因名字特殊保护。内置名单开关为 `builtinSensitiveAsk`，覆盖私钥、工具凭据文件、系统凭据库与分页/休眠文件的内容读、导出、写、删、移动；元数据列举和正常间接认证不因此 Ask。
- 对受管结果中的高置信凭据默认完整遮罩，不为遮罩增加审批。Native/PTC 的真实出口范围仍在验证，不能承诺全部结构化结果、日志或历史会话零泄漏。

只承诺进入 DSH `ctx.tools` 管线的调用；用户手工命令、PTC direct Node、外部同权限程序、远端执行和外部脚本内部副作用不构成完整覆盖。需要强隔离时仍依赖 OS 身份与权限。

## 当前技术路线

PowerShell 使用微软官方 `Parser.ParseInput`，由惰性持久 `pwsh` helper 提供事实；Bash 使用固定本地官方 `shfmt v3.12.0` 的 typed JSON AST，首版二进制目标为 Windows x64、Linux x64/arm64。平台交付目标不等于已经在各平台运行通过。

异步 `tools/pre-execute` 完成分析，将结果绑定同一次 `ToolExecution` 对象的 WeakMap；同步 `ctx.tools.guard` 做最终硬门禁。必检调用遇到解析器、协议或关联结果故障时 fail-closed，不使用旧自研 tokenizer 回退；语义 Unknown 本身不自动 Deny。

## 配置契约

以下配置已通过 schema、运行时测试与 0.2.1 现场激活；设置页的保存交互仍待用户页面走查。

| 字段 | 默认 | 含义 |
|---|---|---|
| `sensitiveFiles` | `[]` | Profile 中精确绝对文件路径；不接受相对路径或通配符，不是目录保护白名单 |
| `builtinSensitiveAsk` | `true` | 内置敏感文件名单（私钥、工具凭据文件、系统凭据库、分页与休眠文件）的内容操作审批开关 |
| `askTimeoutMs` | `120000` | Guardrails 自有审批等待上限，毫秒；legacy `0` 映射为 `120000`，不再无限等待 |

只接受本次 `allowed-once`；拒绝、取消、超时、不可用、异常或会话 `approval: never` 均不执行。超时只约束本插件主动发起的审批，不修改全局 DSH 审批机制。

配置页面使用官方 `plugins.row.config` 入口，并通过 0.2.1 的 `ctx.configForms` 读取活值与提交写入；字段与保存键按官方 `SettingsForm`/`fields` 的几何复制（未修改或输入非法时禁用保存），只用主题 token，不引用 Harness Client 包；沿用 DSH 主题和保存机制。敏感文件每行一个；审批时间以秒显示、毫秒保存；空清单不关闭内置保护。修改暂存到点击保存，失败保留输入，提交绑定开始编辑时的配置修订号。运行期读取 volatile 活值，持久化仍归对应 Profile。界面中可展开查看能力边界；现场加载与验证见[设置页记录](docs/verification/2026-10-17-settings-ui.md)。

## 文档与验证

从 [文档入口](docs/README.md) 阅读当前需求与机制；本轮取舍见 [DSR-017](docs/decisions/DSR-017-官方AST与最终硬门禁.md)，命名变更见 [DSR-018](docs/decisions/DSR-018-内置敏感文件名单改名.md)，工程证据见 [重构验证记录](docs/verification/2026-10-17-v2-refactor.md)。DSR-001 至 DSR-016 保持历史原文。

验证命令为 `node verify/run-verify.mjs`；使用 `DSH_RUNTIME_PATH` 指向现场运行时，可同时执行真实 ToolRuntime/ApprovalService/PTC bridge 测试。以 0.2.1-rc.2 运行时执行当前完整验证为 464 项（400 通过、0 失败、64 条已声明语料跳过），约 10.9 秒；quality_floor PASS（0 error，5 项提醒）。测试适配了点：`run_code` 需要 Agent `ctx` 与 `workingDirectory` 服务，PTC 释放使用 `agent.ctx.effect`。语料与回放已纳入默认 test/check/verify，详见[稳定语料说明](test/fixtures/review-corpus/README.md)和[设计对照审查](docs/verification/2026-10-17-design-review.md)。test 现场 `install_bundle` 返回 `applied`（3.1.0），Config schema 与 `plugins.row.config` 注册均可见，普通命令放行验证通过。Linux 实跑、97,050 条人工标注回放、设置页保存走查及完整启动门禁尚未完成。3.2.0 的配置键改名未重装、未重启 test 实例；运行中的实例已由 HMR 热加载新模块，Config inspect 显示 `builtinSensitiveAsk`。

## 安装与许可

按 DSH bundle 交付；稳定环境只使用发布包或钉 ref 的 `github:` 依赖，须先通过 test 实测门禁。本轮未发布、未修改稳定 Profile，也未提交推送。

[MIT License](LICENSE)，源码仓库：<https://github.com/FengZhiHen1/dsh-guardrails>。
