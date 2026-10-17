# dsh-guardrails — DSH 工具安全防护

在 Full Access 下为 DSH 受管 AI 工具提供 `Deny / Ask / Allow` 防护，不依赖 Auto Review 的模型判定。源码已重构为官方双 Shell AST 与最终硬门禁，包版本 **3.0.0，尚未发布或完成完整部署验收**。“V2”是本轮设计资料的方案名，不代表包版本仍为 2.x。

## 使用边界

- 高置信灾难性目标使用绝对 Deny；有可靠危险证据和可执行替代方式时使用纠正型 Deny；可授权的敏感文件内容操作使用限时、单次原生审批。
- 普通文件、缓存、生成目录、局部 Git 清理和正常非强制 Worktree 回收默认 Allow。候选 Git、链式删除、云资源、数据库、容器与系统命令矩阵**不默认启用**。
- `sensitiveFiles` 来自 Profile 的精确文件标记；普通未标记 `.env` 不因名字特殊保护。内置凭据开关保留 `credentialsReadAsk` 名称，语义扩展到内容读、导出、写、删、移动；元数据列举和正常间接认证不因此 Ask。
- 对受管结果中的高置信凭据默认完整遮罩，不为遮罩增加审批。Native/PTC 的真实出口范围仍在验证，不能承诺全部结构化结果、日志或历史会话零泄漏。

只承诺进入 DSH `ctx.tools` 管线的调用；用户手工命令、PTC direct Node、外部同权限程序、远端执行和外部脚本内部副作用不构成完整覆盖。需要强隔离时仍依赖 OS 身份与权限。

## 当前技术路线

PowerShell 使用微软官方 `Parser.ParseInput`，由惰性持久 `pwsh` helper 提供事实；Bash 使用固定本地官方 `shfmt v3.12.0` 的 typed JSON AST，首版二进制目标为 Windows x64、Linux x64/arm64。平台交付目标不等于已经在各平台运行通过。

异步 `tools/pre-execute` 完成分析，将结果绑定同一次 `ToolExecution` 对象的 WeakMap；同步 `ctx.tools.guard` 做最终硬门禁。必检调用遇到解析器、协议或关联结果故障时 fail-closed，不使用旧自研 tokenizer 回退；语义 Unknown 本身不自动 Deny。

## 配置契约

以下配置已通过 schema 与运行时测试；页面刷新、表单保存仍须页面走查。

| 字段 | 默认 | 含义 |
|---|---|---|
| `sensitiveFiles` | `[]` | Profile 中精确绝对文件路径；不接受相对路径或通配符，不是目录保护白名单 |
| `credentialsReadAsk` | `true` | 内置高置信凭据载体的内容操作审批开关；名称保留以兼容旧配置 |
| `askTimeoutMs` | `120000` | Guardrails 自有审批等待上限，毫秒；legacy `0` 映射为 `120000`，不再无限等待 |

只接受本次 `allowed-once`；拒绝、取消、超时、不可用、异常或会话 `approval: never` 均不执行。超时只约束本插件主动发起的审批，不修改全局 DSH 审批机制。

配置页面改为官方 schema 自动生成设置，已删除旧 client 自绘页面；运行期读取 volatile 活值，持久化仍归对应 Profile。不要把旧卡片激活或保存截图当作新自动表单的验收。

## 文档与验证

从 [文档入口](docs/README.md) 阅读当前需求与机制；本轮取舍见 [DSR-017](docs/decisions/DSR-017-官方AST与最终硬门禁.md)，工程证据见 [重构验证记录](docs/verification/2026-10-17-v2-refactor.md)。DSR-001 至 DSR-016 保持历史原文。

验证命令为 `node verify/run-verify.mjs`；使用 `DSH_RUNTIME_PATH` 指向现场运行时，可同时执行真实 ToolRuntime/ApprovalService/PTC bridge 测试。原始重构95项测试已通过；独立审查后新增稳定语料，当前完整验证为459项（395通过、0失败、64显式跳过），约12.96秒；quality_floor PASS（0 error，4项提醒）。语料与回放已纳入默认test/check/verify，详见[稳定语料说明](test/fixtures/review-corpus/README.md)和[设计对照审查](docs/verification/2026-10-17-design-review.md)。当前 test 实例已观察到源码 HMR 生效，普通命令放行、合成敏感文件读取在 never 下拒绝、合成凭据输出打码。Linux 实跑、97,050 条人工标注回放、页面保存及完整启动门禁尚未完成。初始 pnpm 自动安装的 EPERM 与各出口限制均保留在验证记录。

## 安装与许可

按 DSH bundle 交付；稳定环境只使用发布包或钉 ref 的 `github:` 依赖，须先通过 test 实测门禁。本轮未发布、未修改稳定 Profile，也未提交推送。

[MIT License](LICENSE)，源码仓库：<https://github.com/FengZhiHen1/dsh-guardrails>。
