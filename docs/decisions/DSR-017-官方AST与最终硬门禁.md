# DSR-017：官方 AST 与最终硬门禁

**决定 / 理由 / 被否决项：** Full Access 采用官方双 Shell AST、同执行对象 WeakMap 与同步最终 guard，Guardrails 自有有限审批和高置信凭据防护；降低旧词法误伤并防止前置短路绕过；否决旧 tokenizer 回退、ask-only 依赖 Auto Review、研究矩阵自动启用与零泄漏承诺。

- 日期：2026-10-17。
- 状态：源码已重构为 3.0.0 并通过本轮测试；未发布、未完成 Linux 与完整部署验收。
- “V2”是研究方案名；DSR-001…016 保持原文，涉及现行行为以本决策及当前需求/机制所有者为准。

## 上下文与备选

DSR-015 的 ask-only 路线依赖 Auto Review 判断上下文风险，不能满足用户后来确认的 Full Access 主动防护目标。恢复 v1 全文关键词与自研词法会继承引用误伤和语法信息损失。采用官方 Parser/AST 后，仅提取有限可靠语义，既能保留精确判定，也无需构建 Shell 解释器。

| 方向 | 评价 |
|---|---|
| 继续 ask-only + Auto Review | 不符合已确认主防线方向 |
| 恢复旧自研 tokenizer、宽泛关键词/目录硬禁 | 语法权威冲突、误伤高，不接受为平行检测或回退 |
| `sh-syntax 0.7.0` | JS 映射有损，不能把其对象当完整 typed AST |
| 官方 PowerShell Parser + 官方 shfmt typed JSON | 选定；版本和协议受控，仍须工程与跨平台验证 |

## 决定

1. PowerShell 使用官方 `Parser.ParseInput`，惰性持久受信 `pwsh` helper；Bash 使用官方本地 shfmt typed JSON。实施固定 `v3.12.0`，交付目标 Windows x64、Linux x64/arm64；旧研究参考 v3.14.1 不等于交付版本。通过 stdin 传文本，不执行待审脚本、不按调用下载。
2. 异步 `tools/pre-execute` 解析与判定，结果以同一 `ToolExecution` 对象 WeakMap 关联，同步 `ctx.tools.guard` 最终阻断。必检调用的解析器/协议/关联缺失 fail-closed；有效语法 Unknown 不自动 Deny。没有自研 lexer 故障回退。
3. `Deny > Ask > Allow`。绝对 Deny 仅三个高置信真实对象：宿主磁盘/分区底层灾难破坏、宿主 OS 根/核心结构整体毁坏、Git 共享 common-dir 主体整体破坏。纠正型 Deny 必须证明危险机制及可行安全替代，不因关键词、数量、普通动态语法扩大。
4. S-F1/S-F2：Profile 精确文件与内置高置信凭据的直接内容读/导出/写/删/移走限时 Ask；元数据和正常间接认证 Allow。普通未标记 `.env` 不自动保护。正常非强制 Worktree 回收 Allow，只有高置信确认实际待删树中存在受保护文件才因该删除 Ask。
5. 保留 `credentialsReadAsk` 配置名并扩展为内容操作；`sensitiveFiles` 仍是 Profile 精确文件。Guardrails 自有 `askTimeoutMs` 默认 `120000` ms，legacy `0` 映射为 `120000` ms；不再提供无限等待，不控制其他来源审批。只接收本次 `allowed-once`，never/超时/取消/异常/不可用不执行，迟到批准不复活。
6. 官方 schema 自动设置取代旧 client 自绘；运行期读取 volatile 活值。包版本计划 3.0.0，实际 package 变更与验收由主实施任务完成。
7. M-S1/M-S2：建议秘密与非秘密配置分离、可信运行时注入与不输出明文的检查；不强制厂商、不扫描迁移 `.env`，不宣称同 OS 身份强隔离。
8. R-M1：高置信真实凭据的受管工具结果默认完整遮罩，不增 Ask/Deny。R-M2：高置信参数直接内联真实凭据、有扩散风险且有可行替代才纠正型 Deny；变量/占位符/示例/间接认证不因关键词拒绝。Native/PTC 出口必须逐一实测；不能撤销预审前已记 `tool/call`，不能声称全字段/日志/历史会话零泄漏。
9. 正常清理、缓存、生成物与局部 Git 默认 Allow；撤回 Trusted Disposable Scope、一般清理白名单、生成物注册表、全量扫描与跨调用备份许可状态机。数量只附加于已命中风险，1000 不是正式阈值。

## 保留的决策闸门

Git clean/reset/restore/强推/强删、强制 Worktree 回收、直接删除注册 Worktree、复制后高价值源删除、云/DB/容器/宿主系统和 Secret CLI 的逐命令矩阵未获整体批准，不默认启用。原 G-C1/G-C2、G2/C2 与最小规则集表仍是研究候选。未知 SQL、SDK、远端/容器内部等不以 Shell AST 冒充完整覆盖。

历史某本机 `env --json` token 个例由用户反馈已源头修复；本轮未复验，不纳入通用规则、固定验收命令或新待办。

## 后果与重访

当前需求、规则模型、命令分析、工程和部署正文按本方向更新；README 更新状态与地图，CHANGELOG 增加未发布 3.0.0 条目；本轮验证记录独立区分初始基准和最终证据。历史 DSR 不改。

只有平台真实运行、资源/延迟测量、审批竞态、Native/PTC 多出口和干净安装证据齐备后，才能扩大验收结论。shfmt 升级须重放 typed JSON 合同；新增默认规则须先有明确批准、语义证据和成对反例。强隔离需求需另建 OS 身份/权限方案。

## 来源与证据级别

本决策把管理仓库忽略目录中的已确认约束迁入受版本控制文档。来源读取于 2026-10-17：

- `references/dsh-guardrails/README.md`：资料导航与最新确认优先级。
- `Deny-Ask-Allow规则边界与实施状态索引-2026-10-17.md`：已确认/候选/撤回边界。
- `Full-Access双Shell-AST与硬防护-已确认基线-2026-10-17.md`，尤其 §§7–14：架构与产品确认。
- `DSH-Guardrails-V2-Coding-Agent-实施交接与决策闸门-2026-10-17.md`：实施范围和最终闸门。
- 本轮委派指令：v3.12.0、120000 ms/legacy 0、配置名兼容、schema auto 与 3.0.0 计划。它们覆盖较早研究中尚未定值的状态，不改写历史原文。

DSH 参考基线为知识库 active `v0.2.0-rc.2`，tag `dsh-v0.2.0-rc.2` / commit `639ed015`；知识库注册表的历史运行态不当作当前现场。本记录是决策沉淀，不是源码完成、Linux 实跑、97,050 回放或安装部署证明。
