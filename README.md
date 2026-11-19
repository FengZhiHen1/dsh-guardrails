# dsh-guardrails

dsh-guardrails 为 DeepSeek Harness 的受管工具提供数据破坏防护、敏感文件确认和凭据遮罩。

- 已识别的灾难性操作直接拒绝。删除超过 20 个未豁免文件或链接时，列出范围并请求一次确认。
- 对敏感文件的内容操作请求限时确认。受管结果中可识别的凭据在受支持的文本出口完整遮罩。
- Shell、程序和文件工具提交统一的操作事实。可以交付有效结果的覆盖缺口随本次调用记录，必检调用缺少可信结果时拒绝派发。

## 安装与配置

目标宿主为 DSH `0.2.2-rc.2`，Node.js 基线为 `24.9.0`。在 DSH 的插件页添加已通过验收的 Bundle，确认 `guardrails` 行处于启用状态。包来源、运行条件和发布门禁见 [部署](docs/technical-details/部署.md)。

在插件行的配置页填写需要保护的绝对文件路径、选择内置敏感文件名单，并设置确认等待时间。设置页的「宿主审批关闭时仍弹确认」开关对应 `alwaysAsk`。规则级配置及默认值见 [规则模型](docs/technical-details/规则模型.md)。

| 配置项 | 默认 | 作用 |
|---|---|---|
| `sensitiveFiles` | `[]` | 需要保护的精确绝对文件路径 |
| `builtinSensitiveAsk` | `true` | 内置敏感文件名单的内容操作确认 |
| `askTimeoutMs` | `120000` | 确认等待上限（毫秒）；`0` 使用有界默认值 |
| `alwaysAsk` | `true` | 会话审批策略为 `never` 或审批 seam 缺失时，改经问答通道弹一次确认 |

## 确认通道与失效路径

- 通道优先级：审批 seam 存在且有效策略为 `ask` 时走官方审批；策略为 `never` 或审批 seam 缺失时，在 `alwaysAsk` 开启且问答服务可用时改走问答通道；审批 seam 存在但返回 `unavailable`（无应答方）时直接拒绝（`APPROVAL_UNAVAILABLE`），不再回退问答。
- 无客户端应答方时（headless、CI、未连接该会话）仍拒绝，fail-closed。
- 委派子代理会话无法使用问答通道（宿主把子会话审批固定为 `never`），直接拒绝。
- 拒绝文案区分归因：`APPROVAL_REJECTED` 表示真的有人拒绝；`APPROVAL_POLICY_NEVER` 表示策略为 `never` 且没有交互应答方接受该确认；`APPROVAL_DELEGATED` 表示发生在委派子代理会话。后两者不得表述为「用户拒绝」。
- 问答通道与 `APPROVAL_POLICY_NEVER` 路径都不产生 `approval/asked`、`approval/decided` 审计事件。批准只放行当前调用，不落盘。

## 覆盖边界

防护范围由 DSH 当前启用的工具、语言分析能力和目标身份取证决定。命令派发前的文件系统观察是一份快照。结构化值、错误与元数据的遮罩范围见 [需求](docs/需求.md) 和 [测试体系](docs/technical-details/工程结构与测试体系.md)。

## 开发与验证

在插件目录安装依赖后运行 `pnpm verify`，检查源码语法和自动化用例。设置 `DSH_RUNTIME_PATH` 为目标 DSH 包的 `package.json` 可启用隔离运行时测试。设计、平台边界和证据记录的入口见 [文档索引](docs/README.md)。

采用 [MIT License](LICENSE)。
