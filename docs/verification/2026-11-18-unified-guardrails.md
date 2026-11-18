# 统一执行分析与宿主门禁验证

本次在 Windows x64 使用 Node.js 24.12.0 和 DSH 0.2.2-rc.2。运行时测试直接装配已安装的 DSH 组件，并在独立临时目录内构造目标。

| 检查 | 结果 |
|---|---|
| `pnpm verify`（设置 `DSH_RUNTIME_PATH`） | 422 项通过，0 项失败，3 项 Linux 挂载测试按平台跳过 |
| 插件分层检查 | 通过 |
| `npm pack --dry-run --json` | 包清单包含 Host 和 Client 入口、Bundle patch、Python helper 与三种平台的 shfmt 资产 |

## 实际验证的派发行为

- 普通删除涉及 20 个文件时派发一次。涉及 21 个文件时请求一次确认。收到拒绝后，工具体零次派发。
- 受保护读需要单次确认。真实 ApprovalService 的 `never` 策略拒绝调用并记录审批事件。确认期间，文件服务报告同一路径的文件版本发生变化时，门禁拒绝派发。
- 前置监听器短路后，同步门禁拒绝缺少有效结果的必检调用。未接入工具继续走 DSH 权限流程。
- PTC 外层程序和 SDK 内层工具分别经过门禁。JavaScript 程序直接读取标记文件时，确认发生在程序启动前。内层的大批量补丁只触发一次确认。启用官方 `apply_patch` 的文件工具组合实际更新了临时文件。
- 合成源码验证了 JavaScript `node:fs` 和 Python `open`、`pathlib.Path` 常见 API 的内容目标提取。解析器不会执行这些样例。
- Native 单字符串结果和 PTC 持久日志副本验证了凭据遮罩。对其他输出形状的覆盖记录在[测试体系](../technical-details/工程结构与测试体系.md)。

## 运行中实例冒烟

在 Windows x64 的 DSH `0.2.2-rc.2` 测试实例，通过 DSH 插件管理器重新安装提交 `c80201f` 对应的本地 Bundle（`0.2.1`）。管理器的卸载和安装均返回 `applied`。安装输出包含 pnpm 的本地链接 peer 依赖提醒。Host Inspect 显示重构版的新配置字段，Client Inspect 显示 `dsh-guardrails#guardrails` 设置入口已注册。

| 合成夹具调用 | 实际结果 |
|---|---|
| 删除 20 个普通文件 | 派发成功，核实目标目录已移除 |
| 删除 21 个普通文件 | `data.delete.bulk`，未取得确认，21 个文件均保留 |
| 读合成 `.env` | `credential.file.read`，未取得确认，未返回文件内容 |
| 删除合成 `.env` | `credential.file.mutate`，未取得确认，夹具保留 |

## 仍需验收

Linux x64 和 arm64 的运行验证、Web 设置页表单交互与跨平台性能预算待验证。终端权威上下文、程序内容操作覆盖、目录级再生证据和项目配置层来源见 [TODO](../TODO.md)。发布仍需满足[部署门禁](../technical-details/部署.md)。
