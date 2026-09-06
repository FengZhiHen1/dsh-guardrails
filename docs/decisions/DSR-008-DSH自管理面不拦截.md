# DSR-008：DSH 自管理面不纳入防护——AI 协助改配置是预期用法

> 状态：**已决议（2026-09，v1.4.0 文档落地，无代码变更）**。记录"dsh-guardrails
> 是否拦截对 DSH 自身的操作"的范围决策。

## 上下文

- 2026-09 用户提问：guardrails 会拦截对 DSH 本身的操作吗？逐项核对后的现状：
  | 操作 | 拦否 | 依据 |
  |---|---|---|
  | 按名杀 dsh/node/pwsh 等进程 | 拦 | `destructive.machine` 的 `KILL_TARGET_PATTERN` |
  | 按 PID 杀进程 | 不拦 | 模式只匹配进程名 |
  | 读写 `$DSH_HOME` 配置面（settings.yaml、profiles 的 package.json、cordis.patch.yml） | 不拦 | 不在任何名单 |
  | 读写 DSH 安装目录 | 不拦 | 同上 |
  | 读写会话日志（.dsh） | 不拦 | DSR-003 重访（混合目录无敏感语义） |
  | `$DSH_HOME` 下凭据文件（.credentials.yaml 等） | 拦 | credentials 名单按 basename 命中 |
- 由此暴露一个推论：**自我解除通道**——`danger-full-access` 模式下沙箱不拦
  任何写，AI 可写 `settings.yaml` 的 `dsh-guardrails` 分节关闭本插件规则，
  或写 profile patch 停用插件行；与拒绝消息"另一通道也被拦"的措辞存在出入。
  （`workspace-write` 模式下该通道已由沙箱围栏关闭：工作区外写一律
  `FS_SANDBOX_DENIED`。）

## 决策

**维持不拦截，文档写明边界。** 理由（用户原话）："我经常需要 dsh 自身帮我
修改配置"——AI 协助修改 `$DSH_HOME` 配置是高频预期用法，拦截会把正当工作流
一并阻断。guardrails 的定位是防误操作/防常规注入的护栏，不是对抗性安全边界；
`danger-full-access` 是用户显式选择的完全信任模式，其风险由用户承担。

## 后果与边界（README「已知限制与边界」同步）

- 进程级保护保留：按名杀 dsh/node/pwsh 等进程仍拦（`destructive.machine`）。
- 凭据文件保护保留：`$DSH_HOME` 下的 `.credentials.yaml` 等按名单拦截。
- 自我解除通道作为**已知边界**显式记录，不再宣称"任何通道都被拦"覆盖它。
- 重访条件：出现真实的配置面注入事故，或 guardrails 定位升级为对抗性边界
  （届时另起 DSR 评估 `dsh: { write }` 类别方案）。
