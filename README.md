# dsh-guardrails — DSH 敏感读审批层

对 AI 发起的**敏感文件内容读取**请求 DSH 原生一次性审批（ask / allow-once）的 Host 插件：

1. **内置凭据名单**：SSH 具名私钥（`id_rsa`/`id_ed25519`/…）、注册表/命令行令牌文件（`.npmrc`/`.pypirc`/`.netrc`/`.pgpass`/`.git-credentials`）、DSH 凭据文件（`.credentials.yaml`/`.auteur-media-secret`）、`~/.aws/credentials`、Windows Hive（`NTUSER.DAT` 等，含事务日志）与转储文件（`pagefile.sys`/`hiberfil.sys`）、system32 hive 组合
2. **用户标记的敏感文件**：在插件设置页按绝对路径精确列出（如 `E:/Project/app/.env.production`、`~/.kube/config`）；标记只在读取时触发审批，不是预先批准

**本插件不再拒绝（deny）任何调用。** 旧 v1 的硬阻断（`.env` 全局拦截、`.git` 内部拦截、系统区写、PowerShell 破坏性命令静态分析）在 v2.0.0 全部退役——这些上下文相关的判断交给 DSH 原生 Auto Review 与 OS 权限。设计依据：`docs/decisions/DSR-015-审批式敏感读与职责收缩.md`。

## 拦截语义

- **触发面**：`read` / `read_image` / `grep`（显式单文件路径）对命中目标的内容读取 → `{ kind: 'ask' }` → DSH 原生一次性审批。
- **批准一次只放行对应调用**；再次读取重新审批。拒绝/取消/超时/不可用（无审批通道、`never` 策略）一律不执行。
- **不触发**：普通文档与代码读取、`.env.example` 等模板、`*.pub` 公钥、`~/.ssh/config`（路由表）、`.git` 正常读取、元数据列举（`glob`）、目录级/工作区级 grep 搜索、一切写/改/删、pwsh/bash 命令。
- 审批提示只含动作与目标路径，**绝不读取或记录文件内容**。
- 未挂载 approval 服务时 `ask` 退化为拒绝（fail-closed，DSH 原生语义）；插件自身判定层异常时放行并大声记日志（fail-open）。

## 有限覆盖声明（重要）

本插件是**降低误操作概率的审批触发器，不是机密性边界**。以下路径不经过或不能被它识别：shell/脚本间接读取、目录级搜索间接命中、符号链接别名、PTC `run_code` 内的直接 Node 操作、同权限其他进程/插件。需要真实强隔离时使用 OS 账户权限/沙箱（DSH `workspace-write`、Windows ACL runner 等），不要依赖本插件兜底。宽范围搜索能否命中标记文件由 Auto Review 的模型审查把关。

## 已知边界

- 覆盖工具固定为 `read`/`read_image`/`grep` 的**确定单文件目标**；目录级 `grep` 按精确路径等值判断，不会因项目里存在标记文件而升级。
- 内置名单只按文件 basename / 固定段组合匹配：`.pem`/`.key` 等后缀**不再拦截**（v1 实测 24/24 为属性访问误报）；`.ssh`/`.aws` 等目录本身、浏览器资料、DPAPI、`.docker/config.json`、`.kube/config` 等混合载体**不再默认拦截**——需要时在设置页自行标记。
- 判定基准目录来自 `sandboxPolicy.resolve({ session })`；无该服务时绝对路径目标仍可判定。
- Windows 大小写不敏感、分隔符统一（`\`→`/`）；不做 fs 探测，不解析符号链接。

## 配置

全部字段 `.volatile()`：设置页修改即写入本 profile 的 `cordis.patch.yml` 并立即生效，无需重启。

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `sensitiveFiles` | `string[]` | `[]` | 精确绝对路径清单；相对路径、通配符挂载即失败 |
| `credentialsReadAsk` | `boolean` | `true` | 内置凭据名单开关；关闭后整类交 Auto Review |
| `askTimeoutMs` | integer | `0` | 审批等待的插件侧上界（毫秒，0–3600000）；`0` = 不设上界（沿用 DSH 原生无超时等待），`>0` 到点自动拒绝并收起弹窗（见「审批超时」） |

**配置入口**：侧栏「插件」→ dsh-guardrails → 行内「配置」——内置名单开关 + 标记文件路径编辑器（每行一个绝对路径），由官方 `SettingsForm` 呈现。命名空间 = loader 条目 id `guardrails`（改名即脱钩）。

profile 覆盖形态示例：

```yaml
- id: guardrails
  config:
    credentialsReadAsk: true
    sensitiveFiles:
      - E:/Project/app/.env.production
      - C:/Users/me/.kube/config
```

## 包形态（DSH 官方 Bundle 范式）

- `package.json` 声明 `dsh.bundle.patch: ./cordis.patch.yml`，`files` 包含 `index.js`（薄转发）、`src/`（core/adapter/client 三层）与 `cordis.patch.yml`；
- `cordis.patch.yml` `insert` 一行 `{ id: guardrails, name: dsh-guardrails }`；行 `id` 同时是该插件的 settings 命名空间；
- profile 通过 `dsh plugin --profile <name> add <包>` 安装。

## 部署形态（单一源码）

本目录是**唯一源码**，按 AGENTS.md 红线分 profile 挂载：

- **test（试验）profile**：允许 `link:` 源码直挂，源码改动重启即生效；
- **web（稳定）profile**：只吃发布物——当前为 `github:` git 依赖（lockfile 承载 resolution；推荐钉 ref），发布 npm 后切换 registry 版本。**挂载/更新 web 前必须过 test 实测门禁**（AGENTS.md「发布前置门禁」）。

> ⚠️ **基线要求（硬性）**：v2.0.0 适配 **DSH `0.2.0-rc.2` 及以后**（peer `@deepseek-ai/dsh-settings ^0.2.0-rc.2`）。在 `0.1.7-rc.2` 等旧运行时上，peer 门禁会把该行**静默禁用**（stderr 一行 `disabling profile plugin`，实例照常启动、守护消失）——**升级顺序：先把实例升到 `0.2.0-rc.2`，再挂载/更新本插件**。旧实例继续用 v1.7.0 发布物（`ctx.tools.guard` 硬阻断模型）。

## 审批超时（T-A 修订为 DSR-016）

DSH `0.2.0-rc.2` 的原生审批链**没有任何等待超时**（`@deepseek-ai/dsh-user-approval` 只提供 `policy: 'ask' | 'never'`，pending 的 answerer 会被无限等待；`never` 为立即确定性拒绝）。这仍是上游事实。

本插件因此提供一个**可选的、只约束自己的**上界：

- `askTimeoutMs = 0`（默认）—— 原样交给 DSH，行为与没有本功能一致；
- `askTimeoutMs > 0` —— 插件自己发这次审批请求（`approval.request` + `AbortSignal.any([exec.signal, 计时器])`），到点 abort：弹窗随 signal 收起，工具调用以**明确的自动拒绝**结束，并在控制台记一行 `[guardrails] ask timed out after Nms`。
- 超时与「用户拒绝」在会话审计里都落成 `approval/decided: cancelled`（结果词表封闭），区分只能靠上面那行日志与工具返回文案。**不要**把超时当成安全边界：它只解决"没人点导致挂起"。
- **不覆盖**其他来源的弹窗（Auto Review 等）——它们仍无超时。无人值守的完整姿态是会话 `approval policy = never`。

设计依据与取舍见 [DSR-016](docs/decisions/DSR-016-插件自有审批超时.md)。

## 测试

`node --test test/`（Node ≥20）：mock ctx 直接驱动 `tools/pre-execute` 监听器，覆盖目标匹配、配置校验、生命周期、设置接缝与客户端布线，不触碰文件系统。

`node verify/run-verify.mjs` 全量验证：单元/集成/生命周期测试、覆盖率门禁（行覆盖 ≥80%）、test/web 组合断言（每 profile 恰一行、web 依赖为发布物形态）、tarball 干净目录安装 + 导入冒烟。第 4 步启动冒烟会 spawn 真实实例，须由用户在启动器侧执行（或 `DSH_VERIFY_SKIP_BOOT_SMOKE=1` 跳过并明确登记）。

## 开源协议

[MIT License](LICENSE)（Copyright © 2026 FengZhiHen1）。源码仓库：
<https://github.com/FengZhiHen1/dsh-guardrails>——web profile 通过
`github:` 钉 ref 的 git 依赖安装当前版本（见"部署形态"）。
