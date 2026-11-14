# 本轮验证记录 · 删除计数与不确定执行拒绝（2026-11-14）

> 本文件记录本轮（用户 2026-11-14 明确确认收紧批量删除策略）的**源码级**验证结果。
> **源码与隔离 Runtime 验证已通过；live 激活已在验收环境复验**：验收版本已同步到源码并经官方插件管理器重新应用后，观察到新版拒绝策略生效（见「live 激活复验」）。UI 显示、稳定环境部署与 Linux/跨平台实跑仍未验证。
> 基线运行时：DSH `0.2.2-rc.2`；Node `v24.12.0`；插件仓库 HEAD `6f0531e8e5bf4159b54b6398a8fc7e0dc6a72a9e`。

## 验证环境

- 源码验证与在线部署证据分离：所有测试在独立 integration 工作树中运行，使用 **合成 fixture**（`os.tmpdir` / 项目 `tmp/`），不启动 DSH 实例、不写部署 HOME、不改已挂载插件与 profile。
- 真实运行时测试通过 `DSH_RUNTIME_PATH` 指向 `0.2.2-rc.2` 的 `@deepseek-ai/dsh` 包现场锚点，加载真实 `ToolRuntime`（native 与 PTC executor）、`ApprovalService`、`workingDirectory` 契约。

## 结果（可复现命令）

```powershell
$env:DSH_RUNTIME_PATH='<0.2.2-rc.2>/node_modules/@deepseek-ai/dsh/package.json'
node verify/run-verify.mjs          # 语法 + 全量测试
node --test test/*.test.mjs         # 全量
node --test test/strict-runtime.test.mjs   # 真实 Runtime 严格语义
```

| 检查 | 结果 |
|---|---|
| `verify/run-verify.mjs` 全量 | 语法检查通过；**618 tests / 553 pass / 0 fail / 65 skip**，`Source verification: PASS` |
| `test/strict-runtime.test.mjs`（真实 Runtime） | **8 / 8 pass / 0 fail / 0 skip** |
| 维护用分层检查 | **PASS**（core 文件 6 个，无 `@deepseek-ai/*`、无 adapter 反向依赖；由私有维护环境运行验证） |

65 项 skip 的构成（非隐藏失败）：55 项为既有命令语料的明确“No independent definite oracle”（`replayCorpus` 记为 not-run，不当作已复核通过），9 项为明确排除/不支持用例，仅 1 项为 POSIX-only 平台用例。注入 `DSH_RUNTIME_PATH` 后，真实 `ToolRuntime` 严格用例 8 项全部执行通过（不属未注入 Runtime 的子进程 skip）。
## 真实 Runtime 严格语义用例（`strict-runtime.test.mjs`，8/8）

1. 纯字面 `Remove-Item -Recurse` 删除 20 文件 → 允许，执行体恰好 dispatch 1 次；21 文件 → 拒绝（DEL-01），执行体 0 次、fixture 未被修改。
2. 未登记工具（`cleanup_cache`）→ `[UNKNOWN_TOOL]` 拒绝，0 dispatch。
3. `terminal_send` → `[UNVERIFIED_TERMINAL]` 拒绝，0 dispatch。
4. 真实 PTC executor 外层 `run_code` → `[OPAQUE_CODE]` 拒绝，`FixturePtcRuntime.run` 调用 0 次（非伪造登记）。
5. `workingDirectory.get` 优先于 `sandboxPolicy.workspaceRoot`，相对 `workdir` 解析：按真实 cwd 放置的 1 文件允许，反之按 sandbox 根放置的 21 文件会 DEL-01。
6. 审批等待期间目标增长到 21 → 拒绝（DEL-01 / `PLAN_CHANGED`），执行体 0 dispatch。
7. 白名单只折抵内置开发产物：19 普通文件 + `pyproject.toml`（pyc 折抵后计 20）允许；树内含受保护 `id_rsa` → 先 1 次审批后拒绝，执行体 0。
8. 真实 `pwsh Remove-Item -Recurse` 作用于含真实 junction 的合成目录 → 树外目标文件**仍存在**（junction 条目被删、目标未跟随）。

## 源码同步后的运行中检查

验收版本已同步到开发检出；同步时逐一核对交付文件的数量、总字节和 SHA-256，均与隔离验收版本一致。随后只更新了本文的运行中检查记录，没有改变执行代码。

此前一次同步后，既有会话执行无副作用命令 `node --version` 仍返回版本号，新策略当时未生效；该观测本身不能区分未重载、缓存或调用作用域等原因。下节记录后续的复验结论。

## live 激活复验（官方重新应用）

在验收环境用官方插件管理器对已挂载行重新应用（`set_plugin`），返回 `application: applied`、`warnings: []`；随后按用户要求刷新页面。复验使用合成 fixture，先以纯预览确认，再验证真实 20/21 边界：

| 检查 | 命令形态 | 结果 |
|---|---|---|
| 不透明程序拒绝（**已被 v3 取代，见下节**）| `node --version` | v1/v2：拒绝（Node 脚本副作用不可证）；**v3 起改为放行** |
| 明确只读放行 | `Get-Location` | 放行，返回当前路径 |
| 纯预览不入清单 | `Remove-Item -LiteralPath <合成目录> -Recurse -WhatIf`（21 文件） | 放行，仅打印 `What if:`，无删除 |
| provider 路径前拒 | `Remove-Item -LiteralPath 'Microsoft.PowerShell.Core\FileSystem::<合成目录>' -Recurse -WhatIf` | 拒绝（非本地 provider 路径） |
| 真实 21 文件 | `Remove-Item -LiteralPath <合成目录> -Recurse`（21 文件） | 拒绝（DEL-01，至少 21），文件全部保留 |
| 真实 20 文件 | 同命令作用于 20 文件子目录 | 放行并执行，恰好删除 20 个 |

结论：宿主侧新代码已在验收环境生效，20/21 边界、纯预览、provider 拒绝与不透明拒绝与源码一致。`application: applied` 表示配置层已应用；页面刷新只重取 Client 半区，宿主侧生效在刷新前已观察到，故不能把宿主生效归因于刷新。UI 显示、稳定环境部署、Linux 与并发竞态验收仍未完成。

## 二次收紧轮（v2）源码与真实 Runtime 验证结果

本段为第二轮「二次收紧」（白名单证据化、挂载边界、预览、provider 谓词、边界与预算细化）的**源码与隔离 Runtime 验证**，与上文首轮数字独立。**live 激活已在验收环境复验（见上节）；UI 显示、稳定环境部署与跨平台/Linux 实跑仍未完成**，正文只给出结论，精确数字只在本记录出现一次。

可复现命令（与上文相同）：设置 `DSH_RUNTIME_PATH` 指向 `0.2.2-rc.2` 的 `@deepseek-ai/dsh/package.json` 后：

- 全量 `verify/run-verify.mjs`：**719 tests / 651 pass / 0 fail / 68 skip**，`Source verification: PASS`。skip 均为运行环境门控（既有语料「No independent definite oracle」、明确排除用例、POSIX-only 及 Windows 上真实 `/proc` 集成用例），非隐藏失败。
- 真实 `ToolRuntime` 严格语义 `strict-runtime.test.mjs`：**9 / 9 pass / 0 fail / 0 skip**。新增覆盖：真实 `-WhatIf` 预览排除（25 预览 + 1 真删 → allow）、混合真实 25 → DEL-01、observation-unknown 目标 0 dispatch。
- 维护用分层检查：**PASS**（core 文件 7 个；由私有维护环境运行验证）。
- `git diff --check`：exit 0（无尾空白/冲突标记；仅 CRLF 归一化提示）。

v2 关键行为（源码级，见正文与白名单文档）：白名单须「形态匹配 + 证据 `verify.eligible`」双通过才减计数；Cargo 取消自动豁免（`Cargo.toml` 仅边界 marker）；TS 仅有限子集；Linux 挂载边界用 `/proc/self/mountinfo`（含同设备 bind）；真实 `-WhatIf` 为预览不入清单、混合真实删除仍全计；provider 非本地路径前拒；边界包含区分大小写、与执行 cwd 独立；共享单一扫描预算超限 DEL-07；U+FFFD/非 well-formed 文件名拒绝不漏计。

## 第三轮（v3）源码与真实 Runtime 验证结果

本段为第三轮「语言运行时放行、shell 脚本分析与统一删除强提示」的**源码与隔离 Runtime 验证**，与上文各轮数字独立。live 激活已在验收环境复验（见下节）；UI 显示、稳定环境部署与跨平台实跑仍未完成；正文只给结论，精确数字只在本记录出现一次。

可复现命令（设置 `DSH_RUNTIME_PATH` 指向 `0.2.2-rc.2` 的 `@deepseek-ai/dsh/package.json`）：

- 全量 `verify/run-verify.mjs`：**741 tests / 673 pass / 0 fail / 68 skip**，`Source verification: PASS`。
- 真实 `ToolRuntime` 严格语义 `strict-runtime.test.mjs`：**11 / 11 pass / 0 fail / 0 skip**。新增：`node --version`/`python -V` 放行、`node -e`/`python -c` 拒绝（0 dispatch）、`>20` 删除拒绝含统一强提示。
- 维护用分层检查：**PASS**（core 文件 7 个）。
- 文件哈希：以 SHA-256 核对成员合并文件（deletion-intent.js / test、shell-analysis.mjs / test）与集成改动文件，无越界改动。

68 项 skip 均为运行环境门控（既有命令语料「No independent definite oracle」、明确排除用例、POSIX-only、以及 Windows 上需真实 `/proc` 的 Linux 挂载集成用例），非隐藏失败；注入 `DSH_RUNTIME_PATH` 后真实 Runtime 严格用例 11 项全部执行。

v3 关键行为：语言运行时脚本（`node/python/perl/ruby/php/deno/bun/uv`）放行、不计数；其内联代码开关（`-e/-c/-p/-r/-E/-i`、stdin `-`）仍 `DI-INLINE-CODE` 拒绝；`bash/sh/dash/zsh <脚本文件>` 与 `pwsh -File <脚本>` 在字面/存在/常规/≤1MiB/编码可判定时分析内容并计数，任何无法证明→unknown 拒绝（不支持 `./x.sh` 路径限定可执行）；所有删除拒绝（`DEL-*`/`DI-*` 删除族）与 `S-F1` 审批附统一强提示 `DELETION_DOCTRINE`（先列明并核对确切文件集）。20 门禁、白名单证据、预览过滤、挂载边界行为保持。

### 第三轮（v3）live 激活复验

验收环境以「Plugins 页关闭再启用」完成重新组合（仅刷新页面不会重载宿主半区）。因为该插件自身的策略拒绝插件管理器的变更类调用，重载必须由人工在管理页触发；本轮共两次（引导版、v3 终版）。复验使用合成 fixture，全部在仓库 `tmp/` 下，结束后已清理：

| 检查 | 命令形态 | 结果 |
|---|---|---|
| 语言运行时放行 | `node --version` | 放行，输出 `v24.12.0` |
| 语言运行时放行 | `python --version` | 放行；本地为 uv-first 提示 shim，返回规范文本而非解释器版本 |
| 内联代码拒绝 | `node -e "…"` | 拒绝 `DI-INLINE-CODE`，理由含统一强提示 |
| 未知命令仍拒 | `Test-Path <路径>` | 拒绝（未建模命令），理由含统一强提示 |
| 脚本内容计数 | `pwsh -NoProfile -File <21 条字面 Remove-Item 的脚本>` | 拒绝 `DEL-01`「至少 21、上限 20」，21 个文件全部保留 |
| 脚本内容放行 | `pwsh -NoProfile -File <2 条字面 Remove-Item 的脚本>` | 放行并执行，恰好删除 2 个（剩余 19） |
| 脚本内容不可证 | 同一 `-File` 形态但脚本含变量赋值 | 拒绝 `DI-UNKNOWN-SEMANTICS`（证明分析读取的是脚本内容，而非仅看命令行） |

结论：脚本文件分析确实把脚本文本送进解析器并以内容计数；放行路径真实执行；拒绝路径不改动文件；统一强提示已进入 `DI-*` 与 `DEL-*` 文案。上一节「不透明程序拒绝 `node --version`」一行因此改写为 v3 放行。（注意：上表「未知命令仍拒 `Test-Path`」是 v3 行为；v4 起未知程序名改为 L3 放行，该行已过时，见下「第三轮（v4）」）。

## 第三轮（v4）源码与真实 Runtime 验证结果

本段为第四轮「灾难性删除标准（L1/L2/L3）+ git 分级 + 框架工具放宽 + move 计数」的**源码与隔离 Runtime 验证**，与上文各轮数字独立。live 激活、UI 显示与稳定环境部署仍未完成；正文只给结论，精确数字只在本记录出现一次。

可复现命令（设置 `DSH_RUNTIME_PATH` 指向 `0.2.2-rc.2` 的 `@deepseek-ai/dsh/package.json`）：

- 全量 `verify/run-verify.mjs`：**790 tests / 722 pass / 0 fail / 68 skip**，`Source verification: PASS`（core=ds-intent、git-intent 与 git-evidence 成员产物测试均计入）。
- 真实 `ToolRuntime` 严格语义 `strict-runtime.test.mjs`：**15 / 15 pass / 0 fail / 0 skip**。新增：框架工具（`create_worktree`/`terminal_open`/`plugin_manager`）真实 dispatch；`terminal_send` 就地解析（普通命令 allow、非字符串文本 deny 0 dispatch）；`git clean` 证据缺失 fail-closed（0 dispatch）；`>20` 删除带 doctrine；git 分级实时端到端（`reset --hard`/`reset --hard <rev>` 拒绝、`reset --hard -- <path>` 计数、`checkout .` restore、`status` 放行）。
- 维护用分层检查：**PASS**（core 8 文件）。
- 文件哈希：以 SHA-256 核对成员合并文件与集成改动文件，无越界改动。

v4 关键行为：**L1** 物理设备/系统树/`.git`/销毁历史的 git 子命令拒绝；**L2** 可识别命令行删除计数（含工作区外目标、`move`/`Move-Item` 源删除 `DEL-14`），>20 拒绝；**L3** 未建模程序/`copy`/`create_worktree`/`terminal_open`/全部 `plugin_manager` 动作/常规 git 操作放行。git 分级由 `assessGit`（核心）与 `git-evidence`（证据）实现：销毁历史 `DI-GIT-REFUSE`、clean/restore/worktree 计数 `DEL-GIT-*`、证据缺失 `DEL-GIT-UNKNOWN` fail-closed。`terminal_send` 的文本就地按平台方言分析；`run_code` 仍拒。

### 本轮验证发现（真实 git / live 端到端，均已修复后复验）

用真实合成 git 仓库与真实 host gate 做端到端核验，发现并修复三处缺陷（均已在对应分支修复并补回归）：

1. **`git reset --hard <rev>` 未拒绝（防御不足，L1 漏放）**：一度被 `assessGit` 误判为 `restore`（把 commit 参数当成 pathspec），导致销毁历史的 `reset --hard` 被当作 restore 计数放行。正确口径：`reset --hard`（无 `--` 路径）一律拒绝，仅 `reset --hard -- <paths>` 走 restore 计数。已在核心 `git-intent.js` 修复，strict-runtime 补回归。
2. **命令形式 `Move-Item`/`mv` 未被计数（防御不足，L2 漏放）**：live 复现 `Move-Item`×21 被整体放行并真实移动。已在核心把移动命令纳入 `move-source` L2（源删除可枚举，>20 → `DEL-14`），host 把 `move-source` 纳入删除计数过滤；guard.integration 补回归（21 条 → `DEL-14`、单条放行）。
3. **非删除命令被 ENOENT/state-changing 误拒（过度防御，L3）**：`Copy-Item`/`New-Item`/`Move-Item ... -Destination <新路径>` 因 observation 的裸 errno（ENOENT）或 shell 分析的 `State-changing command` 被当成 unknown 而拒绝。修法：裸 errno 一律不因“路径尚不存在”拒绝；state-changing 仅在本次调用确有删除时保留（mutated 集合不可信 → fail-closed）；不放宽任何真实删除语义 unknown。guard.integration 补回归（三类放行、`New-Item; Remove-Item` 仍拒绝）。

其余真实场景复核通过：`git status` 放行、`git push --force` 拒绝、`git clean` 25 未跟踪拒绝（`DEL-GIT-CLEAN`）、`git worktree remove` 干净放行/脏工作树拒绝。

## 边界与未覆盖（诚实声明）

- **源码测试通过 ≠ 全量部署生效**。验收环境的 live 激活已复验（见「live 激活复验」）；UI 显示、稳定环境门禁、Linux/跨平台实跑与并发竞态仍需另行验证，本文不据此声称稳定部署完成。
- **非原子**：计数是 dispatch 前的观察。并发写者、或同一 invocation 内的前置 mutation 仍可能在计数后改变集合。本实现拒绝同调用内前置 mutation（intent 层）并在审批等待后重计；不声称并发 mutation 下的原子 ≤20 执行。
- **安全范围**：覆盖经 `ctx.tools` 受管调用与标准 OS 工具。**不经 `ctx.tools` 直接调用 runtime service（例如 PTC runtime 内部裸 Node 副作用）与本插件无关**——`run_code` 在受管入口被整体拒绝以阻断该通道，插件不承诺对绕过 `ctx.tools` 的直接服务调用提供 OS 强隔离。
- **平台**：Win32 上 Bash/posix 执行域的路径不能当作主机路径处理，WSL 删除无法可靠枚举时显式拒绝并要求明确的、受支持的主机命令（如字面 `Remove-Item`）。
- **运行时先验（v3 有意取舍）**：语言运行时的放行是「不分析其内部行为」的放行。因此运行时自带的清理/卸载子命令也在放行面内，例如 `uv cache prune`、`python -m pip uninstall`、`node` 脚本内的 `fs.rm`。这是用户明确选择的取舍（脚本由 agent 自行负责，防御重心在命令行拼写错误）；需要收回时应在核心层为这些子命令加白名单，而不是恢复整体拒绝。
- **脚本分析非原子**：脚本文件在分析读取与派发执行之间可能被替换（TOCTOU）。实现只保证「分析的是当时读到的 ≤1 MiB 文本」，不声称该文本与执行时字节一致；符号链接、目录、超限、编码不可判、相对路径无可证 cwd、非宿主域一律拒绝。
- **重载需人工**：插件自身拒绝插件管理器的变更类调用，因此更新宿主半区后必须由人在管理页关闭再启用（或重启实例）；仅刷新页面只重载 Client 半区。
- 运行时锚点为 `0.2.2-rc.2`；声明兼容区间 `>=0.2.1-rc.2 <0.3.0-0`，其他版本未复验。
