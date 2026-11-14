# DSR-021 非删除语义 unknown 放行与定向提示

- 状态：已采纳
- 日期：2026-11-14
- 关联：[DSR-019 删除计数与不确定执行拒绝](DSR-019-删除计数与不确定执行拒绝.md)、[DSR-020 灾难性删除标准](DSR-020-灾难性删除标准.md)

## 背景

v3/v0.2.0 引入 `DI-UNKNOWN-SEMANTICS`：解析层任何 `unknown` 都升级为拒绝（`deletion-intent.js` 经 `host.js` 二段判定）。一次 Windows 会话审计（464 次工具调用）发现 8 次拒绝全部为过度防御：7 次命令没有任何删除意图（只读查询/展示），1 次是 3 条**字面路径**的 `Remove-Item`。根因是把解析层的“状态/展示噪声”（脚本块参数、变量/环境赋值、字面变量、`.NET` 成员调用）当成了“执行通道不可分析”。同时拒绝文案只有一段英文散文，不含规则号、命令片段与替代建议，agent 只能猜着重写。

本决策收窄触发面，并统一 tool-return 的提示结构。**不放宽任何可能隐藏删除的路径**。

## 决定

### 1. 放行集合（仅当本次调用无真实删除）

- `Bash assignment changes state`、`PowerShell variable assignment changes state`、`PowerShell environment variable assignment changes state`；
- 只读中性命令的动态操作数/动态值（`echo/ls/cat/...`、`Write-Output/Get-ChildItem/Get-Content/Get-Location`）；
- 通用 `Dynamic command or argument` 只保留给**命令名为 null** 的执行通道；参数为 null 交删除/移动语法自行判定（删除语法的 null 目标仍 `DI-DYNAMIC-ARGUMENT` + 计划层 `DEL-02`）。

存在真实删除时，赋值/状态标记仍保留为保守 unknown。

### 2. 始终拒绝（硬约束，逐条保留）

- **动态目标删除/移动**：`Remove-Item $p`（`$p` 非字面量）→ `DI-DYNAMIC-ARGUMENT`（`deletion-intent.js` 的 null 参数）+ 计划层 `DEL-02`（`unknown:'dynamic-path'`）；`mv/Move-Item` 动态源同理。
- **动态命令执行**：`& $cmd`、`iex`/`Invoke-Expression`、`source`/`.`、`env/xargs/sudo/start` 等 → `DI-DYNAMIC-COMMAND`/`DI-UNSUPPORTED-COMMAND`。
- **通配/不可枚举目标** → null 参数路径拒绝。
- **执行通道不可分析**：动态内联脚本、不可读/超限/链接脚本文件、WSL/cmd、路径限定可执行、解释器内联动态 → adapter unknown 仍拒绝。
- **`>20` 计数门禁**：`DEL-01`/`DEL-14`/`DEL-GIT-*` 不变。
- **L1 灾难拒绝**：`ABS-01..03`、`DEL-12`（根）、`DEL-13`（`.git`）、物理设备/宿主系统树/销毁 git 历史。

### 3. 字面量 `cd` 跟踪

同一调用内、script scope、单字面参数（可选 `-Path`/`-LiteralPath`）的 `cd`/`Set-Location`/`sl`/`chdir`：以 `lstat` 确认目标存在、为目录且非符号链接后，把后续命令的 `cwd` 更新为该目录，删除计划据此计数。动态/多参数/带其他选项/非 script scope 的 `cd` 仍标 `State-changing command ... invalidates a fixed target set`；`pushd`/`popd` 不跟踪。无法证明的 `cd` 之后若有删除，按 unknown 拒绝（fail-closed）。

### 4. 成员/类型能力分级

- 属性访问、索引访问不产生 unknown（`$c.Count`、`$c[-1]`）。
- 实例方法**仅**放行纯字符串/格式化白名单：`Replace/Substring/Trim/TrimStart/TrimEnd/ToUpper/ToLower/ToString/PadLeft/PadRight/Split/IndexOf/LastIndexOf/StartsWith/EndsWith/Contains/Normalize`，且仅当目标为变量/属性链/字符串字面量（或本身是另一个已判定方法调用）。
- 静态类型 `::` 调用（`[IO.File]::Delete`）、非白名单方法（`.Delete()`、`$sb.Invoke()`）、成员链含不确定类型 → 仍 unknown。
- 基元类型约束（`[int]$x`）放行；自定义/未知类型转换仍 unknown。

### 5. 字面量常量传播（仅 PowerShell）

顶层、单一赋值、右侧为静态字面量、赋值位置早于使用的 `$p = 'literal'` 解析为字面量（恢复 `-LiteralPath $p` 的计数与凭据保护）。多次赋值、右侧为命令结果、循环/条件/脚本块内赋值仍为动态（fail-closed）。bash 侧不做常量传播（`shfmt` 展开语义复杂），保留为动态。

### 6. 凭据静态文本扫描（收窄到动态读取）

命令文本、`terminal_send` 文本、以及被当脚本读入并解析的文件源（`bash -File`/`pwsh -File` 内容）在**本次调用存在未解析的动态操作数（commands 任一 `args` 含 `null`）且决策为 allow** 时才静态匹配凭据基名（`CRED_BASENAMES`、`.env.*.local`、私钥名）与私钥头；命中升级为 `S-F1` 审批（只升不降）。路径全部可解析时由既有 path-check/S-F1 负责，不再做文本扫描——因此 `git commit -m "remove .npmrc from docs"`、`Select-String -Pattern '.npmrc' <file>`、`echo "checking .env"` 等普通命令不触发审批。不扫描 `write`/`edit` 正文（其路径仍由 path-check 判定）。

### 7. tool-return 五段式提示

所有拒绝与审批文案渲染为固定块：

```
[GUARDRAILS] DENY|ASK <RULE-ID> (<layer>)
Why: <点到具体 token/语句/表达式>
Trigger: <实际命令/参数/路径 + 解析器表达式详情，截断 200，凭据遮蔽>
Effect: <要检查/计数什么；为何无法完成>
Next: <最小可行替代>
```

删除类拒绝（DEL-*/DI 删除族/S-F1/S-F2/ABS-*）末句保留 `DELETION_DOCTRINE`。实现集中在 `src/core/diagnostics.js` 与 `host.js` 单点渲染。

## 后果

- 审计会话的 8 次拒绝按新策略全部放行（7 次只读、1 次 3 个字面删除 ≤20）；危险/边界对照（动态删除、动态命令、通配、>20、L1、执行通道）按预期仍拒绝。
- 新增 `src/core/diagnostics.js`；`host.js` 增加凭据静态扫描与统一渲染；`powershell-helper.ps1` 增常量传播、成员能力分级、基元类型约束放行与 extent 详情；`shell-analysis.mjs` 增字面 `cd` 跟踪与外部脚本源收集；`deletion-intent.js` 放行只读动态操作数并导出 `CLEARER`；`rules.js` 增 `textMentionsCredential`。

## 已知残余风险

- **成员/类型仍偏保守**：非白名单方法调用（含 `.Delete()` 以外的可用删除 API）与自定义类型转换仍拒绝，会误伤部分只读脚本；本轮不以放宽方法面换取覆盖，需后续以更细的类型判据再收窄。
- **自定义类型转换副作用**：仅基元类型约束放行；自定义类型仍 unknown。
- **bash 无常量传播**：`$p='literal'; Get-ChildItem -LiteralPath $p` 在 bash 下仍为动态（可能误拒）。
- **只读动态读取**：已知只读命令的动态路径不再拒绝；仅当本次调用含未解析动态操作数时才对文本做凭据基名扫描，若该文本身未出现凭据基名/私钥头（如 `$p = (Get-Item ...).FullName; Get-Content $p`），则不触发 S-F1（无法解析的读取保护有限）。这是有意的可用性取舍。
- **`cd` 跟踪的边界**：只跟踪经 `lstat` 证明的真实目录；符号链接、`..`、`~`、动态/多参 `cd` 不跟踪并 fail-closed。`cd` 与删除之间的并发/条件变化不原子。
- 非原子与覆盖范围限制同 DSR-020（并发写者、绕过 `ctx.tools` 的直接 runtime 调用、程序内部副作用不在覆盖内）。
