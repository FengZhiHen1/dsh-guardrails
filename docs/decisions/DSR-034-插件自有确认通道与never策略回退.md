# DSR-034 插件自有确认通道与 `never` 策略回退

- 日期：2026-11-19
- 状态：已决定

## 背景

DSH 宿主的审批策略 `never` 在分发前确定性地拒绝所有审批请求：`ApprovalService` 在进入应答方链路之前就按有效策略短路，任何 `approval.request()` 都得到 `rejected`。对本插件而言，这意味着「确认」被静默降级——用户界面上没有可接受的确认（审批 seam 在分发前即拒绝），工具调用却被拒绝，并且拒绝文案按「用户拒绝」呈现。真实情况是：策略拒绝被误归因为用户拒绝，且用户没有任何批准的机会。

触发场景：会话采用 `never` 策略（例如无人值守/自动化预设，或委派子会话被宿主固定为 `never`），本插件判定某次调用需要确认（批量删除、受保护文件内容操作、动态目标等）。此时既有行为是：插件调用 `approval.request()`，宿主返回 `rejected`，插件输出 `APPROVAL_REJECTED`「用户拒绝了本次调用」。用户既未看到卡片，也未做决定。

用户目标：不改变宿主权限预设，插件自身仍能在该场景下弹出一次确认，并且拒绝归因必须准确。

## 决定

1. **新增配置项 `alwaysAsk`**（boolean，默认 `true`，可热改）。当宿主有效审批策略为 `never`（或审批 seam 缺失）时，插件不再走 `approval.request()`，改走官方问答 seam：`ctx.get('userQuestions').ask({ questions, agent, signal })`，以 `intent.kind = 'approval'` 的**阻塞式单问题问答卡**弹出确认。已安装客户端对该意图不做专门特判，按**通用单问题问答卡**渲染：选项标签为英文 `Allow once` / `Reject`，中文界面下按钮仍为英文。用户选 `Allow once` 只放行当前调用；选 `Reject` 则拒绝当前调用。`alwaysAsk = false` 时退回自动拒绝（不提问）。

2. **通道优先级**（每次确认按此顺序选择通道）：
   1. 审批 seam `ctx.get('approval')` 存在，且该会话**有效策略为 `ask`** → 仍走官方 `approval.request()`。保留 `approval/asked`、`approval/decided` 审计，兼容 ACP 等应答方。
   2. 否则（有效策略为 `never`，或审批 seam 缺失），且 `alwaysAsk = true` → 走问答 seam 的通用单问题问答卡。
   3. `alwaysAsk = false`，或问答 seam 不可用/无应答方 → 拒绝，fail-closed。

   注意：审批 seam 存在且策略为 `ask` 时，若 `approval.request()` 返回 `unavailable`（无应答方），直接输出 `APPROVAL_UNAVAILABLE`，**不回退**问答通道。回退问答只在「策略为 `never`」或「审批 seam 缺失」时发生。

   有效策略的定义沿用宿主：会话 `approval/policy` 覆盖优先，否则部署默认策略，再否则 `ask`。实现读取 `approval.overrideOf(session)` 与会话配置的默认值，无需改动宿主。

3. **归因修正**：新增两个拒绝码，并收紧既有码的含义。
   - `APPROVAL_POLICY_NEVER`：有效策略为 `never` 且**没有可用应答方**（含 `alwaysAsk = false`、问答 seam 缺失、问答链路 `NO_PROVIDER`）。**没有交互应答方接受该确认**，不是用户拒绝。
   - `APPROVAL_DELEGATED`：操作发生在委派子代理会话。宿主把子会话审批策略固定为 `never`，且问答 seam 拒绝委派调用者（`DELEGATED_CALLER`），无法询问用户。不是用户拒绝。
   - 既有 `APPROVAL_REJECTED`：只在**真的有人拒绝**时出现（审批应答方返回 `rejected`，或用户在问答卡里选了拒绝项）。修掉「策略拒绝被说成用户拒绝」的误归因。

   三个码的区别：`APPROVAL_REJECTED` 有真实人类决定；`APPROVAL_POLICY_NEVER` 与 `APPROVAL_DELEGATED` 都**没有人参与**，区别在于前者由会话策略 + 无应答方导致、后者由委派子会话的限制导致。回退到自动拒绝或无人应答时，一律不得输出「用户拒绝」。

4. **不变的语义**：一次性授权（只放行当前调用、不落盘、不构成删除授权）；确认后的完整重访与作用域比对；`askTimeoutMs` 等待预算；灾难身份不可确认；规则号契约不变（不新增、不改既有规则号）。

5. **与宿主审批策略正交**：本决定不要求、也不修改宿主的权限预设；`alwaysAsk` 只作用于插件自己发起的确认，不改变其他来源的确认行为。

## 理由

- 宿主 `never` 是部署级安全姿态，用户未必意识到它会让插件的确认在无交互应答方参与的情况下被拒绝。插件对自己发起的确认负责，应在不改变宿主策略的前提下仍能询问一次。
- 官方问答 seam 已是稳定的 UI 通道；已安装客户端对 `intent.kind = 'approval'` 没有专门特判，按通用单问题问答卡渲染（选项标签为英文 `Allow once` / `Reject`，中文界面下按钮仍为英文）。复用它仍能以最低成本恢复「可确认」，无需自造 UI 或改宿主。
- 保留 `approval.request()` 作为首选通道，是为了维持审批审计事件与 ACP 等应答方的兼容；问答通道只作为 `never`/审批 seam 缺失时的回退，不是替换。
- 默认开启是因为静默拒绝让「确认」语义彻底失效（用户被以「拒绝」告知，却没有交互应答方参与）。代价可控：只在 `never`/缺 seam 时触发，且可配置关闭。

## 被否决项

1. **改宿主权限预设（把会话从 `never` 改为 `ask`）**。否决：这要求用户放弃部署级的无人值守姿态，并影响所有工具与所有应答方，超出插件职责；也与「不要求用户改宿主权限预设」的目标冲突。
2. **只在设置页提示「`never` 会静默拒绝确认」**。否决：只解释不修复，用户仍然无法批准必要操作，事故照旧发生。
3. **把 `userQuestions` 用于所有确认（不区分策略）**。否决：会丢失审批通道的 `approval/asked`、`approval/decided` 审计，并降低 ACP 等应答方的兼容；对 `ask` 策略是能力降级。
4. **只修文案、不做通道**（把 `APPROVAL_REJECTED` 直接改成 `APPROVAL_POLICY_NEVER`）。否决：能消除误归因，但不恢复「可确认」能力，`never` 下仍然无法放行必要操作。

## 已知取舍（必须保留）

- **审计影响**：问答通道路径**不产生** `approval/asked`、`approval/decided` 审计事件；且 `APPROVAL_POLICY_NEVER` 路径（策略 `never` 且无可用应答方）在改前经 `approval.request()` 会写这对审计事件，改后不再写。也就是说，`never` 下的确认可能完全没有 `approval` 审计对——这是真实取舍。其可见记录只能依赖问答 seam 的请求事件与客户端卡片/会话消息；持久审计与 ACP 应答方兼容弱于审批通道。
- **无应答方 fail-closed**：无客户端应答方时（headless、CI、未连接该会话）仍拒绝，`userQuestions` 链路以 `NO_PROVIDER` 结束，插件按 `APPROVAL_POLICY_NEVER` 归因。安全方向不放松。
- **子代理限制**：委派子代理会话无法使用该通道（宿主把子会话审批固定为 `never`，且问答 seam 对委派调用者抛 `DELEGATED_CALLER`），归因 `APPROVAL_DELEGATED`。
- **对会话策略的有意覆盖**：该通道在 `never` 策略下仍向用户提问，属于对会话策略的有意覆盖。这是产品取舍，默认开启、可配置关闭（`alwaysAsk = false`）。
- **等待预算**：问答通道复用 `askTimeoutMs` 预算。`ask()` 对 approval 意图要求阻塞式请求（不得带 `wait`），因此由插件自建计时与 `AbortController` 包装；到点中止按 `APPROVAL_TIMEOUT` 处理（自动拒绝，非用户拒绝）。

## 后果

- 会话为 `never`、有客户端、`alwaysAsk = true`：需要确认的调用会弹出通用单问题问答卡（选项 `Allow once` / `Reject`）。选批准只放行当前调用，随后执行既有的完整重访与作用域比对；选拒绝输出 `APPROVAL_REJECTED`。
- 会话为 `never`、无客户端应答方：拒绝，输出 `APPROVAL_POLICY_NEVER`，文案不再说「用户拒绝」。
- 委派子代理会话：拒绝，输出 `APPROVAL_DELEGATED`。
- 会话为 `ask`：行为不变，仍走 `approval.request()`，审计事件照旧。
- `alwaysAsk = false`：`never`/缺 seam 时自动拒绝，输出 `APPROVAL_POLICY_NEVER`。
- 灾难身份、一次性授权、规则号与 `askTimeoutMs` 语义均不变。

## 证据与验证

**已由源码/运行契约证明**（目标运行时 `0.2.2-rc.2` 安装树）：

- `@deepseek-ai/dsh-user-approval` 的 `ApprovalService.decide()`：在进入应答方链路前判定有效策略，`never` 直接返回 `rejected`（`src/index.ts`）。因此既有 `approval.request()` 在 `never` 下必然 `rejected`。
- 同一 `request()` 先 append `approval/asked`、`decide()` 之后再 append `approval/decided`，故改前经 `approval.request()` 的 `never` 路径仍会写这对审计事件（但没有交互应答方接受该确认）——这是旧行为；改后 `never` 下的问答路径与 `APPROVAL_POLICY_NEVER` 路径都不再写。
- 有效策略可由 `approval.overrideOf(session)` 与会话默认策略读取（同包源码；同类公开读取见内置 auto-review 的 `ctx.approval.overrideOf(agent.session) === 'never'` 与权限预设的 `approval.config.policy ?? 'ask'`）。
- `@deepseek-ai/dsh-user-questions` 的 `UserQuestionService.ask()`：approval 意图校验为「单问题、无 `wait`、非 `multiSelect`、标签互异且与选项一一对应、必须带 `detail`」，违者 `BAD_INTENT`；`assertLiveRoot()` 对 `subagent` origin 抛 `DELEGATED_CALLER`；无应答方 `NO_PROVIDER`；信号中止 `ASK_ABORTED`。这些错误码与语义均来自源码。
- `@deepseek-ai/dsh-subagent` 的委派策略捕获：子会话 `approval/policy` 固定为 `never` 且标记 `source: 'delegation'`（`child-agent.ts`）。
- `@deepseek-ai/dsh-user-questions` 的会话投影只折叠 `ask_user_question` 工具调用（`projection.ts`），插件直接调用的阻塞式 ask 不进入该投影；这印证问答通道没有持久审计行。

插件侧实现点（本仓库）：`src/adapter/dsh-gate.js` 的 `askOnce()` 负责通道选择，`askViaQuestions()` 发出通用单问题问答卡，`questionFailureReason()` 把问答异常映射为拒绝码，等待预算统一由 `runBoundedAsk()` 施加；配置 schema 在 `src/adapter/host.js` 的 `Config`，字段校验在 `src/core/rules.js`。

**待实测（本轮没有实测证据，不得写成已验证）**：

- GUI 是否把 approval 意图按通用单问题问答卡渲染，并以英文 `Allow once` / `Reject` 的所选标签返回（中文界面下按钮仍为英文）；
- `askTimeoutMs` 到点中止后错误映射为 `APPROVAL_TIMEOUT` 的端到端行为；
- 真实委派子代理会话是否稳定返回 `APPROVAL_DELEGATED` 而非挂起；
- headless / 未连接会话是否确实以 `NO_PROVIDER` fail-closed；
- 实会话日志中确认问答通道与 `APPROVAL_POLICY_NEVER` 路径都没有 `approval/asked`、`approval/decided` 行。

## 追溯

承接 [DSR-016](DSR-016-插件自有审批超时.md) 的插件自有限时确认；确认语义与失败分类归 [规则模型](../technical-details/规则模型.md)。需求 R-09、新增 R-21。
