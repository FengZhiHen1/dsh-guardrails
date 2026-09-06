# TODO

## 已定位：git 依赖安装后 client 行消失 = web-next 启动中途致命失败的后遗症（2026-09-06 晚排查）

**现象**：web-next profile（dev 实例，0.1.2-rc.1）以 `github:` 依赖安装本插件后，浏览器端 client 行缺席——
`__DSH_BOOT__` 里没有 dsh-guardrails（同 profile 的 dsh-skill-manager 在），设置页「权限守护」卡片因此不出现。

**结论（根因）**：不是本插件的打包/声明问题，是**宿主那次启动根本没走完**。
`logs/i-e5bbda3d-*.log`（dev 实例，末次写入 10:34）尾部为致命崩溃：

```
dsh: plugin tree failed to load: failed to apply loader entry include (cordis:include):
failed to apply loader entry workspace (@deepseek-ai/dsh-workspace):
corrupt Zstandard session log: first frame is not exactly one header line
  assertZstdHeaderFrame ← readFirstZstdLine ← listArtifacts ← dsh-workspace [cordis.init]
```

即 `knowledge/shared/s01` **签名 C**（坏首帧 → 启动扫描全库，共享该 HOME 的实例启动即崩）。
链路：`listArtifacts` 抛 → plugin tree 中止 → 排在 `dsh.profile.bundles` **末位**的 guardrails 行拿不到 fiber
→ client 注册表按设计静默跳过（部署包 `@deepseek-ai/dsh-client-modules/lib/index.js:759`，
源码 `packages/client/modules/src/index.ts:905` 的 `entry.fiber === undefined`）。
**原「当前嫌疑」方向正确，但成因在上游启动失败，不在 guardrails 行本身。**

**已排除（全部带证据，无需再看）**：

| 嫌疑 | 结论 | 证据 |
| --- | --- | --- |
| `{default: …}` 对象形态不被认 | ❌ 排除 | 同 HOME 正常工作的 web profile 装的是 **v1.3.0**，其 `exports["./client"]` 同为 `{default:"./client.js"}`——对象形态一直可用 |
| 产物缺失 / 指向源码不合法 | ❌ 排除 | 安装件 `src/client/card.js` 在（21,095B），且它**就是合规惰性 CJS bundle**：`window.__ModuleLoader__.load({ id:'dsh-guardrails', factory })`（`knowledge/14` §3 要求的形态） |
| `resolveMeta` 静默返回 null | ❌ 排除 | `tmp/probe-clientrow.mjs`（复刻 `locatePkgJson`→`resolveMeta`，对 web-next 真实安装树跑 149 个 loader 行）判 `dsh-guardrails` = **CLIENT ROW**，clientPath 命中 |
| 依赖不可解析 / 行重复 / 行被 disable | ❌ 排除 | `@deepseek-ai/schemastery` 解析成功；`--dump-config` 中 `guardrails` 行唯一且无 `disabled` |

静态判定的 client 行共 51 个，其中 `@deepseek-ai/dsh-client-ui-schedule` 在本 profile 被无条件 `disabled: true`；
与浏览器观测到的「50 且缺 guardrails」不能精确对齐——**计数不是可靠裁判，以干净启动的真实图为准**。

**启动阻塞已解除（待实例门禁确认）**：坏首帧文件已在 10:41–10:50 被按 s01 §3 修复——
`sessions/--E-Project-Skills--/session-fee24621-…/`，原件旁路留 `session.jsonl.zstd.corrupt-single-frame.bak`，
修复件 1,247,005B 重新分帧，该会话 `storages/session_projcache/sessions/` 条目已删（红线 3.5）。
全库首帧复扫（`tmp/verify-first-frame.mjs`，695 个日志）**0 失败**，且探针经
`tmp/selftest-first-frame.mjs` 正对照验证（能抓单帧、放行合规 header 帧）。

**未完成门禁（缺一不可）**：

1. ✅ **已结案（2026-09-06 21:48 重启实测）**：dev/web-next 干净启动，设置页「权限守护」卡片出现 ⇒ client 行
   随启动修复一并回来，**本插件的打包/声明侧无需任何改动即可正常挂载**（原始症状就此归因完毕）。
   取证：实例日志 `logs/i-e5bbda3d-*.log` 崩溃块全属 10:34 历史残留，其后 4 次成功 `dsh web:`、**无**
   `N entries did not activate`；启动器 `logs/latest.log` 最后两条 doctor 记录停在 21:19:50 / 21:20:10
   （即修复前那次启动），21:48 重启后**零记录**。

2. ✅ 已做（2026-09-06 晚）：复发根因消除——`dev` 实例改挂**独立 HOME** `homes\dev`，
   `web-next` profile 在新 HOME 内**由 `dsh plugin add` 重建**（非目录搬迁：旧 profile 的 149 个 reparse point
   用绝对路径回指 `homes\stable-dev`，搬过去等于留一个半坏的预检场）。bundle 栈与依赖 spec 与旧 profile 逐项一致，
   `guardrails` 仍居末位；`--dump-config` exit=0、`dsh-guardrails` 静态判定 = CLIENT ROW。
   拓扑与工作流（dev 预检 → 通过后升 stable-dev）记于 `docs/dsh-dev-env-config-0.1.2.md`；
   跨实例共用 HOME 已入 AGENTS.md Security 红线。
   遗留：旧 `homes\stable-dev\profiles\web-next` 待新场验证通过后删除（未获指令不动）。
3. 存量损伤（不阻塞启动）：sweep 报的 seq gap 会话仍在
   （`--E-Project-DSH_Plugins--/session-2205a29b-…`（约 21.4 万事件）、`session-e1560a4f-…`）——
   表现为该会话「history unavailable」，修它有丢内容风险，按 s01 §2 须逐案与用户确认。


## 结案取证时附带查出：核心包被声明成 `dependencies`（2026-09-06 晚）

重启后启动器弹的两条「依赖树异常」把我引到一个**真实的插件缺陷**上：

- **弹窗本身是误报**：上游 doctor 拿 `@deepseek-ai/dsh` 的**发布版本号**去比被检包**自身版本号**
  （`doctor.rs:57-65` 供值、`:121-123` 比较），独立编号的核心库永不可能与它相等 ⇒ 必然升级为 Error。
  实测 dev/web-next 的 cosmokit 1.8.3 / schemastery 3.18.2 与其 CLI 树**逐项相同**。判读细则已写入
  `tools/dsh-launcher-patch/README.md` 验收实录（含"何时是真分叉、怎么自己比"）。
- **本插件确有一处可清理项，但我当时把它判重了**：`@deepseek-ai/schemastery` 挂在 `dependencies` ⇒ 安装时在 profile 的
  `node_modules/@deepseek-ai/` 落一份私有副本。**（2026-09-06 晚更正）** 本条原写"两份 module-local `Symbol()` 不等 ⇒
  该 profile 工具调用可**静默全灭**"——该机理**不适用于 schemastery**：它的跨边界身份是 `Symbol.for("schemastery")` /
  `Symbol.for("ValidationError")`（全局注册表 ⇒ 副本之间同一身份），实测私装 3.18.1 与安装树 3.18.2 并存数日、工具调用正常。
  真正致命的是 `cordis` 与携带 service key 的 `@deepseek-ai/dsh-*`（实测 `@deepseek-ai/dsh-tools` lib 内 `const key = Symbol()`，
  module-local ⇒ 版本相同也致命），而本插件对 `cordis`、`dsh-settings` **一直就是 peer**，从未触雷。
  故 `60ba0b0`（改判 `peerDependencies ^3.18.2` + 补 `devDependencies`，因 `src/adapter/host.js:10` 是装载期 import）
  的收益是**少一份冗余拷贝、消除未来漂移，属清理而非修 bug**。刷新 web-next 后该目录条目数 **0**、重启后弹窗消失、卡片仍在
  ——现象不变，变的是对危险等级的归因。
- **稳定 web profile 是"真分叉"那一例**（未处理，需用户指令）：`homes\stable-dev\profiles\web` 自 09-04 起
  每次启动弹 3 条同类 Error，其副本 cosmokit 1.8.2 / schemastery 3.18.1 **确实落后** rc.2 CLI 树的 1.8.3 / 3.18.2。
  来源是本插件旧装件 + `dsh-skill-manager`（带 `@deepseek-ai/dsh-storage-domain@0.1.0-rc.7`）；
  **两者源码现均已正确**（skill-manager 已是 peer `*` + devDep `0.1.2-rc.1`），故按现源码重装即清。
  但 web 是用户正在使用的稳定环境、刷新须过 test 实测门禁 ⇒ 未获指令不动。
- 规则曾据此起草进知识库（`knowledge/04` §7 泛化为"任何 `@deepseek-ai/*` 核心包一律 peer，不得进 dependencies"、
  `05` §7 失败表新增症状行、`21`/`22` 清单加复查项），**当晚被外部插件作者的反问证伪并收窄**（顶层 commit `1750285`）：
  作者把 `dsh-settings` 移进 peer 却把 `schemastery` 留在 deps，不是漏修一半，而是精确地按身份机制分类——
  DSH 一方 18 个包（`dsh-llm`、`dsh-tools`、全部 `dsh-tool-*`…）本来就把 schemastery 写在 `dependencies`。
  现行口径：`cordis` 与携带 service key 的 `@deepseek-ai/dsh-*` **必须 peer**；`schemastery`/`cosmokit` 可 deps；
  检测面由"该目录应为空"改为"**非空不等于故障**，须分类并逐项比版本"。过宽泛化的实际代价是给无害声明报假红、
  并驱动人去给上游提不该提的 issue。
- **教训（比结论更该留下）**：从一个观察（本插件有私装副本）跳到普适红线（所有核心包都危险）之前，先做两件
  十分钟就能查实的事——**① 数一方包怎么写这份声明；② 打开该包 lib 看身份符号是 `Symbol()` 还是 `Symbol.for()`**。
  两条都是硬证据，我当时一条都没做，只凭"看到副本在 profile 里"就推定了机理并写进基线。

**解除记录**：同日已把本插件与 dsh-skill-manager 从 test profile 解除应用（测试归测试，常态挂载在 web-next）。


