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
- **但本插件确有缺陷**：`@deepseek-ai/schemastery` 挂在 `dependencies` ⇒ `dsh plugin add` 会在 profile 的
  `node_modules/@deepseek-ai/` 落一份**私有副本**，与 CLI 树那份并存——两份 module-local `Symbol()` 不等，
  该 profile 工具调用可**静默全灭**（加载期零报错）。今天副本版本恰好一致才没爆，下次 CLI 升代就真分叉。
  已改判 `peerDependencies ^3.18.2` 并补 `devDependencies`（`src/adapter/host.js:10` 是装载期 import，
  裸 node 单测须能解析；profile 侧靠自身 `autoInstallPeers: false` 不会装回）——子仓库 `60ba0b0`。
  刷新 web-next 后该目录条目数 **0**，重启后弹窗消失、卡片仍在。
- **稳定 web profile 是"真分叉"那一例**（未处理，需用户指令）：`homes\stable-dev\profiles\web` 自 09-04 起
  每次启动弹 3 条同类 Error，其副本 cosmokit 1.8.2 / schemastery 3.18.1 **确实落后** rc.2 CLI 树的 1.8.3 / 3.18.2。
  来源是本插件旧装件 + `dsh-skill-manager`（带 `@deepseek-ai/dsh-storage-domain@0.1.0-rc.7`）；
  **两者源码现均已正确**（skill-manager 已是 peer `*` + devDep `0.1.2-rc.1`），故按现源码重装即清。
  但 web 是用户正在使用的稳定环境、刷新须过 test 实测门禁 ⇒ 未获指令不动。
- 规则已收紧入知识库：`knowledge/04` §7（泛化为"任何 `@deepseek-ai/*` 核心包一律 peer"＋装载期 import 须配
  devDeps）、`05` §7 失败表（新增"某 profile 工具调用全部死在 `.prepare`、加载期零报错"症状行）、
  `21`/`22` 清单（含安装后复查"该目录应为空"）。**原口径只点名 `cordis` 与 `@deepseek-ai/dsh-*`，
  `schemastery` 正落在缝里**——这就是当初漏掉它的原因，清单跑一遍也不会亮红。

**解除记录**：同日已把本插件与 dsh-skill-manager 从 test profile 解除应用（测试归测试，常态挂载在 web-next）。


