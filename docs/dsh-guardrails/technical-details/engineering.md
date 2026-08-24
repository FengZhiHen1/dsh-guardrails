# dsh-guardrails 工程结构与测试体系

## 权威范围

本文唯一拥有 `dsh-guardrails` 的源码目录结构、模块边界、依赖方向、测试分层、覆盖率门禁与验证流程。规则机制归 `rule-model.md` 与 `command-analysis.md`，部署归 `deployment.md`，需求与验收归 `requirements.md`。

## 结论先行

- 源码结构：`index.js` 薄入口 + `lib/` 四模块（`rules` / `path-check` / `command` / `destructive`），依赖单向，名单唯一维护点。
- 测试体系：六层（单元 / 生命周期 / 集成 / 组合 / 发布 / 名单驱动），零依赖 `node:test`；覆盖率报告 + 门禁阈值 80% 起步。
- 验证流程：`verify/run-verify.mjs` 一键全量（单测+集成+生命周期 → 覆盖率 → 组合断言 → tarball 干净安装冒烟）；冒烟为手动步骤。

## 源码结构

```text
plugins/dsh-guardrails/
├── index.js                  # 薄入口：config 开关、guard 钩子装配、deny 消息、fail-open 容错
├── lib/
│   ├── rules.js              # 敏感名单数据 + 文本引用正则 + 类别开关求值（唯一同步维护点，无依赖）
│   ├── path-check.js         # 路径归一 + checkPath（按操作类型套规则）+ 系统区判定
│   ├── command.js            # 词法 tokenize + 动词集合 + 列举模式判定 + 敏感文本引用判定 + cd 链状态 + 系统区写检测
│   └── destructive.js        # 破坏性命令分析（assessDestructive 与全部命令集合）
├── cordis.patch.yml
├── package.json
├── README.md
├── test/
│   ├── fixtures/             # 行为级样本：命令组合场景、路径边界
│   ├── rules.test.mjs        # 名单/正则单测（名单驱动，遍历数据表生成正反用例）
│   ├── path-check.test.mjs   # 路径规则单测
│   ├── command.test.mjs      # 词法/动词/列举判定/cd 链/system 写检测单测
│   ├── destructive.test.mjs  # 破坏性分析单测
│   ├── lifecycle.test.mjs    # mount/dispose/remount/HMR/双挂载/非法配置（mock ctx 记录 disposer）
│   └── guard.integration.test.mjs  # mock ctx 驱动 guard 钩子的全矩阵（含现有基线用例）
└── verify/
    └── run-verify.mjs        # 全量验证：单测+集成+生命周期 → 覆盖率 → composition 断言 → 干净安装冒烟
```

### 模块职责

| 模块 | 职责 | 不承担 |
|---|---|---|
| `index.js` | 官方插件入口（具名导出 `name`/`inject`/`Config`/`apply`，0.1.1 范式）：`Config` 为 Schemastery schema（loader 在 apply 前验证并填默认值）、调用 `evaluateRules` 归一化叶子、`ctx.tools.guard` 装配、deny 消息文案、钩子异常 fail-open | 任何规则判定逻辑 |
| `lib/rules.js` | 名单数据（文件名/后缀/目录段/相邻段组合/系统区前缀与段组合）、文本引用正则、叶子级配置求值与校验（DSR-006：类别布尔/对象、操作叶子、`unverifiable`） | 路径解析、命令词法 |
| `lib/path-check.js` | 路径归一（`slash`/`segmentsOf`/`resolvePath`/`baseNameOf`）、`checkPath`（`metadataOnly` 分级 + 操作叶子，DSR-006）、`isSystemAreaPath` | 命令文本分析 |
| `lib/command.js` | `tokenizePwsh`、动词集合（METADATA/REMOVAL/WRITE/CD/LIST）、`isListingOnly`、`classifyVerb`/`assessContentClass`（操作级分类，DSR-006）、敏感文本引用判定、cd 链状态（`applyCwdCommand`）、`assessSystemWrite`（W0 写检测） | 破坏性判定 |
| `lib/destructive.js` | `assessDestructive` 全部集合与分支（机器级/清空/管道删除/git 高危/远程执行/磁盘/DB/.NET/盘根删除/cd 链模拟）+ 六子族 `sub` 门控（DSR-006） | 敏感名单 |

### 依赖方向

```text
index.js → @deepseek-ai/schemastery   # 官方配置 schema（运行时依赖，v1.2.0）
index.js → lib/path-check.js → lib/rules.js
index.js → lib/command.js    → lib/rules.js
index.js → lib/command.js    → lib/path-check.js   # 路径解析与系统区判定
index.js → lib/destructive.js
lib/destructive.js → lib/command.js      # 词法、片段工具与共享 cd 链状态
lib/destructive.js → lib/path-check.js   # cd 链模拟的路径工具
lib/rules.js（无依赖）
```

模块间不得反向依赖；`rules.js` 是名单与文本正则的唯一维护点，任何名单变更只改此文件。

## 测试体系

### 分层

| 层 | 载体 | 覆盖内容 | 运行条件 |
|---|---|---|---|
| 单元 | `test/{rules,path-check,command,destructive}.test.mjs` | 直接 import `lib/*`：名单匹配、路径解析、词法、动词分类、列举判定、cd 链状态、system 写检测、破坏性分析分支 | 无（纯内存） |
| 生命周期 | `test/lifecycle.test.mjs` | mock ctx 记录 effect disposer：mount/dispose/remount ×20、HMR 重放、双挂载不静默去重、非法配置挂载失败 | 无（纯内存） |
| 集成 | `test/guard.integration.test.mjs` | mock ctx 驱动完整 guard 钩子：误伤消除、防护保持、配置开关、混合命令、重定向、R0/system 新增用例（AC-05/AC-06） | 无（纯内存） |
| 组合 | `verify/run-verify.mjs` 内嵌 | 调 `bin.js --dump-config`：test/web 各恰一行、无重复行、web 依赖为发布物形态 | 本机 `DSH_HOME` 与 harness 路径（环境变量，参照 `dsh-anchored-standard` 的 verify 模式） |
| 发布 | `verify/run-verify.mjs` 内嵌 | `npm pack` → 临时目录 `npm install` tarball → 导入并校验包内文件（干净环境，无源码/兄弟包） | npm CLI（`node <npm-cli.js>`） |
| 名单驱动 | `rules.test.mjs` 遍历 `rules.js` 数据表 | 每个名单项自动生成"命中正例 + 相邻反例" | 无 |

### 名单驱动机制

`rules.js` 以结构化数据导出名单（如 `{ basenames: [...], suffixes: [...], dirSegments: [...], combos: [...], systemPrefixes: [...] }`）。`rules.test.mjs` 遍历数据表为每项生成正反用例。**新增名单项 = 修改 `rules.js` 数据 = 测试自动覆盖**，不要求手工补 fixture；`test/fixtures/` 只放行为级样本（组合场景、边界、回归命令），不放名单逐项样本。

### 覆盖率与门禁

- `node --test --experimental-test-coverage`（Node 24 内置，零依赖）。
- 门禁：行覆盖 ≥ 80%；`verify/run-verify.mjs` 解析文本报告 `all files` 行自动断言（2026-08 实测格式，总体行覆盖 96.15%）。
- 安全关键代码（名单、破坏性分支）不设豁免；漏覆盖分支必须在实现时补用例或显式标注豁免理由。

### 脚本

| script | 命令 | 内容 |
|---|---|---|
| `test` | `node --test test/` | 单元 + 集成 |
| `check` | `node --check index.js lib/*.js && node --test test/` | 语法门禁 + 测试（对齐 `dsh-anchored-standard`） |
| `verify` | `node verify/run-verify.mjs` | 全量：单测+集成 → 覆盖率摘要 → composition 断言 → 冒烟提示 |

## 验证流程

`verify/run-verify.mjs` 执行顺序：

1. `node --test test/`：单元 + 集成，失败即退出；
2. 覆盖率报告：输出行覆盖摘要，低于门禁阈值给出告警（阈值执行方式见上）；
3. composition 断言：调用 `bin.js --profile test/web --dump-config`，断言 test 与 web 各恰一行 `guardrails` 且解析自 `dsh-guardrails` 包、web 依赖为发布物形态、均无重复行与源码残留；
4. 输出汇总，并提示冒烟步骤（重启 test profile 后手动验证真实拦截行为）。

## 约束与重访条件

- C-01 零测试依赖：只用 Node 内置 `node:test` 与 coverage，不引入测试框架。
- C-02 名单单一维护点：任何敏感名单或文本正则变更只改 `lib/rules.js`。
- C-03 依赖方向单向：`lib/rules.js` 不得 import 其他模块。
- 重访：覆盖率门禁的自动化执行（CI 或脚本解析）、CI 接入、跨平台 fixtures（Linux/macOS 命令样本）。
