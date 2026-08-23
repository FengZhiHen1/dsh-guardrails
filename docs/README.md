# dsh-guardrails 设计

## 权威范围

本文是 `docs/design/dsh-guardrails/` 的入口，唯一拥有本主题的目录组织、当前状态、阅读顺序与文档地图。需求事实归 `requirements.md`，技术机制归 `technical-details/`，选型理由归 `decisions/`。本文不重复定义任何需求或技术事实。

## 当前状态

- 主题：`dsh-guardrails`（DSH 权限守护层，Host 插件，bundle 形态）。
- 设计基线：2026-08-17 经用户逐项确认，见 [决策记录](decisions/)。
- 实现状态：**已实现（v1.0.0 + v1.1.0 + v1.2.0）**——bundle 包形态（`dsh.bundle.patch` + 包内 `cordis.patch.yml`）、五类规则（env / git / credentials / destructive / system）、范围 B 增量（R0 补漏与 W0 系统区写拦截，DSR-001）、操作类型分级（列举 vs 内容访问）、配置校验、规则矩阵与生命周期测试 101 例全过（行覆盖 97.12%，门禁 ≥80%）；**防御层全量配置化（DSR-006，v1.1.0）**——叶子级可配（操作级叶子 + destructive 六子族 + `unverifiable` 键）；**配置入口按 DSH 官方范式（v1.2.0）**——导出 Schemastery `Config` schema，loader 在 `apply` 前验证/填默认值。`.dsh`（含会话历史）不敏感（DSR-003 重访注记）。
- 工程化设计：2026-08-17 经用户确认，结构重构已随 v1.0.0 落地——`lib/` 四模块拆分 + 四层测试（单元/集成/组合/名单驱动）+ `verify` 全量脚本，见 [engineering.md](technical-details/engineering.md)。
- 已实现设计（2026-08 定稿，v1.1.0 落地）：**防御层全量配置化**——类别键扩展为布尔/对象（操作级叶子 `read`/`modify`/`list`/`write`）、`destructive` 拆分六子族（git/machine/eval/cli/bulk/target）、新增 `unverifiable` 键，见 [DSR-006](decisions/DSR-006-defense-configuration-2026-08.md) 与 [requirements.md](requirements.md) R-03。
- 部署：test profile 源码直挂（`link:` 符号链接，重启生效）；web profile 当前以 `file:` 打包产物 tarball（`dist/dsh-guardrails-1.0.0.tgz`，只读快照）过渡挂载，发布后切换 registry 版本——web 只吃发布物（AGENTS.md 红线：禁止源码直挂）。
- `missing evidence`：符号链接/Junction 的真实路径解析行为（现状为纯段运算，不解析链接）；跨平台（Linux/macOS）敏感清单；`reg` 注册表类命令文本的覆盖范围。

## 阅读顺序

1. `requirements.md`：先确认目标、范围、约束与验收。
2. `technical-details/README.md`：按机制阅读顺序展开。
3. `decisions/`：需要了解决策理由时阅读。

## 文档地图

| 文档 | 唯一权威范围 |
|---|---|
| `requirements.md` | 目标、用户与场景、功能范围、需求约束、非目标与验收条件 |
| `technical-details/README.md` | 技术细节目录的阅读顺序与文档地图 |
| `technical-details/rule-model.md` | 敏感类别 × 操作类型矩阵、路径级与命令文本级检查、名单结构与 fail 语义 |
| `technical-details/command-analysis.md` | PowerShell 命令文本词法、动词分类、列举模式判定、破坏性分析与固有限制 |
| `technical-details/deployment.md` | 包形态、部署红线、安装验证、生效流程、测试体系与发布路径 |
| `decisions/` | 真实重大取舍的备选、评价、后果与重访条件 |
