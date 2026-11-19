# dsh-guardrails TODO

本文件只记录产品与工程质量的**待办**，不含任何特定环境的部署、实例或运维条目。已完成项与历史取证不入此处。

## 待办

- [ ] **补齐执行分析覆盖**。核实 `terminal_send` 的解释器、有效工作目录和待提交输入状态。扩展常见 Python 与 Node 文件 API 之外的内容操作覆盖，保留更多 AST 原始位置，并核对通配内容操作的受保护目标。详见[执行分析契约](technical-details/执行分析.md)。
- [ ] **解释器脚本文件正文覆盖（RR-5）**：当前 `python`、`node`、`tsx`、`deno`、`bun` 后接脚本文件时只保留外层命令事实，不读取脚本正文，按覆盖缺口放行。若需覆盖脚本正文的删除/内容操作，按执行分析契约设计有界读取与来源证明，并同步验证矩阵。参考 DSR-028。
- [ ] **扩大可重建目录的证明范围**。当前只合并每个叶子都有独立再生证据的目录。`node_modules`、`dist`、`build`、`target` 等仍需包管理器或构建配置证据。
- [ ] **可重建豁免的工具约定证据**：评估把 Gradle `build/`、Go 构建缓存与输出、PHP `vendor/` 等原先按工具名排除的目录改为「工具约定证据」（如 `go.mod`、`vendor/modules.txt`、Gradle wrapper 存在）后再豁免；在此之前照常计数。
- [ ] **`data.redirect.truncate` 需求追溯**：规则模型将该条目标为内部细化候选，需求追溯未定，尚未启用；需补需求条目，或决定移除。决定前该规则不启用，不产生确认动作。
- [ ] **验证项目层配置边界**。核对 DSH 如何为插件提供可信的配置层来源。现有 Profile 规则配置及单次审批已纳入回归。
- [ ] **完成 Python 与 JavaScript/TypeScript 交付验证**。按[技术栈设计](技术栈设计.md)「分析器定版条件」取得定版证据；在目标 Linux 平台复测解析器，实测资源上限与供应链打包，并取得 `rimraf`、`fs-extra` 等第三方删除库的已证版本契约。
- [ ] **失败语义回归验证**：分别制造坏配置、局部覆盖缺口、必检分析超时、异常回包和计数失败，验证诊断与处置符合规则模型。在真实运行时记录插件复核、宿主审批与最终门禁的顺序，定位复核后的竞态窗口。
- [ ] **确定发布预算**。在目标平台用统一语料与并发测试测量解析、取证和盘存，确定总时限、字节、工作量和资源并发上限。验证预算耗尽的局部缺口与整次故障。
- [ ] **官方文件工具组合验收**。在目标组合逐个核对实际注册、参数和派发。启用 `apply_patch` 的组合验证纯解析接口和文件服务的目标语义，验证整份补丁的删除、移走和敏感文件检测，以及 `@deepseek-ai/dsh-fs-patch` 的接入与兼容。
- [ ] **平台实跑与性能留证**。完成目标宿主锚点 DSH `0.2.2-rc.2` 的完整安装与平台验收，在技术栈规定的各目标平台运行验收矩阵。分别记录解析器资产来源、校验结果、冷启动和稳态延迟。
- [ ] **人工标注历史语料回放**：用人工标注的真实语料评估误伤率与漏拦率；不得把合成用例通过率当作历史误伤率。
- [ ] **未覆盖出口的遮罩边界**：Native finalizer、结构化 value/meta/error/additionalContexts 等出口需要独立上游接口或逐工具契约才能扩大遮罩承诺，目前不承诺这些出口零泄漏。
- [ ] **云 / 数据库 / 容器 / 系统逐命令矩阵（长尾）**：DSR-031 已按 provider 补齐主要删除与不可逆资源变更面、备份/密钥/平台删除面（`src/adapter/analysis/commands-remote.js`）。剩余长尾仍为候选：`eks`/`glue`/`athena`/`redshift`/`kinesis`/`cloudtrail`、`bq`/`snowflake`/`databricks`/`supabase`、DNS/邮件/消息、CI/CD、`s3api delete-object(s)` 与 `s3 sync --delete`、`kubectl scale --replicas=0`/`apply --prune`。评审后再决定纳入与门控方式。
- [ ] **实测兼容矩阵并声明 peer 范围**。在目标宿主 `0.2.2-rc.2` 上实测本包对 Node 与各宿主包（`@deepseek-ai/cordis`、`@deepseek-ai/dsh-settings`、`@deepseek-ai/schemastery`）的 peer 范围及 DSH 兼容区间；取得实测证据后写入包声明，在此之前包声明只锚定目标版本。见[技术栈设计](技术栈设计.md)「运行时与关键库」。
- [ ] **容器与远端载荷的剩余形态**：`docker run|exec` 无宿主暴露时的载荷不分析、`--device`/卷映射之外的文件系统暴露、`ssh -o ProxyCommand` 与多跳跳板链、`sftp` 批处理、`parted` 交互式与 `printf | parted`、`zip -d`、`7z` 其余删除变体、`cmd` 双引号内含反斜杠路径的字面量折叠。见 DSR-031「不做」。
- [ ] **传输族与隧道**：`nc`/`ncat`/`socat`、`ssh -R`/`-D`、`scp -i` 身份文件读、`rclone`/`azcopy` 以外客户端的上行与隧道。是否纳入取决于对正常上传与隧道流量的摩擦容忍度（DSR-031 只做了元数据端点候选与本地读事实）。
- [ ] **`cmd.exe` 方言覆盖边界**：`for`/`if`/`%VAR%`、`/k` 交互、`del /s` 通配枚举目前记缺口放行；扩展前需定义可证范围。
- [ ] **凭据名单候选（需精确文件布局核实）**：`.azure/msal_token_cache.json`（新版 Azure CLI 令牌缓存）、gcloud `legacy_credentials/<account>/adc.json`（目录级不支持，只能按精确文件或 Profile `sensitiveFiles`）。核实前不加入内置名单。
- [ ] **预览选项语义矩阵**。逐工具按官方语义核对 `--dry-run`、`-WhatIf` 类预览选项；未核对的选项不标预览。见 [Shell 语法接入](technical-details/命令文本分析.md)「覆盖边界与验证要求」。
- [ ] **临时 Git 仓库清理的误伤**：删除含 `.git` 的临时目录会被 `catastrophic.git-metadata` 拒绝，或被 `git-metadata-inside-tree` 的 inventory 失败升级为 `execution.check-failed` 拒绝（实测：清理本轮取证用的临时仓库时两次被拒）。需评估「整目录删除」与「直接删除 `.git` 内容」的区分，避免正常清理被误伤。
