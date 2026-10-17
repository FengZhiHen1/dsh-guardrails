# 原设计对照审查与稳定语料回归

本轮由4个独立审查任务覆盖解析器、门禁审批、目标策略、凭据出口。使用 DeepSeek V4.1 Flash、GLM 5.3 Flash、GPT 6 Luna；主维护者逐项复核，子代理发现不是直接接受的最终结论。所有生成命令仅作为官方解析器 stdin 数据，未执行任何被测命令，未查询其真实危险目标。

## 稳定测试交付

语料已纳入插件自己的 test/fixtures/review-corpus 与 test/corpus.test.mjs；默认 test/check/verify 会执行。回放实现 verify/corpus-replay.mjs 可单独写 JSON 报告，不导入任何命令执行器或磁盘目标观察器。

| 数据 | 条数 | 回放状态 |
|---|---:|---|
| 规则命令 | 91 | 全部确定断言通过；目标身份由 syntheticTargets 提供 |
| 语法命令 | 115 | 全部解析契约通过；2条预算用例程序化生成2100命令 |
| 凭据命令/文本 | 151 | 87条确定断言通过；64条未定/观察/不支持项明确 skip |
| 门禁状态目录 | 28 | 结构校验；对应已有真实运行时/模拟测试，未宣称全部状态逐条执行 |

共385条资料；357条命令/文本回放，293条强断言、64条skip。默认完整测试为459项，395通过、0失败、64跳过，约12.96秒。数量包括父子测试和原有回归，不等于459条不同命令。quality_floor PASS（0 error、4 warning）；复杂度提醒未隐藏。源码语法及运行时集成通过，未启动实例。

## 确认且已修复

| 问题 | 修复与回归 |
|---|---|
| Unix通用选项表将rm -f/cat -n目标吞掉 | 改命令专用带值选项，rm/cat/less/head正反回归；91条策略回放原有1条失败归零 |
| PowerShell未调用脚本块当执行 | 区分字面块直接调用/明确执行块与存储/事件参数；不扫描纯存储块体 |
| PowerShell switch false与WhatIf | AST常量保持合并参数，Recurse:false不递归，wi/WhatIf演练不生成破坏；Bash同词不抑制删除 |
| 字面数组目标丢失 | ArrayLiteral/ArrayExpression仅递归消费官方AST纯表达式元素，不执行数组内容 |
| 动态目标无Unknown诊断 | 两方言动态参数产生类别标记，Host同execution结果保留解析/观察Unknown；不因此新增Ask/Deny |
| 协议字段部分未验证 | unknown、scope、redirects的字段类型验证，畸形回包fail-closed |
| 元数据观察单次IO无法及时返回 | caller cancel/1500ms预算race有界结算；底层原生stat不能强杀，后台迟到观察不能授权 |
| ANSI前缀遮住provider边界 | 仅识别到凭据时返回去色遮罩文本；普通彩色文本保持原样 |

## 审查结论复核与撤回

- 子代理将函数Unknown Allow报为P1：不采纳。设计明确有效语义Unknown不自动拒绝，且函数展开是已声明限制；采纳诊断不得静默丢失部分。
- 2048命令/有界队列拒绝：合理资源限制，不作为策略缺陷；保留压力输入断言。
- 未知配置挂载失败：DSH插件生命周期事实，不由失效插件自我保证fail-closed。不能以忽略未知配置自动补救；仍需部署激活门禁。
- 非法live配置拒绝：安全方向正确，原报“设置负数可随意提交”未证明实际schema写入渠道可绕过；不计已证实产品故障。
- 审查方曾称Node stat支持signal：未采纳该API建议，改为有界等待并明确不能取消内核IO。
- accept{value}未核实：本轮已使用DSH_RUNTIME_PATH运行真实ToolRuntime/PTC测试，原“只有mock”的结论不成立。
- 凭据语料glpat/github_pat生成器遗漏格式分隔符，已保留oracleCorrection修正格式，不改变预期；否则不能把无provider格式的随机字符串当漏遮。
- 多出口error/meta残余已由原验证矩阵公开，不宣称已消除。也不因纯字符串redact通过而声称error.message已改。

## 保留的覆盖缺口

1. cd/Set-Location/pushd改变后续相对路径，当前没有完整控制流cwd传播；持久Shell跨调用变量/位置也未完整建模。显式工具workdir已经读取，审查中把workdir与cd混为一谈的部分撤回。此项不能声称已防住，当前未新增Unknown审批政策。
2. sed -i、openssl/perl/awk等未识别CLI效果、bash -c内层、外部脚本、PowerShell静态方法/存储块及函数调用未完整展开。只对实际语义表内操作承诺检测，不能把S-F1说成任意程序的机密性边界。
3. Linux实跑、真实历史标注回放、多Agent生产延迟/队列压力、自动设置页面走查和完整部署门禁未完成。
4. 结构化object/enum value、error/meta/additionalContexts、Native post后的finalizer、预审前输入参数仍可能保留凭据。候选规则仍未默认启用。

原始审查过程数据留管理仓库tmp/guardrails-review供人工核对；稳定接收件以插件测试目录为准。审查目录的implementationStatus/preFixObserved保留当时观测，不用它替代本轮实际回归。未提交推送，未改稳定Profile。
