# 稳定审查语料

这些文件是测试数据，不是待运行脚本。任何 source 都只能送入官方 Parser/shfmt stdin；不得交给 pwsh/bash 执行。测试不读取 source 中的路径，也不查询这些目标的真实磁盘/仓库身份。

默认 `node --test test/*.test.mjs`、`npm test`、`npm run check` 和 `npm run verify` 均包含 `test/corpus.test.mjs`。

| 语料 | 条数 | 自动断言 |
|---|---:|---|
| policy-cases.json | 91 | 官方 AST → 操作提取 → 合成目标事实 → 策略判定 |
| parser-cases.json | 115 | 必须出现/不得出现的命令、参数、重定向、Unknown、语法与预算失败 |
| credential-cases.json | 151 | 42 条命令与45条文本有独立明确预期；64条未定/观察/不支持通道显式 skip |
| gate-cases.json | 28 | 门禁状态审查目录，结构校验；行为证据对应既有 guard/approval/lifecycle 测试，未逐条自动执行全部序列 |

共385条资料；命令/文本回放357条，其中293条确定断言、64条明确跳过。门禁目录28条不能加入“执行通过”计数。通过率不等于真实语料误伤率或跨平台验收。

语料由 DeepSeek V4.1 Flash、GLM 5.3 Flash、GPT 6 Luna 独立审查构造，再由主维护者复核设计预期。保留子代理原始 implementationStatus/preFixObserved 作为审查时间点信息，当前执行结果以默认测试为准。

主维护者修正了三类 oracle/执行器问题：Git per-worktree admin 不是 common-dir 主体；原生成器漏掉 glpat-/github_pat_ 格式分隔符；预算占位文字需要程序化生成2100条命令。没有为了匹配实现而降低危险/正常预期。动态目标的语义 Unknown 用分类标签匹配，不绑定大小写文案。

修改任一强预期时须写明设计条款和正反例。候选未批准规则不得通过改测试预期变成默认政策。观察组 OBS 由实现产生，不能作为独立正确性证据，默认 skip。

单独回放并留JSON报告：

```powershell
node verify/corpus-replay.mjs test/fixtures/review-corpus/policy-cases.json reports/policy-replay.json
node verify/corpus-replay.mjs test/fixtures/review-corpus/parser-cases.json reports/parser-replay.json
node verify/corpus-replay.mjs test/fixtures/review-corpus/credential-cases.json reports/credential-replay.json
```
