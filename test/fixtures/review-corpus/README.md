# 历史审查语料

这些文件包含早期设计下的审查样例。源码字段只能作为解析器输入，不得交给 Shell 执行，也不得用于观察实际磁盘目标。

现行 `pnpm verify` 通过 `test/corpus.test.mjs` 回放 `credential-cases.json` 中具有独立预期的凭据文本。`policy-cases.json`、`parser-cases.json` 和 `gate-cases.json` 保留原设计预期供查阅。现行规则、语言分析和派发行为由 `test/target-*.test.mjs` 验证。

单独输出凭据回放报告：

```powershell
node verify/corpus-replay.mjs test/fixtures/review-corpus/credential-cases.json credential-replay.json
```
