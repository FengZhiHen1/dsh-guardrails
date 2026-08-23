# dsh-guardrails 部署

## 权威范围

本文唯一拥有 `dsh-guardrails` 的包形态、部署红线、安装与验证命令、生效流程、测试体系与发布路径。需求归 `requirements.md`，规则机制归 `rule-model.md` 与 `command-analysis.md`。

## 结论先行

按 DSH 官方 Bundle 范式交付：包内声明 `dsh.bundle.patch` 并携带 `cordis.patch.yml` 安装层，profile 用官方 CLI（`dsh plugin add`）安装并自动对账 `dsh.profile.bundles`。部署红线（AGENTS.md）：**test 源码直挂，web 只吃发布包**；任一 profile 禁止 bundle 层与用户 patch 层重复 insert 同一行（重复 id 导致整个 profile 启动失败）。

## 包形态

`plugins/dsh-guardrails/`（仓库内唯一源码）：

- `package.json`：`name: dsh-guardrails`，`dsh.bundle.patch: ./cordis.patch.yml`，`files: [index.js, cordis.patch.yml]`，`scripts.test: node --test test/`。
- `cordis.patch.yml`：随包分发的安装层，`insert` 一行 `{ id: guardrails, name: dsh-guardrails }`——**行不带 config**：默认值属于插件 config boundary（导出的 Schemastery `Config` schema 的 `.default()`，DSH 官方范式，见 DSR-006/rule-model.md 配置模型）；用户覆盖在该行基础上按 `id: guardrails` 合并。行 `name` 与包名一致供 Node 模块解析，行 `id` 是稳定身份供 profile 层覆盖。
- `index.js`：官方插件形态——具名导出 `name` / `inject` / `Config`（Schemastery schema）/ `apply(ctx, config)`（0.1.1 范式，无 default export），注册 `ctx.tools.guard` 钩子。
- `test/`（`*.test.mjs`）：规则矩阵、命令解析与生命周期测试。

## 部署红线（AGENTS.md 固化）

- **web（稳定）profile**：绝对拒绝源码直挂——插件只能来自已发布 npm 包（registry 版本）。禁止 `link:`/`file:` 指向源码、junction/symlink 指向源码（含 `profiles/node_modules` 共享解析层）、patch 层用源码路径引用插件行。流程：修改插件 → 打包发布 → `dsh plugin --profile web add <已发布包>`。
- **test（试验）profile**：允许源码直挂（`link:` 依赖，符号链接实时可见），用于快速验证；源码改动重启即生效。
- **任一 profile**：同一插件禁止在 bundle 层与用户 patch 层重复 insert（同 id 重复行 → `duplicate loader entry id`，profile 启动失败）。覆盖 bundle 行配置用 id-targeted override，不再 insert。

## 安装与验证

CLI 路径（PATH 上无 `dsh`）：`node E:/Project/Open_Source/deepseek-harness/apps/cli/lib/bin.js`。

```sh
# test：源码直挂（link: 依赖 + bundles 自动对账）
node .../bin.js plugin --profile test add E:/Project/DSH_Plugins/plugins/dsh-guardrails

# 部署后必查（AGENTS.md）：无重复插件行、无源码解析残留
node .../bin.js --profile test --dump-config
node .../bin.js --profile web --dump-config
```

预期结果：test 与 web 的 dump 各出现 `# == dsh-guardrails` 层且恰一行 `id: guardrails / name: dsh-guardrails`，解析自 `dsh-guardrails` 包；web 依赖为发布物形态（当前 `file:` tarball 过渡，发布后切换 registry）。test 的 `node_modules/dsh-guardrails` 为符号链接指向仓库。

## 生效流程

- test：编辑源码 → 重启 test profile（端口 3099）即加载（符号链接直挂，无需重装）。
- web：当前以 `file:` tarball 过渡挂载（pnpm 装入 store 的只读快照）；改代码须先 `npm pack` 更新 `dist/` 产物并重装；发布后切换 `dsh plugin --profile web add <registry 版本>`。

## 测试体系

`node --test test/`（Node ≥20）用 mock ctx 直接驱动 guard 钩子：

- 不触碰文件系统、不 spawn 进程（`node --test` 的运行器需子进程，沙箱内需提权运行）。
- 覆盖：误伤消除（列举 .dsh/.git/.env 放行、`.dsh` 读/写放行）、防护保持（凭据/破坏性全拦）、列举模式边界（重定向、混合命令）、配置开关、R0/W0 新增类别用例、生命周期（mount/dispose/remount、HMR 重放、非法配置挂载失败）。

## 发布路径（web 启用前置步骤）

1. 移除 `package.json` 的 `private: true`。
2. `npm publish`（或 `pnpm pack` 交付 tarball）。
3. `dsh plugin --profile web add dsh-guardrails`（registry 版本）。
4. `--dump-config` 复查恰一行。
