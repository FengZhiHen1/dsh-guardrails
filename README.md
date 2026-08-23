# dsh-guardrails — DSH 权限守护层

对 AI 发起的工具调用做**硬阻断**（不弹确认框）的 Host 插件：

1. 访问敏感 `.env` 文件（read/write/edit/grep/pwsh）
2. 访问 `.git` 目录内部（read/write/edit/grep/glob/pwsh）
3. 访问凭据文件（SSH 私钥、云/注册表 token、密钥存储、浏览器资料、Windows 凭据/DPAPI、系统 Hive、转储文件）
4. 写入 Windows 系统区（W0：**只拦写**，读与列举放行）
5. 执行高风险破坏性命令（PowerShell 方言静态分析）

仅拦截 AI 工具调用，不拦截用户自己的命令；纯静态分析，不产生子进程。

**覆盖的工具名是固定的**：`read` / `write` / `edit` / `read_image` / `grep` / `glob` / `pwsh`。
其他工具不在此插件的规则范围内（harness 自身的权限管线仍对它们生效）。

## 拦截语义：敏感类别 × 操作类型

访问按操作分类，不是"提及即拦"：

| 敏感类别 | 内容读/写 | 元数据列举 |
|---|---|---|
| 凭据（`.ssh`/`.aws`/`.gnupg`/`.kube`/`.pki`、`id_rsa`/`.npmrc`/`.credentials.yaml`/`.auteur-media-secret`、范围 B：`.git-credentials`/`NTUSER.DAT`/`pagefile.sys`/`SAM`/浏览器资料/DPAPI 等） | 拦 | 拦（文件存在性本身敏感） |
| `.env` 文件 | 拦 | 放行 |
| `.git` 目录 | 拦 | 放行 |
| 系统区（`C:\Windows`/`C:\Program Files`/`C:\Program Files (x86)`/`C:\ProgramData`/`C:\Recovery`、用户启动目录、PowerShell Profile） | 只拦写 | 放行 |

- 命令文本：整条命令全部由元数据动词组成（`Get-ChildItem`/`ls`/`dir`/`Get-Item`/`Test-Path`/`Resolve-Path`/`Split-Path` 等，以及格式化/过滤动词 `Select-Object`/`Sort-Object`/`Where-Object`，且无 `$()` 子表达式、无重定向）才按"列举"处理；否则按内容访问走全规则（未识别命令保持保守）。
- 命令文本先经**字面量重建**：可静态求值的 `$()`（如 `$('nv')`）与同命令内的赋值变量（`$p='.env'`）会先还原为字面量，再跑全部规则——`$()` 拼接、变量间接调用无法再隐藏敏感名（每次 pwsh 调用都是全新进程，变量无法跨调用持久）。
- 重建后仍含动态 `$()` 的命令：若命令本身或**内容/删除类动词**（`Get-Content`/`Set-Content`/`Remove-Item`/`Copy-Item`/`Out-File`/`New-Item` 等）的参数由动态表达式构成，目标无法静态验证，一律保守拦截（与类别开关无关的 fail-safe 层，受 `unverifiable` 键控制，缺省开）。
- 工具层：`read`/`grep`/`write`/`edit` 是内容访问（全规则）；`glob` 只列举（仅凭据目标拦截）。
- **系统区写检测**（W0）：写类动词（`Set-Content`/`Remove-Item`/`New-Item`/`Copy-Item`/`Move-Item`/`Out-File` 等）的静态目标、重定向目标（`>`/`>>`/`2>`）命中系统区前缀即拦；带 cd 链模拟（`cd C:\Windows; Set-Content x y` 同样被拦）。读与列举始终放行（DSR-005）。
- 破坏性分析（`rm -rf`、`Get-ChildItem | Remove-Item`——含中间夹过滤/格式化动词或 `%`/`ForEach-Object` 脚本块的管道、`git reset --hard`、机器级命令、**绝对盘根删除**（`Remove-Item C:\`/`D:\`/`/` 及 `C:\*` 通配形态）等）逐子族受 `destructive` 配置控制（缺省全开，DSR-006）；其中删除目标分析（盘根/工作区根）属 `target` 子族，关闭对应拦截即放行。
- 混合目录说明：`.dsh`（含 `sessions/` 会话历史、skills/attachments/profiles 等）不是敏感类别，读/写/列举均放行（见 DSR-003 重访注记）；`.dsh` 下的凭据文件（`.credentials.yaml`、`.auteur-media-secret`）仍按凭据名单拦截。

## 包形态（DSH 官方 Bundle 范式）

- `package.json` 声明 `dsh.bundle.patch: ./cordis.patch.yml`，`files` 包含
  `index.js` 与 `cordis.patch.yml`；
- `cordis.patch.yml` 是随包分发的安装层：`insert` 一行
  `{ id: guardrails, name: dsh-guardrails, config: {...} }`，行名与包名一致，
  供 Node 模块解析；
- profile 通过 `dsh plugin --profile <name> add <包>` 安装：pnpm 写入依赖，
  CLI 自动把声明了 `dsh.bundle` 的包追加进 `dsh.profile.bundles`。

## 部署形态（单一源码）

本目录是**唯一源码**，按 AGENTS.md 红线分 profile 挂载：

- **test（试验）profile**：允许源码直挂。`dsh plugin --profile test add`
  指向本目录，得到 `link:` 依赖（node_modules 中是符号链接，源码改动
  **重启即生效**，无需重新安装）。插件行由 bundle 层提供，test 的用户层
  patch 不得再 insert 同一行（重复 id 会导致整个 profile 启动失败）。
- **web（稳定）profile**：只吃发布物。当前形态为 **`github:` 钉 ref 的 git 依赖**：`dsh plugin --profile web add github:FengZhiHen1/dsh-guardrails#<commit>`（pnpm 克隆进 store 的只读快照，ref 钉死 commit——非分支/tag 漂移、不指向本地可写源码目录，符合 AGENTS.md 红线中"未发布插件可走 `github:` git 依赖"）。`npm publish` 发布后切换为 `dsh plugin --profile web add dsh-guardrails`（registry 版本）。每次源码更新需 push 到该仓库并重新 add 新的 commit ref。

## 配置覆盖

防御层全量配置化（DSR-006）：每个防御层都是独立开关，缺省全开（关闭必须显式写 `false`，子键缺省继承 `true`）。类别键接受布尔（= 整类开/关）或对象（= 按操作细分）。

**配置入口按 DSH 官方范式（0.1.1）**：插件导出 Schemastery `Config` schema（依赖 `@deepseek-ai/schemastery`），loader 在 `apply` 前验证行的 `config` 块并填充默认值——默认值只属于 schema（bundle 行不写 config），非法类型在加载期报 `ValidationError` 并挂载失败；未知键/未知子键由 `evaluateRules` 兜底拒绝。profile 覆盖形态示例：

```yaml
- id: guardrails
  config:
    env:          { read: true, modify: true }   # .env 路径内容访问（读/写）
    git:          { read: true, modify: true }   # .git 内部内容访问（读/写）
    credentials:  { read: true, modify: true, list: true }  # 凭据 读/写/列举
    system:       { write: true }                 # 系统区写入（W0）
    destructive:
      git: true      # git reset --hard / clean -f / force push / branch -D ...
      machine: true  # 关机/磁盘/net user/杀进程/清空等机器级命令
      eval: true     # 不可信内容执行（curl|bash、.NET 直调）
      cli: true      # docker prune / terraform / kubectl / aws s3 rm / dropdb ...
      bulk: true     # Get-ChildItem | Remove-Item 管道批删
      target: true   # 盘根/工作区根/动态 cd 删除目标分析（绝对破坏层，慎关）
    unverifiable: true  # 动态 $() 目标 fail-safe（慎关：检测力下降）

# 例：test 环境放松——只对 CLI 数据破坏器降级：
- id: guardrails
  config:
    destructive: { cli: false }
```

- 非法配置（未知键、非布尔、非对象）挂载即失败，不会静默降级。
- 关闭任意一个防御层前，请先阅读上方"已知限制与边界"中对应条目的风险标注；`destructive.target` 与 `unverifiable` 关闭后对应拦截**完全放行**。
- v1 五键布尔写法依然有效（等价于对应类别全开/全关）。
- 若要改某 profile 的配置，在**该 profile 自己的 `cordis.patch.yml`** 里按 `id: guardrails` 做 id-targeted override，而不要再次 insert 同一行；重复 insert 会导致整个 profile 启动失败（`duplicate loader entry id`）。

## 已知限制与边界

- 覆盖工具固定为 `read`/`write`/`edit`/`read_image`/`grep`/`glob`/`pwsh`；
  其他具备文件能力的工具（如 `bash`、`git` 工具等）不在本插件规则内。
- 纯静态文本分析：符号链接/junction 指向敏感目标的逃逸无法探测（插件
  不做 fs 探测）；`$env:` 环境变量路径（如 `$env:windir\x`）无法静态解析，
  不命中前缀规则（动态 `$()` 目标另有 fail-safe 拦截）。
- 文本引用规则对"提及"敏感：在模式/字符串里**提到**凭据名或 `.env`
  （如 `Select-String -Pattern "\.env"`）的只读元数据命令也会被拦——
  保守取舍，避免文本混淆绕过；`git` 等常见只读命令不在列举白名单中，
  只能走全规则。
- 系统区前缀按 C: 系统盘建模；Linux/macOS 清单与注册表类命令
  （`reg`/`HKCU:`）不在 v1 范围（见 DSR-001）。
- 判定层 fail-closed（无法分类的命令按全规则处理），钩子层 fail-open
  （guard 内部异常记录并放行，防止死锁会话）——两层语义不可互换。

## 常见错误与排查

- **合法操作被拦**：拒绝消息会说明命中的类别与替代方案。属保守取舍（见"已知限制与边界"）时，可让用户手动执行该操作，或在 profile 自己的 `cordis.patch.yml` 中按 `id: guardrails` 关闭对应规则（`env: false` 等），重启 profile 生效。
- **profile 启动失败，报 `unknown config key` / `must be a boolean`**：插件行的 `config` 有非法键或非法值；按错误信息修正 profile 的 patch 层。
- **重复行启动失败（`duplicate loader entry id`）**：bundle 层已 insert 了 `guardrails` 行，用户 patch 层又 insert 了一次；删除用户层的重复行，改用 id-targeted override。
- **guard 内部异常**：控制台出现 `[guardrails] internal error (fail-open)`——插件判定层出错但已放行（防死锁），收集错误信息反馈修复。

## 测试

`node --test test/`（Node ≥20）：mock ctx 直接驱动 `tools.guard` 钩子，
覆盖误伤消除与防护保持矩阵、生命周期（mount/dispose/remount ×20、HMR
重放、双挂载不静默去重、非法配置挂载失败），不触碰文件系统。

`node verify/run-verify.mjs` 全量验证：单元/集成/生命周期测试、覆盖率门禁
（行覆盖 ≥80%）、test/web 组合断言（每 profile 恰一行、web 依赖为发布物
形态）、tarball 干净目录安装 + 导入冒烟。

## 开源协议

[MIT License](LICENSE)（Copyright © 2026 FengZhiHen1）。源码仓库：
<https://github.com/FengZhiHen1/dsh-guardrails>——web profile 通过
`github:` 钉 ref 的 git 依赖安装当前版本（见"部署形态"）。
