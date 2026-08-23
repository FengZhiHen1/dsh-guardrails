# dsh-guardrails 命令文本分析

## 权威范围

本文唯一拥有 `dsh-guardrails` 对 pwsh 命令文本的词法、动词分类、列举模式判定、破坏性分析与固有限制。规则模型与名单归 `rule-model.md`，需求归 `requirements.md`。

## 结论先行

pwsh 命令文本是唯一"只有文本、没有操作类型"的通道，因此先做**列举模式判定**（是否为纯元数据列举），再按模式套用敏感规则；破坏性分析独立于敏感规则，两种模式下都执行。解析不了的命令一律按全规则处理（fail-closed）。

## 词法（tokenizePwsh）

对命令文本做纯静态词法切分，不执行任何代码：

- 单词（word）：连续非空白、非分隔符字符。
- 引号：单引号 `'...'` 与双引号 `"..."` 原样吞入内容；反引号 `` ` `` 为转义符，吞入下一个字符。
- 子表达式 `$(...)`：按括号配平提取 `nested` 列表，原位置替换为占位 `$(x)`（子表达式内容单独递归分析）。
- 分隔符（sep）：`;`、换行、`|`、`&`（`&&`/`||` 合并为一个），按分隔符切分为 fragments。

## 动词分类

命令名经 `normalizeCommand` 归一（小写、去连字符）后分类：

| 集合 | 成员（基线） | 语义 |
|---|---|---|
| METADATA_CMDS | `getchilditem`、`gci`、`ls`、`dir`、`getitem`、`gi`、`testpath`、`resolvepath`、`getlocation`、`gl`、`pwd`、`splitpath`、`joinpath` | 列举/元数据：不读取内容 |
| REMOVAL_CMDS | `removeitem`、`rm`、`ri`、`rmdir`、`del`、`erase`、`rd` | 删除 |
| CD_CMDS | `cd`、`setlocation`、`sl`、`pushd` | 目录切换（破坏性分析跟踪 cwd 链） |
| LIST_CMDS | `getchilditem`、`gci`、`ls`、`dir` | 列举（管道删除检测） |
| 其余（未列出） | — | 视为内容访问或写/删，套全规则 |

> DSR-006（v1.1.0 已实现）：`classifyVerb → read / modify / list` 协助（复用 `CONTENT_VERBS` / `WRITE_VERBS` / `METADATA_CMDS` 集合）与 `assessContentClass`（整条命令的操作级分类：`>` 或修改类动词 → modify；`$()`/未知动词 → unknown 全规则）一起，使命令文本层按操作叶子（`env.read` 与 `env.modify` 等）判定，而不是类别整开关；引用规则的分组与叶子保持一致。

## 列举模式判定（isListingOnly）

整条命令同时满足以下条件才按"列举"处理（只查凭据目标）：

1. 不含 `>`（PowerShell 中 `>` 只表示重定向，重定向目标可能是敏感文件）；
2. 无 `$()` 子表达式（子表达式内可能含内容访问命令）；
3. 每个 fragment 的首命令（`unwrapFragment` 跳过 `$var`、`&`、`.` 前缀后）都 ∈ METADATA_CMDS。

不满足任一条件 → 全规则（env / git / credentials 文本引用 + destructive 分析）。

## 敏感文本引用

- `ENV_REFERENCE`：匹配 `.env` 及 `.env.*`（排除 `$env:NAME` 形式）。
- `GIT_DIR_REFERENCE`：匹配独立成词的 `.git`（后随分隔符或行尾）。
- `CRED_TEXT_REFERENCE`：凭据文件名/目录段/组合的文本出现（`.pub` 排除）；`.dsh`（含会话历史）不在任何引用规则中（见 DSR-003 重访注记，rule-model.md）。

## 破坏性分析（assessDestructive）

独立于敏感规则，对命令文本做片段级模拟分析：

| 类别 | 判定 |
|---|---|
| 机器级 | `shutdown`（重启/关机/休眠）、`restartcomputer`、`stopcomputer`、磁盘工具（`cleardisk`/`initializedisk`/`formatvolume`/`removepartition`）、`net user/localgroup /add` |
| 进程 | `stop-process`/`taskkill` 目标为 node/dsh/pwsh/explorer/cmd |
| 远程内容执行 | `iex`/`Invoke-Expression`；管道进 `bash`/`sh`/`pwsh` 等；`curl \| bash` 模式 |
| 清空 | `Clear-Content`；`Set-Content` 到 `$null` |
| 管道删除 | `Get-ChildItem`（含与不含 `-Recurse`）管道 `Remove-Item` |
| git 高危 | `reset --hard`、`clean -f`、强推/删远端 ref、`branch -D`、`stash drop/clear`、`checkout/restore .` |
| 文件/磁盘 | `shred`、`find -delete`、`dd of=`、`mkfs*`、`fdisk`/`parted`/`format`/`diskpart`、`truncate -s 0` |
| 基础设施/云 | `docker system prune`、`terraform destroy`、`kubectl delete`、`aws s3 rm --recursive` |
| 数据库 | `dropdb`、`redis flushall/flushdb`、psql/mysql 等 CLI 的 drop/truncate/delete |
| 删除目标分析 | 删除命令的目标解析：`cd` 链模拟 cwd；目标为 `./*`/`$pwd` 等"全部"且 cwd 为工作区根 → 拦；cwd 动态不可知 → 拦（无法验证删除范围） |
| .NET 直接 API | `[System.IO.File/Directory]::Delete/WriteAllText` |

> 子族分组（DSR-006，v1.1.0 已实现；逐族可配，缺省全开）：`machine` = 机器级 / 进程 / 清空；`eval` = 远程内容执行 / .NET 直接 API；`cli` = 文件磁盘 / 基础设施云 / 数据库；`bulk` = 管道删除；`git` = git 高危；`target` = 删除目标分析。

## 固有限制（接受并文档化）

- **动态路径不可解析**：`$var`、通配符、`Join-Path` 拼接等无法静态求值，敏感引用按文本出现判定或放行；这是"正则兜底"存在的原因，也是误伤的来源——操作分级已把无害列举与内容访问分开，残余误伤面在动态路径内容访问。
- **别名不完备**：动词集合是常用子集，未知动词按全规则处理（保守方向正确）。
- **cwd 链为近似模拟**：`pushd`/动态目标会使 cwd 状态变为 unknown，此时删除"全部"目标无法验证 → 拦。
- **`>` 判定**：命令文本含任何 `>` 即退出列举模式（全规则），可能把无害列举升级为保守模式，但不会漏拦。

## 与工具通道的关系

工具通道（read/grep/write/edit/glob）直接携带路径与操作类型，不需要命令文本分析；命令文本分析只服务于 pwsh 工具。两者名单与规则语义一致（同一 `checkPath` 规则集，命令文本层增加动词/引用判定）。
