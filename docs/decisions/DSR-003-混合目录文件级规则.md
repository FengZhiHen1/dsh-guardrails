# DSR-003：混合目录按文件级规则（.dsh/sessions）

## 上下文

实测 `~/.dsh` 是混合目录：`profiles/`、`skills/`、`attachments/`、`storages/` 等大量内容无害；真敏感面在文件级——`.credentials.yaml`、`.auteur-media-secret`（凭据）与 `sessions/**`（会话历史）。基线把 `.dsh` 整体放进凭据目录名单，导致列出目录被误伤。

## 真实方向与评价

- 目录级黑名单：`.dsh` 整体敏感。误伤列举，且把无害内容与敏感内容混为一谈。
- 文件级规则：`.dsh` 本身不敏感；凭据文件由文件名名单覆盖（`.credentials.yaml` 已在列，`.auteur-media-secret` 实测存在需补入）；`sessions` 子目录按独立隐私类别（内容访问拦、列举放行）。

评价：文件级规则符合参考文档"对象性质 × 操作类型"模型，且与操作分级（DSR-002）天然配套；目录级是"为省名单维护而牺牲可用性"的过度保守。

## 最终决定

采用文件级规则：新增 sessions 类别——路径相邻段 `[.dsh, sessions]` 命中即内容访问拦截；`.auteur-media-secret` 补入凭据文件名名单；`.dsh` 从凭据目录名单与命令文本正则移除。

## 直接后果

- 新增 `sessions` 配置键（缺省开）。
- `Get-ChildItem .dsh` / `ls ~/.dsh` 放行；`Get-Content .dsh/sessions/...` 拦截；read/grep/write/edit 指向会话历史拦截。

## 重访条件

- `~/.dsh` 结构变化（sessions 目录改名/迁移）时更新相邻段规则。

## 重访记录（2026 用户决策）

**sessions 类别已整体移除**：`.dsh` 目录（含 `sessions/` 会话历史）不再属于任何敏感
类别，内容读/写/改/删与列举全部放行；配置键 `sessions` 一并移除（传入即挂载失败）。
保留不动：`.dsh` 下的凭据文件（`.credentials.yaml`、`.auteur-media-secret` 等）仍由
credentials 名单覆盖；破坏性类别（管道批量删除等）与 `.dsh` 无关，照常拦截。
本记录的"最终决定"与"直接后果"为当时决策事实，以其后的重访记录为准。
