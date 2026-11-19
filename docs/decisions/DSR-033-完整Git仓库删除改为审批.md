# DSR-033 完整 Git 仓库的删除改为审批（ask）

## 背景

DSR-020 把「真实 Git common-dir 主体（`.git` 本体）」列为灾难身份，绝对拒绝且不可确认；删除包含 `.git` 的目录树则一度被升级为 `execution.check-failed` 拒绝。实践中删除一个完整仓库（清理一次性仓库、迁移、去版本化）是合法操作，硬拒绝无法批准，属过度防御。用户要求：**完整 Git 仓库的删除改为审批（ask），不再拒绝**；**Git worktree（`.git` 是文件指针）不触发该审批**。

## 决定

1. **完整 Git 仓库的删除产出确认（审批），不再产生灾难身份拒绝。** 目标为 `.git` 目录本身、其子目录（如 `objects`/`refs`）、bare 仓库目录，或**包含 `.git` 目录的目录树**时，删除事实保留，判定为确认（`data.delete.bulk` / `data.delete.dynamic`），确认范围明确写「complete Git repository metadata (.git) … would be destroyed」。不再产生 `catastrophic.git-metadata` 身份。
2. **完整仓库识别**：目标路径是或位于名为 `.git` 的目录之下；或目标目录本身具备 Git 目录布局（`HEAD` 文件 + `objects`/`refs` 目录，覆盖 bare 仓库与改名的 git 目录）。识别只读、失败不升级为拒绝（D1）：无法识别时按普通删除分档处理。
3. **Git worktree / Linked Worktree 不触发该审批**：`.git` 是**文件**指针，历史在别处。删除 worktree 目录按普通文件计数（≤20 放行、>20 确认）；删除 worktree 内的 `.git` 指针文件是单文件普通删除。
4. **`catastrophic.git-metadata` 规则号保留但不再产生**（reserved，仅保留在规则目录以维持编号稳定）。`catastrophic.git-history`（`filter-branch`、`rebase` 前必删历史形式、`push --force` 等）不受影响，仍是绝对拒绝。
5. **不新增规则号**；不修改 `src/core` 的判定模型（确认仍走既有删除分档与 `knownScope`）。

## 不做

- 不细分 `.git` 内部单个文件的删除（如 `rm .git/config`）：它是普通单文件删除，不触发仓库级审批；只对「整个 `.git` 主体或其子目录」「bare 仓库」「包含 `.git` 目录的树」产出审批。
- 不把非 Git 的、恰好名为 `.git` 的空目录改为拒绝：仍按完整仓库识别为确认（多一次审批，不误伤）。

## 后果

- `rm -rf repo`、`rm -rf repo/.git`、`rm -rf bare.git`、`mv repo dest`、`Remove-Item -Recurse repo` → **confirm（ask）**，范围说明会销毁完整仓库元数据。
- `rm -rf worktree`、`rm -rf worktree/.git`（文件指针）→ 按普通删除分档（小树放行、大树确认）。
- 无人值守会话里删除完整仓库仍需一次用户批准——这正是「避免灾难」的机制，不是失败。
- 直接销毁历史的 Git 子命令（`filter-branch`、`reset --hard` 等）仍绝对拒绝。

## 追溯

修订 [DSR-020](DSR-020-灾难性删除标准.md) 中「Git common-dir 主体」的绝对拒绝口径；承接 [DSR-032](DSR-032-过度防御修正与隧道控制流长尾的灾难防御.md) 决定 2（目录含 `.git` 改为确认）。需求 R-03、R-15；验收 AC-01、AC-06。
