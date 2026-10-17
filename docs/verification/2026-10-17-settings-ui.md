# Guardrails 原生风格设置页

用户：在 DSH 插件管理页调整保护范围和审批时间的本机使用者。主任务：修改三项现有配置，保存后确认生效。入口/标题/返回导航由 DSH 提供；离开不保存即丢弃草稿，不额外显示未保存标记。

## 页面设计

采用 DSH 原生设置页单列密度，按官方 `SettingsForm`/`fields` 复制：字段 12px 纵向 padding 与 0.5px 分隔线、13px 标签、34px 控件（0.5px `border-l4`、`--dsw-radius-md`、`bg-layer-3`）、12px 提示、底部 16px 保存行；保存键沿用官方 `.save` 的 13px/`5px 14px`/`label-primary`，类名统一加 `gr-` 前缀并只保留 token 引用。未修改或输入非法时禁用保存，成功保存后回到未修改态、不额外显示成功文案。不 `require` 任何 Harness Client 包——0.2.1 的 platform seed 虽能解析，但属于无插件支持承诺的内部装配件。内容宽度680px上限，窄屏保持单列并允许底部反馈换行。

内容优先级：敏感文件多行输入 → 内置保护checkbox → 审批时间秒数 → 保存及状态 → 分隔线后的保护范围与可展开边界说明。配置控件为唯一主任务；只读防护摘要不伪装成实时健康状态。

三个字段沿用原数据键。路径每行一个，保留有效路径原始空格，不展开目录规则或通配符。等待时间展示秒、保存整数毫秒，支持0.001秒精度；legacy 0展示默认120秒，不自动写回。空清单不关闭内置保护。读取到不完整或过期section时按安全默认派生，不让页面因缺字段崩溃。

界面不新增防护总开关或未批准候选规则。内置开关明确只影响内置清单，自定义清单独立生效。固定文案不承诺任意脚本全面识别或零凭据泄露。

## 原生集成与状态

0.2.1 使用官方 plugins.row.config 键 dsh-guardrails#guardrails，并经注入面取 ctx.configForms.get('guardrails')；组件订阅 ConfigForm 快照，读取 ready/loading/unavailable、value、revision、writable，一次 mutate 原子提交三字段。不依赖页面 owner props.form 的一次性快照，不跨插件导入运行时组件，不新建配置RPC或存储。英中文案经locale注册，标题与摘要由包locale元数据提供。

loading/unavailable/只读各有明确反馈；未修改禁用保存；非法输入保留并提示；开始编辑时冻结revision；函数体busy防重复；失败/冲突保留输入并指导重新打开核对；成功保存后回到未修改态（保存键禁用），不再额外显示成功文案。取消/卸载后的异步响应不更新已卸载组件。标签、描述关联、焦点样式、details键盘行为沿用语义HTML。

## 验证与现场边界

0.2.1 运行时全量验证464项：400通过、0失败、64已声明语料skip，约10.9秒。适配覆盖：PTC `run_code` 的 Agent `ctx`/`workingDirectory` 服务与释放钩子、`ctx.configForms` 订阅写入、不完整section派生。命令语料仍只解析不执行。

设置页改为复制官方 `SettingsForm`/`fields` 后，`node test/settings-client.test.mjs` 5/5 通过（含“无 Client 包引用”“无字面颜色”“未修改禁用保存”断言）；当前受限沙箱对插件 `tmp/` 的 `mkdtemp` 返回 EPERM，全量 464 项未在本轮重跑，需在不受限环境补跑。

test 实例 0.2.1-rc.2 的安装结果早于本次设置页重排，只证明当时版本；本次未重装或重启实例。当时：官方 `install_bundle` 返回 application=applied、changed=true、version=3.1.0；Host `Config.listConfigs` 可见三项 schema；Client `plugins.row.config` 显示 occupant active；普通 pwsh 命令返回预期输出，证明 guard 已接管且未误拦。

浏览器页面本身仍需用户刷新后走查：输入、保存成功/失败反馈、明暗主题与窄屏布局；复制字段与保存键同官方并排的几何、焦点、禁用一致性同样未走查。Inspect 只证明注册与 schema，不证明视觉与交互。本机仓库规则将页面级检查交用户，本轮未运行浏览器自动化，未声称视觉验收完成。
