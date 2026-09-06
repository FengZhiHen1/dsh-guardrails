# TODO

## 待排查：git 依赖安装后 client 行消失（2026-09-06 dev/web-next 实测发现）

**现象**：web-next profile（dev 实例，0.1.2-rc.1）以 `github:` 依赖安装本插件后，Host 行正常激活（启动零报错），但**浏览器端 client 行整个缺席**——`__DSH_BOOT__` 50 个 entries 里没有 dsh-guardrails（同 profile 的 dsh-skill-manager 正常）。设置页「权限守护」卡片因此不出现。

**对比面**：test profile（同版本运行时，`link:` 直挂源码）工作正常；web profile（0.1.1-rc.2，github 依赖旧版）也正常。

**已排除**：安装内容完整（`dsh.client` 声明、`src/client/card.js` 都在）；`clientExportOf` 支持 `{default}` 形态；注册表激活扫描对畸形声明会大声抛错（启动无此错）——即 `resolveMeta` 对 guardrails 静默返回了 null。

**当前嫌疑**（`packages/client/modules/src/index.ts`）：`processOne` 只认 `entry.fiber !== undefined` 的加载行（L905）——guardrails 行若无 fiber（未激活/挂起）则直接被跳过。下一步：
1. 复现时打印/观察 guardrails 加载行的 fiber 状态（为何无 fiber：inject ['settings'] 用 `ctx.inject` 数组形态……注：本插件 inject 只声明 ['tools']）
2. 或在 `resolveMeta`/`locatePkgJson` 打日志看分类落点（loader internal resolveSync 失败会静默归 "not a client row"）
3. 与 skill-manager 对照：它走 esbuild 产物 `./client: ./dist/client.js`（字符串形态），guardrails 是 `./client: {default: ./src/client/card.js}`——虽 clientExportOf 支持，仍可作为对照变量排除

**解除记录**：同日已把本插件与 dsh-skill-manager 从 test profile 解除应用（测试归测试，常态挂载在 web-next）。
