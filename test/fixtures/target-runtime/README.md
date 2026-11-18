# target-runtime fixtures — reusable real-runtime harness

`runtime-harness.mjs` mounts one isolated composition of the **real DSH 0.2.2-rc.2
runtime** for guardrails acceptance tests. It is the only support file for
`test/target-runtime.test.mjs` and is safe to reuse from other test files in this
package.

## Runtime anchor

The runtime is located only through `DSH_RUNTIME_PATH`. Accepted shapes:

- the launcher install directory, e.g. `<launcher>/versions/0.2.2-rc.2` (the harness
  anchors at its `node_modules/@deepseek-ai/dsh`);
- a runtime package directory containing `package.json`;
- a direct `package.json` path.

Without `DSH_RUNTIME_PATH` every consumer test skips with an explicit reason; a skip
is never a pass.

Verified facts about the anchor (probed against the launcher install, 2026-11-18):

- Runtime dependencies are pnpm-hidden: the anchor must be resolved through its
  **realpath** (`realpathSync`), otherwise sibling `@deepseek-ai/*` packages do not
  resolve.
- `tools.execute` requires exactly one mounted executor per scope:
  `@deepseek-ai/dsh-tool-executor-native` for direct calls, or
  `@deepseek-ai/dsh-tool-executor-ptc` when a program (`run_code`) is executed. The
  PTC executor injects `systemPrompt` and a `ptcRuntime` service and admits only
  `run_code` as a direct call; every other tool is reachable only as an SDK
  sub-dispatch inside a program, each through the full pre-execute / approval / guard
  pipeline with its own `ToolExecution` object.

## Isolation rules

- No DSH instance is started and no profile is written.
- Every filesystem target is a managed `mkdtemp` directory under `os.tmpdir()`,
  removed at test end; fixtures are created by the harness only.
- Tool bodies registered by the harness are counting no-ops. A test that executes
  anything beyond its own fixtures must say so in its header comment.
- The gate under test is mounted exactly like a production plugin:
  `ctx.plugin({ name, inject: ['tools'], apply: gate.apply }, config)`.

## Exports

`runtime`, `runtimeSkipReason`, `mount(t, options)`, `fixtureRoot(t, label)`,
`makeAgent(root, ctx)`, `realSession(id)`, `registerCounting(ctx, name, counter)`,
`toolCall`, `resultOf`, `runTool(ctx, agent, name, args, signal?)`,
`observePreExecute(ctx, log?)`, `fixturePtcRuntime(run)`, `writeTree(root, name, count)`,
`psLiteral(value)`, `patchText(operations)`.

`observePreExecute` appends **after** the gate, so its entries show only executions
the gate forwarded with `next()`; `nested` marks SDK sub-dispatches (a `ToolExecution`
carrying a parent token).

## Verification status

- Harness mechanics (anchor resolution, native + PTC compositions, observer, SDK
  nested dispatch) are executed against the real runtime — see
  `docs/verification/` for the run record of each acceptance round.
- Gate behavior cases live in `test/target-runtime.test.mjs` and encode the target
  contract of `docs/technical-details/` (DSR-025…027). They skip until the new
  package entry (`index.js`: apply/Config/name/inject) is integrated.
