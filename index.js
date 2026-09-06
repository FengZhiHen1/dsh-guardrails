// dsh-guardrails — package root: thin re-export of the Host adapter entry.
// The bundle row resolves this package by name; the wiring lives in
// src/adapter/host.js, the judgment logic in src/core/, the browser half in
// src/client/card.js (see docs/technical-details/工程结构与测试体系.md).
export * from './src/adapter/host.js'
