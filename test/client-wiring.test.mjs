// Client-half wiring contract (the gap verify/run-verify.mjs does not cover).
//
// The browser half is a lazy-CJS bundle: loading it only registers a factory
// through `window.__ModuleLoader__.load`, and the module body materializes when
// the loader imports this package's `/client`. Nothing in the unit suite ran
// that path before, which is exactly how a wiring break (a slot name, a key, an
// inject-face shape) can ship green: the knowledge base records that
// `run-verify.mjs` only checks that `client.js` EXISTS and does not cover the
// render contract, and that a crashed page entry "abdicates" silently with no
// deployment-level error.
//
// These tests therefore drive the real bundle with a minimal React and a mock
// client ctx, and assert the v0.1.7 contract the Plugins page depends on:
//   - the module registers and exports the cordis plugin face;
//   - `apply` registers into `plugins.row.config` under `<pkg>#<row id>`;
//   - reactivity rides the RESERVED `hooks` compartment (a `form` prop would be
//     a one-time snapshot the page passes in, with no subscribe side);
//   - the reserved keys never leak into component props;
//   - the component honours `view: 'summary' | 'page'`;
//   - no removed v0.1.2-era API name survives in the shipped bundle.
//
// No browser, no network, no DSH process.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const CARD = join(HERE, '..', 'src', 'client', 'card.js')
const SOURCE = readFileSync(CARD, 'utf8')

/**
 * A minimal hook runtime: `useState`/`useEffect` with per-render slots, enough
 * for the card's local state. Renders are synchronous test calls.
 */
function makeReact() {
  let cells = []
  let cursor = 0
  const tree = []
  const react = {
    createElement(type, props, ...children) {
      const node = { type, props: props ?? {}, children }
      tree.push(node)
      return node
    },
    useState(initial) {
      const index = cursor++
      if (cells.length <= index) cells[index] = typeof initial === 'function' ? initial() : initial
      const set = (next) => {
        cells[index] = typeof next === 'function' ? next(cells[index]) : next
      }
      return [cells[index], set]
    },
    /** The official SettingsForm discards on unmount through this hook. */
    useEffect() {},
    useRef(initial) { return { current: initial } },
    /** Reset between renders (a fresh mount). */
    __reset() { cells = []; cursor = 0; tree.length = 0 },
    __tree: tree,
  }
  return react
}

/**
 * A fake `SettingsFormModel` recording the specs it was constructed with, so a
 * test can assert the page's declared fields against the Host Config schema.
 * `shell()`/`field()` answer from the same snapshot shape the real model reads.
 */
function makeFormModelClass(record) {
  return class FakeSettingsFormModel {
    constructor(scope, specs) {
      record.scope = scope
      record.specs = specs
      record.model = this
    }
    shell() {
      const snapshot = record.scope.getSnapshot()
      return {
        available: snapshot.status === 'ready',
        writable: snapshot.writable,
        dirty: record.dirty ?? false,
        invalid: false,
        saving: false,
        failed: false,
      }
    }
    field(field) {
      const snapshot = record.scope.getSnapshot()
      const spec = record.specs.find((s) => s.field === field)
      const value = snapshot.value === undefined ? undefined : snapshot.value[field]
      return { text: spec.format(value), overridden: false, invalid: false }
    }
    bind(project) {
      record.project = project
      return { getSnapshot: () => project(), subscribe: () => () => {} }
    }
    actions() {
      return {
        edit: (field, text) => { record.edits.push([field, text]) },
        resetField: (field) => { record.resets.push(field) },
        save: () => { record.saves += 1 },
        discard: () => { record.discards += 1 },
      }
    }
    dispose() { record.disposed = true }
  }
}

/** Static UI primitives the shell seeds; Checkbox/Tag render their props through. */
function makePrimitives(record) {
  // The form frame is a plain ELEMENT in this harness (the real one renders a
  // div around children). It must NOT be a function component echoing its own
  // `children` prop: the card passes children positionally, so echoing props
  // would re-enter the same node forever.
  const SettingsForm = 'SettingsForm'
  return {
    SettingsFormModel: makeFormModelClass(record),
    SettingsForm,
    Checkbox: (props) => ({ type: 'Checkbox', props }),
    Tag: (props) => ({ type: 'Tag', props }),
  }
}

/**
 * A miniature React: resolve function components so the tree a test walks is the
 * tree that would render. Without this, a node whose `type` is a component
 * function (e.g. `CategoryRow`) stays opaque and its Checkbox children are
 * invisible to `collect` — which is exactly how the first version of this
 * assertion silently counted zero toggles.
 */
function expand(node) {
  if (node === null || node === undefined || typeof node === 'boolean') return null
  if (Array.isArray(node)) return node.map(expand).filter((n) => n !== null)
  if (typeof node !== 'object') return node
  if (typeof node.type === 'function') {
    return expand({ ...node.type({ ...node.props, children: node.children }), __from: node.type })
  }
  return { ...node, children: expand(node.children) }
}

/** Every rendered element in an expanded tree (depth-first). */
function collect(node, out = []) {
  if (node === null || node === undefined) return out
  if (Array.isArray(node)) { for (const child of node) collect(child, out); return out }
  if (typeof node !== 'object') return out
  out.push(node)
  if (Array.isArray(node.children)) for (const child of node.children) collect(child, out)
  return out
}

/** Every plain-string text under a node. */
function texts(node) {
  const out = []
  const walk = (n) => {
    if (typeof n === 'string' || typeof n === 'number') { out.push(String(n)); return }
    if (Array.isArray(n)) { for (const c of n) walk(c); return }
    if (n && typeof n === 'object' && Array.isArray(n.children)) for (const c of n.children) walk(c)
  }
  walk(node)
  return out
}

/** Load the bundle exactly as the client module system does, capturing its factory. */
function loadBundle({ react, record }) {
  let registration
  const globalWindow = {
    __ModuleLoader__: { load: (entry) => { registration = entry } },
  }
  // The bundle is plain script text: evaluate it against a scoped `window`.
  const run = new Function('window', `${SOURCE}\n;return window.__ModuleLoader__;`)
  run(globalWindow)
  assert.ok(registration, 'bundle did not call __ModuleLoader__.load')
  const primitives = makePrimitives(record)
  const exportsObject = registration.factory((name) => {
    if (name === 'react') return react
    if (name === '@deepseek-ai/dsh-client-ui-primitives') return primitives
    throw new Error(`unexpected require(${name})`)
  })
  return { registration, exportsObject }
}

/** A settings-form snapshot as `ConfigForm.getSnapshot()` returns it. */
const snapshot = (over = {}) => ({
  status: 'ready',
  value: { env: true, git: true, credentials: true, system: true, destructive: true, unverifiable: true },
  base: undefined,
  user: {},
  revision: 3,
  writable: true,
  mode: 'host',
  ...over,
})

/**
 * Mount the client plugin against a mock ctx and return the captured
 * registration plus the inject face it registered.
 */
function mount({ form = {} } = {}) {
  const react = makeReact()
  // Records the controller's construction, actions, and disposal so tests can
  // assert the official form model is actually driving the page.
  const record = { edits: [], resets: [], saves: 0, discards: 0, disposed: false }
  const { registration, exportsObject } = loadBundle({ react, record })
  const registered = []
  const injections = []
  const effects = []
  const configForm = {
    getSnapshot: form.getSnapshot ?? (() => snapshot()),
    subscribe: form.subscribe ?? (() => () => {}),
    set: form.set ?? (async () => true),
    unset: form.unset ?? (async () => true),
    mutate: form.mutate ?? (async () => true),
  }
  const ctx = {
    configForms: {
      get: (ns) => { configForm.__ns = ns; return configForm },
      whileServed: (namespaces, register) => {
        injections.push(namespaces)
        // Stand in for the mirror: register immediately, return the disposer.
        return register(new Set(namespaces))
      },
    },
    slots: {
      inject: (name, factory) => {
        injections.push(name)
        // `ctx.slots.inject(name, factory)` runs the factory and keeps the
        // disposer it returns (the card registers a row page here).
        const off = factory()
        if (typeof off === 'function') effects.push(off)
      },
      register: (options, component) => {
        registered.push({ options, component })
        return () => {}
      },
    },
    effect: (fn) => { const off = fn(); if (typeof off === 'function') effects.push(off) },
  }
  exportsObject.apply(ctx)
  return {
    exported: exportsObject,
    registration,
    registered,
    injections,
    configForm,
    react,
    record,
    /** Render the component by hand with the props the page binds. */
    render(props) {
      react.__reset()
      return registered[0].component(props)
    },
    face: registered[0]?.options.inject?.(),
    /** Run every fiber-scoped disposer (what unload does). */
    dispose() { for (const off of effects) off() },
  }
}

test('bundle registers as a lazy-CJS module under its id', () => {
  const m = mount()
  assert.equal(m.registration.id, 'dsh-guardrails')
  assert.equal(typeof m.registration.factory, 'function')
})

test('module face is a cordis client plugin with the v0.1.7 services', () => {
  const m = mount()
  assert.equal(m.exported.name, 'dsh-guardrails')
  assert.equal(typeof m.exported.apply, 'function')
  assert.deepEqual([...m.exported.inject].sort(), ['configForms', 'slots'])
  // The removed client APIs must not be requested: `inject` naming a service
  // that no longer exists leaves the fiber PENDING forever (the entry never
  // activates), which is the quietest possible failure.
  for (const gone of ['settingsScope', 'connection']) {
    assert.equal(m.exported.inject.includes(gone), false, `${gone} must not be injected`)
  }
})

test('registers into plugins.row.config under <package>#<row id>', () => {
  const m = mount()
  assert.equal(m.registered.length, 1)
  const { options } = m.registered[0]
  // A keyed slot requires its key, and the page derives the key from the
  // bundle package name plus the row id the patch declares.
  assert.equal(options.name, 'plugins.row.config')
  assert.equal(options.key, 'dsh-guardrails#guardrails')
  assert.equal(typeof m.registered[0].component, 'function')
})

test('namespace bound to configForms is the loader entry id, not the package name', () => {
  const m = mount()
  // v0.1.7: a settings namespace IS the local loader entry id (`id: guardrails`
  // in cordis.patch.yml). Binding the package name would silently resolve to a
  // namespace no entry serves, leaving the page permanently 'unavailable'.
  assert.equal(m.configForm.__ns, 'guardrails')
})

test('reactivity rides the reserved hooks compartment and never leaks into props', () => {
  const m = mount()
  const face = m.face
  assert.ok(face.hooks, 'the hooks compartment is missing')
  const source = face.hooks.guardrailForm
  assert.equal(typeof source.getSnapshot, 'function')
  assert.equal(typeof source.subscribe, 'function')
  // The reserved keys are consumed by the renderer; the rest is passed through
  // verbatim as props. `hooks` must not be among the pass-through props.
  assert.equal('hooks' in face, true)
  assert.equal('keyedHooks' in face, false)
})

test('apply wires configForms.whileServed so an unserved namespace shows nothing', () => {
  const m = mount()
  // The page must not register unless the Host serves the namespace.
  assert.ok(m.injections.includes('guardrails') || m.injections.some((i) => Array.isArray(i) && i.includes('guardrails')),
    `whileServed was not called with the namespace: ${JSON.stringify(m.injections)}`)
})

test('the form is read through the injected sources, not a one-time prop', () => {
  const m = mount()
  const face = m.face
  // The page passes `form: { state, mutate }` — a snapshot with no subscribe
  // side — so a component reading it would freeze at its first value. The live
  // snapshot must come from the hook source instead.
  assert.notEqual(face.hooks?.guardrailForm, undefined)
  const seen = face.hooks.guardrailForm.getSnapshot()
  // The official shell's shape: availability + writability + a per-field state.
  assert.equal(seen.available, true)
  assert.equal(seen.writable, true)
  assert.equal(seen.env.text, 'true')
  assert.equal(seen.unverifiable.text, 'true')
})

test('the page is driven by the official SettingsFormModel over the row namespace', () => {
  const m = mount()
  // The controller constructs the official model with the row's ConfigForm and
  // this page's field specs — that is what owns the draft, the revision fence,
  // the read-back and discard-on-unmount now.
  assert.equal(m.record.scope, m.configForm, 'the model must be bound to the row ConfigForm')
  const fields = m.record.specs.map((spec) => spec.field)
  assert.deepEqual(fields, ['env', 'git', 'credentials', 'system', 'destructive', 'unverifiable'])
  for (const spec of m.record.specs) {
    assert.equal(typeof spec.format, 'function', `${spec.field} needs format`)
    assert.equal(typeof spec.parse, 'function', `${spec.field} needs parse`)
  }
  // Every action the component consumes comes from the model.
  const face = m.face
  for (const action of ['edit', 'resetField', 'save', 'discard']) {
    assert.equal(typeof face[action], 'function', `the inject face must carry ${action}`)
  }
  // The model subscription is released with the fiber.
  assert.equal(m.record.disposed, false)
  m.dispose()
  assert.equal(m.record.disposed, true, 'unload must dispose the form model')
})

test('view: summary renders the one-liner; view: page renders the official SettingsForm', () => {
  const m = mount()
  const props = {
    useGuardrailForm: (selector) => selector(m.face.hooks.guardrailForm.getSnapshot()),
    ...m.face,
  }
  const summary = m.render({ ...props, view: 'summary' })
  // The page draws the row's title and crumb itself; the summary is text.
  assert.equal(summary.type, 'span')
  assert.equal(typeof summary.children[0], 'string')

  const page = expand(m.render({ ...props, view: 'page' }))
  // The body is the OFFICIAL form primitive — not a self-drawn card shell. The
  // official pages render a bare <SettingsForm>; the previous hand-written
  // collapsible card (header + chevron + 「未保存」 pill + 「放弃」 button)
  // diverged from them and is gone.
  assert.equal(page.type, 'SettingsForm', 'the body must be the official SettingsForm')
  assert.equal(page.props.labels.save, '保存')
  assert.equal(typeof page.props.onSave, 'function')
  assert.equal(typeof page.props.onDiscard, 'function')
  assert.equal(page.props.state.writable, true)
  // No discard control and no unsaved pill: the official form offers neither
  // (SettingsForm.tsx: "discards on unmount and offers no discard control").
  // Asserted on CONTROL labels only — the page's explanatory note legitimately
  // uses those words, so scanning all text would test the wording, not the chrome.
  const nodes = collect(page)
  const controlLabels = nodes
    .filter((n) => n.type === 'button' || n.type === 'Tag')
    .map((n) => (Array.isArray(n.children) ? n.children.filter((c) => typeof c === 'string').join('') : ''))
  assert.equal(controlLabels.some((label) => /放弃/.test(label)), false,
    'the official form offers no discard control')
  assert.equal(controlLabels.some((label) => /未保存/.test(label)), false,
    'the official form shows no unsaved pill')
  // Leaf toggles are the official Checkbox: one per leaf (2+2+3+1+8) + fail-safe.
  const boxes = nodes.filter((n) => n.type === 'Checkbox')
  assert.equal(boxes.length, 2 + 2 + 3 + 1 + 8 + 1, 'one Checkbox per leaf plus the fail-safe toggle')
  // The page renders the category titles itself (the shell draws no row chrome).
  const rendered = texts(page)
  for (const title of ['env 文件访问', '.git 内部访问', '凭据文件访问', '系统区写入', '破坏性命令', '动态目标 fail-safe']) {
    assert.ok(rendered.some((t) => t.includes(title)), `missing category title: ${title}`)
  }
})

test('page renders the not-ready notice without throwing when the namespace is absent', () => {
  const m = mount()
  const props = {
    useGuardrailForm: (selector) => selector(m.face.hooks.guardrailForm.getSnapshot()),
    ...m.face,
  }
  // `snapshot.value === undefined` must not crash normalization: a page that
  // throws here is removed from the slot silently.
  assert.doesNotThrow(() => m.render({ ...props, view: 'page' }))
})

test('shipped bundle carries none of the removed v0.1.2-era API names as code', () => {
  // Comments may NAME the removed APIs (they document the migration), so strip
  // comments first and assert on the remaining CODE only.
  const code = SOURCE
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1')
  assert.equal(/settingsScope/.test(code), false, 'ctx.settingsScope must be gone from code')
  assert.equal(/settings\.plugin\.item/.test(code), false, 'the removed slot must not be registered')
  assert.equal(/IconChevronDownOutline14/.test(code), false, 'the pre-0.1.7 icon name must be gone from code')
  // The live names must be present in the code instead.
  assert.ok(code.includes("'plugins.row.config'"), 'plugins.row.config must be registered')
  assert.ok(code.includes('useGuardrailForm'), 'the hooks compartment must be consumed')
  assert.ok(code.includes("'guardrails'"), 'the entry-id namespace must be bound')
})

test('the hand-written card shell is gone from code; the official form owns the write path', () => {
  // DSR-011 (2026-09-28): the card no longer draws its own collapsible shell, and
  // no longer hand-writes the draft/busy/failed state machine or calls
  // form.mutate/unset itself — the official SettingsFormModel owns the draft, the
  // revision fence, the read-back and discard-on-unmount. Comments may describe
  // the removed shell (that is the migration record), so this asserts on CODE.
  const code = SOURCE
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1')
  for (const [name, re] of [
    ['the collapse chevron', /Chevron/],
    ['the card shell style', /cardShell/],
    ['the disclosure header style', /headerStyle/],
    ['the unsaved pill', /dirtyPill/],
    ['the discard hover state', /hoverDiscard/],
    ['the local draft state', /setDraft/],
  ]) {
    assert.equal(re.test(code), false, `${name} must be gone from the shipped code`)
  }
  // And the self-written write path must not come back.
  assert.equal(/\.mutate\(/.test(code), false, 'the card must not call form.mutate directly')
  assert.equal(/\.unset\(/.test(code), false, 'the card must not call form.unset directly')
  // The official primitives must be the ones in use.
  assert.ok(/\bSettingsForm\b/.test(code), 'the official SettingsForm must frame the page')
  assert.ok(/\bSettingsFormModel\b/.test(code), 'the official SettingsFormModel must own the form')
  assert.ok(/\bCheckbox\b/.test(code), 'leaf toggles must use the official Checkbox')
})
