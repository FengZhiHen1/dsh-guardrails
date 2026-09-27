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
 * A minimal hook runtime: `useState` with per-render slots, enough for the
 * card's local draft/busy/failed/… state. Renders are synchronous test calls.
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
    /** Reset between renders (a fresh mount). */
    __reset() { cells = []; cursor = 0; tree.length = 0 },
    __tree: tree,
  }
  return react
}

/** Load the bundle exactly as the client module system does, capturing its factory. */
function loadBundle({ react }) {
  let registration
  const globalWindow = {
    __ModuleLoader__: { load: (entry) => { registration = entry } },
  }
  // The bundle is plain script text: evaluate it against a scoped `window`.
  const run = new Function('window', `${SOURCE}\n;return window.__ModuleLoader__;`)
  run(globalWindow)
  assert.ok(registration, 'bundle did not call __ModuleLoader__.load')
  const primitives = { IconChevronDownOutlineRegular: () => ({ type: 'svg' }) }
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
  const { registration, exportsObject } = loadBundle({ react })
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
    /** Render the component by hand with the props the page binds. */
    render(props) {
      react.__reset()
      return registered[0].component(props)
    },
    face: registered[0]?.options.inject?.(),
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
  assert.equal(seen.status, 'ready')
  assert.equal(seen.revision, 3)
})

test('view: summary renders the one-liner; view: page renders the form', () => {
  const m = mount()
  const props = {
    useGuardrailForm: (selector) => selector(snapshot()),
    mutate: async () => true,
    unset: async () => true,
  }
  const summary = m.render({ ...props, view: 'summary' })
  // The page draws the row's title and crumb itself; the summary is text.
  assert.equal(summary.type, 'span')
  assert.equal(typeof summary.children[0], 'string')

  const page = m.render({ ...props, view: 'page' })
  // Body shell: a div (the slot renders inside a <section>), never the old
  // list-shaped <li> that belonged to the removed settings slot.
  assert.equal(page.type, 'div')
  assert.notEqual(page.type, 'li')
})

test('page renders the not-ready notice without throwing when the namespace is absent', () => {
  const m = mount()
  const props = {
    useGuardrailForm: (selector) => selector(snapshot({ status: 'unavailable', value: undefined, writable: false })),
    mutate: async () => true,
    unset: async () => true,
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
