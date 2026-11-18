// python — runtime discovery and helper protocol for the Python program provider.
//
// The source under review is only ever stdin data for the stdlib-ast helper
// (python-ast-helper.py); it is never executed. The helper is spawned as a
// one-shot `python -I -B <helper>` process per unit, bounded by env.limits
// (timeoutMs, maxInputBytes, maxOutputBytes).
//
// Runtime discovery is explicit-first and never guesses a policy shim:
// 1. options.pythonExecutable (string or [exe, ...args]),
// 2. process.env.DSH_GUARDRAILS_PYTHON,
// 3. bare `python3` on PATH (`python` is intentionally NOT probed: on managed
//    hosts it can be a local policy shim, not a real interpreter),
// 4. `py -3` on Windows,
// 5. uv-managed interpreter installs (standard uv data locations).
// A candidate is accepted only after `--version` exits 0.
//
// Failure semantics (distinguished, per the shared failure table):
// - executable absent (no candidate probes, spawn ENOENT) -> kind 'no-python-runtime'
// - runtime present but the parse subprocess failed (nonzero exit, timeout,
//   protocol damage) -> kind 'parser-failed'
// - source failed to parse (helper reports a SyntaxError) -> fact gap 'parse-failed'

import { spawn } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const HELPER_PATH = fileURLToPath(new URL('./python-ast-helper.py', import.meta.url));
const PROBE_TIMEOUT_MS = 3000;

export class RuntimeAbsent extends Error {
  constructor(detail) { super(detail); this.name = 'RuntimeAbsent'; this.absent = true; }
}
export class RuntimeFailed extends Error {
  constructor(detail) { super(detail); this.name = 'RuntimeFailed'; this.failed = true; }
}

function parseExecutable(value) {
  if (Array.isArray(value)) {
    if (value.length === 0 || value.some(part => typeof part !== 'string')) throw new TypeError('pythonExecutable array must be non-empty strings');
    return { executable: value[0], args: value.slice(1) };
  }
  if (typeof value !== 'string' || value.length === 0) throw new TypeError('pythonExecutable must be a string or array');
  return { executable: value, args: [] };
}

function runOnce(executable, args, input, timeoutMs, maxOutputBytes, signal) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = Buffer.alloc(0);
    let err = Buffer.alloc(0);
    let settled = false;
    const done = (fn, value) => { if (!settled) { settled = true; clearTimeout(timer); signal?.removeEventListener('abort', abort); fn(value); } };
    const abort = () => { child.kill(); done(reject, new RuntimeFailed('cancelled')); };
    const timer = setTimeout(() => { child.kill(); done(reject, new RuntimeFailed('deadline exceeded')); }, timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    child.stdout.on('data', chunk => {
      out = Buffer.concat([out, chunk]);
      if (out.length > maxOutputBytes) { child.kill(); done(reject, new RuntimeFailed('output exceeded budget')); }
    });
    child.stderr.on('data', chunk => { err = Buffer.concat([err, chunk]); if (err.length > maxOutputBytes) { child.kill(); done(reject, new RuntimeFailed('diagnostics exceeded budget')); } });
    child.on('error', error => {
      if (error.code === 'ENOENT' || error.code === 'EACCES') done(reject, new RuntimeAbsent(`${executable}: ${error.code}`));
      else done(reject, new RuntimeFailed(`${error.code || error.name}`));
    });
    child.on('close', code => {
      if (code !== 0) return done(reject, new RuntimeFailed(`exit ${code}${err.length ? ': ' + err.toString('utf8').slice(0, 200) : ''}`));
      done(resolve, out.toString('utf8'));
    });
    child.stdin.on('error', () => { /* close handler reports the failure */ });
    child.stdin.end(input);
  });
}

async function probe(candidate, signal) {
  try {
    await runOnce(candidate.executable, [...candidate.args, '-I', '--version'], '', PROBE_TIMEOUT_MS, 65536, signal);
    return true;
  } catch (error) {
    if (error instanceof RuntimeFailed && /cancelled|deadline/.test(error.message)) return false;
    return false;
  }
}

async function uvCandidates() {
  const roots = process.platform === 'win32'
    ? [path.join(process.env.APPDATA ?? '', 'uv', 'python')]
    : [path.join(process.env.XDG_DATA_HOME ?? path.join(os.homedir(), '.local', 'share'), 'uv', 'python')];
  const found = [];
  for (const root of roots) {
    if (!root || path.parse(root).name === '' || !existsSync(root)) continue;
    let entries;
    try { entries = await readdir(root); } catch { continue; }
    const versions = [];
    for (const entry of entries) {
      const match = /^cpython-(\d+)\.(\d+)\.(\d+)/.exec(entry);
      if (!match) continue;
      versions.push({ major: +match[1], minor: +match[2], patch: +match[3], entry });
    }
    versions.sort((a, b) => b.major - a.major || b.minor - a.minor || b.patch - a.patch);
    for (const version of versions) {
      const executable = process.platform === 'win32'
        ? path.join(root, version.entry, 'python.exe')
        : path.join(root, version.entry, 'bin', 'python3');
      if (existsSync(executable)) found.push({ executable, args: [] });
    }
  }
  return found;
}

export function createPythonProvider(options = {}) {
  const explicit = options.pythonExecutable ?? process.env.DSH_GUARDRAILS_PYTHON ?? null;
  let cached = null;
  let cachedPromise = null;
  let disposed = false;

  async function resolveRuntime(signal) {
    if (cached) return cached;
    if (!cachedPromise) {
      cachedPromise = (async () => {
        const candidates = [];
        if (explicit) candidates.push(parseExecutable(explicit));
        candidates.push({ executable: 'python3', args: [] });
        if (process.platform === 'win32') candidates.push({ executable: 'py', args: ['-3'] });
        candidates.push(...await uvCandidates());
        for (const candidate of candidates) {
          if (await probe(candidate, signal)) return candidate;
        }
        throw new RuntimeAbsent('no probed Python runtime (explicit, python3, py -3, uv-managed)');
      })().finally(() => { cachedPromise = null; });
      try {
        cached = await cachedPromise;
        return cached;
      } catch (error) {
        if (error instanceof RuntimeAbsent) throw error;
        throw new RuntimeFailed(String(error?.message ?? error));
      }
    }
    return cachedPromise;
  }

  return {
    /** Parse one inline Python unit into fact objects; throws RuntimeAbsent/RuntimeFailed. */
    async analyze(source, { cwd, platform, limits, signal }) {
      if (disposed) throw new RuntimeFailed('provider disposed');
      const runtime = await resolveRuntime(signal);
      const request = JSON.stringify({
        source,
        cwd: typeof cwd === 'string' && cwd.length > 0 ? cwd : null,
        platform: platform ?? null,
        // maxNodes is the shared remaining walker budget; the helper debits
        // exactly the AST steps it walks and reports them back as `nodes`.
        limits: { maxNodes: Math.min(200000, Math.max(1, limits.maxSteps)), maxFacts: 4096 },
      });
      if (signal?.aborted) throw new RuntimeFailed('cancelled');
      let output;
      try {
        output = await runOnce(runtime.executable, [...runtime.args, '-I', '-B', HELPER_PATH], request, limits.timeoutMs, limits.maxOutputBytes, signal);
      } catch (error) {
        if (error instanceof RuntimeAbsent) throw new RuntimeAbsent(error.message);
        throw new RuntimeFailed(error instanceof RuntimeFailed ? error.message : String(error?.message ?? error));
      }
      let result;
      try {
        const newline = output.indexOf('\n');
        if (newline < 0) throw new TypeError('no JSON line');
        result = JSON.parse(output.slice(0, newline));
      } catch {
        throw new RuntimeFailed('helper protocol damage (invalid JSON)');
      }
      if (result && result.ok === false) {
        if (result.error === 'syntax') {
          return { facts: [{ t: 'gap', kind: 'parse-failed', detail: result.message ?? 'source failed to parse', line: Number.isInteger(result.line) ? result.line : undefined }], truncated: null, stepsUsed: 0 };
        }
        throw new RuntimeFailed(`helper error: ${result.error}`);
      }
      if (!result || result.ok !== true || !Array.isArray(result.facts)) throw new RuntimeFailed('helper protocol damage (invalid result)');
      return { facts: result.facts, truncated: result.truncated ?? null, stepsUsed: Number.isInteger(result.nodes) ? result.nodes : 0 };
    },
    dispose() {
      disposed = true;
      cached = null;
      cachedPromise = null;
    },
  };
}
