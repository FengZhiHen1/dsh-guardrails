import { spawn } from 'node:child_process';
import { readFile, chmod } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { bashCommands } from './shfmt-ir.mjs';

/** Explicit parser failure; callers must deny execution on rejection. */
export class ShellParseError extends Error {
  constructor(code, message, options) { super(message, options); this.name = 'ShellParseError'; this.code = code; }
}
const failure = (code, message) => new ShellParseError(code, message);

/**
 * Create bounded official shell parser adapters. Source is passed only as stdin data.
 * @throws {TypeError} If resource budgets are invalid.
 */
export function createShellParsers(options = {}) {
  // 256 KiB input and 8 MiB output cover tool commands while bounding AST expansion.
  const limits = { timeoutMs: 5000, maxInputBytes: 262144, maxOutputBytes: 8388608, maxConcurrent: 2, maxQueue: 16, ...options };
  for (const key of ['timeoutMs', 'maxInputBytes', 'maxOutputBytes', 'maxConcurrent', 'maxQueue']) {
    if (!Number.isSafeInteger(limits[key]) || limits[key] < 1) throw new TypeError(`Invalid ${key}`);
  }
  const spawnProcess = limits.spawnProcess ?? spawn;
  let requestSequence = 0;
  let disposal = null;
  const children = new Map();
  function trackChild(child) {
    const exited = new Promise(resolve => {
      child.once('close', () => { children.delete(child); resolve(); });
    });
    children.set(child, exited);
    return child;
  }
  let disposed = false;
  let active = 0;
  let pwsh = null;
  let pwshRequest = null;
  let pwshBuffer = Buffer.alloc(0);
  const queue = [];
  const running = new Set();

  function stopPwsh(error) {
    const child = pwsh;
    pwsh = null;
    pwshBuffer = Buffer.alloc(0);
    if (pwshRequest) { const request = pwshRequest; pwshRequest = null; request.reject(error); }
    child?.kill();
  }

  function ensurePwsh() {
    if (pwsh) return pwsh;
    const child = trackChild(spawnProcess(limits.pwshPath ?? 'pwsh', ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', fileURLToPath(new URL('./powershell-helper.ps1', import.meta.url))], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] }));
    pwsh = child;
    child.stdout.on('data', chunk => {
      if (pwsh !== child) return;
      if (!pwshRequest) return stopPwsh(failure('PROTOCOL', 'Unsolicited PowerShell output'));
      pwshBuffer = Buffer.concat([pwshBuffer, chunk]);
      if (pwshBuffer.length > limits.maxOutputBytes) return stopPwsh(failure('OUTPUT_LIMIT', 'PowerShell output exceeded budget'));
      const newline = pwshBuffer.indexOf(10);
      if (newline < 0) return;
      const request = pwshRequest;
      const line = pwshBuffer.subarray(0, newline).toString('utf8');
      pwshBuffer = pwshBuffer.subarray(newline + 1);
      pwshRequest = null;
      try {
        const result = JSON.parse(line);
        if (result.reqId !== request.reqId || request.child !== child) throw failure('PROTOCOL', 'PowerShell response request identity mismatch');
        validateResult(result);
        if (pwshBuffer.length) throw failure('PROTOCOL', 'Extra PowerShell output');
        request.resolve(result);
      } catch (error) { request.reject(error instanceof ShellParseError ? error : failure('PROTOCOL', 'Invalid PowerShell parser response')); stopPwsh(failure('PROTOCOL', 'Invalid PowerShell parser response')); }
    });
    child.stderr.on('data', chunk => {
      if (pwsh !== child || !pwshRequest || pwshRequest.child !== child) return;
      pwshRequest.stderrBytes += chunk.length;
      if (pwshRequest.stderrBytes > limits.maxOutputBytes) stopPwsh(failure('OUTPUT_LIMIT', 'PowerShell diagnostics exceeded budget'));
    });
    child.on('error', error => { if (pwsh === child) stopPwsh(new ShellParseError('UNAVAILABLE', 'PowerShell parser unavailable', { cause: error })); });
    child.on('exit', () => { if (pwsh === child) stopPwsh(failure('EXIT', 'PowerShell parser exited')); });
    child.stdin.on('error', error => { if (pwsh === child) stopPwsh(new ShellParseError('IO', 'PowerShell parser input failed', { cause: error })); });
    return child;
  }

  async function parseBash(source, task) {
    const manifest = JSON.parse(await readFile(new URL('../../../vendor/shfmt/manifest.json', import.meta.url), 'utf8'));
    const entry = manifest.binaries[`${process.platform}-${process.arch}`];
    if (!entry) throw failure('UNAVAILABLE', 'Unsupported shfmt platform');
    const url = new URL(`../../../vendor/shfmt/${entry.file}`, import.meta.url);
    let binary;
    try { binary = await readFile(url); } catch (error) { throw new ShellParseError('UNAVAILABLE', 'Local shfmt binary unavailable', { cause: error }); }
    if (createHash('sha256').update(binary).digest('hex') !== entry.sha256) throw failure('INTEGRITY', 'shfmt SHA256 mismatch');
    // npm packing on Windows drops Unix executable bits; restore only the verified binary.
    if (process.platform !== 'win32') await chmod(url, 0o755);
    if (task.stopped) throw task.stopped;
    const text = await new Promise((resolve, reject) => {
      const child = trackChild(spawnProcess(fileURLToPath(url), ['-ln', 'bash', '--to-json'], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] }));
      task.kill = () => child.kill();
      const chunks = [];
      let size = 0;
      let diagnostics = 0;
      child.stdout.on('data', chunk => { size += chunk.length; if (size > limits.maxOutputBytes) { reject(failure('OUTPUT_LIMIT', 'shfmt output exceeded budget')); child.kill(); } else chunks.push(chunk); });
      child.stderr.on('data', chunk => { diagnostics += chunk.length; if (diagnostics > limits.maxOutputBytes) { reject(failure('OUTPUT_LIMIT', 'shfmt diagnostics exceeded budget')); child.kill(); } });
      child.on('error', error => reject(new ShellParseError('UNAVAILABLE', 'shfmt unavailable', { cause: error })));
      child.on('close', code => code === 0 ? resolve(Buffer.concat(chunks).toString('utf8')) : reject(failure('SYNTAX', 'shfmt rejected shell input')));
      child.stdin.on('error', error => reject(new ShellParseError('IO', 'shfmt input failed', { cause: error })));
      child.stdin.end(source);
    });
    try { return bashCommands(JSON.parse(text)); } catch (error) { if (error instanceof ShellParseError) throw error; throw new ShellParseError('PROTOCOL', 'Invalid shfmt AST', { cause: error }); }
  }

  function pump() {
    if (disposed) return;
    for (let i = 0; i < queue.length && active < limits.maxConcurrent;) {
      const task = queue[i];
      if (task.dialect === 'powershell' && pwshRequest) { i++; continue; }
      queue.splice(i, 1);
      active++;
      running.add(task);
      const work = task.dialect === 'bash' ? parseBash(task.source, task) : new Promise((resolve, reject) => {
        const child = ensurePwsh();
        const reqId = ++requestSequence;
        pwshRequest = { resolve, reject, reqId, child, stderrBytes: 0 };
        task.kill = () => { if (pwsh === child && pwshRequest?.reqId === reqId) stopPwsh(task.stopped ?? failure('CANCELLED', 'PowerShell request cancelled')); };
        child.stdin.write(`${JSON.stringify({ reqId, source: task.source })}\n`);
      });
      work.then(task.resolve, task.reject).finally(() => { active--; running.delete(task); pump(); });
    }
  }

  return {
    /** Parse execution syntax into literal/dynamic command IR, or reject explicitly. */
    async parse(dialect, source, { signal } = {}) {
      if (disposed) throw failure('DISPOSED', 'Shell parsers disposed');
      if (dialect === 'pwsh') dialect = 'powershell';
      if (!['bash', 'powershell'].includes(dialect)) throw failure('DIALECT', 'Unsupported shell dialect');
      if (typeof source !== 'string' || Buffer.byteLength(source) > limits.maxInputBytes) throw failure('INPUT_LIMIT', 'Shell input exceeded budget or is not text');
      if (signal?.aborted) throw failure('CANCELLED', 'Shell parsing cancelled');
      if (queue.length >= limits.maxQueue) throw failure('BUSY', 'Shell parser queue full');
      return new Promise((resolve, reject) => {
        let settled = false;
        const task = { dialect, source, kill: null, stopped: null, resolve: done(resolve), reject: done(reject) };
        function done(callback) { return value => { if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener('abort', abort); callback(value); }; }
        function stop(error) { task.stopped = error; const index = queue.indexOf(task); if (index >= 0) queue.splice(index, 1); task.kill?.(); task.reject(error); }
        const abort = () => stop(failure('CANCELLED', 'Shell parsing cancelled'));
        // Includes queue wait and cold process startup, preventing indefinite backlog.
        const timer = setTimeout(() => stop(failure('TIMEOUT', 'Shell parser deadline exceeded')), limits.timeoutMs);
        task.cancel = stop;
        signal?.addEventListener('abort', abort, { once: true });
        queue.push(task);
        pump();
      });
    },
    /** Reject queued/in-flight requests and terminate the persistent helper. */
    dispose() {
      if (disposal) return disposal;
      disposed = true;
      for (const task of [...queue, ...running]) task.cancel(failure('DISPOSED', 'Shell parsers disposed'));
      queue.length = 0;
      stopPwsh(failure('DISPOSED', 'Shell parsers disposed'));
      const exits = [...children.values()];
      for (const child of children.keys()) child.kill();
      disposal = new Promise((resolve, reject) => {
        // Two seconds bounds process teardown after termination has been requested.
        const timer = setTimeout(() => reject(failure('DISPOSE_TIMEOUT', 'Shell parser process did not exit')), 2000);
        Promise.all(exits).then(() => { clearTimeout(timer); resolve(); });
      });
      return disposal;
    },
  };
}

function validateResult(result) {
  if (result?.error) throw failure('SYNTAX', result.error);
  if (!result || !Array.isArray(result.commands) || !Array.isArray(result.unknown) || result.unknown.some(reason => typeof reason !== 'string')) throw failure('PROTOCOL', 'Malformed parser result');
  for (const command of result.commands) {
    if (!command || !(command.name === null || typeof command.name === 'string') || !Array.isArray(command.args) || command.args.some(arg => arg !== null && typeof arg !== 'string')) throw failure('PROTOCOL', 'Malformed command');
    if (command.scope !== undefined && typeof command.scope !== 'string') throw failure('PROTOCOL', 'Malformed command scope');
    if (command.redirects !== undefined && (!Array.isArray(command.redirects) || command.redirects.some(redirect => !redirect || typeof redirect.operator !== 'string' || !(redirect.target === null || typeof redirect.target === 'string') || (redirect.heredoc !== undefined && typeof redirect.heredoc !== 'boolean')))) throw failure('PROTOCOL', 'Malformed redirection');
  }
}
