// Bounded official shfmt (mvdan/sh v3.12.0) client for POSIX-family shell text.
//
// The analyzed text is DATA: it is passed to the checksum-verified vendored shfmt
// binary as stdin and never executed or interpreted. This module reuses the
// verified vendor asset and mirrors the parser-pool budget mechanics, but keeps
// WORD-LEVEL quoting and glob facts that the shared pool mapper flattens away,
// so the analysis layer can emit accurate `patterns` and `literalOperands`.
//
// Error codes follow the analyzer's failure split:
// - `SYNTAX`   : shfmt rejected the input (parser syntax failure -> partial gap).
// - everything else (`UNAVAILABLE`, `INTEGRITY`, `TIMEOUT`, `IO`, `INPUT_LIMIT`,
//   `OUTPUT_LIMIT`, `PROTOCOL`, `CANCELLED`) is a resource or infrastructure
//   failure and must propagate (fail-closed at the caller).

import { spawn } from 'node:child_process';
import { readFile, chmod } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export class PosixParseError extends Error {
  constructor(code, message, options) { super(message, options); this.name = 'PosixParseError'; this.code = code; }
}

// Node types the official typed JSON may contain; anything else is refused
// instead of guessed (same contract as the shared parser pool).
const STRUCTURAL_TYPES = new Set(['File', 'CallExpr', 'Block', 'Subshell', 'BinaryCmd', 'IfClause', 'WhileClause', 'ForClause', 'WordIter', 'CStyleLoop', 'CaseClause', 'CaseItem', 'TestClause', 'DeclClause', 'LetClause', 'TimeClause', 'CoprocClause', 'Lit', 'SglQuoted', 'DblQuoted', 'ParamExp', 'CmdSubst', 'ProcSubst', 'ArithmExp', 'ArithmCmd', 'BinaryArithm', 'UnaryArithm', 'ParenArithm', 'BinaryTest', 'UnaryTest', 'ParenTest', 'ArrayExpr', 'ArrayElem', 'ExtGlob', 'BraceExp']);
const REDIRECT_OPERATORS = ['>', '>>', '<', '<>', '<&', '>&', '>|', '<<', '<<-', '<<<', '&>', '&>>'];
const AST_NODE_BUDGET = 200000;

// Verified vendored binary, resolved and checksum-checked once per process.
let verifiedBinary = null;

async function verifiedShfmt() {
  if (verifiedBinary) return verifiedBinary;
  const manifest = JSON.parse(await readFile(new URL('../../../../vendor/shfmt/manifest.json', import.meta.url), 'utf8'));
  const entry = manifest.binaries[`${process.platform}-${process.arch}`];
  if (!entry) throw new PosixParseError('UNAVAILABLE', 'Unsupported shfmt platform');
  const url = new URL(`../../../../vendor/shfmt/${entry.file}`, import.meta.url);
  let binary;
  try { binary = await readFile(url); } catch (error) { throw new PosixParseError('UNAVAILABLE', 'Local shfmt binary unavailable', { cause: error }); }
  if (createHash('sha256').update(binary).digest('hex') !== entry.sha256) throw new PosixParseError('INTEGRITY', 'shfmt SHA256 mismatch');
  // npm packing on Windows drops Unix executable bits; restore only the verified binary.
  if (process.platform !== 'win32') await chmod(url, 0o755);
  verifiedBinary = fileURLToPath(url);
  return verifiedBinary;
}

/**
 * Reduce one shell word (list of typed parts) to provable facts.
 * Returns `{ dynamic: true }` when the word needs expansion the parser cannot
 * prove; otherwise `{ dynamic: false, text, quoted, glob }` where `quoted` means
 * at least one part was quoted (so a leading `-` is a literal operand, not a
 * flag) and `glob` means an UNQUOTED glob metacharacter stays in the word (the
 * shell will expand it into a pattern target at run time).
 */
function wordInfo(parts, quoted = false) {
  if (!Array.isArray(parts)) throw new TypeError('Missing shell word parts');
  let text = '';
  let quotedAny = quoted;
  let glob = false;
  for (const part of parts) {
    if (part.Type === 'SglQuoted' && !part.Dollar) { text += part.Value; quotedAny = true; }
    else if (part.Type === 'DblQuoted' && !part.Dollar) {
      const nested = wordInfo(part.Parts ?? [], true);
      if (nested.dynamic) return { dynamic: true };
      // Glob characters inside quotes are literal data in POSIX shells; the
      // nested `glob` flag is intentionally NOT propagated.
      text += nested.text;
      quotedAny = true;
    } else if (part.Type === 'Lit') {
      if (typeof part.Value !== 'string') return { dynamic: true };
      if (part.Value.includes('\\')) return { dynamic: true }; // escape needs expansion; never guess
      if (!quoted) {
        if (/[*?[]/.test(part.Value)) glob = true;
        if (part.Value.includes('{') || part.Value.includes('}')) return { dynamic: true }; // brace expansion is unprovable
        // An unquoted `~` no longer forces a dynamic word: tilde expansion happens
        // only at the start of a word and resolves to the host home directory, which
        // commands.js normalizes against os.homedir() (an adapter fact, same trust
        // level as a verified cd). `~user` forms reach commands.js too and stay
        // unresolvable there; a tilde mid-word is literal data.
      }
      text += part.Value;
    } else return { dynamic: true }; // ParamExp/CmdSubst/ProcSubst/ArithmExp/ExtGlob/... unprovable
  }
  return { dynamic: false, text, quoted: quotedAny, glob };
}

/**
 * Convert the official typed JSON AST to command facts without evaluating shell
 * expansion. Each command carries `condition` ('certain' outside any loop or
 * conditional, 'possible' inside one) and the full word facts of its arguments.
 * @throws {TypeError} If AST structure or operators are unsupported.
 * @throws {RangeError} If the AST exceeds the traversal budget.
 */
export function posixCommands(ast) {
  if (ast?.Type !== 'File' || (ast.Stmts !== undefined && !Array.isArray(ast.Stmts))) throw new TypeError('Not a shfmt File');
  const commands = [];
  const unknown = new Set();
  const functions = new Set();
  // Iterative traversal bounds JS stack use even for deeply nested valid ASTs.
  const pending = [{ node: ast, scope: 'script', redirects: [], gated: false }];
  let nodes = 0;
  while (pending.length) {
    if (++nodes > AST_NODE_BUDGET) throw new RangeError('Shell AST node budget exceeded');
    const { node, scope, redirects, gated } = pending.pop();
    if (!node || typeof node !== 'object') continue;
    if (Array.isArray(node)) { for (let i = node.length - 1; i >= 0; i--) pending.push({ node: node[i], scope, redirects, gated }); continue; }
    if (node.Type === 'FuncDecl') { functions.add(node.Name?.Value); continue; }
    // An assignment (`x=/srv`, `export X=..`) changes shell state, so any fixed
    // target set derived from the literal command list is not trustworthy.
    if (node.Assigns?.length) unknown.add('Bash assignment changes state');
    if (node.Type && !STRUCTURAL_TYPES.has(node.Type)) throw new TypeError(`Unsupported Bash AST ${node.Type}`);
    if (node.Type === 'DeclClause' || node.Type === 'LetClause' || node.Type === 'ArithmCmd' || node.Type === 'ArithmExp') unknown.add(`Bash ${node.Type} evaluation`);
    let childGated = gated;
    if (node.Type === 'ForClause' || node.Type === 'WordIter' || node.Type === 'CStyleLoop') { unknown.add('Bash for loop repeats execution'); childGated = true; }
    if (node.Type === 'WhileClause') { unknown.add('Bash loop repeats execution'); childGated = true; }
    if (node.Type === 'IfClause') { unknown.add('Bash conditional statement gates execution'); childGated = true; }
    if (node.Type === 'CaseClause') { unknown.add('Bash case statement gates execution'); childGated = true; }
    const nextScope = ['CmdSubst', 'ProcSubst', 'Subshell'].includes(node.Type) ? node.Type : scope;
    const nextRedirects = node.Redirs ? node.Redirs.map((redir) => {
      if (!Number.isInteger(redir.Op)) throw new TypeError('Malformed shell redirection');
      const operator = REDIRECT_OPERATORS[redir.Op - 54];
      if (!operator) throw new TypeError('Unknown shfmt redirection');
      const target = redir.Word ? wordInfo(redir.Word.Parts) : { dynamic: true };
      return { operator, target: target.dynamic ? null : target.text, heredoc: Boolean(redir.Hdoc) };
    }) : nextScope !== scope ? [] : redirects;
    if (node.Type === 'CallExpr' && node.Args?.length) {
      const words = node.Args.map((word) => wordInfo(word.Parts));
      if (words.some((word) => word.dynamic)) unknown.add('Dynamic command or argument');
      commands.push({
        name: words[0].dynamic ? null : words[0].text,
        args: words.slice(1).map((word) => word.dynamic ? null : word.text),
        words: words.slice(1),
        redirects: nextRedirects,
        scope: nextScope,
        condition: childGated ? 'possible' : 'certain',
      });
    } else if ((node.Type === 'CallExpr' && nextRedirects.length) || (node.Redirs?.length && !node.Cmd)) {
      // Redirection without a command word still opens the target file.
      commands.push({ name: null, args: [], words: [], redirects: nextRedirects, scope: nextScope, condition: childGated ? 'possible' : 'certain' });
    }
    for (const [key, value] of Object.entries(node)) {
      if (value && typeof value === 'object' && !['Pos', 'End', 'Position', 'Comments', 'Last'].includes(key)) pending.push({ node: value, scope: nextScope, redirects: nextRedirects, gated: childGated });
    }
  }
  for (const command of commands) if (functions.has(command.name)) unknown.add('Invocation of locally defined Bash function');
  return { commands, unknown: [...unknown] };
}

/**
 * Parse POSIX-family shell text through the official shfmt binary.
 * @param {'bash'|'posix'} dialect Language dialect; never guessed.
 * @param {{timeoutMs:number,maxInputBytes:number,maxOutputBytes:number}} limits
 * @param {AbortSignal=} signal
 * @returns {Promise<{commands:Array,unknown:string[]}>}
 */
export async function parsePosix(source, dialect, limits, signal) {
  if (typeof source !== 'string' || Buffer.byteLength(source) > limits.maxInputBytes) {
    throw new PosixParseError('INPUT_LIMIT', 'Shell input exceeded budget or is not text');
  }
  if (signal?.aborted) throw new PosixParseError('CANCELLED', 'Shell parsing cancelled');
  const binary = await verifiedShfmt();
  // `-ln` selects the language dialect: bash or posix (shfmt's POSIX mode). Never guess.
  const languageDialect = dialect === 'posix' ? 'posix' : 'bash';
  const text = await new Promise((resolve, reject) => {
    const child = spawn(binary, ['-ln', languageDialect, '--to-json'], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    const chunks = [];
    let size = 0;
    let diagnostics = 0;
    let settled = false;
    const finish = (fn) => (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      fn(value);
    };
    const onAbort = () => { child.kill(); finish(reject)(new PosixParseError('CANCELLED', 'Shell parsing cancelled')); };
    const timer = setTimeout(() => { child.kill(); finish(reject)(new PosixParseError('TIMEOUT', 'shfmt deadline exceeded')); }, limits.timeoutMs);
    signal?.addEventListener('abort', onAbort, { once: true });
    child.stdout.on('data', (chunk) => {
      size += chunk.length;
      if (size > limits.maxOutputBytes) { child.kill(); finish(reject)(new PosixParseError('OUTPUT_LIMIT', 'shfmt output exceeded budget')); } else chunks.push(chunk);
    });
    child.stderr.on('data', (chunk) => {
      diagnostics += chunk.length;
      if (diagnostics > limits.maxOutputBytes) { child.kill(); finish(reject)(new PosixParseError('OUTPUT_LIMIT', 'shfmt diagnostics exceeded budget')); }
    });
    child.on('error', (error) => finish(reject)(new PosixParseError('UNAVAILABLE', 'shfmt unavailable', { cause: error })));
    child.stdin.on('error', (error) => finish(reject)(new PosixParseError('IO', 'shfmt input failed', { cause: error })));
    child.on('close', (code) => {
      if (code === 0) finish(resolve)(Buffer.concat(chunks).toString('utf8'));
      else finish(reject)(new PosixParseError('SYNTAX', 'shfmt rejected shell input'));
    });
    child.stdin.end(source);
  });
  let ast;
  try { ast = JSON.parse(text); } catch (error) { throw new PosixParseError('PROTOCOL', 'Invalid shfmt AST', { cause: error }); }
  try { return posixCommands(ast); } catch (error) {
    if (error instanceof PosixParseError) throw error;
    throw new PosixParseError('PROTOCOL', 'Invalid shfmt AST', { cause: error });
  }
}
