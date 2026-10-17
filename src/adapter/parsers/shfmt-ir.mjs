// This consumes mvdan's typed AST only; uncertain expansion remains dynamic.
const structuralTypes = new Set(['File', 'CallExpr', 'Block', 'Subshell', 'BinaryCmd', 'IfClause', 'WhileClause', 'ForClause', 'WordIter', 'CStyleLoop', 'CaseClause', 'CaseItem', 'TestClause', 'DeclClause', 'LetClause', 'TimeClause', 'CoprocClause', 'Lit', 'SglQuoted', 'DblQuoted', 'ParamExp', 'CmdSubst', 'ProcSubst', 'ArithmExp', 'ArithmCmd', 'BinaryArithm', 'UnaryArithm', 'ParenArithm', 'BinaryTest', 'UnaryTest', 'ParenTest', 'ArrayExpr', 'ArrayElem', 'ExtGlob', 'BraceExp']);

function literalParts(parts, quoted = false) {
  if (!Array.isArray(parts)) throw new TypeError('Missing shell word parts');
  let value = '';
  for (const part of parts) {
    if (part.Type === 'SglQuoted' && !part.Dollar) value += part.Value;
    else if (part.Type === 'DblQuoted' && !part.Dollar) {
      const nested = literalParts(part.Parts ?? [], true);
      if (nested === null) return null;
      value += nested;
    } else if (part.Type === 'Lit') {
      // Backslashes, tilde, braces and glob syntax need expansion; never guess.
      if (typeof part.Value !== 'string' || /\\/.test(part.Value) || (!quoted && /[*?\[\]~{}]/.test(part.Value))) return null;
      value += part.Value;
    } else return null;
  }
  return value;
}

/**
 * Convert official typed JSON to command IR without evaluating shell expansion.
 * @throws {TypeError} If AST structure or operators are unsupported.
 * @throws {RangeError} If the AST exceeds the traversal budget.
 */
export function bashCommands(ast) {
  if (ast?.Type !== 'File' || (ast.Stmts !== undefined && !Array.isArray(ast.Stmts))) throw new TypeError('Not a shfmt File');
  const commands = [];
  const unknown = new Set();
  const functions = new Set();
  // Iterative traversal bounds JS stack use even for deeply nested valid ASTs.
  const pending = [{ node: ast, scope: 'script', redirects: [] }];
  let nodes = 0;
  while (pending.length) {
    if (++nodes > 200000) throw new RangeError('Shell AST node budget exceeded');
    const { node, scope, redirects } = pending.pop();
    if (!node || typeof node !== 'object') continue;
    if (Array.isArray(node)) { for (let i = node.length - 1; i >= 0; i--) pending.push({ node: node[i], scope, redirects }); continue; }
    if (node.Type === 'FuncDecl') { functions.add(node.Name?.Value); continue; }
    if (node.Type && !structuralTypes.has(node.Type)) throw new TypeError(`Unsupported Bash AST ${node.Type}`);
    if (node.Type === 'DeclClause' || node.Type === 'LetClause' || node.Type === 'ArithmCmd' || node.Type === 'ArithmExp') unknown.add(`Bash ${node.Type} evaluation`);
    const nextScope = ['CmdSubst', 'ProcSubst', 'Subshell'].includes(node.Type) ? node.Type : scope;
    const nextRedirects = node.Redirs ? node.Redirs.map(redir => {
      if (!Number.isInteger(redir.Op)) throw new TypeError('Malformed shell redirection');
      const operator = ['>', '>>', '<', '<>', '<&', '>&', '>|', '<<', '<<-', '<<<', '&>', '&>>'][redir.Op - 54];
      if (!operator) throw new TypeError('Unknown shfmt redirection');
      return { operator, target: redir.Word ? literalParts(redir.Word.Parts) : null, heredoc: Boolean(redir.Hdoc) };
    }) : nextScope !== scope ? [] : redirects;
    if (node.Type === 'CallExpr' && node.Args?.length) {
      const words = node.Args.map(word => literalParts(word.Parts));
      if (words.includes(null)) unknown.add('Dynamic command or argument');
      commands.push({ name: words[0], args: words.slice(1), redirects: nextRedirects, scope: nextScope });
    } else if ((node.Type === 'CallExpr' && nextRedirects.length) || (node.Redirs?.length && !node.Cmd)) {
      commands.push({ name: null, args: [], redirects: nextRedirects, scope: nextScope });
    }
    for (const [key, value] of Object.entries(node)) {
      if (value && typeof value === 'object' && !['Pos', 'End', 'Position', 'Comments', 'Last'].includes(key)) pending.push({ node: value, scope: nextScope, redirects: nextRedirects });
    }
  }
  for (const command of commands) if (functions.has(command.name)) unknown.add('Invocation of locally defined Bash function');
  return { commands, unknown: [...unknown] };
}
