// js — JavaScript/TypeScript program provider on the official TypeScript Compiler API.
//
// The source under review is only parsed with `ts.createSourceFile`; it is never
// type-checked against real files, never executed, and never evaluated. The
// bounded target evaluation performs pure string arithmetic on literal path
// expressions (docs/technical-details/跨语言删除分析.md「有界目标求值」).
//
// Subset (docs/technical-details/跨语言删除分析.md「删除 sink 识别」):
// - node:fs / node:fs/promises: rm, rmSync, unlink, unlinkSync, rmdir, rmdirSync,
//   promises.rm/unlink/rmdir -> delete; rename/renameSync (and promises.rename)
//   -> move-source
// - fs-extra: remove/removeSync/emptyDir/emptyDirSync -> delete, move/moveSync
//   -> move-source; rimraf: rimraf/sync/rimrafSync/native -> delete
// - child_process: exec/execSync with a literal command -> shell fact; dynamic
//   command -> candidate; spawn/spawnSync/execFile/execFileSync with static argv
//   -> command fact or child-script fact for language runtimes; fork -> child-script
// - eval / new Function -> dynamic-execution candidate
// - tools.* / ctx.tools.* SDK sub-calls are skipped: they pass through their own
//   guard at dispatch time and must not be judged twice
// - aliases: import/default/namespace/named, `import x = require(...)`, require()
//   destructuring, require(<string literal>) direct chains, string-literal
//   element members (fs['rmSync']), module-level and single-assignment local
//   constants, small local functions with single-call-site parameter binding
// - reachability: module top level plus called/referenced functions; unreached
//   functions containing registered sinks are reported as a gap

import { createRequire } from 'node:module';
import { isRuntimeSpawn, CONDITION } from './common.js';

const FS_MODULES = new Set(['fs', 'node:fs']);
const FS_PROMISES_MODULES = new Set(['fs/promises', 'node:fs/promises']);
const FSX_MODULES = new Set(['fs-extra']);
const RIMRAF_MODULES = new Set(['rimraf']);
const CP_MODULES = new Set(['child_process', 'node:child_process']);
const PATH_MODULES = new Set(['path', 'node:path', 'path/posix', 'path/win32']);
const PATH_METHODS = new Set(['join', 'resolve', 'dirname', 'basename', 'normalize']);

const FS_DELETE = new Set(['rm', 'rmSync', 'unlink', 'unlinkSync', 'rmdir', 'rmdirSync']);
const FS_MOVE = new Set(['rename', 'renameSync']);
const FS_CONTENT = new Map([
  ['readFile', 'read-content'], ['readFileSync', 'read-content'], ['createReadStream', 'read-content'],
  ['writeFile', 'write-content'], ['writeFileSync', 'write-content'], ['createWriteStream', 'write-content'],
  ['appendFile', 'write-content'], ['appendFileSync', 'write-content'],
  ['truncate', 'truncate-content'], ['truncateSync', 'truncate-content'],
]);
const FS_COPY = new Set(['copyFile', 'copyFileSync']);
const FSX_DELETE = new Set(['remove', 'removeSync', 'emptyDir', 'emptyDirSync']);
const FSX_MOVE = new Set(['move', 'moveSync']);
const RIMRAF_DELETE = new Set(['rimraf', 'sync', 'rimrafSync', 'native']);
const CP_SHELL = new Set(['exec', 'execSync']);
const CP_ARGV = new Set(['spawn', 'spawnSync', 'execFile', 'execFileSync']);
// Execution-sink member names (child_process API). Called through a require
// direct chain on an UNMODELED module (require('cp').exec(x)) they are dynamic
// execution, never a silent skip; on modeled modules they flow into the normal
// dispatch below.
const CP_SINK_NAMES = new Set([...CP_SHELL, ...CP_ARGV]);
// Modules with modeled delete/execution sinks: computed member names on their
// objects (fs[k](x)) surface as dynamic-execution candidates.
const SINK_MODULES = new Set([...FS_MODULES, ...FS_PROMISES_MODULES, ...FSX_MODULES, ...RIMRAF_MODULES, ...CP_MODULES]);
const MODELED_MODULES = new Set([...SINK_MODULES, ...PATH_MODULES]);

class Unk extends Error {
  constructor(reason, base = null) { super(reason); this.base = base; }
}

class Scope {
  constructor(parent = null) { this.vars = new Map(); this.parent = parent; }
  get(name) {
    let scope = this;
    while (scope) {
      const binding = scope.vars.get(name);
      if (binding !== undefined) return binding;
      scope = scope.parent;
    }
    return null;
  }
}

class Analyzer {
  constructor(ts, sourceFile, cwd, platform, maxSteps, maxFacts, { signal, deadline } = {}) {
    this.ts = ts;
    this.sf = sourceFile;
    this.cwd = cwd;
    this.sep = platform === 'win32' ? '\\' : '/';
    this.maxSteps = maxSteps;
    this.maxFacts = maxFacts;
    this.signal = signal;
    this.deadline = deadline;
    this.steps = 0;
    this.facts = [];
    this.gaps = [];
    this.opaqueCalls = new Set();
    this.functions = new Map();   // name -> function node
    this.classes = new Map();     // name -> class node
    this.callSites = new Map();   // name -> CallExpression[]
    this.referenced = new Set();
    this.activeStack = [];
    this.inlined = new Set();     // functions already inlined from a reachable call site
  }

  line(node) { return this.sf.getLineAndCharacterOfPosition(node.getStart(this.sf)).line + 1; }
  // The walker debits steps and checks cancellation/deadline between
  // traversals; a timeout or cancel aborts as a signal, never as a result.
  tick() {
    if (this.signal?.aborted) throw 'cancelled';
    if (this.deadline !== undefined && Date.now() > this.deadline) throw 'timeout';
    if (++this.steps > this.maxSteps) throw 'steps';
  }
  add(fact) { if (this.facts.length >= this.maxFacts) throw 'facts'; this.facts.push(fact); }
  gap(kind, detail, node, fn) {
    this.gaps.push({ t: 'gap', kind, ...(detail ? { detail } : {}), ...(node ? { line: this.line(node) } : {}), ...(fn ? { function: fn } : {}) });
  }
  cond(depth) { return depth > 0 ? CONDITION.POSSIBLE : CONDITION.CERTAIN; }

  // ---------------- name resolution ----------------

  dotted(node, scope) {
    this.tick();
    const ts = this.ts;
    if (ts.isIdentifier(node)) {
      const binding = scope.get(node.text);
      if (!binding) {
        // PTC SDK roots (`tools`/`ctx`) are program globals, not imports; resolve
        // them so handleCall can skip SDK sub-calls without reporting opaque gaps.
        if (node.text === 'tools' || node.text === 'ctx') return node.text;
        return null;
      }
      if (binding.k === 'module') return binding.module;
      if (binding.k === 'member') return `${binding.module}.${binding.member}`;
      return null;
    }
    if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.name)) {
      const base = this.dotted(node.expression, scope);
      return base ? `${base}.${node.name.text}` : null;
    }
    // require(<string literal>) direct chains and string-literal element
    // members resolve like imports: require('fs').rmSync(...), fs['rmSync'](...).
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'require'
        && node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0])) {
      return node.arguments[0].text;
    }
    if (ts.isElementAccessExpression(node) && node.argumentExpression && ts.isStringLiteral(node.argumentExpression)) {
      const base = this.dotted(node.expression, scope);
      return base ? `${base}.${node.argumentExpression.text}` : null;
    }
    return null;
  }

  // ---------------- bounded target evaluation ----------------

  evalString(node, scope) {
    this.tick();
    const ts = this.ts;
    if (ts.isStringLiteral(node)) return node.text;
    if (ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
    if (ts.isTemplateExpression(node)) {
      let value = node.head.text;
      for (const span of node.templateSpans) {
        value += this.evalString(span.expression, scope);
        value += span.literal.text;
      }
      return value;
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === this.ts.SyntaxKind.PlusToken) {
      return this.evalString(node.left, scope) + this.evalString(node.right, scope);
    }
    if (ts.isIdentifier(node)) {
      const binding = scope.get(node.text);
      if (!binding) throw new Unk(`name '${node.text}' is not a locally verified constant`);
      if (binding.k === 'value' || binding.k === 'path') return binding.value;
      if (binding.k === 'enum') throw new Unk('value comes from directory enumeration', binding.base);
      throw new Unk(`name '${node.text}' is ${binding.k}`);
    }
    if (ts.isCallExpression(node)) return this.evalCallString(node, scope);
    if (ts.isPropertyAccessExpression(node)) {
      const binding = ts.isIdentifier(node.expression) ? scope.get(node.expression.text) : null;
      if (binding && (binding.k === 'path' || binding.k === 'value') && ts.isIdentifier(node.name)) {
        return this.evalPathMember(binding.value, node.name.text);
      }
      throw new Unk('property access not evaluated');
    }
    throw new Unk(`expression ${this.ts.SyntaxKind[node.kind]} not evaluated`);
  }

  evalPathMember(value, name) {
    const work = value.replace(/[\\/]+$/, '');
    const cut = Math.max(work.lastIndexOf('/'), work.lastIndexOf('\\'));
    if (name === 'parent') return cut > 0 ? work.slice(0, cut) : (cut === 0 ? work.slice(0, 1) : '.');
    if (name === 'name') return cut >= 0 ? work.slice(cut + 1) : work;
    if (name === 'stem' || name === 'suffix') {
      const base = cut >= 0 ? work.slice(cut + 1) : work;
      const dot = base.lastIndexOf('.');
      return name === 'stem' ? (dot > 0 ? base.slice(0, dot) : base) : (dot > 0 ? base.slice(dot) : '');
    }
    throw new Unk(`path member '${name}' not evaluated`);
  }

  evalCallString(node, scope) {
    this.tick();
    const dotted = this.dotted(node.expression, scope);
    const args = node.arguments;
    if (dotted && PATH_MODULES.has(dotted.split('.')[0])) {
      const members = dotted.split('.').slice(1).filter(m => m !== 'posix' && m !== 'win32');
      const method = members[members.length - 1];
      if (members.length === 1 && PATH_METHODS.has(method)) {
        if (method === 'join') {
          const parts = args.map(a => this.evalString(a, scope));
          if (parts.length === 0) throw new Unk('join with no parts');
          let base = parts[0];
          for (const part of parts.slice(1)) {
            if (/^[\\/]/.test(part) || /^[A-Za-z]:/.test(part)) base = part;
            else base = base.endsWith('/') || base.endsWith('\\') ? base + part : base + this.sep + part;
          }
          return base;
        }
        const value = this.evalString(args[0], scope);
        if (method === 'resolve') {
          if (/^[\\/]/.test(value) || /^[A-Za-z]:/.test(value)) return value;
          if (this.cwd) return this.cwd.endsWith('/') || this.cwd.endsWith('\\') ? this.cwd + value : this.cwd + this.sep + value;
          throw new Unk('relative resolve without a verified cwd');
        }
        if (method === 'normalize') return value;
        return this.evalPathMember(value, method);
      }
    }
    if (dotted && dotted === 'process.cwd' && this.cwd) return this.cwd;
    if (this.ts.isIdentifier(node.expression) && node.expression.text === 'String' && args.length === 1) return this.evalString(args[0], scope);
    throw new Unk(`call ${dotted ?? 'opaque'} not evaluated`);
  }

  // ---------------- bindings ----------------

  bindModule(name, module, scope) {
    scope.vars.set(name, { k: 'module', module });
  }

  bindImports(sf, scope) {
    const ts = this.ts;
    for (const statement of sf.statements) {
      if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) {
        const module = statement.moduleSpecifier.text;
        const clause = statement.importClause;
        if (!clause) continue;
        if (clause.name) this.bindModule(clause.name.text, module, scope);
        const bindings = clause.namedBindings;
        if (bindings && ts.isNamespaceImport(bindings)) this.bindModule(bindings.name.text, module, scope);
        else if (bindings && ts.isNamedImports(bindings)) {
          for (const element of bindings.elements) {
            const imported = element.propertyName && ts.isIdentifier(element.propertyName) ? element.propertyName.text : element.name.text;
            scope.vars.set(element.name.text, { k: 'member', module, member: imported });
          }
        }
      } else if (ts.isImportEqualsDeclaration(statement) && statement.moduleReference && ts.isExternalModuleReference(statement.moduleReference) && statement.moduleReference.expression && ts.isStringLiteral(statement.moduleReference.expression)) {
        this.bindModule(statement.name.text, statement.moduleReference.expression.text, scope);
      }
    }
  }

  bindDeclaration(statement, scope) {
    const ts = this.ts;
    if (!ts.isVariableStatement(statement)) return false;
    let bound = false;
    for (const declaration of statement.declarationList.declarations) {
      // const { remove, removeSync } = require('fs-extra') — member bindings.
      if (ts.isObjectBindingPattern(declaration.name) && declaration.initializer && ts.isCallExpression(declaration.initializer) && ts.isIdentifier(declaration.initializer.expression) && declaration.initializer.expression.text === 'require' && declaration.initializer.arguments.length === 1 && ts.isStringLiteral(declaration.initializer.arguments[0])) {
        const module = declaration.initializer.arguments[0].text;
        for (const element of declaration.name.elements) {
          if (!ts.isBindingElement(element)) continue;
          const imported = element.propertyName && ts.isIdentifier(element.propertyName) ? element.propertyName.text : (ts.isIdentifier(element.name) ? element.name.text : null);
          if (imported && ts.isIdentifier(element.name)) {
            scope.vars.set(element.name.text, { k: 'member', module, member: imported });
            bound = true;
          }
        }
        continue;
      }
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
      bound = bound || this.bindInitializer(declaration.name.text, declaration.initializer, scope);
    }
    return bound;
  }

  bindInitializer(name, initializer, scope) {
    const ts = this.ts;
    this.tick();
    // const fs = require('node:fs') / const { rm } = require('node:fs/promises')
    if (ts.isCallExpression(initializer) && ts.isIdentifier(initializer.expression) && initializer.expression.text === 'require' && initializer.arguments.length === 1 && ts.isStringLiteral(initializer.arguments[0])) {
      const module = initializer.arguments[0].text;
      this.bindModule(name, module, scope);
      return true;
    }
    // const rm = fs.rm / const r = rimraf.sync / const p = path.join
    if (ts.isPropertyAccessExpression(initializer) && ts.isIdentifier(initializer.name)) {
      const dotted = this.dotted(initializer, scope);
      if (dotted) {
        const [module, ...members] = dotted.split('.');
        scope.vars.set(name, { k: 'member', module, member: members.join('.') });
        return true;
      }
    }
    // const p = Path(d) / path value
    if (ts.isCallExpression(initializer) || ts.isStringLiteral(initializer) || ts.isTemplateExpression(initializer) || (ts.isBinaryExpression(initializer) && initializer.operatorToken.kind === ts.SyntaxKind.PlusToken)) {
      try {
        scope.vars.set(name, { k: 'path', value: this.evalString(initializer, scope) });
        return true;
      } catch (error) {
        if (!(error instanceof Unk)) throw error;
        scope.vars.set(name, { k: 'unknown' });
        return false;
      }
    }
    // Local function reference: const clean = (p) => { ... }
    if (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)) {
      scope.vars.set(name, { k: 'func', node: initializer, name });
      this.functions.set(name, initializer);
      return true;
    }
    if (ts.isIdentifier(initializer)) {
      const binding = scope.get(initializer.text);
      if (binding && (binding.k === 'value' || binding.k === 'path')) {
        scope.vars.set(name, { k: 'path', value: binding.value });
        return true;
      }
      if (binding && binding.k === 'member') {
        scope.vars.set(name, { k: 'member', module: binding.module, member: binding.member });
        return true;
      }
    }
    scope.vars.set(name, { k: 'unknown' });
    return false;
  }

  // ---------------- statement walk ----------------

  walkStatements(statements, scope, depth, fn) {
    for (const statement of statements) this.walkStatement(statement, scope, depth, fn);
  }

  walkStatement(statement, scope, depth, fn) {
    this.tick();
    const ts = this.ts;
    if (ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement)) return; // reachability phase
    if (ts.isVariableStatement(statement)) {
      this.bindDeclaration(statement, scope);
      this.walkNode(statement.declarationList, scope, depth, fn);
      return;
    }
    if (ts.isExpressionStatement(statement)) {
      this.walkExpression(statement.expression, scope, depth, fn);
      return;
    }
    if (ts.isIfStatement(statement)) {
      this.walkExpression(statement.expression, scope, depth, fn);
      this.walkStatement(statement.thenStatement, scope, depth + 1, fn);
      if (statement.elseStatement) this.walkStatement(statement.elseStatement, scope, depth + 1, fn);
      return;
    }
    // WhileStatement carries its body in `statement` (there is no thenStatement);
    // reading thenStatement here was the while crash root cause.
    if (ts.isWhileStatement(statement)) {
      this.walkExpression(statement.expression, scope, depth, fn);
      this.walkStatement(statement.statement, scope, depth + 1, fn);
      return;
    }
    if (ts.isForStatement(statement) || ts.isForOfStatement(statement) || ts.isForInStatement(statement)) {
      if (ts.isForStatement(statement)) {
        if (statement.initializer) this.walkNode(statement.initializer, scope, depth, fn);
        if (statement.condition) this.walkExpression(statement.condition, scope, depth, fn);
        if (statement.incrementor) this.walkExpression(statement.incrementor, scope, depth, fn);
      } else {
        if (statement.initializer) this.walkNode(statement.initializer, scope, depth, fn);
        this.bindEnumeration(statement, scope);
        this.walkExpression(statement.expression, scope, depth, fn);
      }
      this.walkStatement(statement.statement, scope, depth + 1, fn);
      return;
    }
    if (ts.isDoStatement(statement)) {
      this.walkStatement(statement.statement, scope, depth + 1, fn);
      this.walkExpression(statement.expression, scope, depth, fn);
      return;
    }
    if (ts.isBlock(statement)) {
      this.walkStatements(statement.statements, new Scope(scope), depth, fn);
      return;
    }
    if (ts.isTryStatement(statement)) {
      this.walkStatement(statement.tryBlock, scope, depth + 1, fn);
      if (statement.catchClause && statement.catchClause.block) this.walkStatement(statement.catchClause.block, scope, depth + 1, fn);
      if (statement.finallyBlock) this.walkStatement(statement.finallyBlock, scope, depth + 1, fn);
      return;
    }
    if (ts.isSwitchStatement(statement)) {
      this.walkExpression(statement.expression, scope, depth, fn);
      for (const clause of statement.caseBlock.clauses) this.walkStatements(clause.statements, scope, depth + 1, fn);
      return;
    }
    if (ts.isReturnStatement(statement) && statement.expression) {
      this.walkExpression(statement.expression, scope, depth, fn);
      return;
    }
    this.walkNode(statement, scope, depth, fn);
  }

  bindEnumeration(statement, scope) {
    // for (const f of fs.readdirSync(dir)) -> enum binding with verified base
    const ts = this.ts;
    if (!ts.isForOfStatement(statement)) return;
    let boundName = null;
    if (ts.isIdentifier(statement.initializer)) boundName = statement.initializer.text;
    else if (ts.isVariableDeclarationList(statement.initializer) && statement.initializer.declarations.length === 1 && ts.isIdentifier(statement.initializer.declarations[0].name)) boundName = statement.initializer.declarations[0].name.text;
    if (!boundName) return;
    const call = statement.expression;
    if (!ts.isCallExpression(call)) return;
    const dotted = this.dotted(call.expression, scope);
    if (!dotted) return;
    const [module, ...members] = dotted.split('.');
    if (FS_MODULES.has(module) || FS_PROMISES_MODULES.has(module)) {
      const method = members[members.length - 1];
      if (method !== 'readdir' && method !== 'readdirSync') return;
      try {
        const base = this.evalString(call.arguments[0], scope);
        scope.vars.set(boundName, { k: 'enum', base });
      } catch (error) {
        if (error instanceof Unk && error.base) scope.vars.set(boundName, { k: 'enum', base: error.base });
      }
    }
  }

  walkExpression(node, scope, depth, fn) {
    this.tick();
    const ts = this.ts;
    if (ts.isCallExpression(node)) {
      this.handleCall(node, scope, depth, fn);
      return;
    }
    if (ts.isNewExpression(node)) {
      const dotted = this.dotted(node.expression, scope);
      const name = dotted ?? (ts.isIdentifier(node.expression) ? node.expression.text : null);
      if (name === 'Function' || name === 'eval') {
        this.add({ t: 'candidate', kind: 'dynamic-execution', reason: 'new Function executes dynamically constructed code', condition: this.cond(depth), line: this.line(node), ...(fn ? { function: fn } : {}) });
        return;
      }
      for (const arg of node.arguments ?? []) this.walkExpression(arg, scope, depth, fn);
      return;
    }
    // Depth-first over children, excluding the dotted resolution noise.
    ts.forEachChild(node, child => {
      if (ts.isCallExpression(child) || ts.isNewExpression(child)) this.walkExpression(child, scope, depth, fn);
      else if (ts.isStatement(child)) this.walkStatement(child, scope, depth, fn);
      else this.walkExpression(child, scope, depth, fn);
    });
  }

  walkNode(node, scope, depth, fn) {
    const ts = this.ts;
    ts.forEachChild(node, child => {
      if (ts.isStatement(child)) this.walkStatement(child, scope, depth, fn);
      else this.walkExpression(child, scope, depth, fn);
    });
  }

  // ---------------- call dispatch ----------------

  handleCall(node, scope, depth, fn) {
    this.tick();
    const ts = this.ts;
    const line = this.line(node);
    const cond = this.cond(depth);
    const dotted = this.dotted(node.expression, scope);
    // Root of the callee chain when it is a require(...) call, if any: direct
    // chains (require('cp').exec(x)) and dynamic-specifier requires.
    const requireRoot = this.rootRequireCall(node.expression);

    // tools.<name> / ctx.tools.<name> SDK sub-calls: own guard at dispatch time.
    if (dotted && (dotted === 'tools' || dotted.startsWith('tools.') || dotted.startsWith('ctx.tools.') || dotted.startsWith('ctx.'))) return;

    if (!dotted && ts.isIdentifier(node.expression)) {
      const name = node.expression.text;
      if (name === 'eval') {
        this.add({ t: 'candidate', kind: 'dynamic-execution', reason: 'eval() executes dynamically constructed code', condition: cond, line, ...(fn ? { function: fn } : {}) });
        return;
      }
      if (name === 'require' && node.arguments.length === 1 && !ts.isStringLiteral(node.arguments[0])) {
        this.opaqueCalls.add('require(dynamic)');
        return;
      }
      // A require(<string literal>) call is a provable binding, not an opaque
      // surface (R-9): direct-chain and destructuring forms resolve it.
      if (name === 'require' && node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0])) {
        return;
      }
      const binding = scope.get(name);
      if (binding && binding.k === 'func') {
        this.inlineFunction(binding, node, scope, depth, fn);
        return;
      }
      if (!binding) this.opaqueCalls.add(name);
    }

    if (!dotted) {
      // Counter-examples that must never drop silently: a require of a
      // dynamically computed module specifier (require(m).rmSync(x)) and a
      // computed member name on a resolved sink module (fs[k](x)) are
      // dynamic-execution candidates.
      if (requireRoot && !ts.isStringLiteral(requireRoot.arguments[0])) {
        this.add({ t: 'candidate', kind: 'dynamic-execution', reason: 'require() module specifier is not statically known', condition: cond, line, ...(fn ? { function: fn } : {}) });
      } else if (ts.isElementAccessExpression(node.expression) && node.expression.argumentExpression && !ts.isStringLiteral(node.expression.argumentExpression)) {
        const base = this.dotted(node.expression.expression, scope);
        const baseModule = base ? base.split('.')[0] : null;
        if (baseModule && SINK_MODULES.has(baseModule)) {
          this.add({ t: 'candidate', kind: 'dynamic-execution', reason: 'member name of a resolved module is computed at runtime', condition: cond, line, ...(fn ? { function: fn } : {}) });
        }
      }
      // Method call on a value (e.g. Path(...).unlink()) — try receiver path value.
      if (ts.isPropertyAccessExpression(node.expression) && ts.isIdentifier(node.expression.name)) {
        if (this.handleValueMethod(node, scope, cond, line, fn)) return;
        const receiverBinding = ts.isIdentifier(node.expression.expression) ? scope.get(node.expression.expression.text) : null;
        if (receiverBinding && (receiverBinding.k === 'path' || receiverBinding.k === 'value')) {
          this.opaqueCalls.add(node.expression.name.text);
          return;
        }
      }
      for (const arg of node.arguments) this.walkExpression(arg, scope, depth, fn);
      return;
    }

    const [module, ...members] = dotted.split('.');
    const member = members[members.length - 1];
    const chain = members.filter(m => m !== 'promises' && m !== 'posix' && m !== 'win32');

    if ((FS_MODULES.has(module) || FS_PROMISES_MODULES.has(module)) && chain.length === 1) {
      const contentAction = FS_CONTENT.get(member);
      if (contentAction) {
        this.reportContent(contentAction, node.arguments[0], scope, cond, line, fn);
        return;
      }
      if (FS_COPY.has(member)) {
        this.reportContent('copy-content', node.arguments[0], scope, cond, line, fn);
        this.reportContent('write-content', node.arguments[1], scope, cond, line, fn);
        return;
      }
      if (FS_DELETE.has(member)) {
        this.reportDelete(node, member, scope, cond, line, fn, { recursiveOption: member === 'rm' || member === 'rmSync' || member === 'rmdir' || member === 'rmdirSync' });
        return;
      }
      if (chain.length === 1 && FS_MOVE.has(member)) {
        this.reportMove(node, scope, cond, line, fn);
        return;
      }
    }
    if (FSX_MODULES.has(module) && chain.length === 1) {
      if (FSX_DELETE.has(member)) {
        this.reportDelete(node, member, scope, cond, line, fn, { recursiveOption: false, alwaysRecursive: true, contentsOnly: member.startsWith('emptyDir') });
        return;
      }
      if (FSX_MOVE.has(member)) {
        this.reportMove(node, scope, cond, line, fn);
        return;
      }
    }
    if (RIMRAF_MODULES.has(module) && chain.length === 1 && RIMRAF_DELETE.has(member)) {
      this.reportDelete(node, member, scope, cond, line, fn, { recursiveOption: false, alwaysRecursive: true });
      return;
    }
    if (CP_MODULES.has(module) && chain.length === 1) {
      if (CP_SHELL.has(member)) {
        this.reportShellExec(node, scope, cond, line, fn);
        return;
      }
      if (CP_ARGV.has(member)) {
        this.reportSpawn(node, scope, cond, line, fn);
        return;
      }
      if (member === 'fork') {
        this.reportFork(node, scope, cond, line, fn);
        return;
      }
    }
    // Execution-sink names called through a require direct chain on an
    // unmodeled module (require('cp').exec(x)) are dynamic execution, not a
    // silent skip. Import/member bindings on unmodeled modules keep their
    // existing opaque semantics.
    if (requireRoot && ts.isStringLiteral(requireRoot.arguments[0]) && CP_SINK_NAMES.has(member) && !MODELED_MODULES.has(module)) {
      this.add({ t: 'candidate', kind: 'dynamic-execution', reason: `execution sink '${member}' on unmodeled module '${module}'`, condition: cond, line, ...(fn ? { function: fn } : {}) });
      return;
    }
    for (const arg of node.arguments) this.walkExpression(arg, scope, depth, fn);
  }

  // Walks a callee chain down to a root require(...) call, if any.
  rootRequireCall(node) {
    const ts = this.ts;
    let current = node;
    while (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) current = current.expression;
    if (ts.isCallExpression(current) && ts.isIdentifier(current.expression) && current.expression.text === 'require' && current.arguments.length === 1) return current;
    return null;
  }

  handleValueMethod(node, scope, cond, line, fn) {
    // Path binding method sinks: p.unlink(), p.rmdir(); also rimraf default-call shape
    // is handled through module bindings; only value receivers are covered here.
    const ts = this.ts;
    const attr = node.expression.name.text;
    if (attr !== 'unlink' && attr !== 'rmdir') return false;
    const binding = ts.isIdentifier(node.expression.expression) ? scope.get(node.expression.expression.text) : null;
    if (!binding || (binding.k !== 'path' && binding.k !== 'value')) return false;
    this.add({ t: 'operation', action: 'delete', target: { kind: 'exact', paths: [binding.value] }, recursive: false, condition: cond, line, ...(fn ? { function: fn } : {}) });
    return true;
  }

  resolveTarget(node, scope, fn) {
    // Returns {value} or {candidateReason, knownScope?}
    const args = node.arguments;
    if (args.length === 0) return { candidateReason: 'sink called without a positional target' };
    try {
      return { value: this.evalString(args[0], scope) };
    } catch (error) {
      if (!(error instanceof Unk)) throw error;
      let receiver = null;
      if (this.ts.isIdentifier(args[0])) {
        const binding = scope.get(args[0].text);
        if (binding && binding.k === 'enum') receiver = binding.base;
      }
      return { candidateReason: `target is not statically evaluable (${error.message})`, knownScope: receiver ? [receiver] : (error.base ? [error.base] : null) };
    }
  }

  reportContent(action, argument, scope, condition, line, fn) {
    if (!argument) return;
    try {
      const value = this.evalString(argument, scope);
      this.add({ t: 'operation', action, target: { kind: 'exact', paths: [value] }, recursive: false, condition, line,
        ...(fn ? { function: fn } : {}) });
    } catch (error) {
      if (!(error instanceof Unk)) throw error;
      this.add({ t: 'gap', kind: 'content-target-unresolved', line, ...(fn ? { function: fn } : {}) });
    }
  }

  reportDelete(node, member, scope, cond, line, fn, { recursiveOption, alwaysRecursive = false, contentsOnly = false }) {
    let recursive = alwaysRecursive;
    let details = contentsOnly ? 'directory contents are removed, the directory itself is kept' : null;
    if (recursiveOption) {
      const options = node.arguments[1];
      if (options && this.ts.isObjectLiteralExpression(options)) {
        for (const property of options.properties) {
          if (this.ts.isSpreadAssignment(property) || this.ts.isComputedPropertyName(property.name)) {
            recursive = 'unknown';
          } else if (property.name?.text === 'recursive') {
            const kind = this.ts.isPropertyAssignment(property) ? property.initializer.kind : undefined;
            recursive = kind === this.ts.SyntaxKind.TrueKeyword ? true
              : kind === this.ts.SyntaxKind.FalseKeyword ? false : 'unknown';
          }
        }
      } else if (options) {
        recursive = 'unknown';
        details = 'options object is not statically known';
      }
    }
    const target = this.resolveTarget(node, scope, fn);
    if (target.value !== undefined) {
      this.add({ t: 'operation', action: 'delete', target: { kind: 'exact', paths: [target.value] }, recursive, condition: cond, line, ...(details ? { details } : {}), ...(fn ? { function: fn } : {}) });
    } else {
      this.add({ t: 'candidate', kind: 'unverified-effect', reason: `${member}: ${target.candidateReason}`, condition: cond, line, ...(target.knownScope ? { knownScope: target.knownScope } : {}), ...(fn ? { function: fn } : {}) });
    }
  }

  reportMove(node, scope, cond, line, fn) {
    const args = node.arguments;
    if (args.length < 2) {
      this.add({ t: 'candidate', kind: 'unverified-effect', reason: 'move without statically known source or destination', condition: cond, line, ...(fn ? { function: fn } : {}) });
      return;
    }
    let source;
    let destination;
    const issues = [];
    try { source = this.evalString(args[0], scope); } catch (error) { if (!(error instanceof Unk)) throw error; issues.push(`source (${error.message})`); }
    try { destination = this.evalString(args[1], scope); } catch (error) { if (!(error instanceof Unk)) throw error; issues.push(`destination (${error.message})`); }
    if (issues.length > 0) {
      this.add({ t: 'candidate', kind: 'unverified-effect', reason: `move: ${issues.join(', ')} not statically evaluable`, condition: cond, line, ...(fn ? { function: fn } : {}) });
      return;
    }
    this.add({ t: 'operation', action: 'move-source', target: { kind: 'exact', paths: [source] }, recursive: false, condition: cond, line, ...(destination ? { details: `destination: ${destination}` } : {}), ...(fn ? { function: fn } : {}) });
  }

  reportShellExec(node, scope, cond, line, fn) {
    const command = node.arguments[0];
    try {
      const text = this.evalString(command, scope);
      this.add({ t: 'shell', text, condition: cond, line, ...(fn ? { function: fn } : {}) });
    } catch (error) {
      if (!(error instanceof Unk)) throw error;
      this.add({ t: 'candidate', kind: 'dynamic-execution', reason: `exec command is not statically known (${error.message})`, condition: cond, line, ...(error.base ? { knownScope: [error.base] } : {}), ...(fn ? { function: fn } : {}) });
    }
  }

  reportSpawn(node, scope, cond, line, fn) {
    const args = node.arguments;
    if (args.length === 0) {
      this.add({ t: 'candidate', kind: 'dynamic-execution', reason: 'spawn without a static command', condition: cond, line, ...(fn ? { function: fn } : {}) });
      return;
    }
    let shellOption = false;
    const options = args[2];
    if (options && this.ts.isObjectLiteralExpression(options)) {
      for (const property of options.properties) {
        if (this.ts.isPropertyAssignment(property) && this.ts.isIdentifier(property.name) && property.name.text === 'shell') {
          shellOption = property.initializer.kind === this.ts.SyntaxKind.TrueKeyword;
        }
      }
    }
    let executable;
    try { executable = this.evalString(args[0], scope); } catch (error) {
      if (!(error instanceof Unk)) throw error;
      this.add({ t: 'candidate', kind: 'dynamic-execution', reason: `spawn command is not statically known (${error.message})`, condition: cond, line, ...(error.base ? { knownScope: [error.base] } : {}), ...(fn ? { function: fn } : {}) });
      return;
    }
    let argv = [];
    let allStatic = true;
    if (args[1] && this.ts.isArrayLiteralExpression(args[1])) {
      for (const element of args[1].elements) {
        if (this.ts.isSpreadElement(element)) { allStatic = false; argv.push(null); continue; }
        try { argv.push(this.evalString(element, scope)); } catch (error) {
          if (!(error instanceof Unk)) throw error;
          argv.push(null);
          allStatic = false;
        }
      }
    } else if (args[1]) {
      allStatic = false;
    }
    if (shellOption) {
      if (allStatic) {
        const text = [executable, ...argv].join(' ');
        this.add({ t: 'shell', text, condition: cond, line, ...(fn ? { function: fn } : {}) });
      } else {
        this.add({ t: 'candidate', kind: 'dynamic-execution', reason: 'spawn with shell:true has a partially dynamic command', condition: cond, line, ...(fn ? { function: fn } : {}) });
      }
      return;
    }
    if (isRuntimeSpawn(executable, argv)) {
      this.add({ t: 'child-script', executable, args: argv, condition: cond, line, ...(fn ? { function: fn } : {}) });
    } else {
      this.add({ t: 'command', executable, args: argv, condition: cond, line, ...(fn ? { function: fn } : {}) });
    }
  }

  reportFork(node, scope, cond, line, fn) {
    const args = node.arguments;
    if (args.length === 0) {
      this.add({ t: 'candidate', kind: 'dynamic-execution', reason: 'fork without a static module path', condition: cond, line, ...(fn ? { function: fn } : {}) });
      return;
    }
    let script;
    try { script = this.evalString(args[0], scope); } catch (error) {
      if (!(error instanceof Unk)) throw error;
      this.add({ t: 'candidate', kind: 'dynamic-execution', reason: `fork module path is not statically known (${error.message})`, condition: cond, line, ...(fn ? { function: fn } : {}) });
      return;
    }
    const argv = [script];
    if (args[1] && this.ts.isArrayLiteralExpression(args[1])) {
      for (const element of args[1].elements) {
        try { argv.push(this.evalString(element, scope)); } catch { argv.push(null); }
      }
    }
    this.add({ t: 'child-script', executable: 'node', args: argv, condition: cond, line, ...(fn ? { function: fn } : {}) });
  }

  // ---------------- local function inlining ----------------

  inlineFunction(binding, callNode, scope, depth, fn) {
    this.tick();
    const ts = this.ts;
    const name = binding.name ?? '<anonymous>';
    if (this.activeStack.includes(name)) return;
    this.inlined.add(name);
    if (this.activeStack.length >= 4) {
      this.gap('call-depth-exceeded', 'local function inlining stopped at depth limit', callNode, name);
      return;
    }
    const local = new Scope(scope);
    const { names: params, rest } = getParameterNames(ts, binding.node);
    const args = callNode.arguments;
    for (let index = 0; index < params.length; index += 1) {
      const param = params[index];
      if (!param) continue;
      if (index < args.length) {
        try {
          local.vars.set(param, { k: 'path', value: this.evalString(args[index], scope) });
        } catch (error) {
          if (!(error instanceof Unk)) throw error;
          local.vars.set(param, { k: 'unknown' });
        }
      } else local.vars.set(param, { k: 'unknown' });
    }
    if (rest) local.vars.set(rest, { k: 'unknown' });
    this.activeStack.push(name);
    try {
      const body = binding.node.body;
      if (ts.isBlock(body)) this.walkStatements(body.statements, local, depth, name);
      else this.walkExpression(body, local, depth, name);
    } finally {
      this.activeStack.pop();
    }
  }

  analyzeDetached(node, name) {
    const ts = this.ts;
    const local = new Scope();
    const { names, rest } = getParameterNames(ts, node);
    for (const param of names) if (param) local.vars.set(param, { k: 'unknown' });
    if (rest) local.vars.set(rest, { k: 'unknown' });
    this.activeStack.push(name);
    try {
      const body = node.body;
      if (body && ts.isBlock(body)) this.walkStatements(body.statements, local, 1, name);
      else if (body) this.walkExpression(body, local, 1, name);
    } finally {
      this.activeStack.pop();
    }
  }

  // ---------------- reachability ----------------

  collectSymbols(sf, scope) {
    const ts = this.ts;
    for (const statement of sf.statements) {
      if (ts.isFunctionDeclaration(statement) && statement.name) {
        this.functions.set(statement.name.text, statement);
        scope.vars.set(statement.name.text, { k: 'func', node: statement, name: statement.name.text });
      } else if (ts.isClassDeclaration(statement) && statement.name) {
        this.classes.set(statement.name.text, statement);
        scope.vars.set(statement.name.text, { k: 'unknown' });
      } else if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
          if (ts.isArrowFunction(declaration.initializer) || ts.isFunctionExpression(declaration.initializer)) {
            this.functions.set(declaration.name.text, declaration.initializer);
            scope.vars.set(declaration.name.text, { k: 'func', node: declaration.initializer, name: declaration.name.text });
          }
        }
      }
    }
    for (const node of sf.statements) collectCallsAndReferences(ts, node, this.callSites, this.referenced, null);
  }

  hasRegisteredSink(node, scope) {
    let found = false;
    const visit = (current) => {
      this.tick();
      const ts = this.ts;
      if (ts.isCallExpression(current)) {
        const dotted = this.dotted(current.expression, scope);
        if (dotted) {
          const [module, ...members] = dotted.split('.');
          const member = members[members.length - 1];
          const chain = members.filter(m => m !== 'promises' && m !== 'posix' && m !== 'win32');
          if ((FS_MODULES.has(module) || FS_PROMISES_MODULES.has(module) || FSX_MODULES.has(module) || RIMRAF_MODULES.has(module) || CP_MODULES.has(module)) && chain.length === 1) return found = true;
        }
        const name = ts.isIdentifier(current.expression) ? current.expression.text : null;
        if (name === 'eval' || name === 'exec' || name === 'compile') return found = true;
      }
      if (found) return;
      ts.forEachChild(current, visit);
    };
    try { visit(node); } catch { return true; }
    return found;
  }

  run(sf) {
    const moduleScope = new Scope();
    this.bindImports(sf, moduleScope);
    this.collectSymbols(sf, moduleScope);
    this.walkStatements(sf.statements, moduleScope, 0, null);
    for (const [name, node] of this.functions) {
      if ((this.callSites.has(name) || this.referenced.has(name)) && !this.inlined.has(name)) this.analyzeDetached(node, name);
    }
    if (this.classes) {
      for (const [name, classNode] of this.classes) {
        for (const member of classNode.members) {
          const method = this.ts.isMethodDeclaration(member) ? member : null;
          if (!method || !method.body) continue;
          if (this.referenced.has(name)) this.analyzeDetached({ body: method.body, parameters: method.parameters }, `${name}.${method.name?.text ?? '<computed>'}`);
          else if (this.hasRegisteredSink(method, moduleScope)) this.gap('unreached-sink-function', `method of never-referenced class '${name}'`, method, method.name?.text);
        }
      }
    }
    for (const [name, node] of this.functions) {
      if (!this.callSites.has(name) && !this.referenced.has(name) && this.hasRegisteredSink(node, moduleScope)) {
        this.gap('unreached-sink-function', 'function is never called or referenced', node, name);
      }
    }
  }

  finish(truncated) {
    for (const entry of this.gaps) this.facts.push(entry);
    if (this.opaqueCalls.size > 0) {
      const sample = [...this.opaqueCalls].sort().slice(0, 8);
      this.facts.push({ t: 'gap', kind: 'opaque-calls', detail: `unmodeled calls (possible under-report): ${sample.join(', ')}${this.opaqueCalls.size > 8 ? ' …' : ''}` });
    }
    const seen = new Set();
    const unique = [];
    for (const fact of this.facts) {
      const key = JSON.stringify(fact);
      if (seen.has(key)) continue;
      seen.add(key);
      unique.push(fact);
    }
    return { facts: unique, truncated };
  }
}

function getParameterNames(ts, node) {
  const names = [];
  let rest = null;
  for (const parameter of node.parameters ?? []) {
    if (parameter.dotDotDotToken) {
      if (ts.isIdentifier(parameter.name)) rest = parameter.name.text;
      continue;
    }
    names.push(ts.isIdentifier(parameter.name) ? parameter.name.text : null);
  }
  return { names, rest };
}

function collectCallsAndReferences(ts, node, callSites, referenced, skip) {
  const visit = (current) => {
    if (ts.isCallExpression(current) || ts.isNewExpression(current)) {
      if (ts.isIdentifier(current.expression)) {
        const list = callSites.get(current.expression.text) ?? [];
        list.push(current);
        callSites.set(current.expression.text, list);
        visitArguments(ts, current.arguments, callSites, referenced);
        return;
      }
    } else if (ts.isIdentifier(current) && !ts.isPropertyName(current) && current !== skip) {
      const parentIsCallTarget = current.parent && (ts.isCallExpression(current.parent) || ts.isNewExpression(current.parent)) && current.parent.expression === current;
      if (!parentIsCallTarget && !isBindingContext(ts, current)) referenced.add(current.text);
    }
    ts.forEachChild(current, visit);
  };
  visit(node);
}

function visitArguments(ts, args, callSites, referenced) {
  for (const arg of args ?? []) collectCallsAndReferences(ts, arg, callSites, referenced, null);
}

function isBindingContext(ts, identifier) {
  const parent = identifier.parent;
  if (!parent) return true;
  if (ts.isVariableDeclaration(parent) && parent.name === identifier) return true;
  if (ts.isParameter(parent) && parent.name === identifier) return true;
  if ((ts.isFunctionDeclaration(parent) || ts.isClassDeclaration(parent) || ts.isMethodDeclaration(parent)) && parent.name === identifier) return true;
  if (ts.isPropertyAccessExpression(parent) && parent.name === identifier) return true;
  if (ts.isPropertyAssignment(parent) && parent.name === identifier) return true;
  if (ts.isImportSpecifier(parent) && (parent.name === identifier || parent.propertyName === identifier)) return true;
  if (ts.isImportClause(parent) && parent.name === identifier) return true;
  if (ts.isNamespaceImport(parent) && parent.name === identifier) return true;
  if (ts.isBindingElement(parent) && (parent.name === identifier || parent.propertyName === identifier)) return true;
  return false;
}

export function createJsProvider(options = {}) {
  let ts = options.typescript ?? null;
  let disposed = false;
  function loadTs() {
    if (ts) return ts;
    try {
      ts = createRequire(import.meta.url)('typescript');
    } catch (error) {
      const missing = new Error('typescript dependency is not installed');
      missing.unavailable = true;
      throw missing;
    }
    return ts;
  }

  return {
    /** Parse one inline JS/TS unit into fact objects. Throws on provider failure. */
    analyze(source, { language, cwd, platform, limits, signal }) {
      if (disposed) throw new Error('provider disposed');
      const compiler = loadTs();
      const scriptKind = language === 'typescript' ? compiler.ScriptKind.TS : compiler.ScriptKind.JS;
      const sourceFile = compiler.createSourceFile(language === 'typescript' ? 'unit.ts' : 'unit.js', source, compiler.ScriptTarget.Latest, /* setParentNodes */ true, scriptKind);
      const analyzer = new Analyzer(compiler, sourceFile, cwd ?? null, platform ?? null, limits.maxSteps, 4096, { signal, deadline: limits.deadline });
      let truncated = null;
      try {
        analyzer.run(sourceFile);
      } catch (signal2) {
        if (signal2 === 'steps' || signal2 === 'facts') truncated = signal2;
        else throw signal2; // 'cancelled' | 'timeout' | real error: never a result
      }
      return { ...analyzer.finish(truncated), parseDiagnostics: sourceFile.parseDiagnostics.length > 0, stepsUsed: analyzer.steps };
    },
    dispose() { disposed = true; ts = null; },
  };
}
