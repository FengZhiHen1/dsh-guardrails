# python-ast-helper — stdlib-ast fact extractor for dsh-guardrails program analysis.
#
# Protocol (one request per process):
#   stdin : single JSON object {"source": str, "cwd": str|null, "platform": str,
#                              "limits": {"maxNodes": int, "maxFacts": int}}
#   stdout: single JSON line {"ok": true, "facts": [...], "truncated": str|null}
#           or {"ok": false, "error": "syntax"|"limit"|"internal", "message": str, "line": int?}
#
# Security boundary: the source under review is DATA. This helper only runs
# `ast.parse` and walks the resulting tree; it never imports, compiles or
# executes the source, never reads or writes the file system, and never
# evaluates arbitrary expressions. The bounded target evaluation only performs
# pure string/label arithmetic on literal values (documented in
# docs/technical-details/跨语言删除分析.md「有界目标求值」). Diagnostics never
# echo source text: messages carry node types and line numbers only.
#
# Analysis subset (docs/technical-details/跨语言删除分析.md「删除 sink 识别」):
# - sinks: os.remove/unlink/rmdir/removedirs, shutil.rmtree, os.rename/replace/
#   renames, shutil.move, pathlib Path.unlink/rmdir
# - execution: os.system/popen, subprocess.run/call/check_call/check_output/
#   Popen (static argv -> argv fact, static text -> shell fact, dynamic -> candidate)
# - content access: builtins.open / io.open and pathlib Path.open / read_text /
#   read_bytes / write_text / write_bytes emit 'read-content' / 'write-content'
#   with the literal path and mode; unknown mode or target gets a bounded gap
#   ('content-mode-unknown' / 'content-target-unknown') and no action claim
# - read-only enumeration feeding a sink (os.listdir/scandir/walk, glob.glob,
#   Path.iterdir/glob) -> candidate with the verified base as known scope
# - aliases: plain `import`, `import as`, `from ... import [as]`, module-level
#   and single-assignment local constants, small local cleanup functions
#   (single call-site parameter binding), star imports for registry-known names
# - reachability: module top level plus functions that are called or referenced
#   anywhere; unreached functions are skipped and reported as a gap when their
#   body contains a registered sink/exec call
# - eval/exec/compile are reported as dynamic execution candidates

import ast
import json
import sys

WILDCARD_HINT = (
    "from %s import *: only registry-known sink names resolve; "
    "other names stay unanalyzed"
)


class Unk(Exception):
    """A value that bounded evaluation cannot resolve, with optional verified base."""

    def __init__(self, reason, base=None):
        super().__init__(reason)
        self.reason = reason
        self.base = base


class Budget(Exception):
    def __init__(self, what):
        super().__init__(what)
        self.what = what


# dotted-module registry: function name -> (recursive, note)
DELETE_SINKS = {
    ("os", "remove"): (False, None),
    ("os", "unlink"): (False, None),
    ("os", "rmdir"): (False, None),
    ("os", "removedirs"): (False, "removedirs also removes now-empty parent directories"),
    ("shutil", "rmtree"): (True, None),
}
MOVE_SINKS = {("os", "rename"), ("os", "replace"), ("os", "renames"), ("shutil", "move")}
ENUM_SINKS = {
    ("os", "listdir"), ("os", "scandir"), ("glob", "glob"), ("glob", "iglob"), ("os", "walk"),
}
SHELL_SINKS = {("os", "system"), ("os", "popen"), ("subprocess", "getoutput"), ("subprocess", "getstatusoutput")}
SUBPROC_SINKS = {
    ("subprocess", "run"), ("subprocess", "call"), ("subprocess", "check_call"),
    ("subprocess", "check_output"), ("subprocess", "Popen"),
}
DYN_EXEC_SINKS = {"eval", "exec", "compile"}
# Wildcard-import resolution: bare name -> dotted sink name.
WILDCARD_NAMES = {
    "remove": "os.remove", "unlink": "os.unlink", "rmdir": "os.rmdir",
    "removedirs": "os.removedirs", "rmtree": "shutil.rmtree", "move": "shutil.move",
    "rename": "os.rename", "replace": "os.replace", "listdir": "os.listdir",
    "scandir": "os.scandir", "walk": "os.walk", "system": "os.system",
    "popen": "os.popen", "run": "subprocess.run", "call": "subprocess.call",
    "glob": "glob.glob", "Path": "pathlib.Path",
}
PATH_FUNC_NAMES = {
    "os.path.join", "os.path.abspath", "os.path.realpath",
    "os.path.normpath", "os.path.dirname", "os.path.basename",
    "pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath",
}

# Bare language runtimes: a static argv spawn of one of these names (unqualified,
# no path, no drive) names a program unit that the entry recognizer must handle,
# so the helper reports a 'child-script' fact instead of a plain command.
BARE_RUNTIMES = {"python", "python3", "pythonw", "py", "node", "nodejs", "tsx", "ts-node", "deno", "bun"}
RUNTIME_RUN_WRAPPERS = {"uv", "npm", "pnpm", "yarn"}

# pathlib content methods (receiver-verified only; see handle_path_method).
CONTENT_METHODS = ("open", "read_text", "read_bytes", "write_text", "write_bytes")


def classify_open_mode(mode_text):
    """'read' | 'write' | None. Default and explicit 'r' (incl. 'rb'/'rt') read;
    any of w/a/x/+ writes (append, exclusive-create, update). Unknown or invalid
    characters ('U', 'z', …) stay unknown and get bounded diagnostics."""
    if not isinstance(mode_text, str) or not mode_text:
        return None
    chars = set(mode_text)
    if not chars <= set("rwxab+tBb"):
        return None
    if chars & set("wax+"):
        return "write"
    if "r" in chars:
        return "read"
    return None


def is_runtime_spawn(executable, args):
    if not isinstance(executable, str) or not executable:
        return False
    if "/" in executable or "\\" in executable or ":" in executable:
        return False
    base = executable.lower()
    if base.endswith(".exe"):
        base = base[:-4]
    if base in RUNTIME_RUN_WRAPPERS:
        return bool(args) and args[0] in ("run", "exec")
    return base in BARE_RUNTIMES


def join_path(base, name, sep):
    if base.endswith("/") or base.endswith("\\"):
        return base + name
    return base + sep + name


def norm_path(value, sep):
    # Textual normpath on literal path text (no file system access). Collapses
    # duplicate separators and resolves '.'/'..' lexically, like os.path.normpath.
    prefix = ""
    work = value.replace("\\", "/")
    if work.startswith("//"):
        prefix, work = "//", work[2:]
    elif work.startswith("/"):
        prefix, work = "/", work[1:]
    else:
        drive = work[:2]
        if len(drive) == 2 and drive[1] == ":" and drive[0].isalpha():
            prefix, work = drive + "/", work[2:]
    out = []
    for part in work.split("/"):
        if part in ("", "."):
            continue
        if part == ".." and out and out[-1] != "..":
            out.pop()
        elif part == "..":
            if prefix:
                continue  # '..' past an absolute root stays at the root
            out.append(part)
        else:
            out.append(part)
    if sep == "\\":
        return prefix.replace("/", "\\") + "\\".join(out) if out else (prefix or ".")
    return prefix + "/".join(out) if out else (prefix or ".")


class Env:
    __slots__ = ("vars", "parent")

    def __init__(self, parent=None):
        self.vars = {}
        self.parent = parent

    def get(self, name):
        env = self
        while env is not None:
            if name in env.vars:
                return env.vars[name]
            env = env.parent
        return None


class Analyzer:
    def __init__(self, tree, cwd, platform, max_nodes, max_facts):
        self.tree = tree
        self.cwd = cwd
        self.sep = "\\" if platform == "win32" else "/"
        self.platform = platform
        self.max_nodes = max_nodes
        self.max_facts = max_facts
        self.nodes = 0
        self.facts = []
        self.opaque_calls = set()
        self.gaps = []
        self.functions = {}      # name -> FunctionDef at module level
        self.classes = {}
        self.call_sites = {}     # function name -> [Call nodes, ...]
        self.referenced = set()  # function/class names used as values anywhere
        self.wildcards = {}      # bare name -> dotted sink name via star imports
        self.active_stack = []   # recursion guard for inlined function bodies
        self.inlined = set()     # functions already inlined from a reachable call site

    # ---------------- budget / facts ----------------

    def tick(self):
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise Budget("steps")

    def add(self, fact):
        if len(self.facts) >= self.max_facts:
            raise Budget("facts")
        self.facts.append(fact)

    def gap(self, kind, detail=None, line=None, function=None):
        entry = {"t": "gap", "kind": kind}
        if detail is not None:
            entry["detail"] = str(detail)
        if line is not None:
            entry["line"] = line
        if function is not None:
            entry["function"] = function
        self.gaps.append(entry)

    # ---------------- name resolution ----------------

    def dotted(self, node, env):
        """Resolve a Name/Attribute chain to a dotted module path, or None."""
        self.tick()
        if isinstance(node, ast.Name):
            binding = env.get(node.id)
            if binding is None:
                if node.id in ("tools", "ctx"):
                    return node.id  # PTC SDK roots: skipped, judged by their own guard
                return self.wildcards.get(node.id)
            kind = binding[0]
            if kind == "module":
                return binding[1]
            if kind == "member":
                return binding[1] + "." + binding[2]
            return None
        if isinstance(node, ast.Attribute):
            base = self.dotted(node.value, env)
            if base:
                return base + "." + node.attr
            return None
        return None

    # ---------------- bounded target evaluation ----------------

    def eval_str(self, node, env):
        """Evaluate an expression to a literal path/string or raise Unk."""
        self.tick()
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(value.value if isinstance(value.value, str) else str(value.value))
                elif isinstance(value, ast.FormattedValue):
                    if value.format_spec is not None or value.conversion not in (-1, 115):
                        raise Unk("f-string with format spec or conversion")
                    parts.append(self.eval_str(value.value, env))
                else:
                    raise Unk("f-string part not evaluable")
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.eval_str(node.left, env) + self.eval_str(node.right, env)
        if isinstance(node, ast.Name):
            binding = env.get(node.id)
            if binding is None:
                raise Unk("name '%s' is not a locally verified constant" % node.id)
            kind = binding[0]
            if kind in ("const", "path"):
                return binding[1]
            if kind == "enum":
                raise Unk("value comes from directory enumeration", base=binding[1])
            raise Unk("name '%s' is %s" % (node.id, kind))
        if isinstance(node, ast.Call):
            return self.eval_call_str(node, env)
        if isinstance(node, ast.Attribute):
            return self.eval_path_attr(node, env)
        raise Unk("expression %s not evaluated" % type(node).__name__)

    def eval_call_str(self, node, env):
        dotted = self.dotted(node.func, env)
        args = node.args
        if dotted in PATH_FUNC_NAMES:
            if dotted in ("pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath"):
                return self.eval_path_construct(args, env)
            if dotted == "os.path.join":
                parts = [self.eval_str(a, env) for a in args]
                if not parts:
                    raise Unk("join with no parts")
                base = parts[0]
                for part in parts[1:]:
                    if part.startswith("/") or part.startswith("\\") or (len(part) > 1 and part[1] == ":"):
                        base = part  # an absolute part resets, like os.path.join
                    else:
                        base = join_path(base, part, self.sep)
                return base
            value = self.eval_str(args[0], env)
            if dotted in ("os.path.abspath", "os.path.realpath"):
                if value.startswith("/") or value.startswith("\\") or (len(value) > 1 and value[1] == ":"):
                    return norm_path(value, self.sep)
                if self.cwd:
                    return norm_path(join_path(self.cwd, value, self.sep), self.sep)
                raise Unk("relative path without a verified cwd")
            if dotted == "os.path.normpath":
                return norm_path(value, self.sep)
            if dotted == "os.path.dirname":
                work = value.rstrip("/\\")
                cut = max(work.rfind("/"), work.rfind("\\"))
                return work[:cut] if cut > 0 else (work[:1] if cut == 0 else ".")
            if dotted == "os.path.basename":
                work = value.rstrip("/\\")
                cut = max(work.rfind("/"), work.rfind("\\"))
                return work[cut + 1:] if cut >= 0 else work
        if dotted is None and isinstance(node.func, ast.Name) and node.func.id == "str" and len(args) == 1:
            return self.eval_str(args[0], env)
        raise Unk("call %s not evaluated" % (dotted or "opaque"))

    def eval_path_construct(self, args, env):
        if not args:
            raise Unk("Path with no parts")
        base = self.eval_str(args[0], env)
        for part in args[1:]:
            if part.startswith("/") or part.startswith("\\") or (len(part) > 1 and part[1] == ":"):
                base = part
            else:
                base = join_path(base, part, self.sep)
        return base

    def eval_path_attr(self, node, env):
        # Attribute on a Path binding: .parent / .name / .stem / .suffix
        binding = None
        if isinstance(node.value, ast.Name):
            binding = env.get(node.value.id)
        if binding is None or binding[0] != "path":
            raise Unk("attribute target not a verified Path value")
        value = binding[1]
        if node.attr == "parent":
            work = value.rstrip("/\\")
            cut = max(work.rfind("/"), work.rfind("\\"))
            return work[:cut] if cut > 0 else (work[:1] if cut == 0 else ".")
        if node.attr == "name":
            work = value.rstrip("/\\")
            cut = max(work.rfind("/"), work.rfind("\\"))
            return work[cut + 1:] if cut >= 0 else work
        if node.attr in ("stem", "suffix"):
            work = value.rstrip("/\\")
            cut = max(work.rfind("/"), work.rfind("\\"))
            base = work[cut + 1:] if cut >= 0 else work
            dot = base.rfind(".")
            if node.attr == "stem":
                return base[:dot] if dot > 0 else base
            return base[dot:] if dot > 0 else ""
        raise Unk("Path attribute '%s' not evaluated" % node.attr)

    # ---------------- imports / bindings ----------------

    def bind_import(self, node, env):
        self.tick()
        for alias in node.names:
            name = alias.name
            bound = alias.asname or name.split(".")[0]
            if alias.asname:
                env.vars[bound] = ("module", name)
            elif "." in name:
                # `import os.path` binds the top package name.
                env.vars[bound] = ("module", bound)
            else:
                env.vars[bound] = ("module", name)

    def bind_import_from(self, node, env, line):
        self.tick()
        module = node.module or ""
        for alias in node.names:
            if alias.name == "*":
                self.gap("star-import", WILDCARD_HINT % (module or "relative module"), line=line)
                for bare, dotted in WILDCARD_NAMES.items():
                    if dotted.startswith(module + ".") or (module == "os" and dotted.startswith("os.")):
                        self.wildcards[bare] = dotted
                continue
            bound = alias.asname or alias.name
            env.vars[bound] = ("member", module, alias.name)

    # ---------------- statement walk ----------------

    def walk_body(self, stmts, env, depth, function=None):
        for stmt in stmts:
            self.walk_stmt(stmt, env, depth, function)

    def walk_stmt(self, stmt, env, depth, function=None):
        self.tick()
        line = getattr(stmt, "lineno", None)
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return  # bodies analyzed on reachability
        if isinstance(stmt, ast.ClassDef):
            return  # handled in reachability phase
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            if isinstance(stmt, ast.Import):
                self.bind_import(stmt, env)
            else:
                self.bind_import_from(stmt, env, line)
            return
        if isinstance(stmt, ast.Assign):
            self.bind_assign(stmt.targets, stmt.value, env, line)
            self.walk_expr_value(stmt.value, env, depth, function)
            return
        if isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
            if isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                self.bind_assign([stmt.target], stmt.value, env, line)
                self.walk_expr_value(stmt.value, env, depth, function)
            else:
                self.walk_expr_value(getattr(stmt, "value", None) or stmt.target, env, depth, function)
            return
        if isinstance(stmt, ast.Expr):
            self.walk_expr_value(stmt.value, env, depth, function)
            return
        if isinstance(stmt, (ast.If, ast.While)):
            self.walk_expr_value(stmt.test, env, depth, function)
            self.walk_body(stmt.body, env, depth + 1, function)
            for clause in stmt.orelse:
                self.walk_stmt(clause, env, depth + 1, function)
            return
        if isinstance(stmt, ast.For):
            self.bind_for_target(stmt, env, line)
            self.walk_expr_value(stmt.iter, env, depth, function)
            self.walk_body(stmt.body, env, depth + 1, function)
            for clause in stmt.orelse:
                self.walk_stmt(clause, env, depth + 1, function)
            return
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                self.walk_expr_value(item.context_expr, env, depth, function)
                if item.optional_vars is not None and isinstance(item.optional_vars, ast.Name):
                    env.vars[item.optional_vars.id] = ("unknown", "with-target")
            self.walk_body(stmt.body, env, depth + 1, function)
            return
        if isinstance(stmt, ast.Try):
            self.walk_body(stmt.body, env, depth + 1, function)
            for handler in stmt.handlers:
                self.walk_body(handler.body, env, depth + 1, function)
            for clause in stmt.orelse + stmt.finalbody:
                self.walk_stmt(clause, env, depth + 1, function)
            return
        if hasattr(ast, "Match") and isinstance(stmt, ast.Match):
            self.walk_expr_value(stmt.subject, env, depth, function)
            for case in stmt.cases:
                self.walk_body(case.body, env, depth + 1, function)
            return
        if isinstance(stmt, (ast.Return, ast.Delete, ast.Assert)):
            value = getattr(stmt, "value", None)
            if value is not None:
                self.walk_expr_value(value, env, depth, function)
            return
        if isinstance(stmt, (ast.Raise, ast.Pass, ast.Break, ast.Continue, ast.Global, ast.Nonlocal)):
            return
        # Anything else: walk any expression children conservatively.
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.expr):
                self.walk_expr_value(child, env, depth, function)

    def bind_assign(self, targets, value, env, line):
        self.tick()
        if not isinstance(value, (ast.Constant, ast.JoinedStr, ast.BinOp, ast.Call, ast.Name, ast.Attribute)):
            return
        try:
            evaluated = self.eval_str(value, env)
        except Unk as exc:
            for target in targets:
                if isinstance(target, ast.Name):
                    env.vars[target.id] = ("unknown", exc.reason)
            return
        except Budget:
            raise
        except RecursionError:
            raise Unk("evaluation recursion limit")
        for target in targets:
            if isinstance(target, ast.Name):
                env.vars[target.id] = ("path", evaluated)

    def bind_for_target(self, stmt, env, line):
        self.tick()
        iter_node = stmt.iter
        base = None
        pattern = None
        if isinstance(iter_node, ast.Call):
            dotted = self.dotted(iter_node.func, env)
            module, _, func = dotted.rpartition(".") if dotted else (None, None, None)
            key = (module, func) if dotted else None
            if key in ENUM_SINKS:
                try:
                    first = self.eval_str(iter_node.args[0], env) if iter_node.args else None
                except Unk as exc:
                    first, base = None, exc.base
                if key == ("os", "walk"):
                    base = first
                elif key in (("glob", "glob"), ("glob", "iglob")):
                    pattern = first
                    base = split_glob_base(first) if first else base
                else:
                    base = first
            elif isinstance(iter_node.func, ast.Attribute):
                recv = self.try_path_value(iter_node.func.value, env)
                if recv is not None and iter_node.func.attr in ("iterdir", "glob", "rglob"):
                    if iter_node.func.attr == "iterdir":
                        base = recv
                    else:
                        try:
                            pattern = self.eval_str(iter_node.args[0], env) if iter_node.args else None
                        except Unk as exc:
                            pattern, base = None, exc.base or recv
                        base = split_glob_base(pattern) if pattern else recv
        if base is None:
            return
        names = []
        if isinstance(stmt.target, ast.Name):
            names = [stmt.target.id]
        elif isinstance(stmt.target, (ast.Tuple, ast.List)):
            names = [e.id for e in stmt.target.elts if isinstance(e, ast.Name)]
        for name in names:
            env.vars[name] = ("enum", base)

    def try_path_value(self, node, env):
        try:
            value = self.eval_str(node, env)
            return value
        except Unk as exc:
            return exc.base
        except Budget:
            raise

    # ---------------- content access (read/write file bodies) ----------------

    def open_mode_text(self, node, first_index=1):
        """Returns (mode_text, proven). Absent mode means the default 'r'; a
        present-but-non-literal mode is NOT proven and yields bounded diagnostics.
        `first_index` is 1 for function calls (path, mode) and 0 for method calls
        (self is implicit, so the mode is the first argument)."""
        args = node.args
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        mode_node = args[first_index] if len(args) > first_index else kw.get("mode")
        if mode_node is None:
            return "r", True
        if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
            return mode_node.value, True
        return None, False

    def report_content_open(self, node, env, cond, line, function):
        args = node.args
        if not args:
            self.gap("content-target-unknown", "open() without a positional target", line=line, function=function)
            return
        try:
            target = self.eval_str(args[0], env)
        except Unk as exc:
            self.gap("content-target-unknown", "target is not statically evaluable (%s)" % exc.reason, line=line, function=function)
            return
        mode_text, proven = self.open_mode_text(node)
        if not proven:
            self.gap("content-mode-unknown", "mode is not a proven literal", line=line, function=function)
            return
        cls = classify_open_mode(mode_text)
        if cls is None:
            self.gap("content-mode-unknown", "mode '%s' is not a recognized file mode" % mode_text, line=line, function=function)
            return
        self.add({"t": "operation", "action": "read-content" if cls == "read" else "write-content",
                  "target": {"kind": "exact", "paths": [target]},
                  "recursive": False, "condition": cond, "line": line, "function": function,
                  "details": "mode: %s" % mode_text})

    # ---------------- expression facts ----------------

    def walk_expr_value(self, node, env, depth, function):
        if node is None:
            return
        self.tick()
        if isinstance(node, ast.Call):
            self.handle_call(node, env, depth, function)
            return
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.expr, ast.comprehension)):
                if isinstance(child, ast.comprehension):
                    self.walk_expr_value(child.iter, env, depth, function)
                    for cond in child.ifs:
                        self.walk_expr_value(cond, env, depth, function)
                else:
                    self.walk_expr_value(child, env, depth, function)

    def handle_call(self, node, env, depth, function):
        self.tick()
        line = getattr(node, "lineno", None)
        cond = CONDITION[depth > 0]
        dotted = self.dotted(node.func, env)
        args = node.args
        keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}

        if dotted is None and isinstance(node.func, ast.Name):
            name = node.func.id
            if name in DYN_EXEC_SINKS:
                self.add({"t": "candidate", "kind": "dynamic-execution",
                          "reason": "%s() executes dynamically constructed code" % name,
                          "condition": cond, "line": line, "function": function})
                return
            if name == "open":
                self.report_content_open(node, env, cond, line, function)
                return
            binding = env.get(name)
            if binding is not None and binding[0] == "func":
                self.inline_function(binding[1], node, env, depth, function)
                return
            if self.wildcards.get(name):
                dotted = self.wildcards[name]

        if dotted is None and isinstance(node.func, ast.Attribute):
            if self.handle_path_method(node, env, depth, cond, line, function):
                return

        if dotted is None:
            # Opaque third-party call: allowed with declared possible under-report
            # (docs/technical-details/跨语言删除分析.md「失败语义」).
            if isinstance(node.func, ast.Name):
                self.opaque_calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                self.opaque_calls.add(node.func.attr)
            for arg in args:
                self.walk_expr_value(arg, env, depth, function)
            return

        module, _, func = dotted.rpartition(".")
        key = (module, func)

        if key in DELETE_SINKS or key in MOVE_SINKS:
            self.report_delete_or_move(node, key, args, keywords, env, depth, cond, line, function)
            return

        if key in (("io", "open"), ("builtins", "open")):
            self.report_content_open(node, env, cond, line, function)
            return

        if key in SHELL_SINKS:
            try:
                text = self.eval_str(args[0], env)
                self.add({"t": "shell", "text": text, "condition": cond, "line": line, "function": function})
            except Unk:
                self.add({"t": "candidate", "kind": "dynamic-execution",
                          "reason": "%s.%s command is not statically known" % (module, func),
                          "condition": cond, "line": line, "function": function})
            return

        if key in SUBPROC_SINKS:
            self.report_subprocess(args, keywords, env, depth, cond, line, function)
            return

        if key in ENUM_SINKS:
            # Standalone enumeration is read-only; only feeds for-loops (bind_for_target).
            return

        # tools.<name> SDK sub-calls go through their own guard at dispatch time
        # (docs/technical-details/跨语言删除分析.md「删除 sink 识别」); do not judge them here.
        if module == "tools" or module.startswith("ctx.tools") or dotted.startswith("tools.") or dotted.startswith("ctx."):
            return

        for arg in args:
            self.walk_expr_value(arg, env, depth, function)
        for value in keywords.values():
            self.walk_expr_value(value, env, depth, function)

    def report_delete_or_move(self, node, key, args, keywords, env, depth, cond, line, function):
        module, func = key
        if not args:
            self.add({"t": "candidate", "kind": "dynamic-target",
                      "reason": "%s.%s without a positional target" % (module, func),
                      "condition": cond, "line": line, "function": function})
            return
        try:
            target_value = self.eval_str(args[0], env)
        except Unk as exc:
            known = [exc.base] if exc.base else None
            if known is None:
                receiver = self.try_path_value(args[0], env)
                known = [receiver] if receiver else None
            fact = {"t": "candidate", "kind": "dynamic-target",
                    "reason": "%s.%s target is not statically evaluable (%s)" % (module, func, exc.reason),
                    "condition": cond, "line": line, "function": function}
            if known:
                fact["knownScope"] = known
            self.add(fact)
            return
        if key in DELETE_SINKS:
            recursive, note = DELETE_SINKS[key]
            fact = {"t": "operation", "action": "delete",
                    "target": {"kind": "exact", "paths": [target_value]},
                    "recursive": recursive, "condition": cond, "line": line, "function": function}
            if note:
                fact["details"] = note
            self.add(fact)
        else:
            destination = None
            if len(args) > 1:
                try:
                    destination = self.eval_str(args[1], env)
                except Unk:
                    destination = None
            fact = {"t": "operation", "action": "move-source",
                    "target": {"kind": "exact", "paths": [target_value]},
                    "recursive": False, "condition": cond, "line": line, "function": function}
            if destination:
                fact["details"] = "destination: %s" % destination
            self.add(fact)

    def report_subprocess(self, args, keywords, env, depth, cond, line, function):
        shell_kw = keywords.get("shell")
        shell = isinstance(shell_kw, ast.Constant) and shell_kw.value is True
        if not args:
            self.add({"t": "candidate", "kind": "dynamic-execution",
                      "reason": "subprocess call without a static payload",
                      "condition": cond, "line": line, "function": function})
            return
        first = args[0]
        if isinstance(first, (ast.List, ast.Tuple)):
            elements = []
            all_static = True
            for element in first.elts:
                if isinstance(element, ast.Starred):
                    all_static = False
                    break
                try:
                    elements.append(self.eval_str(element, env))
                except Unk:
                    elements.append(None)
                    all_static = False
            executable = elements[0] if elements else None
            if shell and executable:
                self.add({"t": "shell", "text": executable, "condition": cond,
                          "line": line, "function": function})
                return
            if not all_static and executable is None:
                self.add({"t": "candidate", "kind": "dynamic-execution",
                          "reason": "subprocess argv is not static",
                          "condition": cond, "line": line, "function": function})
                return
            if executable and is_runtime_spawn(executable, elements[1:]):
                # Language-runtime spawn: the entry recognizer owns the script.
                self.add({"t": "child-script", "executable": executable,
                          "args": elements[1:], "condition": cond, "line": line, "function": function})
            else:
                self.add({"t": "command", "executable": executable,
                          "args": elements[1:], "condition": cond, "line": line, "function": function})
            return
        try:
            text = self.eval_str(first, env)
        except Unk as exc:
            fact = {"t": "candidate", "kind": "dynamic-execution",
                    "reason": "subprocess payload is not statically known (%s)" % exc.reason,
                    "condition": cond, "line": line, "function": function}
            if exc.base:
                fact["knownScope"] = [exc.base]
            self.add(fact)
            return
        if shell or isinstance(first, ast.Constant):
            # A plain string payload always runs through the platform shell.
            self.add({"t": "shell", "text": text, "condition": cond, "line": line, "function": function})
        else:
            self.add({"t": "shell", "text": text, "condition": cond, "line": line, "function": function})

    # ---------------- pathlib method sinks ----------------

    def handle_path_method(self, node, env, depth, cond, line, function):
        # Only reached when dotted() is None but the receiver may be a Path value.
        attr = node.func.attr
        recv = self.try_path_value(node.func.value, env)
        if attr in CONTENT_METHODS:
            if recv is None:
                self.gap("content-target-unknown",
                         "content method on a receiver that is not a verified Path value",
                         line=line, function=function)
                return True
            if attr == "open":
                mode_text, proven = self.open_mode_text(node, first_index=0)
                cls = classify_open_mode(mode_text) if proven else None
                if not proven or cls is None:
                    self.gap("content-mode-unknown", "open() mode is not a proven literal", line=line, function=function)
                    return True
            else:
                cls = "read" if attr.startswith("read") else "write"
                mode_text = "r" if cls == "read" else "w"
            self.add({"t": "operation", "action": "read-content" if cls == "read" else "write-content",
                      "target": {"kind": "exact", "paths": [recv]},
                      "recursive": False, "condition": cond, "line": line, "function": function,
                      "details": "mode: %s (%s)" % (mode_text, attr)})
            return True
        if recv is None:
            return False
        if attr in ("unlink", "rmdir"):
            self.add({"t": "operation", "action": "delete",
                      "target": {"kind": "exact", "paths": [recv]},
                      "recursive": False, "condition": cond, "line": line, "function": function})
            return True
        if attr in ("iterdir", "glob", "rglob"):
            return True  # read-only enumeration; facts come via for-target binding
        return False

    # ---------------- local function inlining ----------------

    def inline_function(self, func_node, call_node, env, depth, function):
        self.tick()
        name = getattr(func_node, "name", "<anonymous>")
        if name in self.active_stack:
            return  # recursion: bound once per path
        self.inlined.add(name)
        if len(self.active_stack) >= 4:
            self.gap("call-depth-exceeded", "local function inlining stopped at depth limit", function=name)
            return
        local = Env(env)
        params = [a.arg for a in func_node.args.args]
        positional = func_node.args.posonlyargs + func_node.args.args
        param_names = [a.arg for a in positional]
        bound_any = False
        for index, param in enumerate(param_names):
            if index < len(call_node.args):
                try:
                    value = self.eval_str(call_node.args[index], env)
                    local.vars[param] = ("path", value)
                    bound_any = True
                except Unk:
                    local.vars[param] = ("unknown", "argument not evaluable")
            elif param in {kw.arg for kw in call_node.keywords if kw.arg}:
                for kw in call_node.keywords:
                    if kw.arg == param:
                        try:
                            local.vars[param] = ("path", self.eval_str(kw.value, env))
                            bound_any = True
                        except Unk:
                            local.vars[param] = ("unknown", "keyword argument not evaluable")
            else:
                local.vars[param] = ("unknown", "no call-site argument")
        for a in list(func_node.args.kwonlyargs) + list(func_node.args.posonlyargs):
            if a.arg not in local.vars:
                local.vars[a.arg] = ("unknown", "not bound")
        if func_node.args.vararg or func_node.args.kwarg:
            for a in (func_node.args.vararg, func_node.args.kwarg):
                local.vars[a.arg] = ("unknown", "star argument")
        self.active_stack.append(name)
        try:
            self.walk_body(func_node.body, local, depth, name)
        finally:
            self.active_stack.pop()

    # ---------------- reachability ----------------

    def collect_symbols(self):
        for stmt in self.tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[stmt.name] = stmt
            elif isinstance(stmt, ast.ClassDef):
                self.classes[stmt.name] = stmt
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.call_sites.setdefault(node.func.id, []).append(node)
            elif isinstance(node, ast.Name) and not isinstance(node.ctx, (ast.Store, ast.Del)):
                self.referenced.add(node.id)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.decorator_list:
                self.referenced.add(node.name)

    def function_has_registered_sink(self, func_node):
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and (node.func.id in DYN_EXEC_SINKS or self.wildcards.get(node.func.id)):
                    return True
                dotted = None
                try:
                    dotted = self.dotted(node.func, getattr(self, "module_env", None) or Env())
                except Budget:
                    return True
                if dotted:
                    module, _, func = dotted.rpartition(".")
                    if (module, func) in set(DELETE_SINKS) | MOVE_SINKS | SHELL_SINKS | SUBPROC_SINKS | ENUM_SINKS:
                        return True
        return False

    def analyze_reachable(self):
        # Module-level walk first: it also inlines functions called unconditionally.
        module_env = Env()
        self.module_env = module_env
        for name, func_node in self.functions.items():
            module_env.vars[name] = ("func", func_node)
        self.walk_body(self.tree.body, module_env, 0)
        # Functions referenced but never inline-analyzed (callbacks, decorators):
        # analyze once with unknown condition so their sinks are not silent.
        for name, func_node in self.functions.items():
            if (name in self.referenced or name in self.call_sites) and name not in self.inlined:
                self.analyze_detached(func_node)

    def analyze_detached(self, func_node):
        # A function reachable only by reference: sinks run under an unknown
        # condition with unbound parameters.
        name = getattr(func_node, "name", "<anonymous>")
        if name in self.active_stack:
            return
        local = Env(getattr(self, "module_env", None))
        for a in func_node.args.args + func_node.args.kwonlyargs + func_node.args.posonlyargs:
            local.vars[a.arg] = ("unknown", "parameter not bound")
        if func_node.args.vararg or func_node.args.kwarg:
            for a in (func_node.args.vararg, func_node.args.kwarg):
                local.vars[a.arg] = ("unknown", "star argument")
        self.active_stack.append(name)
        try:
            self.walk_body(func_node.body, local, 1, name)
        finally:
            self.active_stack.pop()

    def analyze_classes(self):
        for name, class_node in self.classes.items():
            if name not in self.referenced:
                for stmt in class_node.body:
                    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and self.function_has_registered_sink(stmt):
                        self.gap("unreached-sink-function", "method of never-referenced class '%s'" % name,
                                 line=getattr(stmt, "lineno", None), function="%s.%s" % (name, stmt.name))
                continue
            for stmt in class_node.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.analyze_detached(stmt)

    def analyze_unreached(self):
        for name, func_node in self.functions.items():
            if name in self.referenced or name in self.call_sites:
                continue
            if self.function_has_registered_sink(func_node):
                self.gap("unreached-sink-function", "function is never called or referenced",
                         line=getattr(func_node, "lineno", None), function=name)

    def finish(self, truncated):
        for entry in self.gaps:
            self.facts.append(entry)
        if self.opaque_calls:
            sample = sorted(self.opaque_calls)[:8]
            detail = "unmodeled calls (possible under-report): %s%s" % (
                ", ".join(sample), " …" if len(self.opaque_calls) > 8 else "")
            self.facts.append({"t": "gap", "kind": "opaque-calls", "detail": detail})
        # Dedup identical facts emitted from multiple inlining paths.
        seen = set()
        unique = []
        for fact in self.facts:
            key = json.dumps(fact, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            unique.append(fact)
        return {"ok": True, "facts": unique, "truncated": truncated, "nodes": self.nodes}


CONDITION = {False: "certain", True: "possible"}


def split_glob_base(pattern):
    if not isinstance(pattern, str):
        return None
    for sep in ("*", "?", "["):
        cut = pattern.find(sep)
        if cut >= 0:
            pattern = pattern[:cut]
            break
    cut = max(pattern.rfind("/"), pattern.rfind("\\"))
    base = pattern[:cut] if cut > 0 else (pattern[:1] if cut == 0 else "")
    return base or None


def main():
    raw = sys.stdin.buffer.read()
    try:
        request = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        emit({"ok": False, "error": "internal", "message": "request decode failed (%s)" % type(exc).__name__})
        return 0
    source = request.get("source")
    if not isinstance(source, str):
        emit({"ok": False, "error": "internal", "message": "request source is not text"})
        return 0
    limits = request.get("limits") or {}
    max_nodes = int(limits.get("maxNodes", 200000))
    max_facts = int(limits.get("maxFacts", 4096))
    cwd = request.get("cwd")
    platform = request.get("platform") or ("win32" if sys.platform == "win32" else "posix")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        emit({"ok": False, "error": "syntax", "message": "SyntaxError: %s" % (exc.msg or "invalid syntax"),
              "line": exc.lineno})
        return 0
    except (ValueError, RecursionError, MemoryError) as exc:
        emit({"ok": False, "error": "internal", "message": "parse failed (%s)" % type(exc).__name__})
        return 0
    analyzer = Analyzer(tree, cwd, platform, max_nodes, max_facts)
    truncated = None
    try:
        analyzer.collect_symbols()
        analyzer.analyze_reachable()
        analyzer.analyze_classes()
        analyzer.analyze_unreached()
    except Budget as exc:
        truncated = exc.what
    except RecursionError:
        truncated = "recursion"
    except Exception as exc:  # noqa: BLE001 — one-shot helper; report class only
        emit({"ok": False, "error": "internal", "message": "analysis failed (%s)" % type(exc).__name__})
        return 0
    emit(analyzer.finish(truncated))
    return 0


def emit(payload):
    sys.stdout.write(json.dumps(payload, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    sys.exit(main())
