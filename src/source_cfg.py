"""C AST -> per-function control-flow graphs -> entry-to-function paths.

No uploaded code is executed. Unsupported syntax/configuration and unresolved
dispatch explicitly block negative decisions. Graphs describe uploaded C source,
not a whole deployed firmware image.
"""
from collections import deque
from pathlib import Path
import re

from pycparser import c_ast as A, c_parser

_LEXICAL = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|(?m:^[ \t]*#)', re.S)


def truth(node):
    if isinstance(node, A.Constant) and node.type in ("int", "char"):
        try:
            return int(re.sub(r"[uUlL]+$", "", node.value), 0) != 0
        except ValueError:
            return None
    if isinstance(node, A.UnaryOp) and node.op == "!":
        v = truth(node.expr)
        return None if v is None else not v
    return None


class Graph:
    def __init__(self):
        self.nodes, self.edges, self.blockers = [], [], []

    def node(self, ast, kind="statement"):
        calls = []
        graph = self
        class Calls(A.NodeVisitor):
            def visit_FuncCall(self, n):
                if isinstance(n.name, A.ID):
                    calls.append(n.name.name)
                else:
                    graph.blockers.append("indirect_call")
                self.generic_visit(n)
        if ast is not None:
            Calls().visit(ast)
        n = len(self.nodes)
        self.nodes.append({"id": n, "kind": kind, "line": getattr(getattr(ast, "coord", None), "line", None), "calls": sorted(set(calls))})
        return n

    def edge(self, source, target):
        if target is not None:
            self.edges.append([source, target])

    def statement(self, ast, following, break_to=None, continue_to=None):
        if ast is None:
            return following
        if isinstance(ast, A.Compound):
            for stmt in reversed(ast.block_items or []):
                following = self.statement(stmt, following, break_to, continue_to)
            return following
        if isinstance(ast, A.If):
            n = self.node(ast.cond, "if")
            yes = self.statement(ast.iftrue, following, break_to, continue_to)
            no = self.statement(ast.iffalse, following, break_to, continue_to)
            value = truth(ast.cond)
            if value is not False: self.edge(n, yes)
            if value is not True: self.edge(n, no)
            return n
        if isinstance(ast, (A.While, A.For, A.DoWhile)):
            condition = ast.cond
            n = self.node(condition, "loop_condition")
            step = n
            if isinstance(ast, A.For) and ast.next:
                step = self.node(ast.next, "loop_step"); self.edge(step, n)
            body = self.statement(ast.stmt, step, following, step)
            value = True if condition is None else truth(condition)
            if value is not False: self.edge(n, body)
            if value is not True: self.edge(n, following)
            entry = body if isinstance(ast, A.DoWhile) else n
            if isinstance(ast, A.For) and ast.init:
                init = self.node(ast.init, "loop_init"); self.edge(init, entry); entry = init
            return entry
        if isinstance(ast, A.Return):
            return self.node(ast.expr, "return")
        if isinstance(ast, (A.Break, A.Continue)):
            n = self.node(ast, "break" if isinstance(ast, A.Break) else "continue")
            target = break_to if isinstance(ast, A.Break) else continue_to
            if target is None: self.blockers.append("unresolved_jump")
            self.edge(n, target)
            return n
        if isinstance(ast, (A.Switch, A.Case, A.Default, A.Goto, A.Label)):
            self.blockers.append("unsupported_switch_or_goto")
        n = self.node(ast)
        self.edge(n, following)
        return n

    def build(self, body):
        exit_node = self.node(None, "exit")
        entry = self.statement(body, exit_node)
        adjacency = {}
        for a, b in self.edges: adjacency.setdefault(a, []).append(b)
        live, queue = set(), [entry]
        while queue:
            n = queue.pop()
            if n in live: continue
            live.add(n); queue.extend(adjacency.get(n, []))
        return {"entry": entry, "nodes": self.nodes, "edges": self.edges,
                "reachable_nodes": sorted(live),
                "live_calls": sorted({c for n in self.nodes if n["id"] in live for c in n["calls"]}),
                "blockers": sorted(set(self.blockers))}


def build(root):
    root = Path(root)
    functions, blockers, files = {}, [], []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".py", ".js", ".ts", ".rs", ".go", ".java", ".cs"}:
            continue
        rel = p.relative_to(root).as_posix()
        if p.suffix.lower() not in {".c", ".h"}:
            blockers.append({"file": rel, "reason": "unsupported_language"}); continue
        text = p.read_text(encoding="utf-8", errors="replace")
        # Stop lexing at the first real directive. Do not scan/parse entire
        # preprocessor-heavy library trees when they cannot be analysed here.
        if any(m.group().lstrip().startswith("#") for m in _LEXICAL.finditer(text)):
            blockers.append({"file": rel, "reason": "preprocessing_required"}); continue
        # Preserve newlines and literals. Do not pretend removing preprocessing
        # directives is equivalent to using the actual build configuration.
        text = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                      lambda m: re.sub(r"[^\n]", " ", m.group()) if m.group().startswith(("/*", "//")) else m.group(), text, flags=re.S)
        if re.search(r"(?m)^\s*#", text):
            blockers.append({"file": rel, "reason": "preprocessing_required"}); continue
        try:
            tree = c_parser.CParser().parse(text, filename=rel)
        except Exception as exc:
            blockers.append({"file": rel, "reason": "parse_error", "detail": str(exc)[:300]}); continue
        files.append(rel)
        for ext in tree.ext:
            if not isinstance(ext, A.FuncDef):
                # Function addresses, callbacks and global init dependencies
                # cannot be inferred from the direct-call graph.
                if isinstance(ext, A.Decl) and ext.init is not None:
                    blockers.append({"file": rel, "reason": "global_initializer"})
                continue
            name = ext.decl.name
            if name in functions:
                blockers.append({"file": rel, "reason": "duplicate_function_name", "function": name})
            g = Graph().build(ext.body)
            functions[name] = {"file": rel, "line": ext.decl.coord.line, **g}
            for reason in g["blockers"]:
                blockers.append({"file": rel, "function": name, "reason": reason})
            # Any address escape or function alias needs dispatch resolution.
            class IDs(A.NodeVisitor):
                def visit_FuncCall(self, n):
                    if not isinstance(n.name, A.ID): self.visit(n.name)
                    if n.args: self.visit(n.args)
                def visit_ID(self, n):
                    # Collected below once all function declarations are known.
                    escaped.append(n.name)
            escaped = []
            IDs().visit(ext.body)
            functions[name]["non_call_identifiers"] = escaped
    for name, f in functions.items():
        if set(f.pop("non_call_identifiers")) & set(functions):
            blockers.append({"function": name, "reason": "function_address_or_alias"})
    entries = [n for n in ("main", "wmain", "WinMain", "app_main") if n in functions]
    if not entries: blockers.append({"reason": "no_explicit_entry_point"})
    paths, queue = {}, deque((n, [n]) for n in entries)
    while queue:
        name, path = queue.popleft()
        if name in paths: continue
        paths[name] = path
        for callee in functions[name]["live_calls"]:
            if callee in functions: queue.append((callee, path + [callee]))
            else: blockers.append({"function": name, "callee": callee, "reason": "unresolved_external_or_indirect_call"})
    return {"engine": "c-ast-cfg/1", "scope": "uploaded_source_explicit_entry_points",
            "files": files, "entries": entries, "functions": functions,
            "paths": paths, "blockers": blockers, "negative_decisions_enabled": not blockers}


def assess(graph, names, intake_complete=True):
    present = [name for name in names if name in graph["functions"]]
    paths = [{"function": n, "path": graph["paths"][n]} for n in present if n in graph["paths"]]
    unreachable = bool(present) and not paths and graph["negative_decisions_enabled"] and intake_complete
    return {"reachable_paths": paths, "present_targets": present,
            "unreachable": unreachable, "blockers": graph["blockers"],
            "scope": graph["scope"], "engine": graph["engine"]}
