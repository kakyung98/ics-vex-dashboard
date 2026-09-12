#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Q2 (in-execute-path) via a static call graph over a collected source tree.

For a CVE whose source is in data/source_snapshots/<CVE>/, build a C/C++ call
graph with tree-sitter, then check whether the vulnerable function (from the fix
commit) is reachable from the component's public entry points.

  reachable    -> Q2 does NOT clear not_affected (stays a candidate for fuzzing)
  unreachable  -> not_affected / vulnerable_code_not_in_execute_path

This is the cheap static filter that runs before fuzzing. It does not prove the
path executes at runtime (that is what fuzzing confirms), only that a call chain
exists in the source.

Usage:
  python tools/callgraph_reach.py <CVE> [--target func1,func2] [--json out.json]
  python tools/callgraph_reach.py --all
"""
import argparse
import json
import os
import re
from collections import defaultdict, deque

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(BASE, "data", "source_snapshots")
CE = os.path.join(BASE, "data", "code_evidence.json")
VF = os.path.join(BASE, "data", "vuln_targets.json")  # tools/locate_vuln_funcs.py output

import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Parser

C_LANG = Language(tree_sitter_c.language())
CPP_LANG = Language(tree_sitter_cpp.language())
try:
    import tree_sitter_java
    JAVA_LANG = Language(tree_sitter_java.language())
except Exception:      # grammar absent - Java trees are then simply skipped
    JAVA_LANG = None
EXT_C = {".c", ".h"}
EXT_CPP = {".cc", ".cpp", ".cxx", ".hpp", ".hh"}
EXT_JAVA = {".java"} if JAVA_LANG else set()
SKIP = ("test", "example", "examples", "fuzz", ".git", "doc", "docs")


def _parser(ext):
    if ext in EXT_JAVA:
        return Parser(JAVA_LANG)
    return Parser(CPP_LANG if ext in EXT_CPP else C_LANG)


def _funcname(node, src):
    decl = node.child_by_field_name("declarator")
    seen = 0
    while decl is not None and decl.type != "function_declarator" and seen < 6:
        d = decl.child_by_field_name("declarator")
        if d is None:
            for c in decl.children:
                if c.type in ("function_declarator", "identifier", "pointer_declarator",
                              "parenthesized_declarator"):
                    d = c
                    break
        decl = d
        seen += 1
    if decl is None:
        return None
    idn = decl.child_by_field_name("declarator") if decl.type == "function_declarator" else decl
    q = [idn] if idn else []
    while q:
        n = q.pop()
        if n is None:
            continue
        if n.type in ("identifier", "field_identifier"):
            return src[n.start_byte:n.end_byte].decode("utf-8", "ignore")
        q.extend(n.children)
    return None


def _calls_in(node, src):
    out = set()
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "call_expression":
            fn = n.child_by_field_name("function")
            if fn is not None and fn.type in ("identifier", "field_identifier"):
                out.add(src[fn.start_byte:fn.end_byte].decode("utf-8", "ignore"))
        elif n.type == "method_invocation":
            # Java: `obj.foo(x)` - the callee is the `name` field
            nm = n.child_by_field_name("name")
            if nm is not None:
                out.add(src[nm.start_byte:nm.end_byte].decode("utf-8", "ignore"))
        stack.extend(n.children)
    return out


def _java_methods(tree, src):
    """(name, body node) for every method/constructor in a Java file."""
    out = []
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type in ("method_declaration", "constructor_declaration"):
            nm = n.child_by_field_name("name")
            body = n.child_by_field_name("body")
            if nm is not None and body is not None:
                out.append((src[nm.start_byte:nm.end_byte].decode("utf-8", "ignore"), body))
        stack.extend(n.children)
    return out


# --- K&R fallback ------------------------------------------------------------
# tree-sitter's C grammar chokes on old-style (K&R) definitions and on macro-
# wrapped signatures, which are pervasive in the corpus (zlib 1.2.8's inflate.c
# alone yields 89 ERROR nodes and loses `inflate`). A lost definition makes its
# callees look unreachable - i.e. it manufactures false `not_affected` - so a
# regex scanner supplements, never replaces, the parse.
_KW = {"if", "for", "while", "switch", "return", "sizeof", "do", "else", "case",
       "defined", "typedef", "struct", "union", "enum", "static", "extern"}
# a top-level definition starts at column 0; that alone rejects most statements
_KR_DEF = re.compile(
    # the return type is optional on the name's line: BSD/busybox style puts
    # `static int` on the line above and `readtoken1(...)` at column 0, and the
    # old mandatory prefix lost busybox ash's whole parser (CVE-2021-42375)
    rb"^(?:[A-Za-z_][A-Za-z0-9_ \t\*]*?[ \t\*])?([A-Za-z_]\w*)[ \t]*\("  # [ret] name(
    rb"[^;{}()]*\)[ \t]*"                                          # args)
    rb"(?:\r?\n[ \t]*[A-Za-z_][^;{}\n]*;)*"                        # K&R param decls
    rb"[ \t]*\r?\n?[ \t]*\{",                                      # body brace
    re.M)
_CALL = re.compile(rb"\b([A-Za-z_]\w*)[ \t]*\(")


def _match_brace(src, i):
    """End offset of the block whose '{' is at i, or None.

    Braces inside string/char literals and comments do not count: busybox ash's
    `c != '}'` closed readtoken1 a hundred lines early, cutting the parser code
    CVE-2021-42375's fix edits (and its callees) out of the function."""
    depth, n = 0, len(src)
    while i < n:
        c = src[i:i + 1]
        if c in (b'"', b"'"):
            i += 1
            while i < n and src[i:i + 1] != c:
                i += 2 if src[i:i + 1] == b"\\" else 1
        elif src[i:i + 2] == b"/*":
            j = src.find(b"*/", i + 2)
            i = n if j < 0 else j + 1
        elif src[i:i + 2] == b"//":
            j = src.find(b"\n", i)
            i = n if j < 0 else j
        elif c == b"{":
            depth += 1
        elif c == b"}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _scan_regex(src):
    """(name, calls) for definitions a regex can see. Supplements the parse."""
    out = []
    for m in _KR_DEF.finditer(src):
        name = m.group(1).decode("utf-8", "ignore")
        if name in _KW:
            continue
        brace = src.find(b"{", m.end() - 1)
        end = _match_brace(src, brace) if brace >= 0 else None
        if end is None:
            continue
        body = src[brace:end]
        calls = {c.decode("utf-8", "ignore") for c in _CALL.findall(body)}
        out.append((name, calls - _KW))
    return out


def build_graph(root):
    defs = defaultdict(set)
    defined = set()
    files = 0
    for dp, _dn, fns in os.walk(root):
        low = dp.replace("\\", "/").lower()
        if any(("/" + s) in low for s in SKIP):
            continue
        for fn in fns:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in EXT_C and ext not in EXT_CPP and ext not in EXT_JAVA:
                continue
            p = os.path.join(dp, fn)
            try:
                src = open(p, "rb").read()
            except OSError:
                continue
            if len(src) > 2_000_000:
                continue
            files += 1
            tree = _parser(ext).parse(src)
            if ext in EXT_JAVA:
                for name, body in _java_methods(tree, src):
                    defined.add(name)
                    defs[name] |= _calls_in(body, src)
                continue                      # the C paths below do not apply
            stack = [tree.root_node]
            while stack:
                n = stack.pop()
                if n.type == "function_definition":
                    name = _funcname(n, src)
                    body = n.child_by_field_name("body")
                    if name and body is not None:
                        defined.add(name)
                        defs[name] |= _calls_in(body, src)
                stack.extend(n.children)
            for name, calls in _scan_regex(src):
                if name not in defined:          # parser wins where it succeeded
                    defined.add(name)
                    defs[name] |= calls
    return defs, defined, files


def reachable_from(entries, defs):
    seen, q = set(entries), deque(entries)
    while q:
        f = q.popleft()
        for c in defs.get(f, ()):
            if c not in seen:
                seen.add(c)
                q.append(c)
    return seen


def source_root(root):
    """The tree to analyse: the snapshot's single source tree, or the whole
    snapshot when it holds several - CVE-2023-34035 needs spring-security 6.1.0
    beside spring-framework 6.0.9, and taking the first subdirectory silently
    left the tree with the vulnerable code out of the graph."""
    sub = [os.path.join(root, d) for d in os.listdir(root)] if os.path.isdir(root) else []
    trees = [s for s in sub if os.path.isdir(s)]
    return trees[0] if len(trees) == 1 else root


def analyze(cve, targets):
    root = os.path.join(SNAP, cve)
    src_root = source_root(root)
    defs, defined, nfiles = build_graph(src_root)
    if not defined:
        return {"cve": cve, "status": "no-source", "files": nfiles}

    called = set().union(*defs.values()) if defs else set()
    entries = {f for f in defined if f not in called} | ({"main"} & defined)
    if not entries:
        entries = set(defined)
    reach = reachable_from(entries, defs)

    tgt_present = [t for t in targets if t in defined]
    tgt_reach = [t for t in tgt_present if t in reach]
    if not tgt_present:
        verdict = "target-not-found"
    elif tgt_reach:
        verdict = "reachable"
    else:
        verdict = "unreachable"
    return {"cve": cve, "status": "ok", "files": nfiles, "functions": len(defined),
            "entry_points": len(entries), "targets": targets,
            "targets_present": tgt_present, "targets_reachable": tgt_reach,
            "verdict": verdict,
            "justification": ("vulnerable_code_not_in_execute_path"
                              if verdict == "unreachable" else None)}


# {CVE: {"targets": [...], "source": ...}} - Q2 and Q3 must judge the same targets
_T = json.load(open(VF, encoding="utf-8")) if os.path.exists(VF) else {}
_VULN_FUNCS = {c: v["targets"] for c, v in _T.items() if v.get("targets")}
_TARGET_SOURCE = {c: v.get("source") for c, v in _T.items()}


def targets_for(cve, ce, override):
    """The recorded target set for this CVE, and nothing else.

    There used to be a fallback here that scraped `name(` out of the raw hunk
    text when no target was recorded. It judged CVEs that data/vuln_targets.json
    says have no target, on "targets" like `for` and `sizeof` - C keywords - and
    on names the macro/libc filter had deliberately rejected. Q3 reads
    vuln_targets.json directly and had no such fallback, so Q2 reported 62
    judgments against Q3's 60 over the same corpus.

    Both stages must judge the same targets or their verdicts cannot be compared,
    so a CVE with no recorded target is `target-not-found` here too."""
    if override:
        return [t.strip() for t in override.split(",") if t.strip()]
    return list(_VULN_FUNCS.get(cve, ()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cve", nargs="?")
    ap.add_argument("--target", default="")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--json", default="")
    a = ap.parse_args()
    if not a.cve and not a.all:
        ap.error("give a CVE or --all")     # a bare run once wrote a cve=null row
    ce = json.load(open(CE, encoding="utf-8")) if os.path.exists(CE) else {}

    cves = ([d for d in sorted(os.listdir(SNAP)) if os.path.isdir(os.path.join(SNAP, d))]
            if a.all else [a.cve])
    out = a.json or os.path.join(BASE, "results", "callgraph_reach.json")
    # resume: skip CVEs already in the output file (survives shutdowns)
    results = []
    if a.all and os.path.exists(out):
        try:
            results = [r for r in json.load(open(out, encoding="utf-8")) if r.get("cve")]
        except Exception:
            results = []
    done = {r.get("cve") for r in results}
    for cve in cves:
        if cve in done:
            continue
        try:
            r = analyze(cve, targets_for(cve, ce, a.target))
        except Exception as e:
            r = {"cve": cve, "status": "error", "error": str(e)[:150]}
        results.append(r)
        v = r.get("verdict", r.get("status"))
        print("%-20s %-18s files=%s funcs=%s tgt=%s/reach=%s" % (
            cve, v, r.get("files", "-"), r.get("functions", "-"),
            len(r.get("targets_present", []) or []), len(r.get("targets_reachable", []) or [])), flush=True)
        json.dump(results, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)  # checkpoint each CVE
    from collections import Counter
    dist = Counter(r.get("verdict", r.get("status")) for r in results)
    print("\n== verdicts ==", dict(dist))
    print("-> %s" % out)


if __name__ == "__main__":
    main()
