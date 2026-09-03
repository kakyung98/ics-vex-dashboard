#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Identify the vulnerable function for each CVE, for callgraph Q2 targeting.

The problem callgraph_reach.py hit: it needs the name of the vulnerable function,
but data/code_evidence.json stores only a hunk excerpt (no signature). Here we
locate that excerpt inside the collected snapshot file and read off the *enclosing*
function with tree-sitter — robust, offline, no diff parsing.

For each CVE that has both a code_evidence entry (repo/file/vuln_code) and a
source snapshot:
  1. find the file (by basename) in data/source_snapshots/<CVE>/
  2. take distinctive lines from vuln_code, locate them in that file
  3. tree-sitter the file, find the function_definition spanning those lines
  4. record the enclosing function name(s)

Output: data/vuln_funcs.json = {CVE: [funcnames]} — consumed by callgraph_reach.py.
"""
import json
import os
import re
from collections import Counter

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(BASE, "data", "source_snapshots")
CE = os.path.join(BASE, "data", "code_evidence.json")
OUT = os.path.join(BASE, "data", "vuln_funcs.json")

import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Parser

C_LANG = Language(tree_sitter_c.language())
CPP_LANG = Language(tree_sitter_cpp.language())
EXT_CPP = {".cc", ".cpp", ".cxx", ".hpp", ".hh"}


def _parser(path):
    return Parser(CPP_LANG if os.path.splitext(path)[1].lower() in EXT_CPP else C_LANG)


def _funcname(node, src):
    """Name of a function_definition node (mirrors callgraph_reach.py)."""
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


def _funcs_by_line(path):
    """Map: 0-based line -> enclosing function name, for one file."""
    src = open(path, "rb").read()
    tree = _parser(path).parse(src)
    spans = []  # (start_line, end_line, name)
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type == "function_definition":
            nm = _funcname(n, src)
            if nm:
                spans.append((n.start_point[0], n.end_point[0], nm))
        stack.extend(n.children)
    return spans


def _find_file(root, basename):
    for dp, _dn, fns in os.walk(root):
        if basename in fns:
            return os.path.join(dp, basename)
    # try suffix match (code_evidence 'file' can be a path)
    for dp, _dn, fns in os.walk(root):
        for fn in fns:
            if fn == basename:
                return os.path.join(dp, fn)
    return None


def _distinctive_lines(blob):
    """Lines worth anchoring on: non-trivial, likely unique."""
    out = []
    for ln in (blob or "").splitlines():
        s = ln.strip()
        if len(s) < 12:
            continue
        if s in ("{", "}", "*/", "/*") or s.startswith(("//", "* ", "*")):
            continue
        if re.fullmatch(r"[}\);,]+", s):
            continue
        out.append(s)
    return out


def enclosing_funcs(cve, ev):
    root = os.path.join(SNAP, cve)
    if not os.path.isdir(root):
        return None, "no-snapshot"
    fpath = _find_file(root, os.path.basename(ev.get("file", "")))
    if not fpath:
        return None, "file-not-in-snapshot"
    try:
        spans = _funcs_by_line(fpath)
    except Exception as e:
        return None, "parse-error:%s" % str(e)[:40]
    if not spans:
        return None, "no-functions"
    text = open(fpath, encoding="utf-8", errors="ignore").read().splitlines()
    anchors = _distinctive_lines(ev.get("vuln_code")) + _distinctive_lines(ev.get("patched_code"))
    hit = Counter()
    for a in anchors:
        for i, line in enumerate(text):
            if a in line:
                for s, e, nm in spans:
                    if s <= i <= e:
                        hit[nm] += 1
                break  # first occurrence is enough per anchor
    if not hit:
        return None, "anchors-unmatched"
    # keep the strongly-supported functions
    top = hit.most_common()
    best = [nm for nm, c in top if c >= max(2, top[0][1] // 2)]
    return (best or [top[0][0]]), "ok"


def main():
    ce = json.load(open(CE, encoding="utf-8"))
    out, stats = {}, Counter()
    for cve, ev in ce.items():
        if not isinstance(ev, dict) or not ev.get("file"):
            continue
        if not (ev.get("vuln_code") or ev.get("patched_code")):
            continue
        funcs, why = enclosing_funcs(cve, ev)
        stats[why] += 1
        if funcs:
            out[cve] = funcs
            print("%-18s %-22s -> %s" % (cve, os.path.basename(ev["file"]), funcs))
        else:
            print("%-18s %-22s -- %s" % (cve, os.path.basename(ev["file"]), why))
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("\n== %d CVEs resolved to a vulnerable function ==" % len(out))
    print("reasons:", dict(stats))
    print("->", OUT)


if __name__ == "__main__":
    main()
