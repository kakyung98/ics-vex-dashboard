#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Index every function defined in each source snapshot.

Shared prerequisite for the no-patch localization paths: the NVD-description
matcher needs the set of real function names to filter against, and the CodeBERT
ranker needs each candidate's source text. Built once, cached per CVE.

Output: data/func_index/<CVE>.json
  {"functions": {name: [[file, start_line, end_line], ...]}, "files": N}
"""
import json
import os
import sys
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(BASE, "data", "source_snapshots")
OUTD = os.path.join(BASE, "data", "func_index")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from extract_vuln_funcs import _funcname, _parser, EXT_SRC, SKIP_SEG  # noqa: E402


def index_snapshot(root):
    funcs = defaultdict(list)
    nfiles = 0
    for dp, _dn, fns in os.walk(root):
        low = dp.replace("\\", "/").lower()
        if SKIP_SEG & set(low.split("/")):
            continue
        for fn in fns:
            if os.path.splitext(fn)[1].lower() not in EXT_SRC:
                continue
            p = os.path.join(dp, fn)
            try:
                src = open(p, "rb").read()
            except OSError:
                continue
            if len(src) > 2_000_000:
                continue
            nfiles += 1
            rel = os.path.relpath(p, root).replace("\\", "/")
            tree = _parser(p).parse(src)
            stack = [tree.root_node]
            while stack:
                n = stack.pop()
                if n.type == "function_definition":
                    nm = _funcname(n, src)
                    if nm:
                        funcs[nm].append([rel, n.start_point[0], n.end_point[0]])
                stack.extend(n.children)
    return funcs, nfiles


def main():
    os.makedirs(OUTD, exist_ok=True)
    cves = sorted(d for d in os.listdir(SNAP) if os.path.isdir(os.path.join(SNAP, d)))
    for cve in cves:
        dst = os.path.join(OUTD, cve + ".json")
        if os.path.exists(dst):
            continue
        funcs, nfiles = index_snapshot(os.path.join(SNAP, cve))
        json.dump({"functions": funcs, "files": nfiles},
                  open(dst, "w", encoding="utf-8"))
        print("%-18s files=%-6d funcs=%d" % (cve, nfiles, len(funcs)), flush=True)
    print("-> %s" % OUTD)


if __name__ == "__main__":
    main()
