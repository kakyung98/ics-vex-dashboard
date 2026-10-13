#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Index every function defined in each source snapshot.

Shared prerequisite for the no-patch localization paths: the NVD-description
matcher needs the set of real function names to filter against, and the CodeBERT
ranker needs each candidate's source text. Built once, cached per CVE.

A snapshot belongs to a BUILD, not just to a CVE: the same CVE has a vulnerable
tree under data/source_snapshots/ and the vendor's remediated release under
data/fixed_releases/. Both must be indexable, and into separate caches - a patched
build usually still DEFINES the vulnerable function (only its body changed), so
merging the two indexes would silently answer "present" for whichever was written
last. `--build patched` indexes the vendor releases into data/func_index_patched/.
The axis is named for the GT's vocabulary ("patched"), not the directory's: "fixed"
is already a VEX product_status, and one word must not mean both.

Output: data/func_index[_patched]/<CVE>.json
  {"functions": {name: [[file, start_line, end_line], ...]}, "files": N}
"""
import argparse
import json
import os
import sys
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# build -> (snapshot root, index root). Kept in one table so source_locate and the
# judge can import the same mapping instead of each re-deriving the paths.
BUILDS = {"vulnerable": ("source_snapshots", "func_index"),
          "patched": ("fixed_releases", "func_index_patched")}


def roots(build="vulnerable"):
    snap, outd = BUILDS[build]
    return os.path.join(BASE, "data", snap), os.path.join(BASE, "data", outd)


SNAP, OUTD = roots()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from extract_vuln_funcs import _funcs_by_line, EXT_SRC, EXT_PY, SKIP_SEG  # noqa: E402


def _exts(root):
    """Which extensions to index for THIS component.

    Python is included only for a component that ships no compiled sources at all.
    Nearly every C snapshot carries build and doc scripts - libxml2 2.9.1 alone has
    about 40 .py files - and every extra name in the index can only turn a Q2 miss
    into a hit, i.e. push a verdict toward `affected`. A pure-Python component
    (sqlparse, CVE-2024-4340) has no such ambiguity: its .py files ARE the source.
    """
    for dp, _dn, fns in os.walk(root):
        if SKIP_SEG & set(dp.replace("\\", "/").lower().split("/")):
            continue
        if any(os.path.splitext(f)[1].lower() in EXT_SRC for f in fns):
            return EXT_SRC, "compiled"
    return EXT_SRC | EXT_PY, "python"


def index_snapshot(root):
    exts, kind = _exts(root)
    funcs = defaultdict(list)
    nfiles = 0
    for dp, _dn, fns in os.walk(root):
        low = dp.replace("\\", "/").lower()
        if SKIP_SEG & set(low.split("/")):
            continue
        for fn in fns:
            if os.path.splitext(fn)[1].lower() not in exts:
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
            # The extractor's span reader, so the index and the targets agree on
            # what a function is: Java methods, K&R definitions and tree-sitter
            # nodes cut short by a parse error. The C grammar alone indexed
            # nothing in the Java snapshots and lost K&R functions such as
            # zlib 1.2.12's inflate.
            try:
                spans = _funcs_by_line(p)
            except Exception:
                continue
            for s, e, nm in spans:
                funcs[nm].append([rel, s, e])
    return funcs, nfiles, kind


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", choices=sorted(BUILDS), default="vulnerable",
                    help="'patched' indexes data/fixed_releases into func_index_patched")
    ap.add_argument("--cve", help="index this CVE only")
    ap.add_argument("--force", action="store_true", help="re-index even if cached")
    a = ap.parse_args()

    snap, outd = roots(a.build)
    os.makedirs(outd, exist_ok=True)
    if not os.path.isdir(snap):
        print("no snapshot root: %s" % snap)
        return
    cves = ([a.cve] if a.cve else
            sorted(d for d in os.listdir(snap) if os.path.isdir(os.path.join(snap, d))))
    for cve in cves:
        dst = os.path.join(outd, cve + ".json")
        if os.path.exists(dst) and not a.force:
            continue
        funcs, nfiles, kind = index_snapshot(os.path.join(snap, cve))
        json.dump({"functions": funcs, "files": nfiles, "language": kind},
                  open(dst, "w", encoding="utf-8"))
        print("%-18s files=%-6d funcs=%-7d lang=%s"
              % (cve, nfiles, len(funcs), kind), flush=True)
    print("-> %s" % outd)


if __name__ == "__main__":
    main()
