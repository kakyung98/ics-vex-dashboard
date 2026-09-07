#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Q3 (adversary-controllable) via tainted-entry reachability.

Q2 asks whether the vulnerable function is reachable from ANY entry point. Q3
asks the narrower question CISA's `vulnerable_code_cannot_be_controlled_by_
adversary` actually encodes: can data an attacker supplies reach it?

So the same call graph is walked from a restricted entry set:

  external input  a function whose body calls an I/O primitive
                  (recv/read/fread/accept/SSL_read/getenv/argv ...)
  public API      a function declared in a public header - the caller hands it
                  bytes the library itself never chose

  target reachable from that set     -> Q3 passes, stays an `affected` candidate
  target NOT reachable               -> not_affected /
                                        vulnerable_code_cannot_be_controlled_by_adversary
  target unknown / graph incomplete  -> under_investigation

IMPORTANT - the static call graph is INCOMPLETE (function pointers, dlopen,
build-excluded files). "Not reachable" is therefore a failure to refute, not a
proof, so the verdict is gated on graph completeness and on where the target
name came from: a path-C (CodeBERT-ranked) target may never yield not_affected.

Output: results/taint_reach.json
"""
import argparse
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(BASE, "data", "source_snapshots")
TARGETS = os.path.join(BASE, "data", "vuln_targets.json")
OUT = os.path.join(BASE, "results", "taint_reach.json")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from callgraph_reach import (  # noqa: E402
    EXT_C, EXT_CPP, SKIP, _funcname, _parser, build_graph, reachable_from,
)

# Reading bytes the process did not author: the boundary an attacker sits behind.
IO_PRIMS = {
    # sockets / network
    "recv", "recvfrom", "recvmsg", "accept", "accept4", "read", "readv", "pread",
    "SSL_read", "SSL_peek", "BIO_read", "BIO_gets",
    # files and streams the attacker may supply
    "fread", "fgets", "getline", "getdelim", "fscanf", "fgetc", "getc",
    "mmap", "readlink",
    # process boundary
    "getenv", "secure_getenv", "scanf", "gets",
}
# Definitions live in .c; a public declaration lives in a header the API exposes.
PUBLIC_DIRS = ("include/", "inc/", "api/", "public/")


# Headers routinely wrap signatures in export macros (zlib: `ZEXTERN int ZEXPORT
# inflate OF((z_streamp, int));`), which the parser cannot see through - it found
# 3 of zlib's ~80 public functions. A regex supplements it. Over-collecting here
# is the SAFE direction: a spurious public entry can only make more code look
# reachable, never manufacture a false `not_affected`.
_DECL = re.compile(r"\b([A-Za-z_]\w*)\s*(?:OF\s*)?\(", re.M)
_DECL_KW = {"if", "for", "while", "switch", "return", "sizeof", "defined",
            "typedef", "struct", "union", "enum", "static", "extern", "const",
            "void", "int", "char", "long", "short", "unsigned", "signed"}


def _scan_header_decls(text):
    """Function names declared in a header, macro wrappers included."""
    names = set()
    for stmt in text.split(";"):
        if "(" not in stmt or "{" in stmt:
            continue
        m = _DECL.search(stmt)
        if m and m.group(1) not in _DECL_KW:
            # the declared name is the identifier just before the argument list
            cands = [x for x in _DECL.findall(stmt) if x not in _DECL_KW]
            if cands:
                names.add(cands[0])
    return names


def public_api(root):
    """Function names declared in a public header (the library's attack surface)."""
    names = set()
    for dp, _dn, fns in os.walk(root):
        low = dp.replace("\\", "/").lower()
        if any(("/" + s) in low for s in SKIP):
            continue
        for fn in fns:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in (".h", ".hpp", ".hh"):
                continue
            p = os.path.join(dp, fn).replace("\\", "/")
            rel = p[len(root.replace("\\", "/")):].lstrip("/").lower()
            # a header is public if it sits in an include-ish directory, or at
            # the top of the tree (single-header libraries: zlib.h, expat.h)
            if not (any(d in rel for d in PUBLIC_DIRS) or rel.count("/") <= 1):
                continue
            try:
                src = open(p, "rb").read()
            except OSError:
                continue
            if len(src) > 2_000_000:
                continue
            tree = _parser(ext).parse(src)
            stack = [tree.root_node]
            while stack:
                n = stack.pop()
                if n.type in ("declaration", "function_definition"):
                    nm = _funcname(n, src)
                    if nm:
                        names.add(nm)
                stack.extend(n.children)
            names |= _scan_header_decls(src.decode("utf-8", "ignore"))
    return names


_IDENT = re.compile(rb"\b([A-Za-z_]\w*)\b(?!\s*\()")


def address_taken(root, defined):
    """Functions whose address is taken - i.e. reachable by an INDIRECT call.

    A static call graph sees only `f()`. Dispatch tables and callbacks
    (`sqlite3_create_function(..., rtreenode, ...)`, sshd's `userauth_pubkey,`
    in a handler table) are invisible to it, and both produced a false
    `not_affected` before this was added. Treating every address-taken function
    as a root is the standard conservative approximation: it can only widen the
    reachable set, so it removes false clearances rather than creating them."""
    hit = set()
    for dp, _dn, fns in os.walk(root):
        low = dp.replace("\\", "/").lower()
        if any(("/" + s) in low for s in SKIP):
            continue
        for fn in fns:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in EXT_C and ext not in EXT_CPP:
                continue
            try:
                src = open(os.path.join(dp, fn), "rb").read()
            except OSError:
                continue
            if len(src) > 2_000_000:
                continue
            for m in _IDENT.finditer(src):
                nm = m.group(1).decode("utf-8", "ignore")
                if nm in defined:
                    hit.add(nm)
    return hit


def is_macro_like(name):
    """ALL_CAPS names are export/annotation macros (ZLIB_INTERNAL), not targets."""
    return name.isupper() or (name.replace("_", "").isupper() and len(name) > 3)


def analyze(cve, targets):
    root = os.path.join(SNAP, cve)
    sub = [os.path.join(root, d) for d in os.listdir(root)] if os.path.isdir(root) else []
    src_root = next((s for s in sub if os.path.isdir(s)), root)
    defs, defined, nfiles = build_graph(src_root)
    if not defined:
        return {"cve": cve, "status": "no-source", "files": nfiles}

    called = set().union(*defs.values()) if defs else set()
    # completeness: how much of what the code calls do we actually see defined?
    resolved = len(called & defined) / len(called) if called else 0.0

    io_entries = {f for f, cs in defs.items() if cs & IO_PRIMS}
    api = public_api(src_root) & defined
    indirect = address_taken(src_root, defined)
    tainted = io_entries | api | indirect | ({"main"} & defined)
    reach = reachable_from(tainted, defs) if tainted else set()

    present = [t for t in targets if t in defined and not is_macro_like(t)]
    ctrl = [t for t in present if t in reach]
    if not present:
        verdict = "target-not-found"
    elif ctrl:
        verdict = "controllable"
    elif not tainted:
        verdict = "no-tainted-entry"       # cannot ask the question here
    else:
        verdict = "not-controllable"
    return {"cve": cve, "status": "ok", "files": nfiles, "functions": len(defined),
            "io_entries": len(io_entries), "public_api": len(api),
            "address_taken": len(indirect),
            "tainted_entries": len(tainted), "tainted_reach": len(reach),
            "call_resolution": round(resolved, 3),
            "targets": targets, "targets_present": present, "targets_controllable": ctrl,
            "verdict": verdict}


def decide(row, source, min_resolution=0.5):
    """Map a raw verdict to a VEX outcome, bounded by evidence strength.

    A target that a model merely ranked (path C) can keep a CVE in the affected
    pool but can never clear it - an unreachable guess is not an answer."""
    v = row.get("verdict")
    if v == "controllable":
        return "affected-candidate", None
    if v != "not-controllable":
        return "under_investigation", None
    if source == "codebert":
        return "under_investigation", "target is a model guess (path C)"
    if row.get("call_resolution", 0) < min_resolution:
        return "under_investigation", ("call graph too incomplete (%.2f)"
                                       % row.get("call_resolution", 0))
    return "not_affected", "vulnerable_code_cannot_be_controlled_by_adversary"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cve", nargs="?")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--json", default=OUT)
    a = ap.parse_args()

    known = json.load(open(TARGETS, encoding="utf-8")) if os.path.exists(TARGETS) else {}
    cves = ([d for d in sorted(os.listdir(SNAP)) if os.path.isdir(os.path.join(SNAP, d))]
            if a.all else [a.cve])
    results = []
    if a.all and os.path.exists(a.json):
        try:
            results = json.load(open(a.json, encoding="utf-8"))
        except Exception:
            results = []
    done = {r.get("cve") for r in results}

    for cve in cves:
        if cve in done:
            continue
        k = known.get(cve) or {}
        try:
            row = analyze(cve, k.get("targets") or [])
        except Exception as e:
            row = {"cve": cve, "status": "error", "error": str(e)[:120]}
        row["target_source"] = k.get("source", "none")
        row["vex"], row["justification"] = decide(row, row["target_source"])
        results.append(row)
        print("%-18s %-18s %-20s src=%-12s res=%.2f tainted=%d" %
              (cve, row.get("verdict", row.get("status")), row["vex"],
               row["target_source"], row.get("call_resolution", 0),
               row.get("tainted_entries", 0)), flush=True)
        json.dump(results, open(a.json, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("->", a.json)


if __name__ == "__main__":
    main()
