#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Q1 presence, from the CVE description + the collected snapshot.

The idea (no patch/commit needed): the NVD text usually names the vulnerable
function or file. If that named function is NOT defined anywhere in the collected
source, the vulnerable code is not present in this build ->
  not_affected / vulnerable_code_not_present.
If it IS present, the CVE stays a candidate and its function is handed to the
call-graph (Q2) and, later, the model for a semantic check of the variant.

This is the structural half of Q1 — deterministic, no model. It turns the useless
'target-not-found' verdicts (which only meant "we had no real target") into
either a real presence signal or a defensible not_affected.

Output: data/cve_presence.json  { CVE: {verdict, funcs, files, evidence} }
"""
import json
import os
import re
from collections import Counter

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(BASE, "data", "source_snapshots")
NVD = os.path.join(BASE, "data", "nvd_cache.json")
OUT = os.path.join(BASE, "data", "cve_presence.json")

import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Parser

C_LANG = Language(tree_sitter_c.language())
CPP_LANG = Language(tree_sitter_cpp.language())
EXT_C = {".c", ".h"}
EXT_CPP = {".cc", ".cpp", ".cxx", ".hpp", ".hh"}
SKIP = ("test", "example", "examples", "fuzz", ".git", "doc", "docs")

# common English words that match the func regex but are not identifiers
STOP = {"the", "and", "for", "via", "function", "with", "not", "are", "was", "may",
        "can", "has", "does", "when", "which", "that", "this", "such", "have", "use",
        "allows", "before", "after", "known", "code", "input", "user", "data"}

FUNC_RE = re.compile(r'\b([a-z_][a-zA-Z0-9_]{2,})\s*\(\)'                 # foo()
                     r'|\bfunction\s+([a-z_][a-zA-Z0-9_]{2,})'           # function foo
                     r'|\b([a-z_][a-zA-Z0-9_]{2,})\s+function')          # foo function
FILE_RE = re.compile(r'\b([\w/\-]+\.(?:c|cc|cpp|cxx|h|hpp|hh))\b')


def _parser(ext):
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


def snapshot_defs(cve):
    """Set of function names defined in the snapshot, and the set of file basenames."""
    root = os.path.join(SNAP, cve)
    if not os.path.isdir(root):
        return None, None
    defs, files = set(), set()
    for dp, _dn, fns in os.walk(root):
        low = dp.replace("\\", "/").lower()
        if any(("/" + s) in low for s in SKIP):
            continue
        for fn in fns:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in EXT_C and ext not in EXT_CPP:
                continue
            files.add(fn)
            p = os.path.join(dp, fn)
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
                if n.type == "function_definition":
                    nm = _funcname(n, src)
                    if nm:
                        defs.add(nm)
                stack.extend(n.children)
    return defs, files


def hints(desc):
    funcs = set()
    for m in FUNC_RE.findall(desc or ""):
        for g in m:
            if g and g.lower() not in STOP:
                funcs.add(g)
    files = set(os.path.basename(f) for f in FILE_RE.findall(desc or ""))
    return funcs, files


def main():
    nvd = json.load(open(NVD, encoding="utf-8"))
    cves = sorted(d for d in os.listdir(SNAP) if os.path.isdir(os.path.join(SNAP, d)))
    out, stats = {}, Counter()
    for cve in cves:
        desc = (nvd.get(cve) or {}).get("description", "") if isinstance(nvd.get(cve), dict) else ""
        hf, hfile = hints(desc)
        defs, files = snapshot_defs(cve)
        if defs is None:
            stats["no-snapshot"] += 1
            continue
        present = sorted(f for f in hf if f in defs)
        file_present = sorted(f for f in hfile if f in files)
        if hf and present:
            verdict = "present"          # named function is in this build -> Q2 candidate
        elif hf and not present:
            verdict = "not_present"      # named vulnerable function absent -> not_affected
        elif hfile and not file_present:
            verdict = "not_present"      # named file absent -> not_affected
        elif hfile and file_present:
            verdict = "file-present"     # file here but function unnamed -> needs model scan
        else:
            verdict = "no-hint"          # description names nothing -> model scan territory
        stats[verdict] += 1
        out[cve] = {"verdict": verdict, "hint_funcs": sorted(hf), "hint_files": sorted(hfile),
                    "funcs_present": present, "files_present": file_present}
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("== Q1 structural presence over %d snapshots ==" % len(out))
    for k, n in stats.most_common():
        print("  %-14s %d" % (k, n))
    npresent = stats["present"]
    nna = stats["not_present"]
    print("\n-> vulnerable function CONFIRMED PRESENT (Q2 candidates): %d" % npresent)
    print("-> named vulnerable code ABSENT (=> not_affected / vulnerable_code_not_present): %d" % nna)
    print("-> need model scan (file-present / no-hint): %d" % (stats["file-present"] + stats["no-hint"]))
    print("->", OUT)


if __name__ == "__main__":
    main()
