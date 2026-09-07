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


# --------------------------------------------------------------- patch-driven
# The code_evidence path above is capped at the 34 CVEs that carry a stored
# vuln/patched pair. The fix commits themselves cover far more of the snapshot
# corpus, so drive extraction from the patch diffs and keep code_evidence as a
# fallback.
TIERA = os.environ.get("TIERA_JSON",
                       r"C:\Users\user\Desktop\cve-genie\webapp\data\icsvex_tierA.json")
EXT_SRC = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
SKIP_SEG = {"test", "tests", "example", "examples", "fuzz", "fuzzing", "doc",
            "docs", "benchmark", "benchmarks", ".github", "contrib"}
_FILE_RE = re.compile(r"^Filename: (.+?):$", re.M)
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@", re.M)


def _iter_hunks(content):
    """Yield (path, old_start_line, [removed lines]) for each hunk of a patch blob."""
    parts = _FILE_RE.split(content or "")
    for i in range(1, len(parts) - 1, 2):
        path, body = parts[i], parts[i + 1]
        marks = list(_HUNK_RE.finditer(body))
        for j, m in enumerate(marks):
            end = marks[j + 1].start() if j + 1 < len(marks) else len(body)
            block = body[m.end():end]
            removed = [l[1:] for l in block.splitlines() if l.startswith("-")]
            yield path, int(m.group(1)), removed


PATCHD = os.path.join(BASE, "data", "patches")
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$", re.M)


def _iter_hunks_diff(text):
    """Same, for a real unified diff (tools/fetch_patches.py cache)."""
    marks = list(_DIFF_FILE_RE.finditer(text or ""))
    for i, fm in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        body = text[fm.end():end]
        path = fm.group(1).strip()
        hs = list(_HUNK_RE.finditer(body))
        for j, m in enumerate(hs):
            hend = hs[j + 1].start() if j + 1 < len(hs) else len(body)
            block = body[m.end():hend]
            removed = [l[1:] for l in block.splitlines() if l.startswith("-")]
            yield path, int(m.group(1)), removed


def load_patch_hunks(cve, tier_blobs):
    """Hunk iterators for a CVE: the full cached diffs when present, else the
    tier-A blobs (truncated at 6000 chars, so source hunks are often missing)."""
    d = os.path.join(PATCHD, cve)
    if os.path.isdir(d):
        diffs = [os.path.join(d, f) for f in sorted(os.listdir(d)) if f.endswith(".diff")]
        if diffs:
            return [("diff", open(p, encoding="utf-8", errors="ignore").read())
                    for p in diffs]
    return [("blob", b) for b in (tier_blobs or [])]


def _is_src(path):
    low = path.replace("\\", "/").lower()
    if os.path.splitext(low)[1] not in EXT_SRC:
        return False
    return not (SKIP_SEG & set(low.split("/")[:-1]))


def _find_by_suffix(root, relpath):
    """Locate a patch path in the snapshot by the longest matching path suffix."""
    want = [p for p in relpath.replace("\\", "/").split("/") if p]
    best, best_n = None, 0
    for dp, _dn, fns in os.walk(root):
        for fn in fns:
            if fn != want[-1]:
                continue
            have = os.path.join(dp, fn).replace("\\", "/").split("/")
            n = 0
            while n < len(want) and n < len(have) and want[-1 - n] == have[-1 - n]:
                n += 1
            if n > best_n:
                best, best_n = os.path.join(dp, fn), n
    return best


def enclosing_funcs_from_patch(cve, sources):
    """Enclosing function names for every source hunk of a CVE's fix commit(s).

    `sources` is [(kind, text)] from load_patch_hunks: "diff" = a real unified
    diff, "blob" = the truncated tier-A rendering."""
    root = os.path.join(SNAP, cve)
    if not os.path.isdir(root):
        return None, "no-snapshot"
    hit = Counter()
    cache = {}
    seen_src = missing_file = False
    for kind, content in sources:
        it = _iter_hunks_diff(content) if kind == "diff" else _iter_hunks(content)
        for path, old_start, removed in it:
            if not _is_src(path):
                continue
            seen_src = True
            if path not in cache:
                fpath = _find_by_suffix(root, path)
                ent = False
                if not fpath:
                    missing_file = True
                if fpath:
                    try:
                        ent = (_funcs_by_line(fpath),
                               open(fpath, encoding="utf-8",
                                    errors="ignore").read().splitlines())
                    except Exception:
                        ent = False
                cache[path] = ent
            if not cache[path]:
                continue
            spans, text = cache[path]
            matched = False
            for a in _distinctive_lines("\n".join(removed)):
                for i, line in enumerate(text):
                    if a in line:
                        for s, e, nm in spans:
                            if s <= i <= e:
                                hit[nm] += 1
                                matched = True
                        break  # first occurrence is enough per anchor
            if not matched:
                # no anchor matched (snapshot != patch parent): fall back to the
                # hunk's old-side start line
                i = old_start - 1
                for s, e, nm in spans:
                    if s <= i <= e:
                        hit[nm] += 1
    if not hit:
        if not seen_src:
            return None, "no-source-hunk"
        return None, ("file-not-in-snapshot" if missing_file else "anchors-unmatched")
    top = hit.most_common()
    best = [nm for nm, c in top if c >= max(2, top[0][1] // 2)]
    return (best or [top[0][0]]), "ok"


def main():
    ce = json.load(open(CE, encoding="utf-8")) if os.path.exists(CE) else {}
    tier = json.load(open(TIERA, encoding="utf-8")) if os.path.isfile(TIERA) else {}
    patches = {}
    for cve, v in tier.items():
        blobs = [pc.get("content") or "" for pc in (v.get("patch_commits") or [])]
        if any(blobs):
            patches[cve] = blobs

    snaps = ({d for d in os.listdir(SNAP) if os.path.isdir(os.path.join(SNAP, d))}
             if os.path.isdir(SNAP) else set())
    # only a CVE with a source snapshot can be resolved at all
    out, stats = {}, Counter()
    for cve in sorted(snaps):
        funcs, why, via = None, "no-input", "-"
        sources = load_patch_hunks(cve, patches.get(cve))
        if sources:
            funcs, why = enclosing_funcs_from_patch(cve, sources)
            via = sources[0][0]
        if not funcs and isinstance(ce.get(cve), dict) and ce[cve].get("file"):
            f2, w2 = enclosing_funcs(cve, ce[cve])
            if f2:
                funcs, why, via = f2, w2, "code_ev"
            elif via == "-":
                why, via = w2, "code_ev"
        stats["%s/%s" % (via, why)] += 1
        if funcs:
            out[cve] = funcs
            print("%-18s %-8s -> %s" % (cve, via, funcs[:6]))
        else:
            print("%-18s %-8s -- %s" % (cve, via, why))
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("\n== %d / %d CVEs resolved to a vulnerable function ==" % (len(out), sum(stats.values())))
    for k, v in sorted(stats.items(), key=lambda x: -x[1]):
        print("   %-28s %d" % (k, v))
    print("->", OUT)


if __name__ == "__main__":
    main()
