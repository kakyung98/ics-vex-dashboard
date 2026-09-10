#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Q4 (inline mitigations) - collect the evidence, then decide what it licenses.

Two independent kinds of "mitigation" show up in this corpus, and they are NOT
equally strong:

  compile-time exclusion  the vulnerable function sits inside an #ifdef that the
                          recorded build never defines. The code is not in the
                          shipped binary at all.
  hardening flags         the build carries -D_FORTIFY_SOURCE=2,
                          -fstack-protector-strong, RELRO/NOW, CFI, ...

Evidence is gathered here from two offline sources: the preprocessor guards
around the target function (tree-sitter over the snapshot) and the actual
compile lines in results/verify_build_logs/<CVE>.log.

Output: results/mitigation_scan.json
"""
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from vex_decision import NOT_AFFECTED, UNDER_INV  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(BASE, "data", "source_snapshots")
IDX = os.path.join(BASE, "data", "func_index")
TARGETS = os.path.join(BASE, "data", "vuln_targets.json")
LOGS = os.path.join(BASE, "results", "verify_build_logs")
OUT = os.path.join(BASE, "results", "mitigation_scan.json")

HARDENING = {
    "_FORTIFY_SOURCE": r"-D_FORTIFY_SOURCE=(\d)",
    "stack_protector": r"-fstack-protector(?:-strong|-all)?\b",
    "pie": r"-fPIE\b|-pie\b",
    "relro_now": r"-Wl,-z,relro|-Wl,-z,now",
    "cfi": r"-fsanitize=cfi\b",
    "sanitizer": r"-fsanitize=(?:address|undefined)\b",
}
_IFDEF = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")


def guards_around(path, start_line):
    """The #if/#ifdef stack enclosing a line - what must hold for it to compile."""
    stack = []
    try:
        lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return []
    for i, ln in enumerate(lines[:start_line]):
        m = _IFDEF.match(ln)
        if not m:
            continue
        kind, rest = m.group(1), m.group(2).strip()
        if kind in ("if", "ifdef", "ifndef"):
            stack.append("%s %s" % (kind, rest[:80]))
        elif kind == "endif" and stack:
            stack.pop()
        elif kind in ("elif", "else") and stack:
            stack[-1] = "%s %s" % (kind, rest[:80])
    return stack


# A compiler invocation, not arbitrary log text. The first cut of this scanner
# used a bare `-D(\w+)` over the whole log and harvested substrings out of
# prose ("...-Digital..." -> "igital"), which would have been read as build
# configuration. Flags are only meaningful on a real compile line.
# The command must START with a compiler token - `clang-format` and configure
# chatter ("checking whether gcc accepts -g... yes") both matched a looser
# pattern and were counted as builds, which is how the first run "cleared" five
# CVEs whose files were in fact compiled.
_COMPILE = re.compile(
    r"(?:^|[\s;&|(])(?:gcc|clang|cc|g\+\+|c\+\+)(?![\w.-])[^\n]*?\s-c(?=\s)[^\n]*",
    re.M)
_DEFINE = re.compile(r"(?:^|\s)-D([A-Za-z_]\w*)")
_CSRC = re.compile(r"[\w./+-]+\.(?:c|cc|cpp|cxx)\b")


def build_flags(cve):
    """What the recorded build actually did: its compile lines, defines, flags."""
    p = os.path.join(LOGS, cve + ".log")
    if not os.path.exists(p):
        return None
    try:
        txt = open(p, encoding="utf-8", errors="ignore").read()
    except OSError:
        return None
    lines = [ln for ln in _COMPILE.findall(txt) if _CSRC.search(ln)]
    if not lines:
        return {"compile_lines": 0, "defines": [], "hardening": {}, "compiled": []}
    joined = "\n".join(lines)
    found = {}
    for name, pat in HARDENING.items():
        m = re.search(pat, joined)
        if m:
            found[name] = m.group(0)
    compiled = {os.path.basename(f) for ln in lines for f in _CSRC.findall(ln)}
    return {"compile_lines": len(lines),
            "defines": sorted(set(_DEFINE.findall(joined))),
            "hardening": found,
            "compiled": sorted(compiled)}



def _project_sources(root):
    out = set()
    for dp, _dn, fns in os.walk(root):
        for f in fns:
            if f.endswith((".c", ".cc", ".cpp", ".cxx")):
                out.add(f)
    return out


def _coverage(root, build):
    """Fraction of the project's sources the log shows being compiled."""
    if not build or not build.get("compiled"):
        return 0.0
    src = _project_sources(root)
    return len(set(build["compiled"]) & src) / len(src) if src else 0.0


def _included_by(root, basenames):
    """Files that textually #include one of these - an indirect compile path."""
    if not basenames:
        return []
    pat = re.compile(r'#\s*include\s*[<"][^">]*(?:%s)[">]'
                     % "|".join(re.escape(b) for b in basenames))
    hits = []
    for dp, _dn, fns in os.walk(root):
        for f in fns:
            if not f.endswith((".c", ".cc", ".cpp", ".cxx")):
                continue
            if f in basenames:
                continue
            p = os.path.join(dp, f)
            try:
                if pat.search(open(p, encoding="utf-8", errors="ignore").read()):
                    hits.append(os.path.relpath(p, root).replace("\\", "/"))
            except OSError:
                continue
    return hits[:5]


def scan(cve, targets):
    idxp = os.path.join(IDX, cve + ".json")
    if not os.path.exists(idxp):
        return {"cve": cve, "status": "no-index"}
    index = json.load(open(idxp, encoding="utf-8"))["functions"]
    root = os.path.join(SNAP, cve)
    guards, files = {}, {}
    for t in targets:
        for f, st, _e in index.get(t, [])[:3]:
            files.setdefault(t, []).append(f)
            g = guards_around(os.path.join(root, f.replace("/", os.sep)), st)
            if g:
                guards.setdefault(t, []).append({"file": f, "guards": g})
    build = build_flags(cve)
    tgt_files = {os.path.basename(f) for fs in files.values() for f in fs}
    return {"cve": cve, "status": "ok", "targets": targets, "files": files,
            "guards": guards, "build": build,
            "build_coverage": _coverage(root, build),
            "included_by": _included_by(root, tgt_files)}


# Minimum compile lines before "this file was never compiled" is an argument
# rather than a gap in the log (silent make rules echo nothing).
MIN_COMPILE_LINES = 10
# fraction of the project's .c files the log must show being compiled
MIN_COVERAGE = 0.5


def classify(row):
    """What the collected mitigation evidence licenses. Returns
    (status, justification, reason).

    Three kinds of evidence turn up, and only one of them is strong enough to
    lower a status:

    1. The target's source file never appears on a compile line, in a log that
       clearly shows the project being compiled. The code is not in the shipped
       binary. The honest CISA label for that is `vulnerable_code_not_present`
       (Q1) - NOT `inline_mitigations_already_exist`, which asserts that a
       mitigation stops an attack against code that IS present.

    2. A preprocessor guard (`#ifdef ENABLE_FOO`) whose macro is absent from the
       build's -D flags. This does NOT clear: autoconf projects define most
       macros in a generated config.h, never on the command line, so absence
       from -D says nothing about whether the macro is defined. Reading it as
       exclusion would repeat the Q3 mistake - treating "not observed" as "not
       there".

    3. Hardening flags (_FORTIFY_SOURCE, stack protector, RELRO, CFI). These
       convert memory corruption into a clean abort(); the corruption is stopped
       but the denial of service is not. An impact reduction is not a
       justification, so it is recorded and nothing more.
    """
    b = row.get("build")
    if row.get("status") != "ok" or not row.get("targets"):
        return UNDER_INV, None, "no target to evaluate"
    if not b or b.get("compile_lines", 0) < MIN_COMPILE_LINES:
        return UNDER_INV, None, "no usable build log; guards cannot be resolved"

    compiled = set(b.get("compiled") or [])
    tgt_files = {os.path.basename(f)
                 for fs in (row.get("files") or {}).values() for f in fs}
    if tgt_files and not (tgt_files & compiled):
        # Absence from the log is only an argument when the log demonstrably
        # built the project. Two ways it lies:
        cov = row.get("build_coverage", 0.0)
        if cov < MIN_COVERAGE:
            return (UNDER_INV, None,
                    "log compiled %.0f%% of the project's sources - too partial "
                    "to argue absence from" % (100 * cov))
        # ...and a file can enter the binary without ever being a compiler
        # argument, if another translation unit #includes it (sqlite's
        # amalgamation is the canonical case).
        if row.get("included_by"):
            return (UNDER_INV, None,
                    "%s is #included by %s, so it compiles indirectly"
                    % (sorted(tgt_files)[0], row["included_by"][0]))
        return (NOT_AFFECTED, "vulnerable_code_not_present",
                "none of %s appears on a compile line in a build that compiled "
                "%.0f%% of the project" % (sorted(tgt_files)[:3], 100 * cov))

    if row.get("guards"):
        return (UNDER_INV, None,
                "guarded by %s; -D flags cannot prove the macro is undefined "
                "(config.h is not on the command line)"
                % ";".join(g["guards"][-1] for gs in row["guards"].values() for g in gs[:1])[:120])

    if b.get("hardening"):
        return (UNDER_INV, None,
                "hardening present (%s) - reduces impact, does not justify a status"
                % ",".join(sorted(b["hardening"])))

    return UNDER_INV, None, "no mitigation evidence"


def main():
    known = json.load(open(TARGETS, encoding="utf-8")) if os.path.exists(TARGETS) else {}
    rows = []
    for cve in sorted(os.listdir(SNAP)):
        k = known.get(cve) or {}
        rows.append(scan(cve, k.get("targets") or []))
    verdicts = collections.Counter()
    for r in rows:
        st, just, why = classify(r)
        r["vex"], r["justification"], r["reason"] = st, just, why
        verdicts[st] += 1
        if st == NOT_AFFECTED:
            print("CLEARED %-18s %s | %s" % (r["cve"], just, why))
    json.dump(rows, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    g = sum(1 for r in rows if r.get("guards"))
    b = sum(1 for r in rows if r.get("build"))
    hard = sum(1 for r in rows if (r.get("build") or {}).get("hardening"))
    print("\n== Q4 mitigation scan ==")
    print("   snapshots             %d" % len(rows))
    print("   target under #ifdef   %d" % g)
    print("   build log available   %d" % b)
    print("   hardening flags seen  %d" % hard)
    print("   verdicts              %s" % dict(verdicts))
    print("->", OUT)


if __name__ == "__main__":
    sys.exit(main())
