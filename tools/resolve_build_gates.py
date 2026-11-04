#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Resolve the build-time gate of every localized vulnerable function.

WHY THIS EXISTS. The 267 source snapshots are component trees (openssl, busybox,
sqlite ...), not ICS product firmware. A product's own source is unobtainable
(METHODOLOGY_V3: source closed for 90.87% of declared parts), so "is the vulnerable
function reachable from the product's entry point" cannot be answered from this
corpus. One VEX justification, however, needs no product source at all:

    vulnerable_code_not_present

An embedded vendor almost always ships a REDUCED build - flash budget forces it. If
the vulnerable function is compiled out under that configuration, it is not in the
shipped binary, and the justification is true as a matter of build fact rather than
inference. This tool extracts that fact.

TWO GATE KINDS, DELIBERATELY NOT MERGED.

  build-rule  The build system declares, in its own files, that an object is linked
              only when a config symbol is set. Evidence is one quotable line:
                busybox  editors/awk.c:36  //kbuild:lib-$(CONFIG_AWK) += awk.o
                u-boot   drivers/.../Makefile  obj-$(CONFIG_USB_FUNCTION_DFU) += f_dfu.o
              Strength: the whole translation unit disappears. Nothing of the
              function survives, symbol included.

  cpp-guard   The function body sits inside a preprocessor conditional. Evidence is
              the #if stack active at the function's first line:
                openssl  ssl/d1_both.c  #ifndef OPENSSL_NO_HEARTBEATS
              Strength: weaker per gate - a guard may be on by default, and a second
              definition may exist in the #else branch. Recorded, never silently
              treated as equal to a build-rule gate.

WHAT A GATE IS NOT. A gate is a CONDITION, not a verdict. "Gated by CONFIG_AWK" does
not say whether a given RTU sets CONFIG_AWK - that is a build-profile question,
answered in tools/build_symbol_gt.py. A function with no gate is `unconditional`:
it is in every build of that release, which is itself a usable GT label (the
justification is unavailable, so the CVE cannot be dismissed this way).

Outputs:
  data/build_gates.jsonl            one record per (cve, function)
  results/build_gate_coverage.json  counts, per component and per gate kind

Usage:
  python tools/resolve_build_gates.py
  python tools/resolve_build_gates.py --component busybox --verbose
"""
import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(ROOT, "data", "source_snapshots")
IDX = os.path.join(ROOT, "data", "snapshot_index.json")
LOC = os.path.join(ROOT, "data", "source_locations.json")
OUT_JSONL = os.path.join(ROOT, "data", "build_gates.jsonl")
OUT_SUMMARY = os.path.join(ROOT, "results", "build_gate_coverage.json")

# busybox states its own gating inline, in the .c file:
#   //kbuild:lib-$(CONFIG_AWK) += awk.o
RE_KBUILD = re.compile(r"^//kbuild:\s*lib-\$\((CONFIG_[A-Z0-9_]+)\)\s*\+=\s*(.+)$")
# kbuild/kconfig Makefiles (u-boot, linux):  obj-$(CONFIG_FOO) += bar.o
RE_OBJ = re.compile(r"^\s*(?:obj|lib)-\$\((CONFIG_[A-Z0-9_]+)\)\s*\+?=\s*(.+)$")
RE_OBJ_Y = re.compile(r"^\s*(?:obj|lib)-y\s*\+?=\s*(.+)$")

RE_CPP = re.compile(r"^\s*#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)$")
RE_MACRO = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# tokens that appear in #if expressions but are not configuration macros
CPP_NOISE = {"defined", "sizeof", "__has_include", "__has_attribute"}


def read_text(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def resolve_build_rule(snap_root, rel_path):
    """Find the build rules that link rel_path's object, and the symbols gating them.

    An object is frequently claimed by SEVERAL rules - busybox links
    archival/libarchive/decompress_unlzma.o under CONFIG_UNLZMA, CONFIG_LZCAT and
    CONFIG_LZMA alike. The gate is therefore a DISJUNCTION: the object is linked when
    any one of them is set, and compiled out only when all are unset. Returning just
    the first symbol would understate what a build profile must switch off, so every
    matching rule is kept and `combine` records how to read them.

    An `obj-y` / `lib-y` rule means the object is always linked for that directory;
    it is reported separately so it is never mistaken for an unresolved lookup.
    """
    abs_path = os.path.join(snap_root, rel_path)
    stem = os.path.splitext(os.path.basename(rel_path))[0]
    obj = stem + ".o"
    hits = []
    unconditional = None

    def note(symbol, where, line_no, text, source):
        if symbol not in [h["config_symbol"] for h in hits]:
            hits.append(
                {
                    "config_symbol": symbol,
                    "evidence_file": where,
                    "evidence_line": line_no,
                    "evidence_text": text,
                    "rule_source": source,
                }
            )

    # 1. busybox >= ~1.31: the gate is a comment inside the source file itself.
    if os.path.isfile(abs_path):
        for n, line in enumerate(read_text(abs_path).splitlines(), 1):
            m = RE_KBUILD.match(line.strip())
            if m and obj in m.group(2).split():
                note(m.group(1), rel_path, n, line.strip(), "busybox-inline-kbuild")

    # 2. a build file in the object's own directory. Kbuild.src is older busybox,
    #    Makefile/Kbuild is u-boot and linux.
    mk_dir = os.path.dirname(abs_path)
    for mk_name in ("Kbuild.src", "Kbuild", "Makefile", "Makefile.am"):
        mk = os.path.join(mk_dir, mk_name)
        if not os.path.isfile(mk):
            continue
        rel_mk = os.path.relpath(mk, snap_root).replace("\\", "/")
        for n, line in enumerate(read_text(mk).splitlines(), 1):
            m = RE_OBJ.match(line)
            if m and obj in m.group(2).split():
                note(m.group(1), rel_mk, n, line.strip(), "kbuild-" + mk_name)
            my = RE_OBJ_Y.match(line)
            if my and obj in my.group(1).split():
                unconditional = unconditional or {
                    "evidence_file": rel_mk,
                    "evidence_line": n,
                    "evidence_text": line.strip(),
                    "rule_source": "kbuild-" + mk_name,
                }

    if hits:
        return {
            "gate_kind": "build-rule",
            "config_symbols": [h["config_symbol"] for h in hits],
            "combine": "any",  # linked if ANY symbol is set
            "rules": hits,
        }
    if unconditional:
        return {
            "gate_kind": "build-rule-unconditional",
            "config_symbols": [],
            "combine": None,
            "rules": [unconditional],
        }
    return None


def cpp_stack_at(snap_root, rel_path, start_line):
    """Return the preprocessor conditionals active at start_line.

    Walks the file once, maintaining a stack of (directive, condition, line). The
    stack's contents at start_line are exactly the conditions a compiler must satisfy
    for the function's body to be emitted.
    """
    abs_path = os.path.join(snap_root, rel_path)
    if not os.path.isfile(abs_path) or not start_line:
        return None
    stack = []
    for n, line in enumerate(read_text(abs_path).splitlines(), 1):
        if n >= start_line:
            break
        m = RE_CPP.match(line)
        if not m:
            continue
        kind, rest = m.group(1), m.group(2).strip()
        if kind in ("ifdef", "ifndef", "if"):
            stack.append({"directive": kind, "condition": rest, "line": n})
        elif kind in ("elif", "else"):
            if stack:
                stack[-1] = {
                    "directive": kind,
                    "condition": rest,
                    "line": n,
                    "negates": stack[-1]["condition"],
                }
        elif kind == "endif":
            if stack:
                stack.pop()
    return stack


def macros_of(stack):
    out = []
    for fr in stack:
        for tok in RE_MACRO.findall(fr["condition"]):
            if tok in CPP_NOISE or tok.isdigit():
                continue
            if tok not in out:
                out.append(tok)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--component", help="restrict to one component")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    with open(IDX, encoding="utf-8") as fh:
        index = json.load(fh)
    with open(LOC, encoding="utf-8") as fh:
        locations = json.load(fh)

    records = []
    per_comp = defaultdict(Counter)
    kinds = Counter()
    skipped = Counter()

    for cve in sorted(index):
        meta = index[cve]
        comp = meta["component"]
        if args.component and comp != args.component:
            continue
        loc = locations.get(cve)
        if not loc or not loc.get("any_function_found"):
            skipped["no_localized_function"] += 1
            per_comp[comp]["unlocalized_cve"] += 1
            continue
        snap_root = os.path.join(SNAP, cve)
        if not os.path.isdir(snap_root):
            skipped["snapshot_missing"] += 1
            continue
        for fn in loc.get("functions", []):
            if not fn.get("found"):
                continue
            rel = fn["file"]
            lines = fn.get("lines") or [None]
            rule = resolve_build_rule(snap_root, rel)
            stack = cpp_stack_at(snap_root, rel, lines[0])
            guard_macros = macros_of(stack) if stack else []

            if rule and rule["gate_kind"] == "build-rule":
                kind = "build-rule"
            elif guard_macros:
                kind = "cpp-guard"
            else:
                kind = "unconditional"

            rec = {
                "cve": cve,
                "component": comp,
                "release": meta.get("version"),
                "snapshot": rel.split("/")[0],
                "function": fn["name"],
                "file": rel,
                "start_line": lines[0],
                "localization_source": loc.get("localization_source"),
                "gate_kind": kind,
                "build_rule": rule,
                "cpp_guard": {
                    "depth": len(stack or []),
                    "macros": guard_macros,
                    "stack": stack or [],
                },
            }
            records.append(rec)
            kinds[kind] += 1
            per_comp[comp][kind] += 1
            if args.verbose:
                sym = "|".join((rule or {}).get("config_symbols") or [])                     or ",".join(guard_macros[:3]) or "-"
                print("%-16s %-28s %-12s %s" % (cve, fn["name"], kind, sym))

    os.makedirs(os.path.dirname(OUT_JSONL), exist_ok=True)
    os.makedirs(os.path.dirname(OUT_SUMMARY), exist_ok=True)
    with open(OUT_JSONL, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    gated_cves = {r["cve"] for r in records if r["gate_kind"] in ("build-rule", "cpp-guard")}
    br_cves = {r["cve"] for r in records if r["gate_kind"] == "build-rule"}
    summary = {
        "functions_total": len(records),
        "functions_by_gate_kind": dict(kinds),
        "cves_with_localized_functions": len({r["cve"] for r in records}),
        "cves_with_any_gate": len(gated_cves),
        "cves_with_build_rule_gate": len(br_cves),
        "skipped": dict(skipped),
        "per_component": {c: dict(v) for c, v in sorted(per_comp.items())},
        "top_config_symbols": Counter(
            sym
            for r in records
            if r.get("build_rule")
            for sym in r["build_rule"].get("config_symbols") or []
        ).most_common(25),
        "top_guard_macros": Counter(
            m for r in records for m in r["cpp_guard"]["macros"]
        ).most_common(30),
    }
    with open(OUT_SUMMARY, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)

    print("\nfunctions            %d" % summary["functions_total"])
    for k, n in kinds.most_common():
        print("  %-26s %d" % (k, n))
    print("CVEs localized       %d" % summary["cves_with_localized_functions"])
    print("CVEs with any gate   %d" % summary["cves_with_any_gate"])
    print("CVEs w/ build-rule   %d" % summary["cves_with_build_rule_gate"])
    print("\nwrote %s" % OUT_JSONL)
    print("wrote %s" % OUT_SUMMARY)
    return 0


if __name__ == "__main__":
    sys.exit(main())
