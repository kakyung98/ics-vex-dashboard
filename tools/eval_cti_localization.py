#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Does the LLM name the function the fix actually edits?  (supplementary disclosure)

The one component of the VEX-v2 pipeline that had no measurement at all. Item #4
scores the `affected` verdict, which `vex_judge_v2` decides at Q2 - and Q2 looks for a
function somebody has to name first. For 83 of the 267 collected CVEs that somebody is
the **LLM** (`tools/cti_extract.py`), not the patch: `source_locations.json` records
`localization_source: "cti"`. 33 of item #4's 142 scored verdicts (23.2%) rest on a
name the model produced.

What was verified before this is only that the name **exists in the source tree**.
Existence is not correctness: a model that answers `main` names a function that is
certainly present and almost certainly not the vulnerable one. So the published figure
had a load-bearing component whose error rate was unknown.

THE AUTHORITY, and what it can and cannot say
---------------------------------------------
The fix commit's own diff. Every hunk header git emits carries the enclosing function
("@@ -989,7 +989,7 @@ static int send_dg(...)"), so the set of functions a fix edits
is readable without running anything, and it comes from upstream rather than from this
repository's tooling.

It is a real two-sided key, unlike the Q3/Q4 axis - a named function absent from the
edited set is a genuine miss - so a precision IS reported here. But it is agreement
with the fix, not ground truth about vulnerability, and the gap matters in one
direction: a fix sometimes lands in the CALLER (a guard added before the call) or in a
helper, while the vulnerable function the advisory describes is untouched. Those
surface as disagreements the model did not necessarily get wrong. The figure is
therefore named `agreement`, and the disagreement list is printed in full so each case
can be read rather than averaged away.

    python tools/eval_cti_localization.py
    python tools/eval_cti_localization.py --out results/cti_localization.json
"""
import argparse
import collections
import glob
import json
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOC = os.path.join(BASE, "data", "source_locations.json")
CTI = os.path.join(BASE, "data", "cti_extractions.json")
PATCHES = os.path.join(BASE, "data", "patches")
OUT = os.path.join(BASE, "results", "cti_localization.json")

# "@@ -a,b +c,d @@ <enclosing context>" - git's funcname hint.
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@\s*(.*)$")
_FILE = re.compile(r"^\+\+\+ b/(.*)$")
# A C identifier immediately followed by '(' - the call/definition shape. Anchored to
# the LAST such identifier in the context, because a hint reads
# "static int send_dg (int statp, ...)" and the function is `send_dg`, not `int`.
_IDENT = re.compile(r"([A-Za-z_]\w*)\s*\(")
# Definitions appearing in the changed lines themselves, for diffs whose hunk hints are
# empty (a fix at file scope, or a language git has no funcname pattern for).
_DEFLINE = re.compile(r"^[+-]\s*(?:[A-Za-z_][\w\s\*]*?\s)?\**([A-Za-z_]\w*)\s*\([^;]*$")

_CODE_EXT = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".py", ".java", ".go")

# A diff touching more code files than this is not a fix signature. CVE-2022-0778's
# cache holds four diffs, one of which edits 339 files - a merge or release commit
# that happens to carry the fix. Reading an authority out of it yields 179 "edited
# functions", which agrees with almost any guess and so measures nothing. The repo
# already learned this for the patch gate, which reads the vulnerable function's own
# file first "because a fix commit touches more than the vulnerability".
MAX_FILES_PER_FIX = 20

# A fix commit ships its regression test beside the fix. Reading the authority out of
# the test file makes the answer key name the TEST's functions: libexpat's
# CVE-2022-22822 / -23852 / -25315 each came out "the fix edits START_TEST and
# XML_SetBillionLaughsAttackProtectionActivationThreshold", which no model would ever
# name and which says nothing about where the vulnerability is.
_TEST_PATH = re.compile(r"(^|/)(tests?|testing|spec|regress|fuzz|benchmarks?)(/|$)"
                        r"|(^|/)test_[^/]*$|_test\.[ch]$|(^|/)[^/]*_tests?\.[^/]+$",
                        re.I)


def _canon(name):
    """Fold the naming conventions that make one function look like two.

    glibc exports `getcwd` and implements `__getcwd` / `__getcwd_generic`; the leading
    double underscore is the reserved-identifier convention, not a different function.
    This repo already treats `__` names as an alias axis in the Q3 answer key, so the
    same rule applies here rather than charging the model for knowing the public name.
    """
    n = (name or "").strip()
    n = re.sub(r"^_+", "", n)
    n = re.sub(r"_(generic|internal|impl|r)$", "", n)
    return n.lower()

# Words that look like calls but are never the edited function: control flow, common
# macros, and the sizeof/cast shapes that litter C hunk context.
_NOISE = {
    "if", "for", "while", "switch", "return", "sizeof", "defined", "do", "else",
    "case", "goto", "static", "inline", "struct", "union", "enum", "const", "void",
    "int", "char", "long", "short", "unsigned", "signed", "float", "double",
    "assert", "typeof", "__attribute__", "printf", "fprintf", "memset", "memcpy",
}


def _scan(path):
    """Read one diff: its hunk-header function hints, its fallback definition names,
    and the code files it touches."""
    hints, deflines, files, tests, hunks = set(), set(), set(), set(), 0
    current = None
    for line in open(path, encoding="utf-8", errors="replace"):
        m = _FILE.match(line)
        if m:
            current = m.group(1).strip()
            if current.endswith(_CODE_EXT) and not _TEST_PATH.search(current):
                files.add(current)
            elif current.endswith(_CODE_EXT):
                tests.add(current)
            continue
        if current is None or current not in files:
            continue
        m = _HUNK.match(line)
        if m:
            hunks += 1
            found = [n for n in _IDENT.findall(m.group(1) or "") if n not in _NOISE]
            if found:
                # The last identifier before '(' is the function being declared;
                # earlier ones are its return type or storage class.
                hints.add(found[-1])
            continue
        if line[:1] in "+-":
            m = _DEFLINE.match(line.rstrip())
            if m and m.group(1) not in _NOISE:
                deflines.add(m.group(1))
    return hints, deflines, files, tests, hunks


def edited_functions(cve):
    """The functions the CVE's fix edits, with the diffs that cannot say skipped.

    Prefers git's own hunk-header funcname hints over names scraped from the changed
    lines. The hints are git's dedicated heuristic and are reliable; the scrape picks
    up macros, struct initialisers and `Copyright` lines, so it is a fallback used
    only when a diff yields no hint at all.
    """
    hints, deflines, files, tests, hunks, skipped = (set(), set(), set(), set(), 0, [])
    for path in sorted(glob.glob(os.path.join(PATCHES, cve, "*.diff"))):
        h, d, f, t, n = _scan(path)
        if len(f) + len(t) > MAX_FILES_PER_FIX:
            skipped.append({"diff": os.path.basename(path), "code_files": len(f) + len(t)})
            continue
        hints |= h
        deflines |= d
        files |= f
        tests |= t
        hunks += n
    return (hints or deflines), files, tests, hunks, skipped, bool(hints)


def score(loc_path=LOC, cti_path=CTI):
    loc = json.load(open(loc_path, encoding="utf-8"))
    cti = json.load(open(cti_path, encoding="utf-8"))

    rows, held, file_answer = [], collections.Counter(), []
    for cve, rec in sorted(loc.items()):
        if rec.get("localization_source") != "cti":
            held["not LLM-localised (patch-derived or none)"] += 1
            continue
        named = [f.get("name") for f in (rec.get("functions") or []) if f.get("name")]
        if not named:
            named = (cti.get(cve) or {}).get("vulnerable_functions") or []
        if not named:
            held["the model named no function"] += 1
            continue
        # A name ending in a source extension is not a wrong function - it is the
        # wrong KIND of answer. The model was asked for functions and returned files
        # (`s2_lib.c`, `queue.c`). Scoring those as misses would fold a schema failure
        # into the accuracy figure and overstate how often the model picks the wrong
        # function; they are counted separately and reported on their own.
        files_as_funcs = [n for n in named if n.lower().endswith(_CODE_EXT)]
        named = [n for n in named if n not in files_as_funcs]
        if not named:
            held["the model returned FILE names, not functions"] += 1
            file_answer.append({"cve": cve, "component": rec.get("component"),
                                "returned": files_as_funcs})
            continue
        if not glob.glob(os.path.join(PATCHES, cve, "*.diff")):
            held["no fix-commit diff to compare against"] += 1
            continue
        edited, files, tests, hunks, skipped, from_hints = edited_functions(cve)
        if not edited:
            held["diff exposes no function context (docs/build-only, or no hint)"] += 1
            continue
        # Match on the canonical form so `getcwd` meets glibc's `__getcwd`.
        canon = {_canon(e): e for e in edited}
        hit = sorted({canon[_canon(n)] for n in named if _canon(n) in canon})
        # Did the model at least land in a file the fix touches? This separates "wrong
        # area entirely" (u-boot's `memset` against a fix in ext4fs_read_file) from
        # "right area, the fix landed in a neighbour" (SSL_check_chain against its
        # helper tls1_check_sig_alg) - two failures that deserve different readings.
        named_files = {(f.get("file") or "").replace("\\", "/")
                       for f in (rec.get("functions") or []) if f.get("file")}
        same_file = any(any(nf.endswith("/" + ef) or nf.endswith(ef)
                            for ef in files) for nf in named_files)
        rows.append({
            "cve": cve, "component": rec.get("component"),
            "named_by_llm": named, "edited_by_fix": sorted(edited)[:24],
            "edited_count": len(edited), "files_touched": len(files),
            "test_files_ignored": len(tests), "hunks": hunks,
            "authority": "hunk-header hints" if from_hints else "definition scrape",
            "oversized_diffs_skipped": skipped,
            "also_returned_files": files_as_funcs or None,
            "agree": bool(hit), "matched": hit, "same_file_as_fix": same_file,
        })

    tp = sum(1 for r in rows if r["agree"])
    fp = len(rows) - tp
    # A disagreement where the named function lives in a file the fix edits is a
    # different failure from one that lands nowhere near it, so both are reported.
    near = sum(1 for r in rows if not r["agree"] and r.get("same_file_as_fix"))
    wrong = fp - near
    return {
        "test": "CTI localization agreement - does the LLM name the function the fix edits?",
        "status": "supplementary disclosure - not a certification test item",
        "sut": "tools/cti_extract.py (Ollama qwen2.5-coder:14b) -> source_locate Q2 target",
        "authority": "the fix commit's own diff: the functions its hunks edit "
                     "(git funcname hints + definition lines in the changed text)",
        "unit": "one CVE whose Q2 target came from the model",
        "scored": len(rows), "agree": tp, "disagree": fp,
        "agreement": round(tp / len(rows), 4) if rows else None,
        "near_miss_same_file": near,
        "wrong_area": wrong,
        "file_level_agreement": round((tp + near) / len(rows), 4) if rows else None,
        "file_level_note": (
            "exact + near-miss: the model named a function defined in a file the fix "
            "edits. Reported beside the exact figure because the two failures differ - "
            "SSL_check_chain against its own helper tls1_check_sig_alg is not the same "
            "error as u-boot's `memset` against a fix in ext4fs_read_file."
        ),
        "held_out": dict(held),
        "file_names_returned_instead_of_functions": file_answer,
        "held_out_total": sum(held.values()),
        "interpretation": (
            "Agreement with the fix, NOT ground truth about which function is "
            "vulnerable. A fix that lands in the caller or a helper counts as a "
            "disagreement even where the model named the function the advisory "
            "describes, so the disagreements are listed rather than averaged away."
        ),
        "why_precision_is_reportable_here": (
            "Unlike the Q3/Q4 axis this key is two-sided: a named function absent from "
            "the fix's edited set is a genuine miss, so the negative class exists and "
            "the figure describes the model rather than the key."
        ),
        "disagreements": [r for r in rows if not r["agree"]],
        "cases": rows,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    res = score()
    enc = "utf-8"

    def say(msg):
        import sys
        e = getattr(sys.stdout, "encoding", None) or enc
        print(str(msg).encode(e, "replace").decode(e, "replace"))

    say("=== CTI localization agreement (supplementary disclosure) ===")
    say("  SUT      : %s" % res["sut"])
    say("  authority: %s" % res["authority"])
    say("  scored   : %d CVEs   agree %d / disagree %d"
        % (res["scored"], res["agree"], res["disagree"]))
    say("  AGREEMENT= %s   (exact function match)"
        % ("-" if res["agreement"] is None else "%.4f" % res["agreement"]))
    say("     of the %d disagreements: %d named a function in a file the fix edits, "
        "%d landed elsewhere" % (res["disagree"], res["near_miss_same_file"],
                                 res["wrong_area"]))
    say("     file-level agreement = %s   (exact + near-miss)"
        % ("-" if res["file_level_agreement"] is None
           else "%.4f" % res["file_level_agreement"]))
    say("  held out :")
    for k, v in sorted(res["held_out"].items(), key=lambda kv: -kv[1]):
        say("      %-62s %d" % (k, v))
    if res["disagreements"] and not a.quiet:
        say("\n  disagreements (model named / fix edited):")
        for r in res["disagreements"]:
            say("    %-18s %-12s named=%s" % (r["cve"], r["component"] or "",
                                              ", ".join(r["named_by_llm"])[:46]))
            say("    %-18s %-12s fix  =%s%s"
                % ("", "", ", ".join(r["edited_by_fix"][:6]),
                   " (+%d more)" % (r["edited_count"] - 6)
                   if r["edited_count"] > 6 else ""))
    json.dump(res, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    say("\n-> %s" % a.out)


if __name__ == "__main__":
    main()
