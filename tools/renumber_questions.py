#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Renumber the VEX decision gates Q0-Q3 to Q1-Q4, across code, docs and data.

The gates were numbered from zero because the patch gate was added in front of an
existing Q1-Q3 chain, which left the pipeline reading Q0/Q1/Q2/Q3 while every
description of it counts four questions. This shifts each label up by one:

    Q0 patch gate        -> Q1
    Q1 presence          -> Q2
    Q2 reachability      -> Q3
    Q3 controllability   -> Q4

Done as a SINGLE pass with a callback rather than four ordered replacements. The
naive way - replace Q3 with Q4, then Q2 with Q3, ... - is correct only if the
passes never see each other's output, and they do: a Q2 rewritten to Q3 is then
rewritten again to Q4 by the next pass. One regex, one visit per occurrence, no
ordering to get wrong.

`q23` (the paired reachability/controllability artefacts) becomes `q34`, and the
data keys move with the code so a record cannot say `q1` while the module reading
it calls that question Q2.

    python tools/renumber_questions.py --dry-run     # report, change nothing
    python tools/renumber_questions.py               # apply
"""
import argparse
import io
import json
import os
import re
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Text files that carry the labels. Generated output (site/) is excluded: it is
# rebuilt from these sources, and rewriting it here would hide a rebuild that did
# not happen.
TEXT_EXT = (".py", ".md")
SKIP_DIRS = {".git", "site", "node_modules", "__pycache__", "data", "results",
             "models", "venv", ".venv"}

# This script must not rewrite itself: its docstring states the mapping and its
# regexes contain the digits, so one pass over its own source would leave a
# migration tool that no longer describes - or performs - the migration.
SKIP_FILES = {os.path.abspath(__file__)}

# A label is Q<n> not preceded by an identifier character (so `_q23_scope` and
# `foo.q1` both match) and not followed by a digit (so `Q23` is not half-eaten).
UPPER = re.compile(r"(?<![A-Za-z0-9])Q([0-3])(?![0-9])")
LOWER = re.compile(r"(?<![A-Za-z0-9])q([0-3])(?![0-9])")
PAIR = re.compile(r"(?<![A-Za-z0-9])([Qq])23(?![0-9])")


# `Q1-Q4` (or with an en dash) already reads 1-to-4, because it names CISA's OWN
# numbering of the four justification questions rather than this repository's gate
# labels. Shifting it would produce `Q2-Q4` and misquote CISA, so it is protected
# across the pass and restored afterwards.
CISA_RANGE = re.compile(r"Q1\s*[-–—]\s*Q4")
# The sentinel must carry no gate label of its own. A first attempt used
# "CISA_Q1_Q4", whose own Q1 was shifted to Q2 by the very pass it was meant to
# sit out, so the restore afterwards matched nothing and the guard did the
# opposite of its job - silently, since the output still looked renumbered.
_GUARD = "￼CISARANGE￼"


def shift(text):
    """Every gate label in `text`, moved up by one."""
    guarded = []

    def _hide(m):
        guarded.append(m.group(0))
        return _GUARD
    text = CISA_RANGE.sub(_hide, text)
    text = PAIR.sub(lambda m: m.group(1) + "34", text)
    text = UPPER.sub(lambda m: "Q%d" % (int(m.group(1)) + 1), text)
    text = LOWER.sub(lambda m: "q%d" % (int(m.group(1)) + 1), text)
    for original in guarded:
        text = text.replace(_GUARD, original, 1)
    return text


def text_files():
    for root, dirs, files in os.walk(BASE):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            p = os.path.join(root, f)
            if f.endswith(TEXT_EXT) and os.path.abspath(p) not in SKIP_FILES:
                yield p


# --- data ------------------------------------------------------------------
# Only these keys/values are gate labels. A blanket shift over the data would
# also rewrite CVE text and component names that happen to contain `q1`.
def migrate_json(path, dry):
    """Returns a description of what changed, or None."""
    rel = os.path.relpath(path, BASE)
    if not os.path.isfile(path):
        return None
    name = os.path.basename(path)
    changed = 0

    if name.endswith(".jsonl"):
        rows = [json.loads(l) for l in io.open(path, encoding="utf-8") if l.strip()]
        for r in rows:
            if r.get("question") in ("Q2", "Q3"):
                r["question"] = "Q%d" % (int(r["question"][1]) + 1)
                changed += 1
            if isinstance(r.get("test_case_id"), str):
                new = PAIR.sub(lambda m: m.group(1) + "34", r["test_case_id"])
                new = LOWER.sub(lambda m: "q%d" % (int(m.group(1)) + 1), new)
                if new != r["test_case_id"]:
                    r["test_case_id"] = new
        if changed and not dry:
            with io.open(path, "w", encoding="utf-8", newline="\n") as f:
                for r in rows:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
        return "%s: %d question labels" % (rel, changed) if changed else None

    d = json.load(io.open(path, encoding="utf-8"))

    def walk(node):
        nonlocal changed
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                nk = k
                if re.fullmatch(r"q[0-3]", k) or re.fullmatch(r"q[0-3]_.*", k):
                    nk = LOWER.sub(lambda m: "q%d" % (int(m.group(1)) + 1), k)
                    changed += 1
                out[nk] = walk(v)
            return out
        if isinstance(node, list):
            return [walk(v) for v in node]
        return node

    d2 = walk(d)
    if changed and not dry:
        json.dump(d2, io.open(path, "w", encoding="utf-8", newline="\n"),
                  ensure_ascii=False, indent=2)
    return "%s: %d keys" % (rel, changed) if changed else None


DATA_FILES = [
    "data/source_locations.json",
    "data/source_locations_patched.json",
    "data/vex_v2.json",
    "data/vex_v2_pregate.json",
    "data/vex_v2_patched.json",
    "data/vex_q23_gt.jsonl",
]

# old -> new path. git mv keeps the history attached to the renamed file.
RENAMES = [
    ("tools/build_q23_gt.py", "tools/build_q34_gt.py"),
    ("tools/eval_q23_agreement.py", "tools/eval_q34_agreement.py"),
    ("tools/select_q23_targets.py", "tools/select_q34_targets.py"),
    ("data/vex_q23_gt.jsonl", "data/vex_q34_gt.jsonl"),
    ("data/vex_q23_gt_manifest.json", "data/vex_q34_gt_manifest.json"),
    ("data/q23_targets.json", "data/q34_targets.json"),
    ("results/q23_agreement.json", "results/q34_agreement.json"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    dry = a.dry_run

    print("-- text (%s)" % ("dry run" if dry else "applying"))
    n_files = 0
    for p in sorted(text_files()):
        src = io.open(p, encoding="utf-8").read()
        out = shift(src)
        if out != src:
            n_files += 1
            hits = (len(UPPER.findall(src)) + len(LOWER.findall(src))
                    + len(PAIR.findall(src)))
            print("   %-46s %d labels" % (os.path.relpath(p, BASE), hits))
            if not dry:
                io.open(p, "w", encoding="utf-8", newline="\n").write(out)
    print("   %d files" % n_files)

    print("-- data")
    for rel in DATA_FILES:
        msg = migrate_json(os.path.join(BASE, rel), dry)
        if msg:
            print("   " + msg)

    print("-- renames")
    for old, new in RENAMES:
        op, np_ = os.path.join(BASE, old), os.path.join(BASE, new)
        if not os.path.exists(op):
            continue
        print("   %s -> %s" % (old, new))
        if not dry:
            r = subprocess.run(["git", "mv", old, new], cwd=BASE,
                               capture_output=True, text=True)
            if r.returncode:                       # untracked file: plain rename
                os.replace(op, np_)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
