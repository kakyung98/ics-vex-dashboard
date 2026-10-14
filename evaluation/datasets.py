#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Make sure each test item's evaluation dataset exists, and that it is the RIGHT one.

This is the half of the runner that earns its keep. Scoring is a one-line call into
`src/cert_eval`; getting the correct answer key in front of it is where a run goes
quietly wrong, because every builder here has a default that produces a *different,
also-valid* dataset:

  * `build_cpe_match_gt.py` defaults to `--per-vendor 40`. That cap is the retired
    sampling policy: it holds each vendor to 40 positives, which keeps Siemens (58% of
    the corpus) from dominating and in doing so withholds exactly the device names the
    matcher is weakest on. A capped rebuild scores about 0.9870 instead of 0.9490 and
    looks like an improvement. It is a smaller measurement wearing a bigger number.
  * `build_vex_gt.py` defaults to writing `data/vex_gt_104.jsonl`, the retired
    104-CVE population, not the full collected-source one.

So the flags are pinned here rather than left to the builders' defaults, and every
dataset is checked against the counts its own manifest records before it is scored. A
runner that silently rebuilds a different answer key is worse than one that refuses to
run, which is why `verify()` raises instead of warning.
"""
import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(BASE, "tools")


def _p(*parts):
    return os.path.join(BASE, *parts)


# item -> how to build its answer key, and what the result must look like.
#
# `argv` is the FULL command, flags included: the point is that nothing relies on a
# builder default. `expect` names the manifest field holding the authoritative record
# count, so the check compares the dataset against its own provenance rather than
# against a number typed in here - a count in this file would be one more thing to go
# stale, which is the failure mode the whole runner exists to avoid.
DATASETS = {
    "3": {
        "gt": "data/cpe_match_eval.jsonl",
        "manifest": "data/cpe_match_eval_manifest.json",
        "argv": ["build_cpe_match_gt.py", "--per-vendor", "0", "--seed", "20261007"],
        "expect": ("counts", "total"),
        "note": "--per-vendor 0 lifts the retired cap; the seed is the one the "
                "published figure was measured with",
        "builds_minutes": 12,
    },
    "4": {
        "gt": "data/vex_gt_all.jsonl",
        "manifest": "data/vex_gt_all_manifest.json",
        "argv": ["build_vex_gt.py", "--out", "data/vex_gt_all.jsonl"],
        "expect": ("counts", "cases"),
        "note": "no --population flag: the population is every CVE whose source was "
                "collected, not the retired 104",
        "builds_minutes": 4,
    },
    "q34": {
        "gt": "data/vex_q34_gt.jsonl",
        "manifest": None,
        "argv": ["build_q34_gt.py"],
        "expect": None,
        "note": "authorities are outside this repo: shipped public headers (Q3), "
                "NVD CVSS AV/UI (Q4)",
        "builds_minutes": 2,
    },
}

# Inputs a dataset cannot be built without. Checked before the builder runs, because
# a builder handed a missing cache does not fail - it produces a thinner answer key,
# and a thinner answer key scores higher. That is the quiet failure this guards.
PREREQS = {
    "3": ["reverse_sbom", "data/nvd_cpe_detail.json"],
    "4": ["data/source_snapshots", "data/patches", "data/cve_version_ranges.json"],
    "q34": ["data/source_snapshots", "data/nvd_cvss.json"],
}

# What the SUT side needs in place. These are verdict caches, not datasets: item #4
# scores a stored verdict rather than re-judging, so a missing cache means "run the
# pipeline", never "score anyway".
SUT_INPUTS = {
    "3": [],
    "4": ["data/vex_v2_pregate.json"],
    "q34": ["data/reachability.json", "data/controllability.json"],
}


class DatasetError(RuntimeError):
    """A dataset is absent, unbuildable, or not the one the figure was measured on."""


def status(item):
    """Describe an item's dataset without changing anything."""
    d = DATASETS[item]
    gt = _p(d["gt"])
    missing_pre = [x for x in PREREQS[item] if not os.path.exists(_p(x))]
    missing_sut = [x for x in SUT_INPUTS[item] if not os.path.exists(_p(x))]
    rec = {"item": item, "gt": d["gt"], "exists": os.path.isfile(gt),
           "records": None, "expected": None, "missing_prereqs": missing_pre,
           "missing_sut_inputs": missing_sut, "note": d["note"]}
    if rec["exists"]:
        with open(gt, encoding="utf-8") as f:
            rec["records"] = sum(1 for line in f if line.strip())
        rec["expected"] = _expected(d)
    return rec


def _expected(d):
    """The record count this dataset's own manifest claims, or None."""
    if not d["manifest"] or not d["expect"]:
        return None
    path = _p(d["manifest"])
    if not os.path.isfile(path):
        return None
    doc = json.load(open(path, encoding="utf-8"))
    for key in d["expect"]:
        if not isinstance(doc, dict):
            return None
        doc = doc.get(key)
    return doc if isinstance(doc, int) else None


def build(item, echo=print):
    """Run the item's ground-truth builder with its flags pinned."""
    d = DATASETS[item]
    missing = [x for x in PREREQS[item] if not os.path.exists(_p(x))]
    if missing:
        raise DatasetError(
            "cannot build item #%s's dataset - these inputs are absent: %s\n"
            "    A builder run without them does not fail; it writes a thinner answer "
            "key, and a thinner answer key scores HIGHER. Collect them first "
            "(see README 'Reproduce')." % (item, ", ".join(missing)))
    argv = [sys.executable, os.path.join(TOOLS, d["argv"][0])] + d["argv"][1:]
    echo("    building: %s" % " ".join(d["argv"]))
    echo("    (%s)" % d["note"])
    proc = subprocess.run(argv, cwd=BASE)
    if proc.returncode != 0:
        raise DatasetError("builder failed for item #%s (exit %d): %s"
                           % (item, proc.returncode, " ".join(d["argv"])))
    return status(item)


def verify(item):
    """Raise unless the dataset on disk is present and matches its manifest.

    Deliberately fatal. The alternative - score it and attach a warning - puts a
    number in the report that looks like every other number there, and the report is
    the artifact people quote.
    """
    rec = status(item)
    if not rec["exists"]:
        raise DatasetError("item #%s: %s is absent" % (item, rec["gt"]))
    if rec["records"] == 0:
        raise DatasetError("item #%s: %s is empty" % (item, rec["gt"]))
    if rec["expected"] is not None and rec["records"] != rec["expected"]:
        raise DatasetError(
            "item #%s: %s holds %d records but its manifest records %d.\n"
            "    The dataset and its provenance disagree, so neither can be trusted. "
            "Rebuild with --rebuild %s."
            % (item, rec["gt"], rec["records"], rec["expected"], item))
    if rec["missing_sut_inputs"]:
        raise DatasetError(
            "item #%s: the SUT's own outputs are absent: %s\n"
            "    These are verdict caches produced by the pipeline, not datasets. "
            "Scoring without them would measure nothing."
            % (item, ", ".join(rec["missing_sut_inputs"])))
    return rec


def ensure(item, rebuild=False, echo=print):
    """Get the item's dataset into a scoreable state, building only if needed."""
    rec = status(item)
    if rebuild or not rec["exists"]:
        why = "rebuild requested" if rebuild else "absent"
        echo("  item #%-3s dataset %s (%s), ~%d min"
             % (item, why, rec["gt"], DATASETS[item]["builds_minutes"]))
        build(item, echo=echo)
    return verify(item)
