#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Assemble benchmark/ — the evaluation datasets for test items #3 and #4, alone.

The ground truths, their manifests and the scored results live beside the pipeline
data they were derived from, which is right for reproducing them and wrong for
handing them to a reviewer: `data/` also holds caches, snapshots and training
corpora that have nothing to do with the measurement.

This copies the measurement set into one folder, as a GENERATED snapshot rather
than a second home. A hand-made copy drifts the moment a ground truth is rebuilt
and nothing says so; here every file carries its source path and a SHA-256 in
MANIFEST.json, and `--check` re-verifies the bundle against the live files, so
drift is detectable instead of silent.

What is deliberately NOT bundled: the corpus the #3 ground truth was derived from
(`reverse_sbom/`, 3,765 files) and the source snapshots behind #4
(`data/source_snapshots/`). Both are inputs to building the ground truth, not to
scoring it, and they are large. The bundle holds what a reviewer needs to re-score:
the answer keys, the SUT's predictions, and the results.

Usage:
  python tools/build_benchmark_bundle.py            # (re)build benchmark/
  python tools/build_benchmark_bundle.py --check     # verify, change nothing
"""
import argparse
import datetime
import hashlib
import json
import os
import shutil

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "benchmark")

# bundled path -> (source path, what it is)
# bundled path -> (source path, one line on what it is)
# #3 is scored over the whole corpus and #4 over the 104 CVEs whose source could be
# collected. The populations differ on purpose: identification needs no source, so
# filtering #3 by source availability would import a condition belonging to #4.
FILES = {
    "item3/input.jsonl": (
        "data/bench_input_item3.jsonl",
        "INPUT: 543 SBOM components as the SUT receives them — the messy advisory "
        "string, never the CPE the answer key holds (tools/build_benchmark_inputs.py)"),
    "item3/ground_truth.jsonl": (
        "data/cpe_match_eval.jsonl",
        "GT 6,518 records over 2,652 CVEs and 471 vendors, from CISA CSAF affects "
        "assertions cross-checked against NVD applicability"),
    "item3/excluded.jsonl": (
        "data/cpe_match_eval_layerB.jsonl",
        "22,810 pairs excluded up front: the ICS name appears nowhere in NVD, so no "
        "name-based matcher can reach the answer. Kept so the exclusion is auditable"),
    "item3/manifest.json": (
        "data/cpe_match_eval_manifest.json",
        "How the GT was built: population, vendor mix, negative families, exclusions"),
    "item3/result.json": (
        "results/cpe_match_precision.json",
        "Scored run for item #3 (tools/eval_cpe_match_precision.py)"),

    "item4/population.json": (
        "data/vex_population_104.json",
        "The 104 source-available CVEs — #4's population; #3 has no such filter"),
    "item4/input.jsonl": (
        "data/bench_input_item4.jsonl",
        "INPUT: 54 CVEs with the source/patch evidence available per CVE "
        "(tools/build_benchmark_inputs.py)"),
    "item4/ground_truth.jsonl": (
        "data/vex_gt_all.jsonl",
        "Answer key over the FULL collected-source population: every CVE with a "
        "source snapshot, labelled from execution pairs and fix-commit patch "
        "signatures only"),
    "item4/predictions.json": (
        "data/vex_v2_pregate.json",
        "The SUT output being scored: vex_judge_v2 --no-patch-gate. Pre-gate, because "
        "the patch gate reads the same authorities the GT does and the gated run is circular"),
    "item4/predictions_patched.json": (
        "data/vex_v2_patched.json",
        "vex_judge_v2 --build patched: the verdicts for the vendor's remediated "
        "releases (data/fixed_releases/). A patched build cannot be judged pre-gate - "
        "Q1 reads 'present' on 10 of 12, because a fix edits the vulnerable function "
        "rather than deleting it - so these come from the gate-live run"),
    "item4/predictions_gated.json": (
        "data/vex_v2.json",
        "vex_judge_v2 with the Q0 patch gate live, over the vulnerable build. Needed "
        "to score the full population alongside the patched verdicts; circular on the "
        "patch_verified cases, which the result records"),
    "item4/result_allbuilds.json": (
        "results/vex_precision_allbuilds.json",
        "Scored over BOTH builds with the gate live - the only scope that exercises "
        "not_affected - with its circularity disclosure"),
    "item4/result_independent.json": (
        "results/vex_precision_independent.json",
        "Scored over execution-verified evidence only: the one scope where the GT and "
        "the SUT share no oracle. Small by construction"),
    "item4/manifest.json": (
        "data/vex_gt_all_manifest.json",
        "How the GT was built: evidence mix, corroboration, the 50 CVEs evidence could not label"),
    "item4/result.json": (
        "results/vex_precision_all.json",
        "HEADLINE scored run for item #4: vulnerable build, patch gate off - the "
        "largest scope whose answer key shares no oracle with the SUT"),
}

def _r(rel):
    """Read a result file, or {} if it has not been produced yet."""
    p = os.path.join(BASE, rel)
    return json.load(open(p, encoding="utf-8")) if os.path.isfile(p) else {}


def _pct(res, key="precision"):
    v = res.get(key)
    return "—" if v is None else "%.2f%%" % (v * 100)


README_TEMPLATE = """# Benchmark — certification test items #3 / #4

Evaluation datasets only. Generated by `tools/build_benchmark_bundle.py`; do not edit
here, edit the sources in `MANIFEST.json` and rebuild. `--check` verifies this bundle
still matches them, so a rebuilt ground truth cannot leave a stale copy unnoticed.
Every figure below is read out of the result files at build time rather than written
down, because written-down figures are what went stale last time.

| item | metric | result | acceptance | scored on |
|---|---|---|---|---|
| #3 | SBOM -> CVE identification precision | **{i3p}** (TP {i3tp:,} / FP {i3fp:,}) | >= 0.80 | {i3n:,} labelled predictions |
| #4 | VEX affected-judgment precision | **{i4p}** (TP {i4tp} / FP {i4fp}) | >= 0.85 | {i4n} (CVE, build) cases |

#3 identifies CVEs from the SBOM, #4 judges whether the identified CVEs actually
affect the build: two consecutive stages. They are NOT scoped to one population —
#4 needs collected source and #3 does not, and filtering #3 by source availability
would import a condition that belongs to the later stage.

Both can also be run from the web app at **`/cert.html`**, which scores through the
same `score()` functions these results came from.

## item3/ — SBOM -> CVE identification

| file | what |
|---|---|
| `input.jsonl` | **what the SUT is fed**: components as the SBOM spells them |
| `ground_truth.jsonl` | answer key, applicable true/false ({i3gt:,} labels) |
| `excluded.jsonl` | pairs excluded up front, with reason |
| `manifest.json` | how the GT was built |
| `result.json` | the scored run |

**Read `result.json` with its coverage stated.** Precision is {i3p} over {i3n:,}
scored predictions — {i3share}% of what the matcher emits. The rest are CVEs the
ground truth does not enumerate for that component ({i3un:,}), or cases where CISA
says the ICS product is affected while NVD files the CVE against an embedded third
party ({i3ua:,}): the two authorities disagree about what the CVE is filed against,
not about what the component is. The matcher also declines to identify {i3ab:,} of
{i3runs:,} components rather than guess at an ambiguous name; abstaining costs recall
and is free under a precision-only metric, so it is disclosed here.

## item4/ — VEX impact judgment

| file | what |
|---|---|
| `population.json` | the source-available CVEs |
| `input.jsonl` | **what the SUT is fed**: CVE + source/patch evidence |
| `ground_truth.jsonl` | answer key, affected / not_affected ({i4tot} cases) |
| `predictions.json` | SUT output, pre-gate, vulnerable build — what `result.json` scores |
| `predictions_gated.json` | SUT output with the Q0 patch gate live |
| `predictions_patched.json` | SUT output for the vendor's remediated releases |
| `result.json` | **headline**: vulnerable build, gate off |
| `result_allbuilds.json` | both builds, gate live |
| `result_independent.json` | execution-verified evidence only |

A label is about a **(CVE, build)** pair, not a CVE: the same CVE is affected in its
vulnerable snapshot and not_affected in its patched release. Three scopes, because one
number cannot carry the claim:

| scope | precision | TP/FP/TN/FN | what it is worth |
|---|---|---|---|
| vulnerable, gate off | **{i4p}** | {i4tp}/{i4fp}/{i4tn}/{i4fn} | the headline — largest scope with no shared oracle |
| both builds, gate live | {i4ap} | {i4atp}/{i4afp}/{i4atn}/{i4afn} | the only scope that exercises not_affected; **circular** on the patch_verified cases |
| execution-verified only | {i4ip} | {i4itp}/{i4ifp}/{i4itn}/{i4ifn} | no shared oracle at all, but small by construction |

The third scope is **below the acceptance criterion**, and it is published anyway
because it is a disclosure scope rather than the certification metric. Its single
false positive is instructive: CVE-2024-4340's patched build (sqlparse 0.5.0).
Execution proves that release does not fault, but the fix added a guard *inside*
`flatten` rather than removing it, so Q1 still reads `present` - and NVD carries no
fix commit for this CVE, so the patch gate has no signature to clear it with. The
system therefore says `affected` about a build that demonstrably is not. That is
the honest shape of the limit: **without a fix diff, a patched build is
indistinguishable from a vulnerable one by presence alone.** The figure was not
tuned to remove it.

**Why the patched build needs the gate.** Q1 asks whether the vulnerable function is
*defined*, and a fix edits that function rather than deleting it — Q1 reads `present`
on 10 of the 12 collected patched trees. So there is no pre-gate patched figure to
quote, and the gate decides from the fix signature plus the NVD range, which is where
most of this GT's labels come from. `result_independent.json` is the scope that
removes the shared oracle; it is small because execution-verified evidence is scarce,
and that scarcity is the honest limit of this item.

## Population is not the scored count

Neither figure covers its whole population, because both answer keys are earned from
evidence and evidence does not reach every member. Forcing the unlabelled into either
score would mean counting undecidable as a false positive (charging the system for a
gap in the answer key) or assuming the unlabelled are positives — and for #4 the SUT
answers `affected` for most of them, so FP would become structurally 0 and precision
the identity 1.0.

## Ground truth independence

A ground truth derived from what the system reads measures nothing. #3's comes from
CISA CSAF and NVD applicability, never from `data/cpe_index.json`, the matcher's own
index. #4's uses execution pairs and fix-commit patch signatures; `vendor_asserted` is
excluded because a claim with no source cannot adjudicate a code-level verdict. Where
the two authorities disagree the record is held out as `conflict` rather than labelled
verified — {i3conf} in #3.

## Input, answer key, output — the three the reviewer needs

`input.jsonl` is what the system receives, `ground_truth.jsonl` is the answer, and
`result.json` (item4 also `predictions*.json`) is what it produced. #3's input carries
the component exactly as the advisory spells it — `Siemens SCALANCE XF206-1
(6GK5206-1BC00-2AF2) <V5.2.6` — and never the CPE product the answer key holds,
because resolving that string is the task being scored.

## Re-score from this bundle

    python tools/eval_cpe_match_precision.py --data benchmark/item3/ground_truth.jsonl
    python tools/eval_vex_precision.py --gt  benchmark/item4/ground_truth.jsonl \\
                                       --sut benchmark/item4/predictions.json
    python tools/eval_vex_precision.py --build all \\
        --gt benchmark/item4/ground_truth.jsonl \\
        --sut benchmark/item4/predictions_gated.json \\
        --sut-patched benchmark/item4/predictions_patched.json

## Rebuild the SUT outputs and the ground truths

    python tools/vex_judge_v2.py --all                      # gate live, vulnerable
    python tools/vex_judge_v2.py --all --no-patch-gate --out data/vex_v2_pregate.json
    python tools/build_func_index.py --build patched        # index fixed_releases
    python tools/source_locate.py   --build patched --all   # Q1 on the patched tree
    python tools/vex_judge_v2.py    --build patched --all   # patched verdicts
    python tools/build_benchmark_bundle.py
"""


def readme():
    """Build README.md from the result files, not from frozen copies of them.

    Every figure in the previous README had gone stale - it still advertised #3 at
    1.0000 (TP 42 / FP 0) after the corpus had grown by two orders of magnitude -
    because the numbers were prose and nothing re-checked them. Reading them back
    out of the result JSONs means the bundle cannot describe itself wrongly: if a
    figure here is wrong, the result file it came from is wrong too.
    """
    i3 = _r("results/cpe_match_precision.json")
    i4 = _r("results/vex_precision_all.json")
    i4a = _r("results/vex_precision_allbuilds.json")
    i4i = _r("results/vex_precision_independent.json")
    return README_TEMPLATE.format(
        i3p=_pct(i3), i3tp=i3.get("TP", 0), i3fp=i3.get("FP", 0),
        i3n=i3.get("scored", 0), i3gt=i3.get("gt_labels", 0),
        i3share=i3.get("labelled_share_pct", 0),
        i3un=i3.get("unlabelled_predictions", 0),
        i3ua=i3.get("unadjudicable_predictions", 0),
        i3ab=i3.get("sut_abstained", 0), i3runs=i3.get("sut_runs", 0),
        i3conf=i3.get("gt_conflicts_held_out", 0),
        i4p=_pct(i4), i4tp=i4.get("TP", 0), i4fp=i4.get("FP", 0),
        i4tn=i4.get("TN", 0), i4fn=i4.get("FN", 0),
        i4n=i4.get("TP", 0) + i4.get("FP", 0), i4tot=i4.get("gt_cases_total", 0),
        i4ap=_pct(i4a), i4atp=i4a.get("TP", 0), i4afp=i4a.get("FP", 0),
        i4atn=i4a.get("TN", 0), i4afn=i4a.get("FN", 0),
        i4ip=_pct(i4i), i4itp=i4i.get("TP", 0), i4ifp=i4i.get("FP", 0),
        i4itn=i4i.get("TN", 0), i4ifn=i4i.get("FN", 0),
    )




def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="verify the bundle against the live sources, write nothing")
    a = ap.parse_args()

    if a.check:
        man_path = os.path.join(OUT, "MANIFEST.json")
        if not os.path.isfile(man_path):
            print("no bundle yet: run without --check")
            return
        man = json.load(open(man_path, encoding="utf-8"))
        stale, missing = [], []
        for rel, rec in man["files"].items():
            src = os.path.join(BASE, rec["source"])
            dst = os.path.join(OUT, rel)
            if not os.path.isfile(src) or not os.path.isfile(dst):
                missing.append(rel)
            elif sha256(src) != rec["sha256"] or sha256(dst) != rec["sha256"]:
                stale.append(rel)
        print("bundle built %s" % man["generated"])
        print("  files   : %d" % len(man["files"]))
        print("  stale   : %s" % (", ".join(stale) or "none"))
        print("  missing : %s" % (", ".join(missing) or "none"))
        if stale or missing:
            print("\n-> rebuild: python tools/build_benchmark_bundle.py")
        return

    manifest = {
        "bundle": "ICS-VEX certification benchmark (test items #3, #4)",
        "generated": datetime.date.today().isoformat(),
        "generated_by": "tools/build_benchmark_bundle.py",
        "note": "generated snapshot — edit the source files, then rebuild",
        "files": {},
    }
    copied = skipped = 0
    for rel, (src_rel, what) in sorted(FILES.items()):
        src = os.path.join(BASE, src_rel)
        if not os.path.isfile(src):
            print("  MISSING source, skipped: %s" % src_rel)
            skipped += 1
            continue
        dst = os.path.join(OUT, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        manifest["files"][rel] = {"source": src_rel, "description": what,
                                  "bytes": os.path.getsize(src),
                                  "sha256": sha256(src)}
        copied += 1

    open(os.path.join(OUT, "README.md"), "w", encoding="utf-8").write(readme())
    json.dump(manifest, open(os.path.join(OUT, "MANIFEST.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)

    total = sum(r["bytes"] for r in manifest["files"].values())
    print("benchmark/ built: %d files, %.1f MB%s"
          % (copied, total / 1e6, "  (%d source(s) missing)" % skipped if skipped else ""))
    for rel in sorted(manifest["files"]):
        print("  %-56s %8d B" % (rel, manifest["files"][rel]["bytes"]))
    print("-> %s" % OUT)


if __name__ == "__main__":
    main()
