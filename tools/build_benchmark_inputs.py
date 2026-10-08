#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Emit the INPUT datasets for test items #3 and #4, in the schemas the test
document declares.

The bundle shipped answer keys, predictions and results but no standalone input: #3's
was buried in the ground truth's `_sut_input` field and #4's was implicit in the
snapshot directories. A reviewer cannot check a measurement without seeing what was
fed in, and the test document specifies an input schema for each item, so both are
written out explicitly here.

What goes in is what the SUT actually receives — not the answer. #3's input carries
the component exactly as the SBOM spells it ("Siemens SCALANCE XF206-1 (6GK5206-1BC00
-2AF2) <V5.2.6"), never the CPE product the ground truth holds; resolving that messy
string is the task being scored. `cpe` and `purl` are null throughout because the
corpus has no component-level identifiers, which is itself a finding about ICS
advisory data rather than a gap in this file.

  item3  {test_case_id, asset_id, component{component_id, vendor, product, version,
          identifiers{cpe, purl}}}
  item4  {test_case_id, cve_id, component{vendor, product, version},
          source_evidence{source_available, source_snapshot, patch_available,
          fix_commit, vulnerable_function}, analysis_context{...}}

Written to data/ like every other derived artifact; the bundle copies them, so
benchmark/ stays a snapshot of canonical files rather than a second home.

Out: data/bench_input_item3.jsonl
     data/bench_input_item4.jsonl
"""
import glob
import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(BASE, "benchmark")
GT3 = os.path.join(BENCH, "item3", "ground_truth.jsonl")
GT4 = os.path.join(BENCH, "item4", "ground_truth.jsonl")
LOCS = os.path.join(BASE, "data", "source_locations.json")
VFUNCS = os.path.join(BASE, "data", "vuln_funcs.json")
PATCHES = os.path.join(BASE, "data", "patches")
SNAP = os.path.join(BASE, "data", "source_snapshots")


def _load(p, default):
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return default


def item3_inputs():
    """One record per distinct (component, version) the SUT is run on.

    The ground truth holds several CVEs per component, but the SUT is fed the
    component once and emits a CVE set, so the input is deduplicated to match what
    actually gets run.
    """
    seen, out = set(), []
    for line in open(GT3, encoding="utf-8"):
        if not line.strip():
            continue
        r = json.loads(line)
        si = r.get("_sut_input") or {}
        key = (r["component_id"], si.get("version"))
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "test_case_id": "SBOM-IN-%04d" % (len(out) + 1),
            "asset_id": si.get("asset_id"),
            "component": {
                "component_id": r["component_id"],
                # what the SBOM says, not what the answer key says
                "vendor": si.get("publisher"),
                "product": si.get("name"),
                "version": si.get("version"),
                "identifiers": {"cpe": None, "purl": None},
            },
        })
    return out


def item4_inputs():
    """One record per CVE the ground truth judges, with the evidence the pipeline
    had available for it."""
    locs, vfuncs = _load(LOCS, {}), _load(VFUNCS, {})
    cves, out = [], []
    for line in open(GT4, encoding="utf-8"):
        if not line.strip():
            continue
        c = json.loads(line)["cve_id"]
        if c not in cves:
            cves.append(c)
    for i, cve in enumerate(sorted(cves), 1):
        loc = locs.get(cve) or {}
        diffs = sorted(glob.glob(os.path.join(PATCHES, cve, "*.diff")))
        snap_dir = os.path.join(SNAP, cve)
        funcs = vfuncs.get(cve) or [f.get("name") for f in loc.get("functions") or []]
        out.append({
            "test_case_id": "VEX-IN-%04d" % i,
            "cve_id": cve,
            "component": {
                "vendor": None,                     # ICS advisories pin no component vendor
                "product": loc.get("component"),
                "version": loc.get("snapshot"),
            },
            "source_evidence": {
                "source_available": os.path.isdir(snap_dir),
                "source_snapshot": loc.get("snapshot"),
                "patch_available": bool(diffs),
                "fix_commit": (os.path.splitext(os.path.basename(diffs[0]))[0]
                               if diffs else None),
                "vulnerable_function": (funcs[0] if funcs else None),
            },
            "analysis_context": {
                # the snapshot is a library tree with no consumer, so there is no
                # entry point or attacker-input binding to declare; recording that
                # honestly is why Q2/Q3 only grade confidence and never refute
                "entry_point": None,
                "execution_path": None,
                "attacker_input": None,
            },
        })
    return out


def write(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("  %-34s %4d records" % (os.path.relpath(path, BASE), len(rows)))


def main():
    for p in (GT3, GT4):
        if not os.path.isfile(p):
            print("먼저 번들을 만드십시오: python tools/build_benchmark_bundle.py")
            return
    print("benchmark inputs:")
    write(os.path.join(BASE, "data", "bench_input_item3.jsonl"), item3_inputs())
    write(os.path.join(BASE, "data", "bench_input_item4.jsonl"), item4_inputs())
    print("  -> bundle them: python tools/build_benchmark_bundle.py")


if __name__ == "__main__":
    main()
