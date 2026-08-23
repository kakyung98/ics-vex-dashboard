#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compute execution-verification COVERAGE over the 110 source-collectable CVEs:
how many are attemptable by the engine vs not doable, with a reason per excluded CVE.

Writes results/verify_coverage.json for the dashboard.
"""
import os, json, glob, csv, datetime

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
ENGINE = os.environ.get("VERIFY_ENGINE_DIR", r"C:\Users\user\Desktop\cve-genie")
CACHE = os.path.join(ENGINE, "webapp", "data", "icsvex_tierA.json")

# T = the 110 tier-A / source-collectable CVEs
ci = json.load(open(os.path.join(BASE, "cve_index.json"), encoding="utf-8"))
T = {r["cve"] for r in ci if r.get("source_available")}
cache = set(json.load(open(CACHE, encoding="utf-8"))) if os.path.isfile(CACHE) else set()
recs = {json.load(open(p, encoding="utf-8"))["cve"] for p in glob.glob(os.path.join(BASE, "results", "verify_full", "CVE-*.json"))}
rep = {r["cve"]: r for r in json.load(open(os.path.join(BASE, "results", "data_processor_report.json"), encoding="utf-8")).get("records", [])}

# a CVE is attemptable if the engine has (or has run) it
attemptable = {c for c in T if c in cache or c in recs}
not_doable = sorted(T - attemptable)

REASONS = {
    "linux kernel": "Linux kernel — full-source build infeasible in the sandbox (hundreds of MB, multi-hour compile).",
    "no source tag": "Upstream release tag/source no longer obtainable from the repository.",
    "download failed": "Upstream source download failed (no reachable archive).",
    "no engine source": "No buildable source archive could be resolved for the affected version.",
}

def classify(c):
    r = rep.get(c) or {}
    comp = (r.get("component") or "").lower()
    st = r.get("status")
    if "linux" in comp or "kernel" in comp:
        return "linux kernel", comp or "linux_kernel"
    if st == "no-tag":
        return "no source tag", comp
    if st == "fetch-failed":
        return "download failed", comp
    # fell through: source-available flag but never resolvable
    if "linux" in c or c in ("CVE-2021-33909", "CVE-2023-32233", "CVE-2019-11477",
                             "CVE-2022-0847", "CVE-2024-1086"):
        return "linux kernel", "linux_kernel"
    return "no engine source", comp

groups = {}
items = []
for c in not_doable:
    key, comp = classify(c)
    groups[key] = groups.get(key, 0) + 1
    items.append({"cve": c, "component": comp, "category": key, "reason": REASONS[key]})

out = {
    "generated": datetime.datetime.now().isoformat(timespec="seconds"),
    "total_collectable": len(T),
    "attemptable": len(attemptable),
    "not_doable": len(not_doable),
    "by_reason": groups,
    "excluded": items,
}
json.dump(out, open(os.path.join(BASE, "results", "verify_coverage.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=2)
print("coverage: total=%d attemptable=%d not_doable=%d %s"
      % (out["total_collectable"], out["attemptable"], out["not_doable"], groups))
