#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reclassify each CVE's outcome, taking run.log's final verdict as the authority.

The batch runner's verify_ok regex was too narrow and misfiled genuinely
execution-verified records as exploit-generated. This reads each evidence's run.log
directly and assigns the tier exactly:
  execution-verified : final Results success=True and ('CVE reproduced' | 'Flag found')
  exploit-generated  : 'Critic accepted the exploit'
  build-only         : 'Critic accepted the repo build'
  failed             : everything else
Corrects the outcome and verify_ok columns of verify_full_summary.csv in place, leaving a
backup.
"""
import csv, glob, os, re, shutil

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EV = os.path.join(BASE, "results", "verify_evidence")
CSV = os.path.join(BASE, "results", "verify_full_summary.csv")


def classify(log):
    s = open(log, encoding="utf-8", errors="ignore").read()
    verified = bool(re.search(r"Results:\s*\{'success':\s*'True'", s)) and \
               ("CVE reproduced" in s or "Flag found" in s)
    exploit = "Critic accepted the exploit" in s or "Exploit Script Created" in s
    build = "Critic accepted the repo build" in s
    if verified: return "execution-verified", 1, 1, 1
    if exploit:  return "exploit-generated", 1, 1, 0
    if build:    return "build-only", 1, 0, 0
    return "failed", 0, 0, 0


def main():
    truth = {}
    for d in sorted(glob.glob(f"{EV}/*/")):
        cve = os.path.basename(os.path.normpath(d))
        log = os.path.join(d, "run.log")
        if os.path.exists(log):
            truth[cve] = classify(log)

    rows = list(csv.DictReader(open(CSV, encoding="utf-8")))
    shutil.copy2(CSV, CSV + ".bak.reclassify")
    changed = []
    for r in rows:
        cve = r["cve"]
        if cve in truth:
            oc, b, e, v = truth[cve]
            if r["outcome"] != oc:
                changed.append((cve, r["outcome"], oc))
            r["build_ok"], r["exploit_ok"], r["verify_ok"], r["outcome"] = b, e, v, oc
    with open(CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["cve","build_ok","exploit_ok","verify_ok","seconds","outcome"])
        w.writeheader(); w.writerows(rows)

    from collections import Counter
    dist = Counter(r["outcome"] for r in rows)
    print("Reclassification (run.log is the authority):")
    for k in ("execution-verified","exploit-generated","build-only","failed"):
        print(f"  {dist.get(k,0):>3}  {k}")
    print(f"\nentries corrected: {len(changed)}")
    for cve, old, new in changed:
        print(f"  {cve}: {old} -> {new}")


if __name__ == "__main__":
    main()
