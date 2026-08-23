#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate per-CVE build-only result + evidence records from the real build-batch logs.

Uses results/verify_build_batch.csv + results/verify_build_logs/<CVE>.log (actual
runs of the containerized engine, --run-type build). Writes results/verify_full/<CVE>.json
and copies the build log into results/verify_evidence/<CVE>/run.log. CVEs that already
have a richer full-run record (the pilot) are left untouched.
"""
import os, re, csv, json, glob, shutil, datetime

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CSV = os.path.join(BASE, "results", "verify_build_batch.csv")
LOGDIR = os.path.join(BASE, "results", "verify_build_logs")
OUTDIR = os.path.join(BASE, "results", "verify_full")
EVID = os.path.join(BASE, "results", "verify_evidence")
SHARED = os.environ.get("VERIFY_ENGINE_DIR", r"C:\Users\user\Desktop\cve-genie")
SHARED = os.path.join(SHARED, "webapp", "shared")
os.makedirs(OUTDIR, exist_ok=True); os.makedirs(EVID, exist_ok=True)

def strip_ansi(s): return re.sub(r"\x1b\[[0-9;]*m", "", s or "")

rows = list(csv.DictReader(open(CSV, encoding="utf-8")))
made = 0; skipped = 0
for r in rows:
    cve = r["cve"].strip()
    out = os.path.join(OUTDIR, cve + ".json")
    if os.path.isfile(out):   # keep pilot / already-generated richer records
        skipped += 1; continue
    log = os.path.join(LOGDIR, cve + ".log")
    txt = strip_ansi(open(log, encoding="utf-8", errors="replace").read()) if os.path.isfile(log) else ""
    build_ok = (r.get("build_ok") == "1") or ("Repo Built Successfully" in txt) or ("Critic accepted the repo build" in txt)
    critic = "Critic accepted the repo build" in txt
    outcome = "build-only" if build_ok else "failed"
    status, tier, note = (
        ("under_investigation", "build-only",
         "Vulnerable environment rebuilt by the containerized engine; exploit/verify not "
         "run locally (local model exploiter times out). Reproducer stage pending a capable model.")
        if build_ok else
        ("under_investigation", "failed", "Environment build did not complete.")
    )
    # evidence: copy the real build log into the repo
    ev = os.path.join(EVID, cve); os.makedirs(ev, exist_ok=True)
    if os.path.isfile(log):
        shutil.copyfile(log, os.path.join(ev, "run.log"))
    shared_dir = os.path.join(SHARED, cve)
    rec = {
        "cve": cve,
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "method": "execution-based verification (build stage), local engine",
        "outcome": outcome,
        "stages": {"build": bool(build_ok), "exploit": False, "verify": False},
        "seconds": int(r.get("seconds") or 0),
        "vex": {"status": status, "evidence_tier": tier, "rationale": note},
        "evidence": {
            "run_log": os.path.relpath(os.path.join(ev, "run.log"), BASE).replace("\\", "/") if os.path.isfile(log) else None,
            "build_critic": "Critic accepted the repo build" if critic else "",
            "build_marker": r.get("marker", ""),
            "engine_artifacts": shared_dir.replace("\\", "/") if os.path.isdir(shared_dir) else None,
        },
    }
    json.dump(rec, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    made += 1

# regenerate summary across ALL records (pilot + build-only)
recs = [json.load(open(p, encoding="utf-8")) for p in glob.glob(os.path.join(OUTDIR, "CVE-*.json"))]
def cnt(o): return sum(1 for x in recs if x.get("outcome") == o)
agg = {
    "generated": datetime.datetime.now().isoformat(timespec="seconds"),
    "total": len(recs),
    "build_ok": sum(1 for x in recs if x["stages"]["build"]),
    "exploit_ok": sum(1 for x in recs if x["stages"]["exploit"]),
    "verify_ok": sum(1 for x in recs if x["stages"]["verify"]),
    "by_outcome": {o: cnt(o) for o in ["execution-verified", "exploit-generated", "build-only", "failed"]},
    "cves": sorted(x["cve"] for x in recs),
}
json.dump(agg, open(os.path.join(OUTDIR, "_summary.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print(f"made {made}, skipped {skipped} (existing); total records {len(recs)}")
print("by_outcome:", agg["by_outcome"])
