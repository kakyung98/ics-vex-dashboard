#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Write a per-CVE execution-verification result + evidence record from a real run log.

Usage (per CVE):
  python tools/_verify_record.py <cve> <build_ok> <exploit_ok> <verify_ok> <seconds> \
         <outcome> <logpath> <shareddir> <outjson>
Summary:
  python tools/_verify_record.py --summary <csv> <outjson>
"""
import os, sys, re, json, glob, csv, datetime

def _read(p, n=None):
    try:
        t = open(p, encoding="utf-8", errors="replace").read()
        return t if n is None else t[:n]
    except Exception:
        return ""

def _strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*m", "", s or "")

# VEX interpretation from the execution-verification outcome (honest mapping)
_VEX = {
    "execution-verified": ("affected", "execution-verified",
        "Reproducer triggered the vulnerability in the rebuilt vulnerable environment."),
    "exploit-generated": ("under_investigation", "exploit-generated",
        "Vulnerable environment rebuilt and a critic-accepted PoC exploit was generated; "
        "final CTF verification not completed locally (verifier timeout)."),
    "build-only": ("under_investigation", "build-only",
        "Vulnerable environment rebuilt; reproducer not reached within budget."),
    "failed": ("under_investigation", "failed",
        "Environment build did not complete."),
}

def summary(csv_path, out):
    rows = []
    if os.path.isfile(csv_path):
        rows = list(csv.DictReader(open(csv_path, encoding="utf-8")))
    def c(k, v): return sum(1 for r in rows if r.get(k) == v)
    agg = {
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "total": len(rows),
        "build_ok": sum(1 for r in rows if r.get("build_ok") == "1"),
        "exploit_ok": sum(1 for r in rows if r.get("exploit_ok") == "1"),
        "verify_ok": sum(1 for r in rows if r.get("verify_ok") == "1"),
        "by_outcome": {o: c("outcome", o) for o in
                       ["execution-verified", "exploit-generated", "build-only", "failed"]},
        "cves": [r.get("cve") for r in rows],
    }
    json.dump(agg, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("summary ->", out, agg["by_outcome"])

def one(cve, b, e, v, secs, outcome, logp, shared, out):
    log = _strip_ansi(_read(logp))
    status, tier, note = _VEX.get(outcome, _VEX["failed"])

    # locate the generated PoC exploit script (real artifact)
    exploit_files = []
    if shared and os.path.isdir(shared):
        for pat in ("scripts/*.py", "scripts/*.c", "scripts/*.sh", "scripts/exploit*"):
            exploit_files += [os.path.relpath(p, os.path.dirname(os.path.dirname(os.path.abspath(out)) ))
                              for p in glob.glob(os.path.join(shared, pat))]
    # evidence copied into the repo by the batch driver
    evid_dir = os.path.join("results", "verify_evidence", cve)
    exploit_local = None
    for p in glob.glob(os.path.join(evid_dir, "scripts", "*")):
        if p.endswith((".py", ".c", ".sh")) or "exploit" in os.path.basename(p).lower():
            exploit_local = p.replace("\\", "/"); break

    def grab(pat, span=400):
        m = re.search(pat, log)
        if not m:
            return ""
        i = m.start()
        return log[i:i + span].strip()

    # honest evidence snippets pulled from the real run log
    ev = {
        "run_log": (evid_dir + "/run.log").replace("\\", "/"),
        "exploit_script": exploit_local,
        "engine_artifacts": (shared or "").replace("\\", "/"),
        "build_critic": "Critic accepted the repo build" if "Critic accepted the repo build" in log else "",
        "exploit_critic": "Critic accepted the exploit" if "Critic accepted the exploit" in log else "",
        "verifier_result": grab(r"Results:\s*\{[^}]*verifier", 300) or grab(r"'success':\s*'(?:True|False)'[^\n]*", 200),
        "verifier_timeout": bool(re.search(r"Timeout expired during phase: verifier", log)),
    }

    rec = {
        "cve": cve,
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "method": "execution-based verification (build -> reproduce -> run), local engine",
        "outcome": outcome,
        "stages": {"build": bool(int(b)), "exploit": bool(int(e)), "verify": bool(int(v))},
        "seconds": int(secs),
        "vex": {"status": status, "evidence_tier": tier, "rationale": note},
        "evidence": ev,
    }
    json.dump(rec, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("record ->", out, outcome)

if __name__ == "__main__":
    if sys.argv[1] == "--summary":
        summary(sys.argv[2], sys.argv[3])
    else:
        (cve, b, e, v, secs, outcome, logp, shared, out) = sys.argv[1:10]
        one(cve, b, e, v, secs, outcome, logp, shared, out)
