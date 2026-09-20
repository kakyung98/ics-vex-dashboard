#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VEX-v2 · step 4 — reachability, decided by Joern (CPG).

Q2: is the vulnerable function reachable from an externally-controllable entry
point? Joern builds a Code Property Graph of the snapshot and answers whether the
target method is transitively called from an entry method.

  reachable      -> continue to controllability
  not-reachable  -> not_affected / vulnerable_code_not_in_execute_path
  unknown        -> Joern absent or query failed -> under_investigation

Joern is a JVM tool and is NOT bundled. When `joern` is not on PATH this returns
"unknown" so the rest of the pipeline still runs; install it (see deploy/README.md)
and the same call starts returning real verdicts. Conservative by construction:
"unknown" never clears a CVE, matching the project's "not found != not there" rule.

Out: data/reachability.json  { <CVE>: {...} }
"""
import argparse
import json
import os
import shutil
import subprocess
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(BASE, "data", "source_snapshots")
LOC = os.path.join(BASE, "data", "source_locations.json")
CTI = os.path.join(BASE, "data", "cti_extractions.json")
OUT = os.path.join(BASE, "data", "reachability.json")


def _joern_bin():
    return shutil.which("joern")


def _query(src_dir, target, entries):
    """A Joern script: is `target` transitively called from any `entries` method?
    Entry points default to external/public methods when the CTI named none."""
    ent = "||".join('m.name=="%s"' % e for e in entries) if entries else "!m.isExternal"
    return '''importCode(inputPath="%s")
val tgt = cpg.method.name("%s").l
if (tgt.isEmpty) { println("VERDICT:no-target") }
else {
  val entryM = cpg.method.filter(m => %s).l
  val reached = entryM.repeat(_.callee)(_.emit.maxDepth(30)).name("%s").l.nonEmpty
  val direct  = tgt.nonEmpty && entryM.isEmpty   // no entry model -> treat presence as reachable-unknown
  println("VERDICT:" + (if (reached) "reachable" else if (direct) "no-entry" else "not-reachable"))
}
''' % (src_dir.replace("\\", "/"), target, ent, target)


def reachable(cve, location, extraction):
    """(verdict, detail). verdict in reachable / not-reachable / unknown."""
    jb = _joern_bin()
    if not jb:
        return "unknown", "joern not installed (deploy/README.md)"
    funcs = [f["name"] for f in (location or {}).get("functions", []) if f.get("found")]
    if not funcs:
        return "unknown", "no located function to test"
    snap = (location or {}).get("snapshot")
    src = os.path.join(SNAP, cve, snap) if snap else None
    if not src or not os.path.isdir(src):
        return "unknown", "snapshot missing"
    entries = ((extraction or {}).get("reachability") or {}).get("entry_points") or []
    for target in funcs:                       # any function reachable -> reachable
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".sc", delete=False,
                                             encoding="utf-8") as f:
                f.write(_query(src, target, entries))
                script = f.name
            r = subprocess.run([jb, "--script", script], capture_output=True,
                               text=True, timeout=1200)
            os.unlink(script)
            line = next((l for l in r.stdout.splitlines() if l.startswith("VERDICT:")), "")
            v = line.split(":", 1)[1] if ":" in line else ""
            if v == "reachable":
                return "reachable", "joern: %s reachable from entry" % target
            if v == "no-entry":
                return "unknown", "joern: %s present, no entry model" % target
        except Exception as e:
            return "unknown", "joern error: %s" % e
    return "not-reachable", "joern: no located function reachable from entry"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cve")
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()

    loc = json.load(open(LOC, encoding="utf-8")) if os.path.exists(LOC) else {}
    cti = json.load(open(CTI, encoding="utf-8")) if os.path.exists(CTI) else {}
    cves = [a.cve] if a.cve else sorted(loc) if a.all else None
    if not cves:
        ap.error("pass --cve CVE-XXXX or --all")
    if not _joern_bin():
        print("note: joern not on PATH - every verdict will be 'unknown' until installed")

    out = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    for cve in cves:
        v, d = reachable(cve, loc.get(cve), cti.get(cve))
        out[cve] = {"cve": cve, "verdict": v, "detail": d}
        print("  %-18s reachability=%-14s  %s" % (cve, v, d))
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("-> %s (%d)" % (OUT, len(out)))


if __name__ == "__main__":
    main()
