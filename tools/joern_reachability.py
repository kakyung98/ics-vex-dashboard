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
import glob
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


_HOME = os.path.expanduser("~")


def _joern_bin():
    """joern launcher: $JOERN_BIN, then PATH, then the local ~/opt install
    (joern.bat on Windows, the shell launcher elsewhere)."""
    env = os.environ.get("JOERN_BIN")
    if env and os.path.exists(env):
        return env
    w = shutil.which("joern")
    if w:
        return w
    base = os.path.join(_HOME, "opt", "joern-cli")
    for c in ("joern.bat", "joern"):
        p = os.path.join(base, c)
        if os.path.exists(p):
            return p
    return None


def _joern_env():
    """os.environ plus a JDK 17 in JAVA_HOME/PATH. Joern's platform zip bundles its
    own JRE, so this is only a fallback ($JOERN_JAVA_HOME or a local ~/opt/jdk-17*)."""
    e = dict(os.environ)
    jh = os.environ.get("JOERN_JAVA_HOME")
    if not jh:
        cands = sorted(glob.glob(os.path.join(_HOME, "opt", "jdk-17*")))
        jh = cands[0] if cands else None
    if jh and os.path.isdir(jh):
        e["JAVA_HOME"] = jh
        e["PATH"] = os.path.join(jh, "bin") + os.pathsep + e.get("PATH", "")
    return e


def _joern_cmd(bin_path, script):
    """A subprocess argv for the launcher; .bat must go through cmd on Windows."""
    if bin_path.lower().endswith(".bat"):
        return ["cmd", "/c", bin_path, "--script", script]
    return [bin_path, "--script", script]


def _query(src_dir, targets, entries):
    """One Joern script (one CPG build): is ANY target transitively called from an
    entry method? Entries are the CTI's entry_points, or - when it named none - the
    call-graph roots (internal methods with no caller), i.e. the library's API surface.
    A target that is itself a root counts as reachable."""
    tl = "List(%s)" % ", ".join('"%s"' % t for t in targets)
    if entries:
        el = "List(%s)" % ", ".join('"%s"' % e for e in entries)
        entry_expr = "%s.flatMap(n => cpg.method.nameExact(n).l)" % el
    else:
        entry_expr = "cpg.method.filter(m => !m.isExternal && m.caller.isEmpty).l"
    return '''importCode(inputPath="%s")
val targets = %s.toSet
val defined = cpg.method.name.toSet.intersect(targets)
if (defined.isEmpty) { println("VERDICT:no-target") }
else {
  val entryM = %s
  val entryNames = entryM.name.toSet
  val reached = entryM.repeat(_.callee)(_.emit.maxDepth(30)).name.toSet ++ entryNames
  val hit = defined.exists(reached.contains)
  println("VERDICT:" + (if (hit) "reachable" else if (entryM.isEmpty) "no-entry" else "not-reachable"))
}
''' % (src_dir.replace("\\", "/"), tl, entry_expr)


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
    script = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".sc", delete=False,
                                         encoding="utf-8") as f:
            f.write(_query(src, funcs, entries))   # one CPG build, all targets
            script = f.name
        r = subprocess.run(_joern_cmd(jb, script), capture_output=True,
                           text=True, timeout=2400, env=_joern_env())
        line = next((l for l in r.stdout.splitlines() if l.startswith("VERDICT:")), "")
        v = line.split(":", 1)[1].strip() if ":" in line else ""
        if v == "reachable":
            return "reachable", "joern: a located function is reachable from an entry point"
        if v == "not-reachable":
            return "not-reachable", "joern: no located function reachable from an entry point"
        if v == "no-target":
            return "unknown", "joern: located functions not present in the CPG"
        if v == "no-entry":
            return "unknown", "joern: no entry model"
        return "unknown", "joern: no verdict (%s)" % ((r.stderr or "")[-160:] or "no output")
    except Exception as e:
        return "unknown", "joern error: %s" % e
    finally:
        if script and os.path.exists(script):
            try:
                os.unlink(script)
            except OSError:
                pass


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
