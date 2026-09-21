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


def _launcher_cmd(bin_path, args):
    """A subprocess argv for a joern-cli launcher; .bat must go through cmd on Windows."""
    if bin_path.lower().endswith(".bat"):
        return ["cmd", "/c", bin_path] + list(args)
    return [bin_path] + list(args)


def _frontend_bin(lang):
    """The CPG frontend launcher for a language (c2cpg / javasrc2cpg)."""
    base = os.path.join(_HOME, "opt", "joern-cli")
    name = "javasrc2cpg" if lang == "java" else "c2cpg"
    for ext in (".bat", ""):
        p = os.path.join(base, name + ext)
        if os.path.exists(p):
            return p
    return shutil.which(name)


def _detect_lang(src):
    """Dominant language of a snapshot, for frontend selection (c / java).
    The corpus is 101 C/C++ and 3 Java snapshots."""
    n = {"c": 0, "java": 0}
    for _root, _dirs, files in os.walk(src):
        for f in files:
            e = f.rsplit(".", 1)[-1].lower() if "." in f else ""
            if e in ("c", "h", "cc", "cpp", "cxx", "hpp"):
                n["c"] += 1
            elif e == "java":
                n["java"] += 1
    return "java" if n["java"] > n["c"] else "c"


_SRC_EXT = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".java", ".py", ".go", ".js")


def _snapshot_too_big(src, max_files=4000):
    """A CPG for a huge tree (glibc/linux/u-boot) explodes on the dataflow pass and
    never finishes; skip it rather than burn the timeout. Counts source files."""
    n = 0
    for _root, _dirs, files in os.walk(src):
        n += sum(1 for f in files if f.endswith(_SRC_EXT))
        if n > max_files:
            return True
    return False


def _run(argv, env, timeout):
    """Run joern with a hard timeout that also kills the JVM grandchild. Windows
    subprocess timeout only kills the `cmd` child, orphaning java (seen churning
    12 CPU-hours on glibc); taskkill /T takes the whole tree down.
    Returns (stdout, stderr, timed_out)."""
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, env=env)
    try:
        out, err = p.communicate(timeout=timeout)
        return out, err, False
    except subprocess.TimeoutExpired:
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)],
                           capture_output=True)
        except Exception:
            pass
        try:
            p.kill()
            p.communicate(timeout=30)
        except Exception:
            pass
        return "", "timeout", True


def _query(cpg_bin, targets, entries):
    """Load a pre-built base CPG and apply only the default overlays (base, control
    flow, type, CALLGRAPH) - NOT the dataflow overlay, whose reaching-definitions pass
    explodes on some code (dnsmasq's 45 files timed out at 15 min under importCode).
    The call graph is all reachability needs. Is any target transitively called from an
    entry (the CTI's entry_points, else the call-graph roots)? A target that is itself a
    root counts as reachable."""
    tl = "List(%s)" % ", ".join('"%s"' % t for t in targets)
    if entries:
        entry_expr = ("List(%s).toSet.intersect(c.method.name.toSet)"
                      % ", ".join('"%s"' % e for e in entries))
    else:
        entry_expr = "c.method.filter(m => !m.isExternal && m.caller.isEmpty).name.toSet"
    # BFS over a name->callees adjacency map (O(V+E)); the old
    # repeat(_.callee)(_.emit.maxDepth(30)) explored PATHS and exploded on dnsmasq's
    # densely-connected graph (300s query timeout). Names dedup, so no re-visiting.
    return '''val c = io.shiftleft.codepropertygraph.cpgloading.CpgLoader.load("%s")
io.joern.x2cpg.X2Cpg.applyDefaultOverlays(c)
val targets = %s.toSet
val defined = c.method.name.toSet.intersect(targets)
if (defined.isEmpty) { println("VERDICT:no-target") }
else {
  val edges = scala.collection.mutable.Map[String, Set[String]]()
  c.method.foreach { m =>
    try {
      val cs = m.callee.name.toSet
      if (cs.nonEmpty) edges(m.name) = edges.getOrElse(m.name, Set.empty) ++ cs
    } catch { case _: Throwable => () }
  }
  val entryNames: Set[String] = %s
  var reached = entryNames
  var frontier = entryNames
  var iter = 0
  while (frontier.nonEmpty && iter < 2000) {
    val nxt = frontier.flatMap(n => edges.getOrElse(n, Set.empty)) -- reached
    reached = reached ++ nxt
    frontier = nxt
    iter += 1
  }
  val hit = defined.exists(reached.contains)
  println("VERDICT:" + (if (hit) "reachable" else if (entryNames.isEmpty) "no-entry" else "not-reachable"))
}
''' % (cpg_bin.replace("\\", "/"), tl, entry_expr)


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
    if _snapshot_too_big(src):
        return "unknown", "codebase too large for a CPG (skipped)"
    lang = _detect_lang(src)
    fe = _frontend_bin(lang)
    if not fe:
        return "unknown", "no %s frontend" % lang
    entries = ((extraction or {}).get("reachability") or {}).get("entry_points") or []
    env = _joern_env()
    cpg = os.path.join(tempfile.gettempdir(), "vexv2_%s.cpg.bin" % cve)
    script = None
    try:
        _o, _e, to = _run(_launcher_cmd(fe, ["-o", cpg, src]), env, 600)      # build base CPG
        if to:
            return "unknown", "%s CPG build timed out (600s)" % lang
        if not os.path.exists(cpg):
            return "unknown", "%s CPG build failed (%s)" % (lang, (_e or _o or "")[-140:])
        with tempfile.NamedTemporaryFile("w", suffix=".sc", delete=False,
                                         encoding="utf-8") as f:
            f.write(_query(cpg, funcs, entries))
            script = f.name
        v, err = "", ""
        for _attempt in (1, 2):                                # retry once on a
            out, err, to2 = _run(_launcher_cmd(jb, ["--script", script]), env, 300)
            if to2:
                return "unknown", "joern query timed out (300s)"
            line = next((l for l in out.splitlines() if l.startswith("VERDICT:")), "")
            v = line.split(":", 1)[1].strip() if ":" in line else ""
            if v:
                break                                          # transient repl error
        if v == "reachable":
            return "reachable", "joern: a located function is reachable from an entry point"
        if v == "not-reachable":
            return "not-reachable", "joern: no located function reachable from an entry point"
        if v == "no-target":
            return "unknown", "joern: located functions not present in the CPG"
        if v == "no-entry":
            return "unknown", "joern: no entry model"
        return "unknown", "joern: no verdict (%s)" % ((err or "")[-160:] or "no output")
    except Exception as e:
        return "unknown", "joern error: %s" % e
    finally:
        for _p in (cpg, script):
            if _p and os.path.exists(_p):
                try:
                    os.unlink(_p)
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
    for i, cve in enumerate(cves, 1):
        if not a.cve and cve in out:                 # resume: skip already-judged
            continue
        v, d = reachable(cve, loc.get(cve), cti.get(cve))
        out[cve] = {"cve": cve, "verdict": v, "detail": d}
        print("  [%3d/%3d] %-18s reachability=%-14s  %s" % (i, len(cves), cve, v, d), flush=True)
        json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)  # incremental
    print("-> %s (%d)" % (OUT, len(out)))


if __name__ == "__main__":
    main()
