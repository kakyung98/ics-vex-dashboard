#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""시험항목 #4 — VEX 기반 식별된 취약점 영향 판단 정밀도의 평가용 Ground Truth 생성.

The judged population is the source-collected CVEs (data/source_snapshots/, 107).
`vex_judge_v2` returns `affected` for every one of them, so precision = TP/(TP+FP)
is settled entirely by the ground truth — and a positives-only GT would make it the
identity 1.0. The GT therefore has to carry `not_affected` labels earned from
evidence, which is what these two evidence types provide (vendor_asserted is
excluded by choice: a vendor assertion with no source behind it cannot adjudicate a
code-level verdict).

  execution_verified   results/exec_verification*.json
        A build-and-run pair: the vulnerable version crashes under a sanitizer, the
        patched version does not. One record yields TWO cases — affected on the
        vulnerable build, not_affected on the patched one — which is where the
        `not_affected` side of the benchmark comes from.

  patch_verified       data/patches/<CVE>/<commit>.diff  x  the collected snapshot
        A fix commit turns specific lines vulnerable -> fixed. tools/fixed_check
        compares those signatures against the source actually collected:
          vulnerable lines present, fix absent  -> affected
          fix lines present, vulnerable absent  -> not_affected (fixed)
          anything else                         -> inconclusive, excluded
        Driven from the 91 downloaded fix-commit diffs rather than the 15 hunks in
        code_evidence.json, which is what makes the coverage usable at all.

Every label is a verdict about ONE BUILD, not about a CVE: the same CVE is affected
in its vulnerable snapshot and not_affected in its patched release. `build` names
which, so the eval feeds the SUT the matching snapshot instead of silently scoring
two contradictory labels against one run.

Out: data/vex_gt_104.jsonl              scorable GT (HWP 평가용 Ground Truth schema)
     data/vex_gt_104_manifest.json      coverage, exclusions, evidence-type mix
"""
import argparse
import collections
import glob
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "tools"))
from fixed_check import check as patch_signature_check
sys.path.insert(0, os.path.join(BASE, "src"))
from sbom_match import cmp_ver

SNAP = os.path.join(BASE, "data", "source_snapshots")
FIXED = os.path.join(BASE, "data", "fixed_releases")
PATCHES = os.path.join(BASE, "data", "patches")
EXEC_FILES = ["results/exec_verification_batch.json", "results/exec_verification_c.json",
              "results/exec_verification.json"]
OUT = os.path.join(BASE, "data", "vex_gt_104.jsonl")
MANIFEST = os.path.join(BASE, "data", "vex_gt_104_manifest.json")

C_EXT = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh")
NVD_URL = "https://nvd.nist.gov/vuln/detail/%s"


def diff_hunks(diff_text):
    """Per-file (path, vuln_code, patched_code) from a unified git diff.

    The parser in build_ics_groundtruth merges every C file in the commit into one
    blob, which loses the path. fixed_check needs the path to locate the file inside
    the snapshot, so the files are kept separate here.
    """
    out, path, before, after = [], None, [], []

    def flush():
        if path and (before or after):
            out.append((path, "\n".join(before).strip(), "\n".join(after).strip()))

    for line in diff_text.split("\n"):
        if line.startswith("diff --git"):
            flush()
            m = re.search(r" b/(\S+)", line)
            path = m.group(1) if m and m.group(1).lower().endswith(C_EXT) else None
            before, after = [], []
            continue
        if path is None:
            continue
        if line.startswith(("+++", "---", "@@", "index ", "new file", "deleted file",
                            "similarity index", "rename ")):
            continue
        if line.startswith("-"):
            before.append(line[1:])
        elif line.startswith("+"):
            after.append(line[1:])
        elif line.startswith(" "):
            before.append(line[1:])
            after.append(line[1:])
    flush()
    return out


def load_execution_pairs():
    """CVE -> [{vuln_version, patched_version, signal, method, source}] for records
    that actually ran both sides. A record without the patched side proves only the
    affected half, so it is kept but marked."""
    pairs = collections.defaultdict(list)
    for rel in EXEC_FILES:
        fp = os.path.join(BASE, rel)
        if not os.path.isfile(fp):
            continue
        for r in json.load(open(fp, encoding="utf-8")):
            cve = r.get("cve")
            if not cve:
                continue
            if "vuln_crash" in r:                       # C/sanitizer pair
                pairs[cve].append({
                    "vuln_version": r.get("vuln_version"),
                    "patched_version": r.get("patched_version"),
                    "vuln_triggered": bool(r.get("vuln_crash")),
                    "patched_triggered": bool(r.get("patched_crash")),
                    "signal": r.get("signal"), "method": r.get("method"),
                    "component": r.get("component"), "source": rel})
            elif r.get("versions"):                     # python install/trigger pair
                vs = r["versions"]
                vuln = next((v for v in vs if v.get("expect_trigger")), None)
                fixed = next((v for v in vs if not v.get("expect_trigger")), None)
                if vuln and fixed:
                    pairs[cve].append({
                        "vuln_version": vuln.get("version"),
                        "patched_version": fixed.get("version"),
                        "vuln_triggered": bool(vuln.get("triggered")),
                        "patched_triggered": bool(fixed.get("triggered")),
                        "signal": ", ".join(vuln.get("evidence") or []) or None,
                        "method": "install version, execute trigger",
                        "component": r.get("package"), "source": rel})
    return pairs


def execution_cases(pairs):
    """affected on the vulnerable build, not_affected on the patched build.

    Only emitted when the run actually discriminates: the vulnerable side triggered
    and the patched side did not. A pair where neither triggered proves nothing about
    presence (the trigger may simply not reach), so it is excluded rather than read
    as not_affected on both sides.
    """
    cases, skipped = [], []
    for cve, recs in pairs.items():
        for r in recs:
            if not (r["vuln_triggered"] and not r["patched_triggered"]):
                skipped.append({"cve": cve, "reason": "run did not discriminate "
                                "(vuln_triggered=%s, patched_triggered=%s)"
                                % (r["vuln_triggered"], r["patched_triggered"]),
                                "source": r["source"]})
                continue
            ref = "%s (%s)" % (r["source"], r.get("signal") or "executed")
            for ver, status in ((r["vuln_version"], "affected"),
                                (r["patched_version"], "not_affected")):
                if not ver:
                    continue
                cases.append({"cve_id": cve, "expected_status": status,
                              "evidence_type": "execution_verified",
                              "evidence_reference": ref,
                              "_build": "vulnerable" if status == "affected" else "patched",
                              "_version": ver, "_component": r.get("component"),
                              "_method": r.get("method"), "_detail": r.get("signal")})
    return cases, skipped


_DETAIL_RE = re.compile(r"fix-lines (\d+)/(\d+), vuln-lines (\d+)/(\d+)")
_RANGES = os.path.join(BASE, "data", "cve_version_ranges.json")
_LOCS = os.path.join(BASE, "data", "source_locations.json")


def _nz(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def snapshot_version(dirname):
    """Version out of a snapshot directory name.

    The corpus names them `curl-curl-7_64_0`, `openssh-portable-V_9_6_P1`,
    `busybox-1_30_1`, `u-boot-2020.04`, `linux-4.9.337` — a project prefix, then the
    version with `_` for `.` and sometimes a `V` prefix / `P1` patch suffix.
    """
    s = re.sub(r"^[A-Za-z][A-Za-z0-9+._-]*?[-_](?=[Vv]?[0-9_.])", "", dirname, count=1)
    s = re.sub(r"^[Vv](?=[0-9])", "", s).replace("_", ".")
    s = re.sub(r"\.?[Pp](\d)", r"p\1", s)
    m = re.search(r"\d[\d.]*[a-z]?\d*", s)
    return m.group(0) if m else None


def nvd_still_affected(cve, version, ranges, locs):
    """Does NVD's product-matched range still cover this version?

    True / False / None(no usable range). The product filter is essential: a CVE's
    ranges include every co-listed product, so CVE-2024-6387's list carries NetApp
    bounds (10.0.0, 11.70.2) alongside OpenSSH's, and comparing against those said
    'fixed' for an OpenSSH 9.6p1 snapshot that is squarely inside openssh 8.6-9.8.
    """
    if not version:
        return None
    comp = _nz((locs.get(cve) or {}).get("component"))
    entries = []
    for e in ranges.get(cve) or []:
        p = _nz(e.get("product"))
        if comp and p and (p in comp or comp in p):
            entries.append(e)
    if not entries:
        return None
    for e in entries:
        lo, hi_e, hi_i = e.get("startIncl"), e.get("endExcl"), e.get("endIncl")
        inside = True
        for bound, violates in ((lo, lambda c: c < 0), (hi_e, lambda c: c >= 0),
                                (hi_i, lambda c: c > 0)):
            if bound:
                c = cmp_ver(version, bound)
                if c is not None and violates(c):
                    inside = False
                    break
        if inside:
            return True            # an entry (possibly all-null = every version) covers it
    return False


def _has_positive_fix_evidence(detail):
    """Did the check actually find fix lines in the source?

    fixed_check reports "fix-lines H/N, vuln-lines H/N". H=0 with N=0 means the fix
    commit had no distinctive added line for this file, so the `fixed` verdict rests
    entirely on the vulnerable lines being missing — which a failed file/line match
    produces just as readily as a patched build.
    """
    m = _DETAIL_RE.search(detail or "")
    return bool(m) and int(m.group(1)) >= 1


def vulnerable_files():
    """CVE -> {basenames of the files the vulnerable function was located in}.

    Needed to pick the right hunk. A fix commit touches more than the vulnerability:
    zlib's CVE-2016-9840 commit also bumps the version string in `zlib.h`, and judging
    the build from that hunk produced a `vulnerable` verdict out of a file the CVE has
    nothing to do with. data/source_locations.json already records where the vulnerable
    function actually lives (inftrees.c), so hunks there are preferred.
    """
    out = {}
    fp = os.path.join(BASE, "data", "source_locations.json")
    if not os.path.isfile(fp):
        return out
    for cve, rec in json.load(open(fp, encoding="utf-8")).items():
        names = set()
        for fn in rec.get("functions") or []:
            if fn.get("file"):
                names.add(os.path.basename(fn["file"]).lower())
        if names:
            out[cve] = names
    return out


def rank_hunks(evs, vuln_names):
    """Hunks most likely to carry the vulnerability first.

    1. the file the vulnerable function was located in
    2. any implementation file (.c/.cc/.cpp)
    3. the rest (headers, which in a fix commit are usually version bumps)
    """
    def rank(ev):
        base = os.path.basename(ev["file"]).lower()
        if vuln_names and base in vuln_names:
            return 0
        return 1 if base.endswith((".c", ".cc", ".cpp", ".cxx")) else 2
    return sorted(evs, key=rank), {0: "vuln-located file", 1: "implementation file",
                                   2: "header/other"}


def patch_cases(limit_cves=None):
    """Run the patch-signature check against the collected snapshot, and against the
    patched release where one was downloaded."""
    cases, inconclusive, conflicts = [], [], []
    vuln_names_all = vulnerable_files()
    ranges = json.load(open(_RANGES, encoding="utf-8")) if os.path.isfile(_RANGES) else {}
    locs = json.load(open(_LOCS, encoding="utf-8")) if os.path.isfile(_LOCS) else {}
    cves = sorted(os.listdir(SNAP))
    if limit_cves:
        cves = [c for c in cves if c in limit_cves]
    for cve in cves:
        diffs = sorted(glob.glob(os.path.join(PATCHES, cve, "*.diff")))
        if not diffs:
            inconclusive.append({"cve": cve, "reason": "no fix-commit diff downloaded"})
            continue
        evs = []
        for dp in diffs:
            try:
                text = open(dp, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            for path, vuln, patched in diff_hunks(text):
                if vuln and patched:
                    evs.append({"file": path, "vuln_code": vuln,
                                "patched_code": patched, "commit": os.path.basename(dp)})
        if not evs:
            inconclusive.append({"cve": cve, "reason": "diff carried no C/C++ hunk"})
            continue

        # version of the tree each build points at, for the NVD cross-check
        snap_versions = {}
        for _b, _r in (("vulnerable", os.path.join(SNAP, cve)),
                       ("patched", os.path.join(FIXED, cve))):
            if os.path.isdir(_r):
                inner = [d for d in os.listdir(_r)
                         if os.path.isdir(os.path.join(_r, d))]
                snap_versions[_r] = snapshot_version(inner[0]) if inner else None
        vuln_names = vuln_names_all.get(cve) or set()
        ranked, tiers = rank_hunks(evs, vuln_names)
        for build, root in (("vulnerable", os.path.join(SNAP, cve)),
                            ("patched", os.path.join(FIXED, cve))):
            if not os.path.isdir(root):
                continue
            # the first hunk to return a definite verdict decides, in rank order, so
            # the vulnerability's own file is consulted before a version-bump header
            decided = None
            for ev in ranked:
                v = patch_signature_check(cve, ev, root)
                if v["verdict"] in ("vulnerable", "fixed"):
                    decided = (ev, v)
                    break
            if decided is None:
                inconclusive.append({"cve": cve, "build": build,
                                     "reason": "patch signature inconclusive in %d hunk(s)"
                                               % len(evs)})
                continue
            ev, v = decided
            corroboration = None
            if v["verdict"] == "fixed":
                still = nvd_still_affected(cve, snap_versions.get(root), ranges, locs)
                if still is True:
                    # NVD's own range contradicts the code-level "fixed": the patch
                    # signature found the fix lines, but this version is inside the
                    # affected range (openssh 9.6p1 against openssh 8.6-9.8). Two
                    # authorities disagree, so it is not a usable not_affected label —
                    # and a wrong not_affected charges the SUT with an FP it did not
                    # commit, which is the costlier error for a precision metric.
                    conflicts.append({"cve": cve, "build": build,
                                      "reason": "patch signature says fixed but NVD "
                                                "range still covers %s"
                                                % snap_versions.get(root),
                                      "detail": v.get("detail")})
                    continue
                corroboration = {True: None, False: "patch+nvd",
                                 None: "patch-only"}[still]
            if v["verdict"] == "fixed" and not _has_positive_fix_evidence(v["detail"]):
                # `fixed` with zero fix-lines found rests only on the vulnerable lines
                # being absent, which is indistinguishable from never having located
                # the code (CVE-2016-9318: fix-lines 0/0, vuln-lines 0/3 in parser.c).
                # A not_affected label needs the fix to be positively present, because
                # a wrong not_affected charges the SUT with an FP it did not commit.
                inconclusive.append({"cve": cve, "build": build,
                                     "reason": "fixed verdict without positive fix "
                                               "evidence (%s)" % v["detail"]})
                continue
            base = os.path.basename(ev["file"]).lower()
            tier = 0 if base in vuln_names else (
                1 if base.endswith((".c", ".cc", ".cpp", ".cxx")) else 2)
            status = "affected" if v["verdict"] == "vulnerable" else "not_affected"
            cases.append({"cve_id": cve, "expected_status": status,
                          "evidence_type": "patch_verified",
                          "evidence_reference": "data/patches/%s/%s (%s) vs %s" % (
                              cve, ev["commit"], ev["file"], os.path.relpath(root, BASE)),
                          "_build": build, "_version": None, "_component": None,
                          "_method": "fix-signature line match (tools/fixed_check)",
                          "_detail": v.get("detail"),
                          "_hunk_basis": tiers[tier],
                          "_corroboration": corroboration,
                          "_snapshot_version": snap_versions.get(root)})
    return cases, inconclusive, conflicts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="comma-separated CVEs, for a quick pass")
    ap.add_argument("--population", help="JSON file whose keys fix the population "
                                         "(e.g. results/_vuln_targets_104.json for the "
                                         "104 the test document names, a clean subset "
                                         "of the 107 snapshots collected since)")
    ap.add_argument("--out", help="write elsewhere than data/vex_gt_104.jsonl")
    a = ap.parse_args()
    limit = set(a.only.split(",")) if a.only else None
    population = None
    if a.population:
        population = set(json.load(open(a.population, encoding="utf-8")))
        limit = population & limit if limit else population

    pairs = load_execution_pairs()
    exec_rows, exec_skipped = execution_cases(pairs)
    if population is not None:
        exec_rows = [r for r in exec_rows if r["cve_id"] in population]
    patch_rows, patch_skipped, patch_conflicts = patch_cases(limit)

    # execution outranks patch signature for the same (CVE, build): it observed the
    # fault, the signature only inferred it
    rows, seen = [], set()
    for r in exec_rows + patch_rows:
        key = (r["cve_id"], r["_build"])
        if key in seen:
            continue
        seen.add(key)
        rows.append(r)

    rows.sort(key=lambda r: (r["cve_id"], r["_build"]))
    for i, r in enumerate(rows, 1):
        r["test_case_id"] = "VEX-TC-%04d" % i
        r["review_status"] = "verified"

    order = ["test_case_id", "cve_id", "expected_status", "evidence_type",
             "evidence_reference", "review_status"]
    out_path = a.out or OUT
    with open(out_path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps({**{k: r[k] for k in order},
                                **{k: v for k, v in r.items() if k.startswith("_")}},
                               ensure_ascii=False) + "\n")

    status = collections.Counter(r["expected_status"] for r in rows)
    etype = collections.Counter(r["evidence_type"] for r in rows)
    mix = collections.Counter((r["evidence_type"], r["expected_status"]) for r in rows)
    pop_n = len(population) if population is not None else len(os.listdir(SNAP))
    manifest = {
        "test": "VEX affected-judgment precision (시험항목 #4) — ground truth",
        "population_source_collected": pop_n,
        "population_source": (a.population if a.population
                              else "data/source_snapshots/ (all collected)"),
        "evidence_types_included": ["execution_verified", "patch_verified"],
        "evidence_types_excluded": ["vendor_asserted", "advisory_verified"],
        "exclusion_reason": "a vendor or advisory assertion carries no source, so it "
                            "cannot adjudicate a code-level verdict; including it "
                            "would let the benchmark grade the SUT against the same "
                            "class of claim the SUT exists to replace",
        "counts": {"cases": len(rows), "cves_covered": len({r["cve_id"] for r in rows}),
                   "by_status": dict(status), "by_evidence_type": dict(etype),
                   "by_type_and_status": {"%s/%s" % k: v for k, v in mix.items()}},
        "excluded": {"execution_non_discriminating": len(exec_skipped),
                     "patch_inconclusive": len(patch_skipped),
                     "patch_nvd_conflict": len(patch_conflicts)},
        "conflict_cases": patch_conflicts,
        "corroboration": dict(collections.Counter(
            r.get("_corroboration") for r in rows if r.get("_corroboration"))),
        "labelling_unit": "one (CVE, build) pair — the same CVE is affected in its "
                          "vulnerable snapshot and not_affected in its patched "
                          "release, so a label is about a build, never about a CVE",
        "precedence": "execution_verified overrides patch_verified for the same "
                      "(CVE, build): one observed the fault, the other inferred it",
    }
    man_path = (os.path.splitext(out_path)[0] + "_manifest.json") if a.out else MANIFEST
    json.dump(manifest, open(man_path, "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)

    print("=== 시험항목 #4 GT ===")
    print("  population (source-collected) : %d CVEs  [%s]"
          % (pop_n, a.population or "all snapshots"))
    print("  cases                         : %d  (CVEs covered: %d)"
          % (len(rows), len({r["cve_id"] for r in rows})))
    print("  by status                     : %s" % dict(status))
    print("  by evidence type              : %s" % dict(etype))
    print("  type/status mix               : %s"
          % {"%s/%s" % k: v for k, v in mix.items()})
    print("  excluded: exec non-discriminating=%d  patch inconclusive=%d  "
          "patch/NVD conflict=%d"
          % (len(exec_skipped), len(patch_skipped), len(patch_conflicts)))
    corr = collections.Counter(r.get("_corroboration") for r in rows
                               if r.get("_corroboration"))
    if corr:
        print("  not_affected corroboration    : %s" % dict(corr))
    if not status.get("not_affected"):
        print("  WARNING: no not_affected label — precision would be the identity 1.0")
    print("->", out_path)
    print("->", man_path)


if __name__ == "__main__":
    main()
