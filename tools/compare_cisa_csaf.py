#!/usr/bin/env python3
"""Compare our VEX verdicts 1:1 with the original CISA CSAF, per ICSA.

Because the axis is the ICSA advisory, our output (reverse_sbom/<icsa-id>_SBOM-CVE.json,
results/vex_batch.jsonl) corresponds file-for-file with the CISA original
(cisagov/CSAF: csaf_files/OT/white/<year>/<icsa-id>.json).

Usage:
  git clone --depth 1 https://github.com/cisagov/CSAF.git /path/to/CSAF
  python tools/compare_cisa_csaf.py --csaf-repo /path/to/CSAF

CISA does not use the csaf_vex profile for OT advisories and almost never leaves a
justification (flags), so there are very few labels to compare against. That scarcity is
itself the result.
"""
import argparse
import collections
import glob
import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_ours():
    """ICSA -> {cve: (status, justification)}"""
    out = collections.defaultdict(dict)
    p = os.path.join(BASE, "results", "vex_batch.jsonl")
    for line in open(p, encoding="utf-8"):
        r = json.loads(line)
        out[r["device"]][r["cve"]] = (r["final_vex"], r.get("justification"), r.get("route"))
    return out


def load_cisa(repo):
    """ICSA -> {"category":…, "status":{cve:{status}}, "flags":{cve:{label}}}"""
    out = {}
    for f in glob.glob(os.path.join(repo, "csaf_files", "OT", "**", "*.json"),
                       recursive=True):
        aid = os.path.basename(f)[:-5]
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        rec = {"category": d.get("document", {}).get("category"),
               "status": {}, "flags": {}}
        for v in d.get("vulnerabilities", []) or []:
            cve = v.get("cve")
            if not cve:
                continue
            rec["status"][cve] = {k for k, ids in (v.get("product_status") or {}).items() if ids}
            labs = {fl.get("label") for fl in (v.get("flags") or []) if fl.get("label")}
            if labs:
                rec["flags"][cve] = labs
        out[aid] = rec
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csaf-repo", required=True, help="local clone of cisagov/CSAF")
    a = ap.parse_args()

    ours, cisa = load_ours(), load_cisa(a.csaf_repo)
    common = sorted(set(ours) & set(cisa))
    print("our ICSAs        : %d" % len(ours))
    print("CISA OT CSAF     : %d" % len(cisa))
    print("comparable ICSAs : %d" % len(common))

    prof = collections.Counter(cisa[a_]["category"] for a_ in common)
    print("\nCISA document profiles: %s" % dict(prof))

    # Where CISA left a justification (flags) - the only external ground truth
    labelled = [a_ for a_ in common if cisa[a_]["flags"]]
    print("\nICSAs where CISA left a justification: %d" % len(labelled))
    n_pairs = 0
    ingested = derived_agree = derived_total = just_match = 0
    rows = []
    for aid in labelled:
        for cve, labs in cisa[aid]["flags"].items():
            got = ours[aid].get(cve)
            if not got:
                continue
            ours_st, ours_j, route = got
            n_pairs += 1
            is_up = (route == "upstream-cisa-csaf")
            if is_up:
                ingested += 1
                just_match += bool(ours_j in labs)
            else:
                derived_total += 1
                derived_agree += bool(ours_st == "LIKELY_NOT_AFFECTED")
            rows.append((aid, cve, sorted(labs)[0], ours_st, ours_j,
                         "ingested" if is_up else "derived"))
    print("(ICSA, CVE) pairs compared : %d" % n_pairs)
    print()
    print("  [A] upstream-adopted (carried straight from CISA CSAF) : %d" % ingested)
    if ingested:
        print("      justification matched too                     : %d/%d"
              % (just_match, ingested))
    print("      -> not own adjudication performance. Always excluded from the metrics.")
    print()
    print("  [B] own derivation                                    : %d" % derived_total)
    if derived_total:
        print("      we also said not_affected                     : %d (%.0f%%)"
              % (derived_agree, 100.0 * derived_agree / derived_total))
    else:
        print("      (all were upstream-adopted, so no pair is left to derive)")
    print(
          "%-18s %-16s %-36s %-22s %-34s %s"
          % ("ICSA", "CVE", "CISA flag", "ours", "our justification", "origin"))
    for r in rows[:40]:
        print("%-18s %-16s %-36s %-22s %-34s %s"
              % (r[0], r[1], r[2], r[3], r[4] or "-", r[5]))

    # Where CISA used known_not_affected, even without flags
    kna = [a_ for a_ in common if any("known_not_affected" in v
                                      for v in cisa[a_]["status"].values())]
    print("\nICSAs where CISA used known_not_affected: %d" % len(kna))


if __name__ == "__main__":
    main()
