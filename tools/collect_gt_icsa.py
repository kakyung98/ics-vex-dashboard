#!/usr/bin/env python3
"""Collect, as ground truth, the ICSAs where CISA left grounds for its verdict.

Very few advisories in the public ICS ecosystem carry a label amounting to a VEX
verdict. All of them are pinned inside the project so that comparison and reproduction
need no throwaway clone.

Collection tiers
  tier-1 (has a justification)  ICSAs carrying vulnerabilities[].flags[].label
                                -> the only cases stating one of CISA's five
                                   justifications
  tier-2 (status only)          ICSAs with known_not_affected but no flags
                                -> "not affected" asserted with no grounds given

Usage:
  git clone --depth 1 https://github.com/cisagov/CSAF.git /tmp/CSAF
  python tools/collect_gt_icsa.py --csaf-repo /tmp/CSAF
"""
import argparse
import glob
import json
import os
import shutil

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "data", "gt_icsa")


def scan(repo):
    t1, t2 = {}, {}
    for f in glob.glob(os.path.join(repo, "csaf_files", "OT", "**", "*.json"),
                       recursive=True):
        aid = os.path.basename(f)[:-5]
        if not aid.startswith("icsa-"):
            continue
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        doc = d.get("document", {})
        flags, kna = {}, {}
        for v in d.get("vulnerabilities", []) or []:
            cve = v.get("cve")
            if not cve:
                continue
            labs = [fl.get("label") for fl in (v.get("flags") or []) if fl.get("label")]
            if labs:
                flags[cve] = sorted(set(labs))
            ids = (v.get("product_status") or {}).get("known_not_affected") or []
            if ids:
                kna[cve] = len(ids)
        if not (flags or kna):
            continue
        rec = {
            "advisory_id": aid,
            "title": doc.get("title", ""),
            "document_category": doc.get("category"),
            "publisher": (doc.get("publisher") or {}).get("name"),
            "initial_release_date": (doc.get("tracking") or {}).get("initial_release_date"),
            "current_release_date": (doc.get("tracking") or {}).get("current_release_date"),
            "source_file": os.path.relpath(f, repo).replace("\\", "/"),
            "cisa_url": "https://www.cisa.gov/news-events/ics-advisories/%s" % aid,
            "flags": flags,
            "known_not_affected_counts": kna,
        }
        (t1 if flags else t2)[aid] = (rec, f)
    return t1, t2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csaf-repo", required=True)
    a = ap.parse_args()

    t1, t2 = scan(a.csaf_repo)
    for sub in ("tier1_justification/cisa_csaf", "tier1_justification/our_sbom",
                "tier2_status_only/cisa_csaf"):
        os.makedirs(os.path.join(OUT, sub), exist_ok=True)

    man = {"generated_from": "cisagov/CSAF (OT, icsa-* only)",
           "note": ("tier1 = carries a CISA justification (flags) - the only cases where "
                    "code or SBOM grounds are stated. tier2 = known_not_affected only, "
                    "with no grounds."),
           "tier1": [], "tier2": []}

    for aid, (rec, src) in sorted(t1.items()):
        shutil.copy2(src, os.path.join(OUT, "tier1_justification/cisa_csaf", aid + ".json"))
        ours = os.path.join(BASE, "reverse_sbom", "%s_SBOM-CVE.json" % aid)
        rec["our_sbom"] = None
        if os.path.exists(ours):
            shutil.copy2(ours, os.path.join(OUT, "tier1_justification/our_sbom",
                                            os.path.basename(ours)))
            rec["our_sbom"] = "tier1_justification/our_sbom/%s" % os.path.basename(ours)
        man["tier1"].append(rec)

    for aid, (rec, src) in sorted(t2.items()):
        shutil.copy2(src, os.path.join(OUT, "tier2_status_only/cisa_csaf", aid + ".json"))
        man["tier2"].append(rec)

    man["counts"] = {
        "tier1_advisories": len(man["tier1"]),
        "tier1_labelled_cves": sum(len(r["flags"]) for r in man["tier1"]),
        "tier1_with_our_sbom": sum(1 for r in man["tier1"] if r["our_sbom"]),
        "tier2_advisories": len(man["tier2"]),
    }
    lab = {}
    for r in man["tier1"]:
        for labs in r["flags"].values():
            for l in labs:
                lab[l] = lab.get(l, 0) + 1
    man["counts"]["justification_labels"] = dict(sorted(lab.items(), key=lambda x: -x[1]))

    with open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(man, f, ensure_ascii=False, indent=2)
    print(json.dumps(man["counts"], ensure_ascii=False, indent=2))
    print("\n-> %s" % OUT)


if __name__ == "__main__":
    main()
