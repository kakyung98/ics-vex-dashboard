#!/usr/bin/env python3
"""CISA 가 판정 근거를 남긴 ICSA 를 정답지(ground truth)로 수집한다.

공개 ICS 생태계에서 VEX 판정에 해당하는 라벨을 가진 어드바이저리는 극소수다.
그 전부를 프로젝트 안에 고정해 두어, 임시 clone 없이도 대조·재현이 가능하게 한다.

수집 계층
  tier-1 (justification 보유)  vulnerabilities[].flags[].label 이 있는 ICSA
                               -> CISA 5종 justification 이 명시된 유일한 사례
  tier-2 (status 만)           known_not_affected 는 있으나 flags 가 없는 ICSA
                               -> "영향 없음"만 있고 근거는 없는 사례

사용:
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
           "note": ("tier1 = CISA justification(flags) 보유 — 코드/SBOM 근거가 명시된 유일한 사례. "
                    "tier2 = known_not_affected 만 있고 근거 없음."),
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
