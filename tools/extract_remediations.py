#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-level remediation evidence from CISA's CSAF corpus, for source-less CVEs.

When the vulnerable source cannot be obtained, the code questions Q1-Q4 cannot
be asked at all. But a CSAF advisory carries a structured field that needs no
source: `vulnerabilities[].remediations[].category`.

None of it sets a VEX status. Without source the status is `under_investigation`
and stays there - an advisory is not a substitute for looking at the code, and
`inline_mitigations_already_exist` means a mitigation compiled INTO the product,
not advice printed in an advisory.

What the remediation categories do is TRIAGE the statements already held at
`under_investigation`, so that 11,232 of them are not one undifferentiated pile:

  mitigation / workaround        -> likely_not_affected
      a published mitigation blunts exploitation wherever it is applied
  vendor_fix / none_available /  -> likely_affected
  no_fix_planned                     an unapplied patch shields nothing, and
                                     "no fix planned" shields nothing ever

The mapping lives in src/vex_decision.triage(); this tool only collects the
evidence. The label is emitted in its own field - OpenVEX and CSAF admit four
statuses and `likely_*` is not among them.

Output: data/remediations.json
  {CVE: {"advisories": [...], "categories": {...}, "vex": ..., "likelihood": ...}}
"""
import argparse
import collections
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "data", "remediations.json")

sys.path.insert(0, os.path.join(BASE, "src"))
from vex_decision import UNDER_INV, triage  # noqa: E402


def scan_doc(path):
    """(cve, category, details) for every remediation in one CSAF document."""
    try:
        d = json.load(open(path, encoding="utf-8"))
    except Exception:
        return []
    doc = d.get("document") or {}
    aid = (doc.get("tracking") or {}).get("id") or os.path.basename(path)
    out = []
    for v in d.get("vulnerabilities") or []:
        cve = v.get("cve")
        if not cve:
            continue
        for r in v.get("remediations") or []:
            out.append((cve, aid, r.get("category"), (r.get("details") or "")[:300]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csaf-repo", required=True,
                    help="clone of github.com/cisagov/CSAF")
    a = ap.parse_args()

    rows = collections.defaultdict(lambda: {"advisories": set(), "categories": collections.Counter(),
                                            "details": []})
    ndoc = 0
    for dp, _dn, fns in os.walk(a.csaf_repo):
        if ".git" in dp.replace("\\", "/").split("/"):
            continue
        for fn in fns:
            if not fn.endswith(".json"):
                continue
            hits = scan_doc(os.path.join(dp, fn))
            if hits:
                ndoc += 1
            for cve, aid, cat, det in hits:
                r = rows[cve]
                r["advisories"].add(aid)
                r["categories"][cat] += 1
                if det and len(r["details"]) < 3:
                    r["details"].append({"advisory": aid, "category": cat, "details": det})

    out, verdicts = {}, collections.Counter()
    for cve, r in rows.items():
        likelihood, why = triage(set(r["categories"]))
        verdicts[likelihood] += 1
        out[cve] = {"advisories": sorted(r["advisories"]),
                    "categories": dict(r["categories"]),
                    "details": r["details"],
                    "vex": UNDER_INV,          # never anything else from here
                    "likelihood": likelihood, "reason": why}
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    catsum = collections.Counter()
    for r in out.values():
        catsum.update(r["categories"])
    print("== CSAF remediation scan ==")
    print("   documents with remediations  %d" % ndoc)
    print("   CVEs covered                 %d" % len(out))
    print("   categories                   %s" % dict(catsum))
    print("   status                       under_investigation (all)")
    print("   triage                       %s" % dict(verdicts))
    print("->", OUT)


if __name__ == "__main__":
    main()
