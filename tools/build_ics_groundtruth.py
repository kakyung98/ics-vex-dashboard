#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build vuln/patched ground-truth pairs for the ICS source-available CVEs.

Source: data/code_evidence.json — CVEs with full vulnerable/patched function code
collected from the upstream GitHub fix commits.

Output: data/ics_gt_pairs.jsonl  [{cve, cwe, repo, vuln_code, patched_code}]
This is the ground truth the judge is scored on for the ICS target population.
"""
import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CE = os.path.join(BASE, "data", "code_evidence.json")
OUT = os.path.join(BASE, "data", "ics_gt_pairs.jsonl")


def main():
    ce = json.load(open(CE, encoding="utf-8"))
    pairs = []
    for cve, v in ce.items():
        if isinstance(v, dict) and v.get("vuln_code") and v.get("patched_code"):
            pairs.append({"cve": cve, "cwe": v.get("cwe", ""), "repo": v.get("repo", ""),
                          "vuln_code": v["vuln_code"], "patched_code": v["patched_code"]})

    with open(OUT, "w", encoding="utf-8") as f:
        for r in pairs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("ground-truth pairs: %d CVEs" % len(pairs))
    print("->", OUT)


if __name__ == "__main__":
    main()
