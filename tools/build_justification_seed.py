#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Assemble the VEX-justification seed dataset (system direction B).

Each example asks the model to judge a component-CVE against the four
CISA justification questions and emit a status + justification:

  Q1 vulnerable code present?      -> component_not_present / vulnerable_code_not_present
  Q2 in an executed path?          -> vulnerable_code_not_in_execute_path
  Q3 adversary-controllable?       -> vulnerable_code_cannot_be_controlled_by_adversary
  Q4 inline mitigation present?    -> inline_mitigations_already_exist
  (all pass) -> affected

Sources (all already in the repo):
  data/code_evidence.json     34 vuln/patched code pairs (fix commit + code)
  data/gt_icsa/manifest.json  18 CISA-labelled justifications (eval gold)

Outputs:
  data/vex_justify_seed.jsonl   instruction->completion training seed
  data/vex_justify_eval.jsonl   CISA-gold eval set (never trained on)
"""
import json, os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CE = os.path.join(BASE, "data", "code_evidence.json")
GT = os.path.join(BASE, "data", "gt_icsa", "manifest.json")
OUT = os.path.join(BASE, "data", "vex_justify_seed.jsonl")
EVAL = os.path.join(BASE, "data", "vex_justify_eval.jsonl")

INSTR = (
    "You are a VEX analyst. Decide whether the product is affected by the "
    "vulnerability, following the CISA justification questions in order:\n"
    "Q1 Is the vulnerable code present in the build?\n"
    "Q2 Is the vulnerable code on a path the product actually executes?\n"
    "Q3 Can an adversary control input that reaches the vulnerable code?\n"
    "Q4 Is there an inline mitigation already in the product?\n"
    "Answer with a JSON object: {\"status\": affected|not_affected, "
    "\"justification\": <one of component_not_present, vulnerable_code_not_present, "
    "vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary, "
    "inline_mitigations_already_exist, or null when affected>, \"rationale\": <one sentence>}."
)


def clip(s, n=2600):
    s = s or ""
    return s if len(s) <= n else s[:n] + "\n...[truncated]"


def main():
    ce = json.load(open(CE, encoding="utf-8"))
    seed = []

    for cve, v in ce.items():
        if not (isinstance(v, dict) and v.get("vuln_code") and v.get("patched_code")):
            continue
        comp = v.get("repo", "") or ""
        f = v.get("file", "")
        base = "CVE: %s\nComponent: %s\nFile: %s\n" % (cve, comp, f)

        # Positive: vulnerable code IS present and reachable/controllable -> affected.
        seed.append({
            "cve": cve,
            "instruction": INSTR + "\n\n" + base +
                "Vulnerable version of the code:\n```\n" + clip(v["vuln_code"]) + "\n```",
            "completion": json.dumps({
                "status": "affected", "justification": None,
                "rationale": "The vulnerable code from the fix commit is present in this build."
            }, ensure_ascii=False),
        })
        # Negative: patched code -> vulnerable code no longer present -> not_affected.
        seed.append({
            "cve": cve,
            "instruction": INSTR + "\n\n" + base +
                "Deployed version of the code:\n```\n" + clip(v["patched_code"]) + "\n```",
            "completion": json.dumps({
                "status": "not_affected", "justification": "vulnerable_code_not_present",
                "rationale": "The code matches the fixed release; the vulnerable construct is gone."
            }, ensure_ascii=False),
        })

    # Eval gold from CISA-labelled ICSA (never used for training).
    ev = []
    if os.path.exists(GT):
        man = json.load(open(GT, encoding="utf-8"))
        for r in man.get("tier1", []):
            for cve, labels in (r.get("flags") or {}).items():
                lab = labels[0]
                ev.append({
                    "advisory": r["advisory_id"], "cve": cve,
                    "gold_status": "not_affected", "gold_justification": lab,
                })

    with open(OUT, "w", encoding="utf-8") as f:
        for r in seed:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(EVAL, "w", encoding="utf-8") as f:
        for r in ev:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    import collections
    just = collections.Counter(json.loads(r["completion"])["justification"] for r in seed)
    print("seed examples : %d  -> %s" % (len(seed), OUT))
    print("  by completion justification:", dict(just))
    print("eval gold     : %d  -> %s" % (len(ev), EVAL))
    egold = collections.Counter(r["gold_justification"] for r in ev)
    print("  eval gold justifications:", dict(egold))


if __name__ == "__main__":
    main()
