#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Add DiverseVul C/C++ functions to the VEX-justification training set.

DiverseVul labels individual functions vulnerable(1)/safe(0) with CWE + project.
For direction B (Q1: is the vulnerable code present?) this maps directly:
  target==1 -> affected (vulnerable construct present)
  target==0 -> not_affected / vulnerable_code_not_present (benign code)

Balanced, C/C++ only, capped. Output: data/diversevul_justify.jsonl
"""
import json
import os
import random

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "data", "diversevul_justify.jsonl")
PER_CLASS = int(os.environ.get("DIVERSE_PER_CLASS", "3500"))   # vuln + safe each
SEED = 20260416

INSTR = (
    "You are a VEX analyst. Given a function from an ICS/OT software component, "
    "decide whether the product is affected by a potential weakness, following "
    "the CISA justification questions in order:\n"
    "Q1 Is the vulnerable code present?\n"
    "Q2 Is it on a path the product executes?\n"
    "Q3 Can an adversary control input that reaches it?\n"
    "Q4 Is there an inline mitigation already present?\n"
    "Answer with JSON: {\"status\": affected|not_affected, \"justification\": "
    "<component_not_present|vulnerable_code_not_present|vulnerable_code_not_in_execute_path|"
    "vulnerable_code_cannot_be_controlled_by_adversary|inline_mitigations_already_exist|null>, "
    "\"rationale\": <one sentence>}."
)


def clip(s, n=2400):
    s = s or ""
    return s if len(s) <= n else s[:n] + "\n...[truncated]"


def looks_c(code):
    # DiverseVul is C/C++; keep functions that look like C/C++ definitions
    return code and ("{" in code) and (";" in code)


def main():
    random.seed(SEED)
    from datasets import load_dataset
    ds = load_dataset("bstee615/diversevul", split="train", streaming=True)

    vuln, safe = [], []
    seen = 0
    for r in ds:
        seen += 1
        code = r.get("func")
        if not looks_c(code):
            continue
        cwe = r.get("cwe") or []
        cwe = cwe[0] if isinstance(cwe, list) and cwe else (cwe if isinstance(cwe, str) else "")
        proj = r.get("project", "")
        tgt = r.get("target")
        rec = (code, cwe, proj)
        if tgt == 1 and len(vuln) < PER_CLASS:
            vuln.append(rec)
        elif tgt == 0 and len(safe) < PER_CLASS:
            safe.append(rec)
        if len(vuln) >= PER_CLASS and len(safe) >= PER_CLASS:
            break

    rows = []
    for code, cwe, proj in vuln:
        rows.append({
            "src": "diversevul",
            "instruction": INSTR + "\n\nCWE: %s\nComponent: %s\nFunction in this build:\n```c\n%s\n```" % (cwe, proj, clip(code)),
            "completion": json.dumps({"status": "affected", "justification": None,
                "rationale": "The vulnerable construct (%s) is present in this function." % (cwe or "the weakness")}, ensure_ascii=False),
        })
    for code, cwe, proj in safe:
        rows.append({
            "src": "diversevul",
            "instruction": INSTR + "\n\nComponent: %s\nFunction in this build:\n```c\n%s\n```" % (proj, clip(code)),
            "completion": json.dumps({"status": "not_affected", "justification": "vulnerable_code_not_present",
                "rationale": "No vulnerable construct is present in this function."}, ensure_ascii=False),
        })
    random.shuffle(rows)
    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("scanned %d rows; kept vuln=%d safe=%d -> %d examples" % (seen, len(vuln), len(safe), len(rows)))
    print("output:", OUT)


if __name__ == "__main__":
    main()
