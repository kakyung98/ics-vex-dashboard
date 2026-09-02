#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Collect C/C++ vuln/fix function pairs (BigVul) into VEX-justification format.

Direction-B training material for Q1/Q2/Q3 reasoning: given the vulnerable code
(and its patch context) the model learns "is the vulnerable construct present and
does it sit on a reachable/adversary-influenced path" rather than "write an
exploit". Each BigVul row gives func_before (vulnerable) and func_after (fixed).

We emit two instruction->completion examples per row:
  func_before -> affected (vulnerable code present)
  func_after  -> not_affected / vulnerable_code_not_present (fixed construct)

Filtered to C/C++ with a real before!=after diff. Balanced and capped.

Output: data/vulnfix_justify.jsonl  (merged into training by the tuner)
"""
import json, os, random

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "data", "vulnfix_justify.jsonl")
CAP = int(os.environ.get("VULNFIX_CAP", "1500"))   # rows to keep (each -> 2 examples)
SEED = 20260416

INSTR = (
    "You are a VEX analyst. Given a function from an ICS/OT software component, "
    "decide whether the product is affected by the referenced weakness, following "
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


def main():
    random.seed(SEED)
    from datasets import load_dataset
    ds = load_dataset("bstee615/bigvul", split="train", streaming=True)

    rows = []
    seen = 0
    for r in ds:
        seen += 1
        lang = (r.get("lang") or "").upper()
        if lang not in ("C", "C++", "CPP"):
            continue
        before, after = r.get("func_before"), r.get("func_after")
        if not before or not after or before.strip() == after.strip():
            continue
        cve = r.get("CVE ID") or ""
        cwe = r.get("CWE ID") or ""
        rows.append((cve, cwe, before, after, r.get("project", "")))
        if len(rows) >= CAP:
            break

    random.shuffle(rows)
    out = []
    for cve, cwe, before, after, proj in rows:
        head = "CVE: %s\nCWE: %s\nComponent: %s\n" % (cve, cwe, proj)
        out.append({
            "cve": cve, "src": "bigvul",
            "instruction": INSTR + "\n\n" + head + "Function in this build:\n```c\n" + clip(before) + "\n```",
            "completion": json.dumps({
                "status": "affected", "justification": None,
                "rationale": "The vulnerable construct (%s) is present in this function." % (cwe or "the weakness"),
            }, ensure_ascii=False),
        })
        out.append({
            "cve": cve, "src": "bigvul",
            "instruction": INSTR + "\n\n" + head + "Function in this build:\n```c\n" + clip(after) + "\n```",
            "completion": json.dumps({
                "status": "not_affected", "justification": "vulnerable_code_not_present",
                "rationale": "This function matches the fixed release; the vulnerable construct is gone.",
            }, ensure_ascii=False),
        })

    with open(OUT, "w", encoding="utf-8") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("scanned %d rows, kept %d C/C++ pairs -> %d examples" % (seen, len(rows), len(out)))
    print("output:", OUT)


if __name__ == "__main__":
    main()
