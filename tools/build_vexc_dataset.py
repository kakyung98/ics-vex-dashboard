#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the enlarged, de-duplicated VEX-justification training set.

Merges multiple public C/C++ vulnerability corpora, maps each function to a VEX
judgment (vulnerable -> affected / safe|patched -> not_affected), de-duplicates
by normalized code hash across ALL sources, and balances the two classes.

Sources:
  data/vex_justify_seed.jsonl   project fix-commit pairs (already built)
  data/vulnfix_justify.jsonl    BigVul pairs (already built)
  DiverseVul  (bstee615/diversevul)   streamed, capped
  PrimeVul    (colin/PrimeVul)        streamed, capped

Output: data/vex_train_full.jsonl  (balanced)  + prints composition.
"""
import hashlib
import json
import os
import random
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "data", "vex_train_full.jsonl")
DIVERSE_PER_CLASS = int(os.environ.get("DIVERSE_PER_CLASS", "6000"))
PRIME_PER_CLASS = int(os.environ.get("PRIME_PER_CLASS", "3000"))
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


def norm_hash(code):
    return hashlib.sha1(re.sub(r"\s+", "", code or "").encode("utf-8", "ignore")).hexdigest()


def ex(code, cwe, proj, status):
    if status == "affected":
        comp = {"status": "affected", "justification": None,
                "rationale": "The vulnerable construct (%s) is present in this function." % (cwe or "the weakness")}
        head = "CWE: %s\nComponent: %s\n" % (cwe, proj)
    else:
        comp = {"status": "not_affected", "justification": "vulnerable_code_not_present",
                "rationale": "No vulnerable construct is present in this function."}
        head = "Component: %s\n" % proj
    return {"instruction": INSTR + "\n\n" + head + "Function in this build:\n```c\n" + clip(code) + "\n```",
            "completion": json.dumps(comp, ensure_ascii=False)}


def main():
    random.seed(SEED)
    seen = set()
    aff, naf = [], []

    def add_(code, cwe, proj, status, src, cve=None):
        if not code or "{" not in code:
            return
        h = norm_hash(code)
        if h in seen:
            return
        seen.add(h)
        r = ex(code, cwe, proj, status)
        r["src"] = src
        if cve:
            r["cve"] = cve
        (aff if status == "affected" else naf).append(r)

    # 1) existing local files (seed + bigvul) — re-parse their code out of the prompt is lossy,
    #    so just carry them through as-is (they are already deduped small sets).
    carry = []
    for f, src in [("data/vex_justify_seed.jsonl", "seed"), ("data/vulnfix_justify.jsonl", "bigvul")]:
        p = os.path.join(BASE, f)
        if os.path.exists(p):
            for l in open(p, encoding="utf-8"):
                r = json.loads(l)
                # dedup carries by instruction hash
                h = hashlib.sha1(r["instruction"].encode("utf-8", "ignore")).hexdigest()
                if h in seen:
                    continue
                seen.add(h)
                st = json.loads(r["completion"]).get("status")
                (aff if st == "affected" else naf).append(r)
                carry.append(src)

    from datasets import load_dataset

    # 2) DiverseVul
    try:
        ds = load_dataset("bstee615/diversevul", split="train", streaming=True)
        nv = ns = 0
        for r in ds:
            cwe = r.get("cwe") or []
            cwe = (cwe[0] if isinstance(cwe, list) and cwe else "") or ""
            proj = r.get("project", "")
            if r.get("target") == 1 and nv < DIVERSE_PER_CLASS:
                add_(r.get("func"), cwe, proj, "affected", "diversevul"); nv += 1
            elif r.get("target") == 0 and ns < DIVERSE_PER_CLASS:
                add_(r.get("func"), cwe, proj, "not_affected", "diversevul"); ns += 1
            if nv >= DIVERSE_PER_CLASS and ns >= DIVERSE_PER_CLASS:
                break
    except Exception as e:
        print("diversevul skipped:", str(e)[:120])

    # 3) PrimeVul
    try:
        ds = load_dataset("colin/PrimeVul", split="train", streaming=True)
        nv = ns = 0
        for r in ds:
            cwe = r.get("cwe") or []
            cwe = (cwe[0] if isinstance(cwe, list) and cwe else "") or ""
            proj = r.get("project", "")
            cve = r.get("cve")
            if r.get("target") == 1 and nv < PRIME_PER_CLASS:
                add_(r.get("func"), cwe, proj, "affected", "primevul", cve); nv += 1
            elif r.get("target") == 0 and ns < PRIME_PER_CLASS:
                add_(r.get("func"), cwe, proj, "not_affected", "primevul", cve); ns += 1
            if nv >= PRIME_PER_CLASS and ns >= PRIME_PER_CLASS:
                break
    except Exception as e:
        print("primevul skipped:", str(e)[:120])

    # 4) CVEfixes (C only) — vulnerable_code / secure_code pairs
    try:
        ds = load_dataset("rufimelo/cvefixes-cwe", split="train", streaming=True)
        nc = 0
        CVEFIX_CAP = int(os.environ.get("CVEFIX_CAP", "4000"))
        for r in ds:
            if (r.get("language") or "").lower() not in ("c", "c++", "cpp"):
                continue
            cwe = r.get("cwe") or ""
            proj = (r.get("repository") or "").split("@")[0]
            add_(r.get("vulnerable_code"), cwe, proj, "affected", "cvefixes")
            add_(r.get("secure_code"), cwe, proj, "not_affected", "cvefixes")
            nc += 1
            if nc >= CVEFIX_CAP:
                break
    except Exception as e:
        print("cvefixes skipped:", str(e)[:120])

    # balance
    random.shuffle(aff); random.shuffle(naf)
    n = min(len(aff), len(naf))
    rows = aff[:n] + naf[:n]
    random.shuffle(rows)
    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    import collections
    src = collections.Counter(r.get("src", "?") for r in rows)
    print("affected pool %d | not_affected pool %d -> balanced %d each" % (len(aff), len(naf), n))
    print("total: %d  | by src: %s" % (len(rows), dict(src)))
    print("output:", OUT)


if __name__ == "__main__":
    main()
