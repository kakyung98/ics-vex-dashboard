#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Path C: rank a snapshot's functions by CodeBERT vulnerability score.

Used only where no fix commit (path A) and no NVD function mention (path B)
identifies the vulnerable function. The model is the Devign-fine-tuned CodeBERT
from src/train_codebert_finetune.py — a generic "does this function look
vulnerable" classifier, so it ranks; it does not identify.

That is why a path-C target may never justify `not_affected`: an unreachable
guess says nothing about the CVE. It can only keep a CVE in the affected pool.

  --eval   score the ranker against the CVEs whose target IS known (A/B),
           reporting top-1/5/20 recall — the honest measure of path C.
  default  emit top-k targets for the CVEs with no known target.

Output: results/codebert_rank.json (eval) / data/vuln_targets_c.json (targets)
"""
import argparse
import json
import os

import torch

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDX = os.path.join(BASE, "data", "func_index")
SNAP = os.path.join(BASE, "data", "source_snapshots")
TARGETS = os.path.join(BASE, "data", "vuln_targets.json")
MODEL = os.path.join(BASE, "models", "codebert-vuln")
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
MAXLEN = 384
CAP = 4000          # functions scored per CVE, largest snapshots would not fit


def load_funcs(cve, index, cap=CAP, only_files=None):
    """(name, file, source text) for each function, longest-first up to `cap`."""
    # func_index paths are relative to the snapshot root (build_func_index.py)
    root = os.path.join(SNAP, cve)
    by_file = {}
    for name, locs in index.items():
        for f, s, e in locs:
            if only_files and f not in only_files:
                continue
            by_file.setdefault(f, []).append((name, s, e))
    out = []
    for f, items in by_file.items():
        p = os.path.join(root, f.replace("/", os.sep))
        if not os.path.exists(p):
            continue
        try:
            lines = open(p, encoding="utf-8", errors="ignore").read().splitlines()
        except OSError:
            continue
        for name, s, e in items:
            if e - s < 2:                      # one-liners carry no signal
                continue
            out.append((name, f, "\n".join(lines[s:e + 1])[:8000]))
    out.sort(key=lambda x: -len(x[2]))
    return out[:cap]


def scorer():
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL).to(DEVICE).eval()

    @torch.no_grad()
    def score(texts, bs=48):
        out = []
        for i in range(0, len(texts), bs):
            e = tok(texts[i:i + bs], truncation=True, max_length=MAXLEN,
                    padding=True, return_tensors="pt").to(DEVICE)
            p = model(**e).logits.softmax(-1)[:, 1]
            out += p.cpu().tolist()
        return out
    return score


def rank_one(cve, index, score, only_files=None):
    funcs = load_funcs(cve, index, only_files=only_files)
    if not funcs:
        return []
    s = score([t for _n, _f, t in funcs])
    ranked = sorted(zip(s, funcs), key=lambda x: -x[0])
    return [(n, f, round(sc, 4)) for sc, (n, f, _t) in ranked]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", action="store_true")
    ap.add_argument("--topk", type=int, default=20)
    a = ap.parse_args()
    if not os.path.isdir(MODEL):
        raise SystemExit("missing %s - run src/train_codebert_finetune.py first" % MODEL)

    known = json.load(open(TARGETS, encoding="utf-8"))
    score = scorer()
    cves = sorted(f[:-5] for f in os.listdir(IDX))

    if a.eval:
        rows, hit1 = [], 0
        hit5 = hit20 = 0
        n = 0
        for cve in cves:
            k = known.get(cve) or {}
            gold = set(k.get("targets") or [])
            if not gold:
                continue
            index = json.load(open(os.path.join(IDX, cve + ".json"), encoding="utf-8"))["functions"]
            ranked = rank_one(cve, index, score)
            names = [r[0] for r in ranked]
            pos = next((i for i, nm in enumerate(names) if nm in gold), None)
            n += 1
            hit1 += pos == 0
            hit5 += pos is not None and pos < 5
            hit20 += pos is not None and pos < 20
            rows.append({"cve": cve, "source": k["source"], "gold": sorted(gold),
                         "rank": pos, "n_scored": len(names), "top5": names[:5]})
            print("%-18s %-12s rank=%-6s of %-5d gold=%s" %
                  (cve, k["source"], pos if pos is not None else "miss",
                   len(names), sorted(gold)[:2]), flush=True)
        res = {"n": n, "top1": hit1, "top5": hit5, "top20": hit20,
               "top1_recall": round(hit1 / n, 3) if n else 0,
               "top5_recall": round(hit5 / n, 3) if n else 0,
               "top20_recall": round(hit20 / n, 3) if n else 0,
               "cap_per_cve": CAP, "rows": rows}
        out = os.path.join(BASE, "results", "codebert_rank.json")
        json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("\n== path C ranker vs known targets (n=%d) ==" % n)
        print("   top-1  %d (%.3f)" % (hit1, hit1 / n if n else 0))
        print("   top-5  %d (%.3f)" % (hit5, hit5 / n if n else 0))
        print("   top-20 %d (%.3f)" % (hit20, hit20 / n if n else 0))
        print("->", out)
        return

    out = {}
    for cve in cves:
        k = known.get(cve) or {}
        if k.get("targets"):
            continue
        index = json.load(open(os.path.join(IDX, cve + ".json"), encoding="utf-8"))["functions"]
        ranked = rank_one(cve, index, score, only_files=set(k.get("files") or []) or None)
        if not ranked:
            continue
        out[cve] = {"targets": [r[0] for r in ranked[:a.topk]], "source": "codebert",
                    "evidence": "CodeBERT vulnerability rank (top-%d of %d) - "
                                "may NOT justify not_affected" % (a.topk, len(ranked)),
                    "scored": [{"func": r[0], "file": r[1], "score": r[2]}
                               for r in ranked[:a.topk]]}
        print("%-18s top1=%s (%s) of %d" % (cve, ranked[0][0], ranked[0][2], len(ranked)),
              flush=True)
    dst = os.path.join(BASE, "data", "vuln_targets_c.json")
    json.dump(out, open(dst, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("\n== %d CVEs given a path-C candidate list ==" % len(out))
    print("->", dst)


if __name__ == "__main__":
    main()
