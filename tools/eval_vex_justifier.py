#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Evaluate the fine-tuned VEX-justification model.

Two measurements:
  (A) status classification F1 on a held-out test set (rows NOT used in training,
      separated with the same shuffle seed the trainer used).
  (B) justification accuracy on the CISA-gold set (18 real published labels).

Loads the base model + the trained LoRA adapter and generates the JSON verdict
for each example, then computes precision/recall/F1.

Usage:
  python tools/eval_vex_justifier.py [--n 1000]
Env: POC_BASE_MODEL (base), SUBSAMPLE / SEED must match training.
"""
import argparse
import json
import os
import random
import re
import torch

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FULL = os.path.join(BASE, "data", "vex_train_full.jsonl")
GOLD = os.path.join(BASE, "data", "vex_justify_eval.jsonl")
ADAPTER = os.path.join(BASE, "models", "vex-justifier-lora")
MODEL_ID = os.environ.get("POC_BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")
SEED = int(os.environ.get("SEED", "20260416"))
SUBSAMPLE = int(os.environ.get("SUBSAMPLE", "12000"))
SYS = ("You are a VEX analyst judging whether an ICS/OT product is affected by a "
       "vulnerability, using the CISA justification questions. Answer only with the "
       "requested JSON object.")


def held_out():
    rows = [json.loads(l) for l in open(FULL, encoding="utf-8")]
    random.Random(SEED).shuffle(rows)          # identical to trainer
    return rows[SUBSAMPLE:]                     # everything the trainer did NOT see


def parse_status(text):
    m = re.search(r'"status"\s*:\s*"?(affected|not_affected)"?', text)
    if m:
        return m.group(1)
    t = text.lower()
    if "not_affected" in t or "not affected" in t:
        return "not_affected"
    if "affected" in t:
        return "affected"
    return "unknown"


def parse_just(text):
    m = re.search(r'"justification"\s*:\s*"?([a-z_]+)"?', text)
    return m.group(1) if m else None


def load_model():
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
    from peft import PeftModel
    tok = AutoTokenizer.from_pretrained(MODEL_ID)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    pre4bit = "4bit" in MODEL_ID.lower()
    if pre4bit:
        model = AutoModelForCausalLM.from_pretrained(MODEL_ID, device_map="auto", torch_dtype=torch.bfloat16)
    else:
        bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                 bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
        model = AutoModelForCausalLM.from_pretrained(MODEL_ID, quantization_config=bnb,
                                                     device_map="auto", torch_dtype=torch.bfloat16)
    model = PeftModel.from_pretrained(model, ADAPTER)
    model.eval()
    return tok, model


def gen(tok, model, user, max_new=96):
    msgs = [{"role": "system", "content": SYS}, {"role": "user", "content": user}]
    prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    ids = tok(prompt, return_tensors="pt", truncation=True, max_length=1024).to(model.device)
    with torch.no_grad():
        out = model.generate(**ids, max_new_tokens=max_new, do_sample=False, pad_token_id=tok.pad_token_id)
    return tok.decode(out[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)


def prf(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1000, help="held-out test examples to score")
    a = ap.parse_args()
    tok, model = load_model()

    # (A) status F1 on held-out
    test = held_out()
    random.Random(7).shuffle(test)
    test = test[:a.n]
    # binary counts with 'affected' as the positive class
    tp = fp = fn = tn = bad = 0
    per = {"affected": {"tp": 0, "fp": 0, "fn": 0}, "not_affected": {"tp": 0, "fp": 0, "fn": 0}}
    for i, r in enumerate(test):
        gold = json.loads(r["completion"])["status"]
        pred = parse_status(gen(tok, model, r["instruction"]))
        if pred not in ("affected", "not_affected"):
            bad += 1
            pred = "not_affected" if gold == "affected" else "affected"  # count as wrong
        # per-class one-vs-rest
        for cls in per:
            if gold == cls and pred == cls:
                per[cls]["tp"] += 1
            elif pred == cls and gold != cls:
                per[cls]["fp"] += 1
            elif gold == cls and pred != cls:
                per[cls]["fn"] += 1
        if (i + 1) % 100 == 0:
            print("  scored %d/%d" % (i + 1, len(test)), flush=True)

    macro = []
    print("\n=== (A) status classification (held-out, n=%d, unparsable=%d) ===" % (len(test), bad))
    for cls in ("affected", "not_affected"):
        p, r, f = prf(per[cls]["tp"], per[cls]["fp"], per[cls]["fn"])
        macro.append(f)
        print("  %-13s P=%.3f R=%.3f F1=%.3f  (tp=%d fp=%d fn=%d)"
              % (cls, p, r, f, per[cls]["tp"], per[cls]["fp"], per[cls]["fn"]))
    acc = sum(per[c]["tp"] for c in per) / len(test)
    print("  macro-F1=%.3f | accuracy=%.3f" % (sum(macro) / 2, acc))

    # (B) justification accuracy on CISA gold
    if os.path.exists(GOLD):
        gold = [json.loads(l) for l in open(GOLD, encoding="utf-8")]
        jc = sc = 0
        rows = []
        for r in gold:
            user = ("CVE %s (advisory %s). Judge this vulnerability for the product per the "
                    "CISA justification questions and answer with the JSON object."
                    % (r["cve"], r.get("advisory", "")))
            txt = gen(tok, model, user)
            ps, pj = parse_status(txt), parse_just(txt)
            sc += (ps == r.get("gold_status"))
            jc += (pj == r.get("gold_justification"))
            rows.append((r["cve"], r.get("gold_justification"), pj, ps))
        print("\n=== (B) CISA gold (n=%d) ===" % len(gold))
        print("  status not_affected correct : %d/%d" % (sc, len(gold)))
        print("  justification exact match   : %d/%d" % (jc, len(gold)))
        for cve, gj, pj, ps in rows:
            print("    %-16s gold=%-38s pred=%s (%s)" % (cve, gj, pj, ps))

    out = os.path.join(BASE, "results", "vex_justifier_eval.json")
    json.dump({"status": {c: per[c] for c in per}, "macro_f1": sum(macro) / 2,
               "accuracy": acc, "n": len(test), "unparsable": bad},
              open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("\n-> %s" % out)


if __name__ == "__main__":
    main()
