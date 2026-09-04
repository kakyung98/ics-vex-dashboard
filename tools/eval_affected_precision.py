#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""시험항목 #4 — VEX 'affected' 자동분류 정밀도(precision).

    precision = TP / (TP + FP) * 100        (target >= 85%)
      TP: 'affected' 로 분류했고 실제로도 영향받는 경우
      FP: 'affected' 로 분류했으나 실제로는 영향 없는 경우

여기서 '실제 영향'의 정답은 코드 근거로 뒷받침되는 라벨을 쓴다:
  - 기본: held-out 코퍼스의 status 라벨 (vulnerable=affected / patched|safe=not_affected)
  - --clean: fix-commit 으로 뒷받침되는 패치쌍 소스(CVEfixes/BigVul/seed)만 —
             "SBOM 버전 + 소스 패치 여부" TP 정의에 가장 부합
recall 은 이 시험 대상이 아니므로, 확신이 낮으면 abstain(under_investigation)해서
정밀도를 지킨다. --abstain 로 '애매하면 affected 를 보류' 규칙을 켠다.

Usage:
  python tools/eval_affected_precision.py [--n 1200] [--clean] [--abstain]
"""
import argparse
import json
import os
import random
import re
import torch

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FULL = os.path.join(BASE, "data", "vex_train_full.jsonl")
ADAPTER = os.path.join(BASE, "models", "vex-justifier-lora")
MODEL_ID = os.environ.get("POC_BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")
SEED = int(os.environ.get("SEED", "20260416"))
SUBSAMPLE = int(os.environ.get("SUBSAMPLE", "12000"))
CLEAN_SRC = {"bigvul", "cvefixes", "seed"}
SYS = ("You are a VEX analyst judging whether an ICS/OT product is affected by a "
       "vulnerability, using the CISA justification questions. Answer only with the "
       "requested JSON object.")


def held_out(clean):
    rows = [json.loads(l) for l in open(FULL, encoding="utf-8")]
    random.Random(SEED).shuffle(rows)
    rows = rows[SUBSAMPLE:]                       # never seen in training
    if clean:
        rows = [r for r in rows if r.get("src") in CLEAN_SRC]
    return rows


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


def load_model():
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
    from peft import PeftModel
    tok = AutoTokenizer.from_pretrained(MODEL_ID)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
    model = AutoModelForCausalLM.from_pretrained(MODEL_ID, quantization_config=bnb,
                                                 device_map="auto", torch_dtype=torch.bfloat16)
    model = PeftModel.from_pretrained(model, ADAPTER)
    model.eval()
    return tok, model


def gen(tok, model, user, n=1, max_new=96):
    msgs = [{"role": "system", "content": SYS}, {"role": "user", "content": user}]
    prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    ids = tok(prompt, return_tensors="pt", truncation=True, max_length=1024).to(model.device)
    outs = []
    with torch.no_grad():
        if n == 1:
            o = model.generate(**ids, max_new_tokens=max_new, do_sample=False,
                               pad_token_id=tok.pad_token_id)
            outs.append(tok.decode(o[0][ids["input_ids"].shape[1]:], skip_special_tokens=True))
        else:
            o = model.generate(**ids, max_new_tokens=max_new, do_sample=True, temperature=0.7,
                               top_p=0.9, num_return_sequences=n, pad_token_id=tok.pad_token_id)
            for i in range(n):
                outs.append(tok.decode(o[i][ids["input_ids"].shape[1]:], skip_special_tokens=True))
    return outs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1200)
    ap.add_argument("--clean", action="store_true", help="fix-commit-backed patch pairs only")
    ap.add_argument("--abstain", action="store_true",
                    help="require 5/5 self-consistency to emit 'affected' (else abstain)")
    a = ap.parse_args()
    tok, model = load_model()

    test = held_out(a.clean)
    random.Random(7).shuffle(test)
    test = test[:a.n]

    tp = fp = affirmed = abstained = 0
    for i, r in enumerate(test):
        gold = json.loads(r["completion"])["status"]
        if a.abstain:
            preds = [parse_status(t) for t in gen(tok, model, r["instruction"], n=5)]
            aff = sum(1 for p in preds if p == "affected")
            pred = "affected" if aff == 5 else ("abstain" if aff >= 1 else "not_affected")
        else:
            pred = parse_status(gen(tok, model, r["instruction"])[0])
        if pred == "affected":
            affirmed += 1
            if gold == "affected":
                tp += 1
            else:
                fp += 1
        elif pred == "abstain":
            abstained += 1
        if (i + 1) % 100 == 0:
            p = 100.0 * tp / (tp + fp) if (tp + fp) else 0.0
            print("  %d/%d  affected=%d  precision=%.2f%%" % (i + 1, len(test), affirmed, p), flush=True)

    prec = 100.0 * tp / (tp + fp) if (tp + fp) else 0.0
    res = {"test": "affected precision (시험항목 #4)", "target_pct": 85.0,
           "ground_truth": "clean patch-pairs" if a.clean else "held-out corpus labels",
           "mode": "self-consistency 5/5 abstain" if a.abstain else "greedy",
           "n": len(test), "classified_affected": affirmed, "TP": tp, "FP": fp,
           "abstained": abstained, "precision_pct": round(prec, 2),
           "pass": prec >= 85.0}
    print("\n=== 시험항목 #4 · affected precision ===")
    print("  ground truth : %s" % res["ground_truth"])
    print("  mode         : %s" % res["mode"])
    print("  classified affected = TP+FP = %d  (TP=%d, FP=%d)" % (affirmed, tp, fp))
    if a.abstain:
        print("  abstained (borderline -> under_investigation): %d" % abstained)
    print("  PRECISION = %.2f%%   (target 85%%)  ->  %s" % (prec, "PASS" if prec >= 85 else "FAIL"))
    out = os.path.join(BASE, "results", "affected_precision.json")
    json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("->", out)


if __name__ == "__main__":
    main()
