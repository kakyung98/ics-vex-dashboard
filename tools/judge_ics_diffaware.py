#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Diff-aware retest: show the judge the vulnerable version AND this build, so it
can detect an inline mitigation (Q4) instead of only Q1 presence. Measures whether
precision on the patched (not_affected) side improves.

Two prompts per CVE:
  - build = vulnerable version  -> gold affected
  - build = patched version + the reference vulnerable version -> gold not_affected
"""
import json
import os
import re
import torch

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT = os.path.join(BASE, "data", "ics_gt_pairs.jsonl")
ADAPTER = os.path.join(BASE, "models", "vex-justifier-lora")
MODEL_ID = os.environ.get("POC_BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")
OUT = os.path.join(BASE, "results", "ics_diffaware.json")
SYS = ("You are a VEX analyst judging whether an ICS/OT product is affected by a "
       "vulnerability, using the CISA justification questions. Answer only with the "
       "requested JSON object.")
INSTR = (
    "You are a VEX analyst. You are given the KNOWN-VULNERABLE version of a function "
    "and the version of that function IN THIS BUILD. Decide whether THIS BUILD is "
    "affected, using the CISA justification questions:\n"
    "Q1 Is the vulnerable code still present in this build?\n"
    "Q4 Has a fix / inline mitigation (added guard, bounds check, removed sink) "
    "already been applied in this build relative to the vulnerable version?\n"
    "If this build already contains the fix/mitigation, it is not_affected with "
    "justification inline_mitigations_already_exist (or vulnerable_code_not_present).\n"
    "Answer with JSON: {\"status\": affected|not_affected, \"justification\": <...>, "
    "\"rationale\": <one sentence>}."
)


def clip(s, n=1500):
    s = s or ""
    return s if len(s) <= n else s[:n] + "\n...[truncated]"


def parse_status(t):
    m = re.search(r'"status"\s*:\s*"?(affected|not_affected)"?', t)
    if m:
        return m.group(1)
    tl = t.lower()
    return "not_affected" if ("not_affected" in tl or "not affected" in tl) else ("affected" if "affected" in tl else "unknown")


def main():
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
    from peft import PeftModel
    rows = [json.loads(l) for l in open(GT, encoding="utf-8")]
    tok = AutoTokenizer.from_pretrained(MODEL_ID)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
    model = AutoModelForCausalLM.from_pretrained(MODEL_ID, quantization_config=bnb,
                                                 device_map="auto", torch_dtype=torch.bfloat16)
    model = PeftModel.from_pretrained(model, ADAPTER)
    model.eval()

    def judge(cwe, vuln, build):
        user = (INSTR + "\n\nCWE: %s\n" % cwe
                + "Known-vulnerable version:\n```c\n%s\n```\n" % clip(vuln)
                + "This build:\n```c\n%s\n```" % clip(build))
        msgs = [{"role": "system", "content": SYS}, {"role": "user", "content": user}]
        prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        ids = tok(prompt, return_tensors="pt", truncation=True, max_length=1536).to(model.device)
        with torch.no_grad():
            o = model.generate(**ids, max_new_tokens=80, do_sample=False, pad_token_id=tok.pad_token_id)
        return parse_status(tok.decode(o[0][ids["input_ids"].shape[1]:], skip_special_tokens=True))

    tp = fp = tn = fn = 0
    for r in rows:
        cwe = r.get("cwe", "") or ""
        pv = judge(cwe, r["vuln_code"], r["vuln_code"])       # build = vulnerable -> affected
        pp = judge(cwe, r["vuln_code"], r["patched_code"])    # build = patched -> not_affected
        if pv == "affected":
            tp += 1
        elif pv == "not_affected":
            fn += 1
        if pp == "not_affected":
            tn += 1
        elif pp == "affected":
            fp += 1
        print("%-18s vuln->%-13s patched->%-13s" % (r["cve"], pv, pp), flush=True)

    prec = 100.0 * tp / (tp + fp) if (tp + fp) else 0.0
    rec = 100.0 * tp / (tp + fn) if (tp + fn) else 0.0
    acc = 100.0 * (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    f1a = 2.0 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else 0.0
    f1n = 2.0 * tn / (2 * tn + fn + fp) if (2 * tn + fn + fp) else 0.0
    res = {"mode": "diff-aware (vuln reference + this build)", "n_cves": len(rows),
           "TP": tp, "FP": fp, "TN": tn, "FN": fn,
           "affected_precision_pct": round(prec, 2), "recall_pct": round(rec, 2),
           "accuracy_pct": round(acc, 2), "macro_f1": round((f1a + f1n) / 2, 3)}
    print("\n== diff-aware retest ==")
    print("  vuln TP=%d FN=%d | patched TN=%d FP=%d" % (tp, fn, tn, fp))
    print("  affected precision=%.1f%%  recall=%.1f%%  accuracy=%.1f%%  macro-F1=%.3f"
          % (prec, rec, acc, (f1a + f1n) / 2))
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("->", OUT)


if __name__ == "__main__":
    main()
