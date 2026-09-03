#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run the current VEX pipeline on the target ICS source-available CVEs.

Fast path (new methodology): local fine-tuned judge for Q1 (presence) + static
call-graph for Q2 (reachability) + execution-verified anchors. No Docker/exploit
loop. Produces a per-CVE result table over the ICS CVEs whose vulnerable code we
have (data/ics_gt_pairs.jsonl), anchored by the 2 execution-verified cases.

Output: results/ics_cve_judgments.json
"""
import json
import os
import re
import torch

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CG = os.path.join(BASE, "results", "callgraph_reach.json")
ADAPTER = os.path.join(BASE, "models", "vex-justifier-lora")
MODEL_ID = os.environ.get("POC_BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")
OUT = os.path.join(BASE, "results", "ics_cve_judgments.json")
EXEC_VERIFIED = {"CVE-2020-8177", "CVE-2022-32221"}   # crash actually reproduced

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
SYS = ("You are a VEX analyst judging whether an ICS/OT product is affected by a "
       "vulnerability, using the CISA justification questions. Answer only with the "
       "requested JSON object.")


def clip(s, n=2400):
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
    cg = {r["cve"]: r for r in json.load(open(CG, encoding="utf-8"))} if os.path.exists(CG) else {}
    GT = os.path.join(BASE, "data", "ics_gt_pairs.jsonl")
    targets = [(r["cve"], r) for r in (json.loads(l) for l in open(GT, encoding="utf-8"))]

    tok = AutoTokenizer.from_pretrained(MODEL_ID)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
    model = AutoModelForCausalLM.from_pretrained(MODEL_ID, quantization_config=bnb,
                                                 device_map="auto", torch_dtype=torch.bfloat16)
    model = PeftModel.from_pretrained(model, ADAPTER)
    model.eval()

    def judge(cwe, proj, code):
        user = INSTR + "\n\nCWE: %s\nComponent: %s\nFunction in this build:\n```c\n%s\n```" % (
            cwe, proj, clip(code))
        msgs = [{"role": "system", "content": SYS}, {"role": "user", "content": user}]
        prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        ids = tok(prompt, return_tensors="pt", truncation=True, max_length=1024).to(model.device)
        with torch.no_grad():
            o = model.generate(**ids, max_new_tokens=80, do_sample=False, pad_token_id=tok.pad_token_id)
        return parse_status(tok.decode(o[0][ids["input_ids"].shape[1]:], skip_special_tokens=True))

    out = []
    # confusion over the ICS CVEs x {vulnerable->affected, patched->not_affected}
    tp = fp = tn = fn = 0
    for cve, v in targets:
        cwe = v.get("cwe", "") or ""
        proj = v.get("repo", "") or ""
        pv = judge(cwe, proj, v["vuln_code"])                        # gold=affected
        pp = judge(cwe, proj, v["patched_code"]) if v.get("patched_code") else None  # gold=not_affected
        if pv == "affected":
            tp += 1
        elif pv == "not_affected":
            fn += 1
        if pp is not None:
            if pp == "not_affected":
                tn += 1
            elif pp == "affected":
                fp += 1
        q2 = (cg.get(cve) or {}).get("verdict", "-")
        out.append({"cve": cve, "component": proj, "vuln_pred": pv, "patched_pred": pp,
                    "q2_reachability": q2, "execution_verified": cve in EXEC_VERIFIED})
        print("%-18s vuln->%-13s patched->%-13s Q2=%s" % (cve, pv, pp, q2), flush=True)

    prec = 100.0 * tp / (tp + fp) if (tp + fp) else 0.0
    rec = 100.0 * tp / (tp + fn) if (tp + fn) else 0.0
    acc = 100.0 * (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    f1_aff = 2.0 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else 0.0
    f1_naf = 2.0 * tn / (2 * tn + fn + fp) if (2 * tn + fn + fp) else 0.0
    macro_f1 = (f1_aff + f1_naf) / 2
    summary = {"population": "ICS source-available CVEs with vuln/patched code pairs",
               "n_cves": len(targets), "n_examples": (tp + fn) + (tn + fp),
               "affected_precision_pct": round(prec, 2), "affected_recall_pct": round(rec, 2),
               "accuracy_pct": round(acc, 2),
               "f1_affected": round(f1_aff, 3), "f1_not_affected": round(f1_naf, 3),
               "macro_f1": round(macro_f1, 3),
               "TP": tp, "FP": fp, "TN": tn, "FN": fn,
               "caveat": "These ICS CVEs overlap the training corpus (same OSS CVEs) -> optimistic, NOT a clean held-out. Descriptive only.",
               "rows": out}
    print("\n== ICS target-population (descriptive; training-overlapped) ==")
    print("  vuln(affected) TP=%d FN=%d | patched(not_affected) TN=%d FP=%d" % (tp, fn, tn, fp))
    print("  affected precision=%.1f%%  recall=%.1f%%  accuracy=%.1f%%" % (prec, rec, acc))
    print("  F1 affected=%.3f  not_affected=%.3f  macro-F1=%.3f" % (f1_aff, f1_naf, macro_f1))
    print("  (실행검증 2건은 code-pair 없어 미포함)")
    json.dump(summary, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("->", OUT)


if __name__ == "__main__":
    main()
