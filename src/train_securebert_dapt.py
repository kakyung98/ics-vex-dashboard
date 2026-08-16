#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureBERT ICS 도메인 적응 사전학습 (DAPT, continued MLM).

CISA ICS 어드바이저리 텍스트로 SecureBERT 를 라벨 없이 재적응한다.
효과는 라벨과 무관한 MLM perplexity 로 측정: held-out ICS 문장에서
vanilla vs ICS-DAPT 의 마스킹 복원 성능을 동일한 마스크로 비교한다.

출력: models/ics-securebert/ (적응 모델), results/dapt_metrics.json
"""
import json, os, re, sys, math, random
import numpy as np, torch
from torch.utils.data import DataLoader

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
ADV = os.path.join(BASE, "data", "cisa_advisories.json")
MODEL_OUT = os.path.join(BASE, "models", "ics-securebert")
RES = os.path.join(BASE, "results", "dapt_metrics.json")
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
SEED = 20260416
MAXLEN = 128
MAX_BLOCKS = 40000

ICS_TERMS = ["Modbus", "DNP3", "PROFINET", "EtherNet/IP", "IEC 61850", "GOOSE", "PLC", "RTU",
             "SCADA", "HMI", "ladder", "firmware", "controller", "OPC UA", "BACnet", "CIP",
             "substation", "actuator", "sensor", "fieldbus", "engineering workstation"]


def build_corpus():
    adv = json.load(open(ADV, encoding="utf-8"))
    texts = []
    for v in adv.values():
        if v.get("error"):
            continue
        t = (v.get("title", "") + ". " + v.get("affected_text", "")).strip()
        if t:
            texts.append(t)
    # 문장 단위 분할 + dedup
    sents = []
    seen = set()
    for t in texts:
        for s in re.split(r"(?<=[.!?])\s+", t):
            s = s.strip()
            if 40 <= len(s) <= 600 and s not in seen:
                seen.add(s); sents.append(s)
    return sents


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
    from transformers import AutoTokenizer, AutoModelForMaskedLM, DataCollatorForLanguageModeling

    sents = build_corpus()
    random.shuffle(sents)
    print("ICS sentences: %d" % len(sents), flush=True)

    tok = AutoTokenizer.from_pretrained("ehsanaghaei/SecureBERT")
    enc = tok(sents, truncation=True, max_length=MAXLEN, padding="max_length")
    examples = [{"input_ids": ids, "attention_mask": am}
                for ids, am in zip(enc["input_ids"], enc["attention_mask"])]
    if len(examples) > MAX_BLOCKS:
        examples = examples[:MAX_BLOCKS]
    n_eval = max(500, len(examples) // 10)
    ev, tr = examples[:n_eval], examples[n_eval:]
    print("train %d | eval %d" % (len(tr), len(ev)), flush=True)

    collator = DataCollatorForLanguageModeling(tokenizer=tok, mlm=True, mlm_probability=0.15)

    # eval 세트를 한 번만 고정 마스킹 (before/after 동일 조건)
    torch.manual_seed(SEED)
    eval_batches = []
    for i in range(0, len(ev), 64):
        eval_batches.append(collator(ev[i:i + 64]))

    def eval_loss(model):
        model.eval(); tot = 0.0; nb = 0
        with torch.no_grad():
            for b in eval_batches:
                bb = {k: v.to(DEVICE) for k, v in b.items()}
                tot += model(**bb).loss.item(); nb += 1
        return tot / nb

    model = AutoModelForMaskedLM.from_pretrained("ehsanaghaei/SecureBERT").to(DEVICE)
    before = eval_loss(model)
    print("baseline (vanilla) eval MLM loss %.4f | ppl %.2f" % (before, math.exp(before)), flush=True)

    # continued MLM 학습
    opt = torch.optim.AdamW(model.parameters(), lr=3e-5, weight_decay=0.01)
    loader = DataLoader(tr, batch_size=32, shuffle=True, collate_fn=collator)
    EPOCHS = 3
    for ep in range(EPOCHS):
        model.train(); run = 0.0; steps = 0
        for b in loader:
            bb = {k: v.to(DEVICE) for k, v in b.items()}
            loss = model(**bb).loss
            opt.zero_grad(); loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            run += loss.item(); steps += 1
        print("epoch %d  train loss %.4f  | eval ppl %.2f" %
              (ep, run / steps, math.exp(eval_loss(model))), flush=True)

    after = eval_loss(model)
    os.makedirs(MODEL_OUT, exist_ok=True)
    model.save_pretrained(MODEL_OUT); tok.save_pretrained(MODEL_OUT)

    # ICS 용어 마스킹 복원 비교
    def term_probe(m):
        m.eval(); ok = 0; tot = 0
        with torch.no_grad():
            for s in sents[:4000]:
                for term in ICS_TERMS:
                    if (" " + term.lower() + " ") in (" " + s.lower() + " ") and " " not in term:
                        masked = re.sub(r"\b" + re.escape(term) + r"\b", tok.mask_token, s, count=1)
                        e = tok(masked, return_tensors="pt", truncation=True, max_length=MAXLEN).to(DEVICE)
                        mp = (e["input_ids"][0] == tok.mask_token_id).nonzero(as_tuple=True)[0]
                        if len(mp) == 0:
                            continue
                        logits = m(**e).logits[0, mp[0]]
                        pred = tok.decode([int(logits.argmax())]).strip()
                        ok += (pred.lower() == term.lower()); tot += 1
                        break
        return ok / tot if tot else 0.0, tot

    vanilla = AutoModelForMaskedLM.from_pretrained("ehsanaghaei/SecureBERT").to(DEVICE)
    va, vn = term_probe(vanilla)
    da, dn = term_probe(model)

    res = {"corpus_sentences": len(sents), "train": len(tr), "eval": len(ev),
           "mlm_loss_before": round(before, 4), "mlm_loss_after": round(after, 4),
           "perplexity_before": round(math.exp(before), 2), "perplexity_after": round(math.exp(after), 2),
           "perplexity_drop_pct": round(100 * (math.exp(before) - math.exp(after)) / math.exp(before), 1),
           "ics_term_recovery_vanilla": round(va, 3), "ics_term_recovery_dapt": round(da, 3),
           "ics_term_probe_n": vn, "device": DEVICE}
    json.dump(res, open(RES, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("=" * 50, flush=True)
    print("ICS-DAPT: perplexity %.2f -> %.2f (%.1f%% drop)" %
          (res["perplexity_before"], res["perplexity_after"], res["perplexity_drop_pct"]), flush=True)
    print("ICS term recovery: vanilla %.3f -> DAPT %.3f (n=%d)" % (va, da, vn), flush=True)


if __name__ == "__main__":
    main()
