#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CodeBERT 취약점 탐지 파인튜닝 (인코더 동결 해제).

frozen CodeBERT 의 추상적 취약성 분류 실패(0.50)를 실제 대규모 코퍼스로 개선.
데이터: CodeXGLUE Defect Detection (Devign, ~27k C 함수, 취약/정상).

절차:
  1) Devign 으로 CodeBERT + 분류헤드 end-to-end 파인튜닝
  2) Devign test 정확도/F1 보고 (실제 취약탐지 학습 확인)
  3) 파인튜닝된 인코더로 우리 vuln/patch 매칭(GroupKFold) 재평가 -> 0.50 대비 개선?
  4) models/codebert-vuln 저장

출력: results/codebert_finetune_metrics.json
"""
import json, os, sys, numpy as np, torch
import torch.nn as nn
from torch.utils.data import DataLoader

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CE = os.path.join(BASE, "data", "code_evidence.json")
MODEL_OUT = os.path.join(BASE, "models", "codebert-vuln")
RES = os.path.join(BASE, "results", "codebert_finetune_metrics.json")
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
SEED = 20260416
MAXLEN = 384


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    torch.manual_seed(SEED); np.random.seed(SEED)
    from transformers import AutoTokenizer, AutoModelForSequenceClassification, AutoModel
    from datasets import load_dataset

    print("loading Devign (CodeXGLUE defect detection) ...", flush=True)
    ds = load_dataset("google/code_x_glue_cc_defect_detection")
    tok = AutoTokenizer.from_pretrained("microsoft/codebert-base")

    def enc_split(split, cap=None):
        rows = ds[split]
        if cap:
            rows = rows.select(range(min(cap, len(rows))))
        e = tok(rows["func"], truncation=True, max_length=MAXLEN, padding="max_length")
        return (torch.tensor(e["input_ids"]), torch.tensor(e["attention_mask"]),
                torch.tensor(rows["target"], dtype=torch.long))

    Xtr, Mtr, Ytr = enc_split("train")
    Xva, Mva, Yva = enc_split("validation")
    Xte, Mte, Yte = enc_split("test")
    print("train %d | val %d | test %d" % (len(Ytr), len(Yva), len(Yte)), flush=True)

    model = AutoModelForSequenceClassification.from_pretrained(
        "microsoft/codebert-base", num_labels=2).to(DEVICE)
    opt = torch.optim.AdamW(model.parameters(), lr=2e-5, weight_decay=0.01)
    ce = nn.CrossEntropyLoss()

    def batches(X, M, Y, bs, shuffle=False):
        idx = torch.randperm(len(Y)) if shuffle else torch.arange(len(Y))
        for i in range(0, len(Y), bs):
            j = idx[i:i + bs]
            yield X[j].to(DEVICE), M[j].to(DEVICE), Y[j].to(DEVICE)

    @torch.no_grad()
    def evaluate(X, M, Y):
        model.eval(); preds = []
        for xb, mb, _ in batches(X, M, Y, 32):
            preds.append(model(input_ids=xb, attention_mask=mb).logits.argmax(1).cpu())
        p = torch.cat(preds).numpy()
        from sklearn.metrics import accuracy_score, f1_score
        return accuracy_score(Y.numpy(), p), f1_score(Y.numpy(), p, zero_division=0)

    import copy
    EPOCHS = 4
    best_f1 = -1.0; best_state = None
    for ep in range(EPOCHS):
        model.train(); run = 0.0; steps = 0
        for xb, mb, yb in batches(Xtr, Mtr, Ytr, 16, shuffle=True):
            loss = ce(model(input_ids=xb, attention_mask=mb).logits, yb)
            opt.zero_grad(); loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0); opt.step()
            run += loss.item(); steps += 1
            if steps % 200 == 0:
                print("  ep%d step%d loss %.4f" % (ep, steps, run / steps), flush=True)
        va = evaluate(Xva, Mva, Yva)
        print("epoch %d  train loss %.4f | val acc %.3f f1 %.3f" % (ep, run / steps, va[0], va[1]), flush=True)
        if va[1] > best_f1:                    # validation F1 기준 최적 체크포인트
            best_f1 = va[1]; best_state = copy.deepcopy(model.state_dict())
            print("    * new best (val f1 %.3f) checkpointed" % best_f1, flush=True)

    if best_state is not None:
        model.load_state_dict(best_state)      # 최적 가중치 복원
    te_acc, te_f1 = evaluate(Xte, Mte, Yte)
    print("Devign TEST  acc %.3f  f1 %.3f" % (te_acc, te_f1), flush=True)
    os.makedirs(MODEL_OUT, exist_ok=True)
    model.save_pretrained(MODEL_OUT); tok.save_pretrained(MODEL_OUT)

    # --- 우리 vuln/patch 매칭 재평가 (파인튜닝 인코더) ---
    base = model.roberta.to(DEVICE).eval()

    def embed(snips):
        out = []
        with torch.no_grad():
            for i in range(0, len(snips), 32):
                e = tok(snips[i:i + 32], truncation=True, max_length=256,
                        padding=True, return_tensors="pt").to(DEVICE)
                o = base(**e).last_hidden_state
                m = e["attention_mask"].unsqueeze(-1).float()
                out.append(((o * m).sum(1) / m.sum(1).clamp(min=1e-6)).cpu().numpy())
        return np.vstack(out).astype(np.float32)

    ce_data = json.load(open(CE, encoding="utf-8"))
    pairs = [v for v in ce_data.values() if v.get("vuln_code") and v.get("patched_code")]
    snips, y, grp = [], [], []
    for i, p in enumerate(pairs):
        snips += [p["vuln_code"], p["patched_code"]]; y += [1, 0]; grp += [i, i]
    Xc = embed(snips); y = np.array(y); grp = np.array(grp)
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import GroupKFold
    from sklearn.metrics import accuracy_score
    accs = []
    for tr, te in GroupKFold(n_splits=5).split(Xc, y, grp):
        clf = LogisticRegression(max_iter=2000, class_weight="balanced").fit(Xc[tr], y[tr])
        accs.append(accuracy_score(y[te], clf.predict(Xc[te])))
    finetuned_match = float(np.mean(accs))

    res = {"devign_test_acc": round(te_acc, 3), "devign_test_f1": round(te_f1, 3),
           "vuln_patch_match_frozen": 0.50, "vuln_patch_match_finetuned": round(finetuned_match, 3),
           "n_pairs": len(pairs), "device": DEVICE, "epochs": EPOCHS}
    os.makedirs(os.path.dirname(RES), exist_ok=True)
    json.dump(res, open(RES, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("=" * 50, flush=True)
    print("Devign test acc %.3f f1 %.3f | vuln/patch match frozen 0.50 -> finetuned %.3f" %
          (te_acc, te_f1, finetuned_match), flush=True)


if __name__ == "__main__":
    main()
