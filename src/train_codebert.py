#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CodeBERT 취약/패치 코드 분류기 — 단독 검증.

수집한 실제 (취약 코드, 패치 코드) 쌍으로, CodeBERT 가 취약 코드를
패치된 코드와 구별할 수 있는지 평가한다.

정직한 평가: GroupKFold(CVE 단위) — 같은 CVE 의 취약/패치가 train/test 에
섞이지 않게 하여, 학습에 없던 CVE 에서도 취약성 패턴을 잡는지 본다.
(같은 CVE 의 두 코드는 몇 줄만 다르므로, 이는 어려운 일반화 과제다.)

출력: results/codebert_metrics.json
"""
import json, os, sys, numpy as np, torch

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CE = os.path.join(BASE, "data", "code_evidence.json")
OUT = os.path.join(BASE, "results", "codebert_metrics.json")
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


def embed_codebert(snippets):
    from transformers import AutoTokenizer, AutoModel
    tok = AutoTokenizer.from_pretrained("microsoft/codebert-base")
    model = AutoModel.from_pretrained("microsoft/codebert-base").to(DEVICE).eval()
    embs = []
    with torch.no_grad():
        for i in range(0, len(snippets), 32):
            b = snippets[i:i + 32]
            enc = tok(b, padding=True, truncation=True, max_length=256, return_tensors="pt").to(DEVICE)
            out = model(**enc).last_hidden_state
            m = enc["attention_mask"].unsqueeze(-1).float()
            pooled = (out * m).sum(1) / m.sum(1).clamp(min=1e-6)
            embs.append(pooled.cpu().numpy())
    return np.vstack(embs).astype(np.float32)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ce = json.load(open(CE, encoding="utf-8"))
    pairs = [v for v in ce.values() if v.get("vuln_code") and v.get("patched_code")]
    print("real vuln/patch pairs: %d" % len(pairs))

    snippets, y, groups = [], [], []
    for i, p in enumerate(pairs):
        snippets.append(p["vuln_code"]); y.append(1); groups.append(i)
        snippets.append(p["patched_code"]); y.append(0); groups.append(i)
    y = np.array(y); groups = np.array(groups)

    print("embedding %d code snippets with CodeBERT ..." % len(snippets))
    X = embed_codebert(snippets)

    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import GroupKFold
    from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

    k = min(5, len(pairs))
    gkf = GroupKFold(n_splits=k)
    accs, f1s, aucs = [], [], []
    y_true_all, y_pred_all = [], []
    for tr, te in gkf.split(X, y, groups):
        clf = LogisticRegression(max_iter=2000, C=1.0, class_weight="balanced").fit(X[tr], y[tr])
        pr = clf.predict(X[te]); pp = clf.predict_proba(X[te])[:, 1]
        accs.append(accuracy_score(y[te], pr))
        f1s.append(f1_score(y[te], pr, zero_division=0))
        if len(set(y[te])) > 1:
            aucs.append(roc_auc_score(y[te], pp))
        y_true_all += list(y[te]); y_pred_all += list(pr)

    res = {
        "n_pairs": len(pairs), "n_snippets": len(snippets),
        "eval": "GroupKFold by CVE (unseen-CVE generalization)",
        "folds": k,
        "accuracy_mean": float(np.mean(accs)), "accuracy_std": float(np.std(accs)),
        "f1_mean": float(np.mean(f1s)), "auc_mean": float(np.mean(aucs)) if aucs else None,
        "chance": 0.5,
        "components": sorted({p["repo"] for p in pairs}),
        "languages": sorted({p["file"].split(".")[-1] for p in pairs}),
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("=" * 50)
    print("CodeBERT vuln-vs-patched (unseen CVE):")
    print("  accuracy %.3f ± %.3f  (chance 0.500)" % (res["accuracy_mean"], res["accuracy_std"]))
    print("  F1 %.3f | AUC %s" % (res["f1_mean"], ("%.3f" % res["auc_mean"]) if res["auc_mean"] else "n/a"))
    print("  %d pairs across %d components" % (res["n_pairs"], len(res["components"])))


if __name__ == "__main__":
    main()
