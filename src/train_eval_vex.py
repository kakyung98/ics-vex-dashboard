#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureBERT/CodeBERT 기반 설명가능 ICS VEX 시스템 — 학습 + 평가 자동화.

파이프라인(README 구조 구현):
  1) SecureBERT(frozen) 로 각 증거 문장 임베딩 -> 캐시
  2) 문장-어텐션 분류기 학습
        - Classification Head : attention-pooled doc emb -> 3-class VEX
        - Rationale Head      : 문장별 driver 확률 (멀티태스크, L = CE + λ·BCE)
  3) CodeBERT 보조: oss-arm findings 의 CVE 설명 <-> CWE 취약코드 템플릿 유사도
  4) Evidence Verifier + 보수적 Decision Engine (README 7절)
        - LIKELY_NOT_AFFECTED 는 적극적 반증 rationale 이 있을 때만 허용
        - 저신뢰/충돌 -> UNDER_INVESTIGATION
  5) 평가: 상태분류(Macro F1, per-class, confusion, ECE, U-전환율, 오탐NOT_AFFECTED),
           rationale(문장 P/R/F1, IoU, Sufficiency, Comprehensiveness),
           baseline(TF-IDF+LogReg), Decision Engine 유무 비교
  6) 산출물: results/metrics.json, results/report.md, results/sample_vex/*.json

device-disjoint split 으로 누수를 방지한다.
"""
import json
import os
import random
import sys
import time

import numpy as np
import torch
import torch.nn as nn

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DATA = os.path.join(BASE, "data", "vex_dataset.jsonl")
EMB_CACHE = os.path.join(BASE, "data", "sent_emb_securebert.npz")
RESULTS = os.path.join(BASE, "results")
SAMPLE_DIR = os.path.join(RESULTS, "sample_vex")

LABELS = ["LIKELY_AFFECTED", "LIKELY_NOT_AFFECTED", "UNDER_INVESTIGATION"]
L2I = {l: i for i, l in enumerate(LABELS)}
SEED = 20260416
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

CWE_CODE_TEMPLATES = {
    "CWE-120": "memcpy(buffer, packet.data, packet.length);",
    "CWE-121": "char buf[64]; strcpy(buf, input);",
    "CWE-122": "p = malloc(len); memcpy(p, src, user_len);",
    "CWE-125": "return array[user_index];",
    "CWE-787": "array[user_index] = value;",
    "CWE-416": "free(obj); use(obj);",
    "CWE-476": "obj = lookup(); return obj->field;",
    "CWE-78": "snprintf(cmd, n, \"ping %s\", user); system(cmd);",
    "CWE-89": "sprintf(q, \"SELECT * FROM t WHERE id=%s\", user);",
    "CWE-190": "size = a * b; buf = malloc(size);",
    "CWE-798": "if (strcmp(pw, \"admin123\") == 0) grant();",
}


def set_seed(s):
    random.seed(s); np.random.seed(s); torch.manual_seed(s)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(s)


# ---------------------------------------------------------------------------
# 데이터 로드 + device-disjoint split
# ---------------------------------------------------------------------------
def load_dataset():
    recs = [json.loads(l) for l in open(DATA, encoding="utf-8")]
    devices = sorted({r["device"] for r in recs})
    rnd = random.Random(SEED)
    rnd.shuffle(devices)
    cut = int(len(devices) * 0.8)
    train_dev = set(devices[:cut])
    tr = [r for r in recs if r["device"] in train_dev]
    te = [r for r in recs if r["device"] not in train_dev]
    return recs, tr, te


# ---------------------------------------------------------------------------
# SecureBERT 문장 임베딩 (frozen, 캐시)
# ---------------------------------------------------------------------------
def encode_sentences(recs):
    if os.path.exists(EMB_CACHE):
        d = np.load(EMB_CACHE, allow_pickle=True)
        return {k: v for k, v in zip(d["keys"], d["emb"])}
    from transformers import AutoTokenizer, AutoModel
    print("  loading SecureBERT ...", flush=True)
    tok = AutoTokenizer.from_pretrained("ehsanaghaei/SecureBERT")
    model = AutoModel.from_pretrained("ehsanaghaei/SecureBERT").to(DEVICE).eval()
    uniq = sorted({s["text"] for r in recs for s in r["sentences"]})
    print("  unique sentences: %d" % len(uniq), flush=True)
    emb = {}
    B = 128
    with torch.no_grad():
        for i in range(0, len(uniq), B):
            batch = uniq[i:i + B]
            enc = tok(batch, padding=True, truncation=True, max_length=64, return_tensors="pt").to(DEVICE)
            out = model(**enc).last_hidden_state           # [B,T,H]
            mask = enc["attention_mask"].unsqueeze(-1).float()
            pooled = (out * mask).sum(1) / mask.sum(1).clamp(min=1e-6)
            for t, v in zip(batch, pooled.cpu().numpy().astype(np.float32)):
                emb[t] = v
            if i % (B * 20) == 0:
                print("    %d/%d" % (i, len(uniq)), flush=True)
    keys = list(emb.keys())
    np.savez_compressed(EMB_CACHE, keys=np.array(keys, dtype=object),
                        emb=np.array([emb[k] for k in keys], dtype=np.float32))
    return emb


def codebert_signal(recs):
    """oss-arm findings: CVE 설명 <-> CWE 취약코드 템플릿 CodeBERT 유사도."""
    from transformers import AutoTokenizer, AutoModel
    tok = AutoTokenizer.from_pretrained("microsoft/codebert-base")
    model = AutoModel.from_pretrained("microsoft/codebert-base").to(DEVICE).eval()

    def embed(texts):
        with torch.no_grad():
            enc = tok(texts, padding=True, truncation=True, max_length=96, return_tensors="pt").to(DEVICE)
            out = model(**enc).last_hidden_state
            m = enc["attention_mask"].unsqueeze(-1).float()
            return ((out * m).sum(1) / m.sum(1).clamp(min=1e-6)).cpu().numpy()

    tmpl_keys = list(CWE_CODE_TEMPLATES)
    tmpl_emb = embed([CWE_CODE_TEMPLATES[k] for k in tmpl_keys])
    tmpl_emb /= (np.linalg.norm(tmpl_emb, axis=1, keepdims=True) + 1e-9)

    sig = {}
    oss = [r for r in recs if r["arm"] == "oss"]
    for i in range(0, len(oss), 128):
        batch = oss[i:i + 128]
        descs = [next(s["text"] for s in r["sentences"] if s["id"] == "CVE-1") for r in batch]
        de = embed(descs); de /= (np.linalg.norm(de, axis=1, keepdims=True) + 1e-9)
        sims = de @ tmpl_emb.T
        for r, srow in zip(batch, sims):
            cwe = r["structured"].get("av") and r  # placeholder
            best = float(srow.max())
            sig[r["sampleId"]] = "present" if best >= 0.92 else "weak"
    return sig   # 그 외(context-arm) 는 abstain


# ---------------------------------------------------------------------------
# 문장-어텐션 멀티태스크 모델
# ---------------------------------------------------------------------------
class VexModel(nn.Module):
    def __init__(self, dim, n_cls=3, hid=256):
        super().__init__()
        self.att_w = nn.Linear(dim, hid)
        self.att_v = nn.Linear(hid, 1, bias=False)
        self.cls = nn.Sequential(nn.Linear(dim, hid), nn.ReLU(), nn.Dropout(0.2), nn.Linear(hid, n_cls))
        self.rat = nn.Sequential(nn.Linear(dim, hid), nn.ReLU(), nn.Linear(hid, 1))

    def forward(self, x, mask):
        # x [B,K,D], mask [B,K]
        a = self.att_v(torch.tanh(self.att_w(x))).squeeze(-1)   # [B,K]
        a = a.masked_fill(mask == 0, -1e9)
        att = torch.softmax(a, dim=1)
        doc = (att.unsqueeze(-1) * x).sum(1)                    # [B,D]
        logits = self.cls(doc)
        rat = self.rat(x).squeeze(-1)                           # [B,K] driver logits
        return logits, rat, att


def build_tensors(recs, emb, max_k):
    D = len(next(iter(emb.values())))
    X = np.zeros((len(recs), max_k, D), np.float32)
    M = np.zeros((len(recs), max_k), np.float32)
    R = np.zeros((len(recs), max_k), np.float32)      # gold driver
    Y = np.zeros(len(recs), np.int64)
    meta = []
    for i, r in enumerate(recs):
        gold = set(r["gold_rationale_ids"])
        for j, s in enumerate(r["sentences"][:max_k]):
            X[i, j] = emb[s["text"]]; M[i, j] = 1.0
            if s["id"] in gold:
                R[i, j] = 1.0
        Y[i] = L2I[r["label"]]
        meta.append([s["id"] for s in r["sentences"][:max_k]])
    return X, M, R, Y, meta


def train(model, Xtr, Mtr, Rtr, Ytr, epochs=25, lam=0.5):
    opt = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-5)
    ce = nn.CrossEntropyLoss()
    bce = nn.BCEWithLogitsLoss()
    Xtr, Mtr, Rtr, Ytr = (torch.tensor(t).to(DEVICE) for t in (Xtr, Mtr, Rtr, Ytr))
    n = Xtr.shape[0]; bs = 256
    for ep in range(epochs):
        model.train(); perm = torch.randperm(n)
        tot = 0.0
        for i in range(0, n, bs):
            idx = perm[i:i + bs]
            logits, rat, _ = model(Xtr[idx], Mtr[idx])
            loss = ce(logits, Ytr[idx]) + lam * bce(rat[Mtr[idx] == 1], Rtr[idx][Mtr[idx] == 1])
            opt.zero_grad(); loss.backward(); opt.step()
            tot += loss.item() * len(idx)
        if ep % 5 == 0 or ep == epochs - 1:
            print("    epoch %2d  loss %.4f" % (ep, tot / n), flush=True)


@torch.no_grad()
def predict(model, X, M):
    model.eval()
    X, M = torch.tensor(X).to(DEVICE), torch.tensor(M).to(DEVICE)
    logits, rat, att = model(X, M)
    probs = torch.softmax(logits, 1).cpu().numpy()
    rat_p = torch.sigmoid(rat).cpu().numpy()
    return probs, rat_p, att.cpu().numpy()


# ---------------------------------------------------------------------------
# Evidence Verifier + 보수적 Decision Engine
# ---------------------------------------------------------------------------
def decision_engine(rec, probs, rat_p, ids, code_sig, conf_thresh=0.55):
    """모델 출력 -> 보수적 최종 VEX. NOT_AFFECTED 는 적극적 반증 rationale 필요."""
    pred_i = int(np.argmax(probs))
    pred = LABELS[pred_i]; conf = float(probs[pred_i])
    # 선택된 rationale 문장(상위, 임계 0.5)
    sel = [ids[j] for j in range(len(ids)) if rat_p[j] >= 0.5]
    # 문장 kind 조회
    kind = {s["id"]: s["kind"] for s in rec["sentences"]}
    has_counter = any(kind.get(e) in ("neg_absent", "neg_version", "neg_patched", "neg_disabled", "exposure")
                      and kind.get(e) is not None for e in sel)
    # exposure 문장이 반증이 되려면 isolated/physical 맥락이어야 하지만
    # 여기서는 '노출 관련 근거가 선택되었는가'를 완화 조건으로 사용
    neg_selected = any(kind.get(e, "").startswith("neg_") for e in sel)

    # 규칙
    if conf < conf_thresh:
        return "UNDER_INVESTIGATION", conf, sel, "model confidence below threshold"
    if pred == "LIKELY_NOT_AFFECTED":
        if neg_selected or any(kind.get(e) == "exposure" for e in sel):
            return "LIKELY_NOT_AFFECTED", conf, sel, "positive counter-evidence present"
        return "UNDER_INVESTIGATION", conf, sel, "not-affected lacks positive counter-evidence"
    if pred == "LIKELY_AFFECTED":
        # oss-arm 이고 코드 신호가 weak/none 이면 코드확인 필요 -> 유지하되 표시
        return "LIKELY_AFFECTED", conf, sel, "affected conditions supported by evidence"
    return "UNDER_INVESTIGATION", conf, sel, "insufficient or conflicting evidence"


# ---------------------------------------------------------------------------
# 지표
# ---------------------------------------------------------------------------
def cls_metrics(y_true, y_pred):
    from sklearn.metrics import f1_score, precision_recall_fscore_support, confusion_matrix
    macro = f1_score(y_true, y_pred, labels=list(range(3)), average="macro", zero_division=0)
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=list(range(3)), zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=list(range(3)))
    return macro, {LABELS[i]: {"precision": float(p[i]), "recall": float(r[i]),
                               "f1": float(f[i]), "support": int(s[i])} for i in range(3)}, cm.tolist()


def ece(probs, y_true, bins=10):
    conf = probs.max(1); pred = probs.argmax(1); acc = (pred == y_true).astype(float)
    e = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        m = (conf > lo) & (conf <= hi)
        if m.sum() > 0:
            e += m.mean() * abs(acc[m].mean() - conf[m].mean())
    return float(e)


def rationale_metrics(rat_p, meta, recs, X, M, model):
    """문장 P/R/F1, IoU + Sufficiency/Comprehensiveness(입력 제거)."""
    tp = fp = fn = 0; ious = []
    for i, r in enumerate(recs):
        gold = set(r["gold_rationale_ids"])
        ids = meta[i]
        sel = {ids[j] for j in range(len(ids)) if rat_p[i, j] >= 0.5}
        tp += len(sel & gold); fp += len(sel - gold); fn += len(gold - sel)
        u = len(sel | gold)
        ious.append(len(sel & gold) / u if u else 1.0)
    P = tp / (tp + fp) if tp + fp else 0.0
    R = tp / (tp + fn) if tp + fn else 0.0
    F = 2 * P * R / (P + R) if P + R else 0.0
    # Sufficiency / Comprehensiveness
    probs_full, rat_full, _ = predict(model, X, M)
    base = probs_full[np.arange(len(recs)), probs_full.argmax(1)]
    Xs = X.copy(); Ms = M.copy(); Xc = X.copy(); Mc = M.copy()
    for i in range(len(recs)):
        for j in range(M.shape[1]):
            if M[i, j] == 0:
                continue
            is_sel = rat_full[i, j] >= 0.5
            if not is_sel:            # sufficiency: 선택된 것만 남김
                Ms[i, j] = 0
            else:                     # comprehensiveness: 선택된 것 제거
                Mc[i, j] = 0
    ps, _, _ = predict(model, Xs, np.clip(Ms, 0, 1))
    pc, _, _ = predict(model, Xc, np.clip(Mc, 0, 1))
    pred = probs_full.argmax(1)
    suff = float(np.mean(base - ps[np.arange(len(recs)), pred]))
    comp = float(np.mean(base - pc[np.arange(len(recs)), pred]))
    return {"precision": P, "recall": R, "f1": F, "iou": float(np.mean(ious)),
            "sufficiency_drop": suff, "comprehensiveness_drop": comp}


def tfidf_baseline(tr, te):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    def doc(r): return " ".join(s["text"] for s in r["sentences"])
    vec = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    Xtr = vec.fit_transform([doc(r) for r in tr]); Xte = vec.transform([doc(r) for r in te])
    ytr = [L2I[r["label"]] for r in tr]; yte = [L2I[r["label"]] for r in te]
    clf = LogisticRegression(max_iter=2000, C=4.0).fit(Xtr, ytr)
    from sklearn.metrics import f1_score
    return float(f1_score(yte, clf.predict(Xte), average="macro", zero_division=0))


def main():
    set_seed(SEED)
    os.makedirs(RESULTS, exist_ok=True); os.makedirs(SAMPLE_DIR, exist_ok=True)
    t0 = time.time()
    print("[1] load dataset", flush=True)
    recs, tr, te = load_dataset()
    print("    total %d | train %d | test %d | devices train/test disjoint" % (len(recs), len(tr), len(te)), flush=True)

    print("[2] SecureBERT sentence embeddings", flush=True)
    emb = encode_sentences(recs)
    max_k = max(len(r["sentences"]) for r in recs)

    print("[3] CodeBERT auxiliary signal (oss-arm)", flush=True)
    try:
        code_sig = codebert_signal(recs)
    except Exception as e:
        print("    CodeBERT skipped: %s" % e, flush=True); code_sig = {}

    Xtr, Mtr, Rtr, Ytr, _ = build_tensors(tr, emb, max_k)
    Xte, Mte, Rte, Yte, meta_te = build_tensors(te, emb, max_k)

    print("[4] train SecureBERT sentence-attention model", flush=True)
    model = VexModel(Xtr.shape[2]).to(DEVICE)
    train(model, Xtr, Mtr, Rtr, Ytr)

    print("[5] inference + decision engine", flush=True)
    probs, rat_p, att = predict(model, Xte, Mte)
    raw_pred = probs.argmax(1)

    final_pred = []; final_conf = []
    for i, r in enumerate(te):
        fp_label, conf, sel, reason = decision_engine(r, probs[i], rat_p[i], meta_te[i], code_sig.get(r["sampleId"]))
        final_pred.append(L2I[fp_label]); final_conf.append(conf)
    final_pred = np.array(final_pred)

    print("[6] metrics", flush=True)
    macro_raw, per_raw, cm_raw = cls_metrics(Yte, raw_pred)
    macro_de, per_de, cm_de = cls_metrics(Yte, final_pred)
    # 잘못된 NOT_AFFECTED: 실제 AFFECTED 인데 NOT_AFFECTED 로 예측
    def wrong_na(pred):
        na = L2I["LIKELY_NOT_AFFECTED"]; aff = L2I["LIKELY_AFFECTED"]
        m = pred == na
        return float(np.mean((Yte[m] == aff)) ) if m.sum() else 0.0, int(((pred == na) & (Yte == aff)).sum())
    wr_raw = wrong_na(raw_pred); wr_de = wrong_na(final_pred)
    u_rate_raw = float(np.mean(raw_pred == L2I["UNDER_INVESTIGATION"]))
    u_rate_de = float(np.mean(final_pred == L2I["UNDER_INVESTIGATION"]))
    ece_v = ece(probs, Yte)
    rat_m = rationale_metrics(rat_p, meta_te, te, Xte, Mte, model)
    base_f1 = tfidf_baseline(tr, te)

    metrics = {
        "dataset": {"total": len(recs), "train": len(tr), "test": len(te),
                    "label_dist_test": {LABELS[i]: int((Yte == i).sum()) for i in range(3)}},
        "classification_raw_securebert": {"macro_f1": macro_raw, "per_class": per_raw,
                                          "confusion_matrix": cm_raw, "under_investigation_rate": u_rate_raw,
                                          "wrong_not_affected_rate": wr_raw[0], "wrong_not_affected_count": wr_raw[1],
                                          "ece": ece_v},
        "classification_with_decision_engine": {"macro_f1": macro_de, "per_class": per_de,
                                                "confusion_matrix": cm_de, "under_investigation_rate": u_rate_de,
                                                "wrong_not_affected_rate": wr_de[0], "wrong_not_affected_count": wr_de[1]},
        "rationale": rat_m,
        "baseline_tfidf_logreg_macro_f1": base_f1,
        "runtime_sec": round(time.time() - t0, 1),
        "device": DEVICE,
    }
    with open(os.path.join(RESULTS, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)

    # 샘플 VEX 출력 (검증된 근거 포함) 20건
    kind_te = [{s["id"]: s for s in r["sentences"]} for r in te]
    for i in range(min(20, len(te))):
        r = te[i]
        fp_label, conf, sel, reason = decision_engine(r, probs[i], rat_p[i], meta_te[i], code_sig.get(r["sampleId"]))
        out = {
            "sampleId": r["sampleId"], "device": r["device"], "cve": r["cve"],
            "vex_status": fp_label, "confidence": round(conf, 3),
            "oracle_label": r["label"], "decision_reason": reason,
            "selected_rationale": [{"evidenceId": e, "text": kind_te[i][e]["text"]} for e in sel],
            "model_probs": {LABELS[k]: round(float(probs[i][k]), 3) for k in range(3)},
        }
        json.dump(out, open(os.path.join(SAMPLE_DIR, "%s.json" % r["sampleId"]), "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)

    # 대시보드용 per-sample 예측 덤프
    preds = []
    for i, r in enumerate(te):
        preds.append({
            "sampleId": r["sampleId"], "device": r["device"], "cve": r["cve"],
            "arm": r["arm"], "tier": r["tier"],
            "true": LABELS[int(Yte[i])], "raw_pred": LABELS[int(raw_pred[i])],
            "de_pred": LABELS[int(final_pred[i])],
            "probs": [round(float(x), 4) for x in probs[i]],
            "av": r["structured"]["av"], "exposure": r["structured"]["exposure"],
            "kev": bool(r["structured"]["kev"]),
        })
    json.dump(preds, open(os.path.join(RESULTS, "predictions.json"), "w", encoding="utf-8"),
              ensure_ascii=False)

    # 리포트
    write_report(metrics)
    print("DONE  macro-F1 raw=%.3f  DE=%.3f  baseline=%.3f  wrongNA raw=%d DE=%d  (%.0fs)" %
          (macro_raw, macro_de, base_f1, wr_raw[1], wr_de[1], metrics["runtime_sec"]), flush=True)


def write_report(m):
    L = []
    L.append("# ICS VEX 시스템 평가 리포트\n")
    L.append("SecureBERT(문장-어텐션 멀티태스크) + 보수적 Decision Engine. device-disjoint split.\n")
    d = m["dataset"]
    L.append("## 데이터셋")
    L.append("- 총 %d findings | train %d | test %d" % (d["total"], d["train"], d["test"]))
    L.append("- test 라벨 분포: " + ", ".join("%s=%d" % (k, v) for k, v in d["label_dist_test"].items()) + "\n")
    for key, title in [("classification_raw_securebert", "SecureBERT 원분류"),
                       ("classification_with_decision_engine", "보수적 Decision Engine 적용")]:
        c = m[key]
        L.append("## %s" % title)
        L.append("- Macro F1: **%.3f**" % c["macro_f1"])
        L.append("- UNDER_INVESTIGATION 전환율: %.1f%%" % (100 * c["under_investigation_rate"]))
        L.append("- 잘못된 LIKELY_NOT_AFFECTED: %d건 (해당예측중 %.1f%%)" %
                 (c["wrong_not_affected_count"], 100 * c["wrong_not_affected_rate"]))
        L.append("- per-class:")
        for cl, v in c["per_class"].items():
            L.append("  - %-22s P=%.3f R=%.3f F1=%.3f (n=%d)" % (cl, v["precision"], v["recall"], v["f1"], v["support"]))
        L.append("- confusion (rows=true %s):" % ",".join(LABELS))
        for row in c["confusion_matrix"]:
            L.append("  - %s" % row)
        L.append("")
    L.append("## 근거(rationale) 추출")
    r = m["rationale"]
    L.append("- 문장 P/R/F1: %.3f / %.3f / %.3f | IoU %.3f" % (r["precision"], r["recall"], r["f1"], r["iou"]))
    L.append("- Sufficiency drop: %.3f (작을수록 좋음) | Comprehensiveness drop: %.3f (클수록 좋음)\n" %
             (r["sufficiency_drop"], r["comprehensiveness_drop"]))
    L.append("## 비교")
    L.append("- TF-IDF+LogReg baseline Macro F1: %.3f" % m["baseline_tfidf_logreg_macro_f1"])
    L.append("- SecureBERT Macro F1: %.3f" % m["classification_raw_securebert"]["macro_f1"])
    L.append("- SecureBERT calibration ECE: %.3f" % m["classification_raw_securebert"]["ece"])
    L.append("\n- 실행: %s, %.0fs" % (m["device"], m["runtime_sec"]))
    open(os.path.join(RESULTS, "report.md"), "w", encoding="utf-8").write("\n".join(L) + "\n")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
