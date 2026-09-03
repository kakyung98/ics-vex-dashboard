#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""시험항목 #3 — SBOM 기반 공개 취약점 정보 식별 정밀도.

    precision = TP / (TP + FP) × 100        (target >= 95%)
      TP: SBOM 항목이 Ratcliff–Obershelp(difflib) 정규화로 매칭된 CPE 제품이
          라벨(정답)의 CPE 제품과 일치하고, 그 결과 식별된 CVE가 정답 CVE와 일치.
      FP: 매칭된 CPE 제품/버전이 정답과 불일치(버전·에디션 불일치 또는 잘못된 제품 매핑).

SUT의 CPE 정규화·CVE 재식별(api_server.vex_compare_sbom / _ro_best_match,
Ratcliff–Obershelp, 임계값 0.7)을 그대로 구동한다. 정답은 라벨 데이터셋
(data/cpe_match_eval.jsonl)이며, 각 항목은 실제 SBOM에 나타나는 컴포넌트 표기와
그에 대한 정확한 CPE 제품·CVE(외부 DB/CISA CSAF 기준)를 담는다.

'영향 있음(affected)' 여부는 고려하지 않으며, 식별된 CVE가 항목과 정확히
일치하는지만 판정한다(전제조건).

라벨 데이터셋 형식(JSONL, 한 줄당):
  {"component": "OpenSSL", "version": "1.0.2", "correct_cpe_product": "openssl",
   "correct_cves": ["CVE-2016-2107", ...]}

Usage:
  python tools/eval_cpe_match_precision.py [--data data/cpe_match_eval.jsonl] [--threshold 0.7]
"""
import argparse
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "src"))
import api_server as A   # loads STORE (KB + matcher) on import

DATA = os.path.join(BASE, "data", "cpe_match_eval.jsonl")
OUT = os.path.join(BASE, "results", "cpe_match_precision.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DATA)
    ap.add_argument("--threshold", type=float, default=0.7)
    a = ap.parse_args()

    if not os.path.isfile(a.data):
        print("라벨 데이터셋 없음: %s" % a.data)
        print("각 줄에 {component, version, correct_cpe_product, correct_cves[]} 형식으로 준비하십시오.")
        print("(CISA CSAF product↔CVE 권위 매핑에서 구성 — compare_cisa_csaf.py 참조)")
        return

    rows = [json.loads(l) for l in open(a.data, encoding="utf-8") if l.strip()]
    tp = fp = 0
    per = []
    for r in rows:
        sbom = {"components": [{"name": r["component"], "version": r.get("version", "")}]}
        res = A.vex_compare_sbom(sbom, threshold=a.threshold)
        row0 = res["normalization"][0] if res["normalization"] else {}
        matched = row0.get("normalized_match") or row0.get("best_match")
        # 매칭된 KB 제품의 cpe_product 를 확인
        matched_cpe = None
        for comp, _strs in A.STORE.kb_match:
            if comp["name"] == matched:
                matched_cpe = comp.get("cpe_product"); break
        identified = set(res["comparison"]["both"]) | set(res["comparison"]["only_normalized"])
        gold_cves = set(r.get("correct_cves") or [])
        product_ok = (matched_cpe == r.get("correct_cpe_product"))
        # CVE 단위 TP/FP
        for cve in identified:
            if product_ok and cve in gold_cves:
                tp += 1
            else:
                fp += 1
        per.append({"component": r["component"], "matched_cpe": matched_cpe,
                    "product_ok": product_ok, "identified": len(identified)})

    prec = 100.0 * tp / (tp + fp) if (tp + fp) else 0.0
    res = {"test": "SBOM CVE-identification precision (시험항목 #3)",
           "algorithm": "Ratcliff–Obershelp (difflib) CPE normalization + CVE re-identification",
           "threshold": a.threshold, "target_pct": 95.0,
           "ground_truth": "labeled component→correct CPE product+CVE (data/cpe_match_eval.jsonl)",
           "n_components": len(rows), "identified_cves": tp + fp,
           "TP": tp, "FP": fp, "precision_pct": round(prec, 2), "pass": prec >= 95.0}
    print("=== 시험항목 #3 · SBOM CVE 식별 정밀도 ===")
    print("  algorithm    : Ratcliff–Obershelp (threshold %.2f)" % a.threshold)
    print("  components   : %d  |  identified CVEs = TP+FP = %d" % (len(rows), tp + fp))
    print("  TP=%d  FP=%d" % (tp, fp))
    print("  PRECISION = %.2f%%  (target 95%%)  ->  %s" % (prec, "PASS" if prec >= 95 else "FAIL"))
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("->", OUT)


if __name__ == "__main__":
    main()
