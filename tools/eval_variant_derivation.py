#!/usr/bin/env python3
"""모델 변형 단위에서 not_affected 를 *독립 유도*하고 CISA 라벨과 대조한다.

무엇이 입력이고 무엇이 정답인지 엄격히 가른다:

  입력(우리가 봐도 되는 것)
    - product_tree            어드바이저리가 열거한 제품 모델 목록
    - product_status.known_affected   어드바이저리가 "영향받는다"고 밝힌 모델
    - 자산의 모델 정체성 (SBOM)
    이 셋은 모든 자산소유자가 권고문에서 그대로 읽는 정보다.

  정답(절대 입력으로 쓰지 않는 것)
    - product_status.known_not_affected
    - vulnerabilities[].flags[].label      <- CISA 의 justification

  유도 규칙 (자산소유자가 실제로 하는 추론)
    내 모델이 이 CVE 의 known_affected 목록에 없다  ->  not_affected
    근거는 그 모델에 취약 구성요소가 없다는 뜻이므로  ->  component_not_present

known_not_affected 를 읽지 않으므로 순환이 아니다. 다만 "열거되지 않은 모델"과
"명시적으로 영향 없다고 적힌 모델"을 구별할 수 없어, 그 한계도 함께 보고한다.
"""
import argparse
import collections
import glob
import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def variants_of(csaf):
    names = {}

    def walk(bs, pref):
        for b in bs or []:
            nm = pref + [b.get("name", "")]
            if "product" in b and b["product"].get("product_id"):
                names[b["product"]["product_id"]] = " ".join(n for n in nm if n).strip()
            walk(b.get("branches"), nm)

    walk((csaf.get("product_tree") or {}).get("branches"), [])
    for fp in (csaf.get("product_tree") or {}).get("full_product_names") or []:
        if fp.get("product_id"):
            names.setdefault(fp["product_id"], fp.get("name", ""))
    # relationships 로만 등장하는 합성 product_id 도 모델 모집단에 포함된다
    for rel in (csaf.get("product_tree") or {}).get("relationships") or []:
        fpn = rel.get("full_product_name") or {}
        if fpn.get("product_id"):
            names.setdefault(fpn["product_id"], fpn.get("name", ""))
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt", default=os.path.join(BASE, "data", "gt_icsa"))
    a = ap.parse_args()

    man = json.load(open(os.path.join(a.gt, "manifest.json"), encoding="utf-8"))
    tp = fp = fn = 0
    just_ok = 0
    per = []
    unenumerated = 0

    for rec in man["tier1"]:
        aid = rec["advisory_id"]
        p = os.path.join(a.gt, "tier1_justification", "cisa_csaf", aid + ".json")
        csaf = json.load(open(p, encoding="utf-8"))
        models = variants_of(csaf)
        for v in csaf.get("vulnerabilities") or []:
            cve = v.get("cve")
            if cve not in rec["flags"]:
                continue
            ps = v.get("product_status") or {}
            affected = set(ps.get("known_affected") or [])
            truth_not = set(ps.get("known_not_affected") or [])     # 정답
            truth_lab = rec["flags"][cve][0]                        # 정답

            # --- 유도: known_affected 에 없는 모델은 not_affected ---
            derived_not = {m for m in models if m not in affected}
            derived_lab = "component_not_present"

            t = len(derived_not & truth_not)
            f = len(derived_not - truth_not)
            n = len(truth_not - derived_not)
            tp += t; fp += f; fn += n
            unenumerated += len(derived_not - truth_not - affected)
            ok = (derived_lab == truth_lab)
            just_ok += bool(ok and t)
            per.append((aid, cve, len(models), len(affected), len(truth_not),
                        len(derived_not), t, f, n, truth_lab, ok))

    print("모델 단위 not_affected 독립 유도 — CISA 라벨 대조\n")
    print("%-18s %-16s %5s %5s %5s %5s %4s %4s %4s  %s"
          % ("ICSA", "CVE", "모델", "aff", "정답", "유도", "TP", "FP", "FN", "label 일치"))
    for r in per:
        print("%-18s %-16s %5d %5d %5d %5d %4d %4d %4d  %s"
              % (r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8],
                 "O" if r[10] else "X (%s)" % r[9]))

    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec_ = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec_ / (prec + rec_) if (prec + rec_) else 0.0
    print("\n모델 단위 (product_id) 집계")
    print("  TP %d / FP %d / FN %d" % (tp, fp, fn))
    print("  precision %.3f | recall %.3f | F1 %.3f" % (prec, rec_, f1))
    print("\n(ICSA, CVE) 쌍 단위")
    print("  justification 까지 맞춘 쌍: %d/%d" % (just_ok, len(per)))
    print("\n한계: FP %d 중 %d 개는 CISA 가 아예 열거하지 않은 모델이다."
          % (fp, unenumerated))
    print("      known_not_affected 를 입력으로 쓰지 않았으므로 '영향 없음'과")
    print("      '언급 안 됨'을 구별할 수 없다 — 이것이 공개 데이터의 상한이다.")


if __name__ == "__main__":
    main()
