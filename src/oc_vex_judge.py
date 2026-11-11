#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OC 대조 결과 -> VEX 상태. 자산 운영맥락 판정기.

왜 대조(oc_context)와 판정(여기)을 나누는가
-------------------------------------------
docs/ICSVEX.md §8 의 비교 실험 M1~M4 는 **같은 평가 사례**를 써야 한다. 대조
결과를 한 곳에서 만들고 판정 규칙만 갈아끼우면 M2(규칙)와 M4(제안)가 같은
입력을 보는 것이 구조적으로 보장된다. 둘을 한 함수에 두면 실험마다 입력이
조용히 달라진다.

상태 결정 규칙
--------------
  ABSENT 가 하나라도 있다      -> not_affected   (구조적 반박, 정당화 부여)
  아니면 UNKNOWN 이 하나라도   -> under_investigation  (유보)
  아니면                        -> affected       (DISABLED 는 완화로 기록)

세 번째 줄이 중요하다. DISABLED 만 잔뜩 있어도 상태는 `affected` 다. 포트를
닫았다는 사실은 변경 창 한 번이면 되돌아오므로, 그것으로 발행된 VEX 문서를
`not_affected` 로 만들면 문서가 조직의 설정 변경보다 먼저 낡는다.

두 번째 줄은 **정밀도를 사는 대신 판정률을 판다**. docs/ICSVEX.md §7 이
"정보 부족은 under_investigation"이라고 정했으므로 그대로 따르되, 유보가
Precision 분모에서 빠진다는 점 때문에 지표가 게임이 될 수 있다 (§8). 그래서
`judge_many()` 가 유보율을 **항상** 함께 돌려준다 — 정밀도만 떼어 보고하는 것이
불가능하게 만드는 것이 이 함수의 숨은 목적이다.

이 판정기가 절대 내지 않는 정당화 두 가지
-----------------------------------------
  * `inline_mitigations_already_exist` — CISA 정의상 **공급자**가 제품에 넣어둔
    완화를 뜻한다. 운영자의 방화벽은 그것이 아니다. 라벨을 빌려 쓰면 기계
    판독 문서에 거짓 주장이 실린다.
  * `vulnerable_code_not_present` — 코드를 봐야 할 수 있는 말이다. 이 팔은
    운영자 진술을 다루므로 코드 부재를 확정하지 않는다.
"""
try:
    from src import oc_context as OC
except ModuleNotFoundError:
    import oc_context as OC

AFFECTED = "affected"
NOT_AFFECTED = "not_affected"
UNDER_INVESTIGATION = "under_investigation"
FIXED = "fixed"

# 구조적 반박이 얻는 CISA 정당화. OC5(설정)에 항목이 없는 것은 설계다 —
# 설정은 ABSENT 가 될 수 없고 DISABLED 까지만 간다.
JUSTIFICATION = {
    "OC1": "vulnerable_code_not_in_execute_path",
    "OC2": "vulnerable_code_not_in_execute_path",
    "OC3": "vulnerable_code_cannot_be_controlled_by_adversary",
    "OC4": "vulnerable_code_cannot_be_controlled_by_adversary",
}

_WHY = {
    "service": "자산 빌드에 '%s' 서비스가 포함되어 있지 않아 해당 코드 경로에 진입할 수 없다",
    "feature": "'%s' 기능이 이 빌드에 존재하지 않는다",
    "protocol": "'%s' 프로토콜 스택이 펌웨어에 구현되어 있지 않다",
    "channel": "CVE가 점수화된 '%s' 채널이 이 자산에 물리적으로 존재하지 않는다",
    "privilege": "해당 인터페이스에 계정 개념 자체가 없어 '%s' 권한을 가질 주체가 없다",
    "interaction": "콘텐츠를 다루는 사람이 없는 자산이라 상호작용을 수행할 주체가 없다",
    "config": "설정 '%s' 가 요구값과 다르다",
}


def judge(cve, requirements, asset, component_present=True,
          version_in_range=True, patched=False):
    """자산 하나 × CVE 하나의 VEX 문장.

    component_present / version_in_range 는 SBOM 단계(식별)의 답이며, 여기 오기
    전에 이미 정해져 있다. 둘 중 하나라도 거짓이면 운영맥락을 볼 필요가 없다 —
    그 CVE는 이 자산의 것이 아니다.
    """
    if not component_present:
        return _stmt(cve, NOT_AFFECTED, "component_not_present",
                     "해당 구성요소가 이 자산의 SBOM에 없다", [], [])
    if not version_in_range:
        return _stmt(cve, NOT_AFFECTED, "component_not_present",
                     "설치된 버전이 CVE의 영향 범위 밖이다", [], [])
    if patched:
        return _stmt(cve, FIXED, None, "수정된 버전이 설치되어 있다", [], [])

    ev = OC.evaluate(requirements, asset)
    rows = ev["rows"]

    # 전제조건이 하나도 추출되지 않았으면 "전부 충족"이 아니라 "아무것도 모른다"다.
    # 빈 요구 집합을 충족으로 읽으면 CVSS 벡터도 서술문도 없는 CVE가 전부
    # `affected` 로 쏟아지고, 그 거짓 양성이 Precision 분자가 아니라 분모를 채운다
    # - 지표를 직접 깎는 실패이고, 조용히 일어나기 때문에 더 나쁘다.
    if not rows:
        st = _stmt(cve, UNDER_INVESTIGATION, None,
                   "이 CVE에서 확인 가능한 공격 전제조건을 하나도 추출하지 못했다 "
                   "(CVSS 벡터 없음 + 서술문에서 조건 식별 실패). 대조할 것이 "
                   "없으므로 충족 여부를 말할 수 없다.", [], [])
        st["missing"] = [{"slot": "-", "requirement": "no preconditions extracted"}]
        return st

    refutations = [r for r in rows if r["result"] == OC.ABSENT]
    unknowns = [r for r in rows if r["result"] == OC.UNKNOWN]
    mitigations = [r for r in rows if r["result"] == OC.DISABLED]

    if refutations:
        top = refutations[0]
        just = JUSTIFICATION.get(top["slot"])
        why = _WHY.get(top["kind"], "%s 조건을 자산이 공급할 수 없다")
        try:
            reason = why % top["requirement"]
        except TypeError:
            reason = why
        st = _stmt(cve, NOT_AFFECTED, just, reason, refutations, mitigations)
        # 점수화된 경로만 반박했을 뿐 다른 경로를 본 것이 아니다. 이 문장을
        # 빼면 문서가 실제보다 강한 주장을 하게 된다.
        st["scope"] = "as-scored"
        st["caveat"] = ("NVD는 가장 심각한 현실적 경로를 점수화한다. 이 반박은 "
                        "그 경로에 대한 것이며 '이 CVE가 이 자산에서 결코 악용될 "
                        "수 없다'는 뜻이 아니다.")
        st["evidence_basis"] = "운영자 진술 (기계 측정이 아님)"
        return st

    if unknowns:
        st = _stmt(cve, UNDER_INVESTIGATION, None,
                   "%d개 전제조건을 판단할 정보가 없다: %s"
                   % (len(unknowns),
                      ", ".join("%s(%s)" % (u["slot"], u["requirement"])
                                for u in unknowns[:4])),
                   [], mitigations)
        st["missing"] = [{"slot": u["slot"], "requirement": u["requirement"]}
                         for u in unknowns]
        return st

    return _stmt(cve, AFFECTED, None,
                 "모든 전제조건이 이 자산에서 충족된다"
                 + (" (완화 %d건은 상태를 바꾸지 않는다)" % len(mitigations)
                    if mitigations else ""),
                 [], mitigations)


def _stmt(cve, status, justification, reason, refutations, mitigations):
    return {
        "cve": cve, "status": status, "justification": justification,
        "reason": reason, "arm": "operational-context", "model": OC.OC_MODEL,
        "refutations": [{"slot": r["slot"], "requirement": r["requirement"]}
                        for r in refutations],
        # 완화는 상태를 바꾸지 않지만 CSAF remediation/mitigation 으로 나가야
        # 한다 - 운영자가 실제로 취한 조치를 문서에서 지우면 안 된다.
        "mitigations": [{"slot": m["slot"], "requirement": m["requirement"],
                         "category": "mitigation"} for m in mitigations],
    }


def judge_many(cases):
    """여러 (자산, CVE) 사례를 한 번에. 유보율을 반드시 같이 돌려준다.

    cases : [{cve, requirements, asset, component_present?, version_in_range?}]

    Precision(>90%)은 `affected` 를 positive 로 보는 이진 지표이고 유보는
    분모에서 빠진다 (docs/ICSVEX.md §8). 유보를 늘리면 정밀도는 올라가므로
    두 수를 떼어 놓을 수 없게 한 묶음으로 돌려준다.
    """
    out = [judge(c["cve"], c.get("requirements"), c.get("asset"),
                 c.get("component_present", True),
                 c.get("version_in_range", True),
                 c.get("patched", False)) for c in cases]
    for statement,case in zip(out,cases):
        requirements=case.get('requirements') or {}
        if 'cwe_context' in requirements:statement['cwe_context']=requirements['cwe_context']
    n = len(out)
    counts = {}
    for s in out:
        counts[s["status"]] = counts.get(s["status"], 0) + 1
    deferred = counts.get(UNDER_INVESTIGATION, 0)
    decided = n - deferred
    return {
        "statements": out,
        "total": n,
        "by_status": counts,
        "deferred": deferred,
        # 이 두 수가 정밀도 해석의 전부다. 판정률이 낮으면 높은 정밀도는
        # 성취가 아니라 회피다.
        "deferral_rate": round(deferred / n, 4) if n else None,
        "decision_rate": round(decided / n, 4) if n else None,
    }


def precision(statements, truth):
    """Precision = TP / (TP + FP), positive = `affected` (docs/ICSVEX.md §8).

    truth : {cve: "affected" | "not_affected"}  독립 근거로 만든 정답.
    유보한 사례는 분자·분모 어디에도 들어가지 않는다. 그래서 `covered` 를
    함께 돌려준다 — 이 값 없이 정밀도만 인용하는 것은 보고가 아니다.
    """
    tp = fp = 0
    for s in statements:
        if s["status"] != AFFECTED:
            continue
        t = truth.get(s["cve"])
        if t == AFFECTED:
            tp += 1
        elif t == NOT_AFFECTED:
            fp += 1
    denom = tp + fp
    return {
        "tp": tp, "fp": fp, "denominator": denom,
        # TP+FP = 0 이면 정밀도는 계산되지 않으며 목표 달성으로 보지 않는다.
        "precision": round(tp / denom, 4) if denom else None,
        "meets_target": bool(denom and (tp / denom) > 0.90),
        "covered": denom,
        "scored_total": len(statements),
    }


if __name__ == "__main__":
    import io, sys, json
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    req = {"required_services": ["web admin"], "required_protocols": ["modbus"],
           "attack_channel": "network", "requires_privileges": "low"}
    cases = [
        {"cve": "CVE-A", "requirements": req,
         "asset": {"protocols_absent": ["modbus"], "running_services": ["web admin"],
                   "reachable_from": "control-network", "effective_privileges": "low",
                   "authentication_enabled": True}},
        {"cve": "CVE-B", "requirements": req,
         "asset": {"active_protocols": ["modbus"], "running_services": ["web admin"],
                   "reachable_from": "ot-dmz", "anonymous_access_allowed": True}},
        {"cve": "CVE-C", "requirements": req, "asset": {}},
    ]
    res = judge_many(cases)
    for s in res["statements"]:
        print("%-8s %-20s %s" % (s["cve"], s["status"], s["reason"]))
    print("\ndeferral_rate=%s  decision_rate=%s" %
          (res["deferral_rate"], res["decision_rate"]))
    print(json.dumps(precision(res["statements"],
                               {"CVE-A": "not_affected", "CVE-B": "affected"}),
                     ensure_ascii=False))
