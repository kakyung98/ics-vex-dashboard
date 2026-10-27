#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""소스코드가 있는 경우의 VEX 판정 — 호출그래프·CFG 근거.

언제 이 팔이 도는가
-------------------
사용자가 분석기에서 "소스코드 있음"을 고르고 ZIP을 올린 경우에만. 소스가 없으면
전부 src/oc_vex_judge.py(운영맥락 팔)로 간다. 두 팔은 **같은 CVE에 대해 동시에
돌지 않는다** — 근거의 종류가 다르고, 섞으면 어느 쪽이 상태를 정했는지 문서에서
읽을 수 없게 된다.

질문 순서
---------
  Q1  취약 함수가 이 트리에 정의되어 있는가
        없다 -> not_affected / vulnerable_code_not_present
  Q2  죽은 코드 안에 있는가 (`#if 0`, `if (0)`)
        그렇다 -> not_affected / vulnerable_code_not_in_execute_path
  Q3  진입점에서 호출 경로가 있는가
        없다 -> not_affected / vulnerable_code_not_in_execute_path  (단, 아래 단서)
        있다 -> affected, 경로를 근거로 첨부

Q3 의 단서가 이 모듈에서 가장 중요한 줄이다
-------------------------------------------
호출그래프는 구문에서 세운 **근사**다. 함수 포인터(`cb->handler(x)`,
`(*fp)(x)`)로 가는 호출은 보이지 않는다. 보이지 않는 엣지는 **도달 가능을 놓치는**
방향으로만 틀리므로, "경로 없음"은 과신이 되기 쉽다. ICS 펌웨어는 디스패치
테이블로 짜인 코드가 많아 이 위험이 이론이 아니다 — zlib 한 트리에도 간접 호출
자리가 113곳 있다.

그래서 **도달 불가 + 간접 호출 존재 = `under_investigation`** 이다. 해제하지
않는다. 반대로 도달 **가능** 판정은 간접 호출과 무관하게 유효하다: 실제 경로를
하나 찾았으므로 근사의 불완전성이 결론을 흔들지 않는다. 근사가 한쪽으로만
틀린다는 사실을 판정 규칙이 그대로 반영한 것이다.

Q1 은 이 팔만 할 수 있는 주장이다
---------------------------------
`vulnerable_code_not_present` 는 코드를 봐야 할 수 있는 말이고, 운영맥락 팔은
정의상 그 자격이 없다 (src/oc_vex_judge 의 주석 참조). 소스를 받은 지금은
그 주장을 할 수 있다 — 단, **트리가 제품 전체일 때만**. 사용자가 일부만
올렸다면 "없다"는 "안 올렸다"와 구분되지 않으므로, 트리 완전성을 사용자가
선언하게 하고(`tree_is_complete`) 선언하지 않으면 Q1 을 유보한다.
"""
import source_intake as SI

AFFECTED = "affected"
NOT_AFFECTED = "not_affected"
UNDER_INVESTIGATION = "under_investigation"


def judge(cve, index, entries, vulnerable_functions,
          tree_is_complete=False, component=None):
    """한 CVE에 대한 코드 근거 판정.

    vulnerable_functions : CVE가 지목한 함수 이름들. 비어 있으면 판정 불가 —
        무엇을 찾아야 하는지 모르는 채로 "못 찾았다"고 말할 수는 없다.
    tree_is_complete : 업로드한 트리가 제품 소스 전체라고 사용자가 선언했는지.
    """
    funcs = index["functions"]
    indirect = index.get("indirect_call_sites", 0)

    if not vulnerable_functions:
        return _stmt(cve, UNDER_INVESTIGATION, None,
                     "CVE가 지목하는 취약 함수를 특정하지 못했다. 무엇을 찾을지 "
                     "모르는 상태에서 '없다'고 판정할 수 없다.",
                     {"indirect_call_sites": indirect})

    found = [f for f in vulnerable_functions if f in funcs]

    # ---- Q1: 존재 -----------------------------------------------------------
    if not found:
        if not tree_is_complete:
            return _stmt(cve, UNDER_INVESTIGATION, None,
                         "취약 함수 %s 를 업로드된 트리에서 찾지 못했으나, 트리가 "
                         "제품 전체라는 선언이 없다. '없음'과 '올리지 않음'을 "
                         "구분할 수 없다." % ", ".join(vulnerable_functions),
                         {"searched": vulnerable_functions})
        return _stmt(cve, NOT_AFFECTED, "vulnerable_code_not_present",
                     "취약 함수 %s 가 제품 소스 어디에도 정의되어 있지 않다"
                     % ", ".join(vulnerable_functions),
                     {"searched": vulnerable_functions,
                      "files_indexed": index["files"]})

    # ---- Q2: 죽은 코드 ------------------------------------------------------
    live = []
    for name in found:
        for rec in funcs[name]:
            if not rec["cfg"]["has_dead_code"]:
                live.append((name, rec))
    if not live:
        return _stmt(cve, NOT_AFFECTED, "vulnerable_code_not_in_execute_path",
                     "취약 함수 %s 의 정의가 모두 비활성 전처리 블록(`#if 0` 등) "
                     "안에 있어 빌드에 포함되지 않는다" % ", ".join(found),
                     {"definitions": _locs(funcs, found)})

    # ---- Q3: 도달성 ---------------------------------------------------------
    for name in found:
        r = SI.reaches(index, name, entries)
        if r["reachable"]:
            return _stmt(cve, AFFECTED, None,
                         "진입점에서 취약 함수 %s 까지 호출 경로가 존재한다 (%s)"
                         % (name, " → ".join(r["path"])),
                         {"path": r["path"], "depth": r["depth"],
                          "definitions": _locs(funcs, [name]),
                          "entry_kind": entries_kind(entries)})

    # 경로를 못 찾았다. 여기서 해제할지 유보할지가 이 모듈의 핵심 판단이다.
    if indirect:
        return _stmt(cve, UNDER_INVESTIGATION, None,
                     "구문 기반 호출그래프에서는 경로를 찾지 못했으나, 이 트리에 "
                     "간접 호출 자리가 %d곳 있다. 함수 포인터로 가는 호출은 "
                     "그래프에 나타나지 않으므로 '도달 불가'를 주장할 수 없다."
                     % indirect,
                     {"indirect_call_sites": indirect,
                      "definitions": _locs(funcs, found)})

    return _stmt(cve, NOT_AFFECTED, "vulnerable_code_not_in_execute_path",
                 "취약 함수 %s 는 정의되어 있으나 어떤 진입점에서도 호출 경로가 "
                 "없고, 이 트리에는 간접 호출이 존재하지 않는다"
                 % ", ".join(found),
                 {"definitions": _locs(funcs, found),
                  "indirect_call_sites": 0})


def entries_kind(entries):
    return "main" if any(e in ("main", "wmain", "WinMain", "app_main")
                         for e in entries) else "unreferenced-roots"


def _locs(funcs, names):
    return [{"function": n, "file": r["file"], "line": r["line"],
             "branches": r["cfg"]["branches"]}
            for n in names for r in funcs.get(n, [])]


def _stmt(cve, status, justification, reason, evidence):
    return {"cve": cve, "status": status, "justification": justification,
            "reason": reason, "arm": "source-cfg",
            "evidence_basis": "업로드된 소스의 구문 기반 호출그래프 (근사)",
            "evidence": evidence}


def judge_all(index, entries, targets, tree_is_complete=False):
    """targets : {cve: [function, ...]}  -> 사례별 판정 + 유보율.

    운영맥락 팔과 같은 모양으로 돌려준다 (src/oc_vex_judge.judge_many). 두 팔의
    출력이 같은 형태여야 docs/ICSVEX.md §8 의 Precision 을 한 함수로 잴 수 있다.
    """
    out = [judge(cve, index, entries, fns, tree_is_complete)
           for cve, fns in targets.items()]
    counts = {}
    for s in out:
        counts[s["status"]] = counts.get(s["status"], 0) + 1
    n = len(out)
    deferred = counts.get(UNDER_INVESTIGATION, 0)
    return {"statements": out, "total": n, "by_status": counts,
            "deferred": deferred,
            "deferral_rate": round(deferred / n, 4) if n else None,
            "decision_rate": round((n - deferred) / n, 4) if n else None}


if __name__ == "__main__":
    import io, sys, json
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    if len(sys.argv) < 2:
        print("usage: cfg_vex.py <source-dir> [function ...]")
        raise SystemExit(2)
    idx = SI.index_tree(sys.argv[1])
    ep = SI.entry_points(idx)
    fns = sys.argv[2:] or ["deflate_stored"]
    r = judge("CVE-DEMO", idx, ep["entries"], fns, tree_is_complete=True)
    print(json.dumps(r, ensure_ascii=False, indent=2))
