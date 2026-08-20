#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VEX decision tree for source-code-UNCOLLECTABLE CVEs (closed firmware).

Faithful encoding of the operational decision tree: when a CVE's affected range
applies but the vulnerable source cannot be obtained, VEX is decided from the
deployment's operational context (exposure, host/network) rather than code. The
branch is chosen by the CVSS Attack Vector; each node is answered yes/no from
collected context. Terminals are (VEX status, justification / confidence label).

Shared TREE structure so the Python endpoint and the JS walker stay identical.
`classify(av, answers)` walks the tree and returns the verdict + the path taken.
"""

NOT_AFFECTED = "not_affected"
UNDER_INV = "under_investigation"
ROUTE = "route_to_icsvexforge"   # source obtainable -> code-available methodology

# node: {"q": question, "no": target, "yes": target}
#   target = next node id (str) | terminal [status, label]
# av_split uses "branch": {network|local|physical: node_id}
TREE = {
    "start": "affected_range",
    "nodes": {
        "affected_range": {
            "q": "CVE 영향 범위 포함 여부",
            "no": [NOT_AFFECTED, "code_not_reachable"],
            "yes": "source_check",
        },
        "source_check": {
            "q": "소스코드 확보 가능 여부",
            "yes": [ROUTE, "ICS-VEXForge 방법론으로 전환"],
            "no": "av_split",
        },
        "av_split": {
            "q": "CVE 공격 벡터 (CVSS AV)",
            "branch": {"network": "net_reach", "local": "loc_priv", "physical": "phy_access"},
        },
        # --- 네트워크 접근 (AV: N, A) ---
        "net_reach": {
            "q": "도달성: 관측된 노출 경로로 서비스 도달 가능 여부",
            "no": [NOT_AFFECTED, "protected_at_perimeter"],
            "yes": "net_exec",
        },
        "net_exec": {
            "q": "실행 활성: 취약 코드가 실행되는 서비스 도달 활성 여부",
            "no": [NOT_AFFECTED, "code_not_reachable"],
            "yes": "net_mit",
        },
        "net_mit": {
            "q": "완화 통제 여부: 경로 차단 여부 (세그멘테이션 방화벽·인증 등)",
            "no": [NOT_AFFECTED, "protected_by_mitigating_control"],
            "yes": "net_impact",
        },
        "net_impact": {
            "q": "고영향 자산 여부 (안전기능·공정 영향)",
            "no": [UNDER_INV, "likely_affected_medium"],
            "yes": [UNDER_INV, "likely_affected_high"],
        },
        # --- 로컬 접근 (AV: L) ---
        "loc_priv": {
            "q": "권한-상호작용: 로컬 접근·필요 권한 확보 가능 여부",
            "no": [NOT_AFFECTED, "requires_environment"],
            "yes": "loc_exec",
        },
        "loc_exec": {
            "q": "실행 활성: 취약 코드 경로 활성 여부",
            "no": [NOT_AFFECTED, "code_not_reachable"],
            "yes": "loc_mit",
        },
        "loc_mit": {
            "q": "완화 통제: 계정·상호작용 통제 여부 (최소권한·서명)",
            "no": [NOT_AFFECTED, "protected_by_mitigating_control"],
            "yes": "loc_impact",
        },
        "loc_impact": {
            "q": "고영향 자산 여부 (안전기능·공정 영향)",
            "no": [UNDER_INV, "likely_affected_medium"],
            "yes": [UNDER_INV, "likely_affected_high"],
        },
        # --- 물리적 접근 (AV: P) ---
        "phy_access": {
            "q": "물리 접근 통제: 포트·매체 접근 차단 여부",
            "no": [NOT_AFFECTED, "protected_at_perimeter"],
            "yes": "phy_config",
        },
        "phy_config": {
            "q": "구성: 탈착 매체·유지보수 포트 활성 구성 여부",
            "no": [NOT_AFFECTED, "requires_configuration"],
            "yes": "phy_impact",
        },
        "phy_impact": {
            "q": "고영향 자산 여부 (안전기능·공정 영향)",
            "no": [UNDER_INV, "likely_affected_medium"],
            "yes": [UNDER_INV, "likely_affected_high"],
        },
    },
}


def av_branch(av):
    """CVSS Attack Vector -> tree branch. N/A = network, L = local, P = physical."""
    a = (av or "").upper()
    if a in ("N", "A"):
        return "network"
    if a == "L":
        return "local"
    if a == "P":
        return "physical"
    return None


def classify(av, answers):
    """Walk the tree.
    answers: {node_id: True/False} (True = 예/yes, False = 아니오/no) for decision nodes.
    Returns {status, justification, path:[{node,q,answer}], av_branch, complete}.
    Stops (complete=False) at the first decision node with no answer supplied.
    """
    nodes = TREE["nodes"]
    nid = TREE["start"]
    path = []
    while True:
        node = nodes[nid]
        if nid == "av_split":
            br = av_branch(av)
            path.append({"node": nid, "q": node["q"], "answer": br})
            if not br:
                return {"status": UNDER_INV, "justification": "attack_vector_unstated",
                        "path": path, "av_branch": None, "complete": False}
            nid = node["branch"][br]
            continue
        ans = answers.get(nid)
        if ans is None:
            return {"status": None, "justification": None, "path": path,
                    "av_branch": av_branch(av), "complete": False, "pending": nid,
                    "question": node["q"]}
        path.append({"node": nid, "q": node["q"], "answer": bool(ans)})
        target = node["yes"] if ans else node["no"]
        if isinstance(target, list):       # terminal
            return {"status": target[0], "justification": target[1], "path": path,
                    "av_branch": av_branch(av), "complete": True}
        nid = target


if __name__ == "__main__":
    # smoke: AV:N, reachable, active, not blocked, high-impact -> likely_affected_high
    r = classify("N", {"affected_range": True, "source_check": False, "net_reach": True,
                       "net_exec": True, "net_mit": True, "net_impact": True})
    print(r["status"], r["justification"], "| path:", [p["node"] for p in r["path"]])
