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
            "q": "Is the component within the CVE's affected range?",
            "no": [NOT_AFFECTED, "code_not_reachable"],
            "yes": "source_check",
        },
        "source_check": {
            "q": "Can the vulnerable source code be obtained?",
            "yes": [ROUTE, "Switch to the ICS-VEXForge (code-based) methodology"],
            "no": "av_split",
        },
        "av_split": {
            "q": "CVE attack vector (CVSS AV)",
            "branch": {"network": "net_reach", "local": "loc_priv", "physical": "phy_access"},
        },
        # --- Network access (AV: N, A) ---
        "net_reach": {
            "q": "Reachability: is the service reachable via an observed exposure path?",
            "no": [NOT_AFFECTED, "protected_at_perimeter"],
            "yes": "net_exec",
        },
        "net_exec": {
            "q": "Execution active: is the service running the vulnerable code active?",
            "no": [NOT_AFFECTED, "code_not_reachable"],
            "yes": "net_mit",
        },
        "net_mit": {
            "q": "Mitigating control: is the path blocked? (segmentation, firewall, auth)",
            "no": [NOT_AFFECTED, "protected_by_mitigating_control"],
            "yes": "net_impact",
        },
        "net_impact": {
            "q": "High-impact asset? (safety function / process impact)",
            "no": [UNDER_INV, "likely_affected_medium"],
            "yes": [UNDER_INV, "likely_affected_high"],
        },
        # --- Local access (AV: L) ---
        "loc_priv": {
            "q": "Privilege/interaction: can local access and the required privilege be obtained?",
            "no": [NOT_AFFECTED, "requires_environment"],
            "yes": "loc_exec",
        },
        "loc_exec": {
            "q": "Execution active: is the vulnerable code path active?",
            "no": [NOT_AFFECTED, "code_not_reachable"],
            "yes": "loc_mit",
        },
        "loc_mit": {
            "q": "Mitigating control: account/interaction controls? (least privilege, signing)",
            "no": [NOT_AFFECTED, "protected_by_mitigating_control"],
            "yes": "loc_impact",
        },
        "loc_impact": {
            "q": "High-impact asset? (safety function / process impact)",
            "no": [UNDER_INV, "likely_affected_medium"],
            "yes": [UNDER_INV, "likely_affected_high"],
        },
        # --- Physical access (AV: P) ---
        "phy_access": {
            "q": "Physical access control: are ports/media blocked?",
            "no": [NOT_AFFECTED, "protected_at_perimeter"],
            "yes": "phy_config",
        },
        "phy_config": {
            "q": "Configuration: are removable media / maintenance ports enabled?",
            "no": [NOT_AFFECTED, "requires_configuration"],
            "yes": "phy_impact",
        },
        "phy_impact": {
            "q": "High-impact asset? (safety function / process impact)",
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
