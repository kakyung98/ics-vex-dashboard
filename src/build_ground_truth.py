#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ground Truth 구축 (v2, 현실적 난이도):

(device, CVE) findings -> 배치 맥락 결합 -> 3-class VEX silver label.

라벨 오라클(진짜 신호): CISA CVSS Attack Vector, KEV, EPSS, 심각도.
배치 맥락(결정적 합성): network-exposure(장비별), 음성증거 플래그.

현실적 난이도 장치:
  - Attack Vector 를 명시하지 않고 공격 표면 산문으로 암시 -> 모델이 추론
  - 문장별 패러프레이즈 풀(해시 선택) -> 어휘 암기 차단, 의미 이해 요구
  - 모호성 꼬리(~12%): 판정 근거가 불충분하게 서술된 케이스 -> UNDER_INVESTIGATION
                        (라벨과 텍스트가 함께 모호해지는 진짜 어려운 샘플)

오라클(보수적): LIKELY_NOT_AFFECTED 는 적극적 반증에서만.

출력: data/vex_dataset.jsonl
"""
import csv
import hashlib
import json
import os
import sys

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
FIND = os.path.join(BASE, "data", "findings.csv")
OUT = os.path.join(BASE, "data", "vex_dataset.jsonl")

EXPOSURES = ["isolated-cell", "control-network", "dmz-routable", "remote-accessible"]
EXP_TIER = {e: i for i, e in enumerate(EXPOSURES)}

# 노출도 패러프레이즈 풀 (의미 동일, 표현 다양)
EXP_POOL = {
    "isolated-cell": [
        "The asset sits in an air-gapped cell with no routable link to other networks.",
        "This equipment is fully segmented; nothing outside the local cabinet can address it.",
        "Deployed standalone behind a hard network break, unreachable from any routed segment.",
        "The unit operates islanded, with no IP path in from plant or enterprise networks.",
    ],
    "control-network": [
        "It resides on the OT control LAN, addressable only by peers already inside that segment.",
        "Reachable strictly from within the process control network, not from outside it.",
        "The device answers only to hosts that already have a foothold on the control network.",
        "Confined to the supervisory control subnet with no direct external routing.",
    ],
    "dmz-routable": [
        "The device is reachable across the industrial DMZ from the enterprise boundary.",
        "Routed paths reach this unit from the corporate edge through the OT DMZ.",
        "Exposed via the plant DMZ, so enterprise-side hosts can open sessions to it.",
        "Sessions can be initiated from the business network through the DMZ to this device.",
    ],
    "remote-accessible": [
        "The unit is reachable remotely, including through vendor remote-support tunnels.",
        "Remote operators and third-party maintenance links can reach this device directly.",
        "Internet-adjacent management paths expose this equipment to remote sessions.",
        "The device accepts connections from remote and enterprise-wide origins.",
    ],
}
# 공격 표면 산문 (AV 를 명시하지 않고 암시)
AV_POOL = {
    "N": [
        "A remote actor can trigger the flaw by sending crafted traffic to a listening service.",
        "The weakness is driven through network messages accepted by an exposed interface.",
        "Exploitation proceeds over the wire against a service the device publishes.",
        "Malformed protocol input from across the network reaches the vulnerable routine.",
    ],
    "A": [
        "An attacker sharing the local link layer can steer the device into the fault.",
        "Triggering it requires a foothold on the same broadcast segment as the target.",
        "The path opens only to an adjacent station on the same physical network.",
        "It is reachable from a neighbor on the local segment, not from routed distance.",
    ],
    "L": [
        "Reaching the flaw first requires an authenticated session or shell on the device.",
        "The issue is driven by an already-logged-in local user, not from the network.",
        "Prior local access to the unit is a precondition for triggering it.",
        "Only a party with an existing account on the device can exercise the path.",
    ],
    "P": [
        "The fault can only be reached by someone with hands-on physical access.",
        "Triggering requires direct physical manipulation of the hardware.",
        "The path opens solely at the console or physical ports of the device.",
        "Exploitation demands bodily access to the equipment itself.",
    ],
    "": [
        "The precise conditions needed to reach the flaw are not clearly documented.",
        "How an attacker would drive this weakness is not spelled out in the source material.",
    ],
}
KEV_POOL = [
    "This weakness is being exploited in live campaigns right now.",
    "It appears on the catalog of vulnerabilities known to be exploited in the wild.",
    "Threat actors are actively leveraging this issue against deployed systems.",
]
KEVNEG_POOL = [
    "No confirmed in-the-wild exploitation has been reported to date.",
    "There is no evidence yet that this issue is being used in real attacks.",
    "Active exploitation of this weakness has not been observed.",
]
PRESENT_POOL = [
    "The affected component ships in the running firmware build.",
    "This build includes the vulnerable module in its active image.",
    "The impacted software is compiled into the deployed firmware.",
]
ABSENT_POOL = [
    "The affected component is not part of this firmware build at all.",
    "This image was built without the vulnerable module compiled in.",
    "The impacted software is excluded from the deployed configuration.",
]
INRANGE_POOL = [
    "The installed release falls inside the versions flagged as affected.",
    "The running version matches the vulnerable version window.",
    "The deployed build number lies within the affected range.",
]
OUTRANGE_POOL = [
    "The installed release sits outside the affected version window.",
    "The running version is newer than any build flagged vulnerable.",
    "The deployed build number falls past the affected range.",
]
PATCHED_POOL = [
    "The vendor fix addressing this issue has already been rolled out here.",
    "The corrective update for this weakness is installed on the device.",
    "A supplier patch closing this flaw has been applied.",
]
DISABLED_POOL = [
    "The feature that carries the flaw is switched off in this configuration.",
    "The vulnerable function is not enabled on this deployment.",
    "Configuration on this unit disables the affected capability.",
]
VAGUE_POOL = [
    "Network reachability of this device in the current plant layout is not documented.",
    "The deployment context for this asset is only partially recorded.",
    "It is unclear from the available records how this unit is exposed.",
    "The prerequisites an attacker would need here are not established in the evidence.",
]
CWE_NAME = {
    "CWE-78": "OS command injection", "CWE-79": "cross-site scripting", "CWE-89": "SQL injection",
    "CWE-119": "memory buffer error", "CWE-120": "buffer copy without size check",
    "CWE-121": "stack-based buffer overflow", "CWE-122": "heap-based buffer overflow",
    "CWE-125": "out-of-bounds read", "CWE-190": "integer overflow", "CWE-200": "information exposure",
    "CWE-269": "improper privilege management", "CWE-287": "improper authentication",
    "CWE-295": "improper certificate validation", "CWE-306": "missing authentication",
    "CWE-311": "missing encryption", "CWE-327": "broken crypto algorithm",
    "CWE-352": "cross-site request forgery", "CWE-362": "race condition",
    "CWE-400": "uncontrolled resource consumption", "CWE-401": "memory leak",
    "CWE-416": "use after free", "CWE-434": "unrestricted file upload",
    "CWE-476": "null pointer dereference", "CWE-502": "deserialization of untrusted data",
    "CWE-787": "out-of-bounds write", "CWE-798": "hard-coded credentials",
    "CWE-862": "missing authorization", "CWE-863": "incorrect authorization",
}


def h(*p):
    return int(hashlib.sha256("::".join(map(str, p)).encode()).hexdigest(), 16)


def pick(pool, *seed):
    return pool[h(*seed) % len(pool)]


def exposure_for(device):
    d = device.lower()
    if any(k in d for k in ("plc", "rtu", "relay", "controller", "safety", "ied", "drive")):
        w = [0.42, 0.34, 0.16, 0.08]
    elif any(k in d for k in ("gateway", "firewall", "router", "switch", "vpn", "remote")):
        w = [0.05, 0.20, 0.40, 0.35]
    elif any(k in d for k in ("scada", "hmi", "historian", "server", "workstation", "engineering")):
        w = [0.10, 0.34, 0.34, 0.22]
    else:
        w = [0.25, 0.30, 0.28, 0.17]
    r = (h("exp", device) % 1000) / 1000.0
    acc = 0.0
    for e, wi in zip(EXPOSURES, w):
        acc += wi
        if r <= acc:
            return e
    return EXPOSURES[-1]


def reachability(av, exposure):
    t = EXP_TIER[exposure]
    if av == "N":
        return "no" if t == 0 else ("conditional" if t == 1 else "yes")
    if av == "A":
        return "no" if t == 0 else ("conditional" if t <= 2 else "yes")
    if av == "L":
        return "conditional"
    if av == "P":
        return "no"
    return "conditional"


def neg_evidence(device, cve):
    r = h("neg", device, cve) % 100
    if r < 6:
        return "patched"
    if r < 11:
        return "version-out-of-range"
    if r < 15:
        return "component-absent"
    if r < 18:
        return "function-disabled"
    return None


def oracle(av, exposure, kev, epss, sev, neg):
    reach = reachability(av, exposure)
    if neg:
        reason = {"patched": "vendor patch applied",
                  "version-out-of-range": "installed version outside affected range",
                  "component-absent": "affected component not present",
                  "function-disabled": "vulnerable function disabled"}[neg]
        return "LIKELY_NOT_AFFECTED", reason, reach
    if reach == "no":
        return "LIKELY_NOT_AFFECTED", ("requires physical access" if av == "P"
                                       else "attack path not reachable in deployment"), reach
    if reach == "yes":
        return "LIKELY_AFFECTED", ("component present and reachable"
                                   + ("; exploited in the wild" if kev else "")), reach
    return "UNDER_INVESTIGATION", "reachability not determinable from available evidence", reach


DRIVER_KINDS = {"av", "kev", "exposure", "neg_absent", "neg_version", "neg_patched", "neg_disabled", "vague"}

ADJ = {"LIKELY_AFFECTED": "UNDER_INVESTIGATION",
       "LIKELY_NOT_AFFECTED": "UNDER_INVESTIGATION"}


def annotator_noise(label, device, cve, reach, sev, epss):
    """사람 주석자 불일치(κ≈0.85) 시뮬레이션. 경계 사례에 집중.
    안전하지 않은 AFFECTED<->NOT_AFFECTED 직접 전이는 만들지 않는다."""
    boundary = (reach == "conditional" or sev == "medium"
                or (epss is not None and 0.3 <= epss <= 0.6))
    p = 0.16 if boundary else 0.04
    if (h("noise", device, cve) % 1000) / 1000.0 >= p:
        return label
    if label == "UNDER_INVESTIGATION":
        # 모호 -> 주석자가 한쪽으로 판단 (AFFECTED/NOT 를 해시로)
        return "LIKELY_AFFECTED" if (h("nd", device, cve) % 2) else "LIKELY_NOT_AFFECTED"
    return ADJ.get(label, label)


def render(device, vendor, product, cve, cwe, av, sev, epss, kev, exposure, neg, vague):
    S = []

    def add(txt, kind, eid):
        S.append({"id": eid, "text": txt, "kind": kind})

    cwe_name = CWE_NAME.get(cwe, (cwe or "an unspecified weakness"))
    sevw = {"critical": "critical-severity", "high": "high-severity",
            "medium": "moderate-severity", "low": "low-severity"}.get(sev, "unrated")
    add("%s is a %s %s issue (%s)." % (cve, sevw, cwe_name, cwe or "CWE-unknown"), "cve_desc", "CVE-1")
    # 공격 표면(AV 암시) — vague 이면 모호 문장으로 대체
    if vague:
        add(pick(VAGUE_POOL, "vg", device, cve), "vague", "CVE-2")
    else:
        add(pick(AV_POOL.get(av, AV_POOL[""]), "av", device, cve), "av", "CVE-2")
    add(pick(KEV_POOL if kev else KEVNEG_POOL, "kev", device, cve), "kev" if kev else "kev_neg", "CVE-3")
    if epss is not None:
        add("Statistical models put its near-term exploitation likelihood around %.2f." % epss, "epss", "CVE-4")

    add("Asset: %s %s." % (vendor, product), "product", "ASSET-1")
    add(pick(EXP_POOL[exposure], "exp", device), "exposure", "ASSET-2")
    add(pick(ABSENT_POOL if neg == "component-absent" else PRESENT_POOL, "pres", device, cve),
        "neg_absent" if neg == "component-absent" else "present", "ASSET-3")
    add(pick(OUTRANGE_POOL if neg == "version-out-of-range" else INRANGE_POOL, "ver", device, cve),
        "neg_version" if neg == "version-out-of-range" else "in_range", "ASSET-4")
    if neg == "patched":
        add(pick(PATCHED_POOL, "pat", device, cve), "neg_patched", "ASSET-5")
    if neg == "function-disabled":
        add(pick(DISABLED_POOL, "dis", device, cve), "neg_disabled", "ASSET-6")
    return S


def main():
    rows = list(csv.DictReader(open(FIND, encoding="utf-8-sig")))
    n = 0
    labels = {}
    with open(OUT, "w", encoding="utf-8") as out:
        for r in rows:
            device, vendor, product = r["device"], r["vendor"], r["product"]
            cve, cwe = r["cve"], r["cwe"]
            av = r["av"]
            sev = r["severity"]
            kev = r["kev"] == "True"
            epss = float(r["epss"]) if r["epss"] not in ("", None) else None
            exposure = exposure_for(device)
            neg = neg_evidence(device, cve)
            # 모호성 꼬리 ~12% (음성증거·KEV 가 없는 경우에 한해 진짜 모호하게)
            vague = (not neg and not kev and (h("vague", device, cve) % 100) < 14)
            if vague:
                label, reason, reach = "UNDER_INVESTIGATION", "evidence too vague to adjudicate", "unknown"
                av_used = ""
            else:
                av_used = av
                label, reason, reach = oracle(av, exposure, kev, epss, sev, neg)
            sents = render(device, vendor, product, cve, cwe, av_used, sev, epss, kev, exposure, neg, vague)
            gold = [s["id"] for s in sents if s["kind"] in DRIVER_KINDS]
            clean_label = label
            label = annotator_noise(label, device, cve, reach, sev, epss)
            rec = {
                "sampleId": "S%06d" % n, "device": device, "cve": cve, "arm": r["arm"], "tier": r["tier"],
                "label": label, "clean_label": clean_label, "oracle_reason": reason,
                "sentences": sents, "gold_rationale_ids": gold,
                "structured": {"av": av, "exposure": exposure, "reach": reach, "kev": kev,
                               "epss": epss, "severity": sev, "neg": neg or "", "vague": vague},
            }
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            labels[label] = labels.get(label, 0) + 1
            n += 1
    print("samples: %d" % n)
    for k in ("LIKELY_AFFECTED", "LIKELY_NOT_AFFECTED", "UNDER_INVESTIGATION"):
        print("  %-22s %6d (%.1f%%)" % (k, labels.get(k, 0), 100 * labels.get(k, 0) / n))
    print("output: %s" % OUT)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
