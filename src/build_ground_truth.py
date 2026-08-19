#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ground Truth 구축 (v3, 증거 계층 기반):

핵심 원칙 — 판정은 확보한 증거의 강도를 넘어서지 않는다.

  증거 계층(evidence tier)은 findings.csv 의 `tier` 컬럼에서 온다.
  이 컬럼은 build_reverse_sbom.py 가 SBOM 속성 `component:source-availability`
  로 기록한 값이며, 소스코드 확보 가능성을 그대로 나타낸다.

    tier A  소스 확보됨(OSS, vuln/patched 코드 쌍 보유)
              -> 실행 검증 결과가 있으면  AFFECTED / NOT_AFFECTED 확정
              -> 없으면 UNDER_INVESTIGATION (실행 검증 대기)
    tier C  OSS 컴포넌트이나 코드 미확보   -> UNDER_INVESTIGATION
    tier E  벤더 폐쇄 펌웨어, 소스 확보 불가 -> UNDER_INVESTIGATION

  즉 1차 상태(vex_status)는 소스코드를 확보하고 실행 검증에 성공한 건에서만
  확정되고, 나머지는 전부 UNDER_INVESTIGATION 이다.

모델 라우팅(route) — 소스 확보 여부가 파이프라인 경로를 정한다:

    tier A       SecureBERT -> CodeBERT -> sLLM/실행 검증
                 대조할 코드가 있으므로 코드 leg 로 넘겨 확정을 시도한다.
    tier C / E   SecureBERT 에서 종결.
                 대조할 코드가 없으므로 CodeBERT 로 넘기지 않는다.
                 (코드 없이 돌린 CodeBERT 출력은 근거가 없어 오탐만 만든다)

2차 VEX 추정(estimated_status):
  1차가 UNDER_INVESTIGATION 인 건에 대해, 확보 가능한 유일한 신호인
  CVSS Attack Vector 와 배치 노출도로 도달성을 계산해 상태를 '추정'한다.
  이는 VEX 진술이 아니라 추정치이며 estimate_confidence 를 함께 싣는다.
  모델 학습 타깃(`label`)은 확정값이 있으면 확정값, 없으면 이 추정치다.

판정 사유(justification):
  CSAF VEX / OpenVEX 의 not_affected justification 5종 통제 어휘를 사용한다.
    component_not_present
    vulnerable_code_not_present
    vulnerable_code_not_in_execute_path
    vulnerable_code_cannot_be_controlled_by_adversary
    inline_mitigations_already_exist
  affected 에 대해서는 표준이 justification 어휘를 정의하지 않으므로
  (표준 필드는 impact_statement / action_statement),
  위 5종을 그대로 뒤집은 대응 어휘를 별도 확장으로 부여하고
  표준 필드도 함께 채운다. justification_vocabulary 필드로 구분한다.

v2 대비 제거된 것 — 근거 없이 합성하던 요소:
  - neg_evidence(): 해시로 patched/component-absent/version-out-of-range/
    function-disabled 를 지어내던 로직. 실제 증거가 없으므로 삭제.
  - 해시 기반 vague 꼬리: AV 가 실제로 미기재인 건(av=="")으로 대체.
  - 주석자 노이즈: 실행 검증으로 확정된 건에는 적용하지 않고,
    추정치에만 적용한다(분석가는 사실이 아니라 추정에서 갈린다).

여전히 합성인 것(명시):
  - exposure: 배치 노출도. 실제 플랜트 네트워크 정보는 공개 데이터에 없다.
    structured.exposure_synthetic = true 로 표시한다.

출력: data/vex_dataset.jsonl
"""
import csv
import hashlib
import json
import os
import sys

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
FIND = os.path.join(BASE, "data", "findings.csv")
CODE_EV = os.path.join(BASE, "data", "code_evidence.json")
EXEC_PY = os.path.join(BASE, "results", "exec_verification.json")
EXEC_C = os.path.join(BASE, "results", "exec_verification_c.json")
EXEC_BATCH = os.path.join(BASE, "results", "exec_verification_batch.json")
OUT = os.path.join(BASE, "data", "vex_dataset.jsonl")
# 코드 leg 전용 서브셋 (OSS 귀속 = tier A/C 중 tier A). 실제 코드 보유 여부는
# 각 레코드의 code_evidence_available 로 구분한다.
OUT_CODE = os.path.join(BASE, "data", "vex_dataset_code.jsonl")
# 실행 검증으로 확정된 건만 (진짜 ground truth)
OUT_GT = os.path.join(BASE, "data", "vex_ground_truth.jsonl")

AFFECTED = "LIKELY_AFFECTED"
NOT_AFFECTED = "LIKELY_NOT_AFFECTED"
UNDER_INV = "UNDER_INVESTIGATION"

# findings.csv 의 tier. SBOM 속성명은 component:source-availability 이지만 실제 의미는
# "OSS 카탈로그에 CVE 가 귀속되었는가"다(build_reverse_sbom.py:202). 코드 실보유와 다르다.
TIER_DESC = {"A": "oss-attributed", "C": "oss-inferred", "E": "vendor-proprietary"}

# 모델 라우팅 — 소스 확보 여부가 파이프라인 경로를 결정한다.
#   소스 있음(tier A)  : SecureBERT -> CodeBERT -> sLLM/실행 검증 (확정 가능)
#   소스 없음(tier C/E): SecureBERT 에서 종결. 코드 leg 로 넘기지 않는다.
#                        (대조할 코드가 없어 CodeBERT 는 근거 없는 출력을 낼 뿐)
ROUTE_CODE = "securebert->codebert->sllm"
ROUTE_CONTEXT_ONLY = "securebert-only"
# 2026-08 정적 개편: 라이브 판정 파이프라인(src/vex_pipeline.py)은 PoC 생성·실행을
# 전혀 하지 않고 정적분석(sLLM static analyst + grounding critic)으로만 VEX 를 확정한다.
# 아래 sllm-static-analyst 라벨이 그 경로다. 과거 execution-verified 5건은
# results/exec_verification*.json 실측을 근거로 역사적 확정 계층으로만 유지된다.
ROUTE_STAGES = {
    ROUTE_CODE: ["securebert", "codebert", "sllm-static-analyst"],
    ROUTE_CONTEXT_ONLY: ["securebert"],
}

# CSAF VEX / OpenVEX not_affected justification 통제 어휘 (5종)
JUSTIFY_NOT_AFFECTED = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}
# affected 대응 어휘 (표준 확장 — 위 5종의 역대응)
JUSTIFY_AFFECTED = {
    "component_present",
    "vulnerable_code_present",
    "vulnerable_code_in_execute_path",
    "vulnerable_code_controllable_by_adversary",
    "no_inline_mitigations",
}

EXPOSURES = ["isolated-cell", "control-network", "dmz-routable", "remote-accessible"]
EXP_TIER = {e: i for i, e in enumerate(EXPOSURES)}

# AV=P(물리 접근)를 도달 불가로 볼지 여부.
# 무인 변전소·원격 펌프장 등에서는 물리 접근이 현실적 위협이므로
# 표준 VEX 는 이를 자동으로 not_affected 로 인정하지 않는다.
# False 로 두면 AV=P 는 확정 대신 UNDER_INVESTIGATION 으로 남는다.
TREAT_PHYSICAL_AS_UNREACHABLE = True

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
        "The advisory does not state how an attacker would reach this weakness.",
        "No attack-surface description accompanies this entry in the source advisory.",
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
# SBOM 이 컴포넌트 버전을 NOASSERTION 으로 기록한 사실 (실제 데이터 특성)
VERSION_UNKNOWN_POOL = [
    "The inventory records no version for this component, so the affected range cannot be checked.",
    "No version string is asserted for this module in the bill of materials.",
    "The build inventory leaves this component's release unspecified.",
    "Version information for the module is absent from the recorded inventory.",
]
# 소스 확보 불가 (tier E — 벤더 폐쇄 펌웨어)
SRC_UNAVAIL_POOL = [
    "The vendor ships this module as closed firmware, so its source cannot be obtained for inspection.",
    "No source is retrievable for this proprietary component; only the binary image is distributed.",
    "This part of the stack is vendor-proprietary and its code is unavailable for review.",
    "The supplier does not publish source for this module, blocking any code-level check.",
]
# OSS 이나 코드 미확보 (tier C)
SRC_PENDING_POOL = [
    "The component is open source, but no vulnerable or fixed code has been retrieved for it yet.",
    "Upstream code exists for this module, though none has been collected for comparison here.",
    "This is an open component, yet the relevant patch material has not been gathered.",
    "Source is in principle obtainable for this module, but nothing has been pulled down so far.",
]
# 코드 확보, 실행 검증 대기 (tier A, 미검증)
SRC_AVAIL_POOL = [
    "Vulnerable and fixed source for this module has been obtained, but it has not been executed.",
    "Both the flawed and corrected code are on hand; no run-time trigger has been attempted.",
    "The relevant source pair is available, awaiting an execution test to settle the question.",
    "Code for both states of this module is collected, with dynamic confirmation still outstanding.",
]
# 실행 검증 결과
EXEC_AFF_POOL = [
    "Running the recorded trigger against this build reproduced the fault under a sanitizer.",
    "A controlled execution of the module drove it into the documented failure state.",
    "The flaw was reproduced by executing the collected trigger against this code.",
    "Dynamic testing of the module produced the expected crash signature.",
]
EXEC_NOT_POOL = [
    "Executing the same trigger against this build produced no fault, unlike the flawed release.",
    "The corrected code withstood the recorded trigger without entering the failure state.",
    "A run against this build failed to reproduce the fault that the flawed release exhibits.",
    "Dynamic testing showed the vulnerable path is no longer reachable in this code.",
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


# ---------------------------------------------------------------- 증거 로딩

def load_exec_verification():
    """실행 검증 결과를 CVE -> 판정 맵으로 정규화.

    두 harness 를 모두 읽는다:
      results/exec_verification.json    (Python 라이브러리, pip 격리설치)
      results/exec_verification_c.json  (C 라이브러리, WSL + AddressSanitizer)

    새 CVE 가 검증되면 이 파일에 추가되는 것만으로 해당 findings 가
    자동으로 확정 계층으로 승격된다. 코드 수정 불필요.
    """
    out = {}
    # 배치 러너(src/exec_verify_batch.py) 결과. 확정 판정이 난 건만 취한다 —
    # NEEDS_TRIGGER / BUILD_FAILED 등은 증거가 아니라 작업 상태이므로 제외.
    if os.path.exists(EXEC_BATCH):
        for e in json.load(open(EXEC_BATCH, encoding="utf-8")):
            if e.get("verdict") not in ("EXPLOITABLE", "NOT_TRIGGERED"):
                continue
            out[e["cve"]] = {
                "exploitable": bool(e.get("vuln_crash")),
                "discriminates": bool(e.get("vuln_crash")) and not e.get("patched_crash"),
                "vuln_version": e.get("vuln_version"), "patched_version": e.get("patched_version"),
                "component": e.get("component", ""),
                "signal": e.get("signal", ""),
                "method": e.get("method", "build vuln vs patched, execute trigger"),
            }
    if os.path.exists(EXEC_PY):
        for e in json.load(open(EXEC_PY, encoding="utf-8")):
            vuln_v = patched_v = None
            exploitable = False
            for v in e.get("versions", []):
                if v.get("triggered"):
                    vuln_v = v.get("version")
                    exploitable = True
                else:
                    patched_v = v.get("version")
            out[e["cve"]] = {
                "exploitable": exploitable,
                "discriminates": bool(e.get("discriminates")),
                "vuln_version": vuln_v, "patched_version": patched_v,
                "component": e.get("package", ""),
                "signal": "; ".join(sorted({s for v in e.get("versions", [])
                                            for s in v.get("evidence", [])})),
                "method": "isolated pip install + subprocess execution",
            }
    if os.path.exists(EXEC_C):
        for e in json.load(open(EXEC_C, encoding="utf-8")):
            out[e["cve"]] = {
                "exploitable": bool(e.get("vuln_crash")),
                "discriminates": bool(e.get("vuln_crash")) and not e.get("patched_crash"),
                "vuln_version": e.get("vuln_version"), "patched_version": e.get("patched_version"),
                "component": e.get("component", ""),
                "signal": e.get("signal", ""),
                "method": e.get("method", "build vuln vs patched, execute trigger"),
            }
    return out


def load_code_available():
    """vuln/patched 코드 쌍을 실제로 확보한 CVE 집합."""
    if not os.path.exists(CODE_EV):
        return set()
    ce = json.load(open(CODE_EV, encoding="utf-8"))
    return {k for k, v in ce.items()
            if isinstance(v, dict) and v.get("vuln_code") and v.get("patched_code")}


# ---------------------------------------------------------- 배치 맥락(합성)

def exposure_for(device):
    """배치 노출도. 실제 플랜트 네트워크 정보가 공개 데이터에 없어 합성한다.
    장비 종류별 사전분포에서 (device 해시로) 결정론적 표집."""
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
    """CVSS Attack Vector x 배치 노출도 -> 공격자 도달 가능성."""
    if not av:
        return "unknown"
    t = EXP_TIER[exposure]
    if av == "N":
        return "no" if t == 0 else ("conditional" if t == 1 else "yes")
    if av == "A":
        return "no" if t == 0 else ("conditional" if t <= 2 else "yes")
    if av == "L":
        return "conditional"
    if av == "P":
        return "no" if TREAT_PHYSICAL_AS_UNREACHABLE else "conditional"
    return "conditional"


# ------------------------------------------------------ 1차 판정 (증거 기반)

def adjudicate(tier, has_code, exec_rec, version_asserted):
    """확보한 증거만으로 내리는 1차 VEX 상태.

    주의 — findings.csv 의 `tier` 는 SBOM 속성명이 component:source-availability 이지만,
    실제로는 "OSS 카탈로그에 CVE 가 귀속되었는가"만 나타낸다(build_reverse_sbom.py:202).
    tier=="A" 132 CVE 중 실제로 vuln/patched 코드 쌍을 확보한 것은 15 CVE 뿐이다.
    따라서 코드 leg 진입 여부는 tier 가 아니라 `has_code`(code_evidence.json 실보유)로 판정한다.

    반환: (status, justification, justification_vocabulary,
           impact_statement, action_statement, evidence_tier, detail)
    """
    # --- 계층 1: 실행 검증 완료 --------------------------------------------
    if exec_rec and exec_rec["discriminates"]:
        sig = exec_rec["signal"] or "documented failure state"
        if version_asserted and version_asserted == exec_rec.get("patched_version"):
            return (NOT_AFFECTED, "vulnerable_code_not_present", "csaf-openvex",
                    "The corrected code is deployed; the recorded trigger does not reproduce the fault.",
                    "No action required for this component version.",
                    "execution-verified",
                    {"exec_method": exec_rec["method"], "exec_signal": sig,
                     "version_basis": "asserted", "version_unconfirmed": False})
        # 버전이 취약본으로 확인되었거나(asserted), SBOM 이 버전을 밝히지 않은 경우.
        # 후자는 ICS 안전 우선 원칙에 따라 취약본을 가정한다(fail-safe).
        unconfirmed = not version_asserted
        return (AFFECTED, "vulnerable_code_present", "extension",
                "Execution of the recorded trigger reproduced the fault (%s)." % sig,
                "Upgrade the component to the fixed release, or apply the vendor mitigation.",
                "execution-verified",
                {"exec_method": exec_rec["method"], "exec_signal": sig,
                 "version_basis": "assumed-vulnerable" if unconfirmed else "asserted",
                 "version_unconfirmed": unconfirmed})

    # --- 계층 2: 코드 실보유, 실행 미검증 -----------------------------------
    if has_code:
        return (UNDER_INV, None, None, None, None, "source-available-unverified",
                {"blocker": "source obtained but no execution result recorded for this CVE"})

    # --- 계층 3: OSS 귀속이나 코드 미확보 -----------------------------------
    if tier in ("A", "C"):
        return (UNDER_INV, None, None, None, None, "source-pending",
                {"blocker": "component is open source but no vulnerable/fixed code pair has been collected",
                 "oss_attributed": True})

    # --- 계층 4: 벤더 폐쇄 펌웨어 -------------------------------------------
    return (UNDER_INV, None, None, None, None, "source-unavailable",
            {"blocker": "vendor-proprietary firmware; source cannot be obtained"})


# ------------------------------------------- 2차 추정 (AV x 노출도, 확정 불가시)

def estimate(av, exposure, av_source, tier, kev):
    """1차가 UNDER_INVESTIGATION 일 때의 상태 추정.

    확보 가능한 유일한 신호인 CVSS Attack Vector 와 배치 노출도로
    도달성을 계산한다. VEX 진술이 아니라 추정치다.

    반환: (status, justification, vocabulary, basis, confidence, reach)
    """
    reach = reachability(av, exposure)

    if reach == "unknown":
        return (UNDER_INV, None, None,
                "attack vector not stated in the source advisory", 0.20, reach)

    if reach == "yes":
        status, just, vocab = AFFECTED, "vulnerable_code_controllable_by_adversary", "extension"
        basis = "AV:%s reaches the asset at exposure tier '%s'" % (av, exposure)
    elif reach == "no":
        status, just, vocab = NOT_AFFECTED, "vulnerable_code_cannot_be_controlled_by_adversary", "csaf-openvex"
        basis = ("AV:P requires hands-on access to the hardware" if av == "P"
                 else "AV:%s cannot traverse to an asset at exposure tier '%s'" % (av, exposure))
    else:
        status, just, vocab = UNDER_INV, None, None
        basis = "AV:%s is conditionally reachable at exposure tier '%s'" % (av, exposure)

    # 신뢰도: AV 출처가 CVE 단위인지 권고문 일괄인지가 가장 큰 요인
    conf = 0.78 if av_source == "per-cve" else 0.55
    if reach == "conditional":
        conf -= 0.18
    if tier == "A":
        conf += 0.06          # 코드가 있으면 후속 확정 여지가 있어 추정도 더 신뢰
    elif tier == "E":
        conf -= 0.05          # 폐쇄 펌웨어는 컴포넌트 구성 자체가 불확실
    if kev and status == AFFECTED:
        conf += 0.05          # 실제 악용 사례가 도달성 추정을 보강
    conf = round(min(0.92, max(0.15, conf)), 3)
    return (status, just, vocab, basis, conf, reach)


# ---------------------------------------------------- 주석자 불일치 (추정에만)

ADJ = {AFFECTED: UNDER_INV, NOT_AFFECTED: UNDER_INV}


def annotator_noise(label, device, cve, reach, sev, epss):
    """사람 주석자 불일치(k≈0.85) 시뮬레이션 — 추정치에만 적용한다.
    실행 검증으로 확정된 건은 사실이므로 흔들지 않는다.
    안전하지 않은 AFFECTED<->NOT_AFFECTED 직접 전이는 만들지 않는다."""
    boundary = (reach in ("conditional", "unknown") or sev == "medium"
                or (epss is not None and 0.3 <= epss <= 0.6))
    p = 0.16 if boundary else 0.04
    if (h("noise", device, cve) % 1000) / 1000.0 >= p:
        return label
    if label == UNDER_INV:
        return AFFECTED if (h("nd", device, cve) % 2) else NOT_AFFECTED
    return ADJ.get(label, label)


# -------------------------------------------------------------- 텍스트 렌더링

# 학습 타깃(label)을 인과적으로 결정하는 문장 종류만 정답 근거로 표시한다.
# kev / epss / severity 는 어느 경로에서도 상태를 바꾸지 않으므로 제외한다.
DRIVER_EXEC = {"exec_affected", "exec_not_affected"}
DRIVER_ESTIMATE = {"av", "exposure"}
# 1차 상태(vex_status)를 결정하는 문장 — primary_rationale_ids 용.
# 확정 건은 실행 검증 문장이, 미확정 건은 소스 확보 불가 문장이 근거다.
DRIVER_PRIMARY = ({"src_unavailable", "src_pending", "src_available", "version_unknown"}
                  | DRIVER_EXEC)


def render(device, vendor, product, cve, cwe, av, sev, epss, kev,
           exposure, has_code, oss_attributed, exec_rec, exec_status):
    S = []

    def add(txt, kind, eid):
        S.append({"id": eid, "text": txt, "kind": kind})

    cwe_name = CWE_NAME.get(cwe, (cwe or "an unspecified weakness"))
    sevw = {"critical": "critical-severity", "high": "high-severity",
            "medium": "moderate-severity", "low": "low-severity"}.get(sev, "unrated")
    add("%s is a %s %s issue (%s)." % (cve, sevw, cwe_name, cwe or "CWE-unknown"), "cve_desc", "CVE-1")
    # 공격 표면 (AV 를 명시하지 않고 암시). av=="" 이면 미기재 문장.
    add(pick(AV_POOL.get(av, AV_POOL[""]), "av", device, cve),
        "av" if av else "av_unstated", "CVE-2")
    add(pick(KEV_POOL if kev else KEVNEG_POOL, "kev", device, cve),
        "kev" if kev else "kev_neg", "CVE-3")
    if epss is not None:
        add("Statistical models put its near-term exploitation likelihood around %.2f." % epss,
            "epss", "CVE-4")

    add("Asset: %s %s." % (vendor, product), "product", "ASSET-1")
    add(pick(EXP_POOL[exposure], "exp", device), "exposure", "ASSET-2")
    add(pick(PRESENT_POOL, "pres", device, cve), "present", "ASSET-3")
    # SBOM 이 버전을 NOASSERTION 으로 기록한 실제 사실
    add(pick(VERSION_UNKNOWN_POOL, "ver", device, cve), "version_unknown", "ASSET-4")

    # 소스 확보 상태
    if has_code:
        if exec_rec is None:
            add(pick(SRC_AVAIL_POOL, "src", device, cve), "src_available", "SRC-1")
    elif oss_attributed:
        add(pick(SRC_PENDING_POOL, "src", device, cve), "src_pending", "SRC-1")
    else:
        add(pick(SRC_UNAVAIL_POOL, "src", device, cve), "src_unavailable", "SRC-1")

    # 실행 검증 결과 (확정된 건에만)
    if exec_status == AFFECTED:
        add(pick(EXEC_AFF_POOL, "exec", device, cve), "exec_affected", "EXEC-1")
    elif exec_status == NOT_AFFECTED:
        add(pick(EXEC_NOT_POOL, "exec", device, cve), "exec_not_affected", "EXEC-1")
    return S


# --------------------------------------------------------------------- main

def main():
    exec_map = load_exec_verification()
    code_cves = load_code_available()
    print("실행 검증 CVE : %d %s" % (len(exec_map), sorted(exec_map)))
    print("코드 확보 CVE : %d" % len(code_cves))

    rows = list(csv.DictReader(open(FIND, encoding="utf-8-sig")))
    n = 0
    tiers = {}
    prim = {}
    labels = {}
    routes = {}
    n_code = n_gt = 0
    with open(OUT, "w", encoding="utf-8") as out, \
            open(OUT_CODE, "w", encoding="utf-8") as out_code, \
            open(OUT_GT, "w", encoding="utf-8") as out_gt:
        for r in rows:
            device, vendor, product = r["device"], r["vendor"], r["product"]
            cve, cwe, tier = r["cve"], r["cwe"], r["tier"]
            av, sev = r["av"], r["severity"]
            av_source = r.get("av_source", "")
            kev = r["kev"] == "True"
            epss = float(r["epss"]) if r["epss"] not in ("", None) else None
            exposure = exposure_for(device)
            exec_rec = exec_map.get(cve)

            # SBOM 이 모든 컴포넌트 버전을 NOASSERTION 으로 기록하므로 확정 버전은 없다.
            # 실제 버전이 채워지면 여기서 읽어 adjudicate() 로 넘기면 된다.
            version_asserted = None

            # 코드 leg 진입 조건은 tier 문자가 아니라 실제 코드 보유 여부다.
            has_code = cve in code_cves
            oss_attributed = tier in ("A", "C")

            (status, just, vocab, impact, action,
             ev_tier, detail) = adjudicate(tier, has_code, exec_rec, version_asserted)

            # 대조할 코드가 실제로 있어야만 코드 leg(CodeBERT->sLLM)로 보낸다.
            route = ROUTE_CODE if has_code else ROUTE_CONTEXT_ONLY

            if status == UNDER_INV:
                (est_status, est_just, est_vocab,
                 est_basis, est_conf, reach) = estimate(av, exposure, av_source, tier, kev)
                # 학습 타깃은 2차 추정치. 추정에만 주석자 불일치를 적용한다.
                clean_label = est_status
                label = annotator_noise(est_status, device, cve, reach, sev, epss)
                gold_kinds = DRIVER_ESTIMATE
            else:
                reach = reachability(av, exposure)
                est_status = est_just = est_vocab = est_basis = None
                est_conf = None
                clean_label = label = status      # 확정값에는 노이즈를 넣지 않는다
                gold_kinds = DRIVER_EXEC

            sents = render(device, vendor, product, cve, cwe, av, sev, epss, kev,
                           exposure, has_code, oss_attributed, exec_rec,
                           status if ev_tier == "execution-verified" else None)

            rec = {
                "sampleId": "S%06d" % n, "device": device, "cve": cve,
                "arm": r["arm"], "tier": tier,

                # --- 1차: 증거 기반 VEX 진술 (표준 호환) ---
                "vex_status": status,
                "justification": just,
                "justification_vocabulary": vocab,   # csaf-openvex | extension | None
                "impact_statement": impact,
                "action_statement": action,
                "evidence_tier": ev_tier,            # execution-verified | source-available-unverified
                                                     # | source-pending | source-unavailable
                "evidence_detail": detail,
                "source_availability": TIER_DESC.get(tier, "unknown"),
                "code_evidence_available": has_code,   # vuln/patched 코드 쌍 실보유
                "oss_attributed": oss_attributed,      # OSS 카탈로그 귀속 (tier A/C)

                # --- 모델 라우팅 (소스 확보 여부가 경로를 결정) ---
                "route": route,
                "route_stages": ROUTE_STAGES[route],
                "route_terminal_model": "codebert" if route == ROUTE_CODE else "securebert",

                # --- 2차: AV 기반 추정 (1차가 UNDER_INVESTIGATION 인 경우만) ---
                "estimated_status": est_status,
                "estimated_justification": est_just,
                "estimated_justification_vocabulary": est_vocab,
                "estimate_basis": est_basis,
                "estimate_confidence": est_conf,

                # --- 학습 타깃 ---
                "label": label,                      # 확정값 우선, 없으면 2차 추정치
                "clean_label": clean_label,          # 주석자 노이즈 적용 전
                "label_source": ("execution" if ev_tier == "execution-verified"
                                 else "av-estimate"),

                "sentences": sents,
                "gold_rationale_ids": [s["id"] for s in sents if s["kind"] in gold_kinds],
                "primary_rationale_ids": [s["id"] for s in sents if s["kind"] in DRIVER_PRIMARY],

                "structured": {
                    "av": av, "av_source": av_source, "exposure": exposure, "reach": reach,
                    "kev": kev, "epss": epss, "severity": sev,
                    "version_asserted": version_asserted,
                    "source_availability": tier,
                    "exposure_synthetic": True,       # 배치 노출도는 합성값
                    "neg": "", "vague": (av == ""),   # v2 호환 필드
                },
            }
            line = json.dumps(rec, ensure_ascii=False) + "\n"
            out.write(line)
            if tier == "A":
                out_code.write(line)
                n_code += 1
            if ev_tier == "execution-verified":
                out_gt.write(line)
                n_gt += 1
            n += 1
            tiers[ev_tier] = tiers.get(ev_tier, 0) + 1
            prim[status] = prim.get(status, 0) + 1
            labels[label] = labels.get(label, 0) + 1
            routes[route] = routes.get(route, 0) + 1

    print("\nsamples: %d" % n)
    print("\n[증거 계층]")
    for k in ("execution-verified", "source-available-unverified", "source-pending", "source-unavailable"):
        if k in tiers:
            print("  %-30s %6d (%5.2f%%)" % (k, tiers[k], 100 * tiers[k] / n))
    print("\n[모델 라우팅 — 소스 확보 여부로 결정]")
    for k in (ROUTE_CODE, ROUTE_CONTEXT_ONLY):
        if k in routes:
            print("  %-30s %6d (%5.2f%%)" % (k, routes[k], 100 * routes[k] / n))
    print("\n[1차 VEX 진술 — 증거 기반]")
    for k in (AFFECTED, NOT_AFFECTED, UNDER_INV):
        print("  %-22s %6d (%5.2f%%)" % (k, prim.get(k, 0), 100 * prim.get(k, 0) / n))
    print("\n[학습 타깃 label — 확정값 + 2차 추정]")
    for k in (AFFECTED, NOT_AFFECTED, UNDER_INV):
        print("  %-22s %6d (%5.2f%%)" % (k, labels.get(k, 0), 100 * labels.get(k, 0) / n))
    print("\n[출력]")
    print("  %-46s %6d" % (os.path.relpath(OUT, BASE), n))
    print("  %-46s %6d  (OSS 귀속 tier A — 코드 leg 후보군)" % (os.path.relpath(OUT_CODE, BASE), n_code))
    print("  %-46s %6d  (실행 검증 확정 — 진짜 ground truth)" % (os.path.relpath(OUT_GT, BASE), n_gt))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
