#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OT 운영 맥락(OC) 모델 — 자산의 운영맥락 VEX 판정 입력.

이 모듈이 지키는 규칙
---------------------
CVE 서술은 공격이 환경에 **요구하는 것**을 말하고, 자산은 그것을 공급할 수도
없을 수도 있다. 이 모듈은 요구와 공급을 대조해 OC 슬롯 5개를 채운다. 세 가지가
설계의 전부다:

  1. **값이 없으면 `false`가 아니라 `unknown`이다.** 빈칸은 안전의 증거가
     아니다. VEX는 `not_affected` 쪽에 입증 책임을 둔다 (docs/ICSVEX.md §6).
  2. **조건 불충족이 자동으로 `not_affected`가 되지 않는다.** 불충족의 *근거*가
     무엇이냐가 상태를 가른다 — 아래 ABSENT / DISABLED 구분.
  3. **OC는 질문이 아니라 대조 결과다.** 운영자는 자산을 1회 기술하고(ASSET_FIELDS),
     CVE가 요구하는 것은 CVE 쪽에서 오며, OC1~OC5는 그 둘을 맞춰본 결과로 채워진다.
     OC를 폼으로 만들면 CVE마다 다시 물어야 하므로 자산 하나에 수천 번 답해야 한다.

ABSENT 와 DISABLED — 상태를 가르는 단 하나의 구분
--------------------------------------------------
  ABSENT    자산이 그것을 **갖고 있지 않아서** 요구를 공급할 수 없다. 펌웨어에
            프로토콜 스택이 없고, NIC이 안 달렸고, 그 서비스가 빌드에 없다.
            바꾸려면 하드웨어나 펌웨어를 바꿔야 한다 → `not_affected` 가능.

  DISABLED  갖고 있으나 **현재 설정으로** 공급하지 않는다. 포트를 닫아뒀고,
            기능을 꺼뒀고, 방화벽이 막고 있다. 변경 창 한 번, 설정 실수 하나,
            노트북 든 엔지니어 한 명이면 되돌아온다 → 절대 `not_affected`가
            되지 않는다. `affected`로 남고 CSAF `remediation/mitigation`으로
            나가며 우선순위 점수만 낮춘다.

이 구분은 CISA Appendix A에 없다. Appendix A는 **지금 열려 있는 포트**를 적게
하지 **스택이 펌웨어에 존재하는지**는 묻지 않는다. 그래서 각 목록형 필드에
`*_absent` 짝을 두어 운영자가 "아예 없음"을 따로 주장하게 했고, 주장하지 않으면
DISABLED로만 취급한다 — 더 약한 쪽이 기본값이다.

필드 출처
---------
CISA 외 공동기관 (2025), *Foundations for OT Cybersecurity: Asset Inventory
Guidance for Owners and Operators*, Appendix A, Table 1 (pp. 15-18), 32개 필드.
docs/ICSVEX.md §4가 그 32개를 핵심 10 / 조건부 7 / 우선순위 1 / 제외 14로
분류했고, 이 모듈은 그 분류를 그대로 따른다. `SOURCE`에 필드별 원문 명칭을
남겨 심사에서 역추적이 되게 했다.

Appendix A가 채우지 못하는 것
-----------------------------
OC1(취약 기능 활성)과 OC5(취약점별 구성)를 Appendix A 단독으로 채울 수 없다.
32개 필드 어디에도 **장비 설정값**이 없기 때문이다. 해당 필드들은 `EXTENDED`로
표시했고 출처가 Appendix A가 아니라 설정 백업·벤더 하드닝 가이드임을 명시한다.
표시하지 않으면 "CISA 기반"이라는 말이 실제보다 넓게 읽힌다.
"""

# ---- OC 슬롯 평가 결과 ------------------------------------------------------
SATISFIED = "satisfied"      # 자산이 요구를 공급한다 -> 악용 전제조건 충족
ABSENT = "absent"            # 구조적으로 공급 불가 -> 상태를 바꿀 수 있다
DISABLED = "disabled"        # 설정으로 현재 차단 -> 완화일 뿐, 상태 불변
UNKNOWN = "unknown"          # 판단할 정보가 없다 -> 절대 해제하지 않는다
NOT_REQUIRED = "not_required"  # 이 CVE가 그 조건을 요구하지 않는다 -> 대조할 것 없음

# 상태를 바꿀 수 있는 결과는 ABSENT 하나뿐이다. 이 집합이 비어 보이는 것이 요점.
MAY_REFUTE = {ABSENT}


# ---- OC 모델 ----------------------------------------------------------------
# docs/ICSVEX.md §5.2 의 5개 안. §5.1 의 6개 안은 OC1/OC2 가 중복이고 OC6 범위가
# 지나치게 넓다는 문서 자체의 지적에 따라 채택하지 않았다. 되돌릴 경우 이 표만
# 교체하면 되도록 판정 로직은 OC 키를 하드코딩하지 않는다.
OC_MODEL = "5-slot (docs/ICSVEX.md §5.2)"

OC_SLOTS = [
    ("OC1", "취약 기능 및 코드 실행 상태",
     "CVE가 지목한 기능·서비스가 이 자산에서 활성인지, 그리고 취약 코드 경로가 "
     "실행될 수 있는지.",
     # 운영자 진술의 범위를 결과에 명시한다.
     ["running_services", "service_enabled", "enabled_features", "asset_role_type"]),

    ("OC2", "통신 프로토콜 사용 상태",
     "CVE가 요구하는 프로토콜을 자산이 실제로 쓰고 있는지. 지원(supported)과 "
     "활성(active)은 다른 값이다.",
     ["active_protocols", "supported_protocols", "primary_communication_method"]),

    ("OC3", "공격 경로 접근 가능 상태",
     "가정한 공격자 위치에서 해당 서비스·기능까지 경로가 있는지, 그 경로에 어떤 "
     "통제가 걸려 있는지.",
     ["network_interfaces", "listening_ports", "network_zone", "vlan_id",
      "reachable_from", "path_controls"]),

    ("OC4", "인증 및 권한 조건",
     "취약한 기능에 접근할 때 인증을 요구하는지, 비인증 접근이 허용되는지, 접근 "
     "주체가 실제로 행사하는 권한이 무엇인지.",
     ["authentication_enabled", "anonymous_access_allowed", "effective_privileges"]),

    ("OC5", "취약점별 구성 및 실행 전제조건",
     "그 CVE에만 해당하는 설정값·배포 형태·실행 환경. 다른 슬롯이 포괄하지 못하는 "
     "개별 조건이 여기로 온다.",
     ["config_settings", "physical_or_virtual", "hypervisor", "os_name", "os_version"]),
]

# ---- 자산 필드 --------------------------------------------------------------
# (key, group, type, label_ko, help, source)
#   type: "list" | "tri" | "enum:a|b|c" | "text" | "kv"
#   source: Appendix A 원문 필드명, 또는 EXTENDED(Appendix A 밖)
#
# `tri` 와 `list` 는 셋 다 "미입력"을 값으로 갖는다. 빈 리스트와 미입력 리스트는
# 다른 뜻이다 — 전자는 "없음을 확인했다", 후자는 "확인하지 않았다".
APPENDIX_A = "CISA Appendix A, Table 1"
EXTENDED = "EXTENDED — Appendix A 밖 (설정 백업 / 벤더 하드닝 가이드 / 현장 확인)"

ASSET_FIELDS = [
    # ---- 식별: SBOM->CVE 단계에서 이미 확보되면 다시 묻지 않는다 (§4.1 중복 수집 최소화)
    ("vendor_id", "identity", "text", "제조사",
     "SBOM에서 확보되면 자동으로 채워진다.", APPENDIX_A + " — Manufacturer"),
    ("product_id", "identity", "text", "모델",
     "", APPENDIX_A + " — Model"),
    ("firmware_version", "identity", "text", "펌웨어 / 소프트웨어 버전",
     "", APPENDIX_A + " — Firmware/Software Version"),
    ("os_name", "identity", "text", "운영체제",
     "", APPENDIX_A + " — Operating System"),
    ("os_version", "identity", "text", "운영체제 버전",
     "", APPENDIX_A + " — OS Version"),

    # ---- OC1: 기능·서비스 실행 상태
    ("running_services", "oc1", "list", "실행 중인 서비스",
     "실제로 떠 있는 서비스명. 설치만 되고 안 떠 있으면 적지 않는다.",
     APPENDIX_A + " — Ports/Services"),
    ("running_services_absent", "oc1", "list", "이 빌드에 아예 없는 서비스",
     "설정으로 끈 것이 아니라 펌웨어/이미지에 포함조차 되지 않은 서비스. "
     "여기 적힌 것만 not_affected 의 근거가 된다.", EXTENDED),
    ("enabled_features", "oc1", "list", "활성화된 기능 / 모듈",
     "웹 관리, OPC UA 서버, 원격 로깅 등 켜져 있는 기능.", EXTENDED),
    ("enabled_features_absent", "oc1", "list", "이 빌드에 없는 기능 / 모듈",
     "주문 사양에서 빠졌거나 펌웨어에 빌드되지 않은 기능.", EXTENDED),
    ("asset_role_type", "oc1", "enum:plc|rtu|ied|hmi|engineering-workstation|"
     "historian|sis-logic-solver|network-device|hypervisor-host",
     "자산 역할 / 유형", "", APPENDIX_A + " — Asset Role/Type"),

    # ---- OC2: 프로토콜
    ("active_protocols", "oc2", "list", "실제 사용 중인 통신 프로토콜",
     "Modbus/TCP, DNP3, OPC UA, HTTP 등 실제로 트래픽이 흐르는 것.",
     APPENDIX_A + " — Active/Supported Communication Protocols"),
    ("supported_protocols", "oc2", "list", "지원하지만 사용하지 않는 프로토콜",
     "스택은 있으나 꺼져 있는 것. 설정이므로 완화로만 기록된다.",
     APPENDIX_A + " — Active/Supported Communication Protocols"),
    ("protocols_absent", "oc2", "list", "이 빌드에 스택 자체가 없는 프로토콜",
     "펌웨어에 구현이 들어있지 않은 프로토콜. 여기 적힌 것만 해제 근거가 된다.",
     EXTENDED),
    ("primary_communication_method", "oc2",
     "enum:wired|wireless|cellular|rf|satellite|none", "주 통신 매체",
     "", APPENDIX_A + " — Primary Communication Method"),

    # ---- OC3: 접근 경로
    ("network_interfaces", "oc3", "list", "장착된 네트워크 인터페이스",
     "비워두면 '확인 안 함'이다. 인터페이스가 하나도 없음을 확인했다면 아래 "
     "'인터페이스 없음'을 체크한다.", APPENDIX_A + " — IP Address"),
    ("no_network_interface", "oc3", "tri", "네트워크 인터페이스가 하나도 장착되지 않음",
     "하드웨어 사실이다. 맞다면 네트워크 경유 악용은 탈 채널이 없다.", EXTENDED),
    ("listening_ports", "oc3", "list", "열린 포트",
     "", APPENDIX_A + " — Ports/Services"),
    ("network_zone", "oc3", "enum:0|1|2|3|3.5|4", "네트워크 존 (Purdue 레벨)",
     "", APPENDIX_A + " — VLAN (Zone/Conduit)"),
    ("vlan_id", "oc3", "text", "VLAN", "", APPENDIX_A + " — VLAN"),
    ("reachable_from", "oc3",
     "enum:internet|corporate-it|ot-dmz|control-network|isolated-cell|none",
     "어디에서 도달 가능한가",
     "가정하는 공격자 위치. 세그먼트는 설정이므로 상태를 바꾸지 않고 "
     "우선순위만 낮춘다.", APPENDIX_A + " — VLAN (Zone/Conduit)"),
    ("path_controls", "oc3", "list", "경로에 걸린 통제",
     "방화벽 규칙, 단방향 게이트웨이, ACL 등. 전부 완화로 기록된다.", EXTENDED),

    # ---- OC4: 인증·권한 (취약 기능 단위로 기록한다)
    ("authentication_enabled", "oc4", "tri", "인증 기능 활성 여부",
     "취약한 서비스/기능에 접근할 때 사용자 인증을 요구하는지.",
     APPENDIX_A + " — User Accounts (파생)"),
    ("anonymous_access_allowed", "oc4", "tri", "비인증 접근 허용 여부",
     "취약한 서비스/기능에 인증 없이 접근할 수 있는지. 예이면 PR 조건을 "
     "반박하지 못할 뿐 아니라 위험을 **높인다**.",
     APPENDIX_A + " — User Accounts (파생)"),
    ("effective_privileges", "oc4", "enum:none|low|high|admin",
     "실효 접근 권한 수준",
     "해당 접근 주체가 실제로 행사할 수 있는 권한.",
     APPENDIX_A + " — User Accounts (파생)"),
    ("no_account_subsystem", "oc4", "tri", "해당 인터페이스에 계정 개념이 아예 없음",
     "로그인이라는 개념 자체가 없는 인터페이스. 권한을 요구하는 CVE는 탈 것이 "
     "없지만, 비인증 CVE는 더 나빠진다 — 판정에 둘 다 적는다.", EXTENDED),
    ("interactive_operator", "oc4", "tri", "이 자산에서 사람이 콘텐츠를 다루는가",
     "HMI 세션, 브라우저, 파일 열기 등. 헤드리스 컨트롤러에는 클릭할 사람이 없다.",
     EXTENDED),

    # ---- OC5: 개별 구성
    ("config_settings", "oc5", "kv", "관련 설정값",
     "CVE가 지목하는 설정 항목과 현재 값. 예: "
     "`web_admin=enabled`, `legacy_auth=off`.", EXTENDED),
    ("physical_or_virtual", "oc5", "enum:physical|virtual", "물리 / 가상",
     "", APPENDIX_A + " — Physical or Virtual"),
    ("hypervisor", "oc5", "text", "하이퍼바이저", "",
     APPENDIX_A + " — Hypervisor (if applicable)"),

    # ---- 우선순위 전용: 영향 여부를 증명하지 않는다 (§4.3)
    ("asset_criticality", "priority", "enum:low|medium|high|safety-critical",
     "자산 중요도",
     "악용 가능성이 아니라 조치 우선순위에만 쓰인다. 상태를 바꾸지 않는다.",
     APPENDIX_A + " — Asset Criticality"),
    ("availability_tolerance", "priority",
     "enum:continuous|scheduled|interruptible", "허용 가능한 정지",
     "", EXTENDED),
    ("safety_function", "priority", "tri", "안전 기능을 수행 / 보호하는가",
     "", EXTENDED),
]

GROUP_LABEL = {
    "identity": "자산 식별 (SBOM에서 확보되면 자동)",
    "oc1": "OC1 · 취약 기능 및 코드 실행 상태",
    "oc2": "OC2 · 통신 프로토콜 사용 상태",
    "oc3": "OC3 · 공격 경로 접근 가능 상태",
    "oc4": "OC4 · 인증 및 권한 조건",
    "oc5": "OC5 · 취약점별 구성 및 실행 전제조건",
    "priority": "조치 우선순위 전용 (영향 여부와 무관)",
}

# 상태를 절대 바꾸지 못하는 그룹. 우선순위 필드가 판정에 새는 것을 막는다.
PRIORITY_ONLY = {"priority"}


def fields_by_group():
    """폼이 그릴 수 있게 그룹별로 묶어 돌려준다."""
    out = []
    for g in ["identity", "oc1", "oc2", "oc3", "oc4", "oc5", "priority"]:
        items = [{"key": k, "type": t, "label": lab, "help": h, "source": s}
                 for k, grp, t, lab, h, s in ASSET_FIELDS if grp == g]
        out.append({"group": g, "label": GROUP_LABEL[g],
                    "priority_only": g in PRIORITY_ONLY, "fields": items})
    return out


def _norm_list(v):
    """목록 필드를 소문자 집합으로. 미입력(None)과 빈 목록을 구분해 돌려준다."""
    if v is None:
        return None
    if isinstance(v, str):
        v = [x.strip() for x in v.replace("\n", ",").split(",")]
    return {str(x).strip().lower() for x in v if str(x).strip()}


def _tri(v):
    """tri 필드: True / False / None(미입력). 빈 문자열은 미입력이다."""
    if v in (True, "true", "yes", "y", 1, "1"):
        return True
    if v in (False, "false", "no", "n", 0, "0"):
        return False
    return None


def _match(required, present, absent, supported):
    """요구된 항목 하나를 자산의 목록들과 대조한다.

    `absent`(빌드에 없음)가 `supported`(있으나 꺼둠)를 이긴다. 운영자가 두 곳에
    같은 이름을 적었다면 더 강한 주장을 받아들이되, 판정문에 그 사실을 남긴다.
    """
    r = str(required).strip().lower()
    if absent and r in absent:
        return ABSENT
    if present and r in present:
        return SATISFIED
    if supported and r in supported:
        return DISABLED
    # 목록을 아예 받지 못했으면 모름. 목록은 받았는데 거기 없으면, 그것은
    # "확인했고 없었다"이므로 DISABLED 로 본다 - ABSENT 로 올리지 않는 이유는
    # 목록에 없다는 사실이 빌드에 없다는 뜻은 아니기 때문이다.
    if present is None and supported is None:
        return UNKNOWN
    return DISABLED


def evaluate(requirements, asset):
    """CVE가 요구하는 것과 자산이 공급하는 것을 대조해 OC 슬롯을 채운다.

    requirements : src/cve_requirements.py 가 CVE에서 구조화한 dict
    asset        : ASSET_FIELDS 키를 갖는 운영자 입력 dict

    돌려주는 것은 슬롯별 결과 목록이며, 상태 결정은 하지 않는다. 상태는
    src/oc_vex_judge.py 가 이 결과들을 읽고 정한다 — 대조와 판정을 분리해야
    같은 대조 결과를 M1~M4 실험이 공유할 수 있다 (docs/ICSVEX.md §8).
    """
    req = requirements or {}
    a = asset or {}

    svc_on = _norm_list(a.get("running_services"))
    svc_off = None
    svc_absent = _norm_list(a.get("running_services_absent"))
    feat_on = _norm_list(a.get("enabled_features"))
    feat_absent = _norm_list(a.get("enabled_features_absent"))
    proto_on = _norm_list(a.get("active_protocols"))
    proto_sup = _norm_list(a.get("supported_protocols"))
    proto_absent = _norm_list(a.get("protocols_absent"))

    rows = []

    # ---- OC1: 기능 / 서비스 -------------------------------------------------
    for name in (req.get("required_services") or []):
        rows.append(_row("OC1", "service", name,
                         _match(name, svc_on, svc_absent, svc_off)))
    for name in (req.get("required_features") or []):
        rows.append(_row("OC1", "feature", name,
                         _match(name, feat_on, feat_absent, None)))

    # ---- OC2: 프로토콜 ------------------------------------------------------
    for name in (req.get("required_protocols") or []):
        rows.append(_row("OC2", "protocol", name,
                         _match(name, proto_on, proto_absent, proto_sup)))

    # ---- OC3: 접근 경로 -----------------------------------------------------
    chan = req.get("attack_channel")       # network | adjacent | local | physical
    if chan:
        rows.append(_row("OC3", "channel", chan, _channel(chan, a)))

    # ---- OC4: 인증 / 권한 ---------------------------------------------------
    if req.get("requires_privileges"):
        rows.append(_row("OC4", "privilege", req["requires_privileges"],
                         _privilege(req["requires_privileges"], a)))
    if req.get("requires_user_interaction"):
        io = _tri(a.get("interactive_operator"))
        rows.append(_row("OC4", "interaction", "interactive operator",
                         UNKNOWN if io is None else (SATISFIED if io else ABSENT)))

    # ---- OC5: 개별 설정 -----------------------------------------------------
    cfg = a.get("config_settings") or {}
    if isinstance(cfg, str):
        cfg = _parse_kv(cfg)
    for cond in (req.get("required_config") or []):
        rows.append(_row("OC5", "config", _cond_text(cond), _config(cond, cfg)))

    for candidate in req.get('llm_condition_candidates',[]):
        r=_row('OC5','condition_candidate',candidate['evidence'],UNKNOWN)
        r.update(condition_id=candidate['id'],origin='llm_literal_quote',may_refute=False,
                 note='A quoted condition candidate needs CVE-specific semantic and asset evidence.')
        rows.append(r)
    return {"model": OC_MODEL, "rows": rows,
            "unknown": sum(1 for r in rows if r["result"] == UNKNOWN),
            "evaluated": len(rows)}


def _row(slot, kind, name, result):
    return {"slot": slot, "kind": kind, "requirement": name, "result": result,
            "may_refute": result in MAY_REFUTE}


def _channel(chan, a):
    """공격 채널이 이 자산에 존재하는가.

    세그먼트(`reachable_from`)는 DISABLED 까지만 간다 — 방화벽 규칙 하나로
    뒤집히는 사실로 문서에 `not_affected`를 싣지 않는다. 구조적 해제는
    '인터페이스 미장착' 같은 하드웨어 사실에서만 나온다.
    """
    if chan in ("network", "adjacent"):
        if _tri(a.get("no_network_interface")) is True:
            return ABSENT
        rf = a.get("reachable_from")
        if rf == "none":
            return DISABLED
        if not rf:
            return UNKNOWN
        return SATISFIED
    if chan == "local":
        # 로컬 실행 채널은 계정 체계와 상호작용 운영자 둘 다 없으면 탈 것이 없다.
        if _tri(a.get("no_account_subsystem")) is True and \
           _tri(a.get("interactive_operator")) is False:
            return ABSENT
        return UNKNOWN if a.get("effective_privileges") is None else SATISFIED
    if chan == "physical":
        return UNKNOWN
    return UNKNOWN


def _privilege(level, a):
    """CVE가 계정을 요구하는데 자산에 계정 개념이 없으면 구조적 반박이다."""
    if _tri(a.get("no_account_subsystem")) is True:
        return ABSENT
    if _tri(a.get("anonymous_access_allowed")) is True:
        # 비인증 접근이 열려 있으면 권한 요구는 장애물이 아니다.
        return SATISFIED
    auth = _tri(a.get("authentication_enabled"))
    if auth is None:
        return UNKNOWN
    return SATISFIED if a.get("effective_privileges") else UNKNOWN


def _parse_kv(text):
    out = {}
    for line in str(text).replace(",", "\n").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip().lower()] = v.strip().lower()
    return out


def _cond_text(cond):
    if isinstance(cond, dict):
        return "%s=%s" % (cond.get("setting"), cond.get("value"))
    return str(cond)


def _config(cond, cfg):
    """설정 조건 하나를 자산의 설정값과 대조한다.

    설정은 정의상 CONTROL 이므로 불일치해도 ABSENT 가 아니라 DISABLED 다 —
    설정값은 되돌릴 수 있다.
    """
    if not isinstance(cond, dict):
        return UNKNOWN
    key = str(cond.get("setting", "")).strip().lower()
    want = str(cond.get("value", "")).strip().lower()
    if key not in cfg:
        return UNKNOWN
    return SATISFIED if cfg[key] == want else DISABLED


if __name__ == "__main__":
    import json
    demo_req = {"required_services": ["web admin"],
                "required_protocols": ["modbus"],
                "attack_channel": "network",
                "requires_privileges": "low"}
    headless = {"running_services_absent": ["web admin"],
                "protocols_absent": ["modbus"],
                "no_network_interface": True,
                "no_account_subsystem": True}
    blank = {}
    for name, asset in [("sealed headless PLC", headless), ("빈 맥락", blank)]:
        r = evaluate(demo_req, asset)
        print("\n--- %s ---" % name)
        print(json.dumps(r, ensure_ascii=False, indent=2))
    print("\nfields: %d, groups: %d"
          % (len(ASSET_FIELDS), len(fields_by_group())))
