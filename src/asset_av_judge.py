#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Asset-attribute-based exploitability judgment for source-less CVEs.

This is the "CVE & Asset Context Analysis" branch: when no source can be
collected, the vulnerable function cannot be located, so the source-level tree
(Q1-Q4) does not apply. Instead the user supplies the asset's real attributes,
this derives which ATTACK VECTORS physically exist on that asset, and compares
them against the CVE's CVSS Attack Vector (AV) to decide exploitability.

It replaces the earlier synthetic estimate (CVSS AV x a hashed `exposure` value),
which was removed because an estimate built from synthetic input is not a claim
about any real asset. Here every input is user-provided fact about one asset.

Three stages, from the NVAS spec:

  4.1  the user fills the asset attributes. Not all filled -> UNDER_INVESTIGATION.
  4.2  five flowcharts turn those attributes into the set of attack vectors
       present on the asset, a subset of:
         WIRED, WIRELESS, PHYSICAL, PMMD (portable maintenance device), SUPPLY_CHAIN
  4.3  the CVE's CVSS AV is matched against that set (AV_VECTORS below), with
       refinements for AV:N/A (protocol/interface must match) and AV:P (whether
       the exploit needs a PMMD). A match -> AFFECTED; no match -> NOT_AFFECTED;
       genuinely unresolved -> UNDER_INVESTIGATION.

The flowcharts (4.2) are deterministic and implemented in full below. The 4.3
match is the part with design choices and is left as TODO(human).
"""

# The five attack vectors an asset can present.
WIRED = "wired"
WIRELESS = "wireless"
PHYSICAL = "physical"
PMMD = "pmmd"
SUPPLY_CHAIN = "supply_chain"
VECTORS = (WIRED, WIRELESS, PHYSICAL, PMMD, SUPPLY_CHAIN)

AFFECTED = "affected"
NOT_AFFECTED = "not_affected"
UNDER_INVESTIGATION = "under_investigation"

# Which attack vectors a CVSS Attack Vector value can be carried by (spec table 3).
#   AV:N / AV:A  -> wired, wireless, supply-chain
#   AV:L         -> any of the five (a local action can be reached down any path)
#   AV:P         -> physical, pmmd
AV_VECTORS = {
    "N": {WIRED, WIRELESS, SUPPLY_CHAIN},
    "A": {WIRED, WIRELESS, SUPPLY_CHAIN},
    "L": {WIRED, WIRELESS, PHYSICAL, PMMD, SUPPLY_CHAIN},
    "P": {PHYSICAL, PMMD},
}

# The asset attributes each flowchart reads. The union is the set the UI collects;
# a missing one (None) means "not yet entered" and forces UNDER_INVESTIGATION.
#
#   access_right     : "admin" | "operator" | "none"   (관리자 / 취급자 / 없음)
#   physical_location: "VA" | "OCA" | "PA"  (visitor area / op-controlled / protected)
# every other attribute below is a yes/no boolean.
ATTRIBUTES = [
    # PMMD (fc1)
    "maint_port_sealed", "maint_device_used",
    # supply chain (fc2)
    "sys_env_configured", "vendor_remote_access", "work_approval", "account_mgmt",
    # wired (fc3)
    "comm_connected", "unidirectional", "host_firewall",
    # physical (fc4)
    "physical_location", "physical_blocked",
    # wireless (fc5)
    "wireless_capable", "wireless_enabled", "encrypted_comm",
    # shared by several flowcharts
    "access_right",
]


# --- 4.2  the five attack-vector flowcharts -------------------------------------
# Each returns True when the vector is PRESENT on the asset ("공격벡터 존재"),
# False when absent ("공격벡터 부재"). Transcribed node-for-node from the spec.

def _pmmd_present(a):
    """fc1 - portable maintenance/measurement device."""
    if a["maint_port_sealed"]:                 # 유지보수용 포트 물리적 차단?  Y -> absent
        return False
    if not a["maint_device_used"]:             # 유지보수용 기기 사용?         N -> absent
        return False
    if a["access_right"] == "admin":           # 자산 접근 권한 = 관리자       -> absent
        return False
    return True                                # 없음 / 취급자                -> present


def _supply_chain_present(a):
    """fc2 - supply chain."""
    if not a["sys_env_configured"]:            # 시스템 환경 구성?             N -> absent
        return False
    if a["vendor_remote_access"]:              # 공급업체 원격 접속 가능?      Y ->
        return not a["work_approval"]          #   작업 승인?  N -> present, Y -> absent
    # 원격 접속 불가:
    if not a["account_mgmt"]:                  # 접근 계정 관리 지원?          N -> present
        return True
    return a["access_right"] == "none"         # 자산 접근 권한 = 없음 -> present


def _wired_present(a):
    """fc3 - wired network."""
    if not a["comm_connected"]:                # 통신 연결성?                  N -> absent
        return False
    if not a["unidirectional"]:                # 단방향 통신?                  N -> present
        return True
    return not a["host_firewall"]              # 호스트 방화벽?  N -> present, Y -> absent


def _physical_present(a):
    """fc4 - physical access. Branches on the asset's physical location."""
    loc = a["physical_location"]
    if loc == "OCA":                           # operation-controlled area -> present
        return True
    if loc == "VA":                            # visitor-accessible area
        if not a["work_approval"]:             #   작업 승인?  N -> present
            return True
        return a["access_right"] == "none"     #   접근 권한 없음 -> present, else absent
    if loc == "PA":                            # protected area
        if not a["physical_blocked"]:          #   물리적 차단?  N -> present
            return True
        return a["access_right"] == "none"     #   접근 권한 없음 -> present, else absent
    return False


def _wireless_present(a):
    """fc5 - wireless network."""
    if not a["wireless_capable"]:              # 무선 통신 기능?               N -> absent
        return False
    if not a["wireless_enabled"]:              # 무선 통신 활성화?             N -> absent
        return False
    return not a["encrypted_comm"]             # 암호화 통신?  Y -> absent, N -> present


_FLOWCHARTS = {
    PMMD: _pmmd_present, SUPPLY_CHAIN: _supply_chain_present,
    WIRED: _wired_present, PHYSICAL: _physical_present, WIRELESS: _wireless_present,
}


def identify_vectors(attrs):
    """Stage 4.2: the set of attack vectors present on the asset."""
    return {v for v, fn in _FLOWCHARTS.items() if fn(attrs)}


def missing_attributes(attrs):
    """Attributes the user has not filled in (value is None or absent)."""
    return [k for k in ATTRIBUTES if attrs.get(k) is None]


def parse_av(vector):
    """The AV letter (N/A/L/P) from a CVSS vector string, or None."""
    for seg in (vector or "").split("/"):
        if seg.startswith("AV:"):
            return seg[3:]
    return None


# --- 4.3  match the CVSS AV against the identified vectors -----------------------

def judge(cvss_av, present, extra=None):
    """Stage 4.3: (status, reason) from the CVE's AV and the identified vectors.

    cvss_av : "N" | "A" | "L" | "P" | None
    present : set of attack vectors identify_vectors() returned
    extra   : optional dict of CVE-derived facts (spec 3.5):
                {"protocol_required": bool|None,   # AV:N/A: needs a specific protocol?
                 "protocol_match": bool|None,      #   does the asset carry a matching one?
                 "pmmd_required": bool|None}       # AV:P: must the exploit use a PMMD?
    """
    extra = extra or {}
    if cvss_av is None:
        return UNDER_INVESTIGATION, "no CVSS Attack Vector available for this CVE"

    candidates = AV_VECTORS.get(cvss_av, set())
    overlap = candidates & present
    shown = ", ".join(sorted(overlap)) or "none"

    # Common to every AV: the asset carries none of the vectors this AV can ride,
    # so the vulnerability cannot be reached on this asset.
    if not overlap:
        return (NOT_AFFECTED,
                "the asset carries none of the attack vectors AV:%s requires" % cvss_av)

    # AV:L - a local action can be triggered down any path the attacker already has.
    if cvss_av == "L":
        return AFFECTED, "AV:L - a local action is reachable via a present vector (%s)" % shown

    # AV:N / AV:A - a network-borne exploit. If it needs a specific protocol or
    # interface, the asset must carry a matching one (spec 3.1 / 3.2). Unknown
    # requirement is resolved conservatively: not AFFECTED, UNDER_INVESTIGATION.
    if cvss_av in ("N", "A"):
        required = extra.get("protocol_required")
        if required is None:
            return (UNDER_INVESTIGATION,
                    "AV:%s - whether a specific protocol/interface is required is "
                    "unknown (needs the CVE description)" % cvss_av)
        if required:
            match = extra.get("protocol_match")
            if match is True:
                return AFFECTED, "AV:%s - the required protocol/interface is present" % cvss_av
            if match is False:
                return (NOT_AFFECTED,
                        "AV:%s - the required protocol/interface is not present on the "
                        "asset" % cvss_av)
            return (UNDER_INVESTIGATION,
                    "AV:%s - a specific protocol/interface is required but the asset "
                    "match is unknown" % cvss_av)
        return (AFFECTED,
                "AV:%s - no specific protocol required and a network vector is present "
                "(%s)" % (cvss_av, shown))

    # AV:P - physical. Whether the exploit NEEDS a portable maintenance device (PMMD)
    # decides it (spec 3.4). Unknown necessity is UNDER_INVESTIGATION.
    if cvss_av == "P":
        required = extra.get("pmmd_required")
        if required is True:
            if PMMD in present:
                return AFFECTED, "AV:P - the exploit needs a PMMD and one is present"
            return NOT_AFFECTED, "AV:P - the exploit needs a PMMD but none is present"
        if required is False:
            if PHYSICAL in present:
                return AFFECTED, "AV:P - physical access is present and no PMMD is required"
            return (UNDER_INVESTIGATION,
                    "AV:P - no PMMD required, but no physical-access vector is present; "
                    "unresolved")
        return (UNDER_INVESTIGATION,
                "AV:P - whether the exploit requires a PMMD is unknown (needs the CVE "
                "description)")

    return UNDER_INVESTIGATION, "unrecognised CVSS Attack Vector: %r" % cvss_av


def assess(cvss_av, attrs, extra=None):
    """End to end over one (CVE, asset): fills 4.1 -> 4.2 -> 4.3.

    4.1 gate: if any attribute is unfilled, the attack-vector set cannot be
    trusted, so the whole assessment is UNDER_INVESTIGATION.
    """
    missing = missing_attributes(attrs)
    if missing:
        return {"status": UNDER_INVESTIGATION,
                "reason": "asset attributes not fully entered (%d missing)" % len(missing),
                "missing": missing, "vectors": None}
    present = identify_vectors(attrs)
    status, reason = judge(cvss_av, present, extra)
    return {"status": status, "reason": reason,
            "vectors": sorted(present), "cvss_av": cvss_av}
