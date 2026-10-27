#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE가 환경에 요구하는 것을 구조화한다 — 운영맥락 대조의 왼쪽 절반.

docs/ICSVEX.md §2 가 LLM을 배치하는 첫 번째 자리가 여기다: CVE 설명과 벤더
권고문 같은 비정형 텍스트에서 "무엇이 켜져 있어야 / 어떤 프로토콜을 써야 /
어떤 권한이 있어야 악용되는가"를 뽑아낸다. 뽑은 결과는 src/oc_context.evaluate
가 자산 사실과 대조한다.

두 개의 공급원, 섞지 않는다
---------------------------
  CVSS 벡터   기계 판독 가능하고 NVD가 매긴 것이다. AV/PR/UI 는 여기서 온다.
              추측이 끼어들 자리가 없으므로 `evidence: "cvss"` 로 표시한다.

  CVE 서술문  "웹 관리 인터페이스가 활성화된 경우", "Modbus/TCP 를 통해" 같은
              조건은 벡터에 없고 문장에만 있다. 여기서 뽑은 것은
              `evidence: "text"` 이며 원문 구간(`quote`)을 반드시 함께 남긴다.

둘을 섞으면 심사에서 "이 조건은 어디서 나왔는가"에 답할 수 없다. 특히 텍스트
추출은 틀릴 수 있고, 틀린 조건 하나가 `not_affected` 를 만들어내면 그것이 바로
문서가 막으려는 거짓 해제다. 그래서 텍스트에서 나온 조건은 기본적으로
**해제 권한이 없다**(`can_refute: False`) — 사람이 확인해 승격시켜야 한다.

LLM은 선택이다
--------------
`extract(..., llm=None)` 이면 결정적 규칙만 돌아간다. 규칙만으로도 CVSS 절반은
완전히 채워지고, 텍스트 절반은 보수적으로 비어 있게 된다 — 비어 있는 것은
`unknown` 이 되고 unknown 은 아무것도 해제하지 못하므로 안전한 실패다.
LLM을 붙이면 텍스트 절반의 회수율이 올라간다. 정밀도 목표(>90%)는 해제 쪽에
걸려 있으므로, 회수율을 올리는 쪽이 LLM이고 안전장치는 규칙이 쥔다.
"""
import re

# CVSS AV -> 공격 채널. oc_context._channel 이 이 어휘를 받는다.
_AV_CHANNEL = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}

# 서술문에서 프로토콜을 건질 때 쓰는 어휘. ICS 프로토콜을 우선하고, 범용
# 프로토콜은 오탐이 많아 "over/via/through <proto>" 형태일 때만 받는다.
_ICS_PROTOCOLS = [
    "modbus", "modbus/tcp", "dnp3", "ethernet/ip", "ethercat", "profinet",
    "profibus", "opc ua", "opc-ua", "opcua", "opc da", "bacnet", "iec 61850",
    "iec 60870-5-104", "iec-104", "mms", "goose", "s7comm", "fins", "cip",
    "hart", "lonworks", "mqtt", "cc-link", "melsec", "slmp",
]
_GENERIC_PROTOCOLS = ["http", "https", "ftp", "tftp", "telnet", "ssh", "snmp",
                      "smb", "ldap", "rdp", "ntp", "dns", "sip", "rtsp"]

# "~가 활성화된 경우에만" 류의 조건절. 이 패턴에 걸린 것만 required_features 로
# 올라간다 - 설명에 단어가 등장한다는 사실만으로 조건을 만들면 자산 쪽에서
# 영원히 unknown 이 나오고, 그 unknown 이 전부 under_investigation 이 되어
# 판정률을 조용히 0 으로 만든다.
_FEATURE_COND = re.compile(
    r"(?:only\s+)?(?:if|when|where|provided\s+that)\s+(?:the\s+)?"
    r"([A-Za-z][A-Za-z0-9 _/\-]{2,40}?)\s+"
    r"(?:is|are|has been)\s+(enabled|activated|configured|turned on|in use)",
    re.I)
_FEATURE_REQ = re.compile(
    r"requires?\s+(?:that\s+)?(?:the\s+)?"
    r"([A-Za-z][A-Za-z0-9 _/\-]{2,40}?)\s+(?:to\s+be\s+|is\s+|be\s+)"
    r"(enabled|activated|configured|running)", re.I)

_SERVICE_HINT = re.compile(
    r"\b(web (?:admin|management|server|interface|ui)|"
    r"management interface|admin(?:istrative)? interface|"
    r"telnet service|ftp server|ssh server|snmp agent|"
    r"opc ua server|web service|rest api|soap api)\b", re.I)


def from_cvss(vector):
    """CVSS 벡터가 말하는 전제조건. 추측 없음.

    요구를 *서술하는* 메트릭만 돌려준다. PR:N / UI:N / AC:L 은 요구의 **부재**를
    말하므로 대조할 것이 없고, 따라서 조건 목록에 넣지 않는다. 이 구분이
    없으면 "PR:N 이니까 권한 조건 불충족"이라는 뒤집힌 추론이 나온다.
    """
    out = {}
    if not vector:
        return out
    m = dict(p.split(":", 1) for p in str(vector).split("/")
             if ":" in p and len(p.split(":", 1)[0]) <= 3)
    av = m.get("AV")
    if av in _AV_CHANNEL:
        out["attack_channel"] = _AV_CHANNEL[av]
    if m.get("PR") in ("L", "H"):
        out["requires_privileges"] = {"L": "low", "H": "high"}[m["PR"]]
    if m.get("UI") == "R":
        out["requires_user_interaction"] = True
    # AC:H 는 공격자 쪽 운(race, 메모리 배치)이지 자산의 속성이 아니다. 자산
    # 사실로 반박할 수 없으므로 조건으로 만들지 않고 꼬리표만 남긴다.
    if m.get("AC") == "H":
        out["attacker_side_luck"] = True
    return out


def from_text(description):
    """서술문에서 프로토콜 / 서비스 / 기능 조건을 건진다.

    보수적으로 동작한다: 확신이 없으면 비워 둔다. 비어 있으면 대조 결과가
    unknown 이 되고 unknown 은 해제하지 못하므로, 놓치는 쪽이 틀리는 쪽보다
    안전하다.
    """
    if not description:
        return {}
    text = " ".join(str(description).split())
    low = text.lower()
    out = {"protocols": [], "services": [], "features": [], "quotes": {}}

    for p in _ICS_PROTOCOLS:
        if re.search(r"(?<![a-z0-9])" + re.escape(p) + r"(?![a-z0-9])", low):
            out["protocols"].append(p)
    for p in _GENERIC_PROTOCOLS:
        if re.search(r"\b(?:over|via|through|using)\s+" + re.escape(p) + r"\b", low):
            out["protocols"].append(p)

    for m in _SERVICE_HINT.finditer(text):
        out["services"].append(m.group(1).strip().lower())

    for rx in (_FEATURE_COND, _FEATURE_REQ):
        for m in rx.finditer(text):
            feat = m.group(1).strip().lower()
            if 2 < len(feat) <= 40:
                out["features"].append(feat)
                out["quotes"][feat] = _window(text, m.start(), m.end())

    for k in ("protocols", "services", "features"):
        out[k] = _dedupe(out[k])
    return out


def _dedupe(names):
    """겹치는 이름 하나만 남긴다 — 더 구체적인 쪽.

    "modbus" 와 "modbus/tcp" 가 둘 다 걸리면 조건이 두 개가 되고, 운영자는 같은
    사실을 두 번 적어야 하며, 한 쪽만 적으면 나머지가 unknown 으로 남아 판정이
    유보된다. 한쪽이 다른 쪽의 부분 문자열이면 긴 쪽만 남긴다.
    """
    uniq = sorted(set(n.strip().lower() for n in names if n and n.strip()))
    return [n for n in uniq
            if not any(o != n and n in o for o in uniq)]


# 서술문에서 함수 이름을 건지는 패턴. CFG 팔(src/cfg_vex.py)이 "무엇을 찾을지"를
# 여기서 받는다. 이름을 못 찾으면 그 팔은 판정을 유보한다 - 찾을 대상을 모르는 채
# "없다"고 말하는 것이 바로 거짓 해제의 전형이기 때문이다.
_FUNC_PAREN = re.compile(r"\b([a-zA-Z_][A-Za-z0-9_]{2,60})\s*\(\s*\)")
_FUNC_WORD = re.compile(
    r"\b(?:the\s+)?([a-zA-Z_][A-Za-z0-9_]{2,60})\s+"
    r"(?:function|method|routine|handler)\b", re.I)
_FUNC_IN = re.compile(
    r"\b(?:in|within|inside)\s+(?:the\s+)?([a-z_][A-Za-z0-9_]{2,60})\(\)", re.I)

# 영어 단어가 함수처럼 보이는 경우를 쳐낸다. "the parsing function" 의 parsing 은
# 함수 이름이 아니다.
_NOT_A_FUNC = {
    "parsing", "handling", "processing", "validation", "authentication",
    "affected", "vulnerable", "following", "remote", "local", "above",
    "certain", "specific", "this", "that", "which", "where", "these",
    "callback", "hash", "crypto", "memory", "buffer", "string", "input",
}


def vulnerable_functions(description, extra=None):
    """CVE 서술문이 지목하는 함수 이름들.

    과하게 건지지 않는 쪽으로 기운다. 틀린 이름을 넘기면 CFG 팔이 "그 함수가
    트리에 없다"며 `vulnerable_code_not_present` 를 낼 수 있는데, 그것은 존재하는
    취약점을 해제해 버리는 가장 나쁜 실패다. 비워서 유보되는 쪽이 낫다.
    """
    names = []
    if description:
        text = " ".join(str(description).split())
        names += _FUNC_PAREN.findall(text)
        names += _FUNC_IN.findall(text)
        names += [n for n in _FUNC_WORD.findall(text) if "_" in n or n.islower()]
    names += list(extra or [])
    out = []
    for n in names:
        k = n.strip()
        if k.lower() in _NOT_A_FUNC or len(k) < 3:
            continue
        # 소문자/밑줄 또는 camelCase 만 함수 이름으로 받는다. 평범한 영어
        # 단어보다 식별자처럼 보이는 것에 가중치를 두는 싸구려 신호지만,
        # 오탐을 크게 줄인다.
        if "_" in k or re.search(r"[a-z][A-Z]", k) or k.islower():
            if k not in out:
                out.append(k)
    return out


def _window(text, a, b, pad=60):
    """원문 근거 구간. 조건마다 출처 문장을 들고 다녀야 검토가 가능하다."""
    s, e = max(0, a - pad), min(len(text), b + pad)
    return ("…" if s else "") + text[s:e].strip() + ("…" if e < len(text) else "")


def extract(cve, vector=None, description=None, llm=None):
    """한 CVE의 전제조건 묶음.

    llm : callable(description) -> dict  (선택). 규칙이 놓친 조건을 보탠다.
          돌려준 항목은 전부 evidence="llm" 으로 표시되고 해제 권한이 없다.
    """
    req = {"cve": cve, "evidence": {}}
    req.update(from_cvss(vector))
    for k in ("attack_channel", "requires_privileges", "requires_user_interaction"):
        if k in req:
            req["evidence"][k] = "cvss"

    t = from_text(description)
    req["required_protocols"] = list(t.get("protocols") or [])
    req["required_services"] = list(t.get("services") or [])
    req["required_features"] = list(t.get("features") or [])
    req["required_config"] = []
    req["quotes"] = dict(t.get("quotes") or {})

    if llm:
        try:
            add = llm(description) or {}
        except Exception as e:                      # LLM 실패가 판정을 막지 않는다
            add = {}
            req["llm_error"] = str(e)[:200]
        for k in ("required_protocols", "required_services",
                  "required_features", "required_config"):
            for v in (add.get(k) or []):
                if v not in req[k]:
                    req[k].append(v)
                    req["evidence"][str(v)] = "llm"
        req["quotes"].update(add.get("quotes") or {})

    for k in ("required_protocols", "required_services", "required_features"):
        for v in req[k]:
            req["evidence"].setdefault(str(v), "text")

    # 텍스트/LLM 에서 나온 조건은 기본적으로 해제 권한이 없다. 사람이 확인하면
    # 올려 준다 (UI 의 '근거 확인' 체크).
    req["refutable"] = sorted(k for k, v in req["evidence"].items() if v == "cvss")
    return req


if __name__ == "__main__":
    import json
    demo = ("A vulnerability in the web management interface of the device allows "
            "an unauthenticated remote attacker to cause a denial of service over "
            "Modbus/TCP. The issue is only exploitable if the web admin interface "
            "is enabled.")
    r = extract("CVE-0000-0000", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", demo)
    print(json.dumps(r, ensure_ascii=False, indent=2))
