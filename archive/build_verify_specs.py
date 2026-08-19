#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
실행 검증 스펙 생성기.

코드 leg 확장 후보군(tier A, OSS 귀속) 전 CVE 에 대해 실행 검증 스펙을 만든다.
각 CVE 를 '원리상 검증 가능한가'로 먼저 분류하고, 가능한 것에 대해서만
빌드/대조에 필요한 정보(repo, 취약 ref, 패치 ref, 빌드 방식)를 채운다.

분류:
  verifiable-c        C/C++ OSS. WSL + AddressSanitizer 로 취약/패치 대조 빌드 가능
  verifiable-python   pip 격리설치로 대조 가능
  blocked-proprietary 폐쇄 소스(CODESYS, IPnet, Treck, SQL Server 등) — 원리상 불가
  blocked-scope       빌드는 가능하나 단위 실행 검증이 비현실적(커널, JDK, .NET 등)
  blocked-no-repo     OSS 이나 저장소 매핑이 없음

취약/패치 ref 결정 순서:
  1) code_evidence.json 에 픽스 커밋이 있으면  vuln = <commit>^ , patched = <commit>
     (릴리스 태그 없이도 정확한 차분 쌍이 나온다 — 가장 신뢰도 높음)
  2) OSS 카탈로그의 versions 목록에서 해당 CVE 를 담은 버전을 취약본으로,
     그 다음 버전을 패치 후보로 사용 (태그명은 프로젝트별 규칙으로 변환)

트리거는 자동 생성할 수 없다. tools/triggers/<CVE>.c 가 있으면 사용하고,
없으면 needs_trigger 로 표시한다. 이것이 남은 수작업의 전부다.

출력: data/verify_specs.json
"""
import csv
import json
import os
import re
import sys

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(BASE, "tools"))
FIND = os.path.join(BASE, "data", "findings.csv")
CODE_EV = os.path.join(BASE, "data", "code_evidence.json")
TRIGGER_DIR = os.path.join(BASE, "tools", "triggers")
OUT = os.path.join(BASE, "data", "verify_specs.json")

# OSS 컴포넌트 -> 저장소 / 빌드 방식.
# tag_fmt 는 버전 문자열 -> git 태그 변환 규칙 ({v} 치환).
REPO_MAP = {
    "zlib":           {"repo": "https://github.com/madler/zlib.git", "lang": "c",
                       "tag_fmt": "v{v}", "build": "configure_static", "lib": "libz.a"},
    "openssl":        {"repo": "https://github.com/openssl/openssl.git", "lang": "c",
                       "tag_fmt": "OpenSSL_{v_underscore}", "build": "openssl", "lib": "libcrypto.a"},
    "expat":          {"repo": "https://github.com/libexpat/libexpat.git", "lang": "c",
                       "tag_fmt": "R_{v_underscore}", "build": "cmake", "lib": "libexpat.a"},
    "libxml2":        {"repo": "https://github.com/GNOME/libxml2.git", "lang": "c",
                       "tag_fmt": "v{v}", "build": "autogen", "lib": ".libs/libxml2.a"},
    "libcurl":        {"repo": "https://github.com/curl/curl.git", "lang": "c",
                       "tag_fmt": "curl-{v_underscore}", "build": "autogen", "lib": "lib/.libs/libcurl.a"},
    "sqlite":         {"repo": "https://github.com/sqlite/sqlite.git", "lang": "c",
                       "tag_fmt": "version-{v}", "build": "configure_static", "lib": "libsqlite3.a"},
    "busybox":        {"repo": "https://git.busybox.net/busybox", "lang": "c",
                       "tag_fmt": "{v}", "build": "make_defconfig", "lib": "busybox"},
    "libssh2":        {"repo": "https://github.com/libssh2/libssh2.git", "lang": "c",
                       "tag_fmt": "libssh2-{v}", "build": "cmake", "lib": "src/libssh2.a"},
    "dnsmasq":        {"repo": "https://thekelleys.org.uk/git/dnsmasq.git", "lang": "c",
                       "tag_fmt": "v{v}", "build": "make_plain", "lib": "src/dnsmasq"},
    "openssh":        {"repo": "https://github.com/openssh/openssh-portable.git", "lang": "c",
                       "tag_fmt": "V_{v_underscore}", "build": "autoreconf", "lib": "libssh.a"},
    "glibc":          {"repo": "https://sourceware.org/git/glibc.git", "lang": "c",
                       "tag_fmt": "glibc-{v}", "build": "glibc", "lib": "libc.so"},
    "wpa_supplicant": {"repo": "https://w1.fi/hostap.git", "lang": "c",
                       "tag_fmt": "hostap_{v_underscore}", "build": "make_plain", "lib": "wpa_supplicant"},
    "u_boot":         {"repo": "https://github.com/u-boot/u-boot.git", "lang": "c",
                       "tag_fmt": "v{v}", "build": "make_defconfig", "lib": "u-boot"},
    "openvpn":        {"repo": "https://github.com/OpenVPN/openvpn.git", "lang": "c",
                       "tag_fmt": "v{v}", "build": "autoreconf", "lib": "src/openvpn/openvpn"},
    "dropbear":       {"repo": "https://github.com/mkj/dropbear.git", "lang": "c",
                       "tag_fmt": "DROPBEAR_{v}", "build": "configure_static", "lib": "dropbear"},
    "libpcap":        {"repo": "https://github.com/the-tcpdump-group/libpcap.git", "lang": "c",
                       "tag_fmt": "libpcap-{v}", "build": "configure_static", "lib": "libpcap.a"},
    "nginx":          {"repo": "https://github.com/nginx/nginx.git", "lang": "c",
                       "tag_fmt": "release-{v}", "build": "nginx", "lib": "objs/nginx"},
    "ntp":            {"repo": "https://github.com/ntp-project/ntp.git", "lang": "c",
                       "tag_fmt": "ntp-{v_dash}", "build": "configure_static", "lib": "libntp/libntp.a"},
    "net_snmp":       {"repo": "https://github.com/net-snmp/net-snmp.git", "lang": "c",
                       "tag_fmt": "v{v}", "build": "configure_static", "lib": "snmplib/.libs/libnetsnmp.a"},
    "mbedtls":        {"repo": "https://github.com/Mbed-TLS/mbedtls.git", "lang": "c",
                       "tag_fmt": "v{v}", "build": "cmake", "lib": "library/libmbedtls.a"},
    "mosquitto":      {"repo": "https://github.com/eclipse/mosquitto.git", "lang": "c",
                       "tag_fmt": "v{v}", "build": "cmake", "lib": "lib/libmosquitto.a"},
    "musl":           {"repo": "https://git.musl-libc.org/git/musl", "lang": "c",
                       "tag_fmt": "v{v}", "build": "configure_static", "lib": "lib/libc.a"},
    "lighttpd":       {"repo": "https://github.com/lighttpd/lighttpd1.4.git", "lang": "c",
                       "tag_fmt": "lighttpd-{v}", "build": "cmake", "lib": "lighttpd"},
    "lwip":           {"repo": "https://github.com/lwip-tcpip/lwip.git", "lang": "c",
                       "tag_fmt": "STABLE-{v_underscore}", "build": "cmake", "lib": "liblwipcore.a"},
    "wolfssl":        {"repo": "https://github.com/wolfSSL/wolfssl.git", "lang": "c",
                       "tag_fmt": "v{v}-stable", "build": "autogen", "lib": "src/.libs/libwolfssl.a"},
    "open62541":      {"repo": "https://github.com/open62541/open62541.git", "lang": "c",
                       "tag_fmt": "v{v}", "build": "cmake", "lib": "bin/libopen62541.a"},
    "libmodbus":      {"repo": "https://github.com/stephane/libmodbus.git", "lang": "c",
                       "tag_fmt": "v{v}", "build": "autogen", "lib": "src/.libs/libmodbus.a"},
    "goahead":        {"repo": "https://github.com/embedthis/goahead.git", "lang": "c",
                       "tag_fmt": "v{v}", "build": "make_plain", "lib": "build/libgo.a"},
    "freertos":       {"repo": "https://github.com/FreeRTOS/FreeRTOS-Kernel.git", "lang": "c",
                       "tag_fmt": "V{v}", "build": "cmake", "lib": "libfreertos_kernel.a"},
    "zephyr":         {"repo": "https://github.com/zephyrproject-rtos/zephyr.git", "lang": "c",
                       "tag_fmt": "v{v}", "build": "cmake", "lib": "libzephyr.a"},
}

# 원리상 실행 검증이 불가능한 컴포넌트와 그 사유.
BLOCKED = {
    "codesys_rt":        ("blocked-proprietary", "CODESYS Control Runtime 은 폐쇄 소스"),
    "ipnet":             ("blocked-proprietary", "Wind River IPnet 스택은 폐쇄 소스"),
    "treck_tcpip":       ("blocked-proprietary", "Treck TCP/IP 스택은 상용 폐쇄 소스"),
    "sqlserver_express": ("blocked-proprietary", "Microsoft SQL Server 는 폐쇄 소스"),
    "vcredist":          ("blocked-proprietary", "Microsoft VC++ 재배포 패키지는 폐쇄 소스"),
    "dotnet":            ("blocked-scope", ".NET 런타임 전체 빌드는 단위 실행 검증 범위를 벗어남"),
    "openjdk":           ("blocked-scope", "JDK 전체 빌드는 단위 실행 검증 범위를 벗어남"),
    "linux_kernel":      ("blocked-scope", "커널 CVE 는 부팅 가능한 대상 환경이 필요"),
    "tomcat":            ("blocked-scope", "JVM 서버 스택 — C ASan 하네스로 다룰 수 없음"),
    "log4j":             ("blocked-scope", "JVM 라이브러리 — C ASan 하네스로 다룰 수 없음"),
    "spring":            ("blocked-scope", "JVM 프레임워크 — C ASan 하네스로 다룰 수 없음"),
    "jackson":           ("blocked-scope", "JVM 라이브러리 — C ASan 하네스로 다룰 수 없음"),
}

# purl/bom-ref 슬러그 -> OSS 카탈로그 키
def ref_to_key(ref):
    return ref.replace("pkg:oss:", "").replace("-", "_")


def tag_for(fmt, v):
    return (fmt.replace("{v_underscore}", v.replace(".", "_"))
               .replace("{v_dash}", v.replace(".", "-"))
               .replace("{v}", v))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    from generate_ics_sbom import OSS

    code_ev = {}
    if os.path.exists(CODE_EV):
        code_ev = json.load(open(CODE_EV, encoding="utf-8"))

    rows = list(csv.DictReader(open(FIND, encoding="utf-8-sig")))
    # OSS 컴포넌트에 귀속된 전 CVE (tier A = 카탈로그 확정, tier C = 어드바이저리 단일 OSS 추론).
    # tier E 는 벤더 폐쇄 펌웨어라 소스 자체가 없어 대상이 아니다.
    oss_rows = [r for r in rows if r["tier"] in ("A", "C")]

    # CVE -> (컴포넌트 키, findings 수). 한 CVE 가 여러 tier 로 붙으면 A 를 우선한다.
    by_cve = {}
    for r in oss_rows:
        key = ref_to_key(r["component"])
        e = by_cve.setdefault(r["cve"], {"key": key, "findings": 0,
                                         "cwe": r["cwe"], "tier": r["tier"]})
        e["findings"] += 1
        if r["tier"] == "A":
            e["tier"] = "A"
            e["key"] = key

    # OSS 카탈로그: 컴포넌트별 (버전 -> CVE 목록), 버전 순서 보존
    ver_index = {}
    for key, spec in OSS.items():
        ver_index[key] = spec.get("versions", [])

    specs = []
    for cve, e in sorted(by_cve.items()):
        key = e["key"]
        spec = {"cve": cve, "cwe": e["cwe"], "component": key, "tier": e["tier"],
                "findings": e["findings"], "status": None, "reason": None,
                "repo": None, "vuln_ref": None, "patched_ref": None,
                "ref_basis": None, "build": None, "lib": None,
                "lang": None, "trigger": None, "needs_trigger": True}

        if key in BLOCKED:
            spec["status"], spec["reason"] = BLOCKED[key]
            spec["needs_trigger"] = False
            specs.append(spec)
            continue

        rm = REPO_MAP.get(key)
        if not rm:
            spec["status"] = "blocked-no-repo"
            spec["reason"] = "OSS 카탈로그에 있으나 저장소 매핑이 정의되지 않음"
            spec["needs_trigger"] = False
            specs.append(spec)
            continue

        spec["repo"] = rm["repo"]
        spec["build"] = rm["build"]
        spec["lib"] = rm["lib"]
        spec["lang"] = rm["lang"]
        spec["status"] = "verifiable-c" if rm["lang"] == "c" else "verifiable-python"

        # ref 결정 1순위: 픽스 커밋 차분
        ce = code_ev.get(cve) or {}
        commit = ce.get("commit")
        if commit and ce.get("vuln_code"):
            spec["vuln_ref"] = "%s^" % commit
            spec["patched_ref"] = commit
            spec["ref_basis"] = "fix-commit-diff"
            if ce.get("repo"):
                spec["repo"] = "https://github.com/%s.git" % ce["repo"]
        else:
            # 2순위: OSS 카탈로그 버전 목록에서 취약본 -> 다음 버전
            vers = ver_index.get(key, [])
            idx = next((i for i, (v, cs) in enumerate(vers) if cve in cs), None)
            if idx is not None:
                vv = vers[idx][0]
                spec["vuln_ref"] = tag_for(rm["tag_fmt"], vv)
                if idx + 1 < len(vers):
                    spec["patched_ref"] = tag_for(rm["tag_fmt"], vers[idx + 1][0])
                    spec["ref_basis"] = "catalog-version-successor"
                else:
                    spec["ref_basis"] = "catalog-version-no-successor"
            else:
                spec["status"] = "blocked-no-version"
                spec["reason"] = "OSS 카탈로그 버전 목록에서 이 CVE 를 찾을 수 없음"
                spec["needs_trigger"] = False

        # 트리거 존재 확인
        tp = os.path.join(TRIGGER_DIR, "%s.c" % cve)
        if os.path.exists(tp):
            spec["trigger"] = os.path.relpath(tp, BASE).replace("\\", "/")
            spec["needs_trigger"] = False

        specs.append(spec)

    os.makedirs(TRIGGER_DIR, exist_ok=True)
    json.dump(specs, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    # 리포트
    import collections
    st = collections.Counter(s["status"] for s in specs)
    fn = collections.Counter()
    for s in specs:
        fn[s["status"]] += s["findings"]
    total_f = sum(s["findings"] for s in specs)
    tc = collections.Counter(s["tier"] for s in specs)
    print("OSS 귀속 전 CVE: %d CVE / %d findings   (tier A %d + tier C %d)\n"
          % (len(specs), total_f, tc["A"], tc["C"]))
    print("%-24s %6s %10s" % ("분류", "CVE", "findings"))
    for k, v in st.most_common():
        print("  %-22s %6d %10d" % (k, v, fn[k]))

    ready = [s for s in specs if s["status"] == "verifiable-c" and not s["needs_trigger"]]
    need = [s for s in specs if s["status"] == "verifiable-c" and s["needs_trigger"]]
    print("\n검증 가능(C) 중:")
    print("  트리거 확보 — 즉시 실행 가능 : %d CVE / %d findings"
          % (len(ready), sum(s["findings"] for s in ready)))
    print("  트리거 미확보 — 수작업 필요  : %d CVE / %d findings"
          % (len(need), sum(s["findings"] for s in need)))
    blocked_f = sum(v for k, v in fn.items() if k.startswith("blocked"))
    print("\n원리상 검증 불가: %d findings (%.1f%%) — 폐쇄 소스/범위 초과"
          % (blocked_f, 100 * blocked_f / total_f))
    print("\noutput: %s" % os.path.relpath(OUT, BASE))


if __name__ == "__main__":
    main()
