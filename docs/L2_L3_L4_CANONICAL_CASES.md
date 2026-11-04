# L2 / L3 / L4 대표 사례 각 1건 — ICSA · CVE · CPE

모든 CPE 문자열은 **NVD API에서 직접 조회해 검증**했다 (`services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`, 2026-10-30).
역생성 SBOM을 쓰지 않는다. 근거는 CISA 어드바이저리(권위 1)와 NVD CPE(권위 2) 두 개뿐이다.

---

## L2 — Component Name Ambiguity
### Mitsubishi Electric MELSEC-F 시리즈

| 항목 | 값 |
|---|---|
| **ICSA** | [ICSA-23-306-03](https://www.cisa.gov/news-events/ics-advisories/icsa-23-306-03) — Mitsubishi Electric MELSEC Series (Update A) |
| **CVE** | [CVE-2023-4699](https://nvd.nist.gov/vuln/detail/CVE-2023-4699) |
| **어드바이저리 제품 표기** | `MELSEC-F series CPU module FX3G-40MT/DS` |
| **NVD CPE 수** | 216 제품 / 432 cpeMatch (제품마다 `:o:` 펌웨어 + `:h:` 하드웨어 쌍) |

`40MT` 한 토큰만 공유하는 CPE가 **17개**다. 정답은 첫 줄 하나뿐:

```
cpe:2.3:o:mitsubishielectric:fx3g-40mt\/ds_firmware:-:*:*:*:*:*:*:*   ← 정답
cpe:2.3:o:mitsubishielectric:fx3g-40mt\/dss_firmware:-:*:*:*:*:*:*:*  ← DSS (S 하나 차이)
cpe:2.3:o:mitsubishielectric:fx3ge-40mt\/ds_firmware:-:*:*:*:*:*:*:*  ← FX3GE (E 하나 차이)
cpe:2.3:o:mitsubishielectric:fx3g-40mt\/es_firmware:-:*:*:*:*:*:*:*
cpe:2.3:o:mitsubishielectric:fx3g-40mt\/es-a_firmware:-:*:*:*:*:*:*:*
cpe:2.3:o:mitsubishielectric:fx3g-40mt\/ess_firmware:-:*:*:*:*:*:*:*
cpe:2.3:o:mitsubishielectric:fx3ga-40mt-cm_firmware:-:*:*:*:*:*:*:*
cpe:2.3:o:mitsubishielectric:fx5uj-40mt\/ds_firmware:-:*:*:*:*:*:*:*
... (fx3ge-40mt/dss, fx3ge-40mt/es, fx3ge-40mt/ess, fx5s-40mt/es,
    fx5s-40mt/ess, fx5uj-40mt/dss, fx5uj-40mt/es, fx5uj-40mt/es-a, fx5uj-40mt/ess)
```

**무엇이 문제인가**: `FX3G-40MT/DS` · `FX3G-40MT/DSS` · `FX3GE-40MT/DS` 는 **한 글자 차이로 다른 제품**이다.
216개 제품군은 `fx3g`(32) `fx3ga`(6) `fx3gc`(2) `fx3ge`(12) `fx3s`(27) `fx3sa`(8) `fx3u`(52)
`fx3uc`(14) `fx5s`(12) `fx5u`(18) `fx5uc`(9) `fx5uj`(24) 로 갈리는데, 접미사 체계가 동일해
**문자열 유사도로는 서열이 생기지 않는다.**

실제 매처(`src/cpe_match_l0l3.identify_product`) 출력:
```
(None, 'ambiguous (premium_ethernet_module_tsxp572634m 0.362/next 0.362)')
```
1위와 2위가 **동점 0.362** → 기권. 오탐이 아니라 **미탐**이다.

---

## L3 — Version Applicability
### GE Multilin Universal Relay

| 항목 | 값 |
|---|---|
| **ICSA** | [ICSA-17-117-01B](https://www.cisa.gov/news-events/ics-advisories/icsa-17-117-01b) — GE Multilin SR, UR, and URplus Protective Relays (Update B) |
| **CVE** | [CVE-2017-7905](https://nvd.nist.gov/vuln/detail/CVE-2017-7905) |
| **어드바이저리 버전 표기** | `6.02 (excluding Version 5.83, Version 5.92 and all subsequent minor releases)` |
| **NVD CPE** | `cpe:2.3:o:ge:multilin_universal_relay_firmware:*:*:*:*:*:*:*:*`<br>`versionEndIncluding: 6.0` |

**불일치가 두 겹이다.**

1. **상한이 다르다.** 어드바이저리는 **6.02**까지 영향, NVD는 **≤ 6.0**.
   → 펌웨어 **6.01 / 6.02** 를 가진 장비는 NVD 기준으로 "영향 없음", CISA 기준으로 "영향 있음".
2. **예외절을 표현할 수 없다.** "5.83 · 5.92 및 그 이후 마이너 릴리스 제외"는 **비연속 집합**인데
   CPE의 적용성 모델은 `versionStart*` / `versionEnd*` 한 쌍뿐이라 구멍 뚫린 범위를 쓸 방법이 없다.

같은 CVE의 다른 모델은 상한이 제각각이라 하나로 묶이지도 않는다:
```
multilin_sr_750_feeder_protection_relay_firmware   versionEndIncluding 5.02
multilin_sr_469_motor_protection_relay_firmware    versionEndIncluding 2.90
multilin_sr_489_generator_protection_relay_firmware versionEndIncluding 1.53
multilin_sr_745_transformer_protection_relay_firmware versionEndIncluding 2.85
multilin_sr_369_motor_protection_relay_firmware    버전 없음(-)
multilin_urplus_d90_firmware / c90 / b95           버전 없음(-)
```

---

## L4 — Identifier Inconsistency
### Advantech WebAccess — 같은 제품, CPE 식별자 3개, CVE 교집합 0

| ICSA | CVE | NVD CPE |
|---|---|---|
| [ICSA-11-094-02B](https://www.cisa.gov/news-events/ics-advisories/icsa-11-094-02b) — Advantech/Broadwin WebAccess RPC Vulnerability | [CVE-2011-4041](https://nvd.nist.gov/vuln/detail/CVE-2011-4041) | `cpe:2.3:a:`**`broadwin`**`:`**`webaccess`**`:*:*:*:*:*:*:*:*` |
| [ICSA-14-079-03](https://www.cisa.gov/news-events/ics-advisories/icsa-14-079-03) — Advantech WebAccess Vulnerabilities | [CVE-2014-0763](https://nvd.nist.gov/vuln/detail/CVE-2014-0763) | `cpe:2.3:a:`**`advantech`**`:`**`advantech_webaccess`**`:*:…` `versionEndIncluding 7.1` |
| [ICSA-14-324-01](https://www.cisa.gov/news-events/ics-advisories/icsa-14-324-01) — Advantech WebAccess Stack-based Buffer Overflow | [CVE-2014-8388](https://nvd.nist.gov/vuln/detail/CVE-2014-8388) | `cpe:2.3:a:`**`advantech`**`:`**`webaccess`**`:*:…` `versionEndIncluding 7.2` |

**세 가지 불일치가 한 제품에 동시에 있다.**

1. **제조사명**: `broadwin` vs `advantech` — Broadwin을 Advantech가 인수했으나 과거 CPE는 그대로.
2. **제품명**: `webaccess` vs `advantech_webaccess` — **벤더명이 제품명에 중복**된 별도 ID.
3. **분할 결과**: 네 ID의 CVE 집합이 **쌍별 교집합 0**.

| CPE 제품 ID | 커버 CVE |
|---|---:|
| `advantech:webaccess` | 91 |
| `advantech:advantech_webaccess` | 42 |
| `advantech:webaccess\/scada` | 23 |
| `advantech:webaccess_hmi_designer` | 6 |

SBOM에 `Advantech WebAccess 7.0` 한 줄이면 어느 ID로 매칭하든 **나머지 최대 71건을 미탐**한다.
(`advantech:webaccess` 를 골랐다면 CVE-2014-0763은 영원히 안 걸린다 — 버전 7.0은 ≤7.1 범위 안인데도.)

---

## 재검증

```bash
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-4699" | python -c "import json,sys; d=json.load(sys.stdin); print(sum(len(n['cpeMatch']) for c in d['vulnerabilities'][0]['cve']['configurations'] for n in c['nodes']))"
```
