# 슬라이드용 — L2/L3/L4 현황 분석 및 실제 사례 (2.2 ICS SBOM 기반 CVE 정밀도 #3)

상세 근거·재현 절차: [L2_L3_L4_CASES.md](L2_L3_L4_CASES.md)
산출: `python tools/measure_l2l3l4.py` → `results/l2l3l4_incidence.json`

---

## 슬라이드 0 — 현황 분석 (정의별 실측)

> 측정 단위 주의: L2·L4는 **SBOM 컴포넌트**, L3는 **(컴포넌트, CVE) 쌍**이 단위다.
> 세 정의 모두 "S/HBOM → CVE DB 매핑의 실패"를 말하므로 CVE 단위로 세면 다른 것을 세게 된다.
> 근거와 재검토 경위: [L2_L3_L4_DEFINITIONS.md](L2_L3_L4_DEFINITIONS.md)

**모집단** — 역생성 SBOM 컴포넌트 **29,792건** / CISA ICS-CERT 어드바이저리 3,847건이 참조하는 CVE **11,550건**

| 계층 | 정의 속 축 | 지표 | 값 |
|---|---|---|---:|
| **L2**<br>컴포넌트명 모호성 | 동일·유사 명칭 | 이름으로 제품을 확정하지 못해 **식별 기권** | **44.0%** |
| | | 이름 유사도만으로 확정된 매칭 | **0건** |
| **L3**<br>버전 적용성 | 버전 표현 불일치 | 기계적 순서 비교가 불가능한 버전 표기 | **9.5%** |
| | CVE 영향 버전 범위 | 버전 경계·정확버전 모두 없어 판정 불가 | **6.2%** |
| | 빌드/패치 조건 | 조치가 **mitigation**(설정·망분리)이라 버전으로 표현 불가 | **75.3%** |
| **L4**<br>식별자 불일치 | CPE | CSAF OT 제품 중 CPE 보유 | **0.16%** |
| | PURL | CSAF OT 제품 중 purl 보유 | **0건** |
| | 제조사명 | 동일 회사가 NVD에 두 벤더 ID로 존재 | **8쌍** |
| | 제품명 | 같은 제품 라인이 복수 제품 ID로 분할, CVE 교집합 | **0건** |

**계층별 한 줄**

| 계층 | 결론 |
|---|---|
| L2 | 형제 모델이 이름으로 안 갈린다 → **식별 기권(미탐)** |
| L3 | 버전 비교로는 닿지 않는 조건이 대부분 → **판단 불가** |
| L4 | 불일치 이전에 **식별자가 없다** → **미탐** |

## 슬라이드 A — 한 장 요약

| 계층 | 대표 실제 사례 | SBOM → NVD | 규모 |
|---|---|---|---|
| **L2** 컴포넌트명 모호성 | Mitsubishi MELSEC-F<br>CVE-2023-4699 | `FX3G-40MT/DS` → 형제 모델 **216종** 중 택1 불가<br>매처 출력 = **기권** (유사도 0.362, 2위와 동점) | 식별 기권율 **44.0%**<br>이름만으로 확정 **0건** |
| **L3** 버전 적용성 | GE Universal Relay<br>ICSA-17-117-01B | `6.02 (excluding V5.83, V5.92…)`<br>→ CPE의 시작/끝 범위로 표현 불가 | 표현 불일치 **9.5%** · 범위 부재 **6.2%**<br>조치가 설정뿐 **75.3%** |
| **L4** 식별자 불일치 | GE Proficy CIMPLICITY | 한 제품 = NVD 제품 ID 2개<br>`ge:cimplicity`(12 CVE) / `ge:intelligent_platforms_…_cimplicity`(10 CVE)<br>**교집합 0건** | CPE 보유 **0.16%** · purl **0건**<br>제품 ID 분할 교집합 **0건** |

> 한 줄 메시지: L2는 **식별 기권(미탐)**, L3는 **판단 불가**, L4는 **미탐**을 만든다.

---

## 슬라이드 B — L2 (컴포넌트명 모호성)

| # | 사례 | 문제의 형태 |
|---|---|---|
| 1 | **Mitsubishi MELSEC-F** · CVE-2023-4699 (ICSA-23-306-03) | CPE 216종이 전부 `fx3g-14mr/ds_firmware`·`fx3u-32mt/es_firmware` 형태. 유사도 1위 0.362 = 2위 → **기권**. Mitsubishi 컴포넌트 기권율 **76.3%** |
| 2 | **LS ELECTRIC XGB/XGK/XGI** · CVE-2022-2758 (ICSA-22-228-02) | CPE 235종에 엔지니어링 S/W(`xg5000`) + PLC 펌웨어 234종 혼재 → **장비 ≠ 툴 구분 불가**. 1·2위 격차 0.030으로 기권 |
| 3 | **Siemens SCALANCE X204RNA** · CVE-2022-46352 (ICSA-22-349-02) | CPE 제품명이 주문번호 자체: `6gk5204-0ba00-2mb2_firmware` 외 4종. 제품명↔CPE명 **문자열 교집합 0**<br>**단 모델번호로는 확정됨**(`model-number` 경로) ← 해법의 방향 |

**→ 시사점:** 채점된 TP의 경로는 **전부 `model-number`(6,954건)**. 이름 유사도만으로 확정된 매칭은 0건이다.
L2의 해법은 유사도 임계 조정이 아니라 **비(非)모호 식별자(모델번호·주문번호) 확보 + 제품 관계 분석**.

**벤더별 식별 기권율** (전체 44.0%, 6,241/14,173)

| 벤더 | 컴포넌트 | 기권율 | precision |
|---|---:|---:|---:|
| Mitsubishi Electric | 1,208 | 76.3% | 0.791 |
| Schneider Electric | 608 | 45.6% | 0.940 |
| Siemens | 6,740 | 31.7% | 0.970 |
| Rockwell Automation | 718 | 29.1% | 0.474 |
| AutomationDirect·JTEKT·FESTO·NXP·Hikvision 등 | — | **100%** | — |

---

## 슬라이드 C — L3 (버전 적용성)

| # | 사례 | 버전 표기 |
|---|---|---|
| 1 | **GE Universal Relay** (ICSA-17-117-01B) | `6.02 (excluding Version 5.83, Version 5.92 and all subsequent minor releases)` — **비연속 집합** |
| 2 | **Siemens Automation License Manager** (ICSA-11-361-01) | `>=4.0 \| <5.1+SP1+Upd1` — SBOM에 `5.1`만 있으면 **SP/Update 적용 여부 불명** |
| 3 | **Rockwell FactoryTalk** (ICSA-11-273-03A) | `>=CPR9-SR1 \| <=CPR9-SR4` — **dotted version 정렬 불가** |
| 4 | **판정 근거의 부재** | CVE-2023-4699(216 CPE)·CVE-2022-2758(235 CPE) 모두 버전 경계 0 → 제품을 맞춰도 **"내 V1.20이 취약한가" 결정 불가** |

**버전 문자열 분포 (역생성 SBOM 22,413건)**

| 표기 유형 | 건수 | 비율 |
|---|---:|---:|
| 접두사 없는 범위식 (`<3.1.1`, `>=9\|<=9.21`) | 8,932 | 39.9% |
| `vers:all/*` (전 버전) | 5,953 | 26.6% |
| `vers:` 범위식 | 5,373 | 24.0% |
| 벤더 고유 표기 (SP/P/R/Update/_) | 2,097 | 9.4% |
| 자연어 | 26 | 0.1% |
| **순수 dotted version** | **32** | **0.1%** |

> 주의: 위 분포는 *표기 다양성*이지 *비교 불가능성*이 아니다. `vers:` 범위식과 접두사 없는
> 범위식은 기계 비교가 된다. **순서 비교가 정의되지 않는 표기는 2,123건(9.5%)** — 벤더 고유
> 표기 2,097 + 자연어 26 — 이 숫자가 정의상 "버전 표현 불일치"에 해당한다.

**빌드/패치 조건 (정의의 세 번째 축, 어드바이저리 CVE 10,791건 기준)**

| 조치 형태 | 건수 | 비율 |
|---|---:|---:|
| **mitigation** — 설정 변경·망 분리 등, 버전 비교로 표현 불가 | 8,131 | **75.3%** |
| `vendor_fix`인데 수정 버전이 **자연어로만** 기재 | 4,914 | 45.5% |
| `vendor_fix`인데 수정 버전 표기 자체가 없음 | 1,273 | 11.8% |
| 수정본 없음 (`none_available` + `no_fix_planned`) | 1,117 | 10.4% |

**→ 시사점:** ICS에서 "고쳤다"는 대개 **새 버전이 아니라 운영 조치**다.
버전 범위 비교만으로는 취약 여부를 끝까지 결정할 수 없다.

---

## 슬라이드 D — L4 (식별자 불일치)

**(1) 같은 제품, 다른 NVD 제품 ID — 교집합 0**

| GE Proficy CIMPLICITY | 커버 CVE | 시기 |
|---|---:|---|
| `ge:cimplicity` | 12건 | 2016~2022 |
| `ge:intelligent_platforms_proficy_hmi/scada_cimplicity` | 10건 | 2012~2013 |
| **중복** | **0건** | SBOM 1줄 → 어느 쪽을 골라도 **나머지 전부 미탐** |

**(2) 어드바이저리 벤더 ≠ CPE 벤더**

| 어드바이저리 | CPE 벤더 | 영향 CVE |
|---|---|---:|
| Delta Electronics | `deltaww` | 166 |
| ABB (FOX515T, Ellipse) | `hitachienergy` | 19 |
| Hitachi Energy | `hitachi` | 4 |
| AVEVA (Vijeo Citect) | `schneiderelectric` | 2 |

**(3) NVD 내부 벤더 ID 중복 — 정규화하면 충돌하는 8쌍**

`schneider-electric`(1,462) / `schneider_electric`(6) · `mitsubishielectric`(2,417) / `mitsubishi_electric`(1) · `3ssoftware`(3) / `3s-software`(101) · `wecon`(2) / `we-con`(40) · `sierrawireless`(62) / `sierra_wireless`(6) · `digitalalertsystems`(10) / `digital_alert_systems`(2) · `cambiumnetworks`(22) / `cambium_networks`(8) · `hanwhasecurity`(1) / `hanwha-security`(2)

정규화로도 안 잡히는 것: `mitsubishi`(263행, MELSEC iQ-R) 와 `mitsubishielectric`(2,417행)이 **동일 회사의 별개 벤더 ID**

**(4) 불일치 이전에 "부재"가 기본값**

- CISA CSAF OT 제품 28,631건 중 CPE 보유 **47건(0.16%)**, purl **0건**
- 역생성 SBOM 컴포넌트 29,792건 중 CPE 없음 **29,321건(98.4%)**

---

## 측정 범위 (각주용)

- 모집단: CISA ICS-CERT 어드바이저리 3,847건이 참조하는 CVE **11,550건** (NVD 조회 성공 11,314건)
- L2/L3/L4 비율: `tools/measure_l2l3l4.py` → `results/l2l3l4_incidence.json`
- 한계: `data/nvd_cpe_raw.json`은 CVE당 벤더를 최대 4개만 보관하므로, 어드바이저리 벤더가
  5번째 이후에 오는 CVE는 L4로 과대 계상될 수 있다 (`layer_cap_uncertain` 462건).
- 세 축은 **배타적이지 않다.** 중첩표 참조.
