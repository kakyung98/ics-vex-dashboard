# L2 / L3 / L4 실제 사례 (ICS S/HBOM 기반 CVE 식별 한계점)

슬라이드 `2.2 ICS SBOM 기반 CVE 정밀도(#3)`의 L2·L3·L4 근거 사례.
모든 수치는 이 저장소의 로컬 NVD 전수 센서스(`data/nvd_cpe_raw.json`, CVE 11,314건)와
CISA ICS-CERT 역생성 SBOM(`reverse_sbom/*.json`, 컴포넌트 29,792건)에서 계산했다.

---

## L2 — Component Name Ambiguity (컴포넌트명 모호성)

### 사례 L2-1. Mitsubishi Electric MELSEC-F 시리즈 — 형제 모델 216종, 식별 포기
- SBOM 컴포넌트: `Mitsubishi Electric MELSEC-F series CPU module FX3G-40MT/DS`
- CVE-2023-4699 (ICSA-23-306-03)의 NVD CPE는 **216개 제품**, 전부
  `fx3g-14mr/ds_firmware`, `fx3g-14mt/es-a_firmware`, `fx3u-32mt/es_firmware` …
  형태의 거의 동일한 이름.
- 현행 매처(`src/cpe_match_l0l3.identify_product`)의 실제 출력:
  `(None, 'ambiguous (premium_ethernet_module_tsxp572634m 0.362/next 0.362)')`
  → 최고 유사도 0.362, 2위와 **동점**. 즉 오매칭이 아니라 **기권(abstain)**,
  결과적으로 **미탐**이다. Mitsubishi Electric 컴포넌트의 기권율은 **76.3%**
  (922/1,208, `results/cpe_match_precision.json`).
- 더 근본적으로, 같은 벤더가 216개 제품을 앵커하므로 **정답(ground truth)조차 확정할 수 없다.**
  어드바이저리의 `FX3G-40MT/DS`가 NVD의 어느 제품 ID에 대응하는지 어떤 권위도 말해주지 않아,
  GT 빌더는 이런 케이스를 `_ambiguous_product`로 표시하고 채점에서 제외한다(25,116건 held out).
- 출처: https://www.cisa.gov/news-events/ics-advisories/icsa-23-306-03

### 사례 L2-2. LS ELECTRIC XGB/XGK/XGI — 장비명이 엔지니어링 S/W로 흡수
- SBOM 컴포넌트: `LS ELECTRIC XGB-XBCH <V1.90`, `XGK-CPUU/H/A/S/E <V3.50`, `XGR-CPUH <V1.80` …
- CVE-2022-2758 (ICSA-22-228-02)의 NVD CPE는 **235개**: `xg5000`(PC용 엔지니어링 툴) +
  `xbc-dn10e_firmware` 등 PLC 펌웨어 234종이 한 CVE에 섞여 있다.
- 즉 하나의 CVE 안에서 **장비(PLC)와 그 장비를 프로그래밍하는 소프트웨어가 구분되지 않는다.**
  `XGB-XBCH`에 대한 매처 출력도 기권: `ambiguous (electric's_proficy 0.462/next 0.432)`
  — 1·2위 격차가 0.030에 불과해 임계를 넘지 못한다.
- GT 쪽에서도 `_anchored_products`가 235종이라 제품 동일성을 판정할 수 없다.
- 출처: https://www.cisa.gov/news-events/ics-advisories/icsa-22-228-02

### 사례 L2-3. Siemens SCALANCE X204RNA — 주문번호가 곧 제품명
- SBOM 컴포넌트: `Siemens SCALANCE X204RNA (HSR) (6GK5204-0BA00-2MB2) <V3.2.7`
- CVE-2022-46352 (ICSA-22-349-02)의 CPE 5종은 전부 **주문번호(MLFB)** 자체:
  `6gk5204-0ba00-2kb2_firmware`, `6gk5204-0ba00-2mb2_firmware`,
  `6gk5204-0bs00-2na3_firmware`, `6gk5204-0bs00-3la3_firmware`, `6gk5204-0bs00-3pa3_firmware`.
- 사람이 읽는 제품명("SCALANCE X204RNA")과 CPE 제품명(주문번호)이 **문자열 교집합이 0**이라,
  이름 유사도로는 영원히 닿지 않는다. 실제로 `_ro_best`는 0.462/차순위 0.447로 기권선 아래다.
- **다만 이 케이스는 풀린다.** 이름에 주문번호가 들어 있어 `identify_product`가
  `('6GK5204-0BA00-2MB2', 'model-number')`로 확정한다.
  → L2의 해법은 유사도 개선이 아니라 **모델번호 같은 비(非)모호 식별자의 확보**임을 보여주는 대조군.
- 출처: https://www.cisa.gov/news-events/ics-advisories/icsa-22-349-02

> **규모**
> - 모호 케이스: `data/cpe_match_eval_ambig.jsonl` 41,868건 중 **25,184건(60.2%)** 이
>   `_ambiguous_product` — 형제 모델이 여럿이라 제품 동일성을 판정할 수 없는 케이스.
> - 식별 기권율: 전체 **44.0%** (6,241/14,173). 벤더별로 Mitsubishi Electric 76.3%,
>   Schneider Electric 45.6%, Siemens 31.7%이고, AutomationDirect·JTEKT·FESTO·NXP·
>   Hikvision 등은 **100%**(제품명 외 식별자가 전혀 없음).
> - 채점된 TP의 경로는 전부 `model-number` (6,954건). **이름 유사도만으로 확정된 매칭은 없다.**

---

## L3 — Version Applicability (버전 적용성)

### 사례 L3-1. GE Universal Relay — 예외절이 붙은 자연어 버전
- 어드바이저리 버전 표기: `6.02 (excluding Version 5.83, Version 5.92 and all subsequent minor releases)`
- CPE의 `startIncluding/endExcluding` 모델로는 "6.02인데 5.83·5.92와 그 이후 마이너는 제외"라는
  **비연속 집합**을 표현할 수 없다.
- 출처: ICSA-17-117-01B

### 사례 L3-2. Siemens Automation License Manager — SP/Update 합성 표기
- 버전 범위: `>=4.0|<5.1+SP1+Upd1`, `>=2.0|<5.1+SP1+Upd2` (ICSA-11-361-01)
- SBOM에 `5.1`만 적히면 SP1·Upd1 적용 여부를 알 수 없어 적용성 판단이 불가.
- 같은 유형: Rockwell FactoryTalk `>=CPR9-SR1|<=CPR9-SR4` (ICSA-11-273-03A),
  Beckhoff TwinCAT `2.10|2.11|2.11R2` (ICSA-11-279-04),
  Schneider 140NOE77101 `<=Firmware_V4.9` (ICSA-12-018-01B).
  어느 것도 dotted-version 비교로 정렬되지 않는다.

### 사례 L3-3. 버전 판정 근거가 아예 없는 CVE
- CPE는 있으나 **버전 경계(start/end)가 전혀 없는 CVE 2,189건** (CPE 보유 10,059건 중 21.8%).
  단, 이 중 1,474건은 경계 대신 **정확 버전을 열거**하므로 판정은 가능하다.
- 경계도 정확 버전도 없어 **어떤 SBOM 버전도 판정할 수 없는 CVE는 715건** — 이쪽이 정직한 L3 수치.
- 앞의 L2-1/L2-2가 그 예: CVE-2023-4699(216 CPE)·CVE-2022-2758(235 CPE) 모두 버전 경계 0.
  → 제품을 맞춰도 "내 펌웨어 V1.20이 취약한가"는 결정 불가.

> 규모 (`reverse_sbom` 버전 문자열 22,413건):
> `vers:all/*` 전 버전 5,953건(26.6%), 벤더 고유 표기(SP/P/R/Update/_) 2,097건(9.4%),
> 접두사 없는 범위식(`<3.1.1`, `>=9|<=9.21`) 8,932건(39.9%), 자연어 26건.
> 순수 dotted version은 **32건(0.14%)** 뿐이다.

---

## L4 — Identifier Inconsistency (식별자 불일치)

### 사례 L4-1. GE Proficy CIMPLICITY — 한 제품에 NVD 제품 ID 두 개, 교집합 0
- `ge:cimplicity` → CVE 12건 (CVE-2016-5787, CVE-2020-6992, CVE-2022-21798 …)
- `ge:intelligent_platforms_proficy_hmi/scada_cimplicity` → CVE 10건 (CVE-2012-4689, CVE-2013-0653 …)
- **두 집합의 중복은 0건.** SBOM이 `GE Proficy CIMPLICITY 8.2` 하나로 적혀 있으면
  어느 쪽 ID로 매칭하든 나머지 10~12건을 통째로 미탐한다 (2014년 전후로 ID가 갈렸다).

### 사례 L4-1b. Advantech WebAccess — 한 제품 라인에 NVD 제품 ID 4개, 모두 쌍별 교집합 0
| NVD 제품 ID | 커버 CVE |
|---|---:|
| `advantech:webaccess` | 91 |
| `advantech:advantech_webaccess` (벤더명이 제품명에 중복) | 42 |
| `advantech:webaccess\/scada` | 23 |
| `advantech:webaccess_hmi_designer` | 6 |

**6쌍 모두 교집합 0건.** SBOM에 `Advantech WebAccess 8.4` 한 줄이면 어느 ID로 매칭하든
나머지 최대 71건을 미탐한다. CIMPLICITY(2분할)보다 심한 **4분할** 사례.

같은 유형: `siemens:simatic_wincc`(29) vs `siemens:wincc`(43) 교집합 0,
`codesys:development_system_v3`(19) vs `codesys:development_system`(41) 교집합 0.

### 사례 L4-2. Delta Electronics vs CPE 벤더 `deltaww`
- CISA 어드바이저리 벤더 문자열 `Delta Electronics`,
  NVD CPE 벤더는 `deltaww` — 문자열 정규화로도 이어지지 않는다.
- 영향 CVE **166건** (예: CVE-2018-7494, ICSA-18-058-02).
- 이 별칭을 넣지 않았을 때 측정값이 컴포넌트 계층 28.0% → 35.8%로 왜곡됐다
  (`tools/measure_sbom_cpe_limits.py` 주석 참조).

### 사례 L4-3. NVD 내부의 벤더 ID 중복 — 같은 회사, 다른 철자
정규화하면 충돌하는 CPE 벤더 쌍이 이 코퍼스에서 **8쌍**:

| 같은 회사 | NVD CPE 벤더 ID 두 가지 | CPE 행 수 |
|---|---|---|
| Schneider Electric | `schneider-electric` / `schneider_electric` | 1,462 / 6 |
| Mitsubishi Electric | `mitsubishielectric` / `mitsubishi_electric` | 2,417 / 1 |
| WECON | `wecon` / `we-con` | 2 / 40 |
| Sierra Wireless | `sierrawireless` / `sierra_wireless` | 62 / 6 |
| 3S Software | `3ssoftware` / `3s-software` | 3 / 101 |
| Digital Alert Systems | `digitalalertsystems` / `digital_alert_systems` | 10 / 2 |
| Hanwha | `hanwhasecurity` / `hanwha-security` | 1 / 2 |
| Cambium Networks | `cambiumnetworks` / `cambium_networks` | 22 / 8 |

정규화로도 안 잡히는 것: `mitsubishi`(263행, MELSEC iQ-R 계열) 와
`mitsubishielectric`(2,417행)이 **동일 회사의 서로 다른 벤더 ID**로 공존.

### 사례 L4-4. 사업 이관으로 벤더가 바뀐 경우
- `ABB FOX515T`(ICSA-17-304-01), `ABB Ellipse`(ICSA-17-353-01) → CPE 벤더는 `hitachienergy`.
  어드바이저리는 ABB, NVD는 Hitachi Energy. 영향 CVE **19건**.
- `AVEVA Vijeo Citect / CitectSCADA`(ICSA-18-331-01) → CPE 벤더 `schneiderelectric`. 2건.
- `Hitachi Energy` → `hitachi` 4건.

### 사례 L4-5. 식별자 자체의 부재
- CISA CSAF의 OT 제품 **28,631건 중 CPE를 가진 것은 47건(0.16%)**, purl은 **0건**.
- 역생성 SBOM 컴포넌트 29,792건 중 CPE 없음 **29,321건(98.4%)**.
  → L4는 "불일치" 이전에 "식별자가 없음"이 기본값이다.

---

## 재현

```bash
python tools/measure_sbom_cpe_limits.py   # results/sbom_cpe_limits.json
python tools/survey_cpe_all.py            # data/nvd_cpe_raw.json
```
