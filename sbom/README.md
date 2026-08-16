# ICS SBOM 참조 데이터셋 (CycloneDX 1.7)

산업제어시스템(ICS/OT) 자산 **1,000종**에 대한 CycloneDX 1.7 형식 SBOM 예시 데이터셋입니다.
KISA `SBOM 데이터필드 정의-CycloneDX.xlsx` 필드 정의와 `1_2_1_2_VxWorks_RTOS_SBOM 샘플.jsonc`
문서 구조를 그대로 따르되, 대상 컴포넌트를 ICS 자산(PLC, RTU, IED, HMI, SCADA, DCS, SIS 등)으로 치환했습니다.

## ⚠️ 합성 데이터 고지

본 데이터셋은 **연구·시험용 합성(synthetic) 데이터**입니다.

- 벤더명·제품 계열명·OSS 버전은 실존 명칭을 참고했으나, **실제 제품의 실제 부품 구성이 아닙니다.**
- 해시, 시리얼번호, 연락처, URL(`example.invalid`)은 모두 가공된 placeholder입니다.
- 각 문서의 최상위 component에 `dataset:synthetic = "true"` 와 `dataset:disclaimer` property로 명시되어 있습니다.
- 실제 자산 인벤토리나 벤더 공식 SBOM으로 사용하거나 배포해서는 안 됩니다.

## 파일 구성

| 경로 | 설명 |
|---|---|
| `ICS_XXXX_<vendor>_<product>_SBOM.json` | SBOM 본문 1,000개 (UTF-8, CycloneDX 1.7) |
| `index.csv` | 자산 인덱스 — 파일별 벤더/제품/장비유형/Purdue 레벨/섹터/프로토콜 등 요약 |
| `ground_truth_vulnerable_components.csv` | **VEX 판정 정답셋** — 알려진 CVE가 존재하는 컴포넌트·버전 매핑 (5,121행) |
| `../tools/generate_ics_sbom.py` | 결정적(deterministic) 생성기. 동일 시드로 재실행 시 동일 결과 |
| `../docs/README-스키마확장.md` | **원본 KISA 샘플 대비 변경 내역** — 신규 property, 신규 필드, 값 변경, 호환성 정리 |

## 데이터셋 통계

- **파일 수**: 1,000 (시리얼번호 중복 0건, dangling 의존성 참조 0건)
- **총 컴포넌트**: 15,563개 (파일당 평균 15.6개)
  - 출처별: 벤더 자체 코드 7,170 · 서드파티 OSS 6,336 · 서드파티 상용 1,057
- **벤더**: 40개사 (Siemens, Rockwell, Schneider, ABB, Mitsubishi, Honeywell, Yokogawa, Emerson, GE Vernova, OMRON, Phoenix Contact, WAGO, Beckhoff, Hitachi Energy, SEL, Moxa, LS ELECTRIC, HD Hyundai 등)
- **장비 유형**: 24종
- **총 용량**: 약 26 MB

### Purdue 레벨 분포

| 레벨 | 계층 | 자산 수 |
|---|---|---|
| 0 | 필드 계측기 (트랜스미터, 머징유닛) | 32 |
| 1 | 기본 제어 (PLC, RTU, IED, DCS 컨트롤러, SIS, 드라이브) | 612 |
| 2 | 감시 제어 (HMI, SCADA 서버, 산업용 스위치) | 179 |
| 3 | 사이트 운영 (Historian, 엔지니어링 워크스테이션, OPC 서버) | 123 |
| 3.5 | IDMZ (프로토콜 게이트웨이, 산업용 방화벽/라우터) | 54 |

### 기반 플랫폼 분포

`proprietary-rtos` 383 · `linux` 273 · `windows` 213 · `vxworks` 90 · `bare-metal` 24 · `java` 9 · `freertos` 8

### 주요 장비 유형

PLC 207 · IED(보호계전기) 72 · HMI 72 · RTU 63 · SCADA 서버 63 ·
엔지니어링 워크스테이션 54 · DCS 컨트롤러 54 · Historian 45 ·
산업용 스위치/방화벽/라우터 · SIS 로직솔버 · VFD 드라이브 · 로봇/CNC/모션 컨트롤러 ·
프로토콜 게이트웨이 · OPC 서버 · BAS 컨트롤러 · 무선 게이트웨이 · 전력량계 · 필드 트랜스미터

## SBOM 문서 구조

KISA 필드 정의를 그대로 따릅니다.

```
bomFormat / specVersion / serialNumber / version
properties[]                     SBOM_CREATION_DATE, SBOM_MODIFY_DATE (KISA 신규 필드)
metadata
  ├─ timestamp
  ├─ lifecycles[].phase          design | build | post-build | operations | decommission
  ├─ manufacturer{}              문서 작성 기관 (name / address / contact)
  ├─ tools.components[]          생성 도구 정보
  ├─ distributionConstraints.tlp CLEAR | GREEN | AMBER | AMBER+STRICT | RED
  └─ component{}                 ★ 대상 ICS 자산 상세 명세
       type / bom-ref / name / version / description / scope / publisher
       purl / cpe / copyright / manufacturer / supplier / tags / hashes
       licenses / pedigree / externalReferences[] / properties[]
dependencies[]                   ref → dependsOn[] (전체 그래프, 순환 없음)
components[]                     내부 패키지·라이브러리·드라이버 인벤토리
```

### ICS 확장 property

원본 CycloneDX 스키마를 훼손하지 않기 위해, ICS 고유 속성은 최상위 component의 `properties[]`에 담았습니다.

| property | 값 예시 | 용도 |
|---|---|---|
| `ics:asset-id` | `ICS-0042` | 자산 고유 식별자 |
| `ics:device-class` | `plc`, `ied`, `rtu`, `sis-logic-solver` | 장비 유형 |
| `ics:purdue-level` | `0`, `1`, `2`, `3`, `3.5` | Purdue 모델 계층 → **VEX 영향도 판정 핵심 변수** |
| `ics:sector` | `power-transmission`, `water-treatment` | 적용 산업 분야 |
| `ics:protocols` | `iec-61850-mms,dnp3,modbus-tcp` | 지원 산업용 프로토콜 |
| `ics:network-exposure` | `isolated-cell`, `dmz-routable`, `remote-accessible` | 네트워크 노출도 → **공격 경로 도달성 판정** |
| `ics:patch-cadence` | `frozen-validated-state`, `on-advisory-only` | 패치 주기 (OT 가용성 제약) |
| `ics:safety-integrity-level` | `SIL2`, `SIL3 (IEC 61508)`, `PLd (ISO 13849)` | 안전 등급 (해당 자산만) |
| `ics:base-platform` | `vxworks`, `linux`, `proprietary-rtos` | 기반 OS/런타임 |
| `dataset:synthetic` | `true` | 합성 데이터 표식 |

### 컴포넌트 계층

각 SBOM은 4개 계층으로 구성됩니다.

1. **기반 플랫폼** — VxWorks / Embedded Linux(Yocto) / QNX Neutrino / Windows IoT / FreeRTOS / Zephyr / 벤더 자체 RTOS / 베어메탈
2. **OSS 부품** — 플랫폼별 현실적 조합 (OpenSSL, BusyBox, zlib, libcurl, lwIP, Linux Kernel, Dropbear, mbedTLS, libxml2, SQLite, Net-SNMP, U-Boot, CODESYS Runtime, Treck TCP/IP, Interpeak IPnet, Log4j, Tomcat 등 45종)
3. **벤더 고유 모듈** — 제어 실행 엔진, I/O 스캐너, 설정 저장소, 진단 로거, 내장 웹 UI, 펌웨어 업데이트 에이전트, 시큐어 부트, 접근 제어, 이중화 관리 등
4. **프로토콜 스택** — Modbus/TCP, DNP3, IEC 61850(MMS/GOOSE/SV), IEC 60870-5-104, EtherNet/IP(CIP), PROFINET, EtherCAT, OPC UA, BACnet/IP, MQTT Sparkplug, HART-IP, CC-Link IE, PRP/HSR 등 30종

## VEX 파이프라인 활용

`ground_truth_vulnerable_components.csv`는 실제 CVE가 존재하는 컴포넌트·버전 조합을 기록한 **정답셋**입니다.

```csv
file,asset_id,bom_ref,component,version,known_cves
ICS_0001_siemens_simatic-s7-1500-cpu-1511-1-pn_SBOM.json,ICS-0001,pkg:oss:openssl,OpenSSL,1.0.2k,CVE-2017-3731;CVE-2017-3732;CVE-2016-7055
```

이를 이용해 다음을 평가할 수 있습니다.

- **SBOM → CVE 매칭 정확도**: purl/CPE 기반 매칭기가 5,005건의 취약 컴포넌트를 얼마나 찾아내는지 (recall), 오탐은 얼마인지 (precision)
- **VEX 상태 판정 로직**: `ics:network-exposure`, `ics:purdue-level`, `dependencies` 그래프를 근거로 `not_affected` / `affected` / `under_investigation` 판정이 타당한지
- **도달성 분석**: 예를 들어 `isolated-cell`에 배치된 Level 1 PLC의 lighttpd 취약점은 `not_affected (vulnerable_code_not_present)` 대신 `not_affected (inline_mitigations_already_exist)` 판정이 적절한지

취약 버전은 URGENT/11(Interpeak IPnet), Ripple20(Treck TCP/IP), Log4Shell, CODESYS Runtime 취약점 등 **ICS 환경에서 실제로 중요했던 사례**를 포함하도록 구성했습니다.

### 공유 구현(shared implementation) 파급 시나리오

여러 벤더가 동일한 상용 스택을 OEM 탑재하는 구조를 의도적으로 재현했습니다.
하나의 CVE가 벤더 경계를 넘어 동시 파급되는 상황을 다룰 수 있는지 검증하는 용도입니다.

| 공유 부품 | 영향 자산 | 영향 벤더 | 대응 사건 |
|---|---|---|---|
| Treck TCP/IP Stack | 336 | 25개사 | Ripple20 (2020) |
| CODESYS Control Runtime | 144 | 9개사 | CODESYS V3 취약점 (2023) |
| Interpeak IPnet | 70 | 6개사 | URGENT/11 (2019) |

`component:origin` property로 부품 출처를 3분류(`third-party-open-source` /
`third-party-commercial` / `vendor-proprietary`)해 두었으므로, 대응 주체와
리드타임이 다른 계층을 분리해 집계할 수 있습니다.

## 재생성

```bash
python tools/generate_ics_sbom.py
```

생성기는 고정 시드(`SEED = 20260415`)를 사용하는 결정적 구현이라, 재실행해도 동일한 1,000개 파일이 나옵니다.
자산 수를 바꾸려면 `TOTAL` 상수를, 제품 카탈로그를 확장하려면 `PRODUCTS` / `OSS` 리스트를 수정하세요.
