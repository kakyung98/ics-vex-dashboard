# ICS SBOM 스키마 확장 설명서

**KISA `SBOM 데이터필드 정의-CycloneDX.xlsx` / `1_2_1_2_VxWorks_RTOS_SBOM 샘플.jsonc` 대비 변경 내역**

---

## 요약

| 구분 | 내용 |
|---|---|
| **필드명 변경** | **없음.** 기존 KISA/CycloneDX 필드는 이름·위치·중첩 구조 모두 원본 그대로 |
| **신규 필드** | 내부 컴포넌트의 `cpe`, `hashes` 2개 (CycloneDX 표준 필드, 샘플에서 미사용이던 것) |
| **신규 property** | 최상위 component에 ICS 확장 12종, 내부 component에 2종 |
| **신규 externalReference 타입** | `advisories` 1종 |
| **값 변경** | 안내문(`"design or build or operations"`)을 실제 단일 값으로 확정, ICS 자산 데이터로 치환 |
| **의도적 미사용** | OSS 부품의 `group` 필드 |

핵심 원칙은 **"스키마는 손대지 않고, CycloneDX가 공식 허용하는 확장 지점(`properties[]`)만 사용한다"** 입니다.
따라서 기존 KISA 필드 정의를 기준으로 만든 파서·검증기는 수정 없이 그대로 동작합니다.

---

## 0. 구조 동일성 검증

원본 샘플과 생성물의 키를 기계적으로 비교한 결과입니다.

```
=== 최상위 키 ===
sample: ['bomFormat','specVersion','serialNumber','version','properties','metadata','dependencies','components']
gen   : ['bomFormat','specVersion','serialNumber','version','properties','metadata','dependencies','components']
                                    ✅ 완전 일치

=== metadata 키 ===
sample: ['timestamp','lifecycles','manufacturer','tools','distributionConstraints','component']
gen   : ['timestamp','lifecycles','manufacturer','tools','distributionConstraints','component']
                                    ✅ 완전 일치

=== metadata.component 키 ===
gen 에만 있음 : ['properties']
sample 에만 있음: []               ✅ 삭제된 필드 없음

=== components[] 항목 키 ===
gen 에만 있음 : ['cpe', 'hashes']  ✅ 삭제된 필드 없음
```

재현 명령:

```bash
python tools/compare_schema.py
```

---

## 1. 새로 추가된 것

### (a) 최상위 component의 `properties[]` — ICS 확장의 핵심

원본 샘플의 `metadata.component`에는 `properties`가 **아예 없었습니다.**
ICS 자산은 "무슨 소프트웨어가 들어있는가"만으로는 위험도를 판정할 수 없고,
**어느 계층에 어떻게 물려 있는가**가 결정적이기 때문에 이 운영 맥락을 여기에 담았습니다.

| property 이름 | 값 예시 | 넣은 이유 |
|---|---|---|
| `ics:asset-id` | `ICS-0032` | 자산 대장 키. 인벤토리·VEX 문서 간 조인 키 |
| `ics:device-class` | `plc`, `ied`, `rtu`, `sis-logic-solver` | 장비 유형 분류 |
| `ics:purdue-level` | `0` / `1` / `2` / `3` / `3.5` | **VEX 영향도 판정 변수.** Level 1 제어기와 Level 3 워크스테이션은 동일 CVE라도 영향이 다름 |
| `ics:network-exposure` | `isolated-cell`, `control-network`, `dmz-routable`, `remote-accessible` | **공격 경로 도달성 판정 변수.** 격리 셀의 웹서버 취약점은 원격 공격 불가 |
| `ics:patch-cadence` | `frozen-validated-state`, `on-advisory-only`, `maintenance-window-quarterly` | OT 가용성 제약. 패치 불가 자산은 보상 통제로 대응해야 함 |
| `ics:safety-integrity-level` | `SIL2`, `SIL3 (IEC 61508)`, `PLd (ISO 13849)` | 안전 등급. 안전 기능 영향 시 대응 우선순위 최상위 |
| `ics:sector` | `power-transmission`, `water-treatment` | 적용 산업 분야 |
| `ics:protocols` | `iec-61850-mms,dnp3,modbus-tcp` | 지원 산업 프로토콜 |
| `ics:base-platform` | `vxworks`, `linux`, `proprietary-rtos` | 기반 OS/런타임 |
| `ics:vendor-model` | `451-5`, `1756-L71` | 벤더 모델 코드 |
| `dataset:synthetic` | `true` | 합성 데이터 표식 |
| `dataset:disclaimer` | (문장) | 실제 제품 구성이 아님을 명시 |

**왜 새 최상위 필드가 아니라 `properties[]`인가**
CycloneDX 스펙은 표준에 없는 정보를 `properties[]`(name/value 쌍)에 담도록 규정합니다.
새 최상위 필드를 만들면 스키마 검증(`cyclonedx validate`)에서 실패하지만,
`properties[]`는 표준 준수를 유지하면서 임의 확장이 가능합니다.

```jsonc
"metadata": {
  "component": {
    "type": "firmware",
    "name": "SEL-451 Protection System 451-5",
    // ... 기존 필드 그대로 ...
    "properties": [                                   // ← 신규 (샘플엔 없던 배열)
      { "name": "ics:purdue-level",     "value": "1" },
      { "name": "ics:network-exposure", "value": "isolated-cell" }
    ]
  }
}
```

### (b) 내부 `components[]`에 `cpe` + `hashes` 추가

샘플의 내부 부품에는 `cpe`가 없었습니다. 그런데 **CPE 없이는 CVE 매칭이 불가능**합니다.

```jsonc
// 샘플 (VxWorks Kernel Core Package) — cpe 없음
{ "type": "library", "bom-ref": "pkg:vxworks:kernel-core",
  "name": "VxWorks Kernel Core Package", "version": "VERSION_PLACEHOLDER",
  "purl": "pkg:generic/vxworks-kernel-core-package@VERSION_PLACEHOLDER" }

// 생성물 (zlib) — cpe / hashes 추가
{ "type": "library", "bom-ref": "pkg:oss:zlib",
  "name": "zlib", "version": "1.2.8",
  "purl": "pkg:generic/zlib@1.2.8",
  "cpe": "cpe:2.3:a:zlib:zlib:1.2.8:*:*:*:*:*:*:*",           // ← 신규
  "hashes": [ { "alg": "SHA-256", "content": "..." } ] }        // ← 신규
```

- **`cpe`** — SBOM→CVE 식별기(`tools/generate_sbom_cve.py`)가 읽는 1순위 키입니다.
  매칭은 `cpe:2.3:a:{vendor}:{product}:{version}` 을 파싱해 (vendor, product, version) 삼중키로 조회하고,
  CPE가 없으면 `purl`로 폴백합니다.
- **`hashes`** — 샘플에선 최상위 component에만 있었습니다. 내부 부품에도 부여해
  변조 탐지 및 동일 부품 식별(서로 다른 자산의 같은 바이너리)에 쓸 수 있게 했습니다.

> 둘 다 **CycloneDX 표준 필드**입니다. 새로 만든 필드가 아니라, 샘플이 쓰지 않던 표준 필드를 활성화한 것입니다.

### (c) 내부 `properties[]`에 항목 2종 추가

중요한 점 — **`module:role`은 신규가 아니라 샘플에 이미 있던 규약**이고, 그대로 계승했습니다.

```jsonc
// 샘플 (VxWorks task-scheduler)
"properties": [ { "name": "module:role", "value": "task-scheduling" } ]

// 생성물 (zlib)
"properties": [
  { "name": "module:role",      "value": "compression" },              // 샘플 규약 계승
  { "name": "component:origin", "value": "third-party-open-source" }   // 신규
]
```

| property | 값 | 용도 |
|---|---|---|
| `component:origin` | `third-party-open-source` / `third-party-commercial` / `vendor-proprietary` | **취약점 대응 주체·리드타임 결정** (아래 표) |
| `protocol:identifier` | `iec-61850-goose`, `dnp3`, `modbus-tcp` 등 | 프로토콜 스택 모듈 식별. 프로토콜 취약점 영향 범위 산정 |

`module:role`에 쓰인 값도 샘플 어휘(`task-scheduling`, `runtime-services`, `network-stack`, `file-service`)를
그대로 두고 ICS 역할(`control-engine`, `io-scanner`, `protocol-stack`, `secure-boot`, `redundancy` 등)을 추가했습니다.

### (d) `externalReferences`에 `advisories` 타입 추가

| 샘플 | 생성물 |
|---|---|
| `documentation` | `documentation` |
| `release-notes` | `release-notes` |
| `bom` (부모 HBOM / 자식 SBOM 링크) | `bom` (부모 HBOM 링크) |
| — | **`advisories`** ← 신규 |

```jsonc
{ "type": "advisories",
  "url": ["https://example.invalid/ics/sel/psirt"],
  "comment": "Vendor PSIRT advisory feed placeholder used by the VEX pipeline" }
```

벤더 PSIRT(제품 보안 사고 대응팀) 권고 피드를 가리키는 자리입니다.
VEX 단계에서 "벤더가 이 CVE에 대해 뭐라고 했는가"를 조회할 진입점이 필요해 추가했습니다.
`advisories`는 CycloneDX `externalReferences.type` 열거값에 이미 정의된 표준 타입입니다.

---

## 2. 필드는 그대로, 값만 바뀐 것

| 필드 | 샘플 값 | ICS 값 |
|---|---|---|
| `metadata.component.type` | `operating-system` 고정 | `firmware` / `application` / `operating-system` (장비별) |
| `version` | `VERSION_PLACEHOLDER` | `5.16.24` 등 실제 버전 문자열 |
| `lifecycles[].phase` | `"design or build or operations"` (선택지 안내문) | `operations` 등 **실제 단일 값** |
| `distributionConstraints.tlp` | `"CLEAR or GREEN or AMBER or AMBER+STRICT or RED"` (안내문) | `AMBER` 등 실제 값 |
| `scope` | `"required or optional or excluded"` (안내문) | `required` |
| `licenses.license.id` | 전부 `NOASSERTION` | OSS는 `Apache-2.0`, `GPL-2.0-only`, `MIT` 등 실제 SPDX ID |
| `hashes[].content` | 고정 해시 1개 | 부품별 결정적 SHA-256 |
| `pedigree.notes` | 템플릿 문구 | ICS 공급망 맥락 문구 |

> 샘플은 **템플릿**이라 열거형 필드에 선택지를 나열해 뒀습니다.
> 생성물은 **실데이터**이므로 그중 하나를 확정값으로 채웠습니다. 필드 의미는 동일합니다.

### `bom-ref` 네이밍 규칙 확장

샘플의 `<종류>:<대상>:<이름>` 패턴을 그대로 따르되, 계층을 4종으로 나눴습니다.

| 접두어 | 계층 | 예시 |
|---|---|---|
| `platform:<vendor>:<os>` | 기반 플랫폼 | `platform:sel:proprietary-rtos` |
| `pkg:oss:<이름>` | OSS 부품 | `pkg:oss:openssl` |
| `mod:<vendor>:<역할>` | 벤더 고유 모듈 | `mod:sel:control-engine` |
| `proto:<vendor>:<프로토콜>` | 프로토콜 스택 | `proto:sel:iec-61850-goose` |

샘플은 VxWorks 단일 대상이라 `os:vxworks:rtos` + `pkg:vxworks:*` 두 종류로 충분했습니다.
ICS는 **OSS / 벤더코드 / 프로토콜**을 구분해야 취약점 대응 주체와 대응 방식이 갈리므로 접두어를 나눴습니다.

```
pkg:oss:openssl          → OSS. 버전 업그레이드로 자체 해결 가능
mod:sel:control-engine   → 벤더 코드. PSIRT 권고와 펌웨어 릴리스 대기
proto:sel:dnp3           → 프로토콜 스택. 프로토콜 자체 결함이면 전 벤더 공통 영향
```

---

## 3. 의도적으로 빼거나 조정한 것

### `group` 필드 — OSS 부품에서 미사용

샘플 내부 컴포넌트에 있던 `group`은 **벤더 고유 모듈·프로토콜 스택에만** 부여하고 OSS 부품에는 넣지 않았습니다.

- `group`은 Maven `groupId` 같은 **네임스페이스** 개념입니다.
- OpenSSL, zlib 같은 C 라이브러리에는 해당 개념이 없어 억지로 채우면 매칭에 방해가 됩니다.
- Java 부품(Log4j, Jackson, Spring)은 `purl`에 이미 groupId가 들어 있습니다.
  `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`

### `bom` 타입 externalReference — 자식 SBOM 링크 미생성

샘플은 부모 HBOM 1개 + 자식 SBOM 2개를 링크했습니다.
현재 데이터셋은 자산당 SBOM 1개 구조라 **부모 HBOM 링크만** 유지했습니다.
계층형 BOM(HBOM→SBOM→하위 SBOM)이 필요해지면 이 자리에 추가하면 됩니다.

---

## 4. 호환성 정리

| 질문 | 답 |
|---|---|
| 기존 KISA 필드 파서가 그대로 동작하나? | **예.** 필드명·위치·중첩 구조 무변경 |
| CycloneDX 1.7 스키마 검증을 통과하나? | **예.** 확장은 전부 표준 `properties[]`와 표준 필드만 사용 |
| ICS 확장을 모르는 도구는 어떻게 되나? | `properties[]`를 무시하고 정상 파싱. 기능 저하 없음 |
| 삭제된 필드가 있나? | **없음.** OSS 부품의 `group`만 미사용이며, `group`은 원래 optional |
| CVE 매칭에 꼭 필요한 필드는? | 내부 컴포넌트의 `cpe`(1순위), `purl`(폴백), `version` |

---

## 5. 관련 파일

| 경로 | 설명 |
|---|---|
| `sbom/README.md` | 데이터셋 개요·통계·활용법 |
| `sbom/*.json` | SBOM 본문 1,000개 |
| `sbom/index.csv` | 자산 인덱스 |
| `sbom/ground_truth_vulnerable_components.csv` | VEX 정답셋 |
| `tools/generate_ics_sbom.py` | SBOM 생성기 (카탈로그·확장 property 정의 원본) |
| `tools/generate_sbom_cve.py` | SBOM→CVE 식별기 (`cpe`/`purl` 소비) |
| `tools/compare_schema.py` | 원본 샘플 대비 구조 비교 검증 스크립트 |
