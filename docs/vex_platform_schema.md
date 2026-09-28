# VEX 연동 스키마 — 통합보안 관리 플랫폼

ICS-VEXForge → **통합보안 관리 플랫폼** 으로 전달되는 VEX 데이터의 인터페이스 정의.
플랫폼 UI 개발팀이 이 문서를 계약(contract)으로 사용한다.

- **방향**: ICS-VEXForge 가 **출력(output)** 하는 문서 = 플랫폼이 **입력(input)** 으로 받는 문서 (동일 스키마).
- **표준 정합**: 상태·저스티피케이션 어휘는 **OpenVEX / CISA CSAF-VEX** 와 호환. 여기에 UI 표출에 필요한
  **설명가능성(evidence)·위험(risk)·출처(provenance)** 필드를 확장(superset)한다.
- **형식**: UTF-8 JSON. 시각(time)은 ISO 8601 UTC (`YYYY-MM-DDThh:mm:ssZ`).
- **판정 단위**: `product × vulnerability` (한 CVE가 제품마다 다른 상태를 가질 수 있음 → statement 하나 = 제품×취약점 1쌍).
- 기계 검증용 JSON Schema: [`vex_platform_schema.json`](vex_platform_schema.json) · 실데이터 예시: [`vex_platform_example.json`](vex_platform_example.json)

---

## 1. 출력 (ICS-VEXForge → 플랫폼) : `VexDocument`

### 1.1 문서 봉투 (envelope)

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `schema_version` | string | ✅ | 이 연동 스키마 버전 (예: `"1.0"`) |
| `generator` | object | ✅ | 생성기 정보 → 아래 |
| `generator.name` | string | ✅ | `"ICS-VEXForge"` |
| `generator.version` | string | ✅ | 생성기 버전 (예: `"2026.09"`) |
| `generator.org` | string | ➖ | 발행 조직 (예: `"Chonnam SSRC"`) |
| `generated_at` | string (ISO8601) | ✅ | 문서 생성 시각 (UTC) |
| `spec` | string | ✅ | 어휘 정합 표시. 고정값 `"openvex-compatible"` |
| `asset` | object \| null | ➖ | 이 VEX가 대상으로 하는 자산/장비 (SBOM 1건 단위) → 아래 |
| `asset.asset_id` | string | ✅* | 플랫폼 자산 식별자 (`asset` 있을 때 필수) |
| `asset.product` | string \| null | ➖ | 자산(장비) 제품명 |
| `asset.vendor` | string \| null | ➖ | 자산 벤더 |
| `asset.sbom_ref` | string \| null | ➖ | 원본 SBOM 참조(ID/URL) |
| `statement_count` | integer | ✅ | `statements` 길이 |
| `statements` | array\<VexStatement\> | ✅ | VEX 판정 목록 (0개 이상) |

### 1.2 VEX 판정 (`VexStatement`) — 핵심 레코드

#### (a) 식별

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `statement_id` | string | ✅ | 안정적 고유 ID. 규칙: `"<cve>@<product_id>"` |
| `vulnerability` | object | ✅ | 취약점 → 아래 |
| `vulnerability.cve` | string | ✅ | `CVE-YYYY-N…` (정규식 `^CVE-\d{4}-\d+$`) |
| `vulnerability.cwe` | array\<string\> | ➖ | CWE 목록 (예: `["CWE-787"]`) |
| `vulnerability.title` | string \| null | ➖ | 취약점 요약(짧은 설명) |
| `vulnerability.aliases` | array\<string\> | ➖ | 별칭 (GHSA/ICSA 등) |

#### (b) 대상 제품

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `product` | object | ✅ | 영향 제품/컴포넌트 → 아래 |
| `product.product_id` | string | ✅ | CSAF 스타일 제품 ID (statement_id에 사용) |
| `product.name` | string | ✅ | 컴포넌트/제품명 (예: `"zlib"`) |
| `product.version` | string | ✅ | 버전 문자열, 미상이면 `"NOASSERTION"` |
| `product.vendor` | string \| null | ➖ | 벤더 |
| `product.purl` | string \| null | ➖ | Package URL (예: `pkg:generic/zlib@1.2.12`) |
| `product.cpe` | string \| null | ➖ | CPE 2.3 문자열 |
| `product.ics_device` | string \| null | ➖ | 이 컴포넌트를 내장한 ICS 장비/모델 |

#### (c) VEX 판정 (표준 어휘)

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `status` | enum(string) | ✅ | `affected` \| `not_affected` \| `fixed` \| `under_investigation` |
| `justification` | enum(string) \| null | 조건부 | `status=not_affected` 일 때 **필수**, 그 외 `null` |
| `action_statement` | string \| null | 조건부 | `status=affected` 일 때 권고(조치) 문구 |
| `impact_statement` | string \| null | ➖ | 영향 설명(선택) |

- `justification` enum: `component_not_present` \| `vulnerable_code_not_present` \|
  `vulnerable_code_not_in_execute_path` \| `vulnerable_code_cannot_be_controlled_by_adversary` \|
  `inline_mitigations_already_exist` (CISA 5종).

#### (d) 설명가능성 (ICS-VEXForge 확장) — UI의 "왜?" 표출용

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `evidence` | object | ✅ | 판정 근거 → 아래 |
| `evidence.tier` | enum(string) | ✅ | 증거 강도 (아래 enum) |
| `evidence.basis` | string | ✅ | 사람이 읽는 근거 한 줄 |
| `evidence.decided_by` | enum(string) | ✅ | 판정을 확정한 단계: `presence` \| `source-absence` \| `sbom` |
| `evidence.method` | string | ➖ | 분석 방법 (예: `"VEX-v2 (CTI + Joern + Z3)"`) |
| `evidence.gates` | object | ✅ | 게이트별 결과 → 아래 (계층: **존재가 판정, Q2/Q3는 선택적 증거**) |
| `evidence.gates.presence` | enum \| null | ✅ | Q1: `present` \| `component_only` \| `absent` \| `null` |
| `evidence.gates.reachability` | enum \| null | ➖ | Q2(Joern): `reachable` \| `not-reachable` \| `unknown` \| `null` |
| `evidence.gates.controllability` | enum \| null | ➖ | Q3(Z3): `controllable` \| `not-controllable` \| `unknown` \| `null` |

- `evidence.tier` enum: `verified`(존재+도달+제어) \| `reachable`(존재+도달) \| `present`(존재만) \|
  `component`(컴포넌트만, 함수 미국지화) \| `sbom-evidenced`(SBOM에 부재) \| `not-present`(소스에 함수 부재) \|
  `under-investigation`.
- **주의(UI 표출 원칙)**: `reachability`/`controllability` 는 **선택적 증거**다. Q2가 `reachable` 이 아닐 때
  `controllability` 값은 판정에 쓰이지 않으므로 UI에서 "not applicable" 로 표시할 것 (게이트 순서 존중).

#### (e) 위험/우선순위 컨텍스트

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `risk` | object | ✅ | → 아래 |
| `risk.severity` | enum(string) | ✅ | `critical` \| `high` \| `medium` \| `low` \| `unrated` |
| `risk.cvss` | object | ✅ | → 아래 |
| `risk.cvss.score` | number \| null | ➖ | 0.0–10.0 |
| `risk.cvss.vector` | string \| null | ➖ | CVSS 벡터 문자열 |
| `risk.cvss.version` | string \| null | ➖ | `"3.1"` 등 |
| `risk.kev` | boolean | ✅ | CISA KEV 등재 여부 |
| `risk.epss` | number \| null | ➖ | EPSS 확률 0.0–1.0 |
| `risk.attack_vector` | enum \| null | ➖ | `N` \| `A` \| `L` \| `P` \| `null` (CVSS AV) |
| `risk.ssvc` | object \| null | ➖ | → 아래 |
| `risk.ssvc.priority` | enum \| null | ➖ | `act` \| `attend` \| `track*` \| `track` \| `null` |
| `risk.ssvc.vector` | string \| null | ➖ | `SSVCv2/…` 벡터 |

#### (f) 출처 (provenance)

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `provenance` | object | ✅ | → 아래 |
| `provenance.advisory` | string \| null | ➖ | 원 ICS 권고 ID (예: `"ICSA-22-…"`) |
| `provenance.source_repo` | string \| null | ➖ | 분석한 OSS 저장소 URL |
| `provenance.analyzed_version` | string \| null | ➖ | 실제 분석한 소스 버전(스냅샷) |
| `provenance.references` | array\<string\> | ➖ | 참고 URL(NVD 등) |
| `last_updated` | string (ISO8601) | ✅ | 이 statement 최종 갱신 시각 |

---

## 2. 입력 (플랫폼 → ICS-VEXForge) : `VexRequest`

플랫폼이 VEX를 **요청**할 때 보내는 형식. 두 모드.

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `request_id` | string | ✅ | 요청 추적 ID |
| `mode` | enum(string) | ✅ | `sbom` (SBOM 분석) \| `query` (기존 결과 조회) |
| `sbom` | object \| null | 조건부 | `mode=sbom` 일 때 CycloneDX 1.7 SBOM 문서 |
| `sbom_ref` | string \| null | ➖ | SBOM을 인라인 대신 참조로 전달할 때 |
| `exposure` | enum \| null | ➖ | SSVC용 배포 노출도: `open` \| `controlled` \| `small` \| `null` |
| `filter` | object \| null | 조건부 | `mode=query` 일 때 필터 → 아래 |
| `filter.cve` | array\<string\> \| null | ➖ | CVE 화이트리스트 |
| `filter.asset_id` | string \| null | ➖ | 특정 자산 |
| `filter.status` | array\<enum\> \| null | ➖ | 상태 필터 (`affected` 등) |
| `filter.min_severity` | enum \| null | ➖ | `critical`/`high`/… 이상만 |

응답은 항상 위의 **`VexDocument`** (섹션 1).

---

## 3. 상태 × 필수 필드 요약 (UI 분기용)

| status | justification | action_statement | 대표 evidence.tier |
|---|---|---|---|
| `affected` | `null` | 권고 문구(선택) | verified / reachable / present / component |
| `not_affected` | **필수** (5종 중 1) | `null` | sbom-evidenced / not-present |
| `fixed` | `null` | 패치 정보(선택) | (patch-signature 근거) |
| `under_investigation` | `null` | `null` | under-investigation |

---

## 4. 예시

전체 문서 예시(실데이터 매핑): [`vex_platform_example.json`](vex_platform_example.json).
아래는 statement 1건(affected).

```json
{
  "statement_id": "CVE-2022-37434@zlib",
  "vulnerability": { "cve": "CVE-2022-37434", "cwe": ["CWE-787", "CWE-120"],
    "title": "zlib heap over-read in inflate via a large gzip header" },
  "product": { "product_id": "zlib:1.2.12", "name": "zlib", "version": "1.2.12",
    "vendor": "ABB", "purl": "pkg:generic/zlib@1.2.12", "cpe": null,
    "ics_device": "Lumada Asset Performance Management" },
  "status": "affected",
  "justification": null,
  "action_statement": "Update zlib to a fixed release (>= 1.2.13).",
  "impact_statement": null,
  "evidence": {
    "tier": "present",
    "basis": "vulnerable code present; not refuted (Q2/Q3 optional and not decisive here)",
    "decided_by": "presence",
    "method": "VEX-v2 (CTI + Joern + Z3)",
    "gates": { "presence": "present", "reachability": "not-reachable", "controllability": "controllable" }
  },
  "risk": { "severity": "critical", "cvss": { "score": 9.8, "vector": null, "version": "3.1" },
    "kev": false, "epss": null, "attack_vector": null, "ssvc": { "priority": null, "vector": null } },
  "provenance": { "advisory": null, "source_repo": "https://github.com/madler/zlib",
    "analyzed_version": "zlib-1.2.12", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-37434"] },
  "last_updated": "2026-09-28T00:00:00Z"
}
```

---

## 5. 설계 노트 (플랫폼팀과 합의할 점)

1. **표준 vs 확장**: 핵심 어휘(`status`/`justification`)는 OpenVEX/CSAF 그대로라 표준 툴과 상호운용 가능.
   `evidence`/`risk`/`provenance` 는 이 시스템의 확장이므로, 표준-only 소비자는 무시하면 됨.
2. **필수/선택 표기**: ✅=필수, ➖=선택, "조건부"=특정 status/mode에서 필수.
3. **null 규칙**: 값이 없으면 키를 생략하지 말고 `null` 로 보냄(UI 렌더 안정성). 배열은 없으면 `[]`.
4. **버전 정책**: `schema_version` 이 major 바뀌면 비호환. 필드 추가는 minor(하위호환).
5. 전송 방식(REST 응답 / 파일 업로드 / 메시지 큐)은 별도 협의 — 스키마는 페이로드 형태만 규정.
