# CWE 기반 증거 경로 결정 기준

정책 버전: `cwe-evidence-v2.1` / 기준 분류: 고정된 공식 CWE v5.0 View 1000.

갱신: **2026-11-06 (KST)**. CVE에 이미 연결된 CWE를 입력으로 사용한다. `Mapping_Notes.Usage`는 CWE 부여 지침을 보존한 참고 정보이며 **분석 경로의 허용·차단 조건이 아니다.**

현재 결정 순서는 **보고된 CWE 유지 → 필요한 사실과 증거 소재 확인 → CVE·권고의 구체적 메커니즘으로 보완 → 소스·운영 요구 결합 → 자료 유무에 따라 실행 경로 선택**이다. 메커니즘이 불명확하거나 지원하지 않는 전문 자료가 필요하면 그 이유를 기록하고 유보한다.

## 1. 무엇을 결정하는가

이 정책은 **이미 식별된 CVE를 특정 자산에서 검토할 때 어떤 증거를 수집할지** 결정한다. 취약점의 존재, 실제 악용 가능성, VEX 상태를 CWE만으로 결정하지 않는다.

다음 두 질문을 분리한다.

1. 확인하려는 주장이 구현의 속성인가, 배포·운영의 관찰 가능한 속성인가?
2. 현재 자산에 대해 그 주장을 확인할 자료가 실제로 있는가?

소스가 없다는 이유로 운영 경로를 선택하지 않는다. 소스가 있다는 이유로 소스 분석이 필수라고 판단하지 않는다. **증거 요구를 먼저 정하고, 자료 유무는 나중에 적용한다.**

`source_requirement=required`는 이 프로젝트가 구현 속성의 검증을 위해 요구하는 기본 증거 정책이다. 모든 가능한 상황에서 소스가 논리적으로 유일한 증거라는 뜻은 아니다. 벤더의 확인 자료나 동적 검증 등 다른 방법이 존재할 수 있다. 현재 시스템의 기본 경로에서는 이를 임의로 소스 분석 대체물로 받아들이지 않는다.

## 2. 증거의 소재에 따른 판단 축

| 확인할 주장 | 필요한 증거의 예 | 기본 정책 |
| --- | --- | --- |
| 메모리 경계, 객체 수명, 해제 후 사용 | 관련 정의·연산, 입력 크기, 객체 수명과 호출·데이터 흐름 | 소스 증거 필요 |
| 입력 검증, SQL/명령 생성, 경로 정규화 | 입력에서 민감 연산까지의 처리 및 검증 구현 | 소스 증거 필요 |
| 인가·인증 검사의 실제 실행 경로 | 보호 대상, 검사 위치와 누락 경로, 실제 역할·접근 범위 | 소스와 운영 증거 필요 |
| 동기화, 순서, 상태 전이, 계산·비교 의미 | 상태 변경·연산·예외 처리의 구현 | 소스 증거 필요, 운영 전제조건은 별도 확인 |
| 배포한 통신·쿠키·계정·권한 설정 | 실제 프로토콜·속성·계정 정책·권한·설정/점검 기록 | 운영 정보로 수집 가능한 유형에 한해 운영 경로 |
| 하드웨어 레지스터·회로, 물리 조건 | RTL·회로·명세·하드웨어 측정 | 소프트웨어 소스 파서로 대체하지 않고 전문 증거 요구 |
| 모델 강건성, 암호 설계, 은닉 채널 | 모델/데이터 평가, 암호 설계 검토, 정보흐름·측정 자료 | 추가 전문 증거 필요 |
| 정보 노출·설계 문제 등 원인이 넓은 유형 | 해당 CVE에서 실제로 발생한 메커니즘에 관한 벤더 근거 | 근거 확보 전 경로 유보 |

운영자가 어떤 설정을 보고할 수 있다는 것과, 그 보고가 취약하지 않음을 입증한다는 것은 다르다. 운영 경로는 **증거 수집 경로**이며, 운영자 답변은 독립적으로 검증된 코드 부재 증거가 아니다.

## 3. 10개 Pillar와 944개 세부 CWE의 역할

Pillar는 자료의 상위 분류와 탐색에 사용한다. Pillar 전체를 소스 필수 또는 운영 전용으로 지정하지 않는다. 하나의 세부 CWE가 여러 Pillar에 속하면 모든 관계를 보존한다.

944개는 고정된 스냅샷에서 Pillar에 연결된 비폐기 세부 CWE의 수다. 이 집합에는 하드웨어·설계·코딩 품질 유형도 들어 있다. 모두가 CVE 매핑에 적합하거나 현재 소프트웨어 분석기로 검증 가능한 것은 아니다.

각 세부 CWE는 하나의 레코드를 가진다. 레코드에는 자체 정의, 모든 Pillar, 필요한 사실과 증거 위치, 적용한 규칙, 상위에서 상속한 경로, 공식 플랫폼·탐지 설명, CVE 매핑 주의사항, 정책/원문 해시를 기록한다.

<!-- BEGIN GENERATED SECTION 3 RESULTS -->

### 3.1 구분해야 하는 네 가지 숫자

| 구분 | 수 | 의미 |
| --- | ---: | --- |
| Pillar | **10개** | 공식 계층의 상위 유형 |
| 고유 세부 CWE | **944개** | 이번 정책표의 대상 |
| 증거 기본값 | 3종 | 소스 / 운영 / 추가 근거·전문 자료 |
| 실행 경로 | 4종 | 소스만 / 소스+운영 / 필수 소스 대기 / 운영만 |

따라서 728·26·190은 Pillar 수가 아니다. 10개 Pillar 아래의 고유 CWE 944개를 증거 기본값으로 나눈 수다. 분류 근거 부족은 별도 유보이며 새로운 Pillar가 아니다.

### 3.2 10개 Pillar 전체의 실제 집계 결과

| Pillar | 공식 명칭 / 설명 | 소속 수 | 소스 기본값 | 운영 기본값 | 추가 근거·전문 자료 |
| --- | --- | ---: | ---: | ---: | ---: |
| CWE-284 | Improper Access Control<br>접근 제어 부적절 | 182 | 110 | 21 | 51 |
| CWE-435 | Improper Interaction Between Multiple Correctly-Behaving Entities<br>정상 동작 개체 사이의 부적절한 상호작용 | 17 | 15 | 0 | 2 |
| CWE-664 | Improper Control of a Resource Through its Lifetime<br>수명 주기 전반의 자원 제어 부적절 | 380 | 256 | 15 | 109 |
| CWE-682 | Incorrect Calculation<br>잘못된 계산 | 13 | 13 | 0 | 0 |
| CWE-691 | Insufficient Control Flow Management<br>제어 흐름 관리 불충분 | 86 | 79 | 0 | 7 |
| CWE-693 | Protection Mechanism Failure<br>보호 메커니즘 실패 | 103 | 69 | 4 | 30 |
| CWE-697 | Incorrect Comparison<br>잘못된 비교 | 21 | 18 | 1 | 2 |
| CWE-703 | Improper Check or Handling of Exceptional Conditions<br>예외 조건의 확인·처리 부적절 | 58 | 44 | 0 | 14 |
| CWE-707 | Improper Neutralization<br>부적절한 중화 | 145 | 145 | 0 | 0 |
| CWE-710 | Improper Adherence to Coding Standards<br>코딩 표준 준수 부적절 | 196 | 165 | 1 | 30 |
| **소속 합계: 중복 포함** | 한 CWE의 여러 Pillar 소속을 모두 계산 | **1201** | **914** | **42** | **245** |
| **고유 CWE 합계** | 각 CWE를 한 번만 계산 | **944** | **728** | **26** | **190** |

**합계 해석:** 235개 세부 CWE가 여러 Pillar에 속하므로 Pillar별 소속 수 합계는 1,201개다. 같은 CWE를 한 번만 세면 944개다. Pillar별 열을 합쳐 728·26·190과 바로 비교하면 중복 계산이 된다.

### 3.3 증거 기준을 직접 적용했는지·상속했는지

이 표는 증거 요구 기준의 적용 방식을 집계한다. 각 행에서 자체 기준과 상속의 합은 3.2절의 해당 Pillar 소속 수와 같다.

| Pillar | 자체 기준/조건 | 상위 세부 기준점에서 상속 |
| --- | ---: | ---: |
| CWE-284 | 76 | 106 |
| CWE-435 | 5 | 12 |
| CWE-664 | 75 | 305 |
| CWE-682 | 11 | 2 |
| CWE-691 | 19 | 67 |
| CWE-693 | 37 | 66 |
| CWE-697 | 10 | 11 |
| CWE-703 | 13 | 45 |
| CWE-707 | 10 | 135 |
| CWE-710 | 49 | 147 |

자체 기준/조건은 해당 CWE 자체의 규칙·명칭·플랫폼 조건이 적용된 경우이고, 상속은 가장 가까운 명시적 상위 세부 CWE 기준을 적용한 경우다. 직접 적용 여부는 독립 검수 여부나 분류 정확도를 뜻하지 않는다. Pillar 소속 기준이므로 행 사이에 중복을 포함한다.

<details>
<summary>참고 메타데이터: 공식 CWE 부여 지침 집계 — 분석 경로에 사용하지 않음</summary>

아래 네 등급은 CWE를 새로 부여하는 작성자를 위한 공식 지침이다. 이미 CVE에 연결된 CWE의 분석을 허용·금지하는 등급이 아니며, 소스/운영 필요 여부를 결정하지 않는다. 이 집계는 출처 추적을 위해 본 판단 표와 분리해 남긴다.

| Pillar | Allowed | Allowed-with-Review | Discouraged | Prohibited |
| --- | ---: | ---: | ---: | ---: |
| CWE-284 | 157 | 19 | 6 | 0 |
| CWE-435 | 13 | 4 | 0 | 0 |
| CWE-664 | 324 | 35 | 14 | 7 |
| CWE-682 | 12 | 0 | 1 | 0 |
| CWE-691 | 77 | 7 | 2 | 0 |
| CWE-693 | 89 | 10 | 4 | 0 |
| CWE-697 | 17 | 3 | 1 | 0 |
| CWE-703 | 49 | 5 | 4 | 0 |
| CWE-707 | 129 | 10 | 6 | 0 |
| CWE-710 | 120 | 25 | 1 | 50 |

</details>

### 3.4 Pillar별 모든 세부 CWE의 분류 결과

아래 10개 펼침 항목에 전체 1,201개 소속 행을 싣는다. 고유 CWE 944개를 모두 포함하며, 중복 소속 CWE는 해당 Pillar마다 다시 나타난다. 각 행은 **기본 증거 요구**이고, 실제 CVE 메커니즘 보정을 적용한 실행 결과는 4절에서 구분한다.

<details>
<summary>CWE-284 · Improper Access Control · 182개 소속</summary>

| 세부 CWE / 이름 | 기본 요구 / 운영 필요 | 필요한 사실의 소재 | 적용 규칙과 기준점 | CWE 부여 지침 (참고만) |
| --- | --- | --- | --- | --- |
| [CWE-9](https://cwe.mitre.org/data/definitions/9.html) J2EE Misconfiguration: Weak Access Permissions for EJB Methods | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-269 / 거리 2 | Allowed |
| [CWE-13](https://cwe.mitre.org/data/definitions/13.html) ASP.NET Misconfiguration: Password in Configuration File | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 3 | Allowed |
| [CWE-202](https://cwe.mitre.org/data/definitions/202.html) Exposure of Sensitive Information Through Data Queries | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 2 | Allowed |
| [CWE-219](https://cwe.mitre.org/data/definitions/219.html) Storage of File with Sensitive Data Under Web Root | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>feature_configuration (운영) | deployment-configuration @ CWE-219 / 거리 0 | Allowed |
| [CWE-220](https://cwe.mitre.org/data/definitions/220.html) Storage of File With Sensitive Data Under FTP Root | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>feature_configuration (운영) | deployment-configuration @ CWE-220 / 거리 0 | Allowed |
| [CWE-250](https://cwe.mitre.org/data/definitions/250.html) Execution with Unnecessary Privileges | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>resource_permissions (운영) | resource-permissions @ CWE-250 / 거리 0 | Allowed |
| [CWE-256](https://cwe.mitre.org/data/definitions/256.html) Plaintext Storage of a Password | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-257](https://cwe.mitre.org/data/definitions/257.html) Storing Passwords in a Recoverable Format | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-258](https://cwe.mitre.org/data/definitions/258.html) Empty Password in Configuration File | 운영 검토 가능<br>운영: 필수 | account_policy (운영) | password-configuration @ CWE-258 / 거리 0 | Allowed |
| [CWE-259](https://cwe.mitre.org/data/definitions/259.html) Use of Hard-coded Password | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-259 / 거리 0 | Allowed |
| [CWE-260](https://cwe.mitre.org/data/definitions/260.html) Password in Configuration File | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-261](https://cwe.mitre.org/data/definitions/261.html) Weak Encoding for Password | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-262](https://cwe.mitre.org/data/definitions/262.html) Not Using Password Aging | 운영 검토 가능<br>운영: 필수 | account_policy (운영) | password-configuration @ CWE-262 / 거리 0 | Allowed |
| [CWE-263](https://cwe.mitre.org/data/definitions/263.html) Password Aging with Long Expiration | 운영 검토 가능<br>운영: 필수 | account_policy (운영) | password-configuration @ CWE-263 / 거리 0 | Discouraged |
| [CWE-266](https://cwe.mitre.org/data/definitions/266.html) Incorrect Privilege Assignment | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-269 / 거리 1 | Allowed |
| [CWE-267](https://cwe.mitre.org/data/definitions/267.html) Privilege Defined With Unsafe Actions | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-269 / 거리 1 | Allowed |
| [CWE-268](https://cwe.mitre.org/data/definitions/268.html) Privilege Chaining | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-269 / 거리 1 | Allowed |
| [CWE-269](https://cwe.mitre.org/data/definitions/269.html) Improper Privilege Management | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-269 / 거리 0 | Discouraged |
| [CWE-270](https://cwe.mitre.org/data/definitions/270.html) Privilege Context Switching Error | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-269 / 거리 1 | Allowed |
| [CWE-271](https://cwe.mitre.org/data/definitions/271.html) Privilege Dropping / Lowering Errors | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-269 / 거리 1 | Allowed-with-Review |
| [CWE-272](https://cwe.mitre.org/data/definitions/272.html) Least Privilege Violation | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-269 / 거리 2 | Allowed |
| [CWE-273](https://cwe.mitre.org/data/definitions/273.html) Improper Check for Dropped Privileges | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-754 / 거리 1 | Allowed |
| [CWE-274](https://cwe.mitre.org/data/definitions/274.html) Improper Handling of Insufficient Privileges | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>error_handling (소스) | authorization-enforcement @ CWE-269 / 거리 1<br>error-handling @ CWE-755 / 거리 1 | Discouraged |
| [CWE-276](https://cwe.mitre.org/data/definitions/276.html) Incorrect Default Permissions | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>resource_permissions (운영) | resource-permissions @ CWE-276 / 거리 0 | Allowed |
| [CWE-277](https://cwe.mitre.org/data/definitions/277.html) Insecure Inherited Permissions | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>resource_permissions (운영) | resource-permissions @ CWE-277 / 거리 0 | Allowed |
| [CWE-278](https://cwe.mitre.org/data/definitions/278.html) Insecure Preserved Inherited Permissions | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>resource_permissions (운영) | resource-permissions @ CWE-278 / 거리 0 | Allowed |
| [CWE-279](https://cwe.mitre.org/data/definitions/279.html) Incorrect Execution-Assigned Permissions | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>resource_permissions (운영) | resource-permissions @ CWE-279 / 거리 0 | Allowed |
| [CWE-281](https://cwe.mitre.org/data/definitions/281.html) Improper Preservation of Permissions | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>resource_permissions (운영) | resource-permissions @ CWE-281 / 거리 0 | Allowed |
| [CWE-282](https://cwe.mitre.org/data/definitions/282.html) Improper Ownership Management | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-282 / 거리 0 | Allowed-with-Review |
| [CWE-283](https://cwe.mitre.org/data/definitions/283.html) Unverified Ownership | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-282 / 거리 1 | Allowed |
| [CWE-285](https://cwe.mitre.org/data/definitions/285.html) Improper Authorization | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 0 | Discouraged |
| [CWE-286](https://cwe.mitre.org/data/definitions/286.html) Incorrect User Management | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-286 / 거리 0 | Allowed-with-Review |
| [CWE-287](https://cwe.mitre.org/data/definitions/287.html) Improper Authentication | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 0 | Discouraged |
| [CWE-288](https://cwe.mitre.org/data/definitions/288.html) Authentication Bypass Using an Alternate Path or Channel | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 2 | Allowed |
| [CWE-289](https://cwe.mitre.org/data/definitions/289.html) Authentication Bypass by Alternate Name | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 2 | Allowed |
| [CWE-290](https://cwe.mitre.org/data/definitions/290.html) Authentication Bypass by Spoofing | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 2 | Allowed |
| [CWE-291](https://cwe.mitre.org/data/definitions/291.html) Reliance on IP Address for Authentication | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-923 / 거리 1 | Allowed |
| [CWE-293](https://cwe.mitre.org/data/definitions/293.html) Using Referer Field for Authentication | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 3 | Allowed |
| [CWE-294](https://cwe.mitre.org/data/definitions/294.html) Authentication Bypass by Capture-replay | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 2 | Allowed |
| [CWE-295](https://cwe.mitre.org/data/definitions/295.html) Improper Certificate Validation | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-295 / 거리 0 | Allowed |
| [CWE-296](https://cwe.mitre.org/data/definitions/296.html) Improper Following of a Certificate's Chain of Trust | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>code_structure (소스)<br>crypto_implementation (소스) | crypto-implementation @ CWE-295 / 거리 1<br>code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-297](https://cwe.mitre.org/data/definitions/297.html) Improper Validation of Certificate with Host Mismatch | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>crypto_implementation (소스) | authorization-enforcement @ CWE-923 / 거리 1<br>crypto-implementation @ CWE-295 / 거리 1 | Allowed |
| [CWE-298](https://cwe.mitre.org/data/definitions/298.html) Improper Validation of Certificate Expiration | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-295 / 거리 1 | Allowed |
| [CWE-299](https://cwe.mitre.org/data/definitions/299.html) Improper Check for Certificate Revocation | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-404 / 거리 1<br>crypto-implementation @ CWE-295 / 거리 1 | Allowed |
| [CWE-300](https://cwe.mitre.org/data/definitions/300.html) Channel Accessible by Non-Endpoint | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-923 / 거리 1 | Discouraged |
| [CWE-301](https://cwe.mitre.org/data/definitions/301.html) Reflection Attack in an Authentication Protocol | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 2 | Allowed |
| [CWE-302](https://cwe.mitre.org/data/definitions/302.html) Authentication Bypass by Assumed-Immutable Data | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-807 / 거리 1 | Allowed |
| [CWE-303](https://cwe.mitre.org/data/definitions/303.html) Incorrect Implementation of Authentication Algorithm | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 2 | Allowed |
| [CWE-304](https://cwe.mitre.org/data/definitions/304.html) Missing Critical Step in Authentication | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-305](https://cwe.mitre.org/data/definitions/305.html) Authentication Bypass by Primary Weakness | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 2 | Allowed |
| [CWE-306](https://cwe.mitre.org/data/definitions/306.html) Missing Authentication for Critical Functionality | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 1 | Allowed |
| [CWE-307](https://cwe.mitre.org/data/definitions/307.html) Improper Restriction of Excessive Authentication Attempts | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-799 / 거리 1 | Allowed |
| [CWE-308](https://cwe.mitre.org/data/definitions/308.html) Use of Single-factor Authentication | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-654 / 거리 1 | Allowed |
| [CWE-309](https://cwe.mitre.org/data/definitions/309.html) Use of Password System for Primary Authentication | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-654 / 거리 1 | Allowed |
| [CWE-321](https://cwe.mitre.org/data/definitions/321.html) Use of Hard-coded Cryptographic Key | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-321 / 거리 0 | Allowed |
| [CWE-322](https://cwe.mitre.org/data/definitions/322.html) Key Exchange without Entity Authentication | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 2 | Allowed |
| [CWE-346](https://cwe.mitre.org/data/definitions/346.html) Origin Validation Error | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-346 / 거리 0 | Allowed-with-Review |
| [CWE-350](https://cwe.mitre.org/data/definitions/350.html) Reliance on Reverse DNS Resolution for a Security-Critical Action | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-807 / 거리 1 | Allowed |
| [CWE-356](https://cwe.mitre.org/data/definitions/356.html) Missing User Interaction for Potentially Unsafe Action | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 1 | Allowed |
| [CWE-370](https://cwe.mitre.org/data/definitions/370.html) Missing Check for Certificate Revocation after Initial Check | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-404 / 거리 2<br>crypto-implementation @ CWE-295 / 거리 2 | Allowed |
| [CWE-384](https://cwe.mitre.org/data/definitions/384.html) Session Fixation | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>reference_resolution (소스) | authorization-enforcement @ CWE-1462 / 거리 1<br>reference-resolution @ CWE-610 / 거리 1 | Allowed |
| [CWE-419](https://cwe.mitre.org/data/definitions/419.html) Unprotected Primary Channel | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-923 / 거리 1 | Allowed |
| [CWE-420](https://cwe.mitre.org/data/definitions/420.html) Unprotected Alternate Channel | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-923 / 거리 1 | Allowed |
| [CWE-421](https://cwe.mitre.org/data/definitions/421.html) Race Condition During Access to Alternate Channel | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>state_control_flow (소스) | authorization-enforcement @ CWE-923 / 거리 2<br>state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-422](https://cwe.mitre.org/data/definitions/422.html) Unprotected Windows Messaging Channel | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>crypto_implementation (소스) | authorization-enforcement @ CWE-923 / 거리 2<br>crypto-implementation @ CWE-345 / 거리 2 | Allowed |
| [CWE-424](https://cwe.mitre.org/data/definitions/424.html) Improper Protection of Alternate Path | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-424 / 거리 0 | Allowed-with-Review |
| [CWE-425](https://cwe.mitre.org/data/definitions/425.html) Direct Request | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-424 / 거리 1 | Allowed |
| [CWE-433](https://cwe.mitre.org/data/definitions/433.html) Unparsed Raw Web Content Delivery | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>feature_configuration (운영) | deployment-configuration @ CWE-219 / 거리 1 | Allowed |
| [CWE-493](https://cwe.mitre.org/data/definitions/493.html) Critical Public Variable Without Final Modifier | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | language-access-modifiers @ CWE-493 / 거리 0 | Allowed |
| [CWE-500](https://cwe.mitre.org/data/definitions/500.html) Public Static Field Not Marked Final | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | language-access-modifiers @ CWE-500 / 거리 0 | Allowed |
| [CWE-520](https://cwe.mitre.org/data/definitions/520.html) .NET Misconfiguration: Use of Impersonation | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-269 / 거리 2 | Allowed |
| [CWE-521](https://cwe.mitre.org/data/definitions/521.html) Weak Password Requirements | 운영 검토 가능<br>운영: 필수 | account_policy (운영) | password-configuration @ CWE-521 / 거리 0 | Allowed |
| [CWE-522](https://cwe.mitre.org/data/definitions/522.html) Insufficiently Protected Credentials | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed-with-Review |
| [CWE-523](https://cwe.mitre.org/data/definitions/523.html) Unprotected Transport of Credentials | 운영 검토 가능<br>운영: 필수 | communication_configuration (운영) | transport-encryption @ CWE-523 / 거리 0 | Allowed |
| [CWE-527](https://cwe.mitre.org/data/definitions/527.html) Exposure of Version-Control Repository to an Unauthorized Control Sphere | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | authorization-enforcement @ CWE-285 / 거리 2<br>unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-528](https://cwe.mitre.org/data/definitions/528.html) Exposure of Core Dump File to an Unauthorized Control Sphere | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | authorization-enforcement @ CWE-285 / 거리 2<br>unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-529](https://cwe.mitre.org/data/definitions/529.html) Exposure of Access Control List Files to an Unauthorized Control Sphere | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | authorization-enforcement @ CWE-285 / 거리 2<br>unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-530](https://cwe.mitre.org/data/definitions/530.html) Exposure of Backup File to an Unauthorized Control Sphere | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | authorization-enforcement @ CWE-285 / 거리 2<br>unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-539](https://cwe.mitre.org/data/definitions/539.html) Use of Persistent Cookies Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | authorization-enforcement @ CWE-285 / 거리 2<br>unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-549](https://cwe.mitre.org/data/definitions/549.html) Missing Password Field Masking | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-551](https://cwe.mitre.org/data/definitions/551.html) Incorrect Behavior Order: Authorization Before Parsing and Canonicalization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-696 / 거리 1 | Allowed |
| [CWE-552](https://cwe.mitre.org/data/definitions/552.html) Files or Directories Accessible to External Parties | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | authorization-enforcement @ CWE-285 / 거리 1<br>unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-553](https://cwe.mitre.org/data/definitions/553.html) Command Shell in Externally Accessible Directory | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | authorization-enforcement @ CWE-285 / 거리 2<br>unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-555](https://cwe.mitre.org/data/definitions/555.html) J2EE Misconfiguration: Plaintext Password in Configuration File | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 3 | Allowed |
| [CWE-556](https://cwe.mitre.org/data/definitions/556.html) ASP.NET Misconfiguration: Use of Identity Impersonation | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-269 / 거리 2 | Allowed |
| [CWE-566](https://cwe.mitre.org/data/definitions/566.html) Authorization Bypass Through User-Controlled SQL Primary Key | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 3 | Allowed |
| [CWE-582](https://cwe.mitre.org/data/definitions/582.html) Array Declared Public, Final, and Static | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | language-access-modifiers @ CWE-582 / 거리 0 | Allowed |
| [CWE-583](https://cwe.mitre.org/data/definitions/583.html) finalize() Method Declared Public | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | language-access-modifiers @ CWE-583 / 거리 0 | Allowed |
| [CWE-593](https://cwe.mitre.org/data/definitions/593.html) Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-666 / 거리 1 | Allowed |
| [CWE-599](https://cwe.mitre.org/data/definitions/599.html) Missing Validation of OpenSSL Certificate | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-295 / 거리 1 | Allowed |
| [CWE-603](https://cwe.mitre.org/data/definitions/603.html) Use of Client-Side Authentication | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-602 / 거리 1 | Allowed |
| [CWE-608](https://cwe.mitre.org/data/definitions/608.html) Struts: Non-private Field in ActionForm Class | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | language-access-modifiers @ CWE-608 / 거리 0 | Allowed |
| [CWE-612](https://cwe.mitre.org/data/definitions/612.html) Improper Authorization of Index Containing Sensitive Information | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 2 | Allowed |
| [CWE-618](https://cwe.mitre.org/data/definitions/618.html) Exposed Unsafe ActiveX Method | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-749 / 거리 1 | Allowed |
| [CWE-620](https://cwe.mitre.org/data/definitions/620.html) Unverified Password Change | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 2 | Allowed |
| [CWE-623](https://cwe.mitre.org/data/definitions/623.html) Unsafe ActiveX Control Marked Safe For Scripting | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-269 / 거리 2 | Allowed |
| [CWE-638](https://cwe.mitre.org/data/definitions/638.html) Not Using Complete Mediation | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-657 / 거리 1 | Allowed-with-Review |
| [CWE-639](https://cwe.mitre.org/data/definitions/639.html) Authorization Bypass Through User-Controlled Key | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 2 | Allowed |
| [CWE-640](https://cwe.mitre.org/data/definitions/640.html) Weak Password Recovery Mechanism for Forgotten Password | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 2 | Allowed-with-Review |
| [CWE-645](https://cwe.mitre.org/data/definitions/645.html) Overly Restrictive Account Lockout Mechanism | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 1 | Allowed |
| [CWE-647](https://cwe.mitre.org/data/definitions/647.html) Use of Non-Canonical URL Paths for Authorization Decisions | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 2 | Allowed |
| [CWE-648](https://cwe.mitre.org/data/definitions/648.html) Incorrect Use of Privileged APIs | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-269 / 거리 1 | Allowed |
| [CWE-708](https://cwe.mitre.org/data/definitions/708.html) Incorrect Ownership Assignment | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-282 / 거리 1 | Allowed |
| [CWE-732](https://cwe.mitre.org/data/definitions/732.html) Incorrect Permission Assignment for Critical Resource | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>resource_permissions (운영) | resource-permissions @ CWE-732 / 거리 0 | Allowed-with-Review |
| [CWE-749](https://cwe.mitre.org/data/definitions/749.html) Exposed Dangerous Method or Function | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-749 / 거리 0 | Allowed |
| [CWE-766](https://cwe.mitre.org/data/definitions/766.html) Critical Data Element Declared Public | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>code_structure (소스)<br>resource_permissions (운영) | code-structure @ CWE-1061 / 거리 1<br>resource-permissions @ CWE-732 / 거리 1 | Allowed |
| [CWE-782](https://cwe.mitre.org/data/definitions/782.html) Exposed IOCTL with Insufficient Access Control | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-749 / 거리 1 | Allowed |
| [CWE-798](https://cwe.mitre.org/data/definitions/798.html) Use of Hard-coded Credentials | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-798 / 거리 0 | Allowed-with-Review |
| [CWE-804](https://cwe.mitre.org/data/definitions/804.html) Guessable CAPTCHA | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285, CWE-287 / 거리 2 | Allowed |
| [CWE-836](https://cwe.mitre.org/data/definitions/836.html) Use of Password Hash Instead of Password for Authentication | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 2 | Allowed |
| [CWE-842](https://cwe.mitre.org/data/definitions/842.html) Placement of User into Incorrect Group | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-286 / 거리 1 | Allowed |
| [CWE-862](https://cwe.mitre.org/data/definitions/862.html) Missing Authorization | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 1 | Allowed-with-Review |
| [CWE-863](https://cwe.mitre.org/data/definitions/863.html) Incorrect Authorization | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 1 | Allowed-with-Review |
| [CWE-923](https://cwe.mitre.org/data/definitions/923.html) Improper Restriction of Communication Channel to Intended Endpoints | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-923 / 거리 0 | Allowed-with-Review |
| [CWE-925](https://cwe.mitre.org/data/definitions/925.html) Improper Verification of Intent by Broadcast Receiver | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-346, CWE-923 / 거리 2 | Allowed |
| [CWE-926](https://cwe.mitre.org/data/definitions/926.html) Improper Export of Android Application Components | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 1 | Allowed |
| [CWE-927](https://cwe.mitre.org/data/definitions/927.html) Use of Implicit Intent for Sensitive Communication | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285, CWE-923 / 거리 1 | Allowed |
| [CWE-939](https://cwe.mitre.org/data/definitions/939.html) Improper Authorization in Handler for Custom URL Scheme | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285, CWE-346, CWE-923 / 거리 2 | Allowed |
| [CWE-940](https://cwe.mitre.org/data/definitions/940.html) Improper Verification of Source of a Communication Channel | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-346, CWE-923 / 거리 1 | Allowed |
| [CWE-941](https://cwe.mitre.org/data/definitions/941.html) Incorrectly Specified Destination in a Communication Channel | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-923 / 거리 1 | Allowed |
| [CWE-942](https://cwe.mitre.org/data/definitions/942.html) Permissive Cross-domain Security Policy with Untrusted Domains | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>feature_configuration (운영) | deployment-configuration @ CWE-942 / 거리 0 | Allowed |
| [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) Sensitive Cookie Without 'HttpOnly' Flag | 운영 검토 가능<br>운영: 필수 | communication_configuration (운영)<br>feature_configuration (운영) | cookie-configuration @ CWE-1004 / 거리 0 | Allowed |
| [CWE-1022](https://cwe.mitre.org/data/definitions/1022.html) Use of Web Link to Untrusted Target with window.opener Access | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-269 / 거리 2 | Allowed |
| [CWE-1191](https://cwe.mitre.org/data/definitions/1191.html) On-Chip Debug and Test Interface With Improper Access Control | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1191 / 거리 0 | Allowed |
| [CWE-1220](https://cwe.mitre.org/data/definitions/1220.html) Insufficient Granularity of Access Control | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-1220 / 거리 0 | Allowed |
| [CWE-1222](https://cwe.mitre.org/data/definitions/1222.html) Insufficient Granularity of Address Regions Protected by Register Locks | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1222 / 거리 0 | Allowed |
| [CWE-1224](https://cwe.mitre.org/data/definitions/1224.html) Improper Restriction of Write-Once Bit Fields | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1224 / 거리 0 | Allowed |
| [CWE-1230](https://cwe.mitre.org/data/definitions/1230.html) Exposure of Sensitive Information Through Metadata | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 1 | Allowed |
| [CWE-1231](https://cwe.mitre.org/data/definitions/1231.html) Improper Prevention of Lock Bit Modification | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1231 / 거리 0 | Allowed |
| [CWE-1233](https://cwe.mitre.org/data/definitions/1233.html) Security-Sensitive Hardware Controls with Missing Lock Bit Protection | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1233 / 거리 0 | Allowed |
| [CWE-1243](https://cwe.mitre.org/data/definitions/1243.html) Sensitive Non-Volatile Information Not Protected During Debug | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1243 / 거리 0 | Allowed |
| [CWE-1244](https://cwe.mitre.org/data/definitions/1244.html) Internal Asset Exposed to Unsafe Debug Access Level or State | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 2 | Allowed |
| [CWE-1252](https://cwe.mitre.org/data/definitions/1252.html) CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1252 / 거리 0 | Allowed |
| [CWE-1256](https://cwe.mitre.org/data/definitions/1256.html) Improper Restriction of Software Interfaces to Hardware Features | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1256 / 거리 0 | Allowed |
| [CWE-1257](https://cwe.mitre.org/data/definitions/1257.html) Improper Access Control Applied to Mirrored or Aliased Memory Regions | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1257 / 거리 0 | Allowed |
| [CWE-1259](https://cwe.mitre.org/data/definitions/1259.html) Improper Restriction of Security Token Assignment | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1259 / 거리 0 | Allowed |
| [CWE-1260](https://cwe.mitre.org/data/definitions/1260.html) Improper Handling of Overlap Between Protected Memory Ranges | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1260 / 거리 0 | Allowed |
| [CWE-1262](https://cwe.mitre.org/data/definitions/1262.html) Improper Access Control for Register Interface | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1262 / 거리 0 | Allowed |
| [CWE-1263](https://cwe.mitre.org/data/definitions/1263.html) Improper Physical Access Control | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1263 / 거리 0 | Allowed-with-Review |
| [CWE-1267](https://cwe.mitre.org/data/definitions/1267.html) Policy Uses Obsolete Encoding | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | emergent-resource-design @ CWE-1267 / 거리 0 | Allowed |
| [CWE-1268](https://cwe.mitre.org/data/definitions/1268.html) Policy Privileges are not Assigned Consistently Between Control and Data Agents | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-269 / 거리 2 | Allowed |
| [CWE-1270](https://cwe.mitre.org/data/definitions/1270.html) Generation of Incorrect Security Tokens | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1270 / 거리 0 | Allowed |
| [CWE-1274](https://cwe.mitre.org/data/definitions/1274.html) Improper Access Control for Volatile Memory Containing Boot Code | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1274 / 거리 0 | Allowed |
| [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) Sensitive Cookie with Improper SameSite Attribute | 운영 검토 가능<br>운영: 필수 | communication_configuration (운영)<br>feature_configuration (운영) | cookie-configuration @ CWE-1275 / 거리 0 | Allowed |
| [CWE-1276](https://cwe.mitre.org/data/definitions/1276.html) Hardware Child Block Incorrectly Connected to Parent System | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1276 / 거리 0 | Allowed |
| [CWE-1280](https://cwe.mitre.org/data/definitions/1280.html) Access Control Check Implemented After Asset is Accessed | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-696 / 거리 1 | Allowed |
| [CWE-1283](https://cwe.mitre.org/data/definitions/1283.html) Mutable Attestation or Measurement Reporting Data | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1283 / 거리 0 | Allowed |
| [CWE-1290](https://cwe.mitre.org/data/definitions/1290.html) Incorrect Decoding of Security Identifiers | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1290 / 거리 0 | Allowed |
| [CWE-1292](https://cwe.mitre.org/data/definitions/1292.html) Incorrect Conversion of Security Identifiers | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1292 / 거리 0 | Allowed |
| [CWE-1294](https://cwe.mitre.org/data/definitions/1294.html) Insecure Security Identifier Mechanism | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1294 / 거리 0 | Allowed-with-Review |
| [CWE-1296](https://cwe.mitre.org/data/definitions/1296.html) Incorrect Chaining or Granularity of Debug Components | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1296 / 거리 0 | Allowed |
| [CWE-1297](https://cwe.mitre.org/data/definitions/1297.html) Unprotected Confidential Information on Device is Accessible by OSAT Vendors | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 1 | Allowed |
| [CWE-1299](https://cwe.mitre.org/data/definitions/1299.html) Missing Protection Mechanism for Alternate Hardware Interface | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1299 / 거리 0 | Allowed |
| [CWE-1302](https://cwe.mitre.org/data/definitions/1302.html) Missing Source Identifier in Entity Transactions on a System-On-Chip (SOC) | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1302 / 거리 0 | Allowed |
| [CWE-1304](https://cwe.mitre.org/data/definitions/1304.html) Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1304 / 거리 0 | Allowed |
| [CWE-1311](https://cwe.mitre.org/data/definitions/1311.html) Improper Translation of Security Attributes by Fabric Bridge | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1311 / 거리 0 | Allowed |
| [CWE-1312](https://cwe.mitre.org/data/definitions/1312.html) Missing Protection for Mirrored Regions in On-Chip Fabric Firewall | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1312 / 거리 0 | Allowed |
| [CWE-1313](https://cwe.mitre.org/data/definitions/1313.html) Hardware Allows Activation of Test or Debug Logic at Runtime | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1313 / 거리 0 | Allowed |
| [CWE-1314](https://cwe.mitre.org/data/definitions/1314.html) Missing Write Protection for Parametric Data Values | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 2 | Allowed |
| [CWE-1315](https://cwe.mitre.org/data/definitions/1315.html) Improper Setting of Bus Controlling Capability in Fabric End-point | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1315 / 거리 0 | Allowed |
| [CWE-1316](https://cwe.mitre.org/data/definitions/1316.html) Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1316 / 거리 0 | Allowed |
| [CWE-1317](https://cwe.mitre.org/data/definitions/1317.html) Improper Access Control in Fabric Bridge | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1317 / 거리 0 | Allowed |
| [CWE-1320](https://cwe.mitre.org/data/definitions/1320.html) Improper Protection for Outbound Error Messages and Alert Signals | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1320 / 거리 0 | Allowed |
| [CWE-1323](https://cwe.mitre.org/data/definitions/1323.html) Improper Management of Sensitive Trace Data | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1323 / 거리 0 | Allowed |
| [CWE-1327](https://cwe.mitre.org/data/definitions/1327.html) Binding to an Unrestricted IP Address | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-923 / 거리 1 | Allowed |
| [CWE-1328](https://cwe.mitre.org/data/definitions/1328.html) Security Version Number Mutable to Older Versions | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 1 | Allowed |
| [CWE-1334](https://cwe.mitre.org/data/definitions/1334.html) Unauthorized Error Injection Can Degrade Hardware Redundancy | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1334 / 거리 0 | Allowed |
| [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html) Missing Origin Validation in WebSockets | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-346 / 거리 1 | Allowed |
| [CWE-1390](https://cwe.mitre.org/data/definitions/1390.html) Weak Authentication | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 1 | Allowed-with-Review |
| [CWE-1391](https://cwe.mitre.org/data/definitions/1391.html) Use of Weak Credentials | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-287 / 거리 2 | Allowed-with-Review |
| [CWE-1392](https://cwe.mitre.org/data/definitions/1392.html) Use of Default Credentials | 운영 검토 가능<br>운영: 필수 | account_policy (운영) | password-configuration @ CWE-1392 / 거리 0 | Allowed |
| [CWE-1393](https://cwe.mitre.org/data/definitions/1393.html) Use of Default Password | 운영 검토 가능<br>운영: 필수 | account_policy (운영) | password-configuration @ CWE-1393 / 거리 0 | Allowed |
| [CWE-1394](https://cwe.mitre.org/data/definitions/1394.html) Use of Default Cryptographic Key | 운영 검토 가능<br>운영: 필수 | key_configuration (운영) | key-configuration @ CWE-1394 / 거리 0 | Allowed |
| [CWE-1462](https://cwe.mitre.org/data/definitions/1462.html) Improper Session Management | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-1462 / 거리 0 | Allowed-with-Review |
| [CWE-1463](https://cwe.mitre.org/data/definitions/1463.html) Insufficient Session Timeout Value | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-1462 / 거리 1 | Allowed |
| [CWE-1464](https://cwe.mitre.org/data/definitions/1464.html) Improper Session Invalidation | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-1462 / 거리 1 | Allowed |
| [CWE-1465](https://cwe.mitre.org/data/definitions/1465.html) Improper Session Invalidation after User Logout | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-1462 / 거리 2 | Allowed |
| [CWE-1466](https://cwe.mitre.org/data/definitions/1466.html) Improper Session Invalidation after Authentication Credential Change | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-1462 / 거리 2 | Allowed |
| [CWE-1467](https://cwe.mitre.org/data/definitions/1467.html) Use of Singular Authentication Artifact for Multiple User Sessions | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-1462 / 거리 1 | Allowed |
| [CWE-1469](https://cwe.mitre.org/data/definitions/1469.html) Improper Check for Credential Expiration | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-1469 / 거리 0 | Allowed |
| [CWE-1470](https://cwe.mitre.org/data/definitions/1470.html) Improper External Identity Verification | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285, CWE-923 / 거리 1 | Allowed-with-Review |
| [CWE-1472](https://cwe.mitre.org/data/definitions/1472.html) Generation of Credential with Long Expiration | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | credential-expiration-mechanism @ CWE-1472 / 거리 0 | Allowed |

</details>

<details>
<summary>CWE-435 · Improper Interaction Between Multiple Correctly-Behaving Entities · 17개 소속</summary>

| 세부 CWE / 이름 | 기본 요구 / 운영 필요 | 필요한 사실의 소재 | 적용 규칙과 기준점 | CWE 부여 지침 (참고만) |
| --- | --- | --- | --- | --- |
| [CWE-14](https://cwe.mitre.org/data/definitions/14.html) Compiler Removal of Code to Clear Buffers | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1038 / 거리 2 | Allowed |
| [CWE-86](https://cwe.mitre.org/data/definitions/86.html) Improper Neutralization of Invalid Characters in Identifiers in Web Pages | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-436 / 거리 1 | Allowed |
| [CWE-113](https://cwe.mitre.org/data/definitions/113.html) Improper Neutralization of CRLF Sequences in HTTP Headers | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-436 / 거리 1 | Allowed |
| [CWE-115](https://cwe.mitre.org/data/definitions/115.html) Misinterpretation of Input | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-436 / 거리 1 | Allowed |
| [CWE-188](https://cwe.mitre.org/data/definitions/188.html) Reliance on Data/Memory Layout | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-188 / 거리 0 | Allowed |
| [CWE-198](https://cwe.mitre.org/data/definitions/198.html) Use of Incorrect Byte Ordering | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-188 / 거리 1 | Allowed |
| [CWE-436](https://cwe.mitre.org/data/definitions/436.html) Interpretation Conflict | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-436 / 거리 0 | Allowed-with-Review |
| [CWE-437](https://cwe.mitre.org/data/definitions/437.html) Incomplete Model of Endpoint Features | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-436 / 거리 1 | Allowed |
| [CWE-439](https://cwe.mitre.org/data/definitions/439.html) Behavioral Change in New Version or Environment | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-439 / 거리 0 | Allowed |
| [CWE-444](https://cwe.mitre.org/data/definitions/444.html) Inconsistent Interpretation of HTTP Requests | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-436 / 거리 1 | Allowed |
| [CWE-626](https://cwe.mitre.org/data/definitions/626.html) Null Byte Interaction Error (Poison Null Byte) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-436 / 거리 1 | Allowed |
| [CWE-650](https://cwe.mitre.org/data/definitions/650.html) Trusting HTTP Permission Methods on the Server Side | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-436 / 거리 1 | Allowed |
| [CWE-733](https://cwe.mitre.org/data/definitions/733.html) Compiler Optimization Removal or Modification of Security-critical Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1038 / 거리 1 | Allowed |
| [CWE-1037](https://cwe.mitre.org/data/definitions/1037.html) Processor Optimization Removal or Modification of Security-critical Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1038 / 거리 1 | Allowed |
| [CWE-1038](https://cwe.mitre.org/data/definitions/1038.html) Insecure Automated Optimizations | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1038 / 거리 0 | Allowed-with-Review |
| [CWE-1461](https://cwe.mitre.org/data/definitions/1461.html) Hardware Simulation / Synthesis Mismatch | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1461 / 거리 0 | Allowed-with-Review |
| [CWE-1471](https://cwe.mitre.org/data/definitions/1471.html) Insufficiently Controlled Parser Differential | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-436 / 거리 1 | Allowed-with-Review |

</details>

<details>
<summary>CWE-664 · Improper Control of a Resource Through its Lifetime · 380개 소속</summary>

| 세부 CWE / 이름 | 기본 요구 / 운영 필요 | 필요한 사실의 소재 | 적용 규칙과 기준점 | CWE 부여 지침 (참고만) |
| --- | --- | --- | --- | --- |
| [CWE-8](https://cwe.mitre.org/data/definitions/8.html) J2EE Misconfiguration: Entity Bean Declared Remote | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-13](https://cwe.mitre.org/data/definitions/13.html) ASP.NET Misconfiguration: Password in Configuration File | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 3 | Allowed |
| [CWE-15](https://cwe.mitre.org/data/definitions/15.html) External Control of System or Configuration Setting | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-610 / 거리 1 | Allowed |
| [CWE-22](https://cwe.mitre.org/data/definitions/22.html) Improper Limitation of a Pathname to a Restricted Directory | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 1 | Allowed-with-Review |
| [CWE-23](https://cwe.mitre.org/data/definitions/23.html) Relative Path Traversal | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-24](https://cwe.mitre.org/data/definitions/24.html) Path Traversal: '../filedir' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-25](https://cwe.mitre.org/data/definitions/25.html) Path Traversal: '/../filedir' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-26](https://cwe.mitre.org/data/definitions/26.html) Path Traversal: '/dir/../filename' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-27](https://cwe.mitre.org/data/definitions/27.html) Path Traversal: 'dir/../../filename' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-28](https://cwe.mitre.org/data/definitions/28.html) Path Traversal: '..\filedir' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-29](https://cwe.mitre.org/data/definitions/29.html) Path Traversal: '\..\filename' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-30](https://cwe.mitre.org/data/definitions/30.html) Path Traversal: '\dir\..\filename' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-31](https://cwe.mitre.org/data/definitions/31.html) Path Traversal: 'dir\..\..\filename' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-32](https://cwe.mitre.org/data/definitions/32.html) Path Traversal: '...' (Triple Dot) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-33](https://cwe.mitre.org/data/definitions/33.html) Path Traversal: '....' (Multiple Dot) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-34](https://cwe.mitre.org/data/definitions/34.html) Path Traversal: '....//' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-35](https://cwe.mitre.org/data/definitions/35.html) Path Traversal: '.../...//' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-36](https://cwe.mitre.org/data/definitions/36.html) Absolute Path Traversal | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-37](https://cwe.mitre.org/data/definitions/37.html) Path Traversal: '/absolute/pathname/here' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 2 | Allowed |
| [CWE-38](https://cwe.mitre.org/data/definitions/38.html) Path Traversal: '\absolute\pathname\here' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-39](https://cwe.mitre.org/data/definitions/39.html) Path Traversal: 'C:dirname' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-40](https://cwe.mitre.org/data/definitions/40.html) Path Traversal: '\\UNC\share\name\' (Windows UNC Share) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-41](https://cwe.mitre.org/data/definitions/41.html) Improper Resolution of Path Equivalence | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 1 | Allowed |
| [CWE-42](https://cwe.mitre.org/data/definitions/42.html) Path Equivalence: 'filename.' (Trailing Dot) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-138 / 거리 2<br>reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-43](https://cwe.mitre.org/data/definitions/43.html) Path Equivalence: 'filename....' (Multiple Trailing Dot) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-138 / 거리 3<br>reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-44](https://cwe.mitre.org/data/definitions/44.html) Path Equivalence: 'file.name' (Internal Dot) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-45](https://cwe.mitre.org/data/definitions/45.html) Path Equivalence: 'file...name' (Multiple Internal Dot) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-138 / 거리 3<br>reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-46](https://cwe.mitre.org/data/definitions/46.html) Path Equivalence: 'filename ' (Trailing Space) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-138 / 거리 2<br>reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-47](https://cwe.mitre.org/data/definitions/47.html) Path Equivalence: ' filename' (Leading Space) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-48](https://cwe.mitre.org/data/definitions/48.html) Path Equivalence: 'file name' (Internal Whitespace) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-49](https://cwe.mitre.org/data/definitions/49.html) Path Equivalence: 'filename/' (Trailing Slash) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-138 / 거리 2<br>reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-50](https://cwe.mitre.org/data/definitions/50.html) Path Equivalence: '//multiple/leading/slash' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-51](https://cwe.mitre.org/data/definitions/51.html) Path Equivalence: '/multiple//internal/slash' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-52](https://cwe.mitre.org/data/definitions/52.html) Path Equivalence: '/multiple/trailing/slash//' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-53](https://cwe.mitre.org/data/definitions/53.html) Path Equivalence: '\multiple\\internal\backslash' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-54](https://cwe.mitre.org/data/definitions/54.html) Path Equivalence: 'filedir\' (Trailing Backslash) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-138 / 거리 2<br>reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-55](https://cwe.mitre.org/data/definitions/55.html) Path Equivalence: '/./' (Single Dot Directory) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-56](https://cwe.mitre.org/data/definitions/56.html) Path Equivalence: 'filedir*' (Wildcard) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-138 / 거리 2<br>reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-57](https://cwe.mitre.org/data/definitions/57.html) Path Equivalence: 'fakedir/../realdir/filename' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-58](https://cwe.mitre.org/data/definitions/58.html) Path Equivalence: Windows 8.3 Filename | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-59](https://cwe.mitre.org/data/definitions/59.html) Improper Link Resolution Before File Access | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 1 | Allowed |
| [CWE-61](https://cwe.mitre.org/data/definitions/61.html) UNIX Symbolic Link (Symlink) Following | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-62](https://cwe.mitre.org/data/definitions/62.html) UNIX Hard Link | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-64](https://cwe.mitre.org/data/definitions/64.html) Windows Shortcut Following (.LNK) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-65](https://cwe.mitre.org/data/definitions/65.html) Windows Hard Link | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-66](https://cwe.mitre.org/data/definitions/66.html) Improper Handling of File Names that Identify Virtual Resources | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 1 | Allowed |
| [CWE-67](https://cwe.mitre.org/data/definitions/67.html) Improper Handling of Windows Device Names | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-69](https://cwe.mitre.org/data/definitions/69.html) Improper Handling of Windows ::DATA Alternate Data Stream | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-72](https://cwe.mitre.org/data/definitions/72.html) Improper Handling of Apple HFS+ Alternate Data Stream Path | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-73](https://cwe.mitre.org/data/definitions/73.html) External Control of File Name or Path | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-610 / 거리 1 | Allowed |
| [CWE-94](https://cwe.mitre.org/data/definitions/94.html) Improper Control of Generation of Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-74 / 거리 1<br>reference-resolution @ CWE-913 / 거리 1 | Allowed-with-Review |
| [CWE-95](https://cwe.mitre.org/data/definitions/95.html) Improper Neutralization of Directives in Dynamically Evaluated Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-74 / 거리 2<br>reference-resolution @ CWE-913 / 거리 2 | Allowed |
| [CWE-96](https://cwe.mitre.org/data/definitions/96.html) Improper Neutralization of Directives in Statically Saved Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-74 / 거리 2<br>reference-resolution @ CWE-913 / 거리 2 | Allowed |
| [CWE-97](https://cwe.mitre.org/data/definitions/97.html) Improper Neutralization of Server-Side Includes (SSI) Within a Web Page | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-74 / 거리 3<br>reference-resolution @ CWE-913 / 거리 3 | Allowed |
| [CWE-98](https://cwe.mitre.org/data/definitions/98.html) Improper Control of Filename for Include/Require Statement in PHP Program | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 1 | Allowed |
| [CWE-114](https://cwe.mitre.org/data/definitions/114.html) Process Control | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-610 / 거리 2 | Discouraged |
| [CWE-118](https://cwe.mitre.org/data/definitions/118.html) Incorrect Access of Indexable Resource | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-118 / 거리 0 | Discouraged |
| [CWE-119](https://cwe.mitre.org/data/definitions/119.html) Improper Restriction of Operations within the Bounds of a Memory Buffer | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 0 | Discouraged |
| [CWE-120](https://cwe.mitre.org/data/definitions/120.html) Buffer Copy without Checking Size of Input | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 2 | Allowed-with-Review |
| [CWE-121](https://cwe.mitre.org/data/definitions/121.html) Stack-based Buffer Overflow | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 2 | Allowed |
| [CWE-122](https://cwe.mitre.org/data/definitions/122.html) Heap-based Buffer Overflow | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 2 | Allowed |
| [CWE-123](https://cwe.mitre.org/data/definitions/123.html) Write-what-where Condition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 2 | Allowed |
| [CWE-124](https://cwe.mitre.org/data/definitions/124.html) Buffer Underwrite | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 2 | Allowed |
| [CWE-125](https://cwe.mitre.org/data/definitions/125.html) Out-of-bounds Read | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 1 | Allowed |
| [CWE-126](https://cwe.mitre.org/data/definitions/126.html) Buffer Over-read | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 2 | Allowed |
| [CWE-127](https://cwe.mitre.org/data/definitions/127.html) Buffer Under-read | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 2 | Allowed |
| [CWE-134](https://cwe.mitre.org/data/definitions/134.html) Use of Externally-Controlled Format String | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-178](https://cwe.mitre.org/data/definitions/178.html) Improper Handling of Case Sensitivity | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 1 | Allowed |
| [CWE-192](https://cwe.mitre.org/data/definitions/192.html) Integer Coercion Error | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1474 / 거리 3 | Allowed |
| [CWE-194](https://cwe.mitre.org/data/definitions/194.html) Unexpected Sign Extension | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1474 / 거리 3 | Allowed |
| [CWE-195](https://cwe.mitre.org/data/definitions/195.html) Signed to Unsigned Conversion Error | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1474 / 거리 3 | Allowed |
| [CWE-196](https://cwe.mitre.org/data/definitions/196.html) Unsigned to Signed Conversion Error | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1474 / 거리 3 | Allowed |
| [CWE-197](https://cwe.mitre.org/data/definitions/197.html) Numeric Truncation Error | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1474 / 거리 3 | Allowed |
| [CWE-200](https://cwe.mitre.org/data/definitions/200.html) Exposure of Sensitive Information to an Unauthorized Actor | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 0 | Discouraged |
| [CWE-201](https://cwe.mitre.org/data/definitions/201.html) Insertion of Sensitive Information Into Sent Data | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 1 | Allowed |
| [CWE-203](https://cwe.mitre.org/data/definitions/203.html) Observable Discrepancy | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 1 | Allowed |
| [CWE-204](https://cwe.mitre.org/data/definitions/204.html) Observable Response Discrepancy | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-205](https://cwe.mitre.org/data/definitions/205.html) Observable Behavioral Discrepancy | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-206](https://cwe.mitre.org/data/definitions/206.html) Observable Internal Behavioral Discrepancy | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 3 | Allowed |
| [CWE-207](https://cwe.mitre.org/data/definitions/207.html) Observable Behavioral Discrepancy With Equivalent Products | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 3 | Allowed |
| [CWE-208](https://cwe.mitre.org/data/definitions/208.html) Observable Timing Discrepancy | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-209](https://cwe.mitre.org/data/definitions/209.html) Generation of Error Message Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 1<br>unspecified-mechanism @ CWE-200 / 거리 1 | Allowed |
| [CWE-210](https://cwe.mitre.org/data/definitions/210.html) Self-generated Error Message Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 2<br>unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-211](https://cwe.mitre.org/data/definitions/211.html) Externally-Generated Error Message Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 2<br>unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-212](https://cwe.mitre.org/data/definitions/212.html) Improper Removal of Sensitive Information Before Storage or Transfer | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-669 / 거리 1 | Allowed |
| [CWE-213](https://cwe.mitre.org/data/definitions/213.html) Exposure of Sensitive Information Due to Incompatible Policies | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 1 | Allowed |
| [CWE-214](https://cwe.mitre.org/data/definitions/214.html) Invocation of Process Using Visible Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-215](https://cwe.mitre.org/data/definitions/215.html) Insertion of Sensitive Information Into Debugging Code | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 1 | Allowed |
| [CWE-219](https://cwe.mitre.org/data/definitions/219.html) Storage of File with Sensitive Data Under Web Root | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>feature_configuration (운영) | deployment-configuration @ CWE-219 / 거리 0 | Allowed |
| [CWE-220](https://cwe.mitre.org/data/definitions/220.html) Storage of File With Sensitive Data Under FTP Root | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>feature_configuration (운영) | deployment-configuration @ CWE-220 / 거리 0 | Allowed |
| [CWE-221](https://cwe.mitre.org/data/definitions/221.html) Information Loss or Omission | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-221 / 거리 0 | Allowed-with-Review |
| [CWE-222](https://cwe.mitre.org/data/definitions/222.html) Truncation of Security-relevant Information | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-221 / 거리 1 | Allowed |
| [CWE-223](https://cwe.mitre.org/data/definitions/223.html) Omission of Security-relevant Information | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-221 / 거리 1 | Allowed |
| [CWE-224](https://cwe.mitre.org/data/definitions/224.html) Obscured Security-relevant Information by Alternate Name | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-221 / 거리 1 | Allowed |
| [CWE-226](https://cwe.mitre.org/data/definitions/226.html) Sensitive Information in Resource Not Removed Before Reuse | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-404, CWE-669 / 거리 2 | Allowed |
| [CWE-243](https://cwe.mitre.org/data/definitions/243.html) Creation of chroot Jail Without Changing Working Directory | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-669 / 거리 1<br>code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-244](https://cwe.mitre.org/data/definitions/244.html) Improper Clearing of Heap Memory Before Release | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-404, CWE-669 / 거리 3 | Allowed |
| [CWE-256](https://cwe.mitre.org/data/definitions/256.html) Plaintext Storage of a Password | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-257](https://cwe.mitre.org/data/definitions/257.html) Storing Passwords in a Recoverable Format | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-258](https://cwe.mitre.org/data/definitions/258.html) Empty Password in Configuration File | 운영 검토 가능<br>운영: 필수 | account_policy (운영) | password-configuration @ CWE-258 / 거리 0 | Allowed |
| [CWE-260](https://cwe.mitre.org/data/definitions/260.html) Password in Configuration File | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-261](https://cwe.mitre.org/data/definitions/261.html) Weak Encoding for Password | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-262](https://cwe.mitre.org/data/definitions/262.html) Not Using Password Aging | 운영 검토 가능<br>운영: 필수 | account_policy (운영) | password-configuration @ CWE-262 / 거리 0 | Allowed |
| [CWE-263](https://cwe.mitre.org/data/definitions/263.html) Password Aging with Long Expiration | 운영 검토 가능<br>운영: 필수 | account_policy (운영) | password-configuration @ CWE-263 / 거리 0 | Discouraged |
| [CWE-276](https://cwe.mitre.org/data/definitions/276.html) Incorrect Default Permissions | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>resource_permissions (운영) | resource-permissions @ CWE-276 / 거리 0 | Allowed |
| [CWE-277](https://cwe.mitre.org/data/definitions/277.html) Insecure Inherited Permissions | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>resource_permissions (운영) | resource-permissions @ CWE-277 / 거리 0 | Allowed |
| [CWE-278](https://cwe.mitre.org/data/definitions/278.html) Insecure Preserved Inherited Permissions | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>resource_permissions (운영) | resource-permissions @ CWE-278 / 거리 0 | Allowed |
| [CWE-279](https://cwe.mitre.org/data/definitions/279.html) Incorrect Execution-Assigned Permissions | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>resource_permissions (운영) | resource-permissions @ CWE-279 / 거리 0 | Allowed |
| [CWE-281](https://cwe.mitre.org/data/definitions/281.html) Improper Preservation of Permissions | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>resource_permissions (운영) | resource-permissions @ CWE-281 / 거리 0 | Allowed |
| [CWE-298](https://cwe.mitre.org/data/definitions/298.html) Improper Validation of Certificate Expiration | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-295 / 거리 1 | Allowed |
| [CWE-299](https://cwe.mitre.org/data/definitions/299.html) Improper Check for Certificate Revocation | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-404 / 거리 1<br>crypto-implementation @ CWE-295 / 거리 1 | Allowed |
| [CWE-312](https://cwe.mitre.org/data/definitions/312.html) Cleartext Storage of Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 1 | Allowed |
| [CWE-313](https://cwe.mitre.org/data/definitions/313.html) Cleartext Storage in a File or on Disk | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 2 | Allowed |
| [CWE-314](https://cwe.mitre.org/data/definitions/314.html) Cleartext Storage in the Registry | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 2 | Allowed |
| [CWE-315](https://cwe.mitre.org/data/definitions/315.html) Cleartext Storage of Sensitive Information in a Cookie | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 2 | Allowed |
| [CWE-316](https://cwe.mitre.org/data/definitions/316.html) Cleartext Storage of Sensitive Information in Memory | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 2 | Allowed |
| [CWE-317](https://cwe.mitre.org/data/definitions/317.html) Cleartext Storage of Sensitive Information in GUI | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 2 | Allowed |
| [CWE-318](https://cwe.mitre.org/data/definitions/318.html) Cleartext Storage of Sensitive Information in Executable | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 2 | Allowed |
| [CWE-324](https://cwe.mitre.org/data/definitions/324.html) Use of a Key Past its Expiration Date | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-666 / 거리 2 | Allowed |
| [CWE-359](https://cwe.mitre.org/data/definitions/359.html) Exposure of Private Personal Information to an Unauthorized Actor | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 1 | Allowed |
| [CWE-362](https://cwe.mitre.org/data/definitions/362.html) Concurrent Execution using Shared Resource with Improper Synchronization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 1 | Allowed-with-Review |
| [CWE-363](https://cwe.mitre.org/data/definitions/363.html) Race Condition Enabling Link Following | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 3 | Allowed |
| [CWE-364](https://cwe.mitre.org/data/definitions/364.html) Signal Handler Race Condition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-366](https://cwe.mitre.org/data/definitions/366.html) Race Condition within a Thread | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-367](https://cwe.mitre.org/data/definitions/367.html) Time-of-check Time-of-use (TOCTOU) Race Condition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-368](https://cwe.mitre.org/data/definitions/368.html) Context Switching Race Condition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-370](https://cwe.mitre.org/data/definitions/370.html) Missing Check for Certificate Revocation after Initial Check | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-404 / 거리 2<br>crypto-implementation @ CWE-295 / 거리 2 | Allowed |
| [CWE-372](https://cwe.mitre.org/data/definitions/372.html) Incomplete Internal State Distinction | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-372 / 거리 0 | Discouraged |
| [CWE-374](https://cwe.mitre.org/data/definitions/374.html) Passing Mutable Objects to an Untrusted Method | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-375](https://cwe.mitre.org/data/definitions/375.html) Returning a Mutable Object to an Untrusted Caller | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-384](https://cwe.mitre.org/data/definitions/384.html) Session Fixation | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>reference_resolution (소스) | authorization-enforcement @ CWE-1462 / 거리 1<br>reference-resolution @ CWE-610 / 거리 1 | Allowed |
| [CWE-385](https://cwe.mitre.org/data/definitions/385.html) Covert Timing Channel | 추가 근거·전문 자료<br>운영: 미정 | side_channel_measurement (전문 자료) | covert-channel @ CWE-514 / 거리 1 | Allowed |
| [CWE-386](https://cwe.mitre.org/data/definitions/386.html) Symbolic Name not Mapping to Correct Object | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 1 | Allowed |
| [CWE-396](https://cwe.mitre.org/data/definitions/396.html) Declaration of Catch for Generic Exception | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-705 / 거리 1<br>error-handling @ CWE-221, CWE-755 / 거리 1 | Allowed |
| [CWE-397](https://cwe.mitre.org/data/definitions/397.html) Declaration of Throws for Generic Exception | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-397 / 거리 0 | Allowed |
| [CWE-400](https://cwe.mitre.org/data/definitions/400.html) Uncontrolled Resource Consumption | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 0 | Discouraged |
| [CWE-401](https://cwe.mitre.org/data/definitions/401.html) Missing Release of Memory after Effective Lifetime | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-404 / 거리 2 | Allowed |
| [CWE-402](https://cwe.mitre.org/data/definitions/402.html) Transmission of Private Resources into a New Sphere | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed-with-Review |
| [CWE-403](https://cwe.mitre.org/data/definitions/403.html) Exposure of File Descriptor to Unintended Control Sphere | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-404](https://cwe.mitre.org/data/definitions/404.html) Improper Resource Shutdown or Release | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-404 / 거리 0 | Allowed-with-Review |
| [CWE-405](https://cwe.mitre.org/data/definitions/405.html) Asymmetric Resource Consumption (Amplification) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 1 | Allowed-with-Review |
| [CWE-406](https://cwe.mitre.org/data/definitions/406.html) Insufficient Control of Network Message Volume (Network Amplification) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 2 | Allowed-with-Review |
| [CWE-407](https://cwe.mitre.org/data/definitions/407.html) Inefficient Algorithmic Complexity | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 2 | Allowed-with-Review |
| [CWE-408](https://cwe.mitre.org/data/definitions/408.html) Incorrect Behavior Order: Early Amplification | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-696 / 거리 1 | Allowed |
| [CWE-409](https://cwe.mitre.org/data/definitions/409.html) Improper Handling of Highly Compressed Data (Data Amplification) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 2 | Allowed |
| [CWE-410](https://cwe.mitre.org/data/definitions/410.html) Insufficient Resource Pool | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-410 / 거리 0 | Allowed |
| [CWE-412](https://cwe.mitre.org/data/definitions/412.html) Unrestricted Externally Accessible Lock | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-413](https://cwe.mitre.org/data/definitions/413.html) Improper Resource Locking | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-414](https://cwe.mitre.org/data/definitions/414.html) Missing Lock Check | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-415](https://cwe.mitre.org/data/definitions/415.html) Double Free | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-415 / 거리 0 | Allowed |
| [CWE-416](https://cwe.mitre.org/data/definitions/416.html) Use After Free | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-416 / 거리 0 | Allowed |
| [CWE-421](https://cwe.mitre.org/data/definitions/421.html) Race Condition During Access to Alternate Channel | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>state_control_flow (소스) | authorization-enforcement @ CWE-923 / 거리 2<br>state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-426](https://cwe.mitre.org/data/definitions/426.html) Untrusted Search Path | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-673 / 거리 1 | Allowed-with-Review |
| [CWE-427](https://cwe.mitre.org/data/definitions/427.html) Uncontrolled Search Path Element | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed-with-Review |
| [CWE-428](https://cwe.mitre.org/data/definitions/428.html) Unquoted Search Path or Element | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-432](https://cwe.mitre.org/data/definitions/432.html) Dangerous Signal Handler not Disabled During Sensitive Operations | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 3 | Allowed |
| [CWE-433](https://cwe.mitre.org/data/definitions/433.html) Unparsed Raw Web Content Delivery | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>feature_configuration (운영) | deployment-configuration @ CWE-219 / 거리 1 | Allowed |
| [CWE-434](https://cwe.mitre.org/data/definitions/434.html) Unrestricted Upload of File with Dangerous Type | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-669 / 거리 1 | Allowed |
| [CWE-441](https://cwe.mitre.org/data/definitions/441.html) Unintended Proxy or Intermediary | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-610 / 거리 1 | Allowed-with-Review |
| [CWE-451](https://cwe.mitre.org/data/definitions/451.html) User Interface (UI) Misrepresentation of Critical Information | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>error_handling (소스) | error-handling @ CWE-221 / 거리 1<br>code-structure @ CWE-684 / 거리 1 | Allowed-with-Review |
| [CWE-453](https://cwe.mitre.org/data/definitions/453.html) Insecure Default Variable Initialization | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-665 / 거리 3<br>crypto-implementation @ CWE-330 / 거리 3 | Allowed |
| [CWE-454](https://cwe.mitre.org/data/definitions/454.html) External Initialization of Trusted Variables or Data Stores | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665 / 거리 2 | Allowed |
| [CWE-455](https://cwe.mitre.org/data/definitions/455.html) Non-exit on Failed Initialization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665, CWE-705 / 거리 1 | Allowed |
| [CWE-456](https://cwe.mitre.org/data/definitions/456.html) Missing Initialization of a Variable | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665 / 거리 2 | Allowed |
| [CWE-457](https://cwe.mitre.org/data/definitions/457.html) Use of Uninitialized Variable | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-457 / 거리 0 | Allowed |
| [CWE-459](https://cwe.mitre.org/data/definitions/459.html) Incomplete Cleanup | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-404 / 거리 1 | Allowed |
| [CWE-460](https://cwe.mitre.org/data/definitions/460.html) Improper Cleanup on Thrown Exception | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-755 / 거리 1 | Allowed |
| [CWE-466](https://cwe.mitre.org/data/definitions/466.html) Return of Pointer Value Outside of Expected Range | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 1 | Allowed |
| [CWE-470](https://cwe.mitre.org/data/definitions/470.html) Use of Externally-Controlled Input to Select Classes or Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-610, CWE-913 / 거리 1 | Allowed |
| [CWE-471](https://cwe.mitre.org/data/definitions/471.html) Modification of Assumed-Immutable Data (MAID) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-471 / 거리 0 | Allowed |
| [CWE-472](https://cwe.mitre.org/data/definitions/472.html) External Control of Assumed-Immutable Web Parameter | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-471 / 거리 1 | Allowed |
| [CWE-473](https://cwe.mitre.org/data/definitions/473.html) PHP External Variable Modification | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-471 / 거리 1 | Allowed |
| [CWE-479](https://cwe.mitre.org/data/definitions/479.html) Signal Handler Use of a Non-reentrant Function | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-487](https://cwe.mitre.org/data/definitions/487.html) Reliance on Package-level Scope | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-487 / 거리 0 | Allowed |
| [CWE-488](https://cwe.mitre.org/data/definitions/488.html) Exposure of Data Element to Wrong Session | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-491](https://cwe.mitre.org/data/definitions/491.html) Public cloneable() Method Without Final | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-492](https://cwe.mitre.org/data/definitions/492.html) Use of Inner Class Containing Sensitive Data | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-493](https://cwe.mitre.org/data/definitions/493.html) Critical Public Variable Without Final Modifier | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | language-access-modifiers @ CWE-493 / 거리 0 | Allowed |
| [CWE-494](https://cwe.mitre.org/data/definitions/494.html) Download of Code Without Integrity Check | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-669 / 거리 1<br>crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-495](https://cwe.mitre.org/data/definitions/495.html) Private Data Structure Returned From A Public Method | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-496](https://cwe.mitre.org/data/definitions/496.html) Public Data Assigned to Private Array-Typed Field | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-497](https://cwe.mitre.org/data/definitions/497.html) Exposure of Sensitive System Information to an Unauthorized Control Sphere | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 1 | Allowed |
| [CWE-498](https://cwe.mitre.org/data/definitions/498.html) Cloneable Class Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-499](https://cwe.mitre.org/data/definitions/499.html) Serializable Class Containing Sensitive Data | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-500](https://cwe.mitre.org/data/definitions/500.html) Public Static Field Not Marked Final | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | language-access-modifiers @ CWE-500 / 거리 0 | Allowed |
| [CWE-501](https://cwe.mitre.org/data/definitions/501.html) Trust Boundary Violation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-501 / 거리 0 | Allowed |
| [CWE-502](https://cwe.mitre.org/data/definitions/502.html) Deserialization of Untrusted Data | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-913 / 거리 1 | Allowed |
| [CWE-514](https://cwe.mitre.org/data/definitions/514.html) Covert Channel | 추가 근거·전문 자료<br>운영: 미정 | side_channel_measurement (전문 자료) | covert-channel @ CWE-514 / 거리 0 | Allowed-with-Review |
| [CWE-515](https://cwe.mitre.org/data/definitions/515.html) Covert Storage Channel | 추가 근거·전문 자료<br>운영: 미정 | side_channel_measurement (전문 자료) | covert-channel @ CWE-514 / 거리 1 | Allowed |
| [CWE-522](https://cwe.mitre.org/data/definitions/522.html) Insufficiently Protected Credentials | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed-with-Review |
| [CWE-523](https://cwe.mitre.org/data/definitions/523.html) Unprotected Transport of Credentials | 운영 검토 가능<br>운영: 필수 | communication_configuration (운영) | transport-encryption @ CWE-523 / 거리 0 | Allowed |
| [CWE-524](https://cwe.mitre.org/data/definitions/524.html) Use of Cache Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-525](https://cwe.mitre.org/data/definitions/525.html) Use of Web Browser Cache Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-526](https://cwe.mitre.org/data/definitions/526.html) Cleartext Storage of Sensitive Information in an Environment Variable | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 2 | Allowed |
| [CWE-527](https://cwe.mitre.org/data/definitions/527.html) Exposure of Version-Control Repository to an Unauthorized Control Sphere | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | authorization-enforcement @ CWE-285 / 거리 2<br>unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-528](https://cwe.mitre.org/data/definitions/528.html) Exposure of Core Dump File to an Unauthorized Control Sphere | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | authorization-enforcement @ CWE-285 / 거리 2<br>unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-529](https://cwe.mitre.org/data/definitions/529.html) Exposure of Access Control List Files to an Unauthorized Control Sphere | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | authorization-enforcement @ CWE-285 / 거리 2<br>unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-530](https://cwe.mitre.org/data/definitions/530.html) Exposure of Backup File to an Unauthorized Control Sphere | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | authorization-enforcement @ CWE-285 / 거리 2<br>unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-531](https://cwe.mitre.org/data/definitions/531.html) Inclusion of Sensitive Information in Test Code | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 3 | Allowed |
| [CWE-532](https://cwe.mitre.org/data/definitions/532.html) Insertion of Sensitive Information into Log File | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-535](https://cwe.mitre.org/data/definitions/535.html) Exposure of Information Through Shell Error Message | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 3<br>unspecified-mechanism @ CWE-200 / 거리 3 | Allowed |
| [CWE-536](https://cwe.mitre.org/data/definitions/536.html) Servlet Runtime Error Message Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 3<br>unspecified-mechanism @ CWE-200 / 거리 3 | Allowed |
| [CWE-537](https://cwe.mitre.org/data/definitions/537.html) Java Runtime Error Message Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 3<br>unspecified-mechanism @ CWE-200 / 거리 3 | Allowed |
| [CWE-538](https://cwe.mitre.org/data/definitions/538.html) Insertion of Sensitive Information into Externally-Accessible File or Directory | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 1 | Allowed |
| [CWE-539](https://cwe.mitre.org/data/definitions/539.html) Use of Persistent Cookies Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | authorization-enforcement @ CWE-285 / 거리 2<br>unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-540](https://cwe.mitre.org/data/definitions/540.html) Inclusion of Sensitive Information in Source Code | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-541](https://cwe.mitre.org/data/definitions/541.html) Inclusion of Sensitive Information in an Include File | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 3 | Allowed |
| [CWE-543](https://cwe.mitre.org/data/definitions/543.html) Use of Singleton Pattern Without Synchronization in a Multithreaded Context | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-548](https://cwe.mitre.org/data/definitions/548.html) Exposure of Information Through Directory Listing | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>feature_configuration (운영) | deployment-configuration @ CWE-548 / 거리 0 | Allowed |
| [CWE-549](https://cwe.mitre.org/data/definitions/549.html) Missing Password Field Masking | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-550](https://cwe.mitre.org/data/definitions/550.html) Server-generated Error Message Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 2<br>unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-552](https://cwe.mitre.org/data/definitions/552.html) Files or Directories Accessible to External Parties | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | authorization-enforcement @ CWE-285 / 거리 1<br>unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-553](https://cwe.mitre.org/data/definitions/553.html) Command Shell in Externally Accessible Directory | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | authorization-enforcement @ CWE-285 / 거리 2<br>unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-555](https://cwe.mitre.org/data/definitions/555.html) J2EE Misconfiguration: Plaintext Password in Configuration File | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 3 | Allowed |
| [CWE-558](https://cwe.mitre.org/data/definitions/558.html) Use of getlogin() in Multithreaded Application | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-565](https://cwe.mitre.org/data/definitions/565.html) Reliance on Cookies without Validation and Integrity Checking | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-602 / 거리 1 | Allowed |
| [CWE-567](https://cwe.mitre.org/data/definitions/567.html) Unsynchronized Access to Shared Data in a Multithreaded Context | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-568](https://cwe.mitre.org/data/definitions/568.html) finalize() Method Without super.finalize() | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-572](https://cwe.mitre.org/data/definitions/572.html) Call to Thread run() instead of start() | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-574](https://cwe.mitre.org/data/definitions/574.html) EJB Bad Practices: Use of Synchronization Primitives | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2<br>code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-580](https://cwe.mitre.org/data/definitions/580.html) clone() Method Without super.clone() | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-580 / 거리 0 | Allowed |
| [CWE-582](https://cwe.mitre.org/data/definitions/582.html) Array Declared Public, Final, and Static | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | language-access-modifiers @ CWE-582 / 거리 0 | Allowed |
| [CWE-583](https://cwe.mitre.org/data/definitions/583.html) finalize() Method Declared Public | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | language-access-modifiers @ CWE-583 / 거리 0 | Allowed |
| [CWE-588](https://cwe.mitre.org/data/definitions/588.html) Attempt to Access Child of a Non-structure Pointer | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-758 / 거리 1 | Allowed |
| [CWE-590](https://cwe.mitre.org/data/definitions/590.html) Free of Memory not on the Heap | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-404 / 거리 3 | Allowed |
| [CWE-591](https://cwe.mitre.org/data/definitions/591.html) Sensitive Data Storage in Improperly Locked Memory | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 3 | Allowed |
| [CWE-593](https://cwe.mitre.org/data/definitions/593.html) Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-666 / 거리 1 | Allowed |
| [CWE-598](https://cwe.mitre.org/data/definitions/598.html) Use of HTTP Request With Sensitive Query String | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-601](https://cwe.mitre.org/data/definitions/601.html) URL Redirection to Untrusted Site | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-610 / 거리 1 | Allowed |
| [CWE-605](https://cwe.mitre.org/data/definitions/605.html) Multiple Binds to the Same Port | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-666 / 거리 1 | Allowed |
| [CWE-607](https://cwe.mitre.org/data/definitions/607.html) Public Static Final Field References Mutable Object | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-471 / 거리 1 | Allowed |
| [CWE-608](https://cwe.mitre.org/data/definitions/608.html) Struts: Non-private Field in ActionForm Class | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | language-access-modifiers @ CWE-608 / 거리 0 | Allowed |
| [CWE-609](https://cwe.mitre.org/data/definitions/609.html) Double-Checked Locking | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-610](https://cwe.mitre.org/data/definitions/610.html) Externally Controlled Reference to a Resource in Another Sphere | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-610 / 거리 0 | Discouraged |
| [CWE-611](https://cwe.mitre.org/data/definitions/611.html) Improper Restriction of XML External Entity Reference | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-610 / 거리 1 | Allowed |
| [CWE-615](https://cwe.mitre.org/data/definitions/615.html) Inclusion of Sensitive Information in Source Code Comments | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 3 | Allowed |
| [CWE-619](https://cwe.mitre.org/data/definitions/619.html) Dangling Database Cursor | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 2 | Allowed |
| [CWE-621](https://cwe.mitre.org/data/definitions/621.html) Variable Extraction Error | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-913 / 거리 2 | Allowed |
| [CWE-627](https://cwe.mitre.org/data/definitions/627.html) Dynamic Variable Evaluation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-913 / 거리 2 | Allowed |
| [CWE-642](https://cwe.mitre.org/data/definitions/642.html) External Control of Critical State Data | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed-with-Review |
| [CWE-651](https://cwe.mitre.org/data/definitions/651.html) Exposure of WSDL File Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-662](https://cwe.mitre.org/data/definitions/662.html) Improper Synchronization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 0 | Discouraged |
| [CWE-663](https://cwe.mitre.org/data/definitions/663.html) Use of a Non-reentrant Function in a Concurrent Context | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 1 | Allowed |
| [CWE-665](https://cwe.mitre.org/data/definitions/665.html) Improper Initialization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665 / 거리 0 | Discouraged |
| [CWE-666](https://cwe.mitre.org/data/definitions/666.html) Operation on Resource in Wrong Phase of Lifetime | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-666 / 거리 0 | Discouraged |
| [CWE-667](https://cwe.mitre.org/data/definitions/667.html) Improper Locking | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 1 | Allowed-with-Review |
| [CWE-668](https://cwe.mitre.org/data/definitions/668.html) Exposure of Resource to Wrong Sphere | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 0 | Discouraged |
| [CWE-669](https://cwe.mitre.org/data/definitions/669.html) Incorrect Resource Transfer Between Spheres | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-669 / 거리 0 | Allowed-with-Review |
| [CWE-672](https://cwe.mitre.org/data/definitions/672.html) Operation on a Resource after Expiration or Release | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-666 / 거리 1 | Allowed-with-Review |
| [CWE-673](https://cwe.mitre.org/data/definitions/673.html) External Influence of Sphere Definition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-673 / 거리 0 | Allowed-with-Review |
| [CWE-681](https://cwe.mitre.org/data/definitions/681.html) Incorrect Conversion between Numeric Types | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1474 / 거리 2 | Allowed |
| [CWE-689](https://cwe.mitre.org/data/definitions/689.html) Permission Race Condition During Resource Copy | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-704](https://cwe.mitre.org/data/definitions/704.html) Incorrect Type Conversion or Cast | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1474 / 거리 1 | Allowed-with-Review |
| [CWE-706](https://cwe.mitre.org/data/definitions/706.html) Use of Incorrectly-Resolved Name or Reference | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 0 | Allowed-with-Review |
| [CWE-732](https://cwe.mitre.org/data/definitions/732.html) Incorrect Permission Assignment for Critical Resource | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>resource_permissions (운영) | resource-permissions @ CWE-732 / 거리 0 | Allowed-with-Review |
| [CWE-761](https://cwe.mitre.org/data/definitions/761.html) Free of Pointer not at Start of Buffer | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-404 / 거리 2 | Allowed |
| [CWE-762](https://cwe.mitre.org/data/definitions/762.html) Mismatched Memory Management Routines | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-404 / 거리 2 | Allowed |
| [CWE-763](https://cwe.mitre.org/data/definitions/763.html) Release of Invalid Pointer or Reference | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-404 / 거리 1 | Allowed |
| [CWE-764](https://cwe.mitre.org/data/definitions/764.html) Multiple Locks of a Critical Resource | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2<br>code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-765](https://cwe.mitre.org/data/definitions/765.html) Multiple Unlocks of a Critical Resource | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2<br>code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-766](https://cwe.mitre.org/data/definitions/766.html) Critical Data Element Declared Public | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>code_structure (소스)<br>resource_permissions (운영) | code-structure @ CWE-1061 / 거리 1<br>resource-permissions @ CWE-732 / 거리 1 | Allowed |
| [CWE-767](https://cwe.mitre.org/data/definitions/767.html) Access to Critical Private Variable via Public Method | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-770](https://cwe.mitre.org/data/definitions/770.html) Allocation of Resources Without Limits or Throttling | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400, CWE-665 / 거리 1 | Allowed |
| [CWE-771](https://cwe.mitre.org/data/definitions/771.html) Missing Reference to Active Allocated Resource | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 1 | Allowed |
| [CWE-772](https://cwe.mitre.org/data/definitions/772.html) Missing Release of Resource after Effective Lifetime | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-404 / 거리 1 | Allowed |
| [CWE-773](https://cwe.mitre.org/data/definitions/773.html) Missing Reference to Active File Descriptor or Handle | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 2 | Allowed |
| [CWE-774](https://cwe.mitre.org/data/definitions/774.html) Allocation of File Descriptors or Handles Without Limits or Throttling | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400, CWE-665 / 거리 2 | Allowed |
| [CWE-775](https://cwe.mitre.org/data/definitions/775.html) Missing Release of File Descriptor or Handle after Effective Lifetime | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-404 / 거리 2 | Allowed |
| [CWE-776](https://cwe.mitre.org/data/definitions/776.html) Improper Restriction of Recursive Entity References in DTDs | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400, CWE-834 / 거리 2 | Allowed |
| [CWE-778](https://cwe.mitre.org/data/definitions/778.html) Insufficient Logging | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-221 / 거리 2 | Allowed |
| [CWE-779](https://cwe.mitre.org/data/definitions/779.html) Logging of Excessive Data | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 1 | Allowed |
| [CWE-784](https://cwe.mitre.org/data/definitions/784.html) Reliance on Cookies without Validation and Integrity Checking in a Security Decision | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-807 / 거리 1 | Allowed |
| [CWE-785](https://cwe.mitre.org/data/definitions/785.html) Use of Path Manipulation Function without Maximum-sized Buffer | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 2<br>code-structure @ CWE-1177 / 거리 2 | Allowed |
| [CWE-786](https://cwe.mitre.org/data/definitions/786.html) Access of Memory Location Before Start of Buffer | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 1 | Discouraged |
| [CWE-787](https://cwe.mitre.org/data/definitions/787.html) Out-of-bounds Write | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 1 | Allowed-with-Review |
| [CWE-788](https://cwe.mitre.org/data/definitions/788.html) Access of Memory Location After End of Buffer | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 1 | Discouraged |
| [CWE-789](https://cwe.mitre.org/data/definitions/789.html) Memory Allocation with Excessive Size Value | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400, CWE-665 / 거리 2 | Allowed |
| [CWE-805](https://cwe.mitre.org/data/definitions/805.html) Buffer Access with Incorrect Length Value | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 1 | Allowed |
| [CWE-806](https://cwe.mitre.org/data/definitions/806.html) Buffer Access Using Size of Source Buffer | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 2 | Allowed |
| [CWE-820](https://cwe.mitre.org/data/definitions/820.html) Missing Synchronization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 1 | Allowed |
| [CWE-821](https://cwe.mitre.org/data/definitions/821.html) Incorrect Synchronization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 1 | Allowed |
| [CWE-822](https://cwe.mitre.org/data/definitions/822.html) Untrusted Pointer Dereference | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 1 | Allowed |
| [CWE-823](https://cwe.mitre.org/data/definitions/823.html) Use of Out-of-range Pointer Offset | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 1 | Allowed |
| [CWE-824](https://cwe.mitre.org/data/definitions/824.html) Access of Uninitialized Pointer | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 1 | Allowed |
| [CWE-825](https://cwe.mitre.org/data/definitions/825.html) Expired Pointer Dereference | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 1 | Allowed |
| [CWE-826](https://cwe.mitre.org/data/definitions/826.html) Premature Release of Resource During Expected Lifetime | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-666 / 거리 1 | Allowed |
| [CWE-827](https://cwe.mitre.org/data/definitions/827.html) Improper Control of Document Type Definition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 1 | Allowed |
| [CWE-828](https://cwe.mitre.org/data/definitions/828.html) Signal Handler with Functionality that is not Asynchronous-Safe | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 3 | Allowed |
| [CWE-829](https://cwe.mitre.org/data/definitions/829.html) Inclusion of Functionality from Untrusted Control Sphere | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-669 / 거리 1 | Allowed |
| [CWE-830](https://cwe.mitre.org/data/definitions/830.html) Inclusion of Web Functionality from an Untrusted Source | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-669 / 거리 2 | Allowed |
| [CWE-831](https://cwe.mitre.org/data/definitions/831.html) Signal Handler Function Associated with Multiple Signals | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 3 | Allowed |
| [CWE-832](https://cwe.mitre.org/data/definitions/832.html) Unlock of a Resource that is not Locked | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-833](https://cwe.mitre.org/data/definitions/833.html) Deadlock | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-843](https://cwe.mitre.org/data/definitions/843.html) Access of Resource Using Incompatible Type | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1474 / 거리 2 | Allowed |
| [CWE-908](https://cwe.mitre.org/data/definitions/908.html) Use of Uninitialized Resource | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665 / 거리 1 | Allowed |
| [CWE-909](https://cwe.mitre.org/data/definitions/909.html) Missing Initialization of Resource | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665 / 거리 1 | Allowed-with-Review |
| [CWE-910](https://cwe.mitre.org/data/definitions/910.html) Use of Expired File Descriptor | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-666 / 거리 2 | Allowed |
| [CWE-911](https://cwe.mitre.org/data/definitions/911.html) Improper Update of Reference Count | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-911 / 거리 0 | Allowed |
| [CWE-913](https://cwe.mitre.org/data/definitions/913.html) Improper Control of Dynamically-Managed Code Resources | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-913 / 거리 0 | Allowed-with-Review |
| [CWE-914](https://cwe.mitre.org/data/definitions/914.html) Improper Control of Dynamically-Identified Variables | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-913 / 거리 1 | Allowed |
| [CWE-915](https://cwe.mitre.org/data/definitions/915.html) Improperly Controlled Modification of Dynamically-Determined Object Attributes | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-913 / 거리 1 | Allowed |
| [CWE-918](https://cwe.mitre.org/data/definitions/918.html) Server-Side Request Forgery | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-610 / 거리 2 | Allowed |
| [CWE-920](https://cwe.mitre.org/data/definitions/920.html) Improper Restriction of Power Consumption | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 1 | Allowed |
| [CWE-921](https://cwe.mitre.org/data/definitions/921.html) Storage of Sensitive Data in a Mechanism without Access Control | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-922 / 거리 1 | Allowed |
| [CWE-922](https://cwe.mitre.org/data/definitions/922.html) Insecure Storage of Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-922 / 거리 0 | Allowed-with-Review |
| [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) Sensitive Cookie Without 'HttpOnly' Flag | 운영 검토 가능<br>운영: 필수 | communication_configuration (운영)<br>feature_configuration (운영) | cookie-configuration @ CWE-1004 / 거리 0 | Allowed |
| [CWE-1007](https://cwe.mitre.org/data/definitions/1007.html) Insufficient Visual Distinction of Homoglyphs Presented to User | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>error_handling (소스) | error-handling @ CWE-221 / 거리 2<br>code-structure @ CWE-684 / 거리 2 | Allowed |
| [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) Improper Restriction of Rendered UI Layers or Frames | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>error_handling (소스)<br>reference_resolution (소스) | reference-resolution @ CWE-610 / 거리 2<br>error-handling @ CWE-221 / 거리 2<br>code-structure @ CWE-684 / 거리 2 | Allowed |
| [CWE-1042](https://cwe.mitre.org/data/definitions/1042.html) Static Member Data Element outside of a Singleton Class Element | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 3 | Prohibited |
| [CWE-1046](https://cwe.mitre.org/data/definitions/1046.html) Creation of Immutable Text Using String Concatenation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 3 | Allowed |
| [CWE-1049](https://cwe.mitre.org/data/definitions/1049.html) Excessive Data Query Operations in a Large Data Table | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 3 | Allowed |
| [CWE-1050](https://cwe.mitre.org/data/definitions/1050.html) Excessive Platform Resource Consumption within a Loop | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 2 | Allowed |
| [CWE-1051](https://cwe.mitre.org/data/definitions/1051.html) Initialization with Hard-Coded Network Resource Configuration Data | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665 / 거리 2 | Prohibited |
| [CWE-1052](https://cwe.mitre.org/data/definitions/1052.html) Excessive Use of Hard-Coded Literals in Initialization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665 / 거리 2 | Allowed |
| [CWE-1058](https://cwe.mitre.org/data/definitions/1058.html) Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 1 | Allowed |
| [CWE-1063](https://cwe.mitre.org/data/definitions/1063.html) Creation of Class Instance within a Static Code Block | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 3 | Prohibited |
| [CWE-1067](https://cwe.mitre.org/data/definitions/1067.html) Excessive Execution of Sequential Searches of Data Resource | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 3 | Allowed |
| [CWE-1072](https://cwe.mitre.org/data/definitions/1072.html) Data Resource Access without Use of Connection Pooling | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 2 | Prohibited |
| [CWE-1073](https://cwe.mitre.org/data/definitions/1073.html) Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 2 | Prohibited |
| [CWE-1084](https://cwe.mitre.org/data/definitions/1084.html) Invokable Control Element with Excessive File or Data Access Operations | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 2 | Prohibited |
| [CWE-1088](https://cwe.mitre.org/data/definitions/1088.html) Synchronous Access of Remote Resource without Timeout | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-1089](https://cwe.mitre.org/data/definitions/1089.html) Large Data Table with Excessive Number of Indices | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 2 | Allowed |
| [CWE-1091](https://cwe.mitre.org/data/definitions/1091.html) Use of Object without Invoking Destructor Method | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 1 | Allowed |
| [CWE-1094](https://cwe.mitre.org/data/definitions/1094.html) Excessive Index Range Scan for a Data Resource | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 2 | Prohibited |
| [CWE-1096](https://cwe.mitre.org/data/definitions/1096.html) Singleton Class Instance Creation without Proper Locking or Synchronization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-1176](https://cwe.mitre.org/data/definitions/1176.html) Inefficient CPU Computation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 2 | Allowed-with-Review |
| [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) Initialization of a Resource with an Insecure Default | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-665 / 거리 2<br>crypto-implementation @ CWE-330 / 거리 2 | Allowed |
| [CWE-1189](https://cwe.mitre.org/data/definitions/1189.html) Improper Isolation of Shared Resources on System-on-a-Chip (SoC) | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | security-enforcement @ CWE-653 / 거리 1<br>unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-1221](https://cwe.mitre.org/data/definitions/1221.html) Incorrect Register Defaults or Module Parameters | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1221 / 거리 0 | Allowed |
| [CWE-1223](https://cwe.mitre.org/data/definitions/1223.html) Race Condition for Write-Once Attributes | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1223 / 거리 0 | Allowed |
| [CWE-1229](https://cwe.mitre.org/data/definitions/1229.html) Creation of Emergent Resource | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | emergent-resource-design @ CWE-1229 / 거리 0 | Allowed-with-Review |
| [CWE-1232](https://cwe.mitre.org/data/definitions/1232.html) Improper Lock Behavior After Power State Transition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-1233](https://cwe.mitre.org/data/definitions/1233.html) Security-Sensitive Hardware Controls with Missing Lock Bit Protection | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1233 / 거리 0 | Allowed |
| [CWE-1234](https://cwe.mitre.org/data/definitions/1234.html) Hardware Internal or Debug Modes Allow Override of Locks | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1234 / 거리 0 | Allowed |
| [CWE-1235](https://cwe.mitre.org/data/definitions/1235.html) Incorrect Use of Autoboxing and Unboxing for Performance Critical Operations | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 1 | Allowed |
| [CWE-1239](https://cwe.mitre.org/data/definitions/1239.html) Improper Zeroization of Hardware Register | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1239 / 거리 0 | Allowed |
| [CWE-1246](https://cwe.mitre.org/data/definitions/1246.html) Improper Write Handling in Limited-write Non-Volatile Memories | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 1 | Allowed |
| [CWE-1249](https://cwe.mitre.org/data/definitions/1249.html) Application-Level Admin Tool with Inconsistent View of Underlying Operating System | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>state_control_flow (소스) | distributed-state @ CWE-1249 / 거리 0 | Allowed |
| [CWE-1250](https://cwe.mitre.org/data/definitions/1250.html) Improper Preservation of Consistency Between Independent Representations of Shared State | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>state_control_flow (소스) | distributed-state @ CWE-1250 / 거리 0 | Allowed |
| [CWE-1251](https://cwe.mitre.org/data/definitions/1251.html) Mirrored Regions with Different Values | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1251 / 거리 0 | Allowed |
| [CWE-1254](https://cwe.mitre.org/data/definitions/1254.html) Incorrect Comparison Logic Granularity | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 3 | Allowed |
| [CWE-1255](https://cwe.mitre.org/data/definitions/1255.html) Comparison Logic is Vulnerable to Power Side-Channel Attacks | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 3 | Allowed |
| [CWE-1258](https://cwe.mitre.org/data/definitions/1258.html) Exposure of Sensitive System Information Due to Uncleared Debug Information | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-404, CWE-669 / 거리 4 | Allowed |
| [CWE-1264](https://cwe.mitre.org/data/definitions/1264.html) Hardware Logic with Insecure De-Synchronization between Control and Data Channels | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1264 / 거리 0 | Allowed |
| [CWE-1265](https://cwe.mitre.org/data/definitions/1265.html) Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 1 | Allowed |
| [CWE-1266](https://cwe.mitre.org/data/definitions/1266.html) Improper Scrubbing of Sensitive Data from Decommissioned Device | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-669 / 거리 2 | Allowed |
| [CWE-1271](https://cwe.mitre.org/data/definitions/1271.html) Uninitialized Value on Reset for Registers Holding Security Settings | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1271 / 거리 0 | Allowed |
| [CWE-1272](https://cwe.mitre.org/data/definitions/1272.html) Sensitive Information Uncleared Before Debug/Power State Transition | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1272 / 거리 0 | Allowed |
| [CWE-1273](https://cwe.mitre.org/data/definitions/1273.html) Device Unlock Credential Sharing | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1273 / 거리 0 | Allowed |
| [CWE-1277](https://cwe.mitre.org/data/definitions/1277.html) Firmware Not Updateable | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1329 / 거리 1 | Allowed |
| [CWE-1279](https://cwe.mitre.org/data/definitions/1279.html) Cryptographic Operations are Run Before Supporting Units are Ready | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665, CWE-696 / 거리 1 | Allowed |
| [CWE-1282](https://cwe.mitre.org/data/definitions/1282.html) Assumed-Immutable Data is Stored in Writable Memory | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-1295](https://cwe.mitre.org/data/definitions/1295.html) Debug Messages Revealing Unnecessary Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-1298](https://cwe.mitre.org/data/definitions/1298.html) Hardware Logic Contains Race Conditions | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1298 / 거리 0 | Allowed |
| [CWE-1300](https://cwe.mitre.org/data/definitions/1300.html) Improper Protection of Physical Side Channels | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-1301](https://cwe.mitre.org/data/definitions/1301.html) Insufficient or Incomplete Data Removal within Hardware Component | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1301 / 거리 0 | Allowed |
| [CWE-1303](https://cwe.mitre.org/data/definitions/1303.html) Non-Transparent Sharing of Microarchitectural Resources | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1303 / 거리 0 | Allowed |
| [CWE-1310](https://cwe.mitre.org/data/definitions/1310.html) Missing Ability to Patch ROM Code | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1329 / 거리 1 | Allowed |
| [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) Improperly Controlled Modification of Object Prototype Attributes | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-913 / 거리 2 | Allowed |
| [CWE-1325](https://cwe.mitre.org/data/definitions/1325.html) Improperly Controlled Sequential Memory Allocation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400, CWE-665 / 거리 2 | Allowed |
| [CWE-1329](https://cwe.mitre.org/data/definitions/1329.html) Reliance on Component That is Not Updateable | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1329 / 거리 0 | Allowed |
| [CWE-1330](https://cwe.mitre.org/data/definitions/1330.html) Remanent Data Readable after Memory Erase | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-404, CWE-669 / 거리 4 | Allowed |
| [CWE-1331](https://cwe.mitre.org/data/definitions/1331.html) Improper Isolation of Shared Resources in Network On Chip (NoC) | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | security-enforcement @ CWE-653 / 거리 1<br>unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html) Inefficient Regular Expression Complexity | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400 / 거리 3 | Allowed |
| [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) Improper Neutralization of Special Elements Used in a Template Engine | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-74 / 거리 2<br>reference-resolution @ CWE-913 / 거리 2 | Allowed |
| [CWE-1342](https://cwe.mitre.org/data/definitions/1342.html) Information Exposure through Microarchitectural State after Transient Execution | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1342 / 거리 0 | Allowed |
| [CWE-1386](https://cwe.mitre.org/data/definitions/1386.html) Insecure Operation on Windows Junction / Mount Point | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-1389](https://cwe.mitre.org/data/definitions/1389.html) Incorrect Parsing of Numbers with Different Radices | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1474 / 거리 2 | Allowed |
| [CWE-1419](https://cwe.mitre.org/data/definitions/1419.html) Incorrect Initialization of Resource | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665 / 거리 1 | Allowed-with-Review |
| [CWE-1420](https://cwe.mitre.org/data/definitions/1420.html) Exposure of Sensitive Information during Transient Execution | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1420 / 거리 0 | Allowed-with-Review |
| [CWE-1421](https://cwe.mitre.org/data/definitions/1421.html) Exposure of Sensitive Information in Shared Microarchitectural Structures during Transient Execution | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1421 / 거리 0 | Allowed |
| [CWE-1422](https://cwe.mitre.org/data/definitions/1422.html) Exposure of Sensitive Information caused by Incorrect Data Forwarding during Transient Execution | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1422 / 거리 0 | Allowed |
| [CWE-1423](https://cwe.mitre.org/data/definitions/1423.html) Exposure of Sensitive Information caused by Shared Microarchitectural Predictor State that Influences Transient Execution | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1423 / 거리 0 | Allowed |
| [CWE-1429](https://cwe.mitre.org/data/definitions/1429.html) Missing Security-Relevant Feedback for Unexecuted Operations in Hardware Interface | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1429 / 거리 0 | Allowed |
| [CWE-1431](https://cwe.mitre.org/data/definitions/1431.html) Driving Intermediate Cryptographic State/Results to Hardware Module Outputs | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1431 / 거리 0 | Allowed |
| [CWE-1434](https://cwe.mitre.org/data/definitions/1434.html) Insecure Setting of Generative AI/ML Model Inference Parameters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665 / 거리 1 | Allowed |
| [CWE-1472](https://cwe.mitre.org/data/definitions/1472.html) Generation of Credential with Long Expiration | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | credential-expiration-mechanism @ CWE-1472 / 거리 0 | Allowed |
| [CWE-1473](https://cwe.mitre.org/data/definitions/1473.html) Improper Expiration of Cached Data | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-1473 / 거리 0 | Allowed-with-Review |
| [CWE-1474](https://cwe.mitre.org/data/definitions/1474.html) Non-Equivalent Data Transformation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1474 / 거리 0 | Allowed-with-Review |
| [CWE-1475](https://cwe.mitre.org/data/definitions/1475.html) Incomplete Data/State Propagation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-1475 / 거리 0 | Allowed-with-Review |

</details>

<details>
<summary>CWE-682 · Incorrect Calculation · 13개 소속</summary>

| 세부 CWE / 이름 | 기본 요구 / 운영 필요 | 필요한 사실의 소재 | 적용 규칙과 기준점 | CWE 부여 지침 (참고만) |
| --- | --- | --- | --- | --- |
| [CWE-128](https://cwe.mitre.org/data/definitions/128.html) Wrap-around Error | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-128 / 거리 0 | Allowed |
| [CWE-131](https://cwe.mitre.org/data/definitions/131.html) Incorrect Calculation of Buffer Size | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-131 / 거리 0 | Allowed |
| [CWE-135](https://cwe.mitre.org/data/definitions/135.html) Incorrect Calculation of Multi-Byte String Length | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-135 / 거리 0 | Allowed |
| [CWE-190](https://cwe.mitre.org/data/definitions/190.html) Integer Overflow or Wraparound | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-190 / 거리 0 | Allowed |
| [CWE-191](https://cwe.mitre.org/data/definitions/191.html) Integer Underflow (Wrap or Wraparound) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-191 / 거리 0 | Allowed |
| [CWE-193](https://cwe.mitre.org/data/definitions/193.html) Off-by-one Error | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-193 / 거리 0 | Allowed |
| [CWE-369](https://cwe.mitre.org/data/definitions/369.html) Divide By Zero | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-369 / 거리 0 | Allowed |
| [CWE-467](https://cwe.mitre.org/data/definitions/467.html) Use of sizeof() on a Pointer Type | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-131 / 거리 1 | Allowed |
| [CWE-468](https://cwe.mitre.org/data/definitions/468.html) Incorrect Pointer Scaling | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-468 / 거리 0 | Allowed |
| [CWE-469](https://cwe.mitre.org/data/definitions/469.html) Use of Pointer Subtraction to Determine Size | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-469 / 거리 0 | Allowed |
| [CWE-680](https://cwe.mitre.org/data/definitions/680.html) Integer Overflow to Buffer Overflow | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-190 / 거리 1 | Discouraged |
| [CWE-1335](https://cwe.mitre.org/data/definitions/1335.html) Incorrect Bitwise Shift of Integer | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1335 / 거리 0 | Allowed |
| [CWE-1339](https://cwe.mitre.org/data/definitions/1339.html) Insufficient Precision or Accuracy of a Real Number | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1339 / 거리 0 | Allowed |

</details>

<details>
<summary>CWE-691 · Insufficient Control Flow Management · 86개 소속</summary>

| 세부 CWE / 이름 | 기본 요구 / 운영 필요 | 필요한 사실의 소재 | 적용 규칙과 기준점 | CWE 부여 지침 (참고만) |
| --- | --- | --- | --- | --- |
| [CWE-179](https://cwe.mitre.org/data/definitions/179.html) Incorrect Behavior Order: Early Validation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>state_control_flow (소스) | input-processing @ CWE-20 / 거리 1<br>state-and-lifetime @ CWE-696 / 거리 1 | Allowed |
| [CWE-180](https://cwe.mitre.org/data/definitions/180.html) Incorrect Behavior Order: Validate Before Canonicalize | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>state_control_flow (소스) | input-processing @ CWE-20 / 거리 2<br>state-and-lifetime @ CWE-696 / 거리 2 | Allowed |
| [CWE-181](https://cwe.mitre.org/data/definitions/181.html) Incorrect Behavior Order: Validate Before Filter | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>state_control_flow (소스) | input-processing @ CWE-20 / 거리 2<br>state-and-lifetime @ CWE-696 / 거리 2 | Allowed |
| [CWE-248](https://cwe.mitre.org/data/definitions/248.html) Uncaught Exception | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-705 / 거리 1<br>error-handling @ CWE-755 / 거리 1 | Allowed |
| [CWE-307](https://cwe.mitre.org/data/definitions/307.html) Improper Restriction of Excessive Authentication Attempts | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-799 / 거리 1 | Allowed |
| [CWE-362](https://cwe.mitre.org/data/definitions/362.html) Concurrent Execution using Shared Resource with Improper Synchronization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 1 | Allowed-with-Review |
| [CWE-363](https://cwe.mitre.org/data/definitions/363.html) Race Condition Enabling Link Following | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 3 | Allowed |
| [CWE-364](https://cwe.mitre.org/data/definitions/364.html) Signal Handler Race Condition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-366](https://cwe.mitre.org/data/definitions/366.html) Race Condition within a Thread | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-367](https://cwe.mitre.org/data/definitions/367.html) Time-of-check Time-of-use (TOCTOU) Race Condition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-368](https://cwe.mitre.org/data/definitions/368.html) Context Switching Race Condition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-382](https://cwe.mitre.org/data/definitions/382.html) J2EE Bad Practices: Use of System.exit() | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-705 / 거리 1 | Allowed |
| [CWE-395](https://cwe.mitre.org/data/definitions/395.html) Use of NullPointerException Catch to Detect NULL Pointer Dereference | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-705 / 거리 1<br>error-handling @ CWE-755 / 거리 1 | Allowed |
| [CWE-396](https://cwe.mitre.org/data/definitions/396.html) Declaration of Catch for Generic Exception | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-705 / 거리 1<br>error-handling @ CWE-221, CWE-755 / 거리 1 | Allowed |
| [CWE-397](https://cwe.mitre.org/data/definitions/397.html) Declaration of Throws for Generic Exception | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-397 / 거리 0 | Allowed |
| [CWE-408](https://cwe.mitre.org/data/definitions/408.html) Incorrect Behavior Order: Early Amplification | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-696 / 거리 1 | Allowed |
| [CWE-412](https://cwe.mitre.org/data/definitions/412.html) Unrestricted Externally Accessible Lock | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-413](https://cwe.mitre.org/data/definitions/413.html) Improper Resource Locking | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-414](https://cwe.mitre.org/data/definitions/414.html) Missing Lock Check | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-421](https://cwe.mitre.org/data/definitions/421.html) Race Condition During Access to Alternate Channel | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>state_control_flow (소스) | authorization-enforcement @ CWE-923 / 거리 2<br>state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-430](https://cwe.mitre.org/data/definitions/430.html) Deployment of Wrong Handler | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-430 / 거리 0 | Allowed |
| [CWE-431](https://cwe.mitre.org/data/definitions/431.html) Missing Handler | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-431 / 거리 0 | Allowed |
| [CWE-432](https://cwe.mitre.org/data/definitions/432.html) Dangerous Signal Handler not Disabled During Sensitive Operations | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 3 | Allowed |
| [CWE-455](https://cwe.mitre.org/data/definitions/455.html) Non-exit on Failed Initialization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665, CWE-705 / 거리 1 | Allowed |
| [CWE-479](https://cwe.mitre.org/data/definitions/479.html) Signal Handler Use of a Non-reentrant Function | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-480](https://cwe.mitre.org/data/definitions/480.html) Use of Incorrect Operator | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-670 / 거리 1 | Allowed |
| [CWE-481](https://cwe.mitre.org/data/definitions/481.html) Assigning instead of Comparing | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-670 / 거리 2 | Allowed |
| [CWE-482](https://cwe.mitre.org/data/definitions/482.html) Comparing instead of Assigning | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-670 / 거리 2 | Allowed |
| [CWE-483](https://cwe.mitre.org/data/definitions/483.html) Incorrect Block Delimitation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-670 / 거리 1 | Allowed |
| [CWE-484](https://cwe.mitre.org/data/definitions/484.html) Omitted Break Statement in Switch | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-484 / 거리 0 | Allowed |
| [CWE-543](https://cwe.mitre.org/data/definitions/543.html) Use of Singleton Pattern Without Synchronization in a Multithreaded Context | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-551](https://cwe.mitre.org/data/definitions/551.html) Incorrect Behavior Order: Authorization Before Parsing and Canonicalization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-696 / 거리 1 | Allowed |
| [CWE-558](https://cwe.mitre.org/data/definitions/558.html) Use of getlogin() in Multithreaded Application | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-567](https://cwe.mitre.org/data/definitions/567.html) Unsynchronized Access to Shared Data in a Multithreaded Context | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-572](https://cwe.mitre.org/data/definitions/572.html) Call to Thread run() instead of start() | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-574](https://cwe.mitre.org/data/definitions/574.html) EJB Bad Practices: Use of Synchronization Primitives | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2<br>code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-584](https://cwe.mitre.org/data/definitions/584.html) Return Inside Finally Block | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-705 / 거리 1 | Allowed |
| [CWE-591](https://cwe.mitre.org/data/definitions/591.html) Sensitive Data Storage in Improperly Locked Memory | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 3 | Allowed |
| [CWE-597](https://cwe.mitre.org/data/definitions/597.html) Use of Wrong Operator in String Comparison | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-670 / 거리 2<br>calculation-comparison @ CWE-1025 / 거리 2 | Allowed |
| [CWE-600](https://cwe.mitre.org/data/definitions/600.html) Uncaught Exception in Servlet | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-705 / 거리 2<br>error-handling @ CWE-755 / 거리 2 | Allowed |
| [CWE-609](https://cwe.mitre.org/data/definitions/609.html) Double-Checked Locking | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-617](https://cwe.mitre.org/data/definitions/617.html) Reachable Assertion | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-705 / 거리 1 | Allowed |
| [CWE-647](https://cwe.mitre.org/data/definitions/647.html) Use of Non-Canonical URL Paths for Authorization Decisions | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 2 | Allowed |
| [CWE-662](https://cwe.mitre.org/data/definitions/662.html) Improper Synchronization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 0 | Discouraged |
| [CWE-663](https://cwe.mitre.org/data/definitions/663.html) Use of a Non-reentrant Function in a Concurrent Context | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 1 | Allowed |
| [CWE-667](https://cwe.mitre.org/data/definitions/667.html) Improper Locking | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 1 | Allowed-with-Review |
| [CWE-670](https://cwe.mitre.org/data/definitions/670.html) Always-Incorrect Control Flow Implementation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-670 / 거리 0 | Allowed-with-Review |
| [CWE-674](https://cwe.mitre.org/data/definitions/674.html) Uncontrolled Recursion | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-834 / 거리 1 | Allowed-with-Review |
| [CWE-689](https://cwe.mitre.org/data/definitions/689.html) Permission Race Condition During Resource Copy | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-696](https://cwe.mitre.org/data/definitions/696.html) Incorrect Behavior Order | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-696 / 거리 0 | Allowed-with-Review |
| [CWE-698](https://cwe.mitre.org/data/definitions/698.html) Execution After Redirect (EAR) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-670, CWE-705 / 거리 1 | Allowed |
| [CWE-705](https://cwe.mitre.org/data/definitions/705.html) Incorrect Control Flow Scoping | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-705 / 거리 0 | Allowed-with-Review |
| [CWE-764](https://cwe.mitre.org/data/definitions/764.html) Multiple Locks of a Critical Resource | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2<br>code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-765](https://cwe.mitre.org/data/definitions/765.html) Multiple Unlocks of a Critical Resource | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2<br>code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-768](https://cwe.mitre.org/data/definitions/768.html) Incorrect Short Circuit Evaluation | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-768 / 거리 0 | Allowed |
| [CWE-776](https://cwe.mitre.org/data/definitions/776.html) Improper Restriction of Recursive Entity References in DTDs | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-400, CWE-834 / 거리 2 | Allowed |
| [CWE-783](https://cwe.mitre.org/data/definitions/783.html) Operator Precedence Logic Error | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-670 / 거리 1 | Allowed |
| [CWE-799](https://cwe.mitre.org/data/definitions/799.html) Improper Control of Interaction Frequency | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-799 / 거리 0 | Allowed-with-Review |
| [CWE-820](https://cwe.mitre.org/data/definitions/820.html) Missing Synchronization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 1 | Allowed |
| [CWE-821](https://cwe.mitre.org/data/definitions/821.html) Incorrect Synchronization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 1 | Allowed |
| [CWE-828](https://cwe.mitre.org/data/definitions/828.html) Signal Handler with Functionality that is not Asynchronous-Safe | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 3 | Allowed |
| [CWE-831](https://cwe.mitre.org/data/definitions/831.html) Signal Handler Function Associated with Multiple Signals | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 3 | Allowed |
| [CWE-832](https://cwe.mitre.org/data/definitions/832.html) Unlock of a Resource that is not Locked | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-833](https://cwe.mitre.org/data/definitions/833.html) Deadlock | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-834](https://cwe.mitre.org/data/definitions/834.html) Excessive Iteration | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-834 / 거리 0 | Discouraged |
| [CWE-835](https://cwe.mitre.org/data/definitions/835.html) Loop with Unreachable Exit Condition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-834 / 거리 1 | Allowed |
| [CWE-837](https://cwe.mitre.org/data/definitions/837.html) Improper Enforcement of a Single, Unique Action | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-799 / 거리 1 | Allowed |
| [CWE-841](https://cwe.mitre.org/data/definitions/841.html) Improper Enforcement of Behavioral Workflow | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-841 / 거리 0 | Allowed |
| [CWE-1058](https://cwe.mitre.org/data/definitions/1058.html) Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 1 | Allowed |
| [CWE-1077](https://cwe.mitre.org/data/definitions/1077.html) Floating Point Comparison with Incorrect Operator | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1077 / 거리 0 | Allowed |
| [CWE-1088](https://cwe.mitre.org/data/definitions/1088.html) Synchronous Access of Remote Resource without Timeout | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-1096](https://cwe.mitre.org/data/definitions/1096.html) Singleton Class Instance Creation without Proper Locking or Synchronization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-1190](https://cwe.mitre.org/data/definitions/1190.html) DMA Device Enabled Too Early in Boot Phase | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-696 / 거리 1 | Allowed |
| [CWE-1193](https://cwe.mitre.org/data/definitions/1193.html) Power-On of Untrusted Execution Core Before Enabling Fabric Access Control | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-696 / 거리 1 | Allowed |
| [CWE-1223](https://cwe.mitre.org/data/definitions/1223.html) Race Condition for Write-Once Attributes | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1223 / 거리 0 | Allowed |
| [CWE-1232](https://cwe.mitre.org/data/definitions/1232.html) Improper Lock Behavior After Power State Transition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2 | Allowed |
| [CWE-1233](https://cwe.mitre.org/data/definitions/1233.html) Security-Sensitive Hardware Controls with Missing Lock Bit Protection | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1233 / 거리 0 | Allowed |
| [CWE-1234](https://cwe.mitre.org/data/definitions/1234.html) Hardware Internal or Debug Modes Allow Override of Locks | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1234 / 거리 0 | Allowed |
| [CWE-1264](https://cwe.mitre.org/data/definitions/1264.html) Hardware Logic with Insecure De-Synchronization between Control and Data Channels | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1264 / 거리 0 | Allowed |
| [CWE-1265](https://cwe.mitre.org/data/definitions/1265.html) Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 1 | Allowed |
| [CWE-1279](https://cwe.mitre.org/data/definitions/1279.html) Cryptographic Operations are Run Before Supporting Units are Ready | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665, CWE-696 / 거리 1 | Allowed |
| [CWE-1280](https://cwe.mitre.org/data/definitions/1280.html) Access Control Check Implemented After Asset is Accessed | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-696 / 거리 1 | Allowed |
| [CWE-1281](https://cwe.mitre.org/data/definitions/1281.html) Sequence of Processor Instructions Leads to Unexpected Behavior | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1281 / 거리 0 | Allowed |
| [CWE-1298](https://cwe.mitre.org/data/definitions/1298.html) Hardware Logic Contains Race Conditions | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1298 / 거리 0 | Allowed |
| [CWE-1322](https://cwe.mitre.org/data/definitions/1322.html) Use of Blocking Code in Single-threaded, Non-blocking Context | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-834 / 거리 1 | Allowed |
| [CWE-1476](https://cwe.mitre.org/data/definitions/1476.html) Improper Request Propagation before Data Reception in Write Transactions in a Bus Architecture | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-841 / 거리 1 | Allowed |

</details>

<details>
<summary>CWE-693 · Protection Mechanism Failure · 103개 소속</summary>

| 세부 CWE / 이름 | 기본 요구 / 운영 필요 | 필요한 사실의 소재 | 적용 규칙과 기준점 | CWE 부여 지침 (참고만) |
| --- | --- | --- | --- | --- |
| [CWE-5](https://cwe.mitre.org/data/definitions/5.html) J2EE Misconfiguration: Data Transmission Without Encryption | 운영 검토 가능<br>운영: 필수 | communication_configuration (운영) | transport-encryption @ CWE-319 / 거리 1 | Allowed |
| [CWE-6](https://cwe.mitre.org/data/definitions/6.html) J2EE Misconfiguration: Insufficient Session-ID Length | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 2 | Allowed |
| [CWE-184](https://cwe.mitre.org/data/definitions/184.html) Incomplete List of Disallowed Inputs | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-184 / 거리 0 | Allowed |
| [CWE-259](https://cwe.mitre.org/data/definitions/259.html) Use of Hard-coded Password | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-259 / 거리 0 | Allowed |
| [CWE-302](https://cwe.mitre.org/data/definitions/302.html) Authentication Bypass by Assumed-Immutable Data | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-807 / 거리 1 | Allowed |
| [CWE-308](https://cwe.mitre.org/data/definitions/308.html) Use of Single-factor Authentication | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-654 / 거리 1 | Allowed |
| [CWE-309](https://cwe.mitre.org/data/definitions/309.html) Use of Password System for Primary Authentication | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-654 / 거리 1 | Allowed |
| [CWE-311](https://cwe.mitre.org/data/definitions/311.html) Missing Encryption of Sensitive Data | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311 / 거리 0 | Discouraged |
| [CWE-312](https://cwe.mitre.org/data/definitions/312.html) Cleartext Storage of Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 1 | Allowed |
| [CWE-313](https://cwe.mitre.org/data/definitions/313.html) Cleartext Storage in a File or on Disk | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 2 | Allowed |
| [CWE-314](https://cwe.mitre.org/data/definitions/314.html) Cleartext Storage in the Registry | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 2 | Allowed |
| [CWE-315](https://cwe.mitre.org/data/definitions/315.html) Cleartext Storage of Sensitive Information in a Cookie | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 2 | Allowed |
| [CWE-316](https://cwe.mitre.org/data/definitions/316.html) Cleartext Storage of Sensitive Information in Memory | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 2 | Allowed |
| [CWE-317](https://cwe.mitre.org/data/definitions/317.html) Cleartext Storage of Sensitive Information in GUI | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 2 | Allowed |
| [CWE-318](https://cwe.mitre.org/data/definitions/318.html) Cleartext Storage of Sensitive Information in Executable | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 2 | Allowed |
| [CWE-319](https://cwe.mitre.org/data/definitions/319.html) Cleartext Transmission of Sensitive Information | 운영 검토 가능<br>운영: 필수 | communication_configuration (운영) | transport-encryption @ CWE-319 / 거리 0 | Allowed |
| [CWE-321](https://cwe.mitre.org/data/definitions/321.html) Use of Hard-coded Cryptographic Key | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-321 / 거리 0 | Allowed |
| [CWE-323](https://cwe.mitre.org/data/definitions/323.html) Reusing a Nonce, Key Pair in Encryption | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 2 | Allowed |
| [CWE-325](https://cwe.mitre.org/data/definitions/325.html) Missing Cryptographic Step | 추가 근거·전문 자료<br>운영: 미정 | code_structure (소스)<br>cryptographic_design_review (전문 자료) | code-structure @ CWE-573 / 거리 1<br>crypto-design-assurance @ CWE-1240 / 거리 1 | Allowed |
| [CWE-326](https://cwe.mitre.org/data/definitions/326.html) Inadequate Encryption Strength | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | crypto-mechanism-dependent @ CWE-326 / 거리 0 | Allowed-with-Review |
| [CWE-327](https://cwe.mitre.org/data/definitions/327.html) Use of a Broken or Risky Cryptographic Algorithm | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | crypto-mechanism-dependent @ CWE-327 / 거리 0 | Allowed-with-Review |
| [CWE-328](https://cwe.mitre.org/data/definitions/328.html) Use of Weak Hash | 소스 필요<br>운영: CVE 문맥에 따라 추가 | crypto_implementation (소스) | crypto-code-parameters @ CWE-328 / 거리 0 | Allowed |
| [CWE-329](https://cwe.mitre.org/data/definitions/329.html) Generation of Predictable IV with CBC Mode | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-330](https://cwe.mitre.org/data/definitions/330.html) Use of Insufficiently Random Values | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 0 | Discouraged |
| [CWE-331](https://cwe.mitre.org/data/definitions/331.html) Insufficient Entropy | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 1 | Allowed |
| [CWE-332](https://cwe.mitre.org/data/definitions/332.html) Insufficient Entropy in PRNG | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 2 | Allowed |
| [CWE-333](https://cwe.mitre.org/data/definitions/333.html) Improper Handling of Insufficient Entropy in TRNG | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-755 / 거리 1 | Allowed |
| [CWE-334](https://cwe.mitre.org/data/definitions/334.html) Small Space of Random Values | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 1 | Allowed |
| [CWE-335](https://cwe.mitre.org/data/definitions/335.html) Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG) | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 1 | Allowed |
| [CWE-336](https://cwe.mitre.org/data/definitions/336.html) Same Seed in Pseudo-Random Number Generator (PRNG) | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 2 | Allowed |
| [CWE-337](https://cwe.mitre.org/data/definitions/337.html) Predictable Seed in Pseudo-Random Number Generator (PRNG) | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 2 | Allowed |
| [CWE-338](https://cwe.mitre.org/data/definitions/338.html) Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 1 | Allowed |
| [CWE-339](https://cwe.mitre.org/data/definitions/339.html) Small Seed Space in PRNG | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 2 | Allowed |
| [CWE-340](https://cwe.mitre.org/data/definitions/340.html) Generation of Predictable Numbers or Identifiers | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 1 | Allowed-with-Review |
| [CWE-341](https://cwe.mitre.org/data/definitions/341.html) Predictable from Observable State | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 2 | Allowed |
| [CWE-342](https://cwe.mitre.org/data/definitions/342.html) Predictable Exact Value from Previous Values | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 2 | Allowed |
| [CWE-343](https://cwe.mitre.org/data/definitions/343.html) Predictable Value Range from Previous Values | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 2 | Allowed |
| [CWE-344](https://cwe.mitre.org/data/definitions/344.html) Use of Invariant Value in Dynamically Changing Context | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 1 | Allowed |
| [CWE-345](https://cwe.mitre.org/data/definitions/345.html) Insufficient Verification of Data Authenticity | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-345 / 거리 0 | Discouraged |
| [CWE-346](https://cwe.mitre.org/data/definitions/346.html) Origin Validation Error | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-346 / 거리 0 | Allowed-with-Review |
| [CWE-347](https://cwe.mitre.org/data/definitions/347.html) Improper Verification of Cryptographic Signature | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-348](https://cwe.mitre.org/data/definitions/348.html) Use of Less Trusted Source | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-349](https://cwe.mitre.org/data/definitions/349.html) Acceptance of Extraneous Untrusted Data With Trusted Data | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-350](https://cwe.mitre.org/data/definitions/350.html) Reliance on Reverse DNS Resolution for a Security-Critical Action | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-807 / 거리 1 | Allowed |
| [CWE-351](https://cwe.mitre.org/data/definitions/351.html) Insufficient Type Distinction | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-352](https://cwe.mitre.org/data/definitions/352.html) Cross-Site Request Forgery | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-353](https://cwe.mitre.org/data/definitions/353.html) Missing Support for Integrity Check | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-354](https://cwe.mitre.org/data/definitions/354.html) Improper Validation of Integrity Check Value | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스)<br>error_handling (소스) | error-handling @ CWE-754 / 거리 1<br>crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-357](https://cwe.mitre.org/data/definitions/357.html) Insufficient UI Warning of Dangerous Operations | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-357 / 거리 0 | Allowed |
| [CWE-358](https://cwe.mitre.org/data/definitions/358.html) Improperly Implemented Security Check for Standard | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-358 / 거리 0 | Allowed |
| [CWE-360](https://cwe.mitre.org/data/definitions/360.html) Trust of System Event Data | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-422](https://cwe.mitre.org/data/definitions/422.html) Unprotected Windows Messaging Channel | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>crypto_implementation (소스) | authorization-enforcement @ CWE-923 / 거리 2<br>crypto-implementation @ CWE-345 / 거리 2 | Allowed |
| [CWE-424](https://cwe.mitre.org/data/definitions/424.html) Improper Protection of Alternate Path | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-424 / 거리 0 | Allowed-with-Review |
| [CWE-425](https://cwe.mitre.org/data/definitions/425.html) Direct Request | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-424 / 거리 1 | Allowed |
| [CWE-450](https://cwe.mitre.org/data/definitions/450.html) Multiple Interpretations of UI Input | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-357 / 거리 1 | Allowed |
| [CWE-453](https://cwe.mitre.org/data/definitions/453.html) Insecure Default Variable Initialization | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-665 / 거리 3<br>crypto-implementation @ CWE-330 / 거리 3 | Allowed |
| [CWE-494](https://cwe.mitre.org/data/definitions/494.html) Download of Code Without Integrity Check | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-669 / 거리 1<br>crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-526](https://cwe.mitre.org/data/definitions/526.html) Cleartext Storage of Sensitive Information in an Environment Variable | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-311, CWE-922 / 거리 2 | Allowed |
| [CWE-565](https://cwe.mitre.org/data/definitions/565.html) Reliance on Cookies without Validation and Integrity Checking | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-602 / 거리 1 | Allowed |
| [CWE-587](https://cwe.mitre.org/data/definitions/587.html) Assignment of a Fixed Address to a Pointer | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-758 / 거리 1 | Allowed |
| [CWE-602](https://cwe.mitre.org/data/definitions/602.html) Client-Side Enforcement of Server-Side Security | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-602 / 거리 0 | Allowed-with-Review |
| [CWE-603](https://cwe.mitre.org/data/definitions/603.html) Use of Client-Side Authentication | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-602 / 거리 1 | Allowed |
| [CWE-614](https://cwe.mitre.org/data/definitions/614.html) Sensitive Cookie in HTTPS Session Without 'Secure' Attribute | 운영 검토 가능<br>운영: 필수 | communication_configuration (운영)<br>feature_configuration (운영) | cookie-configuration @ CWE-614 / 거리 0 | Allowed |
| [CWE-616](https://cwe.mitre.org/data/definitions/616.html) Incomplete Identification of Uploaded File Variables (PHP) | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-646](https://cwe.mitre.org/data/definitions/646.html) Reliance on File Name or Extension of Externally-Supplied File | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-649](https://cwe.mitre.org/data/definitions/649.html) Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-653](https://cwe.mitre.org/data/definitions/653.html) Improper Isolation or Compartmentalization | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-653 / 거리 0 | Allowed |
| [CWE-654](https://cwe.mitre.org/data/definitions/654.html) Reliance on a Single Factor in a Security Decision | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-654 / 거리 0 | Allowed |
| [CWE-655](https://cwe.mitre.org/data/definitions/655.html) Insufficient Psychological Acceptability | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-655 / 거리 0 | Allowed-with-Review |
| [CWE-656](https://cwe.mitre.org/data/definitions/656.html) Reliance on Security Through Obscurity | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-656 / 거리 0 | Allowed-with-Review |
| [CWE-692](https://cwe.mitre.org/data/definitions/692.html) Incomplete Denylist to Cross-Site Scripting | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-184 / 거리 1 | Discouraged |
| [CWE-757](https://cwe.mitre.org/data/definitions/757.html) Selection of Less-Secure Algorithm During Negotiation | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-757 / 거리 0 | Allowed |
| [CWE-759](https://cwe.mitre.org/data/definitions/759.html) Use of a One-Way Hash without a Salt | 소스 필요<br>운영: CVE 문맥에 따라 추가 | crypto_implementation (소스) | crypto-code-parameters @ CWE-916 / 거리 1 | Allowed |
| [CWE-760](https://cwe.mitre.org/data/definitions/760.html) Use of a One-Way Hash with a Predictable Salt | 소스 필요<br>운영: CVE 문맥에 따라 추가 | crypto_implementation (소스) | crypto-code-parameters @ CWE-916 / 거리 1 | Allowed |
| [CWE-780](https://cwe.mitre.org/data/definitions/780.html) Use of RSA Algorithm without OAEP | 소스 필요<br>운영: CVE 문맥에 따라 추가 | crypto_implementation (소스) | crypto-code-parameters @ CWE-780 / 거리 0 | Allowed |
| [CWE-784](https://cwe.mitre.org/data/definitions/784.html) Reliance on Cookies without Validation and Integrity Checking in a Security Decision | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-807 / 거리 1 | Allowed |
| [CWE-798](https://cwe.mitre.org/data/definitions/798.html) Use of Hard-coded Credentials | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-798 / 거리 0 | Allowed-with-Review |
| [CWE-807](https://cwe.mitre.org/data/definitions/807.html) Reliance on Untrusted Inputs in a Security Decision | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-807 / 거리 0 | Allowed |
| [CWE-916](https://cwe.mitre.org/data/definitions/916.html) Use of Password Hash With Insufficient Computational Effort | 소스 필요<br>운영: CVE 문맥에 따라 추가 | crypto_implementation (소스) | crypto-code-parameters @ CWE-916 / 거리 0 | Allowed |
| [CWE-924](https://cwe.mitre.org/data/definitions/924.html) Improper Enforcement of Message Integrity During Transmission in a Communication Channel | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-925](https://cwe.mitre.org/data/definitions/925.html) Improper Verification of Intent by Broadcast Receiver | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-346, CWE-923 / 거리 2 | Allowed |
| [CWE-939](https://cwe.mitre.org/data/definitions/939.html) Improper Authorization in Handler for Custom URL Scheme | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285, CWE-346, CWE-923 / 거리 2 | Allowed |
| [CWE-940](https://cwe.mitre.org/data/definitions/940.html) Improper Verification of Source of a Communication Channel | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-346, CWE-923 / 거리 1 | Allowed |
| [CWE-1039](https://cwe.mitre.org/data/definitions/1039.html) Inadequate Detection or Handling of Adversarial Input Perturbations in Automated Recognition Mechanism | 추가 근거·전문 자료<br>운영: 미정 | model_robustness_evaluation (전문 자료) | model-robustness @ CWE-1039 / 거리 0 | Allowed-with-Review |
| [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) Initialization of a Resource with an Insecure Default | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-665 / 거리 2<br>crypto-implementation @ CWE-330 / 거리 2 | Allowed |
| [CWE-1189](https://cwe.mitre.org/data/definitions/1189.html) Improper Isolation of Shared Resources on System-on-a-Chip (SoC) | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | security-enforcement @ CWE-653 / 거리 1<br>unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-1204](https://cwe.mitre.org/data/definitions/1204.html) Generation of Weak Initialization Vector (IV) | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 1 | Allowed |
| [CWE-1240](https://cwe.mitre.org/data/definitions/1240.html) Use of a Cryptographic Primitive with a Risky Implementation | 추가 근거·전문 자료<br>운영: 미정 | cryptographic_design_review (전문 자료) | crypto-design-assurance @ CWE-1240 / 거리 0 | Allowed |
| [CWE-1241](https://cwe.mitre.org/data/definitions/1241.html) Use of Predictable Algorithm in Random Number Generator | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-330 / 거리 1 | Allowed |
| [CWE-1248](https://cwe.mitre.org/data/definitions/1248.html) Semiconductor Defects in Hardware Logic with Security-Sensitive Implications | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1248 / 거리 0 | Allowed |
| [CWE-1253](https://cwe.mitre.org/data/definitions/1253.html) Incorrect Selection of Fuse Values | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1253 / 거리 0 | Allowed |
| [CWE-1269](https://cwe.mitre.org/data/definitions/1269.html) Product Released in Non-Release Configuration | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1269 / 거리 0 | Allowed |
| [CWE-1278](https://cwe.mitre.org/data/definitions/1278.html) Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1278 / 거리 0 | Allowed |
| [CWE-1291](https://cwe.mitre.org/data/definitions/1291.html) Public Key Re-Use for Signing both Debug and Production Code | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | emergent-resource-design @ CWE-1291 / 거리 0 | Allowed |
| [CWE-1293](https://cwe.mitre.org/data/definitions/1293.html) Missing Source Correlation of Multiple Independent Data | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-1303](https://cwe.mitre.org/data/definitions/1303.html) Non-Transparent Sharing of Microarchitectural Resources | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1303 / 거리 0 | Allowed |
| [CWE-1318](https://cwe.mitre.org/data/definitions/1318.html) Missing Support for Security Features in On-chip Fabrics or Buses | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1318 / 거리 0 | Allowed |
| [CWE-1319](https://cwe.mitre.org/data/definitions/1319.html) Improper Protection against Electromagnetic Fault Injection (EM-FI) | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1319 / 거리 0 | Allowed |
| [CWE-1326](https://cwe.mitre.org/data/definitions/1326.html) Missing Immutable Root of Trust in Hardware | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1326 / 거리 0 | Allowed |
| [CWE-1331](https://cwe.mitre.org/data/definitions/1331.html) Improper Isolation of Shared Resources in Network On Chip (NoC) | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | security-enforcement @ CWE-653 / 거리 1<br>unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html) Missing Origin Validation in WebSockets | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-346 / 거리 1 | Allowed |
| [CWE-1428](https://cwe.mitre.org/data/definitions/1428.html) Reliance on HTTP instead of HTTPS | 운영 검토 가능<br>운영: 필수 | communication_configuration (운영) | transport-encryption @ CWE-319 / 거리 1 | Allowed |
| [CWE-1431](https://cwe.mitre.org/data/definitions/1431.html) Driving Intermediate Cryptographic State/Results to Hardware Module Outputs | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1431 / 거리 0 | Allowed |

</details>

<details>
<summary>CWE-697 · Incorrect Comparison · 21개 소속</summary>

| 세부 CWE / 이름 | 기본 요구 / 운영 필요 | 필요한 사실의 소재 | 적용 규칙과 기준점 | CWE 부여 지침 (참고만) |
| --- | --- | --- | --- | --- |
| [CWE-183](https://cwe.mitre.org/data/definitions/183.html) Permissive List of Allowed Inputs | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-183 / 거리 0 | Allowed |
| [CWE-184](https://cwe.mitre.org/data/definitions/184.html) Incomplete List of Disallowed Inputs | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-184 / 거리 0 | Allowed |
| [CWE-185](https://cwe.mitre.org/data/definitions/185.html) Incorrect Regular Expression | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-185 / 거리 0 | Allowed-with-Review |
| [CWE-186](https://cwe.mitre.org/data/definitions/186.html) Overly Restrictive Regular Expression | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-185 / 거리 1 | Allowed |
| [CWE-187](https://cwe.mitre.org/data/definitions/187.html) Partial String Comparison | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1023 / 거리 1 | Allowed |
| [CWE-478](https://cwe.mitre.org/data/definitions/478.html) Missing Default Case in Multiple Condition Expression | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1023 / 거리 1 | Allowed |
| [CWE-486](https://cwe.mitre.org/data/definitions/486.html) Comparison of Classes by Name | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1025 / 거리 1 | Allowed |
| [CWE-581](https://cwe.mitre.org/data/definitions/581.html) Object Model Violation: Just One of Equals and Hashcode Defined | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-581 / 거리 0 | Allowed |
| [CWE-595](https://cwe.mitre.org/data/definitions/595.html) Comparison of Object References Instead of Object Contents | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1025 / 거리 1 | Allowed |
| [CWE-597](https://cwe.mitre.org/data/definitions/597.html) Use of Wrong Operator in String Comparison | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-670 / 거리 2<br>calculation-comparison @ CWE-1025 / 거리 2 | Allowed |
| [CWE-625](https://cwe.mitre.org/data/definitions/625.html) Permissive Regular Expression | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-185 / 거리 1 | Allowed |
| [CWE-692](https://cwe.mitre.org/data/definitions/692.html) Incomplete Denylist to Cross-Site Scripting | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-184 / 거리 1 | Discouraged |
| [CWE-777](https://cwe.mitre.org/data/definitions/777.html) Regular Expression without Anchors | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-185 / 거리 2 | Allowed |
| [CWE-839](https://cwe.mitre.org/data/definitions/839.html) Numeric Range Comparison Without Minimum Check | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1023 / 거리 1 | Allowed |
| [CWE-942](https://cwe.mitre.org/data/definitions/942.html) Permissive Cross-domain Security Policy with Untrusted Domains | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>feature_configuration (운영) | deployment-configuration @ CWE-942 / 거리 0 | Allowed |
| [CWE-1023](https://cwe.mitre.org/data/definitions/1023.html) Incomplete Comparison with Missing Factors | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1023 / 거리 0 | Allowed-with-Review |
| [CWE-1024](https://cwe.mitre.org/data/definitions/1024.html) Comparison of Incompatible Types | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1024 / 거리 0 | Allowed |
| [CWE-1025](https://cwe.mitre.org/data/definitions/1025.html) Comparison Using Wrong Factors | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1025 / 거리 0 | Allowed |
| [CWE-1039](https://cwe.mitre.org/data/definitions/1039.html) Inadequate Detection or Handling of Adversarial Input Perturbations in Automated Recognition Mechanism | 추가 근거·전문 자료<br>운영: 미정 | model_robustness_evaluation (전문 자료) | model-robustness @ CWE-1039 / 거리 0 | Allowed-with-Review |
| [CWE-1077](https://cwe.mitre.org/data/definitions/1077.html) Floating Point Comparison with Incorrect Operator | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1077 / 거리 0 | Allowed |
| [CWE-1254](https://cwe.mitre.org/data/definitions/1254.html) Incorrect Comparison Logic Granularity | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘) | unspecified-mechanism @ CWE-200 / 거리 3 | Allowed |

</details>

<details>
<summary>CWE-703 · Improper Check or Handling of Exceptional Conditions · 58개 소속</summary>

| 세부 CWE / 이름 | 기본 요구 / 운영 필요 | 필요한 사실의 소재 | 적용 규칙과 기준점 | CWE 부여 지침 (참고만) |
| --- | --- | --- | --- | --- |
| [CWE-7](https://cwe.mitre.org/data/definitions/7.html) J2EE Misconfiguration: Missing Custom Error Page | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-755 / 거리 2 | Allowed |
| [CWE-12](https://cwe.mitre.org/data/definitions/12.html) ASP.NET Misconfiguration: Missing Custom Error Page | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-755 / 거리 2 | Allowed |
| [CWE-130](https://cwe.mitre.org/data/definitions/130.html) Improper Handling of Length Parameter Inconsistency | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-240 / 거리 1 | Allowed |
| [CWE-166](https://cwe.mitre.org/data/definitions/166.html) Improper Handling of Missing Special Element | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 1 | Allowed |
| [CWE-167](https://cwe.mitre.org/data/definitions/167.html) Improper Handling of Additional Special Element | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 1 | Allowed |
| [CWE-168](https://cwe.mitre.org/data/definitions/168.html) Improper Handling of Inconsistent Special Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 1 | Allowed |
| [CWE-209](https://cwe.mitre.org/data/definitions/209.html) Generation of Error Message Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 1<br>unspecified-mechanism @ CWE-200 / 거리 1 | Allowed |
| [CWE-210](https://cwe.mitre.org/data/definitions/210.html) Self-generated Error Message Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 2<br>unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-211](https://cwe.mitre.org/data/definitions/211.html) Externally-Generated Error Message Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 2<br>unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-228](https://cwe.mitre.org/data/definitions/228.html) Improper Handling of Syntactically Invalid Structure | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 0 | Allowed-with-Review |
| [CWE-229](https://cwe.mitre.org/data/definitions/229.html) Improper Handling of Values | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 1 | Allowed |
| [CWE-230](https://cwe.mitre.org/data/definitions/230.html) Improper Handling of Missing Values | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Allowed |
| [CWE-231](https://cwe.mitre.org/data/definitions/231.html) Improper Handling of Extra Values | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Allowed |
| [CWE-232](https://cwe.mitre.org/data/definitions/232.html) Improper Handling of Undefined Values | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Allowed |
| [CWE-233](https://cwe.mitre.org/data/definitions/233.html) Improper Handling of Parameters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 1 | Allowed |
| [CWE-234](https://cwe.mitre.org/data/definitions/234.html) Failure to Handle Missing Parameter | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Discouraged |
| [CWE-235](https://cwe.mitre.org/data/definitions/235.html) Improper Handling of Extra Parameters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Allowed |
| [CWE-236](https://cwe.mitre.org/data/definitions/236.html) Improper Handling of Undefined Parameters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Allowed |
| [CWE-237](https://cwe.mitre.org/data/definitions/237.html) Improper Handling of Structural Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 1 | Allowed |
| [CWE-238](https://cwe.mitre.org/data/definitions/238.html) Improper Handling of Incomplete Structural Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Allowed |
| [CWE-239](https://cwe.mitre.org/data/definitions/239.html) Failure to Handle Incomplete Element | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Allowed |
| [CWE-240](https://cwe.mitre.org/data/definitions/240.html) Improper Handling of Inconsistent Structural Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-240 / 거리 0 | Allowed |
| [CWE-241](https://cwe.mitre.org/data/definitions/241.html) Improper Handling of Unexpected Data Type | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 1 | Allowed |
| [CWE-248](https://cwe.mitre.org/data/definitions/248.html) Uncaught Exception | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-705 / 거리 1<br>error-handling @ CWE-755 / 거리 1 | Allowed |
| [CWE-252](https://cwe.mitre.org/data/definitions/252.html) Unchecked Return Value | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-754 / 거리 1 | Allowed |
| [CWE-253](https://cwe.mitre.org/data/definitions/253.html) Incorrect Check of Function Return Value | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>error_handling (소스) | error-handling @ CWE-754 / 거리 1<br>code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-273](https://cwe.mitre.org/data/definitions/273.html) Improper Check for Dropped Privileges | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-754 / 거리 1 | Allowed |
| [CWE-274](https://cwe.mitre.org/data/definitions/274.html) Improper Handling of Insufficient Privileges | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>error_handling (소스) | authorization-enforcement @ CWE-269 / 거리 1<br>error-handling @ CWE-755 / 거리 1 | Discouraged |
| [CWE-280](https://cwe.mitre.org/data/definitions/280.html) Improper Handling of Insufficient Permissions or Privileges | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-755 / 거리 1 | Allowed |
| [CWE-333](https://cwe.mitre.org/data/definitions/333.html) Improper Handling of Insufficient Entropy in TRNG | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-755 / 거리 1 | Allowed |
| [CWE-354](https://cwe.mitre.org/data/definitions/354.html) Improper Validation of Integrity Check Value | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스)<br>error_handling (소스) | error-handling @ CWE-754 / 거리 1<br>crypto-implementation @ CWE-345 / 거리 1 | Allowed |
| [CWE-390](https://cwe.mitre.org/data/definitions/390.html) Detection of Error Condition Without Action | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-755 / 거리 1 | Allowed |
| [CWE-392](https://cwe.mitre.org/data/definitions/392.html) Missing Report of Error Condition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 1<br>code-structure @ CWE-684 / 거리 1 | Allowed |
| [CWE-393](https://cwe.mitre.org/data/definitions/393.html) Return of Wrong Status Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-393 / 거리 0 | Allowed |
| [CWE-394](https://cwe.mitre.org/data/definitions/394.html) Unexpected Status Code or Return Value | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-754 / 거리 1 | Allowed |
| [CWE-395](https://cwe.mitre.org/data/definitions/395.html) Use of NullPointerException Catch to Detect NULL Pointer Dereference | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-705 / 거리 1<br>error-handling @ CWE-755 / 거리 1 | Allowed |
| [CWE-396](https://cwe.mitre.org/data/definitions/396.html) Declaration of Catch for Generic Exception | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-705 / 거리 1<br>error-handling @ CWE-221, CWE-755 / 거리 1 | Allowed |
| [CWE-397](https://cwe.mitre.org/data/definitions/397.html) Declaration of Throws for Generic Exception | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-397 / 거리 0 | Allowed |
| [CWE-455](https://cwe.mitre.org/data/definitions/455.html) Non-exit on Failed Initialization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665, CWE-705 / 거리 1 | Allowed |
| [CWE-460](https://cwe.mitre.org/data/definitions/460.html) Improper Cleanup on Thrown Exception | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-755 / 거리 1 | Allowed |
| [CWE-476](https://cwe.mitre.org/data/definitions/476.html) NULL Pointer Dereference | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>memory_bounds_lifetime (소스) | memory-safety @ CWE-476 / 거리 0<br>code-structure @ CWE-476 / 거리 0 | Allowed |
| [CWE-535](https://cwe.mitre.org/data/definitions/535.html) Exposure of Information Through Shell Error Message | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 3<br>unspecified-mechanism @ CWE-200 / 거리 3 | Allowed |
| [CWE-536](https://cwe.mitre.org/data/definitions/536.html) Servlet Runtime Error Message Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 3<br>unspecified-mechanism @ CWE-200 / 거리 3 | Allowed |
| [CWE-537](https://cwe.mitre.org/data/definitions/537.html) Java Runtime Error Message Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 3<br>unspecified-mechanism @ CWE-200 / 거리 3 | Allowed |
| [CWE-544](https://cwe.mitre.org/data/definitions/544.html) Missing Standardized Error Handling Mechanism | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-755 / 거리 1 | Allowed |
| [CWE-550](https://cwe.mitre.org/data/definitions/550.html) Server-generated Error Message Containing Sensitive Information | 추가 근거·전문 자료<br>운영: 미정 | cve_specific_mechanism (CVE 메커니즘)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 2<br>unspecified-mechanism @ CWE-200 / 거리 2 | Allowed |
| [CWE-600](https://cwe.mitre.org/data/definitions/600.html) Uncaught Exception in Servlet | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-705 / 거리 2<br>error-handling @ CWE-755 / 거리 2 | Allowed |
| [CWE-636](https://cwe.mitre.org/data/definitions/636.html) Not Failing Securely | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 1<br>documentation-design @ CWE-657 / 거리 1 | Allowed-with-Review |
| [CWE-690](https://cwe.mitre.org/data/definitions/690.html) Unchecked Return Value to NULL Pointer Dereference | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-754 / 거리 2 | Discouraged |
| [CWE-754](https://cwe.mitre.org/data/definitions/754.html) Improper Check for Unusual or Exceptional Conditions | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-754 / 거리 0 | Allowed-with-Review |
| [CWE-755](https://cwe.mitre.org/data/definitions/755.html) Improper Handling of Exceptional Conditions | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-755 / 거리 0 | Discouraged |
| [CWE-756](https://cwe.mitre.org/data/definitions/756.html) Missing Custom Error Page | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-755 / 거리 1 | Allowed |
| [CWE-1247](https://cwe.mitre.org/data/definitions/1247.html) Improper Protection Against Voltage and Clock Glitches | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1247 / 거리 0 | Allowed |
| [CWE-1261](https://cwe.mitre.org/data/definitions/1261.html) Improper Handling of Single Event Upsets | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1261 / 거리 0 | Allowed |
| [CWE-1332](https://cwe.mitre.org/data/definitions/1332.html) Improper Handling of Faults that Lead to Instruction Skips | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1332 / 거리 0 | Allowed |
| [CWE-1338](https://cwe.mitre.org/data/definitions/1338.html) Improper Protections Against Hardware Overheating | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1338 / 거리 0 | Allowed |
| [CWE-1351](https://cwe.mitre.org/data/definitions/1351.html) Improper Handling of Hardware Behavior in Exceptionally Cold Environments | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1351 / 거리 0 | Allowed-with-Review |
| [CWE-1384](https://cwe.mitre.org/data/definitions/1384.html) Improper Handling of Physical or Environmental Conditions | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1384 / 거리 0 | Allowed-with-Review |

</details>

<details>
<summary>CWE-707 · Improper Neutralization · 145개 소속</summary>

| 세부 CWE / 이름 | 기본 요구 / 운영 필요 | 필요한 사실의 소재 | 적용 규칙과 기준점 | CWE 부여 지침 (참고만) |
| --- | --- | --- | --- | --- |
| [CWE-20](https://cwe.mitre.org/data/definitions/20.html) Improper Input Validation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 0 | Discouraged |
| [CWE-37](https://cwe.mitre.org/data/definitions/37.html) Path Traversal: '/absolute/pathname/here' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 2 | Allowed |
| [CWE-42](https://cwe.mitre.org/data/definitions/42.html) Path Equivalence: 'filename.' (Trailing Dot) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-138 / 거리 2<br>reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-43](https://cwe.mitre.org/data/definitions/43.html) Path Equivalence: 'filename....' (Multiple Trailing Dot) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-138 / 거리 3<br>reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-45](https://cwe.mitre.org/data/definitions/45.html) Path Equivalence: 'file...name' (Multiple Internal Dot) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-138 / 거리 3<br>reference-resolution @ CWE-706 / 거리 3 | Allowed |
| [CWE-46](https://cwe.mitre.org/data/definitions/46.html) Path Equivalence: 'filename ' (Trailing Space) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-138 / 거리 2<br>reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-49](https://cwe.mitre.org/data/definitions/49.html) Path Equivalence: 'filename/' (Trailing Slash) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-138 / 거리 2<br>reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-50](https://cwe.mitre.org/data/definitions/50.html) Path Equivalence: '//multiple/leading/slash' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-52](https://cwe.mitre.org/data/definitions/52.html) Path Equivalence: '/multiple/trailing/slash//' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-53](https://cwe.mitre.org/data/definitions/53.html) Path Equivalence: '\multiple\\internal\backslash' | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-54](https://cwe.mitre.org/data/definitions/54.html) Path Equivalence: 'filedir\' (Trailing Backslash) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-138 / 거리 2<br>reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-56](https://cwe.mitre.org/data/definitions/56.html) Path Equivalence: 'filedir*' (Wildcard) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-138 / 거리 2<br>reference-resolution @ CWE-706 / 거리 2 | Allowed |
| [CWE-74](https://cwe.mitre.org/data/definitions/74.html) Improper Neutralization of Special Elements in Output Used by a Downstream Component | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 0 | Discouraged |
| [CWE-75](https://cwe.mitre.org/data/definitions/75.html) Failure to Sanitize Special Elements into a Different Plane | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 1 | Discouraged |
| [CWE-76](https://cwe.mitre.org/data/definitions/76.html) Improper Neutralization of Equivalent Special Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-77](https://cwe.mitre.org/data/definitions/77.html) Improper Neutralization of Special Elements used in a Command | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 1 | Allowed-with-Review |
| [CWE-78](https://cwe.mitre.org/data/definitions/78.html) Improper Neutralization of Special Elements used in an OS Command | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-79](https://cwe.mitre.org/data/definitions/79.html) Improper Neutralization of Input During Web Page Generation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 1 | Allowed |
| [CWE-80](https://cwe.mitre.org/data/definitions/80.html) Improper Neutralization of Script-Related HTML Tags in a Web Page | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-81](https://cwe.mitre.org/data/definitions/81.html) Improper Neutralization of Script in an Error Message Web Page | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-82](https://cwe.mitre.org/data/definitions/82.html) Improper Neutralization of Script in Attributes of IMG Tags in a Web Page | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 3 | Allowed |
| [CWE-83](https://cwe.mitre.org/data/definitions/83.html) Improper Neutralization of Script in Attributes in a Web Page | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-84](https://cwe.mitre.org/data/definitions/84.html) Improper Neutralization of Encoded URI Schemes in a Web Page | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-85](https://cwe.mitre.org/data/definitions/85.html) Doubled Character XSS Manipulations | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-86](https://cwe.mitre.org/data/definitions/86.html) Improper Neutralization of Invalid Characters in Identifiers in Web Pages | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-436 / 거리 1 | Allowed |
| [CWE-87](https://cwe.mitre.org/data/definitions/87.html) Improper Neutralization of Alternate XSS Syntax | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-88](https://cwe.mitre.org/data/definitions/88.html) Improper Neutralization of Argument Delimiters in a Command | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-89](https://cwe.mitre.org/data/definitions/89.html) Improper Neutralization of Special Elements used in an SQL Command | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-90](https://cwe.mitre.org/data/definitions/90.html) Improper Neutralization of Special Elements used in an LDAP Query | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-91](https://cwe.mitre.org/data/definitions/91.html) XML Injection | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 1 | Allowed-with-Review |
| [CWE-93](https://cwe.mitre.org/data/definitions/93.html) Improper Neutralization of CRLF Sequences | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 1 | Allowed |
| [CWE-94](https://cwe.mitre.org/data/definitions/94.html) Improper Control of Generation of Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-74 / 거리 1<br>reference-resolution @ CWE-913 / 거리 1 | Allowed-with-Review |
| [CWE-95](https://cwe.mitre.org/data/definitions/95.html) Improper Neutralization of Directives in Dynamically Evaluated Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-74 / 거리 2<br>reference-resolution @ CWE-913 / 거리 2 | Allowed |
| [CWE-96](https://cwe.mitre.org/data/definitions/96.html) Improper Neutralization of Directives in Statically Saved Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-74 / 거리 2<br>reference-resolution @ CWE-913 / 거리 2 | Allowed |
| [CWE-97](https://cwe.mitre.org/data/definitions/97.html) Improper Neutralization of Server-Side Includes (SSI) Within a Web Page | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-74 / 거리 3<br>reference-resolution @ CWE-913 / 거리 3 | Allowed |
| [CWE-99](https://cwe.mitre.org/data/definitions/99.html) Improper Control of Resource Identifiers | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 1 | Allowed-with-Review |
| [CWE-102](https://cwe.mitre.org/data/definitions/102.html) Struts: Duplicate Validation Forms | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 2<br>code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-105](https://cwe.mitre.org/data/definitions/105.html) Struts: Form Field Without Validator | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 2 | Allowed |
| [CWE-106](https://cwe.mitre.org/data/definitions/106.html) Struts: Plug-in Framework not in Use | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 2 | Allowed |
| [CWE-108](https://cwe.mitre.org/data/definitions/108.html) Struts: Unvalidated Action Form | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 2 | Allowed |
| [CWE-109](https://cwe.mitre.org/data/definitions/109.html) Struts: Validator Turned Off | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 2 | Allowed |
| [CWE-112](https://cwe.mitre.org/data/definitions/112.html) Missing XML Validation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 2 | Allowed |
| [CWE-113](https://cwe.mitre.org/data/definitions/113.html) Improper Neutralization of CRLF Sequences in HTTP Headers | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-436 / 거리 1 | Allowed |
| [CWE-116](https://cwe.mitre.org/data/definitions/116.html) Improper Encoding or Escaping of Output | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-116 / 거리 0 | Allowed-with-Review |
| [CWE-117](https://cwe.mitre.org/data/definitions/117.html) Improper Output Neutralization for Logs | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-116 / 거리 1 | Allowed |
| [CWE-129](https://cwe.mitre.org/data/definitions/129.html) Improper Validation of Array Index | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 2 | Allowed |
| [CWE-130](https://cwe.mitre.org/data/definitions/130.html) Improper Handling of Length Parameter Inconsistency | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-240 / 거리 1 | Allowed |
| [CWE-138](https://cwe.mitre.org/data/definitions/138.html) Improper Neutralization of Special Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 0 | Discouraged |
| [CWE-140](https://cwe.mitre.org/data/definitions/140.html) Improper Neutralization of Delimiters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-141](https://cwe.mitre.org/data/definitions/141.html) Improper Neutralization of Parameter/Argument Delimiters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 2 | Allowed |
| [CWE-142](https://cwe.mitre.org/data/definitions/142.html) Improper Neutralization of Value Delimiters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 2 | Allowed |
| [CWE-143](https://cwe.mitre.org/data/definitions/143.html) Improper Neutralization of Record Delimiters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 2 | Allowed |
| [CWE-144](https://cwe.mitre.org/data/definitions/144.html) Improper Neutralization of Line Delimiters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 2 | Allowed |
| [CWE-145](https://cwe.mitre.org/data/definitions/145.html) Improper Neutralization of Section Delimiters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 2 | Allowed |
| [CWE-146](https://cwe.mitre.org/data/definitions/146.html) Improper Neutralization of Expression/Command Delimiters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 2 | Allowed |
| [CWE-147](https://cwe.mitre.org/data/definitions/147.html) Improper Neutralization of Input Terminators | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-148](https://cwe.mitre.org/data/definitions/148.html) Improper Neutralization of Input Leaders | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-149](https://cwe.mitre.org/data/definitions/149.html) Improper Neutralization of Quoting Syntax | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-150](https://cwe.mitre.org/data/definitions/150.html) Improper Neutralization of Escape, Meta, or Control Sequences | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-151](https://cwe.mitre.org/data/definitions/151.html) Improper Neutralization of Comment Delimiters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-152](https://cwe.mitre.org/data/definitions/152.html) Improper Neutralization of Macro Symbols | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-153](https://cwe.mitre.org/data/definitions/153.html) Improper Neutralization of Substitution Characters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-154](https://cwe.mitre.org/data/definitions/154.html) Improper Neutralization of Variable Name Delimiters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-155](https://cwe.mitre.org/data/definitions/155.html) Improper Neutralization of Wildcards or Matching Symbols | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-156](https://cwe.mitre.org/data/definitions/156.html) Improper Neutralization of Whitespace | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-157](https://cwe.mitre.org/data/definitions/157.html) Failure to Sanitize Paired Delimiters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-158](https://cwe.mitre.org/data/definitions/158.html) Improper Neutralization of Null Byte or NUL Character | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-159](https://cwe.mitre.org/data/definitions/159.html) Improper Handling of Invalid Use of Special Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed-with-Review |
| [CWE-160](https://cwe.mitre.org/data/definitions/160.html) Improper Neutralization of Leading Special Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-161](https://cwe.mitre.org/data/definitions/161.html) Improper Neutralization of Multiple Leading Special Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 2 | Allowed |
| [CWE-162](https://cwe.mitre.org/data/definitions/162.html) Improper Neutralization of Trailing Special Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-163](https://cwe.mitre.org/data/definitions/163.html) Improper Neutralization of Multiple Trailing Special Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 2 | Allowed |
| [CWE-164](https://cwe.mitre.org/data/definitions/164.html) Improper Neutralization of Internal Special Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-165](https://cwe.mitre.org/data/definitions/165.html) Improper Neutralization of Multiple Internal Special Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 2 | Allowed |
| [CWE-166](https://cwe.mitre.org/data/definitions/166.html) Improper Handling of Missing Special Element | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 1 | Allowed |
| [CWE-167](https://cwe.mitre.org/data/definitions/167.html) Improper Handling of Additional Special Element | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 1 | Allowed |
| [CWE-168](https://cwe.mitre.org/data/definitions/168.html) Improper Handling of Inconsistent Special Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 1 | Allowed |
| [CWE-170](https://cwe.mitre.org/data/definitions/170.html) Improper Null Termination | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-170 / 거리 0 | Allowed |
| [CWE-172](https://cwe.mitre.org/data/definitions/172.html) Improper Encoding or Decoding of Data | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-172 / 거리 0 | Allowed-with-Review |
| [CWE-173](https://cwe.mitre.org/data/definitions/173.html) Improper Handling of Alternate Encoding | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-172 / 거리 1 | Allowed |
| [CWE-174](https://cwe.mitre.org/data/definitions/174.html) Double Decoding of the Same Data | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-172 / 거리 1 | Allowed |
| [CWE-175](https://cwe.mitre.org/data/definitions/175.html) Improper Handling of Mixed Encoding | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-172 / 거리 1 | Allowed |
| [CWE-176](https://cwe.mitre.org/data/definitions/176.html) Improper Handling of Unicode Encoding | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-172 / 거리 1 | Allowed |
| [CWE-177](https://cwe.mitre.org/data/definitions/177.html) Improper Handling of URL Encoding (Hex Encoding) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-172 / 거리 1 | Allowed |
| [CWE-179](https://cwe.mitre.org/data/definitions/179.html) Incorrect Behavior Order: Early Validation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>state_control_flow (소스) | input-processing @ CWE-20 / 거리 1<br>state-and-lifetime @ CWE-696 / 거리 1 | Allowed |
| [CWE-180](https://cwe.mitre.org/data/definitions/180.html) Incorrect Behavior Order: Validate Before Canonicalize | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>state_control_flow (소스) | input-processing @ CWE-20 / 거리 2<br>state-and-lifetime @ CWE-696 / 거리 2 | Allowed |
| [CWE-181](https://cwe.mitre.org/data/definitions/181.html) Incorrect Behavior Order: Validate Before Filter | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>state_control_flow (소스) | input-processing @ CWE-20 / 거리 2<br>state-and-lifetime @ CWE-696 / 거리 2 | Allowed |
| [CWE-182](https://cwe.mitre.org/data/definitions/182.html) Collapse of Data into Unsafe Value | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 2 | Allowed |
| [CWE-228](https://cwe.mitre.org/data/definitions/228.html) Improper Handling of Syntactically Invalid Structure | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 0 | Allowed-with-Review |
| [CWE-229](https://cwe.mitre.org/data/definitions/229.html) Improper Handling of Values | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 1 | Allowed |
| [CWE-230](https://cwe.mitre.org/data/definitions/230.html) Improper Handling of Missing Values | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Allowed |
| [CWE-231](https://cwe.mitre.org/data/definitions/231.html) Improper Handling of Extra Values | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Allowed |
| [CWE-232](https://cwe.mitre.org/data/definitions/232.html) Improper Handling of Undefined Values | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Allowed |
| [CWE-233](https://cwe.mitre.org/data/definitions/233.html) Improper Handling of Parameters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 1 | Allowed |
| [CWE-234](https://cwe.mitre.org/data/definitions/234.html) Failure to Handle Missing Parameter | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Discouraged |
| [CWE-235](https://cwe.mitre.org/data/definitions/235.html) Improper Handling of Extra Parameters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Allowed |
| [CWE-236](https://cwe.mitre.org/data/definitions/236.html) Improper Handling of Undefined Parameters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Allowed |
| [CWE-237](https://cwe.mitre.org/data/definitions/237.html) Improper Handling of Structural Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 1 | Allowed |
| [CWE-238](https://cwe.mitre.org/data/definitions/238.html) Improper Handling of Incomplete Structural Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Allowed |
| [CWE-239](https://cwe.mitre.org/data/definitions/239.html) Failure to Handle Incomplete Element | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 2 | Allowed |
| [CWE-240](https://cwe.mitre.org/data/definitions/240.html) Improper Handling of Inconsistent Structural Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-240 / 거리 0 | Allowed |
| [CWE-241](https://cwe.mitre.org/data/definitions/241.html) Improper Handling of Unexpected Data Type | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-228 / 거리 1 | Allowed |
| [CWE-462](https://cwe.mitre.org/data/definitions/462.html) Duplicate Key in Associative List (Alist) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-463](https://cwe.mitre.org/data/definitions/463.html) Deletion of Data Structure Sentinel | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-463 / 거리 0 | Allowed |
| [CWE-464](https://cwe.mitre.org/data/definitions/464.html) Addition of Data Structure Sentinel | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed |
| [CWE-554](https://cwe.mitre.org/data/definitions/554.html) ASP.NET Misconfiguration: Not Using Input Validation Framework | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 2 | Allowed |
| [CWE-564](https://cwe.mitre.org/data/definitions/564.html) Use of Hibernate with HQL/SQL Query String Containing External Input | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 3 | Allowed |
| [CWE-606](https://cwe.mitre.org/data/definitions/606.html) Unchecked Input for Loop Condition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 2 | Allowed |
| [CWE-621](https://cwe.mitre.org/data/definitions/621.html) Variable Extraction Error | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-913 / 거리 2 | Allowed |
| [CWE-622](https://cwe.mitre.org/data/definitions/622.html) Improper Validation of Function Hook Arguments | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 1 | Allowed |
| [CWE-624](https://cwe.mitre.org/data/definitions/624.html) Executable Regular Expression Error | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-626](https://cwe.mitre.org/data/definitions/626.html) Null Byte Interaction Error (Poison Null Byte) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-436 / 거리 1 | Allowed |
| [CWE-627](https://cwe.mitre.org/data/definitions/627.html) Dynamic Variable Evaluation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-913 / 거리 2 | Allowed |
| [CWE-641](https://cwe.mitre.org/data/definitions/641.html) Improper Restriction of Names for Files and Other Resources | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-643](https://cwe.mitre.org/data/definitions/643.html) Improper Neutralization of Data within XPath Expressions | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-644](https://cwe.mitre.org/data/definitions/644.html) Improper Neutralization of HTTP Headers for Scripting Syntax | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-116 / 거리 1 | Allowed |
| [CWE-647](https://cwe.mitre.org/data/definitions/647.html) Use of Non-Canonical URL Paths for Authorization Decisions | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | authorization-enforcement @ CWE-285 / 거리 2 | Allowed |
| [CWE-652](https://cwe.mitre.org/data/definitions/652.html) Improper Neutralization of Data within XQuery Expressions | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-694](https://cwe.mitre.org/data/definitions/694.html) Use of Multiple Resources with Duplicate Identifier | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-781](https://cwe.mitre.org/data/definitions/781.html) Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 2 | Allowed |
| [CWE-790](https://cwe.mitre.org/data/definitions/790.html) Improper Filtering of Special Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 1 | Allowed-with-Review |
| [CWE-791](https://cwe.mitre.org/data/definitions/791.html) Incomplete Filtering of Special Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 2 | Allowed |
| [CWE-792](https://cwe.mitre.org/data/definitions/792.html) Incomplete Filtering of One or More Instances of Special Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 3 | Allowed |
| [CWE-793](https://cwe.mitre.org/data/definitions/793.html) Only Filtering One Instance of a Special Element | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 4 | Allowed |
| [CWE-794](https://cwe.mitre.org/data/definitions/794.html) Incomplete Filtering of Multiple Instances of Special Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 4 | Allowed |
| [CWE-795](https://cwe.mitre.org/data/definitions/795.html) Only Filtering Special Elements at a Specified Location | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 3 | Allowed |
| [CWE-796](https://cwe.mitre.org/data/definitions/796.html) Only Filtering Special Elements Relative to a Marker | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 4 | Allowed |
| [CWE-797](https://cwe.mitre.org/data/definitions/797.html) Only Filtering Special Elements at an Absolute Position | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-138 / 거리 4 | Allowed |
| [CWE-838](https://cwe.mitre.org/data/definitions/838.html) Inappropriate Encoding for Output Context | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-116 / 거리 1 | Allowed |
| [CWE-839](https://cwe.mitre.org/data/definitions/839.html) Numeric Range Comparison Without Minimum Check | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-1023 / 거리 1 | Allowed |
| [CWE-914](https://cwe.mitre.org/data/definitions/914.html) Improper Control of Dynamically-Identified Variables | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-913 / 거리 1 | Allowed |
| [CWE-917](https://cwe.mitre.org/data/definitions/917.html) Improper Neutralization of Special Elements used in an Expression Language Statement | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |
| [CWE-943](https://cwe.mitre.org/data/definitions/943.html) Improper Neutralization of Special Elements in Data Query Logic | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 1 | Allowed-with-Review |
| [CWE-1173](https://cwe.mitre.org/data/definitions/1173.html) Improper Use of Validation Framework | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 1 | Allowed |
| [CWE-1174](https://cwe.mitre.org/data/definitions/1174.html) ASP.NET Misconfiguration: Improper Model Validation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 2 | Allowed |
| [CWE-1236](https://cwe.mitre.org/data/definitions/1236.html) Improper Neutralization of Formula Elements in a CSV File | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 1 | Allowed |
| [CWE-1284](https://cwe.mitre.org/data/definitions/1284.html) Improper Validation of Specified Quantity in Input | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 1 | Allowed |
| [CWE-1285](https://cwe.mitre.org/data/definitions/1285.html) Improper Validation of Specified Index, Position, or Offset in Input | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 1 | Allowed |
| [CWE-1286](https://cwe.mitre.org/data/definitions/1286.html) Improper Validation of Syntactic Correctness of Input | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 1 | Allowed |
| [CWE-1287](https://cwe.mitre.org/data/definitions/1287.html) Improper Validation of Specified Type of Input | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 1 | Allowed |
| [CWE-1288](https://cwe.mitre.org/data/definitions/1288.html) Improper Validation of Consistency within Input | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 1 | Allowed |
| [CWE-1289](https://cwe.mitre.org/data/definitions/1289.html) Improper Validation of Unsafe Equivalence in Input | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 1 | Allowed |
| [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) Improper Neutralization of Special Elements Used in a Template Engine | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스)<br>reference_resolution (소스) | input-processing @ CWE-74 / 거리 2<br>reference-resolution @ CWE-913 / 거리 2 | Allowed |
| [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html) Improper Validation of Generative AI Output | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-1426 / 거리 0 | Discouraged |
| [CWE-1427](https://cwe.mitre.org/data/definitions/1427.html) Improper Neutralization of Input Used for LLM Prompting | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-74 / 거리 2 | Allowed |

</details>

<details>
<summary>CWE-710 · Improper Adherence to Coding Standards · 196개 소속</summary>

| 세부 CWE / 이름 | 기본 요구 / 운영 필요 | 필요한 사실의 소재 | 적용 규칙과 기준점 | CWE 부여 지침 (참고만) |
| --- | --- | --- | --- | --- |
| [CWE-11](https://cwe.mitre.org/data/definitions/11.html) ASP.NET Misconfiguration: Creating Debug Binary | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-489 / 거리 1 | Allowed |
| [CWE-14](https://cwe.mitre.org/data/definitions/14.html) Compiler Removal of Code to Clear Buffers | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1038 / 거리 2 | Allowed |
| [CWE-102](https://cwe.mitre.org/data/definitions/102.html) Struts: Duplicate Validation Forms | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>input_to_sensitive_operation (소스) | input-processing @ CWE-20 / 거리 2<br>code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-103](https://cwe.mitre.org/data/definitions/103.html) Struts: Incomplete validate() Method Definition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-104](https://cwe.mitre.org/data/definitions/104.html) Struts: Form Bean Does Not Extend Validation Class | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-107](https://cwe.mitre.org/data/definitions/107.html) Struts: Unused Validation Form | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1164 / 거리 2 | Allowed |
| [CWE-110](https://cwe.mitre.org/data/definitions/110.html) Struts: Validator Without Form Field | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1164 / 거리 1 | Allowed |
| [CWE-111](https://cwe.mitre.org/data/definitions/111.html) Direct Use of Unsafe JNI | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-174](https://cwe.mitre.org/data/definitions/174.html) Double Decoding of the Same Data | 소스 필요<br>운영: CVE 문맥에 따라 추가 | input_to_sensitive_operation (소스) | input-processing @ CWE-172 / 거리 1 | Allowed |
| [CWE-188](https://cwe.mitre.org/data/definitions/188.html) Reliance on Data/Memory Layout | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-188 / 거리 0 | Allowed |
| [CWE-198](https://cwe.mitre.org/data/definitions/198.html) Use of Incorrect Byte Ordering | 소스 필요<br>운영: CVE 문맥에 따라 추가 | reference_resolution (소스) | reference-resolution @ CWE-188 / 거리 1 | Allowed |
| [CWE-242](https://cwe.mitre.org/data/definitions/242.html) Use of Inherently Dangerous Function | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1177 / 거리 1 | Allowed |
| [CWE-243](https://cwe.mitre.org/data/definitions/243.html) Creation of chroot Jail Without Changing Working Directory | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-669 / 거리 1<br>code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-245](https://cwe.mitre.org/data/definitions/245.html) J2EE Bad Practices: Direct Management of Connections | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-246](https://cwe.mitre.org/data/definitions/246.html) J2EE Bad Practices: Direct Use of Sockets | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-250](https://cwe.mitre.org/data/definitions/250.html) Execution with Unnecessary Privileges | 운영 검토 가능<br>운영: 필수 | actor_and_access_scope (운영)<br>resource_permissions (운영) | resource-permissions @ CWE-250 / 거리 0 | Allowed |
| [CWE-253](https://cwe.mitre.org/data/definitions/253.html) Incorrect Check of Function Return Value | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>error_handling (소스) | error-handling @ CWE-754 / 거리 1<br>code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-259](https://cwe.mitre.org/data/definitions/259.html) Use of Hard-coded Password | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-259 / 거리 0 | Allowed |
| [CWE-296](https://cwe.mitre.org/data/definitions/296.html) Improper Following of a Certificate's Chain of Trust | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>code_structure (소스)<br>crypto_implementation (소스) | crypto-implementation @ CWE-295 / 거리 1<br>code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-304](https://cwe.mitre.org/data/definitions/304.html) Missing Critical Step in Authentication | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-308](https://cwe.mitre.org/data/definitions/308.html) Use of Single-factor Authentication | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-654 / 거리 1 | Allowed |
| [CWE-309](https://cwe.mitre.org/data/definitions/309.html) Use of Password System for Primary Authentication | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-654 / 거리 1 | Allowed |
| [CWE-321](https://cwe.mitre.org/data/definitions/321.html) Use of Hard-coded Cryptographic Key | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-321 / 거리 0 | Allowed |
| [CWE-325](https://cwe.mitre.org/data/definitions/325.html) Missing Cryptographic Step | 추가 근거·전문 자료<br>운영: 미정 | code_structure (소스)<br>cryptographic_design_review (전문 자료) | code-structure @ CWE-573 / 거리 1<br>crypto-design-assurance @ CWE-1240 / 거리 1 | Allowed |
| [CWE-329](https://cwe.mitre.org/data/definitions/329.html) Generation of Predictable IV with CBC Mode | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-358](https://cwe.mitre.org/data/definitions/358.html) Improperly Implemented Security Check for Standard | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-358 / 거리 0 | Allowed |
| [CWE-383](https://cwe.mitre.org/data/definitions/383.html) J2EE Bad Practices: Direct Use of Threads | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-392](https://cwe.mitre.org/data/definitions/392.html) Missing Report of Error Condition | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 1<br>code-structure @ CWE-684 / 거리 1 | Allowed |
| [CWE-393](https://cwe.mitre.org/data/definitions/393.html) Return of Wrong Status Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | error_handling (소스) | error-handling @ CWE-393 / 거리 0 | Allowed |
| [CWE-415](https://cwe.mitre.org/data/definitions/415.html) Double Free | 소스 필요<br>운영: CVE 문맥에 따라 추가 | memory_bounds_lifetime (소스) | memory-safety @ CWE-415 / 거리 0 | Allowed |
| [CWE-424](https://cwe.mitre.org/data/definitions/424.html) Improper Protection of Alternate Path | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-424 / 거리 0 | Allowed-with-Review |
| [CWE-425](https://cwe.mitre.org/data/definitions/425.html) Direct Request | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-424 / 거리 1 | Allowed |
| [CWE-440](https://cwe.mitre.org/data/definitions/440.html) Expected Behavior Violation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-684 / 거리 1 | Allowed |
| [CWE-446](https://cwe.mitre.org/data/definitions/446.html) UI Discrepancy for Security Feature | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-684 / 거리 1 | Allowed-with-Review |
| [CWE-447](https://cwe.mitre.org/data/definitions/447.html) Unimplemented or Unsupported Feature in UI | 추가 근거·전문 자료<br>운영: 미정 | code_structure (소스)<br>design_documentation (전문 자료) | code-structure @ CWE-684 / 거리 2<br>documentation-design @ CWE-657 / 거리 2 | Allowed |
| [CWE-448](https://cwe.mitre.org/data/definitions/448.html) Obsolete Feature in UI | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-684 / 거리 2 | Allowed |
| [CWE-449](https://cwe.mitre.org/data/definitions/449.html) The UI Performs the Wrong Action | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-684 / 거리 2 | Allowed |
| [CWE-451](https://cwe.mitre.org/data/definitions/451.html) User Interface (UI) Misrepresentation of Critical Information | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>error_handling (소스) | error-handling @ CWE-221 / 거리 1<br>code-structure @ CWE-684 / 거리 1 | Allowed-with-Review |
| [CWE-455](https://cwe.mitre.org/data/definitions/455.html) Non-exit on Failed Initialization | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665, CWE-705 / 거리 1 | Allowed |
| [CWE-462](https://cwe.mitre.org/data/definitions/462.html) Duplicate Key in Associative List (Alist) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-474](https://cwe.mitre.org/data/definitions/474.html) Use of Function with Inconsistent Implementations | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-758 / 거리 1 | Allowed |
| [CWE-475](https://cwe.mitre.org/data/definitions/475.html) Undefined Behavior for Input to API | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-476](https://cwe.mitre.org/data/definitions/476.html) NULL Pointer Dereference | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>memory_bounds_lifetime (소스) | memory-safety @ CWE-476 / 거리 0<br>code-structure @ CWE-476 / 거리 0 | Allowed |
| [CWE-477](https://cwe.mitre.org/data/definitions/477.html) Use of Obsolete Function | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-477 / 거리 0 | Allowed |
| [CWE-484](https://cwe.mitre.org/data/definitions/484.html) Omitted Break Statement in Switch | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-484 / 거리 0 | Allowed |
| [CWE-489](https://cwe.mitre.org/data/definitions/489.html) Active Debug Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-489 / 거리 0 | Allowed |
| [CWE-506](https://cwe.mitre.org/data/definitions/506.html) Embedded Malicious Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-684 / 거리 2 | Allowed-with-Review |
| [CWE-507](https://cwe.mitre.org/data/definitions/507.html) Trojan Horse | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-684 / 거리 3 | Allowed |
| [CWE-508](https://cwe.mitre.org/data/definitions/508.html) Non-Replicating Malicious Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-684 / 거리 4 | Allowed |
| [CWE-509](https://cwe.mitre.org/data/definitions/509.html) Replicating Malicious Code (Virus or Worm) | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-684 / 거리 4 | Allowed |
| [CWE-510](https://cwe.mitre.org/data/definitions/510.html) Trapdoor | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-684 / 거리 3 | Allowed |
| [CWE-511](https://cwe.mitre.org/data/definitions/511.html) Logic/Time Bomb | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-684 / 거리 3 | Allowed |
| [CWE-512](https://cwe.mitre.org/data/definitions/512.html) Spyware | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-684 / 거리 3 | Allowed |
| [CWE-546](https://cwe.mitre.org/data/definitions/546.html) Suspicious Comment | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 2 | Allowed |
| [CWE-547](https://cwe.mitre.org/data/definitions/547.html) Use of Hard-coded, Security-relevant Constants | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 2 | Allowed |
| [CWE-560](https://cwe.mitre.org/data/definitions/560.html) Use of umask() with chmod-style Argument | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 3 | Allowed |
| [CWE-561](https://cwe.mitre.org/data/definitions/561.html) Dead Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1164 / 거리 1 | Allowed-with-Review |
| [CWE-562](https://cwe.mitre.org/data/definitions/562.html) Return of Stack Variable Address | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-758 / 거리 1 | Allowed |
| [CWE-563](https://cwe.mitre.org/data/definitions/563.html) Assignment to Variable without Use | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1164 / 거리 1 | Allowed |
| [CWE-568](https://cwe.mitre.org/data/definitions/568.html) finalize() Method Without super.finalize() | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-570](https://cwe.mitre.org/data/definitions/570.html) Expression is Always False | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-570 / 거리 0 | Allowed |
| [CWE-571](https://cwe.mitre.org/data/definitions/571.html) Expression is Always True | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-571 / 거리 0 | Allowed |
| [CWE-573](https://cwe.mitre.org/data/definitions/573.html) Improper Following of Specification by Caller | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 0 | Allowed-with-Review |
| [CWE-574](https://cwe.mitre.org/data/definitions/574.html) EJB Bad Practices: Use of Synchronization Primitives | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2<br>code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-575](https://cwe.mitre.org/data/definitions/575.html) EJB Bad Practices: Use of AWT Swing | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-576](https://cwe.mitre.org/data/definitions/576.html) EJB Bad Practices: Use of Java I/O | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-577](https://cwe.mitre.org/data/definitions/577.html) EJB Bad Practices: Use of Sockets | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-578](https://cwe.mitre.org/data/definitions/578.html) EJB Bad Practices: Use of Class Loader | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-579](https://cwe.mitre.org/data/definitions/579.html) J2EE Bad Practices: Non-serializable Object Stored in Session | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-580](https://cwe.mitre.org/data/definitions/580.html) clone() Method Without super.clone() | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-580 / 거리 0 | Allowed |
| [CWE-581](https://cwe.mitre.org/data/definitions/581.html) Object Model Violation: Just One of Equals and Hashcode Defined | 소스 필요<br>운영: CVE 문맥에 따라 추가 | calculation_semantics (소스) | calculation-comparison @ CWE-581 / 거리 0 | Allowed |
| [CWE-585](https://cwe.mitre.org/data/definitions/585.html) Empty Synchronized Block | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1164 / 거리 2 | Allowed |
| [CWE-586](https://cwe.mitre.org/data/definitions/586.html) Explicit Call to Finalize() | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 1 | Allowed |
| [CWE-587](https://cwe.mitre.org/data/definitions/587.html) Assignment of a Fixed Address to a Pointer | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-758 / 거리 1 | Allowed |
| [CWE-588](https://cwe.mitre.org/data/definitions/588.html) Attempt to Access Child of a Non-structure Pointer | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-758 / 거리 1 | Allowed |
| [CWE-589](https://cwe.mitre.org/data/definitions/589.html) Call to Non-ubiquitous API | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-758 / 거리 2 | Allowed |
| [CWE-594](https://cwe.mitre.org/data/definitions/594.html) J2EE Framework: Saving Unserializable Objects to Disk | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 1 | Allowed |
| [CWE-605](https://cwe.mitre.org/data/definitions/605.html) Multiple Binds to the Same Port | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-666 / 거리 1 | Allowed |
| [CWE-628](https://cwe.mitre.org/data/definitions/628.html) Function Call with Incorrectly Specified Arguments | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-636](https://cwe.mitre.org/data/definitions/636.html) Not Failing Securely | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료)<br>error_handling (소스) | error-handling @ CWE-755 / 거리 1<br>documentation-design @ CWE-657 / 거리 1 | Allowed-with-Review |
| [CWE-637](https://cwe.mitre.org/data/definitions/637.html) Unnecessary Complexity in Protection Mechanism (Not Using 'Economy of Mechanism') | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-657 / 거리 1 | Allowed-with-Review |
| [CWE-638](https://cwe.mitre.org/data/definitions/638.html) Not Using Complete Mediation | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-657 / 거리 1 | Allowed-with-Review |
| [CWE-653](https://cwe.mitre.org/data/definitions/653.html) Improper Isolation or Compartmentalization | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-653 / 거리 0 | Allowed |
| [CWE-654](https://cwe.mitre.org/data/definitions/654.html) Reliance on a Single Factor in a Security Decision | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>authorization_enforcement (소스) | security-enforcement @ CWE-654 / 거리 0 | Allowed |
| [CWE-655](https://cwe.mitre.org/data/definitions/655.html) Insufficient Psychological Acceptability | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-655 / 거리 0 | Allowed-with-Review |
| [CWE-656](https://cwe.mitre.org/data/definitions/656.html) Reliance on Security Through Obscurity | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-656 / 거리 0 | Allowed-with-Review |
| [CWE-657](https://cwe.mitre.org/data/definitions/657.html) Violation of Secure Design Principles | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-657 / 거리 0 | Discouraged |
| [CWE-671](https://cwe.mitre.org/data/definitions/671.html) Lack of Administrator Control over Security | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-657 / 거리 1 | Allowed-with-Review |
| [CWE-675](https://cwe.mitre.org/data/definitions/675.html) Multiple Operations on Resource in Single-Operation Context | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 1 | Allowed-with-Review |
| [CWE-676](https://cwe.mitre.org/data/definitions/676.html) Use of Potentially Dangerous Function | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1177 / 거리 1 | Allowed |
| [CWE-683](https://cwe.mitre.org/data/definitions/683.html) Function Call With Incorrect Order of Arguments | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-684](https://cwe.mitre.org/data/definitions/684.html) Incorrect Provision of Specified Functionality | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-684 / 거리 0 | Allowed-with-Review |
| [CWE-685](https://cwe.mitre.org/data/definitions/685.html) Function Call With Incorrect Number of Arguments | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-686](https://cwe.mitre.org/data/definitions/686.html) Function Call With Incorrect Argument Type | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-687](https://cwe.mitre.org/data/definitions/687.html) Function Call With Incorrectly Specified Argument Value | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-688](https://cwe.mitre.org/data/definitions/688.html) Function Call With Incorrect Variable or Reference as Argument | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-694](https://cwe.mitre.org/data/definitions/694.html) Use of Multiple Resources with Duplicate Identifier | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-695](https://cwe.mitre.org/data/definitions/695.html) Use of Low-Level Functionality | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 1 | Allowed |
| [CWE-733](https://cwe.mitre.org/data/definitions/733.html) Compiler Optimization Removal or Modification of Security-critical Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1038 / 거리 1 | Allowed |
| [CWE-758](https://cwe.mitre.org/data/definitions/758.html) Reliance on Undefined, Unspecified, or Implementation-Defined Behavior | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-758 / 거리 0 | Allowed-with-Review |
| [CWE-764](https://cwe.mitre.org/data/definitions/764.html) Multiple Locks of a Critical Resource | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2<br>code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-765](https://cwe.mitre.org/data/definitions/765.html) Multiple Unlocks of a Critical Resource | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>state_control_flow (소스) | state-and-lifetime @ CWE-662 / 거리 2<br>code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-766](https://cwe.mitre.org/data/definitions/766.html) Critical Data Element Declared Public | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>code_structure (소스)<br>resource_permissions (운영) | code-structure @ CWE-1061 / 거리 1<br>resource-permissions @ CWE-732 / 거리 1 | Allowed |
| [CWE-785](https://cwe.mitre.org/data/definitions/785.html) Use of Path Manipulation Function without Maximum-sized Buffer | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>memory_bounds_lifetime (소스) | memory-safety @ CWE-119 / 거리 2<br>code-structure @ CWE-1177 / 거리 2 | Allowed |
| [CWE-798](https://cwe.mitre.org/data/definitions/798.html) Use of Hard-coded Credentials | 소스 필요<br>운영: 필수 | actor_and_access_scope (운영)<br>crypto_implementation (소스) | crypto-implementation @ CWE-798 / 거리 0 | Allowed-with-Review |
| [CWE-912](https://cwe.mitre.org/data/definitions/912.html) Hidden Functionality | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-684 / 거리 1 | Allowed-with-Review |
| [CWE-1007](https://cwe.mitre.org/data/definitions/1007.html) Insufficient Visual Distinction of Homoglyphs Presented to User | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>error_handling (소스) | error-handling @ CWE-221 / 거리 2<br>code-structure @ CWE-684 / 거리 2 | Allowed |
| [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) Improper Restriction of Rendered UI Layers or Frames | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스)<br>error_handling (소스)<br>reference_resolution (소스) | reference-resolution @ CWE-610 / 거리 2<br>error-handling @ CWE-221 / 거리 2<br>code-structure @ CWE-684 / 거리 2 | Allowed |
| [CWE-1037](https://cwe.mitre.org/data/definitions/1037.html) Processor Optimization Removal or Modification of Security-critical Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1038 / 거리 1 | Allowed |
| [CWE-1038](https://cwe.mitre.org/data/definitions/1038.html) Insecure Automated Optimizations | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1038 / 거리 0 | Allowed-with-Review |
| [CWE-1041](https://cwe.mitre.org/data/definitions/1041.html) Use of Redundant Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1041 / 거리 0 | Prohibited |
| [CWE-1043](https://cwe.mitre.org/data/definitions/1043.html) Data Element Aggregating an Excessively Large Number of Non-Primitive Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1093 / 거리 1 | Prohibited |
| [CWE-1044](https://cwe.mitre.org/data/definitions/1044.html) Architecture with Number of Horizontal Layers Outside of Expected Range | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1044 / 거리 0 | Prohibited |
| [CWE-1045](https://cwe.mitre.org/data/definitions/1045.html) Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 1 | Allowed |
| [CWE-1047](https://cwe.mitre.org/data/definitions/1047.html) Modules with Circular Dependencies | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1120 / 거리 1 | Prohibited |
| [CWE-1048](https://cwe.mitre.org/data/definitions/1048.html) Invokable Control Element with Large Number of Outward Calls | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1048 / 거리 0 | Prohibited |
| [CWE-1053](https://cwe.mitre.org/data/definitions/1053.html) Missing Documentation for Design | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1059 / 거리 1 | Prohibited |
| [CWE-1054](https://cwe.mitre.org/data/definitions/1054.html) Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1061 / 거리 1 | Prohibited |
| [CWE-1055](https://cwe.mitre.org/data/definitions/1055.html) Multiple Inheritance from Concrete Classes | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1093 / 거리 1 | Prohibited |
| [CWE-1056](https://cwe.mitre.org/data/definitions/1056.html) Invokable Control Element with Variadic Parameters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1120 / 거리 1 | Prohibited |
| [CWE-1057](https://cwe.mitre.org/data/definitions/1057.html) Data Access Operations Outside of Expected Data Manager Component | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1061 / 거리 1 | Prohibited |
| [CWE-1059](https://cwe.mitre.org/data/definitions/1059.html) Insufficient Technical Documentation | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1059 / 거리 0 | Prohibited |
| [CWE-1060](https://cwe.mitre.org/data/definitions/1060.html) Excessive Number of Inefficient Server-Side Data Accesses | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1120 / 거리 1 | Prohibited |
| [CWE-1061](https://cwe.mitre.org/data/definitions/1061.html) Insufficient Encapsulation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1061 / 거리 0 | Allowed-with-Review |
| [CWE-1062](https://cwe.mitre.org/data/definitions/1062.html) Parent Class with References to Child Class | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1061 / 거리 1 | Prohibited |
| [CWE-1064](https://cwe.mitre.org/data/definitions/1064.html) Invokable Control Element with Signature Containing an Excessive Number of Parameters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1120 / 거리 1 | Prohibited |
| [CWE-1065](https://cwe.mitre.org/data/definitions/1065.html) Runtime Resource Management Control Element in a Component Built to Run on Application Servers | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Prohibited |
| [CWE-1066](https://cwe.mitre.org/data/definitions/1066.html) Missing Serialization Control Element | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1066 / 거리 0 | Prohibited |
| [CWE-1068](https://cwe.mitre.org/data/definitions/1068.html) Inconsistency Between Implementation and Documented Design | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1068 / 거리 0 | Prohibited |
| [CWE-1069](https://cwe.mitre.org/data/definitions/1069.html) Empty Exception Block | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1164 / 거리 2 | Allowed |
| [CWE-1070](https://cwe.mitre.org/data/definitions/1070.html) Serializable Data Element Containing non-Serializable Item Elements | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 1 | Prohibited |
| [CWE-1071](https://cwe.mitre.org/data/definitions/1071.html) Empty Code Block | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1164 / 거리 1 | Allowed |
| [CWE-1074](https://cwe.mitre.org/data/definitions/1074.html) Class with Excessively Deep Inheritance | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1093 / 거리 1 | Prohibited |
| [CWE-1075](https://cwe.mitre.org/data/definitions/1075.html) Unconditional Control Flow Transfer outside of Switch Block | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1120 / 거리 1 | Allowed |
| [CWE-1076](https://cwe.mitre.org/data/definitions/1076.html) Insufficient Adherence to Expected Conventions | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 0 | Prohibited |
| [CWE-1078](https://cwe.mitre.org/data/definitions/1078.html) Inappropriate Source Code Style or Formatting | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 1 | Prohibited |
| [CWE-1079](https://cwe.mitre.org/data/definitions/1079.html) Parent Class without Virtual Destructor Method | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 1 | Allowed |
| [CWE-1080](https://cwe.mitre.org/data/definitions/1080.html) Source Code File with Excessive Number of Lines of Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1120 / 거리 1 | Prohibited |
| [CWE-1082](https://cwe.mitre.org/data/definitions/1082.html) Class Instance Self Destruction Control Element | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 1 | Prohibited |
| [CWE-1083](https://cwe.mitre.org/data/definitions/1083.html) Data Access from Outside Expected Data Manager Component | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1061 / 거리 1 | Prohibited |
| [CWE-1085](https://cwe.mitre.org/data/definitions/1085.html) Invokable Control Element with Excessive Volume of Commented-out Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 2 | Prohibited |
| [CWE-1086](https://cwe.mitre.org/data/definitions/1086.html) Class with Excessive Number of Child Classes | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1093 / 거리 1 | Prohibited |
| [CWE-1087](https://cwe.mitre.org/data/definitions/1087.html) Class with Virtual Method without a Virtual Destructor | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 1 | Allowed |
| [CWE-1090](https://cwe.mitre.org/data/definitions/1090.html) Method Containing Access of a Member Element from Another Class | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1061 / 거리 1 | Prohibited |
| [CWE-1091](https://cwe.mitre.org/data/definitions/1091.html) Use of Object without Invoking Destructor Method | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 1 | Allowed |
| [CWE-1092](https://cwe.mitre.org/data/definitions/1092.html) Use of Same Invokable Control Element in Multiple Architectural Layers | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1092 / 거리 0 | Prohibited |
| [CWE-1093](https://cwe.mitre.org/data/definitions/1093.html) Excessively Complex Data Representation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1093 / 거리 0 | Allowed-with-Review |
| [CWE-1095](https://cwe.mitre.org/data/definitions/1095.html) Loop Condition Value Update within the Loop | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1120 / 거리 1 | Prohibited |
| [CWE-1097](https://cwe.mitre.org/data/definitions/1097.html) Persistent Storable Data Element without Associated Comparison Control Element | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 1 | Prohibited |
| [CWE-1098](https://cwe.mitre.org/data/definitions/1098.html) Data Element containing Pointer Item without Proper Copy Control Element | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 1 | Allowed |
| [CWE-1099](https://cwe.mitre.org/data/definitions/1099.html) Inconsistent Naming Conventions for Identifiers | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 2 | Prohibited |
| [CWE-1100](https://cwe.mitre.org/data/definitions/1100.html) Insufficient Isolation of System-Dependent Functions | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1061 / 거리 1 | Allowed |
| [CWE-1101](https://cwe.mitre.org/data/definitions/1101.html) Reliance on Runtime Component in Generated Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1101 / 거리 0 | Prohibited |
| [CWE-1102](https://cwe.mitre.org/data/definitions/1102.html) Reliance on Machine-Dependent Data Representation | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-758 / 거리 1 | Allowed |
| [CWE-1103](https://cwe.mitre.org/data/definitions/1103.html) Use of Platform-Dependent Third Party Components | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-758 / 거리 1 | Prohibited |
| [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) Use of Unmaintained Third Party Components | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1357 / 거리 1 | Allowed |
| [CWE-1105](https://cwe.mitre.org/data/definitions/1105.html) Insufficient Encapsulation of Machine-Dependent Functionality | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1061, CWE-758 / 거리 1 | Prohibited |
| [CWE-1106](https://cwe.mitre.org/data/definitions/1106.html) Insufficient Use of Symbolic Constants | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 2 | Prohibited |
| [CWE-1107](https://cwe.mitre.org/data/definitions/1107.html) Insufficient Isolation of Symbolic Constant Definitions | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 2 | Prohibited |
| [CWE-1108](https://cwe.mitre.org/data/definitions/1108.html) Excessive Reliance on Global Variables | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 1 | Allowed |
| [CWE-1109](https://cwe.mitre.org/data/definitions/1109.html) Use of Same Variable for Multiple Purposes | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 2 | Prohibited |
| [CWE-1110](https://cwe.mitre.org/data/definitions/1110.html) Incomplete Design Documentation | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1059 / 거리 1 | Prohibited |
| [CWE-1111](https://cwe.mitre.org/data/definitions/1111.html) Incomplete I/O Documentation | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1059 / 거리 1 | Prohibited |
| [CWE-1112](https://cwe.mitre.org/data/definitions/1112.html) Incomplete Documentation of Program Execution | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1059 / 거리 1 | Prohibited |
| [CWE-1113](https://cwe.mitre.org/data/definitions/1113.html) Inappropriate Comment Style | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 2 | Prohibited |
| [CWE-1114](https://cwe.mitre.org/data/definitions/1114.html) Inappropriate Whitespace Style | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 2 | Prohibited |
| [CWE-1115](https://cwe.mitre.org/data/definitions/1115.html) Source Code Element without Standard Prologue | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 2 | Prohibited |
| [CWE-1116](https://cwe.mitre.org/data/definitions/1116.html) Inaccurate Source Code Comments | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 2 | Allowed |
| [CWE-1117](https://cwe.mitre.org/data/definitions/1117.html) Callable with Insufficient Behavioral Summary | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1076 / 거리 2 | Prohibited |
| [CWE-1118](https://cwe.mitre.org/data/definitions/1118.html) Insufficient Documentation of Error Handling Techniques | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1059 / 거리 1 | Prohibited |
| [CWE-1119](https://cwe.mitre.org/data/definitions/1119.html) Excessive Use of Unconditional Branching | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1120 / 거리 1 | Prohibited |
| [CWE-1120](https://cwe.mitre.org/data/definitions/1120.html) Excessive Code Complexity | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1120 / 거리 0 | Allowed-with-Review |
| [CWE-1121](https://cwe.mitre.org/data/definitions/1121.html) Excessive McCabe Cyclomatic Complexity | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1120 / 거리 1 | Prohibited |
| [CWE-1122](https://cwe.mitre.org/data/definitions/1122.html) Excessive Halstead Complexity | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1120 / 거리 1 | Prohibited |
| [CWE-1123](https://cwe.mitre.org/data/definitions/1123.html) Excessive Use of Self-Modifying Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1120 / 거리 1 | Allowed |
| [CWE-1124](https://cwe.mitre.org/data/definitions/1124.html) Excessively Deep Nesting | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1120 / 거리 1 | Prohibited |
| [CWE-1125](https://cwe.mitre.org/data/definitions/1125.html) Excessive Attack Surface | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1120 / 거리 1 | Prohibited |
| [CWE-1126](https://cwe.mitre.org/data/definitions/1126.html) Declaration of Variable with Unnecessarily Wide Scope | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1126 / 거리 0 | Allowed |
| [CWE-1127](https://cwe.mitre.org/data/definitions/1127.html) Compilation with Insufficient Warnings or Errors | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1127 / 거리 0 | Allowed |
| [CWE-1164](https://cwe.mitre.org/data/definitions/1164.html) Irrelevant Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1164 / 거리 0 | Allowed-with-Review |
| [CWE-1177](https://cwe.mitre.org/data/definitions/1177.html) Use of Prohibited Code | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-1177 / 거리 0 | Allowed-with-Review |
| [CWE-1189](https://cwe.mitre.org/data/definitions/1189.html) Improper Isolation of Shared Resources on System-on-a-Chip (SoC) | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | security-enforcement @ CWE-653 / 거리 1<br>unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-1192](https://cwe.mitre.org/data/definitions/1192.html) Improper Identifier for IP Block used in System-On-Chip (SOC) | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1192 / 거리 0 | Allowed |
| [CWE-1209](https://cwe.mitre.org/data/definitions/1209.html) Failure to Disable Reserved Bits | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1209 / 거리 0 | Allowed |
| [CWE-1242](https://cwe.mitre.org/data/definitions/1242.html) Inclusion of Undocumented Features or Chicken Bits | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-684 / 거리 2 | Allowed |
| [CWE-1245](https://cwe.mitre.org/data/definitions/1245.html) Improper Finite State Machines (FSMs) in Hardware Logic | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1245 / 거리 0 | Allowed |
| [CWE-1277](https://cwe.mitre.org/data/definitions/1277.html) Firmware Not Updateable | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1329 / 거리 1 | Allowed |
| [CWE-1303](https://cwe.mitre.org/data/definitions/1303.html) Non-Transparent Sharing of Microarchitectural Resources | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1303 / 거리 0 | Allowed |
| [CWE-1310](https://cwe.mitre.org/data/definitions/1310.html) Missing Ability to Patch ROM Code | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1329 / 거리 1 | Allowed |
| [CWE-1329](https://cwe.mitre.org/data/definitions/1329.html) Reliance on Component That is Not Updateable | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1329 / 거리 0 | Allowed |
| [CWE-1331](https://cwe.mitre.org/data/definitions/1331.html) Improper Isolation of Shared Resources in Network On Chip (NoC) | 추가 근거·전문 자료<br>운영: 미정 | actor_and_access_scope (운영)<br>authorization_enforcement (소스)<br>cve_specific_mechanism (CVE 메커니즘) | security-enforcement @ CWE-653 / 거리 1<br>unspecified-mechanism @ CWE-668 / 거리 1 | Allowed |
| [CWE-1341](https://cwe.mitre.org/data/definitions/1341.html) Multiple Releases of Same Resource or Handle | 소스 필요<br>운영: CVE 문맥에 따라 추가 | code_structure (소스) | code-structure @ CWE-573 / 거리 2 | Allowed |
| [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) Reliance on Insufficiently Trustworthy Component | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1357 / 거리 0 | Allowed-with-Review |
| [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) Dependency on Vulnerable Third-Party Component | 추가 근거·전문 자료<br>운영: 미정 | design_documentation (전문 자료) | documentation-design @ CWE-1357, CWE-657 / 거리 1 | Allowed-with-Review |
| [CWE-1431](https://cwe.mitre.org/data/definitions/1431.html) Driving Intermediate Cryptographic State/Results to Hardware Module Outputs | 추가 근거·전문 자료<br>운영: 미정 | hardware_design (전문 자료) | hardware-design-evidence @ CWE-1431 / 거리 0 | Allowed |
| [CWE-1434](https://cwe.mitre.org/data/definitions/1434.html) Insecure Setting of Generative AI/ML Model Inference Parameters | 소스 필요<br>운영: CVE 문맥에 따라 추가 | state_control_flow (소스) | state-and-lifetime @ CWE-665 / 거리 1 | Allowed |

</details>


<!-- END GENERATED SECTION 3 RESULTS -->

### 상속 원칙과 예외

1. 직접 지정한 세부 CWE 규칙을 먼저 적용한다.
2. 직접 규칙이 없으면 View 1000의 실제 `ChildOf` 경로에서 가장 가까운 **명시적 세부 기준점**을 찾는다.
3. 같은 거리의 기준점이 여러 개면 필요한 증거를 합친다. 다중 상속을 임의의 하나로 줄이지 않는다.
4. 직접 지정한 세부 예외는 더 넓은 상위 규칙보다 우선한다. 제외한 상위 규칙도 `shadowed_rules`로 남긴다.
5. 운영 전용 기본값은 별도로 열거한 26개 관찰 가능한 유형으로 제한한다. 새 자식 유형이 권한 관련 부모 아래 추가됐다는 이유만으로 운영 가능으로 확장하지 않는다.
6. 하드웨어 관련 구체 명칭이나 명시적 HDL 플랫폼 범위를 확인하면 소프트웨어 코드로 대체하지 않는다. `Not Language-Specific`이 함께 있는 목록을 단순히 HDL 전용으로 해석하지 않는다.

상속은 프로젝트의 재현 가능한 정책 구성 방법이며, 공식 계층 자체가 동일한 탐지 방법을 보장한다는 뜻은 아니다. 잘못된 일반화를 막기 위해 세부 예외와 보수적 유보를 둔다.

## 4. CWE 기본값과 실제 CVE 메커니즘의 구분

기본표만으로 모든 CVE의 경로를 확정하지 않는다. CVE 설명·권고 요약에서 추출한 **원문 위치와 인용**을 남기면서 제한적인 보정 규칙을 적용한다.

| 사례 | 구분 이유 | 경로 |
| --- | --- | --- |
| CWE-89: 입력으로 SQL 구문을 구성하는 결함 | 입력 처리·구문 생성 구현을 확인해야 함 | 소스 필요, 외부 접근 등 운영 조건이 있으면 함께 수집 |
| CWE-862: 핸들러가 권한 검사를 수행하지 않는다는 구체 설명 | 인가 검사의 구현과 자산의 역할·접근 범위를 모두 확인 | 소스 + 운영 맥락 |
| CWE-862: 접근 정책 설정 파일의 인증/인가 설정 문제라는 구체 설명 | 실제 배포 정책을 운영 기록으로 확인 가능한 메커니즘 | 운영 맥락만 |
| CWE-327: 취약한 암호라는 일반 설명만 존재 | 임베디드 구현 문제인지 설정 선택 문제인지 알 수 없음 | 경로 유보 |
| CWE-327: 지원/활성화한 TLS 암호 설정의 문제라는 구체 설명 | 배포한 프로토콜·암호 설정을 확인 가능 | 운영 맥락만 |
| CWE-493/500 등 Java 접근 제어자·final 선언 문제 | 파일 권한이 아니라 소스 언어 선언의 속성 | 소스 필요 |
| CWE-1394의 기본 키, 실제 CVE는 하드코딩된 키 | 키 회전 설정 질문만으로 임베디드 값을 검증할 수 없음 | 소스 필요 |
| CWE-1240의 위험한 암호 구현 | 암호 원시함수 설계·구현 보증을 설정 질문으로 대신할 수 없음 | 전문 증거 필요 |

코드 결함에 관한 명시적 근거는 운영 설정 보정보다 우선한다. 단순한 약점 이름인 “Missing Authentication”, 단어 “TLS”, 단어 “configuration”만으로 새 구현 메커니즘이나 운영 검증 가능성을 만들어내지 않는다.

`remote`, `authenticated`, `privileges` 등의 문구는 운영 맥락을 추가로 확인할 신호다. 이 신호를 완전한 악용 전제조건이나 충족된 조건으로 취급하지 않는다.

<!-- BEGIN GENERATED SECTION 4 RESULTS -->

### 4.1 실제 적용 순서와 기록하는 결과

| 순서 | 검사 내용 | 기록하는 필드 / 결과 |
| --- | --- | --- |
| 1 | 보고된 세부 CWE와 모든 Pillar 경로 확인 | `cwes`, `pillars`, `decisions[].paths` |
| 2 | CWE 기본 증거 유형 확인; 매핑 Usage는 참고로 보존 | `baseline_source_requirement`, `cve_mapping_gate` |
| 3 | 직접 기준·가장 가까운 상위 세부 기준 적용 | `matched_rules`, `distance`, `anchors[].path` |
| 4 | 명시적 구현 결함 문구 확인 | `refinement_rules`, `evidence[].quote/span/source_id` |
| 5 | 허용한 유형에서 명시적 운영 설정 메커니즘 확인 | 구현 결함 근거가 우선. 허용된 경우에만 운영 경로로 보정 |
| 6 | 실제 역할·접근·설정 등 운영 문맥 신호 확인 | `operational_required`, `operational_requirement_evidence` |
| 7 | 여러 CWE의 요구 합치기 | 필요 증거가 미확정인 항목이 하나라도 있으면 `routing_unknown` |
| 8 | 소스 분석 결과 등록 여부 적용 | `source_available`, `workflow_branch` |

이 순서는 경로 결정의 실행 결과를 설명한다. 소스를 분석하거나 운영 답변의 진위를 검증하거나 최종 VEX 상태를 평가한 결과가 아니다.

### 4.2 고유 CWE 944개 전체에 동일한 중립 입력을 넣은 결과

입력 설명을 모든 CWE에서 `A product vulnerability exists.`로 고정하고 `source_available=True`로 놓아 실행했다. 이 값은 **분석 결과가 있다고 가정한 라우터 인자**이며, 944개 제품의 소스를 수집했다는 뜻이 아니다. 실제 CVE 분포나 분류 정확도도 아니다.

| 실행 결과 | 수 |
| --- | ---: |
| ① 소스만 | 584 |
| ② 소스+운영 | 144 |
| ③ 소스 분석 결과 대기 | 0 |
| ④ 운영만 | 26 |
| 분류 유보 | 190 |

소스 기본값 728개는 CWE 자체가 요구하는 운영 사실에 따라 소스만/소스+운영으로 나뉜다. 운영 기본값 26개와 미확정 190개는 중립 입력에서 그대로 유지된다. 매핑 Usage는 실행 경로를 차단하지 않는다. 중립 입력은 구체적인 CVE 메커니즘 보정을 유발하지 않는다.

### 4.3 로컬에 저장된 실제 CVE 입력의 경로 결과

아래는 로컬 NVD/CSAF 스냅샷의 실제 CVE 설명과 보고된 CWE를 넣어 실행한 결과다. 최신 온라인 원문을 새로 조사한 결과가 아니다. `자료 없음/있음`은 같은 입력에서 **소스 분석 결과 등록 여부만 바꾼 대조**이며, 실제 소스 수집 여부에 대한 주장이 아니다.

| 실제 CVE | 보고된 CWE | 자료 없음 | 자료 있다고 가정 | 적용한 기준 / 보정 |
| --- | --- | --- | --- | --- |
| CVE-2023-27309 | CWE-862 | ③ 소스 분석 결과 대기 | ② 소스+운영 | authorization-enforcement<br>explicit-enforcement-defect |
| CVE-2023-27411 | CWE-89 | ③ 소스 분석 결과 대기 | ② 소스+운영 | input-processing<br>explicit-code-defect |
| CVE-2026-24455 | CWE-319 | ④ 운영만 | ④ 운영만 | transport-encryption |
| CVE-2022-21940 | CWE-614, CWE-311 | 분류 유보 | 분류 유보 | cookie-configuration<br>unspecified-mechanism |
| CVE-2026-9651 | CWE-732 | ④ 운영만 | ④ 운영만 | resource-permissions |
| CVE-2026-61892 | CWE-732 | ④ 운영만 | ④ 운영만 | resource-permissions |
| CVE-2019-1563 | CWE-203, CWE-327 | 분류 유보 | 분류 유보 | crypto-mechanism-dependent<br>unspecified-mechanism |
| CVE-2020-10932 | CWE-203, CWE-327 | 분류 유보 | 분류 유보 | crypto-mechanism-dependent<br>unspecified-mechanism |

**주의할 실제 사례:** `CVE-2026-61892`는 현재 코드상 운영 경로다. 설명에는 token 수정이 나오므로, 구현 결함인지 배포 권한 문제인지 별도 검토가 필요할 수 있다. 이 출력은 라우터의 현 상태를 공개한 것이며, 운영 경로가 충분하다는 독립 정답으로 간주하지 않는다.

### 4.4 문서 재현용 통제 입력의 대조 결과

다음 항목은 **실제 CVE가 아닌 구성한 입력**이다. 같은 CWE에서도 구현/설정 설명이 달라지면 어떻게 동작하는지, 그리고 정보 부족을 유보하는지 확인하는 용도다.

| 통제 사례 | 입력 CWE | 자료 없음 | 자료 있다고 가정 |
| --- | --- | --- | --- |
| 운영 문구가 없는 메모리 결함 | CWE-787 | ③ 소스 분석 결과 대기 | ① 소스만 |
| 운영 문맥이 추가되는 메모리 결함 | CWE-787 | ③ 소스 분석 결과 대기 | ② 소스+운영 |
| 인가 검사 구현 누락 | CWE-862 | ③ 소스 분석 결과 대기 | ② 소스+운영 |
| 명시적인 접근 정책 설정 문제 | CWE-862 | ④ 운영만 | ④ 운영만 |
| TLS라는 단어만 있는 암호 유형 | CWE-327 | 분류 유보 | 분류 유보 |
| 명시적인 TLS 암호 설정 문제 | CWE-327 | ④ 운영만 | ④ 운영만 |
| 기본 키의 배포 기록 검토 | CWE-1394 | ④ 운영만 | ④ 운영만 |
| 하드코딩된 키로 메커니즘 보정 | CWE-1394 | ③ 소스 분석 결과 대기 | ② 소스+운영 |
| Java 선언 속성의 직접 예외 | CWE-493 | ③ 소스 분석 결과 대기 | ① 소스만 |
| 하드웨어 전문 증거 요구 | CWE-1252 | 분류 유보 | 분류 유보 |
| Discouraged도 기존 CWE를 유지하고 메모리 증거로 진행 | CWE-119 | ③ 소스 분석 결과 대기 | ① 소스만 |
| 여러 CWE 중 미확정 항목 보존 | CWE-787, CWE-999999 | 분류 유보 | 분류 유보 |

### 4.5 각 입력의 원문·상속 경로·매칭 인용·필요한 사실

아래 펼침 항목은 위 표의 모든 실제/통제 입력을 상세히 추적한다. 문구가 매칭되지 않으면 “매칭 없음”으로 기록한다. 매칭된 인용을 실제 악용 조건이 모두 파악됐다는 뜻으로 해석하지 않는다.

<details>
<summary>CVE-2023-27309 · CVE-2023-27309 · 실제 CVE의 로컬 스냅샷</summary>

- 입력 종류: **실제 CVE의 로컬 스냅샷**
- 입력 CWE: `CWE-862`
- 자료 없음: **③ 소스 분석 결과 대기**
- 자료 있다고 가정: **② 소스+운영**
- 증거 요구: `source_required` / 운영 필요: `True`
- 로컬 입력 레코드 해시: `8f0fbe0a3dc9b2ad0220b8dc0b9bbf8e21204d5a60a9a175eb2d8b93ca91f805`
- 로컬 수집 시각 필드: `2026-11-01T03:02:34.7216839`

**입력 설명 원문**

> A vulnerability has been identified in RUGGEDCOM CROSSBOW (All versions < V5.2). The client query handler of the affected application fails to check for proper permissions for specific write queries. This could allow an authenticated remote attacker to perform unauthorized actions.

**CWE-862: Missing Authorization**

- Pillar: `CWE-284`
- 기본값 → 이번 입력: `required` → `required`
- 매핑 Usage: `Allowed-with-Review`
- 결정 이유: Verify implementation checks and the deployed actor/role/interface scope separately. CVE evidence refines the mechanism using: explicit-enforcement-defect.
- 기준: `authorization-enforcement` / 거리 `1` / 경로 `CWE-862 → CWE-285`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| explicit-enforcement-defect | fails to check for proper permission | [53, 89] | CVE-2023-27309:ebd6439bbe15 |
| explicit-enforcement-defect | fails to check for proper permission | [134, 170] | description |

| 필요한 사실 | 소재 |
| --- | --- |
| `actor_and_access_scope`: Actual actors, roles, accessible interfaces and operating scope | 운영 |
| `authorization_enforcement`: Authorization/authentication checks on every affected code path | 소스 |

운영 문맥으로 매칭한 원문 조각: `authenticated`, `remote`. 이 조각들은 전제조건 충족의 증거가 아니다.

원문 확인 링크: [NVD 기록](https://nvd.nist.gov/vuln/detail/CVE-2023-27309). 링크의 현재 내용과 로컬 스냅샷은 다를 수 있다.

</details>

<details>
<summary>CVE-2023-27411 · CVE-2023-27411 · 실제 CVE의 로컬 스냅샷</summary>

- 입력 종류: **실제 CVE의 로컬 스냅샷**
- 입력 CWE: `CWE-89`
- 자료 없음: **③ 소스 분석 결과 대기**
- 자료 있다고 가정: **② 소스+운영**
- 증거 요구: `source_required` / 운영 필요: `True`
- 로컬 입력 레코드 해시: `39bb9b3ea0c51595953a617a70cb4a04598abb8074c6842fbb22541413d12586`
- 로컬 수집 시각 필드: `2026-11-01T03:02:34.7216839`

**입력 설명 원문**

> A vulnerability has been identified in RUGGEDCOM CROSSBOW (All versions < V5.4). The affected applications is vulnerable to SQL injection. This could allow an authenticated remote attackers to execute arbitrary SQL queries on the server database and escalate privileges.

**CWE-89: Improper Neutralization of Special Elements used in an SQL Command**

- Pillar: `CWE-707`
- 기본값 → 이번 입력: `required` → `required`
- 매핑 Usage: `Allowed`
- 결정 이유: Validation/neutralization cannot be established by a configured-service answer alone. CVE evidence refines the mechanism using: explicit-code-defect.
- 기준: `input-processing` / 거리 `2` / 경로 `CWE-89 → CWE-943 → CWE-74`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| explicit-code-defect | SQL injection | [43, 56] | CVE-2023-27411:f6a30f099361 |
| explicit-code-defect | SQL injection | [124, 137] | description |

| 필요한 사실 | 소재 |
| --- | --- |
| `input_to_sensitive_operation`: Input validation, normalization and input-to-operation data flow | 소스 |
| `actor_and_access_scope`: Actual actors, roles, accessible interfaces and operating scope | 운영 |

운영 문맥으로 매칭한 원문 조각: `authenticated`, `remote`, `privileges`. 이 조각들은 전제조건 충족의 증거가 아니다.

원문 확인 링크: [NVD 기록](https://nvd.nist.gov/vuln/detail/CVE-2023-27411). 링크의 현재 내용과 로컬 스냅샷은 다를 수 있다.

</details>

<details>
<summary>CVE-2026-24455 · CVE-2026-24455 · 실제 CVE의 로컬 스냅샷</summary>

- 입력 종류: **실제 CVE의 로컬 스냅샷**
- 입력 CWE: `CWE-319`
- 자료 없음: **④ 운영만**
- 자료 있다고 가정: **④ 운영만**
- 증거 요구: `operational_review` / 운영 필요: `True`
- 로컬 입력 레코드 해시: `6c85a2b154fca1cbba4c8ce1722e7944691203d8c02bde93e6cb0f54707186b8`
- 로컬 수집 시각 필드: `2026-11-01T03:00:01.5511476`

**입력 설명 원문**

> The embedded web interface of the device does not support HTTPS/TLS for 
> authentication and uses HTTP Basic Authentication. Traffic is encoded 
> but not encrypted, exposing user credentials to passive interception by 
> attackers on the same network.

**CWE-319: Cleartext Transmission of Sensitive Information**

- Pillar: `CWE-693`
- 기본값 → 이번 입력: `not_required` → `not_required`
- 매핑 Usage: `Allowed`
- 결정 이유: Review documented transport behavior against actual protocol/path records. This does not prove absence of implementation defects.
- 기준: `transport-encryption` / 거리 `0` / 경로 `CWE-319`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| 없음 | 매칭 없음 | 해당 없음 | 해당 없음 |

| 필요한 사실 | 소재 |
| --- | --- |
| `communication_configuration`: Actual communication path, encryption and enabled protocol configuration | 운영 |
| `actor_and_access_scope`: Actual actors, roles, accessible interfaces and operating scope | 운영 |

운영 문맥으로 매칭한 원문 조각: `network`. 이 조각들은 전제조건 충족의 증거가 아니다.

원문 확인 링크: [NVD 기록](https://nvd.nist.gov/vuln/detail/CVE-2026-24455). 링크의 현재 내용과 로컬 스냅샷은 다를 수 있다.

</details>

<details>
<summary>CVE-2022-21940 · CVE-2022-21940 · 실제 CVE의 로컬 스냅샷</summary>

- 입력 종류: **실제 CVE의 로컬 스냅샷**
- 입력 CWE: `CWE-614, CWE-311`
- 자료 없음: **분류 유보**
- 자료 있다고 가정: **분류 유보**
- 증거 요구: `undetermined` / 운영 필요: `False`
- 로컬 입력 레코드 해시: `cd2afb3fb1c9802e0aff94fd9533470261f71c27f0395a8cb956b0aed34fef5a`
- 로컬 수집 시각 필드: `2026-10-31T03:02:42.9303476`

**입력 설명 원문**

> Sensitive Cookie in HTTPS Session Without 'Secure' Attribute vulnerability in Johnson Controls System Configuration Tool (SCT) version 14 prior to 14.2.3 and version 15 prior to 15.0.3 could allow access to the cookie.

**CWE-311: Missing Encryption of Sensitive Data**

- Pillar: `CWE-693`
- 기본값 → 이번 입력: `undetermined` → `undetermined`
- 매핑 Usage: `Discouraged`
- 결정 이유: The broad weakness includes both implementation and deployment mechanisms; obtain CVE-specific evidence.
- 기준: `unspecified-mechanism` / 거리 `0` / 경로 `CWE-311`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| 없음 | 매칭 없음 | 해당 없음 | 해당 없음 |

| 필요한 사실 | 소재 |
| --- | --- |
| `cve_specific_mechanism`: More specific CVE/vendor mechanism evidence before selecting a method | CVE 메커니즘 |

**CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute**

- Pillar: `CWE-693`
- 기본값 → 이번 입력: `not_required` → `not_required`
- 매핑 Usage: `Allowed`
- 결정 이유: Documented cookie and transport settings can be inspected in deployed service records.
- 기준: `cookie-configuration` / 거리 `0` / 경로 `CWE-614`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| 없음 | 매칭 없음 | 해당 없음 | 해당 없음 |

| 필요한 사실 | 소재 |
| --- | --- |
| `communication_configuration`: Actual communication path, encryption and enabled protocol configuration | 운영 |
| `feature_configuration`: Vendor-documented feature and deployment configuration records | 운영 |
| `actor_and_access_scope`: Actual actors, roles, accessible interfaces and operating scope | 운영 |

원문 확인 링크: [NVD 기록](https://nvd.nist.gov/vuln/detail/CVE-2022-21940). 링크의 현재 내용과 로컬 스냅샷은 다를 수 있다.

</details>

<details>
<summary>CVE-2026-9651 · CVE-2026-9651 · 실제 CVE의 로컬 스냅샷</summary>

- 입력 종류: **실제 CVE의 로컬 스냅샷**
- 입력 CWE: `CWE-732`
- 자료 없음: **④ 운영만**
- 자료 있다고 가정: **④ 운영만**
- 증거 요구: `operational_review` / 운영 필요: `True`
- 로컬 입력 레코드 해시: `9b880eedae352be0d6f04b1f4941855e5ade909e4eccba013eb266a80ef0aa1e`
- 로컬 수집 시각 필드: `2026-11-01T03:00:01.5511476`

**입력 설명 원문**

> CWE-732 Incorrect Permission Assignment for Critical Resource vulnerability that could cause unauthorized disclosure of password hashes and potential account compromise when an attacker with privileged local access reads improperly protected system files.

**CWE-732: Incorrect Permission Assignment for Critical Resource**

- Pillar: `CWE-284, CWE-664`
- 기본값 → 이번 입력: `not_required` → `not_required`
- 매핑 Usage: `Allowed-with-Review`
- 결정 이유: Effective permissions and account/process privileges are operator-observable with records.
- 기준: `resource-permissions` / 거리 `0` / 경로 `CWE-732`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| 없음 | 매칭 없음 | 해당 없음 | 해당 없음 |

| 필요한 사실 | 소재 |
| --- | --- |
| `actor_and_access_scope`: Actual actors, roles, accessible interfaces and operating scope | 운영 |
| `resource_permissions`: Effective resource ownership, permissions and access-control records | 운영 |

원문 확인 링크: [NVD 기록](https://nvd.nist.gov/vuln/detail/CVE-2026-9651). 링크의 현재 내용과 로컬 스냅샷은 다를 수 있다.

</details>

<details>
<summary>CVE-2026-61892 · CVE-2026-61892 · 실제 CVE의 로컬 스냅샷</summary>

- 입력 종류: **실제 CVE의 로컬 스냅샷**
- 입력 CWE: `CWE-732`
- 자료 없음: **④ 운영만**
- 자료 있다고 가정: **④ 운영만**
- 증거 요구: `operational_review` / 운영 필요: `True`
- 로컬 입력 레코드 해시: `34c736c9ba10267409ba6764700c3d193666dc47c450cbb0503a59c86cac3336`
- 로컬 수집 시각 필드: `2026-11-01T03:00:01.5511476`

**입력 설명 원문**

> Weintek cMT3092X HMI allows a non-privileged user to modify tokens to escalate privileges.

**해석 한계:** 현재 규칙은 CWE-732 기본값을 따라 운영 경로를 선택한다. 그러나 설명의 token 수정이 구현 검증을 필요로 하는지는 이 규칙이 확정하지 못한다. 올바른 경로의 독립 정답으로 사용하지 말고 추가 메커니즘 검토 대상으로 남긴다.

**CWE-732: Incorrect Permission Assignment for Critical Resource**

- Pillar: `CWE-284, CWE-664`
- 기본값 → 이번 입력: `not_required` → `not_required`
- 매핑 Usage: `Allowed-with-Review`
- 결정 이유: Effective permissions and account/process privileges are operator-observable with records.
- 기준: `resource-permissions` / 거리 `0` / 경로 `CWE-732`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| 없음 | 매칭 없음 | 해당 없음 | 해당 없음 |

| 필요한 사실 | 소재 |
| --- | --- |
| `actor_and_access_scope`: Actual actors, roles, accessible interfaces and operating scope | 운영 |
| `resource_permissions`: Effective resource ownership, permissions and access-control records | 운영 |

운영 문맥으로 매칭한 원문 조각: `privileges`. 이 조각들은 전제조건 충족의 증거가 아니다.

원문 확인 링크: [NVD 기록](https://nvd.nist.gov/vuln/detail/CVE-2026-61892). 링크의 현재 내용과 로컬 스냅샷은 다를 수 있다.

</details>

<details>
<summary>CVE-2019-1563 · CVE-2019-1563 · 실제 CVE의 로컬 스냅샷</summary>

- 입력 종류: **실제 CVE의 로컬 스냅샷**
- 입력 CWE: `CWE-203, CWE-327`
- 자료 없음: **분류 유보**
- 자료 있다고 가정: **분류 유보**
- 증거 요구: `undetermined` / 운영 필요: `False`
- 로컬 입력 레코드 해시: `6eeb4255b2a145191045a456de510d34556e911d2ac0f92d5d811e390e11b637`
- 로컬 수집 시각 필드: `2026-10-30T03:03:02.5554237`

**입력 설명 원문**

> In situations where an attacker receives automated notification of the success or failure of a decryption attempt an attacker, after sending a very large number of messages to be decrypted, can recover a CMS/PKCS7 transported encryption key or decrypt any RSA encrypted message that was encrypted with the public RSA key, using a Bleichenbacher padding oracle attack. Applications are not affected if they use a certificate together with the private RSA key to the CMS_decrypt or PKCS7_decrypt functions to select the correct recipient info to decrypt. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c). Fixed in OpenSSL 1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s).

**CWE-203: Observable Discrepancy**

- Pillar: `CWE-664`
- 기본값 → 이번 입력: `undetermined` → `undetermined`
- 매핑 Usage: `Allowed`
- 결정 이유: The broad weakness includes both implementation and deployment mechanisms; obtain CVE-specific evidence.
- 기준: `unspecified-mechanism` / 거리 `1` / 경로 `CWE-203 → CWE-200`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| 없음 | 매칭 없음 | 해당 없음 | 해당 없음 |

| 필요한 사실 | 소재 |
| --- | --- |
| `cve_specific_mechanism`: More specific CVE/vendor mechanism evidence before selecting a method | CVE 메커니즘 |

**CWE-327: Use of a Broken or Risky Cryptographic Algorithm**

- Pillar: `CWE-693`
- 기본값 → 이번 입력: `undetermined` → `undetermined`
- 매핑 Usage: `Allowed-with-Review`
- 결정 이유: A weak algorithm may be embedded in code or selected by deployment configuration. Require CVE/vendor mechanism evidence before choosing the method.
- 기준: `crypto-mechanism-dependent` / 거리 `0` / 경로 `CWE-327`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| 없음 | 매칭 없음 | 해당 없음 | 해당 없음 |

| 필요한 사실 | 소재 |
| --- | --- |
| `cve_specific_mechanism`: More specific CVE/vendor mechanism evidence before selecting a method | CVE 메커니즘 |

원문 확인 링크: [NVD 기록](https://nvd.nist.gov/vuln/detail/CVE-2019-1563). 링크의 현재 내용과 로컬 스냅샷은 다를 수 있다.

</details>

<details>
<summary>CVE-2020-10932 · CVE-2020-10932 · 실제 CVE의 로컬 스냅샷</summary>

- 입력 종류: **실제 CVE의 로컬 스냅샷**
- 입력 CWE: `CWE-203, CWE-327`
- 자료 없음: **분류 유보**
- 자료 있다고 가정: **분류 유보**
- 증거 요구: `undetermined` / 운영 필요: `False`
- 로컬 입력 레코드 해시: `ca82f22f5f1d8eefb2e6d02294f07e8145590966cc926843ba2301c04025608c`

**입력 설명 원문**

> An issue was discovered in Arm Mbed TLS before 2.16.6 and 2.7.x before 2.7.15. An attacker that can get precise enough side-channel measurements can recover the long-term ECDSA private key by (1) reconstructing the projective coordinate of the result of scalar multiplication by exploiting side channels in the conversion to affine coordinates; (2) using an attack described by Naccache, Smart, and Stern in 2003 to recover a few bits of the ephemeral scalar from those projective coordinates via several measurements; and (3) using a lattice attack to get from there to the long-term ECDSA private key used for the signatures. Typically an attacker would have sufficient access when attacking an SGX enclave and controlling the untrusted OS.

**CWE-203: Observable Discrepancy**

- Pillar: `CWE-664`
- 기본값 → 이번 입력: `undetermined` → `undetermined`
- 매핑 Usage: `Allowed`
- 결정 이유: The broad weakness includes both implementation and deployment mechanisms; obtain CVE-specific evidence.
- 기준: `unspecified-mechanism` / 거리 `1` / 경로 `CWE-203 → CWE-200`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| 없음 | 매칭 없음 | 해당 없음 | 해당 없음 |

| 필요한 사실 | 소재 |
| --- | --- |
| `cve_specific_mechanism`: More specific CVE/vendor mechanism evidence before selecting a method | CVE 메커니즘 |

**CWE-327: Use of a Broken or Risky Cryptographic Algorithm**

- Pillar: `CWE-693`
- 기본값 → 이번 입력: `undetermined` → `undetermined`
- 매핑 Usage: `Allowed-with-Review`
- 결정 이유: A weak algorithm may be embedded in code or selected by deployment configuration. Require CVE/vendor mechanism evidence before choosing the method.
- 기준: `crypto-mechanism-dependent` / 거리 `0` / 경로 `CWE-327`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| 없음 | 매칭 없음 | 해당 없음 | 해당 없음 |

| 필요한 사실 | 소재 |
| --- | --- |
| `cve_specific_mechanism`: More specific CVE/vendor mechanism evidence before selecting a method | CVE 메커니즘 |

원문 확인 링크: [NVD 기록](https://nvd.nist.gov/vuln/detail/CVE-2020-10932). 링크의 현재 내용과 로컬 스냅샷은 다를 수 있다.

</details>

<details>
<summary>control-memory · 운영 문구가 없는 메모리 결함 · 통제 입력: 실제 CVE 아님</summary>

- 입력 종류: **통제 입력: 실제 CVE 아님**
- 입력 CWE: `CWE-787`
- 자료 없음: **③ 소스 분석 결과 대기**
- 자료 있다고 가정: **① 소스만**
- 증거 요구: `source_required` / 운영 필요: `False`

**입력 설명 원문**

> An out-of-bounds write occurs.

**CWE-787: Out-of-bounds Write**

- Pillar: `CWE-664`
- 기본값 → 이번 입력: `required` → `required`
- 매핑 Usage: `Allowed-with-Review`
- 결정 이유: Memory/index/lifetime claims require implementation-level definitions and operation evidence. CVE evidence refines the mechanism using: explicit-memory-defect.
- 기준: `memory-safety` / 거리 `1` / 경로 `CWE-787 → CWE-119`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| explicit-memory-defect | out-of-bounds | [3, 16] | description |

| 필요한 사실 | 소재 |
| --- | --- |
| `memory_bounds_lifetime`: Bounds, object lifetime and affected operations | 소스 |

</details>

<details>
<summary>control-remote-memory · 운영 문맥이 추가되는 메모리 결함 · 통제 입력: 실제 CVE 아님</summary>

- 입력 종류: **통제 입력: 실제 CVE 아님**
- 입력 CWE: `CWE-787`
- 자료 없음: **③ 소스 분석 결과 대기**
- 자료 있다고 가정: **② 소스+운영**
- 증거 요구: `source_required` / 운영 필요: `True`

**입력 설명 원문**

> A remote attacker triggers an out-of-bounds write.

**CWE-787: Out-of-bounds Write**

- Pillar: `CWE-664`
- 기본값 → 이번 입력: `required` → `required`
- 매핑 Usage: `Allowed-with-Review`
- 결정 이유: Memory/index/lifetime claims require implementation-level definitions and operation evidence. CVE evidence refines the mechanism using: explicit-memory-defect.
- 기준: `memory-safety` / 거리 `1` / 경로 `CWE-787 → CWE-119`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| explicit-memory-defect | out-of-bounds | [30, 43] | description |

| 필요한 사실 | 소재 |
| --- | --- |
| `memory_bounds_lifetime`: Bounds, object lifetime and affected operations | 소스 |
| `actor_and_access_scope`: Actual actors, roles, accessible interfaces and operating scope | 운영 |

운영 문맥으로 매칭한 원문 조각: `remote`. 이 조각들은 전제조건 충족의 증거가 아니다.

</details>

<details>
<summary>control-authorization-code · 인가 검사 구현 누락 · 통제 입력: 실제 CVE 아님</summary>

- 입력 종류: **통제 입력: 실제 CVE 아님**
- 입력 CWE: `CWE-862`
- 자료 없음: **③ 소스 분석 결과 대기**
- 자료 있다고 가정: **② 소스+운영**
- 증거 요구: `source_required` / 운영 필요: `True`

**입력 설명 원문**

> The handler fails to check for proper permissions when remote users access it.

**CWE-862: Missing Authorization**

- Pillar: `CWE-284`
- 기본값 → 이번 입력: `required` → `required`
- 매핑 Usage: `Allowed-with-Review`
- 결정 이유: Verify implementation checks and the deployed actor/role/interface scope separately. CVE evidence refines the mechanism using: explicit-enforcement-defect.
- 기준: `authorization-enforcement` / 거리 `1` / 경로 `CWE-862 → CWE-285`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| explicit-enforcement-defect | fails to check for proper permission | [12, 48] | description |

| 필요한 사실 | 소재 |
| --- | --- |
| `actor_and_access_scope`: Actual actors, roles, accessible interfaces and operating scope | 운영 |
| `authorization_enforcement`: Authorization/authentication checks on every affected code path | 소스 |

운영 문맥으로 매칭한 원문 조각: `remote`. 이 조각들은 전제조건 충족의 증거가 아니다.

</details>

<details>
<summary>control-authorization-config · 명시적인 접근 정책 설정 문제 · 통제 입력: 실제 CVE 아님</summary>

- 입력 종류: **통제 입력: 실제 CVE 아님**
- 입력 CWE: `CWE-862`
- 자료 없음: **④ 운영만**
- 자료 있다고 가정: **④ 운영만**
- 증거 요구: `operational_review` / 운영 필요: `True`

**입력 설명 원문**

> Authentication is misconfigured by an access policy setting.

**CWE-862: Missing Authorization**

- Pillar: `CWE-284`
- 기본값 → 이번 입력: `required` → `not_required`
- 매핑 Usage: `Allowed-with-Review`
- 결정 이유: Verify implementation checks and the deployed actor/role/interface scope separately. CVE evidence refines the mechanism using: authorization-configuration-mechanism.
- 기준: `authorization-enforcement` / 거리 `1` / 경로 `CWE-862 → CWE-285`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| authorization-configuration-mechanism | Authentication is misconfigured by an access policy | [0, 51] | description |

| 필요한 사실 | 소재 |
| --- | --- |
| `actor_and_access_scope`: Actual actors, roles, accessible interfaces and operating scope | 운영 |
| `resource_permissions`: Effective resource ownership, permissions and access-control records | 운영 |

</details>

<details>
<summary>control-crypto-unspecified · TLS라는 단어만 있는 암호 유형 · 통제 입력: 실제 CVE 아님</summary>

- 입력 종류: **통제 입력: 실제 CVE 아님**
- 입력 CWE: `CWE-327`
- 자료 없음: **분류 유보**
- 자료 있다고 가정: **분류 유보**
- 증거 요구: `undetermined` / 운영 필요: `False`

**입력 설명 원문**

> The product uses TLS.

**CWE-327: Use of a Broken or Risky Cryptographic Algorithm**

- Pillar: `CWE-693`
- 기본값 → 이번 입력: `undetermined` → `undetermined`
- 매핑 Usage: `Allowed-with-Review`
- 결정 이유: A weak algorithm may be embedded in code or selected by deployment configuration. Require CVE/vendor mechanism evidence before choosing the method.
- 기준: `crypto-mechanism-dependent` / 거리 `0` / 경로 `CWE-327`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| 없음 | 매칭 없음 | 해당 없음 | 해당 없음 |

| 필요한 사실 | 소재 |
| --- | --- |
| `cve_specific_mechanism`: More specific CVE/vendor mechanism evidence before selecting a method | CVE 메커니즘 |

</details>

<details>
<summary>control-crypto-config · 명시적인 TLS 암호 설정 문제 · 통제 입력: 실제 CVE 아님</summary>

- 입력 종류: **통제 입력: 실제 CVE 아님**
- 입력 CWE: `CWE-327`
- 자료 없음: **④ 운영만**
- 자료 있다고 가정: **④ 운영만**
- 증거 요구: `operational_review` / 운영 필요: `True`

**입력 설명 원문**

> The server supports TLS with weak cipher settings.

**CWE-327: Use of a Broken or Risky Cryptographic Algorithm**

- Pillar: `CWE-693`
- 기본값 → 이번 입력: `undetermined` → `not_required`
- 매핑 Usage: `Allowed-with-Review`
- 결정 이유: A weak algorithm may be embedded in code or selected by deployment configuration. Require CVE/vendor mechanism evidence before choosing the method. CVE evidence refines the mechanism using: crypto-config-mechanism.
- 기준: `crypto-mechanism-dependent` / 거리 `0` / 경로 `CWE-327`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| crypto-config-mechanism | supports TLS with weak cipher | [11, 40] | description |

| 필요한 사실 | 소재 |
| --- | --- |
| `communication_configuration`: Actual communication path, encryption and enabled protocol configuration | 운영 |
| `feature_configuration`: Vendor-documented feature and deployment configuration records | 운영 |
| `actor_and_access_scope`: Actual actors, roles, accessible interfaces and operating scope | 운영 |

</details>

<details>
<summary>control-default-key · 기본 키의 배포 기록 검토 · 통제 입력: 실제 CVE 아님</summary>

- 입력 종류: **통제 입력: 실제 CVE 아님**
- 입력 CWE: `CWE-1394`
- 자료 없음: **④ 운영만**
- 자료 있다고 가정: **④ 운영만**
- 증거 요구: `operational_review` / 운영 필요: `True`

**입력 설명 원문**

> The product uses a default cryptographic key.

**CWE-1394: Use of Default Cryptographic Key**

- Pillar: `CWE-284`
- 기본값 → 이번 입력: `not_required` → `not_required`
- 매핑 Usage: `Allowed`
- 결정 이유: Review vendor-supported key replacement/rotation records. An explicit embedded/hard-coded key mechanism adds a source requirement.
- 기준: `key-configuration` / 거리 `0` / 경로 `CWE-1394`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| 없음 | 매칭 없음 | 해당 없음 | 해당 없음 |

| 필요한 사실 | 소재 |
| --- | --- |
| `key_configuration`: Vendor key/certificate replacement or rotation records, without secret key material | 운영 |
| `actor_and_access_scope`: Actual actors, roles, accessible interfaces and operating scope | 운영 |

</details>

<details>
<summary>control-embedded-key · 하드코딩된 키로 메커니즘 보정 · 통제 입력: 실제 CVE 아님</summary>

- 입력 종류: **통제 입력: 실제 CVE 아님**
- 입력 CWE: `CWE-1394`
- 자료 없음: **③ 소스 분석 결과 대기**
- 자료 있다고 가정: **② 소스+운영**
- 증거 요구: `source_required` / 운영 필요: `True`

**입력 설명 원문**

> The device uses a hardcoded default cryptographic key.

**CWE-1394: Use of Default Cryptographic Key**

- Pillar: `CWE-284`
- 기본값 → 이번 입력: `not_required` → `required`
- 매핑 Usage: `Allowed`
- 결정 이유: Review vendor-supported key replacement/rotation records. An explicit embedded/hard-coded key mechanism adds a source requirement. CVE evidence refines the mechanism using: explicit-code-defect.
- 기준: `key-configuration` / 거리 `0` / 경로 `CWE-1394`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| explicit-code-defect | hardcoded default cryptographic key | [18, 53] | description |

| 필요한 사실 | 소재 |
| --- | --- |
| `key_configuration`: Vendor key/certificate replacement or rotation records, without secret key material | 운영 |
| `input_to_sensitive_operation`: Input validation, normalization and input-to-operation data flow | 소스 |
| `actor_and_access_scope`: Actual actors, roles, accessible interfaces and operating scope | 운영 |

</details>

<details>
<summary>control-java-declaration · Java 선언 속성의 직접 예외 · 통제 입력: 실제 CVE 아님</summary>

- 입력 종류: **통제 입력: 실제 CVE 아님**
- 입력 CWE: `CWE-493`
- 자료 없음: **③ 소스 분석 결과 대기**
- 자료 있다고 가정: **① 소스만**
- 증거 요구: `source_required` / 운영 필요: `False`

**입력 설명 원문**

> A critical public variable lacks the final modifier.

**CWE-493: Critical Public Variable Without Final Modifier**

- Pillar: `CWE-284, CWE-664`
- 기본값 → 이번 입력: `required` → `required`
- 매핑 Usage: `Allowed`
- 결정 이유: Public/private/final declarations are source-language properties, not deployed filesystem/account permissions.
- 기준: `language-access-modifiers` / 거리 `0` / 경로 `CWE-493`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| 없음 | 매칭 없음 | 해당 없음 | 해당 없음 |

| 필요한 사실 | 소재 |
| --- | --- |
| `code_structure`: Definitions, dependencies and implementation structure | 소스 |

</details>

<details>
<summary>control-hardware · 하드웨어 전문 증거 요구 · 통제 입력: 실제 CVE 아님</summary>

- 입력 종류: **통제 입력: 실제 CVE 아님**
- 입력 CWE: `CWE-1252`
- 자료 없음: **분류 유보**
- 자료 있다고 가정: **분류 유보**
- 증거 요구: `undetermined` / 운영 필요: `False`

**입력 설명 원문**

> The CPU hardware is not configured for the required memory protection.

**CWE-1252: CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations**

- Pillar: `CWE-284`
- 기본값 → 이번 입력: `undetermined` → `undetermined`
- 매핑 Usage: `Allowed`
- 결정 이유: The detailed CWE name or explicit HDL platform scope requires hardware/design evidence outside the software analyzers.
- 기준: `hardware-design-evidence` / 거리 `0` / 경로 `CWE-1252`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| 없음 | 매칭 없음 | 해당 없음 | 해당 없음 |

| 필요한 사실 | 소재 |
| --- | --- |
| `hardware_design`: RTL, circuit/register design, hardware specification or physical measurement | 전문 자료 |

</details>

<details>
<summary>control-mapping-advisory · Discouraged도 기존 CWE를 유지하고 메모리 증거로 진행 · 통제 입력: 실제 CVE 아님</summary>

- 입력 종류: **통제 입력: 실제 CVE 아님**
- 입력 CWE: `CWE-119`
- 자료 없음: **③ 소스 분석 결과 대기**
- 자료 있다고 가정: **① 소스만**
- 증거 요구: `source_required` / 운영 필요: `False`

**입력 설명 원문**

> A buffer overflow occurs.

**CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer**

- Pillar: `CWE-664`
- 기본값 → 이번 입력: `required` → `required`
- 매핑 Usage: `Discouraged`
- 결정 이유: Memory/index/lifetime claims require implementation-level definitions and operation evidence. CVE evidence refines the mechanism using: explicit-memory-defect.
- 기준: `memory-safety` / 거리 `0` / 경로 `CWE-119`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| explicit-memory-defect | buffer overflow | [2, 17] | description |

| 필요한 사실 | 소재 |
| --- | --- |
| `memory_bounds_lifetime`: Bounds, object lifetime and affected operations | 소스 |

</details>

<details>
<summary>control-mixed-unknown · 여러 CWE 중 미확정 항목 보존 · 통제 입력: 실제 CVE 아님</summary>

- 입력 종류: **통제 입력: 실제 CVE 아님**
- 입력 CWE: `CWE-787, CWE-999999`
- 자료 없음: **분류 유보**
- 자료 있다고 가정: **분류 유보**
- 증거 요구: `undetermined` / 운영 필요: `False`

**입력 설명 원문**

> A remote buffer overflow occurs.

**CWE-787: Out-of-bounds Write**

- Pillar: `CWE-664`
- 기본값 → 이번 입력: `required` → `required`
- 매핑 Usage: `Allowed-with-Review`
- 결정 이유: Memory/index/lifetime claims require implementation-level definitions and operation evidence. CVE evidence refines the mechanism using: explicit-memory-defect.
- 기준: `memory-safety` / 거리 `1` / 경로 `CWE-787 → CWE-119`

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| explicit-memory-defect | buffer overflow | [9, 24] | description |

| 필요한 사실 | 소재 |
| --- | --- |
| `memory_bounds_lifetime`: Bounds, object lifetime and affected operations | 소스 |
| `actor_and_access_scope`: Actual actors, roles, accessible interfaces and operating scope | 운영 |

**CWE-999999: 알 수 없는 유형**

- Pillar: `없음`
- 기본값 → 이번 입력: `undetermined` → `undetermined`
- 매핑 Usage: `Unknown`
- 결정 이유: Missing/deprecated/unmapped CWE or bare Pillar; no detailed evidence requirement assigned.

| 보정 규칙 | 실제 매칭 인용 | 구간 [시작, 끝) | 원문 ID |
| --- | --- | --- | --- |
| 없음 | 매칭 없음 | 해당 없음 | 해당 없음 |

| 필요한 사실 | 소재 |
| --- | --- |
| 매핑/기준이 미확정이어서 필요한 사실도 확정하지 않음 | 미정 |

</details>

### 4.6 재현 파일과 검증 범위

- 전체 실행 입력과 출력: [criteria_results.json](../data/cwe_routing/v2/criteria_results.json)
- 재생성: `python tools/build_cwe_routing_results.py --as-of 2026-11-06`
- 정책 해시: `fc18c51198a485fa7ffffca35af3859d365162fe983f3af5ce9fd15a5fd0f672`
- 공식 XML 해시: `47165a9593def89c69b9ef50c34d99ac68db55df8373613e85e9cc9ceecefb1d`

문서 생성 시 모든 매칭 인용에 대해 `원문[시작:끝] == 인용`을 확인하고, 소스 자료 유무만 바꾸었을 때 증거 요구 자체가 바뀌지 않는지 검사한다. 이 검사는 문서·코드의 일치성 검사다. 독립 정답 라벨, 분류 정확도, Cohen's kappa, 소스 분석 성공률 또는 최종 VEX 정확도를 측정한 것은 아니다.

<!-- END GENERATED SECTION 4 RESULTS -->

## 5. 보고된 CWE 유지와 근거 부족 처리

원문 XML의 `Mapping_Notes.Usage`도 보존한다.

### 5.1 분석 경로를 정하는 기준과 참고 정보의 구분

| 항목 | 현재 처리 |
| --- | --- |
| CVE가 보고한 CWE ID | 입력과 결과에서 그대로 보존한다. 매핑 등급 때문에 자동 교체하지 않는다. |
| 세부 CWE의 정의·규칙·상속 경로 | 확인할 사실과 증거 소재를 결정하는 기본 기준으로 사용한다. |
| CVE 설명·권고의 구체적 구현/설정 메커니즘 | 허용된 보정 규칙에 따라 필요한 소스·운영 증거를 구체화한다. |
| `Mapping_Notes.Usage` | 출처 추적과 CWE 부여 지침 확인용으로만 남긴다. 실행 경로에 영향을 주지 않는다. |
| 필요한 소스 분석 결과가 없음 | 소스 요구를 유지하고 ③ 필수 소스 대기로 분기한다. |
| 필요한 증거 자체를 정할 근거가 없음 | 부족한 메커니즘·전문 자료를 명시하고 분류를 유보한다. |

### 5.2 매핑 지침은 분석 중단 사유가 아님

- `Allowed`, `Allowed-with-Review`, `Discouraged`, `Prohibited`: 모두 보고된 CWE를 유지하고 증거 요구와 CVE 메커니즘에 따라 분석을 진행한다.
- 이 값들은 CWE를 새로 부여할 때 참고하는 공식 지침이다. 이미 연결된 CWE의 분석을 차단하거나 교체를 요구하는 조건으로 사용하지 않는다.
- 주의 등급은 출처 추적용 참고 정보로 보존한다. 등급이 좋다는 이유만으로 경로의 정확성이 검증되는 것도 아니다.
- 포괄적인 CWE는 CVE 설명·권고 근거로 메커니즘을 보완한다. 그래도 필요한 증거를 정할 수 없으면 유보한다.
- Pillar만 보고됐거나, 알 수 없는/폐기된 CWE라면 유보한다.

### 5.3 같은 주의 등급이어도 달라지는 실행 결과

| 보고된 CWE | 참고 Usage | 증거에 따른 처리 |
| --- | --- | --- |
| CWE-119 | Discouraged | 메모리 경계·수명에 관한 소스 증거를 요구한다. 소스 결과가 없으면 ③, 있으면 운영 문맥에 따라 ① 또는 ②다. |
| CWE-263 | Discouraged | 배포된 계정·암호 만료 정책을 운영 기록으로 확인하는 ④ 경로다. |
| CWE-200 | Discouraged | 정보 노출이라는 유형만으로 원인이 특정되지 않는다. CVE·권고 근거로 보완하고, 그래도 필요한 증거가 불명확하면 유보한다. |

위 차이는 Usage 등급이 아니라 **각 CWE에서 확인해야 할 사실과 CVE 메커니즘의 차이**에서 나온다. 경로를 선택했다는 사실만으로 affected/not_affected를 부여하지 않는다.

여러 CWE 중 하나라도 해결되지 않으면 다른 하나의 소스 분석 결과가 그 문제를 가리지 못하게 전체 경로를 유보한다. 모두 분류 가능하면 필요한 소스·운영 증거의 합집합을 사용한다.

## 6. 네 가지 실행 경로

| 증거 요구 | 소스 분석 결과 | 운영 정보 필요 | 실행 경로 |
| --- | --- | --- | --- |
| 소스 필요 | 있음 | 없음 | ① 소스 분석만 |
| 소스 필요 | 있음 | 있음 | ② 소스 분석 + 운영 맥락 |
| 소스 필요 | 없음 | 어느 쪽이든 | ③ 필수 소스 분석 대기, under_investigation |
| 운영 정보로 수집 가능한 메커니즘 | 불필요 | 있음 | ④ 운영 맥락만 |
| 매핑/메커니즘/전문 자료 부족 | 무관 | 무관 | 분류 근거 부족, under_investigation |

현재 웹의 “source available”은 해당 검토 건에 **소스 분석 결과가 등록됐는가**를 나타낸다. 파일이 세상에 없다는 사실을 자동으로 조사한 결과가 아니다. 소스 결과가 등록돼도 컴파일 실패·파서 한계·불완전한 범위는 최종 판정의 한계로 남는다.

운영 답변에서 소스 분석으로 전환하는 별도 경로는 없다. 같은 CVE의 소스·운영 결과는 같은 검토 ID에 누적한다. 정책 버전이 바뀌면 과거 기록을 덮어쓰지 않고 새 검토를 시작한다.

## 7. 현재 분류표와 검증의 의미

기본 증거 유형은 944개 중 소스 필요 728개, 운영 기록으로 수집 가능한 유형 26개, 메커니즘·전문 자료를 더 요구하는 유형 190개다. 이는 CVE별 최종 경로 수나 정답률이 아니다. CVE 메커니즘 보정과 운영 증거 요구를 적용하면 실제 경로 수는 달라진다. 매핑 Usage 자체는 경로를 바꾸지 않는다.

243개는 해당 CWE 자체의 규칙·명칭·명시적 플랫폼 조건에서 결정했고, 701개는 명시적 세부 기준점에서 상속했다. 944개 모두에 설명 가능한 레코드가 있다는 뜻이지, 944개를 독립적인 전문가가 정답으로 인증했다는 뜻은 아니다.

검증은 다음을 분리한다.

1. **기계적 일관성:** 944개 일대일 대응, 10개 Pillar와 1,201개 다중 소속 보존, 실제 상속 경로, 원문/정책 해시, 결과 재현성.
2. **논리 회귀 검사:** 소스 유무로 요구 자체가 바뀌지 않음, 매핑 등급에 의한 차단 없음, 운영 유형 확장의 차단, Java 선언/암호 구현/하드웨어 예외, 같은 CWE의 설정/구현 사례, 여러 CWE에서 불명확한 항목 보존.
3. **의미 정확도:** 별도 독립 평가가 필요하다. 현재 독립 정답표, Cohen's kappa, 경로 분류 정확도를 확보했다고 주장하지 않는다.

또한 이 정책은 파서·CFG·taint 분석기나 운영 악용 조건 평가기의 기능을 새로 구현하지 않는다. 필요한 증거를 분류했다고 그 증거를 실제로 검증할 수 있게 된 것은 아니다.

## 8. 파일과 재현

- 규칙: `data/cwe_evidence_policy_v2.json`
- 공식 계층: `data/cwe_taxonomy/v5.0/catalog.json`
- 동일 원문 해시에 묶인 플랫폼/탐지 설명: `data/cwe_taxonomy/v5.0/evidence_metadata.json`
- 전체 표: `data/cwe_routing/v2/profiles.json`, `profiles.csv`, `summary.json`
- 전체 사람이 읽는 표: `docs/CWE_EVIDENCE_POLICY_V2.md`
- 실행 분류: `src/cwe_evidence_policy.py`, `src/vex_routing.py`

재생성: `python tools/build_cwe_evidence_policy.py`

공식 메타데이터 재수집: `python tools/cache_cwe_evidence_metadata.py`.
기존 고정 XML 해시와 다르면 거절하므로 최신 버전으로 조용히 바뀌지 않는다.

규칙 및 추출된 메타데이터의 `sha256`는 키 정렬·UTF-8·공백 제거를 고정한 JSON 의미 해시다. Git의 LF/CRLF 변환 때문에 같은 정책이 다른 정책으로 보이지 않게 한다. `taxonomy_xml_sha256`는 ZIP에서 꺼낸 공식 XML 바이트의 해시다.

공식 출처: [View 1000](https://cwe.mitre.org/data/definitions/1000.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html), [CWE XML](https://cwe.mitre.org/data/xml/cwec_v5.0.xml.zip).
