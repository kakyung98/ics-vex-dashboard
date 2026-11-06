# CWE 기반 증거 경로 기준의 현재 상태

정책 버전: `cwe-evidence-v2.2-unassigned` / 갱신: **2026-11-06 (KST)**.

## 1. 계획과 최종 증거 요구의 구분

CVE에 기록된 CWE는 변경하지 않는다. 공식 세부 CWE 944개 각각에 **무엇을 검토할지, 어떤 증거 수집 대안이 직접 기재되어 있는지, 어떤 자료를 먼저 요청할지**를 작성했다. 새 CWE를 부여하는 작업이 아니다.

증거 수집 계획과 해당 자산에서 소스가 필수인지·운영 정보만으로 충분한지에 대한 최종 결정은 구분한다. 공식 탐지 방법은 가능한 검토 방법을 설명하므로 그 존재를 필수 증거의 증명으로 바꾸지 않는다.

## 2. 항목별 계획을 지정한 기준

1. **검토할 속성:** 해당 CWE의 `Description` 원문을 그대로 연결한다. 인용 범위와 정의 URL을 기록한다.
2. **직접 근거:** 그 CWE 자체의 `Detection_Methods`만 사용한다. 부모·Pillar의 방법은 가져오지 않는다.
3. **자료 요청:** 기재된 방법을 소스/구현 자료, 컴파일 산출물, 실행 관찰, 설계, 형식 검증, 시뮬레이션 또는 추가 사례 근거로 번역한다. 방법 이름·원문 설명·효과성 표기는 원본 그대로 보존한다.
4. **복수 방법:** 여러 방법은 우선 대안 목록으로 취급한다. 정적·동적 방법이 모두 기재됐다고 둘 다 필수라고 판단하지 않는다.
5. **직접 방법이 없음:** CVE·벤더 권고·패치에서 메커니즘과 관련 기능을 먼저 확인하도록 지정한다. 임의의 소스/운영 기본값을 넣지 않는다.
6. **자산별 선택 조건:** 설치 제품/빌드, 해당 CVE 적용성, 메커니즘과 인터페이스, 수집할 자료와 확인할 주장 사이의 연결 및 한계를 기록해야 한다.

### 2.1 증거 경로의 의미

| 계획 경로 | 요청하는 자료 | 이 경로만으로 주장하지 않는 것 |
| --- | --- | --- |
| 소스 검토 | 실제 관련 소스·리비전·설정과 위치가 있는 분석 기록 | 해당 유형은 항상 소스만으로 판단 가능함 |
| 구현 자료 검토 | 직접 기재된 정적/화이트박스 방법에 맞는 구현 자료 | 일반 Static Analysis가 소스만을 뜻함 |
| 컴파일 산출물 검토 | 독립적으로 확보된 바이너리/바이트코드 검토 기록 | 소스 파서가 바이너리 분석을 수행함 |
| 실행 관찰 자료 검토 | 빌드·입력·조건·범위가 기록된 관찰/시험 보고서 | 운영자 Y/N 답변이 동적 분석을 대체함, 시험 통과가 안전을 증명함 |
| 설계/형식/시뮬레이션 검토 | 모델·설계·가정·속성·범위를 명시한 검토 자료 | 현재 백엔드가 이 검증을 모두 수행함 |
| CVE·벤더 근거 우선 확인 | 실제 메커니즘·기능·관찰 조건과 자료를 구체화할 권고/패치 | 유형명만으로 소스 필수나 운영 충분성을 확정함 |

항목별 JSON에는 `claim_to_examine`, `alternatives`, `artifacts_to_collect`, 원문 `evidence`, `next_action`, `case_selection_requirements`를 포함한다. 출처가 없는 상속 분류와 26개 운영 허용 목록은 다시 도입하지 않았다. 계획은 독립 정답이나 정확도 지표가 아니다.

## 3. 공식 CWE 자료와 현재 상태

<!-- BEGIN GENERATED SECTION 3 RESULTS -->

### 3.1 공식 계층과 증거 계획의 범위

고유 CWE 944개 각각에 증거 수집 계획을 작성했다. Pillar 소속을 모두 나열하면 중복 포함 1,201행이다. 각 계획은 해당 CWE 자체의 공식 정의와 Detection_Methods를 근거로 한다. 소속 관계에서 방법을 상속하지 않는다.

고유 944개 중 596개는 해당 항목의 공식 탐지 방법을 연결했고, 348개는 CVE·벤더 메커니즘 우선 확인을 지정했다. 이 계획 수는 정확도나 최종 필수 증거 확정 수가 아니다.

| Pillar | 공식 이름 | 세부 CWE 소속 수 | 증거 계획 기록 수 |
| --- | --- | ---: | ---: |
| CWE-284 | Improper Access Control | 182 | 182 |
| CWE-435 | Improper Interaction Between Multiple Correctly-Behaving Entities | 17 | 17 |
| CWE-664 | Improper Control of a Resource Through its Lifetime | 380 | 380 |
| CWE-682 | Incorrect Calculation | 13 | 13 |
| CWE-691 | Insufficient Control Flow Management | 86 | 86 |
| CWE-693 | Protection Mechanism Failure | 103 | 103 |
| CWE-697 | Incorrect Comparison | 21 | 21 |
| CWE-703 | Improper Check or Handling of Exceptional Conditions | 58 | 58 |
| CWE-707 | Improper Neutralization | 145 | 145 |
| CWE-710 | Improper Adherence to Coding Standards | 196 | 196 |

### 3.2 세부 CWE 원문과 소속 목록

각 행의 권장 경로는 증거 수집의 대안이다. 여러 경로가 있으면 모두 필수라는 뜻이 아니다. 공식 방법 미기재 항목도 CVE·벤더 메커니즘 우선 확인이라는 첫 단계를 지정했다. 개별 자산의 최종 소스/운영 필요 여부는 아직 확정하지 않는다. 정의 원문 전문·해당 방법의 원문 설명·자료 요청·출처는 JSON/CSV에 포함된다.

<details>
<summary>CWE-284 · Improper Access Control · 182개 소속</summary>

| 세부 CWE | 공식 이름 | 권장 증거 수집 경로 (대안) | 해당 CWE 자체의 근거 |
| --- | --- | --- | --- |
| [CWE-9](https://cwe.mitre.org/data/definitions/9.html) | J2EE Misconfiguration: Weak Access Permissions for EJB Methods | 구현 자료 검토 | Automated Static Analysis |
| [CWE-13](https://cwe.mitre.org/data/definitions/13.html) | ASP.NET Misconfiguration: Password in Configuration File | 구현 자료 검토 | Automated Static Analysis |
| [CWE-202](https://cwe.mitre.org/data/definitions/202.html) | Exposure of Sensitive Information Through Data Queries | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-219](https://cwe.mitre.org/data/definitions/219.html) | Storage of File with Sensitive Data Under Web Root | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-220](https://cwe.mitre.org/data/definitions/220.html) | Storage of File With Sensitive Data Under FTP Root | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | Execution with Unnecessary Privileges | CVE·벤더 근거로 검토 자료 구체화<br>컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Manual Analysis<br>Black Box<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-256](https://cwe.mitre.org/data/definitions/256.html) | Plaintext Storage of a Password | 구현 자료 검토 | Automated Static Analysis |
| [CWE-257](https://cwe.mitre.org/data/definitions/257.html) | Storing Passwords in a Recoverable Format | 구현 자료 검토 | Automated Static Analysis |
| [CWE-258](https://cwe.mitre.org/data/definitions/258.html) | Empty Password in Configuration File | 구현 자료 검토 | Automated Static Analysis |
| [CWE-259](https://cwe.mitre.org/data/definitions/259.html) | Use of Hard-coded Password | CVE·벤더 근거로 검토 자료 구체화<br>구현 자료 검토<br>실행 관찰 자료 검토 | Manual Analysis<br>Black Box<br>Automated Static Analysis |
| [CWE-260](https://cwe.mitre.org/data/definitions/260.html) | Password in Configuration File | 구현 자료 검토 | Automated Static Analysis |
| [CWE-261](https://cwe.mitre.org/data/definitions/261.html) | Weak Encoding for Password | 구현 자료 검토 | Automated Static Analysis |
| [CWE-262](https://cwe.mitre.org/data/definitions/262.html) | Not Using Password Aging | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-263](https://cwe.mitre.org/data/definitions/263.html) | Password Aging with Long Expiration | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-266](https://cwe.mitre.org/data/definitions/266.html) | Incorrect Privilege Assignment | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-267](https://cwe.mitre.org/data/definitions/267.html) | Privilege Defined With Unsafe Actions | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-268](https://cwe.mitre.org/data/definitions/268.html) | Privilege Chaining | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-269](https://cwe.mitre.org/data/definitions/269.html) | Improper Privilege Management | 구현 자료 검토 | Automated Static Analysis |
| [CWE-270](https://cwe.mitre.org/data/definitions/270.html) | Privilege Context Switching Error | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-271](https://cwe.mitre.org/data/definitions/271.html) | Privilege Dropping / Lowering Errors | 구현 자료 검토 | Automated Static Analysis |
| [CWE-272](https://cwe.mitre.org/data/definitions/272.html) | Least Privilege Violation | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-273](https://cwe.mitre.org/data/definitions/273.html) | Improper Check for Dropped Privileges | 구현 자료 검토 | Automated Static Analysis |
| [CWE-274](https://cwe.mitre.org/data/definitions/274.html) | Improper Handling of Insufficient Privileges | 구현 자료 검토 | Automated Static Analysis |
| [CWE-276](https://cwe.mitre.org/data/definitions/276.html) | Incorrect Default Permissions | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-277](https://cwe.mitre.org/data/definitions/277.html) | Insecure Inherited Permissions | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-278](https://cwe.mitre.org/data/definitions/278.html) | Insecure Preserved Inherited Permissions | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-279](https://cwe.mitre.org/data/definitions/279.html) | Incorrect Execution-Assigned Permissions | 구현 자료 검토 | Automated Static Analysis |
| [CWE-281](https://cwe.mitre.org/data/definitions/281.html) | Improper Preservation of Permissions | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-282](https://cwe.mitre.org/data/definitions/282.html) | Improper Ownership Management | 구현 자료 검토 | Automated Static Analysis |
| [CWE-283](https://cwe.mitre.org/data/definitions/283.html) | Unverified Ownership | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-285](https://cwe.mitre.org/data/definitions/285.html) | Improper Authorization | CVE·벤더 근거로 검토 자료 구체화<br>컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis<br>Automated Dynamic Analysis<br>Manual Analysis<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-286](https://cwe.mitre.org/data/definitions/286.html) | Incorrect User Management | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | Improper Authentication | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis<br>Manual Static Analysis<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-288](https://cwe.mitre.org/data/definitions/288.html) | Authentication Bypass Using an Alternate Path or Channel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-289](https://cwe.mitre.org/data/definitions/289.html) | Authentication Bypass by Alternate Name | 구현 자료 검토 | Automated Static Analysis |
| [CWE-290](https://cwe.mitre.org/data/definitions/290.html) | Authentication Bypass by Spoofing | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-291](https://cwe.mitre.org/data/definitions/291.html) | Reliance on IP Address for Authentication | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-293](https://cwe.mitre.org/data/definitions/293.html) | Using Referer Field for Authentication | 구현 자료 검토 | Automated Static Analysis |
| [CWE-294](https://cwe.mitre.org/data/definitions/294.html) | Authentication Bypass by Capture-replay | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | Improper Certificate Validation | 컴파일 산출물 검토<br>설계 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-296](https://cwe.mitre.org/data/definitions/296.html) | Improper Following of a Certificate's Chain of Trust | 구현 자료 검토 | Automated Static Analysis |
| [CWE-297](https://cwe.mitre.org/data/definitions/297.html) | Improper Validation of Certificate with Host Mismatch | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Dynamic Analysis with Manual Results Interpretation<br>Black Box |
| [CWE-298](https://cwe.mitre.org/data/definitions/298.html) | Improper Validation of Certificate Expiration | 구현 자료 검토 | Automated Static Analysis |
| [CWE-299](https://cwe.mitre.org/data/definitions/299.html) | Improper Check for Certificate Revocation | 구현 자료 검토 | Automated Static Analysis |
| [CWE-300](https://cwe.mitre.org/data/definitions/300.html) | Channel Accessible by Non-Endpoint | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Dynamic Analysis<br>Automated Dynamic Analysis<br>Automated Static Analysis |
| [CWE-301](https://cwe.mitre.org/data/definitions/301.html) | Reflection Attack in an Authentication Protocol | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-302](https://cwe.mitre.org/data/definitions/302.html) | Authentication Bypass by Assumed-Immutable Data | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-303](https://cwe.mitre.org/data/definitions/303.html) | Incorrect Implementation of Authentication Algorithm | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-304](https://cwe.mitre.org/data/definitions/304.html) | Missing Critical Step in Authentication | 구현 자료 검토 | Automated Static Analysis |
| [CWE-305](https://cwe.mitre.org/data/definitions/305.html) | Authentication Bypass by Primary Weakness | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-306](https://cwe.mitre.org/data/definitions/306.html) | Missing Authentication for Critical Functionality | CVE·벤더 근거로 검토 자료 구체화<br>컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Manual Analysis<br>Automated Static Analysis<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | Improper Restriction of Excessive Authentication Attempts | 설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-308](https://cwe.mitre.org/data/definitions/308.html) | Use of Single-factor Authentication | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-309](https://cwe.mitre.org/data/definitions/309.html) | Use of Password System for Primary Authentication | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | Use of Hard-coded Cryptographic Key | 구현 자료 검토 | Automated Static Analysis |
| [CWE-322](https://cwe.mitre.org/data/definitions/322.html) | Key Exchange without Entity Authentication | 구현 자료 검토 | Automated Static Analysis |
| [CWE-346](https://cwe.mitre.org/data/definitions/346.html) | Origin Validation Error | 구현 자료 검토 | Automated Static Analysis |
| [CWE-350](https://cwe.mitre.org/data/definitions/350.html) | Reliance on Reverse DNS Resolution for a Security-Critical Action | 구현 자료 검토 | Automated Static Analysis |
| [CWE-356](https://cwe.mitre.org/data/definitions/356.html) | Missing User Interaction for Potentially Unsafe Action | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-370](https://cwe.mitre.org/data/definitions/370.html) | Missing Check for Certificate Revocation after Initial Check | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-384](https://cwe.mitre.org/data/definitions/384.html) | Session Fixation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-419](https://cwe.mitre.org/data/definitions/419.html) | Unprotected Primary Channel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-420](https://cwe.mitre.org/data/definitions/420.html) | Unprotected Alternate Channel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-421](https://cwe.mitre.org/data/definitions/421.html) | Race Condition During Access to Alternate Channel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-422](https://cwe.mitre.org/data/definitions/422.html) | Unprotected Windows Messaging Channel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-424](https://cwe.mitre.org/data/definitions/424.html) | Improper Protection of Alternate Path | 구현 자료 검토 | Automated Static Analysis |
| [CWE-425](https://cwe.mitre.org/data/definitions/425.html) | Direct Request | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-433](https://cwe.mitre.org/data/definitions/433.html) | Unparsed Raw Web Content Delivery | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-493](https://cwe.mitre.org/data/definitions/493.html) | Critical Public Variable Without Final Modifier | 구현 자료 검토 | Automated Static Analysis |
| [CWE-500](https://cwe.mitre.org/data/definitions/500.html) | Public Static Field Not Marked Final | 구현 자료 검토 | Automated Static Analysis |
| [CWE-520](https://cwe.mitre.org/data/definitions/520.html) | .NET Misconfiguration: Use of Impersonation | 구현 자료 검토 | Automated Static Analysis |
| [CWE-521](https://cwe.mitre.org/data/definitions/521.html) | Weak Password Requirements | 구현 자료 검토 | Automated Static Analysis |
| [CWE-522](https://cwe.mitre.org/data/definitions/522.html) | Insufficiently Protected Credentials | 구현 자료 검토 | Automated Static Analysis |
| [CWE-523](https://cwe.mitre.org/data/definitions/523.html) | Unprotected Transport of Credentials | 구현 자료 검토 | Automated Static Analysis |
| [CWE-527](https://cwe.mitre.org/data/definitions/527.html) | Exposure of Version-Control Repository to an Unauthorized Control Sphere | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-528](https://cwe.mitre.org/data/definitions/528.html) | Exposure of Core Dump File to an Unauthorized Control Sphere | 구현 자료 검토 | Automated Static Analysis |
| [CWE-529](https://cwe.mitre.org/data/definitions/529.html) | Exposure of Access Control List Files to an Unauthorized Control Sphere | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-530](https://cwe.mitre.org/data/definitions/530.html) | Exposure of Backup File to an Unauthorized Control Sphere | 구현 자료 검토 | Automated Static Analysis |
| [CWE-539](https://cwe.mitre.org/data/definitions/539.html) | Use of Persistent Cookies Containing Sensitive Information | 구현 자료 검토 | Automated Static Analysis |
| [CWE-549](https://cwe.mitre.org/data/definitions/549.html) | Missing Password Field Masking | 구현 자료 검토 | Automated Static Analysis |
| [CWE-551](https://cwe.mitre.org/data/definitions/551.html) | Incorrect Behavior Order: Authorization Before Parsing and Canonicalization | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-552](https://cwe.mitre.org/data/definitions/552.html) | Files or Directories Accessible to External Parties | 구현 자료 검토 | Automated Static Analysis |
| [CWE-553](https://cwe.mitre.org/data/definitions/553.html) | Command Shell in Externally Accessible Directory | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-555](https://cwe.mitre.org/data/definitions/555.html) | J2EE Misconfiguration: Plaintext Password in Configuration File | 구현 자료 검토 | Automated Static Analysis |
| [CWE-556](https://cwe.mitre.org/data/definitions/556.html) | ASP.NET Misconfiguration: Use of Identity Impersonation | 구현 자료 검토 | Automated Static Analysis |
| [CWE-566](https://cwe.mitre.org/data/definitions/566.html) | Authorization Bypass Through User-Controlled SQL Primary Key | 구현 자료 검토 | Automated Static Analysis |
| [CWE-582](https://cwe.mitre.org/data/definitions/582.html) | Array Declared Public, Final, and Static | 구현 자료 검토 | Automated Static Analysis |
| [CWE-583](https://cwe.mitre.org/data/definitions/583.html) | finalize() Method Declared Public | 구현 자료 검토 | Automated Static Analysis |
| [CWE-593](https://cwe.mitre.org/data/definitions/593.html) | Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-599](https://cwe.mitre.org/data/definitions/599.html) | Missing Validation of OpenSSL Certificate | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-603](https://cwe.mitre.org/data/definitions/603.html) | Use of Client-Side Authentication | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-608](https://cwe.mitre.org/data/definitions/608.html) | Struts: Non-private Field in ActionForm Class | 구현 자료 검토 | Automated Static Analysis |
| [CWE-612](https://cwe.mitre.org/data/definitions/612.html) | Improper Authorization of Index Containing Sensitive Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-618](https://cwe.mitre.org/data/definitions/618.html) | Exposed Unsafe ActiveX Method | 구현 자료 검토 | Automated Static Analysis |
| [CWE-620](https://cwe.mitre.org/data/definitions/620.html) | Unverified Password Change | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-623](https://cwe.mitre.org/data/definitions/623.html) | Unsafe ActiveX Control Marked Safe For Scripting | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-638](https://cwe.mitre.org/data/definitions/638.html) | Not Using Complete Mediation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | Authorization Bypass Through User-Controlled Key | 구현 자료 검토 | Automated Static Analysis |
| [CWE-640](https://cwe.mitre.org/data/definitions/640.html) | Weak Password Recovery Mechanism for Forgotten Password | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-645](https://cwe.mitre.org/data/definitions/645.html) | Overly Restrictive Account Lockout Mechanism | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-647](https://cwe.mitre.org/data/definitions/647.html) | Use of Non-Canonical URL Paths for Authorization Decisions | 구현 자료 검토 | Automated Static Analysis |
| [CWE-648](https://cwe.mitre.org/data/definitions/648.html) | Incorrect Use of Privileged APIs | 구현 자료 검토 | Automated Static Analysis |
| [CWE-708](https://cwe.mitre.org/data/definitions/708.html) | Incorrect Ownership Assignment | CVE·벤더 근거로 검토 자료 구체화 | Automated Analysis |
| [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | Incorrect Permission Assignment for Critical Resource | CVE·벤더 근거로 검토 자료 구체화<br>컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis<br>Automated Dynamic Analysis<br>Manual Analysis<br>Manual Static Analysis<br>Manual Dynamic Analysis<br>Fuzzing<br>Black Box<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-749](https://cwe.mitre.org/data/definitions/749.html) | Exposed Dangerous Method or Function | 구현 자료 검토 | Automated Static Analysis |
| [CWE-766](https://cwe.mitre.org/data/definitions/766.html) | Critical Data Element Declared Public | 구현 자료 검토 | Automated Static Analysis |
| [CWE-782](https://cwe.mitre.org/data/definitions/782.html) | Exposed IOCTL with Insufficient Access Control | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | Use of Hard-coded Credentials | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Black Box<br>Automated Static Analysis<br>Manual Static Analysis<br>Manual Dynamic Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-804](https://cwe.mitre.org/data/definitions/804.html) | Guessable CAPTCHA | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-836](https://cwe.mitre.org/data/definitions/836.html) | Use of Password Hash Instead of Password for Authentication | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-842](https://cwe.mitre.org/data/definitions/842.html) | Placement of User into Incorrect Group | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | Missing Authorization | CVE·벤더 근거로 검토 자료 구체화<br>컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis<br>Automated Dynamic Analysis<br>Manual Analysis<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | Incorrect Authorization | CVE·벤더 근거로 검토 자료 구체화<br>컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis<br>Automated Dynamic Analysis<br>Manual Analysis<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-923](https://cwe.mitre.org/data/definitions/923.html) | Improper Restriction of Communication Channel to Intended Endpoints | 구현 자료 검토 | Automated Static Analysis |
| [CWE-925](https://cwe.mitre.org/data/definitions/925.html) | Improper Verification of Intent by Broadcast Receiver | 구현 자료 검토 | Automated Static Analysis |
| [CWE-926](https://cwe.mitre.org/data/definitions/926.html) | Improper Export of Android Application Components | 구현 자료 검토 | Automated Static Analysis |
| [CWE-927](https://cwe.mitre.org/data/definitions/927.html) | Use of Implicit Intent for Sensitive Communication | 구현 자료 검토 | Automated Static Analysis |
| [CWE-939](https://cwe.mitre.org/data/definitions/939.html) | Improper Authorization in Handler for Custom URL Scheme | 구현 자료 검토 | Automated Static Analysis |
| [CWE-940](https://cwe.mitre.org/data/definitions/940.html) | Improper Verification of Source of a Communication Channel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-941](https://cwe.mitre.org/data/definitions/941.html) | Incorrectly Specified Destination in a Communication Channel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | Permissive Cross-domain Security Policy with Untrusted Domains | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) | Sensitive Cookie Without 'HttpOnly' Flag | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1022](https://cwe.mitre.org/data/definitions/1022.html) | Use of Web Link to Untrusted Target with window.opener Access | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1191](https://cwe.mitre.org/data/definitions/1191.html) | On-Chip Debug and Test Interface With Improper Access Control | 실행 관찰 자료 검토 | Dynamic Analysis with Manual Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Fuzzing |
| [CWE-1220](https://cwe.mitre.org/data/definitions/1220.html) | Insufficient Granularity of Access Control | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1222](https://cwe.mitre.org/data/definitions/1222.html) | Insufficient Granularity of Address Regions Protected by Register Locks | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1224](https://cwe.mitre.org/data/definitions/1224.html) | Improper Restriction of Write-Once Bit Fields | CVE·벤더 근거로 검토 자료 구체화 | Automated Analysis |
| [CWE-1230](https://cwe.mitre.org/data/definitions/1230.html) | Exposure of Sensitive Information Through Metadata | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1231](https://cwe.mitre.org/data/definitions/1231.html) | Improper Prevention of Lock Bit Modification | CVE·벤더 근거로 검토 자료 구체화 | Manual Analysis |
| [CWE-1233](https://cwe.mitre.org/data/definitions/1233.html) | Security-Sensitive Hardware Controls with Missing Lock Bit Protection | CVE·벤더 근거로 검토 자료 구체화 | Manual Analysis |
| [CWE-1243](https://cwe.mitre.org/data/definitions/1243.html) | Sensitive Non-Volatile Information Not Protected During Debug | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1244](https://cwe.mitre.org/data/definitions/1244.html) | Internal Asset Exposed to Unsafe Debug Access Level or State | CVE·벤더 근거로 검토 자료 구체화 | Manual Analysis |
| [CWE-1252](https://cwe.mitre.org/data/definitions/1252.html) | CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1256](https://cwe.mitre.org/data/definitions/1256.html) | Improper Restriction of Software Interfaces to Hardware Features | CVE·벤더 근거로 검토 자료 구체화<br>실행 관찰 자료 검토 | Manual Analysis<br>Automated Dynamic Analysis |
| [CWE-1257](https://cwe.mitre.org/data/definitions/1257.html) | Improper Access Control Applied to Mirrored or Aliased Memory Regions | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1259](https://cwe.mitre.org/data/definitions/1259.html) | Improper Restriction of Security Token Assignment | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1260](https://cwe.mitre.org/data/definitions/1260.html) | Improper Handling of Overlap Between Protected Memory Ranges | CVE·벤더 근거로 검토 자료 구체화 | Manual Analysis |
| [CWE-1262](https://cwe.mitre.org/data/definitions/1262.html) | Improper Access Control for Register Interface | CVE·벤더 근거로 검토 자료 구체화<br>설계 자료 검토<br>형식 검증 자료 검토<br>실행 관찰 자료 검토<br>시뮬레이션 자료 검토 | Manual Analysis<br>Manual Analysis<br>Simulation / Emulation<br>Formal Verification<br>Automated Analysis<br>Architecture or Design Review<br>Fuzzing |
| [CWE-1263](https://cwe.mitre.org/data/definitions/1263.html) | Improper Physical Access Control | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1267](https://cwe.mitre.org/data/definitions/1267.html) | Policy Uses Obsolete Encoding | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1268](https://cwe.mitre.org/data/definitions/1268.html) | Policy Privileges are not Assigned Consistently Between Control and Data Agents | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1270](https://cwe.mitre.org/data/definitions/1270.html) | Generation of Incorrect Security Tokens | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1274](https://cwe.mitre.org/data/definitions/1274.html) | Improper Access Control for Volatile Memory Containing Boot Code | CVE·벤더 근거로 검토 자료 구체화 | Manual Analysis<br>Manual Analysis |
| [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) | Sensitive Cookie with Improper SameSite Attribute | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1276](https://cwe.mitre.org/data/definitions/1276.html) | Hardware Child Block Incorrectly Connected to Parent System | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1280](https://cwe.mitre.org/data/definitions/1280.html) | Access Control Check Implemented After Asset is Accessed | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1283](https://cwe.mitre.org/data/definitions/1283.html) | Mutable Attestation or Measurement Reporting Data | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1290](https://cwe.mitre.org/data/definitions/1290.html) | Incorrect Decoding of Security Identifiers | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1292](https://cwe.mitre.org/data/definitions/1292.html) | Incorrect Conversion of Security Identifiers | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1294](https://cwe.mitre.org/data/definitions/1294.html) | Insecure Security Identifier Mechanism | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1296](https://cwe.mitre.org/data/definitions/1296.html) | Incorrect Chaining or Granularity of Debug Components | 설계 자료 검토<br>실행 관찰 자료 검토 | Architecture or Design Review<br>Dynamic Analysis with Manual Results Interpretation |
| [CWE-1297](https://cwe.mitre.org/data/definitions/1297.html) | Unprotected Confidential Information on Device is Accessible by OSAT Vendors | 설계 자료 검토<br>실행 관찰 자료 검토 | Architecture or Design Review<br>Dynamic Analysis with Manual Results Interpretation |
| [CWE-1299](https://cwe.mitre.org/data/definitions/1299.html) | Missing Protection Mechanism for Alternate Hardware Interface | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1302](https://cwe.mitre.org/data/definitions/1302.html) | Missing Source Identifier in Entity Transactions on a System-On-Chip (SOC) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1304](https://cwe.mitre.org/data/definitions/1304.html) | Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1311](https://cwe.mitre.org/data/definitions/1311.html) | Improper Translation of Security Attributes by Fabric Bridge | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1312](https://cwe.mitre.org/data/definitions/1312.html) | Missing Protection for Mirrored Regions in On-Chip Fabric Firewall | 실행 관찰 자료 검토 | Manual Dynamic Analysis |
| [CWE-1313](https://cwe.mitre.org/data/definitions/1313.html) | Hardware Allows Activation of Test or Debug Logic at Runtime | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1314](https://cwe.mitre.org/data/definitions/1314.html) | Missing Write Protection for Parametric Data Values | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1315](https://cwe.mitre.org/data/definitions/1315.html) | Improper Setting of Bus Controlling Capability in Fabric End-point | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1316](https://cwe.mitre.org/data/definitions/1316.html) | Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Dynamic Analysis<br>Manual Static Analysis |
| [CWE-1317](https://cwe.mitre.org/data/definitions/1317.html) | Improper Access Control in Fabric Bridge | 형식 검증 자료 검토<br>시뮬레이션 자료 검토 | Simulation / Emulation<br>Formal Verification |
| [CWE-1320](https://cwe.mitre.org/data/definitions/1320.html) | Improper Protection for Outbound Error Messages and Alert Signals | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1323](https://cwe.mitre.org/data/definitions/1323.html) | Improper Management of Sensitive Trace Data | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1327](https://cwe.mitre.org/data/definitions/1327.html) | Binding to an Unrestricted IP Address | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1328](https://cwe.mitre.org/data/definitions/1328.html) | Security Version Number Mutable to Older Versions | 설계 자료 검토<br>실행 관찰 자료 검토 | Automated Dynamic Analysis<br>Architecture or Design Review |
| [CWE-1334](https://cwe.mitre.org/data/definitions/1334.html) | Unauthorized Error Injection Can Degrade Hardware Redundancy | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html) | Missing Origin Validation in WebSockets | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1390](https://cwe.mitre.org/data/definitions/1390.html) | Weak Authentication | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1391](https://cwe.mitre.org/data/definitions/1391.html) | Use of Weak Credentials | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1392](https://cwe.mitre.org/data/definitions/1392.html) | Use of Default Credentials | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1393](https://cwe.mitre.org/data/definitions/1393.html) | Use of Default Password | CVE·벤더 근거로 검토 자료 구체화 | Automated Analysis |
| [CWE-1394](https://cwe.mitre.org/data/definitions/1394.html) | Use of Default Cryptographic Key | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1462](https://cwe.mitre.org/data/definitions/1462.html) | Improper Session Management | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1463](https://cwe.mitre.org/data/definitions/1463.html) | Insufficient Session Timeout Value | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1464](https://cwe.mitre.org/data/definitions/1464.html) | Improper Session Invalidation | 실행 관찰 자료 검토 | Dynamic Analysis with Manual Results Interpretation |
| [CWE-1465](https://cwe.mitre.org/data/definitions/1465.html) | Improper Session Invalidation after User Logout | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1466](https://cwe.mitre.org/data/definitions/1466.html) | Improper Session Invalidation after Authentication Credential Change | 실행 관찰 자료 검토 | Dynamic Analysis with Manual Results Interpretation |
| [CWE-1467](https://cwe.mitre.org/data/definitions/1467.html) | Use of Singular Authentication Artifact for Multiple User Sessions | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1469](https://cwe.mitre.org/data/definitions/1469.html) | Improper Check for Credential Expiration | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1470](https://cwe.mitre.org/data/definitions/1470.html) | Improper External Identity Verification | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1472](https://cwe.mitre.org/data/definitions/1472.html) | Generation of Credential with Long Expiration | CVE·벤더 근거로 검토 자료 구체화<br>실행 관찰 자료 검토 | Automated Dynamic Analysis<br>Manual Analysis |

</details>

<details>
<summary>CWE-435 · Improper Interaction Between Multiple Correctly-Behaving Entities · 17개 소속</summary>

| 세부 CWE | 공식 이름 | 권장 증거 수집 경로 (대안) | 해당 CWE 자체의 근거 |
| --- | --- | --- | --- |
| [CWE-14](https://cwe.mitre.org/data/definitions/14.html) | Compiler Removal of Code to Clear Buffers | 구현 자료 검토<br>실행 관찰 자료 검토 | Black Box<br>White Box |
| [CWE-86](https://cwe.mitre.org/data/definitions/86.html) | Improper Neutralization of Invalid Characters in Identifiers in Web Pages | 구현 자료 검토 | Automated Static Analysis |
| [CWE-113](https://cwe.mitre.org/data/definitions/113.html) | Improper Neutralization of CRLF Sequences in HTTP Headers | 구현 자료 검토 | Automated Static Analysis |
| [CWE-115](https://cwe.mitre.org/data/definitions/115.html) | Misinterpretation of Input | 실행 관찰 자료 검토 | Fuzzing |
| [CWE-188](https://cwe.mitre.org/data/definitions/188.html) | Reliance on Data/Memory Layout | 실행 관찰 자료 검토 | Fuzzing<br>Automated Dynamic Analysis |
| [CWE-198](https://cwe.mitre.org/data/definitions/198.html) | Use of Incorrect Byte Ordering | 실행 관찰 자료 검토 | Black Box |
| [CWE-436](https://cwe.mitre.org/data/definitions/436.html) | Interpretation Conflict | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-437](https://cwe.mitre.org/data/definitions/437.html) | Incomplete Model of Endpoint Features | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-439](https://cwe.mitre.org/data/definitions/439.html) | Behavioral Change in New Version or Environment | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-444](https://cwe.mitre.org/data/definitions/444.html) | Inconsistent Interpretation of HTTP Requests | 구현 자료 검토 | Automated Static Analysis |
| [CWE-626](https://cwe.mitre.org/data/definitions/626.html) | Null Byte Interaction Error (Poison Null Byte) | 구현 자료 검토 | Automated Static Analysis |
| [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | Trusting HTTP Permission Methods on the Server Side | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-733](https://cwe.mitre.org/data/definitions/733.html) | Compiler Optimization Removal or Modification of Security-critical Code | 구현 자료 검토<br>실행 관찰 자료 검토 | Black Box<br>White Box |
| [CWE-1037](https://cwe.mitre.org/data/definitions/1037.html) | Processor Optimization Removal or Modification of Security-critical Code | 구현 자료 검토 | White Box |
| [CWE-1038](https://cwe.mitre.org/data/definitions/1038.html) | Insecure Automated Optimizations | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1461](https://cwe.mitre.org/data/definitions/1461.html) | Hardware Simulation / Synthesis Mismatch | CVE·벤더 근거로 검토 자료 구체화<br>형식 검증 자료 검토<br>실행 관찰 자료 검토<br>시뮬레이션 자료 검토<br>소스 검토 | Automated Static Analysis - Source Code<br>Manual Analysis<br>Formal Verification<br>Simulation / Emulation<br>Fuzzing |
| [CWE-1471](https://cwe.mitre.org/data/definitions/1471.html) | Insufficiently Controlled Parser Differential | 실행 관찰 자료 검토 | Automated Dynamic Analysis |

</details>

<details>
<summary>CWE-664 · Improper Control of a Resource Through its Lifetime · 380개 소속</summary>

| 세부 CWE | 공식 이름 | 권장 증거 수집 경로 (대안) | 해당 CWE 자체의 근거 |
| --- | --- | --- | --- |
| [CWE-8](https://cwe.mitre.org/data/definitions/8.html) | J2EE Misconfiguration: Entity Bean Declared Remote | 구현 자료 검토 | Automated Static Analysis |
| [CWE-13](https://cwe.mitre.org/data/definitions/13.html) | ASP.NET Misconfiguration: Password in Configuration File | 구현 자료 검토 | Automated Static Analysis |
| [CWE-15](https://cwe.mitre.org/data/definitions/15.html) | External Control of System or Configuration Setting | 구현 자료 검토 | Automated Static Analysis |
| [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | Improper Limitation of a Pathname to a Restricted Directory | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis<br>Manual Static Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-23](https://cwe.mitre.org/data/definitions/23.html) | Relative Path Traversal | 구현 자료 검토 | Automated Static Analysis |
| [CWE-24](https://cwe.mitre.org/data/definitions/24.html) | Path Traversal: '../filedir' | 구현 자료 검토 | Automated Static Analysis |
| [CWE-25](https://cwe.mitre.org/data/definitions/25.html) | Path Traversal: '/../filedir' | 구현 자료 검토 | Automated Static Analysis |
| [CWE-26](https://cwe.mitre.org/data/definitions/26.html) | Path Traversal: '/dir/../filename' | 구현 자료 검토 | Automated Static Analysis |
| [CWE-27](https://cwe.mitre.org/data/definitions/27.html) | Path Traversal: 'dir/../../filename' | 구현 자료 검토 | Automated Static Analysis |
| [CWE-28](https://cwe.mitre.org/data/definitions/28.html) | Path Traversal: '..\filedir' | 구현 자료 검토 | Automated Static Analysis |
| [CWE-29](https://cwe.mitre.org/data/definitions/29.html) | Path Traversal: '\..\filename' | 구현 자료 검토 | Automated Static Analysis |
| [CWE-30](https://cwe.mitre.org/data/definitions/30.html) | Path Traversal: '\dir\..\filename' | 구현 자료 검토 | Automated Static Analysis |
| [CWE-31](https://cwe.mitre.org/data/definitions/31.html) | Path Traversal: 'dir\..\..\filename' | 구현 자료 검토 | Automated Static Analysis |
| [CWE-32](https://cwe.mitre.org/data/definitions/32.html) | Path Traversal: '...' (Triple Dot) | 구현 자료 검토 | Automated Static Analysis |
| [CWE-33](https://cwe.mitre.org/data/definitions/33.html) | Path Traversal: '....' (Multiple Dot) | 구현 자료 검토 | Automated Static Analysis |
| [CWE-34](https://cwe.mitre.org/data/definitions/34.html) | Path Traversal: '....//' | 설계 자료 검토<br>소스 검토 | Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-35](https://cwe.mitre.org/data/definitions/35.html) | Path Traversal: '.../...//' | 구현 자료 검토 | Automated Static Analysis |
| [CWE-36](https://cwe.mitre.org/data/definitions/36.html) | Absolute Path Traversal | 구현 자료 검토 | Automated Static Analysis |
| [CWE-37](https://cwe.mitre.org/data/definitions/37.html) | Path Traversal: '/absolute/pathname/here' | 구현 자료 검토 | Automated Static Analysis |
| [CWE-38](https://cwe.mitre.org/data/definitions/38.html) | Path Traversal: '\absolute\pathname\here' | 구현 자료 검토 | Automated Static Analysis |
| [CWE-39](https://cwe.mitre.org/data/definitions/39.html) | Path Traversal: 'C:dirname' | 구현 자료 검토 | Automated Static Analysis |
| [CWE-40](https://cwe.mitre.org/data/definitions/40.html) | Path Traversal: '\\UNC\share\name\' (Windows UNC Share) | 구현 자료 검토 | Automated Static Analysis |
| [CWE-41](https://cwe.mitre.org/data/definitions/41.html) | Improper Resolution of Path Equivalence | 컴파일 산출물 검토<br>설계 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-42](https://cwe.mitre.org/data/definitions/42.html) | Path Equivalence: 'filename.' (Trailing Dot) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-43](https://cwe.mitre.org/data/definitions/43.html) | Path Equivalence: 'filename....' (Multiple Trailing Dot) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-44](https://cwe.mitre.org/data/definitions/44.html) | Path Equivalence: 'file.name' (Internal Dot) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-45](https://cwe.mitre.org/data/definitions/45.html) | Path Equivalence: 'file...name' (Multiple Internal Dot) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-46](https://cwe.mitre.org/data/definitions/46.html) | Path Equivalence: 'filename ' (Trailing Space) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-47](https://cwe.mitre.org/data/definitions/47.html) | Path Equivalence: ' filename' (Leading Space) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-48](https://cwe.mitre.org/data/definitions/48.html) | Path Equivalence: 'file name' (Internal Whitespace) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-49](https://cwe.mitre.org/data/definitions/49.html) | Path Equivalence: 'filename/' (Trailing Slash) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-50](https://cwe.mitre.org/data/definitions/50.html) | Path Equivalence: '//multiple/leading/slash' | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-51](https://cwe.mitre.org/data/definitions/51.html) | Path Equivalence: '/multiple//internal/slash' | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-52](https://cwe.mitre.org/data/definitions/52.html) | Path Equivalence: '/multiple/trailing/slash//' | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-53](https://cwe.mitre.org/data/definitions/53.html) | Path Equivalence: '\multiple\\internal\backslash' | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-54](https://cwe.mitre.org/data/definitions/54.html) | Path Equivalence: 'filedir\' (Trailing Backslash) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-55](https://cwe.mitre.org/data/definitions/55.html) | Path Equivalence: '/./' (Single Dot Directory) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-56](https://cwe.mitre.org/data/definitions/56.html) | Path Equivalence: 'filedir*' (Wildcard) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-57](https://cwe.mitre.org/data/definitions/57.html) | Path Equivalence: 'fakedir/../realdir/filename' | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-58](https://cwe.mitre.org/data/definitions/58.html) | Path Equivalence: Windows 8.3 Filename | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-59](https://cwe.mitre.org/data/definitions/59.html) | Improper Link Resolution Before File Access | 컴파일 산출물 검토<br>설계 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-61](https://cwe.mitre.org/data/definitions/61.html) | UNIX Symbolic Link (Symlink) Following | 구현 자료 검토 | Automated Static Analysis |
| [CWE-62](https://cwe.mitre.org/data/definitions/62.html) | UNIX Hard Link | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-64](https://cwe.mitre.org/data/definitions/64.html) | Windows Shortcut Following (.LNK) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-65](https://cwe.mitre.org/data/definitions/65.html) | Windows Hard Link | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-66](https://cwe.mitre.org/data/definitions/66.html) | Improper Handling of File Names that Identify Virtual Resources | 컴파일 산출물 검토<br>설계 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-67](https://cwe.mitre.org/data/definitions/67.html) | Improper Handling of Windows Device Names | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-69](https://cwe.mitre.org/data/definitions/69.html) | Improper Handling of Windows ::DATA Alternate Data Stream | CVE·벤더 근거로 검토 자료 구체화 | Automated Analysis |
| [CWE-72](https://cwe.mitre.org/data/definitions/72.html) | Improper Handling of Apple HFS+ Alternate Data Stream Path | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-73](https://cwe.mitre.org/data/definitions/73.html) | External Control of File Name or Path | 구현 자료 검토 | Automated Static Analysis |
| [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | Improper Control of Generation of Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | Improper Neutralization of Directives in Dynamically Evaluated Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-96](https://cwe.mitre.org/data/definitions/96.html) | Improper Neutralization of Directives in Statically Saved Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-97](https://cwe.mitre.org/data/definitions/97.html) | Improper Neutralization of Server-Side Includes (SSI) Within a Web Page | 구현 자료 검토 | Automated Static Analysis |
| [CWE-98](https://cwe.mitre.org/data/definitions/98.html) | Improper Control of Filename for Include/Require Statement in PHP Program | CVE·벤더 근거로 검토 자료 구체화<br>구현 자료 검토 | Manual Analysis<br>Automated Static Analysis |
| [CWE-114](https://cwe.mitre.org/data/definitions/114.html) | Process Control | 구현 자료 검토 | Automated Static Analysis |
| [CWE-118](https://cwe.mitre.org/data/definitions/118.html) | Incorrect Access of Indexable Resource | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-119](https://cwe.mitre.org/data/definitions/119.html) | Improper Restriction of Operations within the Bounds of a Memory Buffer | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis<br>Automated Dynamic Analysis<br>Automated Dynamic Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-120](https://cwe.mitre.org/data/definitions/120.html) | Buffer Copy without Checking Size of Input | CVE·벤더 근거로 검토 자료 구체화<br>컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis<br>Automated Dynamic Analysis<br>Manual Analysis<br>Automated Dynamic Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-121](https://cwe.mitre.org/data/definitions/121.html) | Stack-based Buffer Overflow | 구현 자료 검토<br>실행 관찰 자료 검토 | Fuzzing<br>Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-122](https://cwe.mitre.org/data/definitions/122.html) | Heap-based Buffer Overflow | 실행 관찰 자료 검토 | Fuzzing<br>Automated Dynamic Analysis |
| [CWE-123](https://cwe.mitre.org/data/definitions/123.html) | Write-what-where Condition | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-124](https://cwe.mitre.org/data/definitions/124.html) | Buffer Underwrite | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-125](https://cwe.mitre.org/data/definitions/125.html) | Out-of-bounds Read | 구현 자료 검토<br>실행 관찰 자료 검토 | Fuzzing<br>Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-126](https://cwe.mitre.org/data/definitions/126.html) | Buffer Over-read | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-127](https://cwe.mitre.org/data/definitions/127.html) | Buffer Under-read | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-134](https://cwe.mitre.org/data/definitions/134.html) | Use of Externally-Controlled Format String | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis<br>Black Box<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-178](https://cwe.mitre.org/data/definitions/178.html) | Improper Handling of Case Sensitivity | 구현 자료 검토 | Automated Static Analysis |
| [CWE-192](https://cwe.mitre.org/data/definitions/192.html) | Integer Coercion Error | 구현 자료 검토 | Automated Static Analysis |
| [CWE-194](https://cwe.mitre.org/data/definitions/194.html) | Unexpected Sign Extension | 구현 자료 검토 | Automated Static Analysis |
| [CWE-195](https://cwe.mitre.org/data/definitions/195.html) | Signed to Unsigned Conversion Error | 구현 자료 검토 | Automated Static Analysis |
| [CWE-196](https://cwe.mitre.org/data/definitions/196.html) | Unsigned to Signed Conversion Error | 구현 자료 검토 | Automated Static Analysis |
| [CWE-197](https://cwe.mitre.org/data/definitions/197.html) | Numeric Truncation Error | 구현 자료 검토<br>실행 관찰 자료 검토 | Fuzzing<br>Automated Static Analysis |
| [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | Exposure of Sensitive Information to an Unauthorized Actor | 컴파일 산출물 검토<br>설계 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-201](https://cwe.mitre.org/data/definitions/201.html) | Insertion of Sensitive Information Into Sent Data | 구현 자료 검토 | Automated Static Analysis |
| [CWE-203](https://cwe.mitre.org/data/definitions/203.html) | Observable Discrepancy | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-204](https://cwe.mitre.org/data/definitions/204.html) | Observable Response Discrepancy | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-205](https://cwe.mitre.org/data/definitions/205.html) | Observable Behavioral Discrepancy | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-206](https://cwe.mitre.org/data/definitions/206.html) | Observable Internal Behavioral Discrepancy | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-207](https://cwe.mitre.org/data/definitions/207.html) | Observable Behavioral Discrepancy With Equivalent Products | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-208](https://cwe.mitre.org/data/definitions/208.html) | Observable Timing Discrepancy | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | Generation of Error Message Containing Sensitive Information | CVE·벤더 근거로 검토 자료 구체화<br>구현 자료 검토<br>실행 관찰 자료 검토 | Manual Analysis<br>Automated Analysis<br>Automated Dynamic Analysis<br>Manual Dynamic Analysis<br>Automated Static Analysis |
| [CWE-210](https://cwe.mitre.org/data/definitions/210.html) | Self-generated Error Message Containing Sensitive Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-211](https://cwe.mitre.org/data/definitions/211.html) | Externally-Generated Error Message Containing Sensitive Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-212](https://cwe.mitre.org/data/definitions/212.html) | Improper Removal of Sensitive Information Before Storage or Transfer | 구현 자료 검토 | Automated Static Analysis |
| [CWE-213](https://cwe.mitre.org/data/definitions/213.html) | Exposure of Sensitive Information Due to Incompatible Policies | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-214](https://cwe.mitre.org/data/definitions/214.html) | Invocation of Process Using Visible Sensitive Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-215](https://cwe.mitre.org/data/definitions/215.html) | Insertion of Sensitive Information Into Debugging Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-219](https://cwe.mitre.org/data/definitions/219.html) | Storage of File with Sensitive Data Under Web Root | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-220](https://cwe.mitre.org/data/definitions/220.html) | Storage of File With Sensitive Data Under FTP Root | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-221](https://cwe.mitre.org/data/definitions/221.html) | Information Loss or Omission | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-222](https://cwe.mitre.org/data/definitions/222.html) | Truncation of Security-relevant Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-223](https://cwe.mitre.org/data/definitions/223.html) | Omission of Security-relevant Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-224](https://cwe.mitre.org/data/definitions/224.html) | Obscured Security-relevant Information by Alternate Name | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-226](https://cwe.mitre.org/data/definitions/226.html) | Sensitive Information in Resource Not Removed Before Reuse | CVE·벤더 근거로 검토 자료 구체화<br>구현 자료 검토 | Manual Analysis<br>Automated Static Analysis |
| [CWE-243](https://cwe.mitre.org/data/definitions/243.html) | Creation of chroot Jail Without Changing Working Directory | 구현 자료 검토 | Automated Static Analysis |
| [CWE-244](https://cwe.mitre.org/data/definitions/244.html) | Improper Clearing of Heap Memory Before Release | 구현 자료 검토 | Automated Static Analysis |
| [CWE-256](https://cwe.mitre.org/data/definitions/256.html) | Plaintext Storage of a Password | 구현 자료 검토 | Automated Static Analysis |
| [CWE-257](https://cwe.mitre.org/data/definitions/257.html) | Storing Passwords in a Recoverable Format | 구현 자료 검토 | Automated Static Analysis |
| [CWE-258](https://cwe.mitre.org/data/definitions/258.html) | Empty Password in Configuration File | 구현 자료 검토 | Automated Static Analysis |
| [CWE-260](https://cwe.mitre.org/data/definitions/260.html) | Password in Configuration File | 구현 자료 검토 | Automated Static Analysis |
| [CWE-261](https://cwe.mitre.org/data/definitions/261.html) | Weak Encoding for Password | 구현 자료 검토 | Automated Static Analysis |
| [CWE-262](https://cwe.mitre.org/data/definitions/262.html) | Not Using Password Aging | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-263](https://cwe.mitre.org/data/definitions/263.html) | Password Aging with Long Expiration | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-276](https://cwe.mitre.org/data/definitions/276.html) | Incorrect Default Permissions | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-277](https://cwe.mitre.org/data/definitions/277.html) | Insecure Inherited Permissions | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-278](https://cwe.mitre.org/data/definitions/278.html) | Insecure Preserved Inherited Permissions | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-279](https://cwe.mitre.org/data/definitions/279.html) | Incorrect Execution-Assigned Permissions | 구현 자료 검토 | Automated Static Analysis |
| [CWE-281](https://cwe.mitre.org/data/definitions/281.html) | Improper Preservation of Permissions | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-298](https://cwe.mitre.org/data/definitions/298.html) | Improper Validation of Certificate Expiration | 구현 자료 검토 | Automated Static Analysis |
| [CWE-299](https://cwe.mitre.org/data/definitions/299.html) | Improper Check for Certificate Revocation | 구현 자료 검토 | Automated Static Analysis |
| [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | Cleartext Storage of Sensitive Information | 구현 자료 검토 | Automated Static Analysis |
| [CWE-313](https://cwe.mitre.org/data/definitions/313.html) | Cleartext Storage in a File or on Disk | 구현 자료 검토 | Automated Static Analysis |
| [CWE-314](https://cwe.mitre.org/data/definitions/314.html) | Cleartext Storage in the Registry | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-315](https://cwe.mitre.org/data/definitions/315.html) | Cleartext Storage of Sensitive Information in a Cookie | 구현 자료 검토 | Automated Static Analysis |
| [CWE-316](https://cwe.mitre.org/data/definitions/316.html) | Cleartext Storage of Sensitive Information in Memory | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-317](https://cwe.mitre.org/data/definitions/317.html) | Cleartext Storage of Sensitive Information in GUI | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-318](https://cwe.mitre.org/data/definitions/318.html) | Cleartext Storage of Sensitive Information in Executable | 구현 자료 검토 | Automated Static Analysis |
| [CWE-324](https://cwe.mitre.org/data/definitions/324.html) | Use of a Key Past its Expiration Date | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-359](https://cwe.mitre.org/data/definitions/359.html) | Exposure of Private Personal Information to an Unauthorized Actor | 설계 자료 검토<br>구현 자료 검토 | Architecture or Design Review<br>Automated Static Analysis<br>Automated Static Analysis |
| [CWE-362](https://cwe.mitre.org/data/definitions/362.html) | Concurrent Execution using Shared Resource with Improper Synchronization | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Black Box<br>White Box<br>Automated Dynamic Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-363](https://cwe.mitre.org/data/definitions/363.html) | Race Condition Enabling Link Following | 구현 자료 검토 | Automated Static Analysis |
| [CWE-364](https://cwe.mitre.org/data/definitions/364.html) | Signal Handler Race Condition | 구현 자료 검토 | Automated Static Analysis |
| [CWE-366](https://cwe.mitre.org/data/definitions/366.html) | Race Condition within a Thread | 구현 자료 검토 | Automated Static Analysis |
| [CWE-367](https://cwe.mitre.org/data/definitions/367.html) | Time-of-check Time-of-use (TOCTOU) Race Condition | 구현 자료 검토 | Automated Static Analysis |
| [CWE-368](https://cwe.mitre.org/data/definitions/368.html) | Context Switching Race Condition | 구현 자료 검토 | Automated Static Analysis |
| [CWE-370](https://cwe.mitre.org/data/definitions/370.html) | Missing Check for Certificate Revocation after Initial Check | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-372](https://cwe.mitre.org/data/definitions/372.html) | Incomplete Internal State Distinction | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-374](https://cwe.mitre.org/data/definitions/374.html) | Passing Mutable Objects to an Untrusted Method | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-375](https://cwe.mitre.org/data/definitions/375.html) | Returning a Mutable Object to an Untrusted Caller | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-384](https://cwe.mitre.org/data/definitions/384.html) | Session Fixation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-385](https://cwe.mitre.org/data/definitions/385.html) | Covert Timing Channel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-386](https://cwe.mitre.org/data/definitions/386.html) | Symbolic Name not Mapping to Correct Object | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-396](https://cwe.mitre.org/data/definitions/396.html) | Declaration of Catch for Generic Exception | 구현 자료 검토 | Automated Static Analysis |
| [CWE-397](https://cwe.mitre.org/data/definitions/397.html) | Declaration of Throws for Generic Exception | 구현 자료 검토 | Automated Static Analysis |
| [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | Uncontrolled Resource Consumption | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis<br>Fuzzing |
| [CWE-401](https://cwe.mitre.org/data/definitions/401.html) | Missing Release of Memory after Effective Lifetime | 구현 자료 검토<br>실행 관찰 자료 검토 | Fuzzing<br>Automated Dynamic Analysis<br>Automated Static Analysis |
| [CWE-402](https://cwe.mitre.org/data/definitions/402.html) | Transmission of Private Resources into a New Sphere | 구현 자료 검토 | Automated Static Analysis |
| [CWE-403](https://cwe.mitre.org/data/definitions/403.html) | Exposure of File Descriptor to Unintended Control Sphere | 구현 자료 검토 | Automated Static Analysis |
| [CWE-404](https://cwe.mitre.org/data/definitions/404.html) | Improper Resource Shutdown or Release | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Dynamic Analysis<br>Manual Dynamic Analysis<br>Automated Static Analysis |
| [CWE-405](https://cwe.mitre.org/data/definitions/405.html) | Asymmetric Resource Consumption (Amplification) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-406](https://cwe.mitre.org/data/definitions/406.html) | Insufficient Control of Network Message Volume (Network Amplification) | 구현 자료 검토 | Automated Static Analysis |
| [CWE-407](https://cwe.mitre.org/data/definitions/407.html) | Inefficient Algorithmic Complexity | 구현 자료 검토 | Automated Static Analysis |
| [CWE-408](https://cwe.mitre.org/data/definitions/408.html) | Incorrect Behavior Order: Early Amplification | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-409](https://cwe.mitre.org/data/definitions/409.html) | Improper Handling of Highly Compressed Data (Data Amplification) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-410](https://cwe.mitre.org/data/definitions/410.html) | Insufficient Resource Pool | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-412](https://cwe.mitre.org/data/definitions/412.html) | Unrestricted Externally Accessible Lock | 구현 자료 검토 | White Box |
| [CWE-413](https://cwe.mitre.org/data/definitions/413.html) | Improper Resource Locking | 구현 자료 검토 | Automated Static Analysis |
| [CWE-414](https://cwe.mitre.org/data/definitions/414.html) | Missing Lock Check | 구현 자료 검토 | Automated Static Analysis |
| [CWE-415](https://cwe.mitre.org/data/definitions/415.html) | Double Free | 구현 자료 검토<br>실행 관찰 자료 검토 | Fuzzing<br>Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-416](https://cwe.mitre.org/data/definitions/416.html) | Use After Free | 구현 자료 검토<br>실행 관찰 자료 검토 | Fuzzing<br>Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-421](https://cwe.mitre.org/data/definitions/421.html) | Race Condition During Access to Alternate Channel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-426](https://cwe.mitre.org/data/definitions/426.html) | Untrusted Search Path | CVE·벤더 근거로 검토 자료 구체화<br>구현 자료 검토<br>실행 관찰 자료 검토 | Black Box<br>Automated Static Analysis<br>Manual Analysis |
| [CWE-427](https://cwe.mitre.org/data/definitions/427.html) | Uncontrolled Search Path Element | 구현 자료 검토 | Automated Static Analysis |
| [CWE-428](https://cwe.mitre.org/data/definitions/428.html) | Unquoted Search Path or Element | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-432](https://cwe.mitre.org/data/definitions/432.html) | Dangerous Signal Handler not Disabled During Sensitive Operations | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-433](https://cwe.mitre.org/data/definitions/433.html) | Unparsed Raw Web Content Delivery | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | Unrestricted Upload of File with Dangerous Type | 설계 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-441](https://cwe.mitre.org/data/definitions/441.html) | Unintended Proxy or Intermediary | 구현 자료 검토 | Automated Static Analysis |
| [CWE-451](https://cwe.mitre.org/data/definitions/451.html) | User Interface (UI) Misrepresentation of Critical Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-453](https://cwe.mitre.org/data/definitions/453.html) | Insecure Default Variable Initialization | 구현 자료 검토 | Automated Static Analysis |
| [CWE-454](https://cwe.mitre.org/data/definitions/454.html) | External Initialization of Trusted Variables or Data Stores | 구현 자료 검토 | Automated Static Analysis |
| [CWE-455](https://cwe.mitre.org/data/definitions/455.html) | Non-exit on Failed Initialization | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-456](https://cwe.mitre.org/data/definitions/456.html) | Missing Initialization of a Variable | 구현 자료 검토 | Automated Static Analysis |
| [CWE-457](https://cwe.mitre.org/data/definitions/457.html) | Use of Uninitialized Variable | 구현 자료 검토<br>실행 관찰 자료 검토 | Fuzzing<br>Automated Static Analysis |
| [CWE-459](https://cwe.mitre.org/data/definitions/459.html) | Incomplete Cleanup | 구현 자료 검토 | Automated Static Analysis |
| [CWE-460](https://cwe.mitre.org/data/definitions/460.html) | Improper Cleanup on Thrown Exception | 구현 자료 검토 | Automated Static Analysis |
| [CWE-466](https://cwe.mitre.org/data/definitions/466.html) | Return of Pointer Value Outside of Expected Range | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-470](https://cwe.mitre.org/data/definitions/470.html) | Use of Externally-Controlled Input to Select Classes or Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-471](https://cwe.mitre.org/data/definitions/471.html) | Modification of Assumed-Immutable Data (MAID) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-472](https://cwe.mitre.org/data/definitions/472.html) | External Control of Assumed-Immutable Web Parameter | 구현 자료 검토 | Automated Static Analysis |
| [CWE-473](https://cwe.mitre.org/data/definitions/473.html) | PHP External Variable Modification | 구현 자료 검토 | Automated Static Analysis |
| [CWE-479](https://cwe.mitre.org/data/definitions/479.html) | Signal Handler Use of a Non-reentrant Function | 구현 자료 검토 | Automated Static Analysis |
| [CWE-487](https://cwe.mitre.org/data/definitions/487.html) | Reliance on Package-level Scope | 구현 자료 검토 | Automated Static Analysis |
| [CWE-488](https://cwe.mitre.org/data/definitions/488.html) | Exposure of Data Element to Wrong Session | 구현 자료 검토 | Automated Static Analysis |
| [CWE-491](https://cwe.mitre.org/data/definitions/491.html) | Public cloneable() Method Without Final | 구현 자료 검토 | Automated Static Analysis |
| [CWE-492](https://cwe.mitre.org/data/definitions/492.html) | Use of Inner Class Containing Sensitive Data | 구현 자료 검토 | Automated Static Analysis |
| [CWE-493](https://cwe.mitre.org/data/definitions/493.html) | Critical Public Variable Without Final Modifier | 구현 자료 검토 | Automated Static Analysis |
| [CWE-494](https://cwe.mitre.org/data/definitions/494.html) | Download of Code Without Integrity Check | CVE·벤더 근거로 검토 자료 구체화<br>구현 자료 검토<br>실행 관찰 자료 검토 | Manual Analysis<br>Black Box<br>Automated Static Analysis |
| [CWE-495](https://cwe.mitre.org/data/definitions/495.html) | Private Data Structure Returned From A Public Method | 구현 자료 검토 | Automated Static Analysis |
| [CWE-496](https://cwe.mitre.org/data/definitions/496.html) | Public Data Assigned to Private Array-Typed Field | 구현 자료 검토 | Automated Static Analysis |
| [CWE-497](https://cwe.mitre.org/data/definitions/497.html) | Exposure of Sensitive System Information to an Unauthorized Control Sphere | 구현 자료 검토 | Automated Static Analysis |
| [CWE-498](https://cwe.mitre.org/data/definitions/498.html) | Cloneable Class Containing Sensitive Information | 구현 자료 검토 | Automated Static Analysis |
| [CWE-499](https://cwe.mitre.org/data/definitions/499.html) | Serializable Class Containing Sensitive Data | 구현 자료 검토 | Automated Static Analysis |
| [CWE-500](https://cwe.mitre.org/data/definitions/500.html) | Public Static Field Not Marked Final | 구현 자료 검토 | Automated Static Analysis |
| [CWE-501](https://cwe.mitre.org/data/definitions/501.html) | Trust Boundary Violation | 구현 자료 검토 | Automated Static Analysis |
| [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | Deserialization of Untrusted Data | 구현 자료 검토 | Automated Static Analysis |
| [CWE-514](https://cwe.mitre.org/data/definitions/514.html) | Covert Channel | 설계 자료 검토 | Architecture or Design Review |
| [CWE-515](https://cwe.mitre.org/data/definitions/515.html) | Covert Storage Channel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-522](https://cwe.mitre.org/data/definitions/522.html) | Insufficiently Protected Credentials | 구현 자료 검토 | Automated Static Analysis |
| [CWE-523](https://cwe.mitre.org/data/definitions/523.html) | Unprotected Transport of Credentials | 구현 자료 검토 | Automated Static Analysis |
| [CWE-524](https://cwe.mitre.org/data/definitions/524.html) | Use of Cache Containing Sensitive Information | 구현 자료 검토 | Automated Static Analysis |
| [CWE-525](https://cwe.mitre.org/data/definitions/525.html) | Use of Web Browser Cache Containing Sensitive Information | 구현 자료 검토 | Automated Static Analysis |
| [CWE-526](https://cwe.mitre.org/data/definitions/526.html) | Cleartext Storage of Sensitive Information in an Environment Variable | 구현 자료 검토 | Automated Static Analysis |
| [CWE-527](https://cwe.mitre.org/data/definitions/527.html) | Exposure of Version-Control Repository to an Unauthorized Control Sphere | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-528](https://cwe.mitre.org/data/definitions/528.html) | Exposure of Core Dump File to an Unauthorized Control Sphere | 구현 자료 검토 | Automated Static Analysis |
| [CWE-529](https://cwe.mitre.org/data/definitions/529.html) | Exposure of Access Control List Files to an Unauthorized Control Sphere | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-530](https://cwe.mitre.org/data/definitions/530.html) | Exposure of Backup File to an Unauthorized Control Sphere | 구현 자료 검토 | Automated Static Analysis |
| [CWE-531](https://cwe.mitre.org/data/definitions/531.html) | Inclusion of Sensitive Information in Test Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-532](https://cwe.mitre.org/data/definitions/532.html) | Insertion of Sensitive Information into Log File | 구현 자료 검토 | Automated Static Analysis |
| [CWE-535](https://cwe.mitre.org/data/definitions/535.html) | Exposure of Information Through Shell Error Message | 구현 자료 검토 | Automated Static Analysis |
| [CWE-536](https://cwe.mitre.org/data/definitions/536.html) | Servlet Runtime Error Message Containing Sensitive Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-537](https://cwe.mitre.org/data/definitions/537.html) | Java Runtime Error Message Containing Sensitive Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | Insertion of Sensitive Information into Externally-Accessible File or Directory | 구현 자료 검토 | Automated Static Analysis |
| [CWE-539](https://cwe.mitre.org/data/definitions/539.html) | Use of Persistent Cookies Containing Sensitive Information | 구현 자료 검토 | Automated Static Analysis |
| [CWE-540](https://cwe.mitre.org/data/definitions/540.html) | Inclusion of Sensitive Information in Source Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-541](https://cwe.mitre.org/data/definitions/541.html) | Inclusion of Sensitive Information in an Include File | 구현 자료 검토 | Automated Static Analysis |
| [CWE-543](https://cwe.mitre.org/data/definitions/543.html) | Use of Singleton Pattern Without Synchronization in a Multithreaded Context | 구현 자료 검토 | Automated Static Analysis |
| [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | Exposure of Information Through Directory Listing | 구현 자료 검토 | Automated Static Analysis |
| [CWE-549](https://cwe.mitre.org/data/definitions/549.html) | Missing Password Field Masking | 구현 자료 검토 | Automated Static Analysis |
| [CWE-550](https://cwe.mitre.org/data/definitions/550.html) | Server-generated Error Message Containing Sensitive Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-552](https://cwe.mitre.org/data/definitions/552.html) | Files or Directories Accessible to External Parties | 구현 자료 검토 | Automated Static Analysis |
| [CWE-553](https://cwe.mitre.org/data/definitions/553.html) | Command Shell in Externally Accessible Directory | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-555](https://cwe.mitre.org/data/definitions/555.html) | J2EE Misconfiguration: Plaintext Password in Configuration File | 구현 자료 검토 | Automated Static Analysis |
| [CWE-558](https://cwe.mitre.org/data/definitions/558.html) | Use of getlogin() in Multithreaded Application | 구현 자료 검토 | Automated Static Analysis |
| [CWE-565](https://cwe.mitre.org/data/definitions/565.html) | Reliance on Cookies without Validation and Integrity Checking | 구현 자료 검토 | Automated Static Analysis |
| [CWE-567](https://cwe.mitre.org/data/definitions/567.html) | Unsynchronized Access to Shared Data in a Multithreaded Context | 구현 자료 검토 | Automated Static Analysis |
| [CWE-568](https://cwe.mitre.org/data/definitions/568.html) | finalize() Method Without super.finalize() | 구현 자료 검토 | Automated Static Analysis |
| [CWE-572](https://cwe.mitre.org/data/definitions/572.html) | Call to Thread run() instead of start() | 구현 자료 검토 | Automated Static Analysis |
| [CWE-574](https://cwe.mitre.org/data/definitions/574.html) | EJB Bad Practices: Use of Synchronization Primitives | 구현 자료 검토 | Automated Static Analysis |
| [CWE-580](https://cwe.mitre.org/data/definitions/580.html) | clone() Method Without super.clone() | 구현 자료 검토 | Automated Static Analysis |
| [CWE-582](https://cwe.mitre.org/data/definitions/582.html) | Array Declared Public, Final, and Static | 구현 자료 검토 | Automated Static Analysis |
| [CWE-583](https://cwe.mitre.org/data/definitions/583.html) | finalize() Method Declared Public | 구현 자료 검토 | Automated Static Analysis |
| [CWE-588](https://cwe.mitre.org/data/definitions/588.html) | Attempt to Access Child of a Non-structure Pointer | 구현 자료 검토 | Automated Static Analysis |
| [CWE-590](https://cwe.mitre.org/data/definitions/590.html) | Free of Memory not on the Heap | 구현 자료 검토<br>실행 관찰 자료 검토 | Fuzzing<br>Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-591](https://cwe.mitre.org/data/definitions/591.html) | Sensitive Data Storage in Improperly Locked Memory | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-593](https://cwe.mitre.org/data/definitions/593.html) | Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-598](https://cwe.mitre.org/data/definitions/598.html) | Use of HTTP Request With Sensitive Query String | 구현 자료 검토 | Automated Static Analysis |
| [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | URL Redirection to Untrusted Site | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Manual Static Analysis<br>Automated Dynamic Analysis<br>Automated Static Analysis<br>Automated Static Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-605](https://cwe.mitre.org/data/definitions/605.html) | Multiple Binds to the Same Port | 구현 자료 검토 | Automated Static Analysis |
| [CWE-607](https://cwe.mitre.org/data/definitions/607.html) | Public Static Final Field References Mutable Object | 구현 자료 검토 | Automated Static Analysis |
| [CWE-608](https://cwe.mitre.org/data/definitions/608.html) | Struts: Non-private Field in ActionForm Class | 구현 자료 검토 | Automated Static Analysis |
| [CWE-609](https://cwe.mitre.org/data/definitions/609.html) | Double-Checked Locking | 구현 자료 검토 | Automated Static Analysis |
| [CWE-610](https://cwe.mitre.org/data/definitions/610.html) | Externally Controlled Reference to a Resource in Another Sphere | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | Improper Restriction of XML External Entity Reference | 구현 자료 검토 | Automated Static Analysis |
| [CWE-615](https://cwe.mitre.org/data/definitions/615.html) | Inclusion of Sensitive Information in Source Code Comments | 구현 자료 검토 | Automated Static Analysis |
| [CWE-619](https://cwe.mitre.org/data/definitions/619.html) | Dangling Database Cursor | 구현 자료 검토 | Automated Static Analysis |
| [CWE-621](https://cwe.mitre.org/data/definitions/621.html) | Variable Extraction Error | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-627](https://cwe.mitre.org/data/definitions/627.html) | Dynamic Variable Evaluation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-642](https://cwe.mitre.org/data/definitions/642.html) | External Control of Critical State Data | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Fuzzing<br>Manual Dynamic Analysis |
| [CWE-651](https://cwe.mitre.org/data/definitions/651.html) | Exposure of WSDL File Containing Sensitive Information | 구현 자료 검토 | Automated Static Analysis |
| [CWE-662](https://cwe.mitre.org/data/definitions/662.html) | Improper Synchronization | 구현 자료 검토 | Automated Static Analysis |
| [CWE-663](https://cwe.mitre.org/data/definitions/663.html) | Use of a Non-reentrant Function in a Concurrent Context | 구현 자료 검토 | Automated Static Analysis |
| [CWE-665](https://cwe.mitre.org/data/definitions/665.html) | Improper Initialization | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Dynamic Analysis<br>Manual Dynamic Analysis<br>Automated Static Analysis |
| [CWE-666](https://cwe.mitre.org/data/definitions/666.html) | Operation on Resource in Wrong Phase of Lifetime | 구현 자료 검토 | Automated Static Analysis |
| [CWE-667](https://cwe.mitre.org/data/definitions/667.html) | Improper Locking | 구현 자료 검토 | Automated Static Analysis |
| [CWE-668](https://cwe.mitre.org/data/definitions/668.html) | Exposure of Resource to Wrong Sphere | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-669](https://cwe.mitre.org/data/definitions/669.html) | Incorrect Resource Transfer Between Spheres | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-672](https://cwe.mitre.org/data/definitions/672.html) | Operation on a Resource after Expiration or Release | 구현 자료 검토 | Automated Static Analysis |
| [CWE-673](https://cwe.mitre.org/data/definitions/673.html) | External Influence of Sphere Definition | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-681](https://cwe.mitre.org/data/definitions/681.html) | Incorrect Conversion between Numeric Types | 구현 자료 검토 | Automated Static Analysis |
| [CWE-689](https://cwe.mitre.org/data/definitions/689.html) | Permission Race Condition During Resource Copy | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-704](https://cwe.mitre.org/data/definitions/704.html) | Incorrect Type Conversion or Cast | 실행 관찰 자료 검토 | Fuzzing |
| [CWE-706](https://cwe.mitre.org/data/definitions/706.html) | Use of Incorrectly-Resolved Name or Reference | 구현 자료 검토 | Automated Static Analysis |
| [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | Incorrect Permission Assignment for Critical Resource | CVE·벤더 근거로 검토 자료 구체화<br>컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis<br>Automated Dynamic Analysis<br>Manual Analysis<br>Manual Static Analysis<br>Manual Dynamic Analysis<br>Fuzzing<br>Black Box<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-761](https://cwe.mitre.org/data/definitions/761.html) | Free of Pointer not at Start of Buffer | 실행 관찰 자료 검토 | Automated Dynamic Analysis |
| [CWE-762](https://cwe.mitre.org/data/definitions/762.html) | Mismatched Memory Management Routines | 실행 관찰 자료 검토 | Automated Dynamic Analysis |
| [CWE-763](https://cwe.mitre.org/data/definitions/763.html) | Release of Invalid Pointer or Reference | 실행 관찰 자료 검토 | Fuzzing<br>Automated Dynamic Analysis |
| [CWE-764](https://cwe.mitre.org/data/definitions/764.html) | Multiple Locks of a Critical Resource | 구현 자료 검토 | Automated Static Analysis |
| [CWE-765](https://cwe.mitre.org/data/definitions/765.html) | Multiple Unlocks of a Critical Resource | 구현 자료 검토 | Automated Static Analysis |
| [CWE-766](https://cwe.mitre.org/data/definitions/766.html) | Critical Data Element Declared Public | 구현 자료 검토 | Automated Static Analysis |
| [CWE-767](https://cwe.mitre.org/data/definitions/767.html) | Access to Critical Private Variable via Public Method | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | Allocation of Resources Without Limits or Throttling | 구현 자료 검토<br>실행 관찰 자료 검토 | Manual Static Analysis<br>Fuzzing<br>Automated Dynamic Analysis<br>Automated Static Analysis |
| [CWE-771](https://cwe.mitre.org/data/definitions/771.html) | Missing Reference to Active Allocated Resource | 구현 자료 검토 | Automated Static Analysis |
| [CWE-772](https://cwe.mitre.org/data/definitions/772.html) | Missing Release of Resource after Effective Lifetime | 구현 자료 검토 | Automated Static Analysis |
| [CWE-773](https://cwe.mitre.org/data/definitions/773.html) | Missing Reference to Active File Descriptor or Handle | 구현 자료 검토 | Automated Static Analysis |
| [CWE-774](https://cwe.mitre.org/data/definitions/774.html) | Allocation of File Descriptors or Handles Without Limits or Throttling | 구현 자료 검토 | Automated Static Analysis |
| [CWE-775](https://cwe.mitre.org/data/definitions/775.html) | Missing Release of File Descriptor or Handle after Effective Lifetime | 구현 자료 검토 | Automated Static Analysis |
| [CWE-776](https://cwe.mitre.org/data/definitions/776.html) | Improper Restriction of Recursive Entity References in DTDs | 구현 자료 검토 | Automated Static Analysis |
| [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | Insufficient Logging | 구현 자료 검토 | Automated Static Analysis |
| [CWE-779](https://cwe.mitre.org/data/definitions/779.html) | Logging of Excessive Data | 구현 자료 검토 | Automated Static Analysis |
| [CWE-784](https://cwe.mitre.org/data/definitions/784.html) | Reliance on Cookies without Validation and Integrity Checking in a Security Decision | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-785](https://cwe.mitre.org/data/definitions/785.html) | Use of Path Manipulation Function without Maximum-sized Buffer | 구현 자료 검토 | Automated Static Analysis |
| [CWE-786](https://cwe.mitre.org/data/definitions/786.html) | Access of Memory Location Before Start of Buffer | 실행 관찰 자료 검토 | Fuzzing<br>Automated Dynamic Analysis |
| [CWE-787](https://cwe.mitre.org/data/definitions/787.html) | Out-of-bounds Write | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis<br>Automated Dynamic Analysis |
| [CWE-788](https://cwe.mitre.org/data/definitions/788.html) | Access of Memory Location After End of Buffer | 구현 자료 검토<br>실행 관찰 자료 검토 | Fuzzing<br>Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-789](https://cwe.mitre.org/data/definitions/789.html) | Memory Allocation with Excessive Size Value | 구현 자료 검토<br>실행 관찰 자료 검토 | Fuzzing<br>Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-805](https://cwe.mitre.org/data/definitions/805.html) | Buffer Access with Incorrect Length Value | CVE·벤더 근거로 검토 자료 구체화<br>구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis<br>Manual Analysis<br>Automated Dynamic Analysis |
| [CWE-806](https://cwe.mitre.org/data/definitions/806.html) | Buffer Access Using Size of Source Buffer | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-820](https://cwe.mitre.org/data/definitions/820.html) | Missing Synchronization | 구현 자료 검토 | Automated Static Analysis |
| [CWE-821](https://cwe.mitre.org/data/definitions/821.html) | Incorrect Synchronization | 구현 자료 검토 | Automated Static Analysis |
| [CWE-822](https://cwe.mitre.org/data/definitions/822.html) | Untrusted Pointer Dereference | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-823](https://cwe.mitre.org/data/definitions/823.html) | Use of Out-of-range Pointer Offset | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-824](https://cwe.mitre.org/data/definitions/824.html) | Access of Uninitialized Pointer | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-825](https://cwe.mitre.org/data/definitions/825.html) | Expired Pointer Dereference | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-826](https://cwe.mitre.org/data/definitions/826.html) | Premature Release of Resource During Expected Lifetime | 구현 자료 검토 | Automated Static Analysis |
| [CWE-827](https://cwe.mitre.org/data/definitions/827.html) | Improper Control of Document Type Definition | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-828](https://cwe.mitre.org/data/definitions/828.html) | Signal Handler with Functionality that is not Asynchronous-Safe | 구현 자료 검토 | Automated Static Analysis |
| [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | Inclusion of Functionality from Untrusted Control Sphere | 컴파일 산출물 검토<br>설계 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-830](https://cwe.mitre.org/data/definitions/830.html) | Inclusion of Web Functionality from an Untrusted Source | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-831](https://cwe.mitre.org/data/definitions/831.html) | Signal Handler Function Associated with Multiple Signals | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-832](https://cwe.mitre.org/data/definitions/832.html) | Unlock of a Resource that is not Locked | 구현 자료 검토 | Automated Static Analysis |
| [CWE-833](https://cwe.mitre.org/data/definitions/833.html) | Deadlock | 구현 자료 검토 | Automated Static Analysis |
| [CWE-843](https://cwe.mitre.org/data/definitions/843.html) | Access of Resource Using Incompatible Type | 구현 자료 검토 | Automated Static Analysis |
| [CWE-908](https://cwe.mitre.org/data/definitions/908.html) | Use of Uninitialized Resource | 구현 자료 검토 | Automated Static Analysis |
| [CWE-909](https://cwe.mitre.org/data/definitions/909.html) | Missing Initialization of Resource | 구현 자료 검토 | Automated Static Analysis |
| [CWE-910](https://cwe.mitre.org/data/definitions/910.html) | Use of Expired File Descriptor | 구현 자료 검토 | Automated Static Analysis |
| [CWE-911](https://cwe.mitre.org/data/definitions/911.html) | Improper Update of Reference Count | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-913](https://cwe.mitre.org/data/definitions/913.html) | Improper Control of Dynamically-Managed Code Resources | 실행 관찰 자료 검토 | Fuzzing |
| [CWE-914](https://cwe.mitre.org/data/definitions/914.html) | Improper Control of Dynamically-Identified Variables | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-915](https://cwe.mitre.org/data/definitions/915.html) | Improperly Controlled Modification of Dynamically-Determined Object Attributes | 구현 자료 검토 | Automated Static Analysis |
| [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | Server-Side Request Forgery | 구현 자료 검토 | Automated Static Analysis |
| [CWE-920](https://cwe.mitre.org/data/definitions/920.html) | Improper Restriction of Power Consumption | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-921](https://cwe.mitre.org/data/definitions/921.html) | Storage of Sensitive Data in a Mechanism without Access Control | 구현 자료 검토 | Automated Static Analysis |
| [CWE-922](https://cwe.mitre.org/data/definitions/922.html) | Insecure Storage of Sensitive Information | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) | Sensitive Cookie Without 'HttpOnly' Flag | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1007](https://cwe.mitre.org/data/definitions/1007.html) | Insufficient Visual Distinction of Homoglyphs Presented to User | 실행 관찰 자료 검토 | Manual Dynamic Analysis |
| [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | Improper Restriction of Rendered UI Layers or Frames | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1042](https://cwe.mitre.org/data/definitions/1042.html) | Static Member Data Element outside of a Singleton Class Element | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1046](https://cwe.mitre.org/data/definitions/1046.html) | Creation of Immutable Text Using String Concatenation | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1049](https://cwe.mitre.org/data/definitions/1049.html) | Excessive Data Query Operations in a Large Data Table | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1050](https://cwe.mitre.org/data/definitions/1050.html) | Excessive Platform Resource Consumption within a Loop | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1051](https://cwe.mitre.org/data/definitions/1051.html) | Initialization with Hard-Coded Network Resource Configuration Data | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1052](https://cwe.mitre.org/data/definitions/1052.html) | Excessive Use of Hard-Coded Literals in Initialization | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1058](https://cwe.mitre.org/data/definitions/1058.html) | Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1063](https://cwe.mitre.org/data/definitions/1063.html) | Creation of Class Instance within a Static Code Block | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1067](https://cwe.mitre.org/data/definitions/1067.html) | Excessive Execution of Sequential Searches of Data Resource | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1072](https://cwe.mitre.org/data/definitions/1072.html) | Data Resource Access without Use of Connection Pooling | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1073](https://cwe.mitre.org/data/definitions/1073.html) | Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1084](https://cwe.mitre.org/data/definitions/1084.html) | Invokable Control Element with Excessive File or Data Access Operations | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1088](https://cwe.mitre.org/data/definitions/1088.html) | Synchronous Access of Remote Resource without Timeout | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1089](https://cwe.mitre.org/data/definitions/1089.html) | Large Data Table with Excessive Number of Indices | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1091](https://cwe.mitre.org/data/definitions/1091.html) | Use of Object without Invoking Destructor Method | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1094](https://cwe.mitre.org/data/definitions/1094.html) | Excessive Index Range Scan for a Data Resource | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1096](https://cwe.mitre.org/data/definitions/1096.html) | Singleton Class Instance Creation without Proper Locking or Synchronization | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1176](https://cwe.mitre.org/data/definitions/1176.html) | Inefficient CPU Computation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) | Initialization of a Resource with an Insecure Default | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1189](https://cwe.mitre.org/data/definitions/1189.html) | Improper Isolation of Shared Resources on System-on-a-Chip (SoC) | 실행 관찰 자료 검토 | Automated Dynamic Analysis |
| [CWE-1221](https://cwe.mitre.org/data/definitions/1221.html) | Incorrect Register Defaults or Module Parameters | CVE·벤더 근거로 검토 자료 구체화 | Automated Analysis |
| [CWE-1223](https://cwe.mitre.org/data/definitions/1223.html) | Race Condition for Write-Once Attributes | CVE·벤더 근거로 검토 자료 구체화 | Automated Analysis |
| [CWE-1229](https://cwe.mitre.org/data/definitions/1229.html) | Creation of Emergent Resource | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1232](https://cwe.mitre.org/data/definitions/1232.html) | Improper Lock Behavior After Power State Transition | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1233](https://cwe.mitre.org/data/definitions/1233.html) | Security-Sensitive Hardware Controls with Missing Lock Bit Protection | CVE·벤더 근거로 검토 자료 구체화 | Manual Analysis |
| [CWE-1234](https://cwe.mitre.org/data/definitions/1234.html) | Hardware Internal or Debug Modes Allow Override of Locks | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1235](https://cwe.mitre.org/data/definitions/1235.html) | Incorrect Use of Autoboxing and Unboxing for Performance Critical Operations | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1239](https://cwe.mitre.org/data/definitions/1239.html) | Improper Zeroization of Hardware Register | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1246](https://cwe.mitre.org/data/definitions/1246.html) | Improper Write Handling in Limited-write Non-Volatile Memories | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1249](https://cwe.mitre.org/data/definitions/1249.html) | Application-Level Admin Tool with Inconsistent View of Underlying Operating System | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1250](https://cwe.mitre.org/data/definitions/1250.html) | Improper Preservation of Consistency Between Independent Representations of Shared State | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1251](https://cwe.mitre.org/data/definitions/1251.html) | Mirrored Regions with Different Values | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1254](https://cwe.mitre.org/data/definitions/1254.html) | Incorrect Comparison Logic Granularity | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1255](https://cwe.mitre.org/data/definitions/1255.html) | Comparison Logic is Vulnerable to Power Side-Channel Attacks | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1258](https://cwe.mitre.org/data/definitions/1258.html) | Exposure of Sensitive System Information Due to Uncleared Debug Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1264](https://cwe.mitre.org/data/definitions/1264.html) | Hardware Logic with Insecure De-Synchronization between Control and Data Channels | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1265](https://cwe.mitre.org/data/definitions/1265.html) | Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1266](https://cwe.mitre.org/data/definitions/1266.html) | Improper Scrubbing of Sensitive Data from Decommissioned Device | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1271](https://cwe.mitre.org/data/definitions/1271.html) | Uninitialized Value on Reset for Registers Holding Security Settings | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1272](https://cwe.mitre.org/data/definitions/1272.html) | Sensitive Information Uncleared Before Debug/Power State Transition | CVE·벤더 근거로 검토 자료 구체화 | Manual Analysis |
| [CWE-1273](https://cwe.mitre.org/data/definitions/1273.html) | Device Unlock Credential Sharing | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1277](https://cwe.mitre.org/data/definitions/1277.html) | Firmware Not Updateable | CVE·벤더 근거로 검토 자료 구체화<br>설계 자료 검토<br>실행 관찰 자료 검토 | Manual Analysis<br>Architecture or Design Review<br>Manual Dynamic Analysis |
| [CWE-1279](https://cwe.mitre.org/data/definitions/1279.html) | Cryptographic Operations are Run Before Supporting Units are Ready | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1282](https://cwe.mitre.org/data/definitions/1282.html) | Assumed-Immutable Data is Stored in Writable Memory | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1295](https://cwe.mitre.org/data/definitions/1295.html) | Debug Messages Revealing Unnecessary Information | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1298](https://cwe.mitre.org/data/definitions/1298.html) | Hardware Logic Contains Race Conditions | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1300](https://cwe.mitre.org/data/definitions/1300.html) | Improper Protection of Physical Side Channels | CVE·벤더 근거로 검토 자료 구체화 | Manual Analysis<br>Manual Analysis<br>Manual Analysis |
| [CWE-1301](https://cwe.mitre.org/data/definitions/1301.html) | Insufficient or Incomplete Data Removal within Hardware Component | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1303](https://cwe.mitre.org/data/definitions/1303.html) | Non-Transparent Sharing of Microarchitectural Resources | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1310](https://cwe.mitre.org/data/definitions/1310.html) | Missing Ability to Patch ROM Code | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) | Improperly Controlled Modification of Object Prototype Attributes | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1325](https://cwe.mitre.org/data/definitions/1325.html) | Improperly Controlled Sequential Memory Allocation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1329](https://cwe.mitre.org/data/definitions/1329.html) | Reliance on Component That is Not Updateable | 설계 자료 검토 | Architecture or Design Review |
| [CWE-1330](https://cwe.mitre.org/data/definitions/1330.html) | Remanent Data Readable after Memory Erase | 설계 자료 검토<br>실행 관찰 자료 검토 | Architecture or Design Review<br>Dynamic Analysis with Manual Results Interpretation |
| [CWE-1331](https://cwe.mitre.org/data/definitions/1331.html) | Improper Isolation of Shared Resources in Network On Chip (NoC) | CVE·벤더 근거로 검토 자료 구체화 | Manual Analysis |
| [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html) | Inefficient Regular Expression Complexity | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) | Improper Neutralization of Special Elements Used in a Template Engine | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1342](https://cwe.mitre.org/data/definitions/1342.html) | Information Exposure through Microarchitectural State after Transient Execution | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1386](https://cwe.mitre.org/data/definitions/1386.html) | Insecure Operation on Windows Junction / Mount Point | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1389](https://cwe.mitre.org/data/definitions/1389.html) | Incorrect Parsing of Numbers with Different Radices | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1419](https://cwe.mitre.org/data/definitions/1419.html) | Incorrect Initialization of Resource | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1420](https://cwe.mitre.org/data/definitions/1420.html) | Exposure of Sensitive Information during Transient Execution | CVE·벤더 근거로 검토 자료 구체화<br>구현 자료 검토<br>실행 관찰 자료 검토 | Manual Analysis<br>Fuzzing<br>Fuzzing<br>Automated Static Analysis<br>Automated Analysis |
| [CWE-1421](https://cwe.mitre.org/data/definitions/1421.html) | Exposure of Sensitive Information in Shared Microarchitectural Structures during Transient Execution | CVE·벤더 근거로 검토 자료 구체화<br>실행 관찰 자료 검토 | Manual Analysis<br>Automated Analysis<br>Automated Analysis<br>Fuzzing |
| [CWE-1422](https://cwe.mitre.org/data/definitions/1422.html) | Exposure of Sensitive Information caused by Incorrect Data Forwarding during Transient Execution | CVE·벤더 근거로 검토 자료 구체화<br>구현 자료 검토 | Automated Static Analysis<br>Manual Analysis<br>Automated Analysis |
| [CWE-1423](https://cwe.mitre.org/data/definitions/1423.html) | Exposure of Sensitive Information caused by Shared Microarchitectural Predictor State that Influences Transient Execution | CVE·벤더 근거로 검토 자료 구체화 | Manual Analysis<br>Automated Analysis<br>Automated Analysis |
| [CWE-1429](https://cwe.mitre.org/data/definitions/1429.html) | Missing Security-Relevant Feedback for Unexecuted Operations in Hardware Interface | 소스 검토 | Automated Static Analysis - Source Code<br>Manual Static Analysis - Source Code |
| [CWE-1431](https://cwe.mitre.org/data/definitions/1431.html) | Driving Intermediate Cryptographic State/Results to Hardware Module Outputs | CVE·벤더 근거로 검토 자료 구체화<br>형식 검증 자료 검토<br>시뮬레이션 자료 검토<br>소스 검토 | Automated Static Analysis - Source Code<br>Simulation / Emulation<br>Formal Verification<br>Manual Analysis |
| [CWE-1434](https://cwe.mitre.org/data/definitions/1434.html) | Insecure Setting of Generative AI/ML Model Inference Parameters | 실행 관찰 자료 검토 | Automated Dynamic Analysis<br>Manual Dynamic Analysis |
| [CWE-1472](https://cwe.mitre.org/data/definitions/1472.html) | Generation of Credential with Long Expiration | CVE·벤더 근거로 검토 자료 구체화<br>실행 관찰 자료 검토 | Automated Dynamic Analysis<br>Manual Analysis |
| [CWE-1473](https://cwe.mitre.org/data/definitions/1473.html) | Improper Expiration of Cached Data | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1474](https://cwe.mitre.org/data/definitions/1474.html) | Non-Equivalent Data Transformation | CVE·벤더 근거로 검토 자료 구체화<br>실행 관찰 자료 검토 | Manual Analysis<br>Automated Dynamic Analysis |
| [CWE-1475](https://cwe.mitre.org/data/definitions/1475.html) | Incomplete Data/State Propagation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |

</details>

<details>
<summary>CWE-682 · Incorrect Calculation · 13개 소속</summary>

| 세부 CWE | 공식 이름 | 권장 증거 수집 경로 (대안) | 해당 CWE 자체의 근거 |
| --- | --- | --- | --- |
| [CWE-128](https://cwe.mitre.org/data/definitions/128.html) | Wrap-around Error | 구현 자료 검토 | Automated Static Analysis |
| [CWE-131](https://cwe.mitre.org/data/definitions/131.html) | Incorrect Calculation of Buffer Size | CVE·벤더 근거로 검토 자료 구체화<br>컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis<br>Automated Dynamic Analysis<br>Automated Dynamic Analysis<br>Manual Analysis<br>Manual Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-135](https://cwe.mitre.org/data/definitions/135.html) | Incorrect Calculation of Multi-Byte String Length | 구현 자료 검토 | Automated Static Analysis |
| [CWE-190](https://cwe.mitre.org/data/definitions/190.html) | Integer Overflow or Wraparound | CVE·벤더 근거로 검토 자료 구체화<br>컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis<br>Black Box<br>Manual Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-191](https://cwe.mitre.org/data/definitions/191.html) | Integer Underflow (Wrap or Wraparound) | 구현 자료 검토 | Automated Static Analysis |
| [CWE-193](https://cwe.mitre.org/data/definitions/193.html) | Off-by-one Error | 구현 자료 검토 | Automated Static Analysis |
| [CWE-369](https://cwe.mitre.org/data/definitions/369.html) | Divide By Zero | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Fuzzing |
| [CWE-467](https://cwe.mitre.org/data/definitions/467.html) | Use of sizeof() on a Pointer Type | 구현 자료 검토 | Automated Static Analysis |
| [CWE-468](https://cwe.mitre.org/data/definitions/468.html) | Incorrect Pointer Scaling | 구현 자료 검토 | Automated Static Analysis |
| [CWE-469](https://cwe.mitre.org/data/definitions/469.html) | Use of Pointer Subtraction to Determine Size | 구현 자료 검토<br>실행 관찰 자료 검토 | Fuzzing<br>Automated Static Analysis |
| [CWE-680](https://cwe.mitre.org/data/definitions/680.html) | Integer Overflow to Buffer Overflow | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-1335](https://cwe.mitre.org/data/definitions/1335.html) | Incorrect Bitwise Shift of Integer | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1339](https://cwe.mitre.org/data/definitions/1339.html) | Insufficient Precision or Accuracy of a Real Number | 구현 자료 검토 | Automated Static Analysis |

</details>

<details>
<summary>CWE-691 · Insufficient Control Flow Management · 86개 소속</summary>

| 세부 CWE | 공식 이름 | 권장 증거 수집 경로 (대안) | 해당 CWE 자체의 근거 |
| --- | --- | --- | --- |
| [CWE-179](https://cwe.mitre.org/data/definitions/179.html) | Incorrect Behavior Order: Early Validation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-180](https://cwe.mitre.org/data/definitions/180.html) | Incorrect Behavior Order: Validate Before Canonicalize | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-181](https://cwe.mitre.org/data/definitions/181.html) | Incorrect Behavior Order: Validate Before Filter | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-248](https://cwe.mitre.org/data/definitions/248.html) | Uncaught Exception | 구현 자료 검토 | Automated Static Analysis |
| [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | Improper Restriction of Excessive Authentication Attempts | 설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-362](https://cwe.mitre.org/data/definitions/362.html) | Concurrent Execution using Shared Resource with Improper Synchronization | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Black Box<br>White Box<br>Automated Dynamic Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-363](https://cwe.mitre.org/data/definitions/363.html) | Race Condition Enabling Link Following | 구현 자료 검토 | Automated Static Analysis |
| [CWE-364](https://cwe.mitre.org/data/definitions/364.html) | Signal Handler Race Condition | 구현 자료 검토 | Automated Static Analysis |
| [CWE-366](https://cwe.mitre.org/data/definitions/366.html) | Race Condition within a Thread | 구현 자료 검토 | Automated Static Analysis |
| [CWE-367](https://cwe.mitre.org/data/definitions/367.html) | Time-of-check Time-of-use (TOCTOU) Race Condition | 구현 자료 검토 | Automated Static Analysis |
| [CWE-368](https://cwe.mitre.org/data/definitions/368.html) | Context Switching Race Condition | 구현 자료 검토 | Automated Static Analysis |
| [CWE-382](https://cwe.mitre.org/data/definitions/382.html) | J2EE Bad Practices: Use of System.exit() | 구현 자료 검토 | Automated Static Analysis |
| [CWE-395](https://cwe.mitre.org/data/definitions/395.html) | Use of NullPointerException Catch to Detect NULL Pointer Dereference | 컴파일 산출물 검토<br>설계 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-396](https://cwe.mitre.org/data/definitions/396.html) | Declaration of Catch for Generic Exception | 구현 자료 검토 | Automated Static Analysis |
| [CWE-397](https://cwe.mitre.org/data/definitions/397.html) | Declaration of Throws for Generic Exception | 구현 자료 검토 | Automated Static Analysis |
| [CWE-408](https://cwe.mitre.org/data/definitions/408.html) | Incorrect Behavior Order: Early Amplification | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-412](https://cwe.mitre.org/data/definitions/412.html) | Unrestricted Externally Accessible Lock | 구현 자료 검토 | White Box |
| [CWE-413](https://cwe.mitre.org/data/definitions/413.html) | Improper Resource Locking | 구현 자료 검토 | Automated Static Analysis |
| [CWE-414](https://cwe.mitre.org/data/definitions/414.html) | Missing Lock Check | 구현 자료 검토 | Automated Static Analysis |
| [CWE-421](https://cwe.mitre.org/data/definitions/421.html) | Race Condition During Access to Alternate Channel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-430](https://cwe.mitre.org/data/definitions/430.html) | Deployment of Wrong Handler | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-431](https://cwe.mitre.org/data/definitions/431.html) | Missing Handler | 구현 자료 검토 | Automated Static Analysis |
| [CWE-432](https://cwe.mitre.org/data/definitions/432.html) | Dangerous Signal Handler not Disabled During Sensitive Operations | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-455](https://cwe.mitre.org/data/definitions/455.html) | Non-exit on Failed Initialization | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-479](https://cwe.mitre.org/data/definitions/479.html) | Signal Handler Use of a Non-reentrant Function | 구현 자료 검토 | Automated Static Analysis |
| [CWE-480](https://cwe.mitre.org/data/definitions/480.html) | Use of Incorrect Operator | 구현 자료 검토 | Automated Static Analysis<br>Manual Static Analysis |
| [CWE-481](https://cwe.mitre.org/data/definitions/481.html) | Assigning instead of Comparing | 구현 자료 검토<br>소스 검토 | Automated Static Analysis<br>Automated Static Analysis - Source Code |
| [CWE-482](https://cwe.mitre.org/data/definitions/482.html) | Comparing instead of Assigning | 구현 자료 검토<br>소스 검토 | Automated Static Analysis<br>Automated Static Analysis - Source Code |
| [CWE-483](https://cwe.mitre.org/data/definitions/483.html) | Incorrect Block Delimitation | 구현 자료 검토 | Automated Static Analysis |
| [CWE-484](https://cwe.mitre.org/data/definitions/484.html) | Omitted Break Statement in Switch | 구현 자료 검토<br>실행 관찰 자료 검토 | White Box<br>Black Box<br>Automated Static Analysis |
| [CWE-543](https://cwe.mitre.org/data/definitions/543.html) | Use of Singleton Pattern Without Synchronization in a Multithreaded Context | 구현 자료 검토 | Automated Static Analysis |
| [CWE-551](https://cwe.mitre.org/data/definitions/551.html) | Incorrect Behavior Order: Authorization Before Parsing and Canonicalization | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-558](https://cwe.mitre.org/data/definitions/558.html) | Use of getlogin() in Multithreaded Application | 구현 자료 검토 | Automated Static Analysis |
| [CWE-567](https://cwe.mitre.org/data/definitions/567.html) | Unsynchronized Access to Shared Data in a Multithreaded Context | 구현 자료 검토 | Automated Static Analysis |
| [CWE-572](https://cwe.mitre.org/data/definitions/572.html) | Call to Thread run() instead of start() | 구현 자료 검토 | Automated Static Analysis |
| [CWE-574](https://cwe.mitre.org/data/definitions/574.html) | EJB Bad Practices: Use of Synchronization Primitives | 구현 자료 검토 | Automated Static Analysis |
| [CWE-584](https://cwe.mitre.org/data/definitions/584.html) | Return Inside Finally Block | 구현 자료 검토 | Automated Static Analysis |
| [CWE-591](https://cwe.mitre.org/data/definitions/591.html) | Sensitive Data Storage in Improperly Locked Memory | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-597](https://cwe.mitre.org/data/definitions/597.html) | Use of Wrong Operator in String Comparison | 구현 자료 검토 | Automated Static Analysis |
| [CWE-600](https://cwe.mitre.org/data/definitions/600.html) | Uncaught Exception in Servlet | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-609](https://cwe.mitre.org/data/definitions/609.html) | Double-Checked Locking | 구현 자료 검토 | Automated Static Analysis |
| [CWE-617](https://cwe.mitre.org/data/definitions/617.html) | Reachable Assertion | 구현 자료 검토 | Automated Static Analysis |
| [CWE-647](https://cwe.mitre.org/data/definitions/647.html) | Use of Non-Canonical URL Paths for Authorization Decisions | 구현 자료 검토 | Automated Static Analysis |
| [CWE-662](https://cwe.mitre.org/data/definitions/662.html) | Improper Synchronization | 구현 자료 검토 | Automated Static Analysis |
| [CWE-663](https://cwe.mitre.org/data/definitions/663.html) | Use of a Non-reentrant Function in a Concurrent Context | 구현 자료 검토 | Automated Static Analysis |
| [CWE-667](https://cwe.mitre.org/data/definitions/667.html) | Improper Locking | 구현 자료 검토 | Automated Static Analysis |
| [CWE-670](https://cwe.mitre.org/data/definitions/670.html) | Always-Incorrect Control Flow Implementation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-674](https://cwe.mitre.org/data/definitions/674.html) | Uncontrolled Recursion | 구현 자료 검토 | Automated Static Analysis |
| [CWE-689](https://cwe.mitre.org/data/definitions/689.html) | Permission Race Condition During Resource Copy | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-696](https://cwe.mitre.org/data/definitions/696.html) | Incorrect Behavior Order | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-698](https://cwe.mitre.org/data/definitions/698.html) | Execution After Redirect (EAR) | 실행 관찰 자료 검토 | Black Box |
| [CWE-705](https://cwe.mitre.org/data/definitions/705.html) | Incorrect Control Flow Scoping | 구현 자료 검토 | Automated Static Analysis |
| [CWE-764](https://cwe.mitre.org/data/definitions/764.html) | Multiple Locks of a Critical Resource | 구현 자료 검토 | Automated Static Analysis |
| [CWE-765](https://cwe.mitre.org/data/definitions/765.html) | Multiple Unlocks of a Critical Resource | 구현 자료 검토 | Automated Static Analysis |
| [CWE-768](https://cwe.mitre.org/data/definitions/768.html) | Incorrect Short Circuit Evaluation | 구현 자료 검토 | Automated Static Analysis |
| [CWE-776](https://cwe.mitre.org/data/definitions/776.html) | Improper Restriction of Recursive Entity References in DTDs | 구현 자료 검토 | Automated Static Analysis |
| [CWE-783](https://cwe.mitre.org/data/definitions/783.html) | Operator Precedence Logic Error | 구현 자료 검토 | Automated Static Analysis |
| [CWE-799](https://cwe.mitre.org/data/definitions/799.html) | Improper Control of Interaction Frequency | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-820](https://cwe.mitre.org/data/definitions/820.html) | Missing Synchronization | 구현 자료 검토 | Automated Static Analysis |
| [CWE-821](https://cwe.mitre.org/data/definitions/821.html) | Incorrect Synchronization | 구현 자료 검토 | Automated Static Analysis |
| [CWE-828](https://cwe.mitre.org/data/definitions/828.html) | Signal Handler with Functionality that is not Asynchronous-Safe | 구현 자료 검토 | Automated Static Analysis |
| [CWE-831](https://cwe.mitre.org/data/definitions/831.html) | Signal Handler Function Associated with Multiple Signals | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-832](https://cwe.mitre.org/data/definitions/832.html) | Unlock of a Resource that is not Locked | 구현 자료 검토 | Automated Static Analysis |
| [CWE-833](https://cwe.mitre.org/data/definitions/833.html) | Deadlock | 구현 자료 검토 | Automated Static Analysis |
| [CWE-834](https://cwe.mitre.org/data/definitions/834.html) | Excessive Iteration | 설계 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-835](https://cwe.mitre.org/data/definitions/835.html) | Loop with Unreachable Exit Condition | 구현 자료 검토 | Automated Static Analysis |
| [CWE-837](https://cwe.mitre.org/data/definitions/837.html) | Improper Enforcement of a Single, Unique Action | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-841](https://cwe.mitre.org/data/definitions/841.html) | Improper Enforcement of Behavioral Workflow | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1058](https://cwe.mitre.org/data/definitions/1058.html) | Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1077](https://cwe.mitre.org/data/definitions/1077.html) | Floating Point Comparison with Incorrect Operator | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1088](https://cwe.mitre.org/data/definitions/1088.html) | Synchronous Access of Remote Resource without Timeout | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1096](https://cwe.mitre.org/data/definitions/1096.html) | Singleton Class Instance Creation without Proper Locking or Synchronization | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1190](https://cwe.mitre.org/data/definitions/1190.html) | DMA Device Enabled Too Early in Boot Phase | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1193](https://cwe.mitre.org/data/definitions/1193.html) | Power-On of Untrusted Execution Core Before Enabling Fabric Access Control | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1223](https://cwe.mitre.org/data/definitions/1223.html) | Race Condition for Write-Once Attributes | CVE·벤더 근거로 검토 자료 구체화 | Automated Analysis |
| [CWE-1232](https://cwe.mitre.org/data/definitions/1232.html) | Improper Lock Behavior After Power State Transition | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1233](https://cwe.mitre.org/data/definitions/1233.html) | Security-Sensitive Hardware Controls with Missing Lock Bit Protection | CVE·벤더 근거로 검토 자료 구체화 | Manual Analysis |
| [CWE-1234](https://cwe.mitre.org/data/definitions/1234.html) | Hardware Internal or Debug Modes Allow Override of Locks | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1264](https://cwe.mitre.org/data/definitions/1264.html) | Hardware Logic with Insecure De-Synchronization between Control and Data Channels | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1265](https://cwe.mitre.org/data/definitions/1265.html) | Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1279](https://cwe.mitre.org/data/definitions/1279.html) | Cryptographic Operations are Run Before Supporting Units are Ready | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1280](https://cwe.mitre.org/data/definitions/1280.html) | Access Control Check Implemented After Asset is Accessed | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1281](https://cwe.mitre.org/data/definitions/1281.html) | Sequence of Processor Instructions Leads to Unexpected Behavior | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1298](https://cwe.mitre.org/data/definitions/1298.html) | Hardware Logic Contains Race Conditions | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1322](https://cwe.mitre.org/data/definitions/1322.html) | Use of Blocking Code in Single-threaded, Non-blocking Context | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1476](https://cwe.mitre.org/data/definitions/1476.html) | Improper Request Propagation before Data Reception in Write Transactions in a Bus Architecture | 설계 자료 검토<br>형식 검증 자료 검토<br>시뮬레이션 자료 검토 | Architecture or Design Review<br>Formal Verification<br>Simulation / Emulation |

</details>

<details>
<summary>CWE-693 · Protection Mechanism Failure · 103개 소속</summary>

| 세부 CWE | 공식 이름 | 권장 증거 수집 경로 (대안) | 해당 CWE 자체의 근거 |
| --- | --- | --- | --- |
| [CWE-5](https://cwe.mitre.org/data/definitions/5.html) | J2EE Misconfiguration: Data Transmission Without Encryption | 구현 자료 검토 | Automated Static Analysis |
| [CWE-6](https://cwe.mitre.org/data/definitions/6.html) | J2EE Misconfiguration: Insufficient Session-ID Length | 구현 자료 검토 | Automated Static Analysis |
| [CWE-184](https://cwe.mitre.org/data/definitions/184.html) | Incomplete List of Disallowed Inputs | 실행 관찰 자료 검토 | Black Box |
| [CWE-259](https://cwe.mitre.org/data/definitions/259.html) | Use of Hard-coded Password | CVE·벤더 근거로 검토 자료 구체화<br>구현 자료 검토<br>실행 관찰 자료 검토 | Manual Analysis<br>Black Box<br>Automated Static Analysis |
| [CWE-302](https://cwe.mitre.org/data/definitions/302.html) | Authentication Bypass by Assumed-Immutable Data | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-308](https://cwe.mitre.org/data/definitions/308.html) | Use of Single-factor Authentication | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-309](https://cwe.mitre.org/data/definitions/309.html) | Use of Password System for Primary Authentication | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-311](https://cwe.mitre.org/data/definitions/311.html) | Missing Encryption of Sensitive Data | CVE·벤더 근거로 검토 자료 구체화<br>컴파일 산출물 검토<br>설계 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Manual Analysis<br>Automated Analysis<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | Cleartext Storage of Sensitive Information | 구현 자료 검토 | Automated Static Analysis |
| [CWE-313](https://cwe.mitre.org/data/definitions/313.html) | Cleartext Storage in a File or on Disk | 구현 자료 검토 | Automated Static Analysis |
| [CWE-314](https://cwe.mitre.org/data/definitions/314.html) | Cleartext Storage in the Registry | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-315](https://cwe.mitre.org/data/definitions/315.html) | Cleartext Storage of Sensitive Information in a Cookie | 구현 자료 검토 | Automated Static Analysis |
| [CWE-316](https://cwe.mitre.org/data/definitions/316.html) | Cleartext Storage of Sensitive Information in Memory | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-317](https://cwe.mitre.org/data/definitions/317.html) | Cleartext Storage of Sensitive Information in GUI | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-318](https://cwe.mitre.org/data/definitions/318.html) | Cleartext Storage of Sensitive Information in Executable | 구현 자료 검토 | Automated Static Analysis |
| [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | Cleartext Transmission of Sensitive Information | 구현 자료 검토<br>실행 관찰 자료 검토 | Black Box<br>Automated Static Analysis |
| [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | Use of Hard-coded Cryptographic Key | 구현 자료 검토 | Automated Static Analysis |
| [CWE-323](https://cwe.mitre.org/data/definitions/323.html) | Reusing a Nonce, Key Pair in Encryption | 구현 자료 검토 | Automated Static Analysis |
| [CWE-325](https://cwe.mitre.org/data/definitions/325.html) | Missing Cryptographic Step | 구현 자료 검토 | Automated Static Analysis |
| [CWE-326](https://cwe.mitre.org/data/definitions/326.html) | Inadequate Encryption Strength | 구현 자료 검토 | Automated Static Analysis |
| [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | Use of a Broken or Risky Cryptographic Algorithm | CVE·벤더 근거로 검토 자료 구체화<br>컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Analysis<br>Manual Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-328](https://cwe.mitre.org/data/definitions/328.html) | Use of Weak Hash | 구현 자료 검토 | Automated Static Analysis |
| [CWE-329](https://cwe.mitre.org/data/definitions/329.html) | Generation of Predictable IV with CBC Mode | 구현 자료 검토 | Automated Static Analysis |
| [CWE-330](https://cwe.mitre.org/data/definitions/330.html) | Use of Insufficiently Random Values | 컴파일 산출물 검토<br>설계 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Black Box<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-331](https://cwe.mitre.org/data/definitions/331.html) | Insufficient Entropy | 구현 자료 검토 | Automated Static Analysis |
| [CWE-332](https://cwe.mitre.org/data/definitions/332.html) | Insufficient Entropy in PRNG | 구현 자료 검토 | Automated Static Analysis |
| [CWE-333](https://cwe.mitre.org/data/definitions/333.html) | Improper Handling of Insufficient Entropy in TRNG | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-334](https://cwe.mitre.org/data/definitions/334.html) | Small Space of Random Values | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-335](https://cwe.mitre.org/data/definitions/335.html) | Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG) | 구현 자료 검토 | Automated Static Analysis |
| [CWE-336](https://cwe.mitre.org/data/definitions/336.html) | Same Seed in Pseudo-Random Number Generator (PRNG) | 구현 자료 검토 | Automated Static Analysis |
| [CWE-337](https://cwe.mitre.org/data/definitions/337.html) | Predictable Seed in Pseudo-Random Number Generator (PRNG) | 구현 자료 검토 | Automated Static Analysis |
| [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) | 구현 자료 검토 | Automated Static Analysis |
| [CWE-339](https://cwe.mitre.org/data/definitions/339.html) | Small Seed Space in PRNG | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-340](https://cwe.mitre.org/data/definitions/340.html) | Generation of Predictable Numbers or Identifiers | 구현 자료 검토 | Automated Static Analysis |
| [CWE-341](https://cwe.mitre.org/data/definitions/341.html) | Predictable from Observable State | 구현 자료 검토 | Automated Static Analysis |
| [CWE-342](https://cwe.mitre.org/data/definitions/342.html) | Predictable Exact Value from Previous Values | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-343](https://cwe.mitre.org/data/definitions/343.html) | Predictable Value Range from Previous Values | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-344](https://cwe.mitre.org/data/definitions/344.html) | Use of Invariant Value in Dynamically Changing Context | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-345](https://cwe.mitre.org/data/definitions/345.html) | Insufficient Verification of Data Authenticity | 구현 자료 검토 | Automated Static Analysis |
| [CWE-346](https://cwe.mitre.org/data/definitions/346.html) | Origin Validation Error | 구현 자료 검토 | Automated Static Analysis |
| [CWE-347](https://cwe.mitre.org/data/definitions/347.html) | Improper Verification of Cryptographic Signature | 구현 자료 검토 | Automated Static Analysis |
| [CWE-348](https://cwe.mitre.org/data/definitions/348.html) | Use of Less Trusted Source | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-349](https://cwe.mitre.org/data/definitions/349.html) | Acceptance of Extraneous Untrusted Data With Trusted Data | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-350](https://cwe.mitre.org/data/definitions/350.html) | Reliance on Reverse DNS Resolution for a Security-Critical Action | 구현 자료 검토 | Automated Static Analysis |
| [CWE-351](https://cwe.mitre.org/data/definitions/351.html) | Insufficient Type Distinction | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | Cross-Site Request Forgery | CVE·벤더 근거로 검토 자료 구체화<br>컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Manual Analysis<br>Automated Static Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-353](https://cwe.mitre.org/data/definitions/353.html) | Missing Support for Integrity Check | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-354](https://cwe.mitre.org/data/definitions/354.html) | Improper Validation of Integrity Check Value | 구현 자료 검토 | Automated Static Analysis |
| [CWE-357](https://cwe.mitre.org/data/definitions/357.html) | Insufficient UI Warning of Dangerous Operations | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-358](https://cwe.mitre.org/data/definitions/358.html) | Improperly Implemented Security Check for Standard | 구현 자료 검토 | Automated Static Analysis |
| [CWE-360](https://cwe.mitre.org/data/definitions/360.html) | Trust of System Event Data | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-422](https://cwe.mitre.org/data/definitions/422.html) | Unprotected Windows Messaging Channel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-424](https://cwe.mitre.org/data/definitions/424.html) | Improper Protection of Alternate Path | 구현 자료 검토 | Automated Static Analysis |
| [CWE-425](https://cwe.mitre.org/data/definitions/425.html) | Direct Request | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-450](https://cwe.mitre.org/data/definitions/450.html) | Multiple Interpretations of UI Input | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-453](https://cwe.mitre.org/data/definitions/453.html) | Insecure Default Variable Initialization | 구현 자료 검토 | Automated Static Analysis |
| [CWE-494](https://cwe.mitre.org/data/definitions/494.html) | Download of Code Without Integrity Check | CVE·벤더 근거로 검토 자료 구체화<br>구현 자료 검토<br>실행 관찰 자료 검토 | Manual Analysis<br>Black Box<br>Automated Static Analysis |
| [CWE-526](https://cwe.mitre.org/data/definitions/526.html) | Cleartext Storage of Sensitive Information in an Environment Variable | 구현 자료 검토 | Automated Static Analysis |
| [CWE-565](https://cwe.mitre.org/data/definitions/565.html) | Reliance on Cookies without Validation and Integrity Checking | 구현 자료 검토 | Automated Static Analysis |
| [CWE-587](https://cwe.mitre.org/data/definitions/587.html) | Assignment of a Fixed Address to a Pointer | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-602](https://cwe.mitre.org/data/definitions/602.html) | Client-Side Enforcement of Server-Side Security | CVE·벤더 근거로 검토 자료 구체화<br>실행 관찰 자료 검토 | Fuzzing<br>Manual Analysis |
| [CWE-603](https://cwe.mitre.org/data/definitions/603.html) | Use of Client-Side Authentication | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-614](https://cwe.mitre.org/data/definitions/614.html) | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute | 구현 자료 검토 | Automated Static Analysis |
| [CWE-616](https://cwe.mitre.org/data/definitions/616.html) | Incomplete Identification of Uploaded File Variables (PHP) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-646](https://cwe.mitre.org/data/definitions/646.html) | Reliance on File Name or Extension of Externally-Supplied File | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-649](https://cwe.mitre.org/data/definitions/649.html) | Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-653](https://cwe.mitre.org/data/definitions/653.html) | Improper Isolation or Compartmentalization | 컴파일 산출물 검토<br>설계 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-654](https://cwe.mitre.org/data/definitions/654.html) | Reliance on a Single Factor in a Security Decision | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-655](https://cwe.mitre.org/data/definitions/655.html) | Insufficient Psychological Acceptability | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-656](https://cwe.mitre.org/data/definitions/656.html) | Reliance on Security Through Obscurity | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-692](https://cwe.mitre.org/data/definitions/692.html) | Incomplete Denylist to Cross-Site Scripting | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-757](https://cwe.mitre.org/data/definitions/757.html) | Selection of Less-Secure Algorithm During Negotiation | 구현 자료 검토 | Automated Static Analysis |
| [CWE-759](https://cwe.mitre.org/data/definitions/759.html) | Use of a One-Way Hash without a Salt | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-760](https://cwe.mitre.org/data/definitions/760.html) | Use of a One-Way Hash with a Predictable Salt | 구현 자료 검토 | Automated Static Analysis |
| [CWE-780](https://cwe.mitre.org/data/definitions/780.html) | Use of RSA Algorithm without OAEP | 구현 자료 검토 | Automated Static Analysis |
| [CWE-784](https://cwe.mitre.org/data/definitions/784.html) | Reliance on Cookies without Validation and Integrity Checking in a Security Decision | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | Use of Hard-coded Credentials | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Black Box<br>Automated Static Analysis<br>Manual Static Analysis<br>Manual Dynamic Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-807](https://cwe.mitre.org/data/definitions/807.html) | Reliance on Untrusted Inputs in a Security Decision | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Manual Static Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-916](https://cwe.mitre.org/data/definitions/916.html) | Use of Password Hash With Insufficient Computational Effort | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-924](https://cwe.mitre.org/data/definitions/924.html) | Improper Enforcement of Message Integrity During Transmission in a Communication Channel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-925](https://cwe.mitre.org/data/definitions/925.html) | Improper Verification of Intent by Broadcast Receiver | 구현 자료 검토 | Automated Static Analysis |
| [CWE-939](https://cwe.mitre.org/data/definitions/939.html) | Improper Authorization in Handler for Custom URL Scheme | 구현 자료 검토 | Automated Static Analysis |
| [CWE-940](https://cwe.mitre.org/data/definitions/940.html) | Improper Verification of Source of a Communication Channel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1039](https://cwe.mitre.org/data/definitions/1039.html) | Inadequate Detection or Handling of Adversarial Input Perturbations in Automated Recognition Mechanism | 설계 자료 검토<br>실행 관찰 자료 검토 | Dynamic Analysis with Manual Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Architecture or Design Review |
| [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) | Initialization of a Resource with an Insecure Default | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1189](https://cwe.mitre.org/data/definitions/1189.html) | Improper Isolation of Shared Resources on System-on-a-Chip (SoC) | 실행 관찰 자료 검토 | Automated Dynamic Analysis |
| [CWE-1204](https://cwe.mitre.org/data/definitions/1204.html) | Generation of Weak Initialization Vector (IV) | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1240](https://cwe.mitre.org/data/definitions/1240.html) | Use of a Cryptographic Primitive with a Risky Implementation | CVE·벤더 근거로 검토 자료 구체화<br>설계 자료 검토<br>실행 관찰 자료 검토 | Architecture or Design Review<br>Manual Analysis<br>Dynamic Analysis with Manual Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation |
| [CWE-1241](https://cwe.mitre.org/data/definitions/1241.html) | Use of Predictable Algorithm in Random Number Generator | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1248](https://cwe.mitre.org/data/definitions/1248.html) | Semiconductor Defects in Hardware Logic with Security-Sensitive Implications | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1253](https://cwe.mitre.org/data/definitions/1253.html) | Incorrect Selection of Fuse Values | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1269](https://cwe.mitre.org/data/definitions/1269.html) | Product Released in Non-Release Configuration | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1278](https://cwe.mitre.org/data/definitions/1278.html) | Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1291](https://cwe.mitre.org/data/definitions/1291.html) | Public Key Re-Use for Signing both Debug and Production Code | 설계 자료 검토<br>실행 관찰 자료 검토 | Architecture or Design Review<br>Dynamic Analysis with Manual Results Interpretation |
| [CWE-1293](https://cwe.mitre.org/data/definitions/1293.html) | Missing Source Correlation of Multiple Independent Data | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1303](https://cwe.mitre.org/data/definitions/1303.html) | Non-Transparent Sharing of Microarchitectural Resources | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1318](https://cwe.mitre.org/data/definitions/1318.html) | Missing Support for Security Features in On-chip Fabrics or Buses | 설계 자료 검토<br>소스 검토 | Architecture or Design Review<br>Manual Static Analysis - Source Code |
| [CWE-1319](https://cwe.mitre.org/data/definitions/1319.html) | Improper Protection against Electromagnetic Fault Injection (EM-FI) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1326](https://cwe.mitre.org/data/definitions/1326.html) | Missing Immutable Root of Trust in Hardware | 설계 자료 검토<br>실행 관찰 자료 검토 | Automated Dynamic Analysis<br>Architecture or Design Review |
| [CWE-1331](https://cwe.mitre.org/data/definitions/1331.html) | Improper Isolation of Shared Resources in Network On Chip (NoC) | CVE·벤더 근거로 검토 자료 구체화 | Manual Analysis |
| [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html) | Missing Origin Validation in WebSockets | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1428](https://cwe.mitre.org/data/definitions/1428.html) | Reliance on HTTP instead of HTTPS | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1431](https://cwe.mitre.org/data/definitions/1431.html) | Driving Intermediate Cryptographic State/Results to Hardware Module Outputs | CVE·벤더 근거로 검토 자료 구체화<br>형식 검증 자료 검토<br>시뮬레이션 자료 검토<br>소스 검토 | Automated Static Analysis - Source Code<br>Simulation / Emulation<br>Formal Verification<br>Manual Analysis |

</details>

<details>
<summary>CWE-697 · Incorrect Comparison · 21개 소속</summary>

| 세부 CWE | 공식 이름 | 권장 증거 수집 경로 (대안) | 해당 CWE 자체의 근거 |
| --- | --- | --- | --- |
| [CWE-183](https://cwe.mitre.org/data/definitions/183.html) | Permissive List of Allowed Inputs | 구현 자료 검토 | Automated Static Analysis |
| [CWE-184](https://cwe.mitre.org/data/definitions/184.html) | Incomplete List of Disallowed Inputs | 실행 관찰 자료 검토 | Black Box |
| [CWE-185](https://cwe.mitre.org/data/definitions/185.html) | Incorrect Regular Expression | 구현 자료 검토 | Automated Static Analysis |
| [CWE-186](https://cwe.mitre.org/data/definitions/186.html) | Overly Restrictive Regular Expression | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-187](https://cwe.mitre.org/data/definitions/187.html) | Partial String Comparison | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-478](https://cwe.mitre.org/data/definitions/478.html) | Missing Default Case in Multiple Condition Expression | 구현 자료 검토 | Automated Static Analysis |
| [CWE-486](https://cwe.mitre.org/data/definitions/486.html) | Comparison of Classes by Name | 구현 자료 검토 | Automated Static Analysis |
| [CWE-581](https://cwe.mitre.org/data/definitions/581.html) | Object Model Violation: Just One of Equals and Hashcode Defined | 구현 자료 검토 | Automated Static Analysis |
| [CWE-595](https://cwe.mitre.org/data/definitions/595.html) | Comparison of Object References Instead of Object Contents | 구현 자료 검토 | Automated Static Analysis |
| [CWE-597](https://cwe.mitre.org/data/definitions/597.html) | Use of Wrong Operator in String Comparison | 구현 자료 검토 | Automated Static Analysis |
| [CWE-625](https://cwe.mitre.org/data/definitions/625.html) | Permissive Regular Expression | 구현 자료 검토 | Automated Static Analysis |
| [CWE-692](https://cwe.mitre.org/data/definitions/692.html) | Incomplete Denylist to Cross-Site Scripting | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-777](https://cwe.mitre.org/data/definitions/777.html) | Regular Expression without Anchors | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-839](https://cwe.mitre.org/data/definitions/839.html) | Numeric Range Comparison Without Minimum Check | 구현 자료 검토 | Automated Static Analysis |
| [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | Permissive Cross-domain Security Policy with Untrusted Domains | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1023](https://cwe.mitre.org/data/definitions/1023.html) | Incomplete Comparison with Missing Factors | 구현 자료 검토 | Manual Static Analysis |
| [CWE-1024](https://cwe.mitre.org/data/definitions/1024.html) | Comparison of Incompatible Types | 구현 자료 검토 | Automated Static Analysis<br>Manual Static Analysis |
| [CWE-1025](https://cwe.mitre.org/data/definitions/1025.html) | Comparison Using Wrong Factors | 구현 자료 검토 | Manual Static Analysis |
| [CWE-1039](https://cwe.mitre.org/data/definitions/1039.html) | Inadequate Detection or Handling of Adversarial Input Perturbations in Automated Recognition Mechanism | 설계 자료 검토<br>실행 관찰 자료 검토 | Dynamic Analysis with Manual Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Architecture or Design Review |
| [CWE-1077](https://cwe.mitre.org/data/definitions/1077.html) | Floating Point Comparison with Incorrect Operator | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1254](https://cwe.mitre.org/data/definitions/1254.html) | Incorrect Comparison Logic Granularity | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |

</details>

<details>
<summary>CWE-703 · Improper Check or Handling of Exceptional Conditions · 58개 소속</summary>

| 세부 CWE | 공식 이름 | 권장 증거 수집 경로 (대안) | 해당 CWE 자체의 근거 |
| --- | --- | --- | --- |
| [CWE-7](https://cwe.mitre.org/data/definitions/7.html) | J2EE Misconfiguration: Missing Custom Error Page | 구현 자료 검토 | Automated Static Analysis |
| [CWE-12](https://cwe.mitre.org/data/definitions/12.html) | ASP.NET Misconfiguration: Missing Custom Error Page | 구현 자료 검토 | Automated Static Analysis |
| [CWE-130](https://cwe.mitre.org/data/definitions/130.html) | Improper Handling of Length Parameter Inconsistency | 구현 자료 검토 | Automated Static Analysis |
| [CWE-166](https://cwe.mitre.org/data/definitions/166.html) | Improper Handling of Missing Special Element | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-167](https://cwe.mitre.org/data/definitions/167.html) | Improper Handling of Additional Special Element | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-168](https://cwe.mitre.org/data/definitions/168.html) | Improper Handling of Inconsistent Special Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | Generation of Error Message Containing Sensitive Information | CVE·벤더 근거로 검토 자료 구체화<br>구현 자료 검토<br>실행 관찰 자료 검토 | Manual Analysis<br>Automated Analysis<br>Automated Dynamic Analysis<br>Manual Dynamic Analysis<br>Automated Static Analysis |
| [CWE-210](https://cwe.mitre.org/data/definitions/210.html) | Self-generated Error Message Containing Sensitive Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-211](https://cwe.mitre.org/data/definitions/211.html) | Externally-Generated Error Message Containing Sensitive Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-228](https://cwe.mitre.org/data/definitions/228.html) | Improper Handling of Syntactically Invalid Structure | 구현 자료 검토 | Automated Static Analysis |
| [CWE-229](https://cwe.mitre.org/data/definitions/229.html) | Improper Handling of Values | 실행 관찰 자료 검토 | Fuzzing |
| [CWE-230](https://cwe.mitre.org/data/definitions/230.html) | Improper Handling of Missing Values | 실행 관찰 자료 검토 | Fuzzing |
| [CWE-231](https://cwe.mitre.org/data/definitions/231.html) | Improper Handling of Extra Values | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-232](https://cwe.mitre.org/data/definitions/232.html) | Improper Handling of Undefined Values | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-233](https://cwe.mitre.org/data/definitions/233.html) | Improper Handling of Parameters | 구현 자료 검토<br>실행 관찰 자료 검토 | Fuzzing<br>Automated Static Analysis |
| [CWE-234](https://cwe.mitre.org/data/definitions/234.html) | Failure to Handle Missing Parameter | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-235](https://cwe.mitre.org/data/definitions/235.html) | Improper Handling of Extra Parameters | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-236](https://cwe.mitre.org/data/definitions/236.html) | Improper Handling of Undefined Parameters | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-237](https://cwe.mitre.org/data/definitions/237.html) | Improper Handling of Structural Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-238](https://cwe.mitre.org/data/definitions/238.html) | Improper Handling of Incomplete Structural Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-239](https://cwe.mitre.org/data/definitions/239.html) | Failure to Handle Incomplete Element | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-240](https://cwe.mitre.org/data/definitions/240.html) | Improper Handling of Inconsistent Structural Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-241](https://cwe.mitre.org/data/definitions/241.html) | Improper Handling of Unexpected Data Type | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-248](https://cwe.mitre.org/data/definitions/248.html) | Uncaught Exception | 구현 자료 검토 | Automated Static Analysis |
| [CWE-252](https://cwe.mitre.org/data/definitions/252.html) | Unchecked Return Value | 구현 자료 검토 | Automated Static Analysis |
| [CWE-253](https://cwe.mitre.org/data/definitions/253.html) | Incorrect Check of Function Return Value | 구현 자료 검토 | Automated Static Analysis |
| [CWE-273](https://cwe.mitre.org/data/definitions/273.html) | Improper Check for Dropped Privileges | 구현 자료 검토 | Automated Static Analysis |
| [CWE-274](https://cwe.mitre.org/data/definitions/274.html) | Improper Handling of Insufficient Privileges | 구현 자료 검토 | Automated Static Analysis |
| [CWE-280](https://cwe.mitre.org/data/definitions/280.html) | Improper Handling of Insufficient Permissions or Privileges | 구현 자료 검토 | Automated Static Analysis |
| [CWE-333](https://cwe.mitre.org/data/definitions/333.html) | Improper Handling of Insufficient Entropy in TRNG | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-354](https://cwe.mitre.org/data/definitions/354.html) | Improper Validation of Integrity Check Value | 구현 자료 검토 | Automated Static Analysis |
| [CWE-390](https://cwe.mitre.org/data/definitions/390.html) | Detection of Error Condition Without Action | 구현 자료 검토 | Automated Static Analysis |
| [CWE-392](https://cwe.mitre.org/data/definitions/392.html) | Missing Report of Error Condition | 구현 자료 검토 | Automated Static Analysis |
| [CWE-393](https://cwe.mitre.org/data/definitions/393.html) | Return of Wrong Status Code | 실행 관찰 자료 검토 | Fuzzing |
| [CWE-394](https://cwe.mitre.org/data/definitions/394.html) | Unexpected Status Code or Return Value | 구현 자료 검토 | Automated Static Analysis |
| [CWE-395](https://cwe.mitre.org/data/definitions/395.html) | Use of NullPointerException Catch to Detect NULL Pointer Dereference | 컴파일 산출물 검토<br>설계 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-396](https://cwe.mitre.org/data/definitions/396.html) | Declaration of Catch for Generic Exception | 구현 자료 검토 | Automated Static Analysis |
| [CWE-397](https://cwe.mitre.org/data/definitions/397.html) | Declaration of Throws for Generic Exception | 구현 자료 검토 | Automated Static Analysis |
| [CWE-455](https://cwe.mitre.org/data/definitions/455.html) | Non-exit on Failed Initialization | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-460](https://cwe.mitre.org/data/definitions/460.html) | Improper Cleanup on Thrown Exception | 구현 자료 검토 | Automated Static Analysis |
| [CWE-476](https://cwe.mitre.org/data/definitions/476.html) | NULL Pointer Dereference | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Dynamic Analysis<br>Manual Dynamic Analysis<br>Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-535](https://cwe.mitre.org/data/definitions/535.html) | Exposure of Information Through Shell Error Message | 구현 자료 검토 | Automated Static Analysis |
| [CWE-536](https://cwe.mitre.org/data/definitions/536.html) | Servlet Runtime Error Message Containing Sensitive Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-537](https://cwe.mitre.org/data/definitions/537.html) | Java Runtime Error Message Containing Sensitive Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-544](https://cwe.mitre.org/data/definitions/544.html) | Missing Standardized Error Handling Mechanism | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-550](https://cwe.mitre.org/data/definitions/550.html) | Server-generated Error Message Containing Sensitive Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-600](https://cwe.mitre.org/data/definitions/600.html) | Uncaught Exception in Servlet | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-636](https://cwe.mitre.org/data/definitions/636.html) | Not Failing Securely | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-690](https://cwe.mitre.org/data/definitions/690.html) | Unchecked Return Value to NULL Pointer Dereference | 구현 자료 검토<br>실행 관찰 자료 검토 | Black Box<br>White Box<br>Automated Dynamic Analysis |
| [CWE-754](https://cwe.mitre.org/data/definitions/754.html) | Improper Check for Unusual or Exceptional Conditions | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Manual Dynamic Analysis |
| [CWE-755](https://cwe.mitre.org/data/definitions/755.html) | Improper Handling of Exceptional Conditions | 구현 자료 검토 | Automated Static Analysis |
| [CWE-756](https://cwe.mitre.org/data/definitions/756.html) | Missing Custom Error Page | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1247](https://cwe.mitre.org/data/definitions/1247.html) | Improper Protection Against Voltage and Clock Glitches | CVE·벤더 근거로 검토 자료 구체화<br>설계 자료 검토<br>실행 관찰 자료 검토 | Manual Analysis<br>Dynamic Analysis with Manual Results Interpretation<br>Architecture or Design Review<br>Architecture or Design Review |
| [CWE-1261](https://cwe.mitre.org/data/definitions/1261.html) | Improper Handling of Single Event Upsets | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1332](https://cwe.mitre.org/data/definitions/1332.html) | Improper Handling of Faults that Lead to Instruction Skips | CVE·벤더 근거로 검토 자료 구체화<br>구현 자료 검토<br>시뮬레이션 자료 검토 | Automated Static Analysis<br>Simulation / Emulation<br>Manual Analysis |
| [CWE-1338](https://cwe.mitre.org/data/definitions/1338.html) | Improper Protections Against Hardware Overheating | 설계 자료 검토<br>실행 관찰 자료 검토 | Dynamic Analysis with Manual Results Interpretation<br>Architecture or Design Review |
| [CWE-1351](https://cwe.mitre.org/data/definitions/1351.html) | Improper Handling of Hardware Behavior in Exceptionally Cold Environments | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1384](https://cwe.mitre.org/data/definitions/1384.html) | Improper Handling of Physical or Environmental Conditions | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |

</details>

<details>
<summary>CWE-707 · Improper Neutralization · 145개 소속</summary>

| 세부 CWE | 공식 이름 | 권장 증거 수집 경로 (대안) | 해당 CWE 자체의 근거 |
| --- | --- | --- | --- |
| [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Improper Input Validation | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis<br>Manual Static Analysis<br>Fuzzing<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-37](https://cwe.mitre.org/data/definitions/37.html) | Path Traversal: '/absolute/pathname/here' | 구현 자료 검토 | Automated Static Analysis |
| [CWE-42](https://cwe.mitre.org/data/definitions/42.html) | Path Equivalence: 'filename.' (Trailing Dot) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-43](https://cwe.mitre.org/data/definitions/43.html) | Path Equivalence: 'filename....' (Multiple Trailing Dot) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-45](https://cwe.mitre.org/data/definitions/45.html) | Path Equivalence: 'file...name' (Multiple Internal Dot) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-46](https://cwe.mitre.org/data/definitions/46.html) | Path Equivalence: 'filename ' (Trailing Space) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-49](https://cwe.mitre.org/data/definitions/49.html) | Path Equivalence: 'filename/' (Trailing Slash) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-50](https://cwe.mitre.org/data/definitions/50.html) | Path Equivalence: '//multiple/leading/slash' | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-52](https://cwe.mitre.org/data/definitions/52.html) | Path Equivalence: '/multiple/trailing/slash//' | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-53](https://cwe.mitre.org/data/definitions/53.html) | Path Equivalence: '\multiple\\internal\backslash' | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-54](https://cwe.mitre.org/data/definitions/54.html) | Path Equivalence: 'filedir\' (Trailing Backslash) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-56](https://cwe.mitre.org/data/definitions/56.html) | Path Equivalence: 'filedir*' (Wildcard) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-74](https://cwe.mitre.org/data/definitions/74.html) | Improper Neutralization of Special Elements in Output Used by a Downstream Component | 구현 자료 검토 | Automated Static Analysis |
| [CWE-75](https://cwe.mitre.org/data/definitions/75.html) | Failure to Sanitize Special Elements into a Different Plane | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-76](https://cwe.mitre.org/data/definitions/76.html) | Improper Neutralization of Equivalent Special Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-77](https://cwe.mitre.org/data/definitions/77.html) | Improper Neutralization of Special Elements used in a Command | 구현 자료 검토 | Automated Static Analysis |
| [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | Improper Neutralization of Special Elements used in an OS Command | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis<br>Automated Dynamic Analysis<br>Manual Static Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Improper Neutralization of Input During Web Page Generation | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Black Box |
| [CWE-80](https://cwe.mitre.org/data/definitions/80.html) | Improper Neutralization of Script-Related HTML Tags in a Web Page | 구현 자료 검토 | Automated Static Analysis |
| [CWE-81](https://cwe.mitre.org/data/definitions/81.html) | Improper Neutralization of Script in an Error Message Web Page | 구현 자료 검토 | Automated Static Analysis |
| [CWE-82](https://cwe.mitre.org/data/definitions/82.html) | Improper Neutralization of Script in Attributes of IMG Tags in a Web Page | 구현 자료 검토 | Automated Static Analysis |
| [CWE-83](https://cwe.mitre.org/data/definitions/83.html) | Improper Neutralization of Script in Attributes in a Web Page | 구현 자료 검토 | Automated Static Analysis |
| [CWE-84](https://cwe.mitre.org/data/definitions/84.html) | Improper Neutralization of Encoded URI Schemes in a Web Page | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-85](https://cwe.mitre.org/data/definitions/85.html) | Doubled Character XSS Manipulations | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-86](https://cwe.mitre.org/data/definitions/86.html) | Improper Neutralization of Invalid Characters in Identifiers in Web Pages | 구현 자료 검토 | Automated Static Analysis |
| [CWE-87](https://cwe.mitre.org/data/definitions/87.html) | Improper Neutralization of Alternate XSS Syntax | 구현 자료 검토 | Automated Static Analysis |
| [CWE-88](https://cwe.mitre.org/data/definitions/88.html) | Improper Neutralization of Argument Delimiters in a Command | 구현 자료 검토 | Automated Static Analysis |
| [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | Improper Neutralization of Special Elements used in an SQL Command | CVE·벤더 근거로 검토 자료 구체화<br>컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis<br>Automated Dynamic Analysis<br>Manual Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-90](https://cwe.mitre.org/data/definitions/90.html) | Improper Neutralization of Special Elements used in an LDAP Query | 구현 자료 검토 | Automated Static Analysis |
| [CWE-91](https://cwe.mitre.org/data/definitions/91.html) | XML Injection | 구현 자료 검토 | Automated Static Analysis |
| [CWE-93](https://cwe.mitre.org/data/definitions/93.html) | Improper Neutralization of CRLF Sequences | 구현 자료 검토 | Automated Static Analysis |
| [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | Improper Control of Generation of Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | Improper Neutralization of Directives in Dynamically Evaluated Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-96](https://cwe.mitre.org/data/definitions/96.html) | Improper Neutralization of Directives in Statically Saved Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-97](https://cwe.mitre.org/data/definitions/97.html) | Improper Neutralization of Server-Side Includes (SSI) Within a Web Page | 구현 자료 검토 | Automated Static Analysis |
| [CWE-99](https://cwe.mitre.org/data/definitions/99.html) | Improper Control of Resource Identifiers | 구현 자료 검토 | Automated Static Analysis |
| [CWE-102](https://cwe.mitre.org/data/definitions/102.html) | Struts: Duplicate Validation Forms | 구현 자료 검토 | Automated Static Analysis |
| [CWE-105](https://cwe.mitre.org/data/definitions/105.html) | Struts: Form Field Without Validator | 구현 자료 검토 | Automated Static Analysis |
| [CWE-106](https://cwe.mitre.org/data/definitions/106.html) | Struts: Plug-in Framework not in Use | 구현 자료 검토 | Automated Static Analysis |
| [CWE-108](https://cwe.mitre.org/data/definitions/108.html) | Struts: Unvalidated Action Form | 구현 자료 검토 | Automated Static Analysis |
| [CWE-109](https://cwe.mitre.org/data/definitions/109.html) | Struts: Validator Turned Off | 구현 자료 검토 | Automated Static Analysis |
| [CWE-112](https://cwe.mitre.org/data/definitions/112.html) | Missing XML Validation | 구현 자료 검토 | Automated Static Analysis |
| [CWE-113](https://cwe.mitre.org/data/definitions/113.html) | Improper Neutralization of CRLF Sequences in HTTP Headers | 구현 자료 검토 | Automated Static Analysis |
| [CWE-116](https://cwe.mitre.org/data/definitions/116.html) | Improper Encoding or Escaping of Output | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-117](https://cwe.mitre.org/data/definitions/117.html) | Improper Output Neutralization for Logs | 구현 자료 검토 | Automated Static Analysis |
| [CWE-129](https://cwe.mitre.org/data/definitions/129.html) | Improper Validation of Array Index | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis<br>Automated Dynamic Analysis<br>Black Box |
| [CWE-130](https://cwe.mitre.org/data/definitions/130.html) | Improper Handling of Length Parameter Inconsistency | 구현 자료 검토 | Automated Static Analysis |
| [CWE-138](https://cwe.mitre.org/data/definitions/138.html) | Improper Neutralization of Special Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-140](https://cwe.mitre.org/data/definitions/140.html) | Improper Neutralization of Delimiters | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-141](https://cwe.mitre.org/data/definitions/141.html) | Improper Neutralization of Parameter/Argument Delimiters | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-142](https://cwe.mitre.org/data/definitions/142.html) | Improper Neutralization of Value Delimiters | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-143](https://cwe.mitre.org/data/definitions/143.html) | Improper Neutralization of Record Delimiters | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-144](https://cwe.mitre.org/data/definitions/144.html) | Improper Neutralization of Line Delimiters | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-145](https://cwe.mitre.org/data/definitions/145.html) | Improper Neutralization of Section Delimiters | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-146](https://cwe.mitre.org/data/definitions/146.html) | Improper Neutralization of Expression/Command Delimiters | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-147](https://cwe.mitre.org/data/definitions/147.html) | Improper Neutralization of Input Terminators | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-148](https://cwe.mitre.org/data/definitions/148.html) | Improper Neutralization of Input Leaders | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-149](https://cwe.mitre.org/data/definitions/149.html) | Improper Neutralization of Quoting Syntax | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-150](https://cwe.mitre.org/data/definitions/150.html) | Improper Neutralization of Escape, Meta, or Control Sequences | 구현 자료 검토 | Automated Static Analysis |
| [CWE-151](https://cwe.mitre.org/data/definitions/151.html) | Improper Neutralization of Comment Delimiters | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-152](https://cwe.mitre.org/data/definitions/152.html) | Improper Neutralization of Macro Symbols | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-153](https://cwe.mitre.org/data/definitions/153.html) | Improper Neutralization of Substitution Characters | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-154](https://cwe.mitre.org/data/definitions/154.html) | Improper Neutralization of Variable Name Delimiters | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-155](https://cwe.mitre.org/data/definitions/155.html) | Improper Neutralization of Wildcards or Matching Symbols | 구현 자료 검토 | Automated Static Analysis |
| [CWE-156](https://cwe.mitre.org/data/definitions/156.html) | Improper Neutralization of Whitespace | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-157](https://cwe.mitre.org/data/definitions/157.html) | Failure to Sanitize Paired Delimiters | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-158](https://cwe.mitre.org/data/definitions/158.html) | Improper Neutralization of Null Byte or NUL Character | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-159](https://cwe.mitre.org/data/definitions/159.html) | Improper Handling of Invalid Use of Special Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-160](https://cwe.mitre.org/data/definitions/160.html) | Improper Neutralization of Leading Special Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-161](https://cwe.mitre.org/data/definitions/161.html) | Improper Neutralization of Multiple Leading Special Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-162](https://cwe.mitre.org/data/definitions/162.html) | Improper Neutralization of Trailing Special Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-163](https://cwe.mitre.org/data/definitions/163.html) | Improper Neutralization of Multiple Trailing Special Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-164](https://cwe.mitre.org/data/definitions/164.html) | Improper Neutralization of Internal Special Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-165](https://cwe.mitre.org/data/definitions/165.html) | Improper Neutralization of Multiple Internal Special Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-166](https://cwe.mitre.org/data/definitions/166.html) | Improper Handling of Missing Special Element | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-167](https://cwe.mitre.org/data/definitions/167.html) | Improper Handling of Additional Special Element | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-168](https://cwe.mitre.org/data/definitions/168.html) | Improper Handling of Inconsistent Special Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-170](https://cwe.mitre.org/data/definitions/170.html) | Improper Null Termination | 구현 자료 검토 | Automated Static Analysis |
| [CWE-172](https://cwe.mitre.org/data/definitions/172.html) | Improper Encoding or Decoding of Data | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-173](https://cwe.mitre.org/data/definitions/173.html) | Improper Handling of Alternate Encoding | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-174](https://cwe.mitre.org/data/definitions/174.html) | Double Decoding of the Same Data | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-175](https://cwe.mitre.org/data/definitions/175.html) | Improper Handling of Mixed Encoding | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-176](https://cwe.mitre.org/data/definitions/176.html) | Improper Handling of Unicode Encoding | 구현 자료 검토 | Automated Static Analysis |
| [CWE-177](https://cwe.mitre.org/data/definitions/177.html) | Improper Handling of URL Encoding (Hex Encoding) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-179](https://cwe.mitre.org/data/definitions/179.html) | Incorrect Behavior Order: Early Validation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-180](https://cwe.mitre.org/data/definitions/180.html) | Incorrect Behavior Order: Validate Before Canonicalize | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-181](https://cwe.mitre.org/data/definitions/181.html) | Incorrect Behavior Order: Validate Before Filter | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-182](https://cwe.mitre.org/data/definitions/182.html) | Collapse of Data into Unsafe Value | 구현 자료 검토 | Automated Static Analysis |
| [CWE-228](https://cwe.mitre.org/data/definitions/228.html) | Improper Handling of Syntactically Invalid Structure | 구현 자료 검토 | Automated Static Analysis |
| [CWE-229](https://cwe.mitre.org/data/definitions/229.html) | Improper Handling of Values | 실행 관찰 자료 검토 | Fuzzing |
| [CWE-230](https://cwe.mitre.org/data/definitions/230.html) | Improper Handling of Missing Values | 실행 관찰 자료 검토 | Fuzzing |
| [CWE-231](https://cwe.mitre.org/data/definitions/231.html) | Improper Handling of Extra Values | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-232](https://cwe.mitre.org/data/definitions/232.html) | Improper Handling of Undefined Values | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-233](https://cwe.mitre.org/data/definitions/233.html) | Improper Handling of Parameters | 구현 자료 검토<br>실행 관찰 자료 검토 | Fuzzing<br>Automated Static Analysis |
| [CWE-234](https://cwe.mitre.org/data/definitions/234.html) | Failure to Handle Missing Parameter | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-235](https://cwe.mitre.org/data/definitions/235.html) | Improper Handling of Extra Parameters | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-236](https://cwe.mitre.org/data/definitions/236.html) | Improper Handling of Undefined Parameters | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-237](https://cwe.mitre.org/data/definitions/237.html) | Improper Handling of Structural Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-238](https://cwe.mitre.org/data/definitions/238.html) | Improper Handling of Incomplete Structural Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-239](https://cwe.mitre.org/data/definitions/239.html) | Failure to Handle Incomplete Element | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-240](https://cwe.mitre.org/data/definitions/240.html) | Improper Handling of Inconsistent Structural Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-241](https://cwe.mitre.org/data/definitions/241.html) | Improper Handling of Unexpected Data Type | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-462](https://cwe.mitre.org/data/definitions/462.html) | Duplicate Key in Associative List (Alist) | 구현 자료 검토 | Automated Static Analysis |
| [CWE-463](https://cwe.mitre.org/data/definitions/463.html) | Deletion of Data Structure Sentinel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-464](https://cwe.mitre.org/data/definitions/464.html) | Addition of Data Structure Sentinel | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-554](https://cwe.mitre.org/data/definitions/554.html) | ASP.NET Misconfiguration: Not Using Input Validation Framework | 구현 자료 검토 | Automated Static Analysis |
| [CWE-564](https://cwe.mitre.org/data/definitions/564.html) | Use of Hibernate with HQL/SQL Query String Containing External Input | 구현 자료 검토 | Automated Static Analysis |
| [CWE-606](https://cwe.mitre.org/data/definitions/606.html) | Unchecked Input for Loop Condition | 구현 자료 검토 | Automated Static Analysis |
| [CWE-621](https://cwe.mitre.org/data/definitions/621.html) | Variable Extraction Error | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-622](https://cwe.mitre.org/data/definitions/622.html) | Improper Validation of Function Hook Arguments | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-624](https://cwe.mitre.org/data/definitions/624.html) | Executable Regular Expression Error | 구현 자료 검토 | Automated Static Analysis |
| [CWE-626](https://cwe.mitre.org/data/definitions/626.html) | Null Byte Interaction Error (Poison Null Byte) | 구현 자료 검토 | Automated Static Analysis |
| [CWE-627](https://cwe.mitre.org/data/definitions/627.html) | Dynamic Variable Evaluation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-641](https://cwe.mitre.org/data/definitions/641.html) | Improper Restriction of Names for Files and Other Resources | 구현 자료 검토 | Automated Static Analysis |
| [CWE-643](https://cwe.mitre.org/data/definitions/643.html) | Improper Neutralization of Data within XPath Expressions | 구현 자료 검토 | Automated Static Analysis |
| [CWE-644](https://cwe.mitre.org/data/definitions/644.html) | Improper Neutralization of HTTP Headers for Scripting Syntax | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-647](https://cwe.mitre.org/data/definitions/647.html) | Use of Non-Canonical URL Paths for Authorization Decisions | 구현 자료 검토 | Automated Static Analysis |
| [CWE-652](https://cwe.mitre.org/data/definitions/652.html) | Improper Neutralization of Data within XQuery Expressions | 구현 자료 검토 | Automated Static Analysis |
| [CWE-694](https://cwe.mitre.org/data/definitions/694.html) | Use of Multiple Resources with Duplicate Identifier | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-781](https://cwe.mitre.org/data/definitions/781.html) | Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-790](https://cwe.mitre.org/data/definitions/790.html) | Improper Filtering of Special Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-791](https://cwe.mitre.org/data/definitions/791.html) | Incomplete Filtering of Special Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-792](https://cwe.mitre.org/data/definitions/792.html) | Incomplete Filtering of One or More Instances of Special Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-793](https://cwe.mitre.org/data/definitions/793.html) | Only Filtering One Instance of a Special Element | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-794](https://cwe.mitre.org/data/definitions/794.html) | Incomplete Filtering of Multiple Instances of Special Elements | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-795](https://cwe.mitre.org/data/definitions/795.html) | Only Filtering Special Elements at a Specified Location | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-796](https://cwe.mitre.org/data/definitions/796.html) | Only Filtering Special Elements Relative to a Marker | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-797](https://cwe.mitre.org/data/definitions/797.html) | Only Filtering Special Elements at an Absolute Position | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-838](https://cwe.mitre.org/data/definitions/838.html) | Inappropriate Encoding for Output Context | 구현 자료 검토 | Automated Static Analysis |
| [CWE-839](https://cwe.mitre.org/data/definitions/839.html) | Numeric Range Comparison Without Minimum Check | 구현 자료 검토 | Automated Static Analysis |
| [CWE-914](https://cwe.mitre.org/data/definitions/914.html) | Improper Control of Dynamically-Identified Variables | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-917](https://cwe.mitre.org/data/definitions/917.html) | Improper Neutralization of Special Elements used in an Expression Language Statement | 구현 자료 검토 | Automated Static Analysis |
| [CWE-943](https://cwe.mitre.org/data/definitions/943.html) | Improper Neutralization of Special Elements in Data Query Logic | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1173](https://cwe.mitre.org/data/definitions/1173.html) | Improper Use of Validation Framework | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1174](https://cwe.mitre.org/data/definitions/1174.html) | ASP.NET Misconfiguration: Improper Model Validation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1236](https://cwe.mitre.org/data/definitions/1236.html) | Improper Neutralization of Formula Elements in a CSV File | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1284](https://cwe.mitre.org/data/definitions/1284.html) | Improper Validation of Specified Quantity in Input | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1285](https://cwe.mitre.org/data/definitions/1285.html) | Improper Validation of Specified Index, Position, or Offset in Input | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1286](https://cwe.mitre.org/data/definitions/1286.html) | Improper Validation of Syntactic Correctness of Input | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1287](https://cwe.mitre.org/data/definitions/1287.html) | Improper Validation of Specified Type of Input | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1288](https://cwe.mitre.org/data/definitions/1288.html) | Improper Validation of Consistency within Input | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1289](https://cwe.mitre.org/data/definitions/1289.html) | Improper Validation of Unsafe Equivalence in Input | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) | Improper Neutralization of Special Elements Used in a Template Engine | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html) | Improper Validation of Generative AI Output | 설계 자료 검토<br>실행 관찰 자료 검토 | Dynamic Analysis with Manual Results Interpretation<br>Dynamic Analysis with Automated Results Interpretation<br>Architecture or Design Review |
| [CWE-1427](https://cwe.mitre.org/data/definitions/1427.html) | Improper Neutralization of Input Used for LLM Prompting | 설계 자료 검토<br>실행 관찰 자료 검토 | Dynamic Analysis with Manual Results Interpretation<br>Dynamic Analysis with Automated Results Interpretation<br>Architecture or Design Review |

</details>

<details>
<summary>CWE-710 · Improper Adherence to Coding Standards · 196개 소속</summary>

| 세부 CWE | 공식 이름 | 권장 증거 수집 경로 (대안) | 해당 CWE 자체의 근거 |
| --- | --- | --- | --- |
| [CWE-11](https://cwe.mitre.org/data/definitions/11.html) | ASP.NET Misconfiguration: Creating Debug Binary | 구현 자료 검토 | Automated Static Analysis |
| [CWE-14](https://cwe.mitre.org/data/definitions/14.html) | Compiler Removal of Code to Clear Buffers | 구현 자료 검토<br>실행 관찰 자료 검토 | Black Box<br>White Box |
| [CWE-102](https://cwe.mitre.org/data/definitions/102.html) | Struts: Duplicate Validation Forms | 구현 자료 검토 | Automated Static Analysis |
| [CWE-103](https://cwe.mitre.org/data/definitions/103.html) | Struts: Incomplete validate() Method Definition | 구현 자료 검토 | Automated Static Analysis |
| [CWE-104](https://cwe.mitre.org/data/definitions/104.html) | Struts: Form Bean Does Not Extend Validation Class | 구현 자료 검토 | Automated Static Analysis |
| [CWE-107](https://cwe.mitre.org/data/definitions/107.html) | Struts: Unused Validation Form | 구현 자료 검토 | Automated Static Analysis |
| [CWE-110](https://cwe.mitre.org/data/definitions/110.html) | Struts: Validator Without Form Field | 구현 자료 검토 | Automated Static Analysis<br>Manual Static Analysis |
| [CWE-111](https://cwe.mitre.org/data/definitions/111.html) | Direct Use of Unsafe JNI | 구현 자료 검토 | Automated Static Analysis |
| [CWE-174](https://cwe.mitre.org/data/definitions/174.html) | Double Decoding of the Same Data | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-188](https://cwe.mitre.org/data/definitions/188.html) | Reliance on Data/Memory Layout | 실행 관찰 자료 검토 | Fuzzing<br>Automated Dynamic Analysis |
| [CWE-198](https://cwe.mitre.org/data/definitions/198.html) | Use of Incorrect Byte Ordering | 실행 관찰 자료 검토 | Black Box |
| [CWE-242](https://cwe.mitre.org/data/definitions/242.html) | Use of Inherently Dangerous Function | 구현 자료 검토 | Automated Static Analysis |
| [CWE-243](https://cwe.mitre.org/data/definitions/243.html) | Creation of chroot Jail Without Changing Working Directory | 구현 자료 검토 | Automated Static Analysis |
| [CWE-245](https://cwe.mitre.org/data/definitions/245.html) | J2EE Bad Practices: Direct Management of Connections | 구현 자료 검토 | Automated Static Analysis |
| [CWE-246](https://cwe.mitre.org/data/definitions/246.html) | J2EE Bad Practices: Direct Use of Sockets | 구현 자료 검토 | Automated Static Analysis |
| [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | Execution with Unnecessary Privileges | CVE·벤더 근거로 검토 자료 구체화<br>컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Manual Analysis<br>Black Box<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Automated Results Interpretation<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-253](https://cwe.mitre.org/data/definitions/253.html) | Incorrect Check of Function Return Value | 구현 자료 검토 | Automated Static Analysis |
| [CWE-259](https://cwe.mitre.org/data/definitions/259.html) | Use of Hard-coded Password | CVE·벤더 근거로 검토 자료 구체화<br>구현 자료 검토<br>실행 관찰 자료 검토 | Manual Analysis<br>Black Box<br>Automated Static Analysis |
| [CWE-296](https://cwe.mitre.org/data/definitions/296.html) | Improper Following of a Certificate's Chain of Trust | 구현 자료 검토 | Automated Static Analysis |
| [CWE-304](https://cwe.mitre.org/data/definitions/304.html) | Missing Critical Step in Authentication | 구현 자료 검토 | Automated Static Analysis |
| [CWE-308](https://cwe.mitre.org/data/definitions/308.html) | Use of Single-factor Authentication | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-309](https://cwe.mitre.org/data/definitions/309.html) | Use of Password System for Primary Authentication | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | Use of Hard-coded Cryptographic Key | 구현 자료 검토 | Automated Static Analysis |
| [CWE-325](https://cwe.mitre.org/data/definitions/325.html) | Missing Cryptographic Step | 구현 자료 검토 | Automated Static Analysis |
| [CWE-329](https://cwe.mitre.org/data/definitions/329.html) | Generation of Predictable IV with CBC Mode | 구현 자료 검토 | Automated Static Analysis |
| [CWE-358](https://cwe.mitre.org/data/definitions/358.html) | Improperly Implemented Security Check for Standard | 구현 자료 검토 | Automated Static Analysis |
| [CWE-383](https://cwe.mitre.org/data/definitions/383.html) | J2EE Bad Practices: Direct Use of Threads | 구현 자료 검토 | Automated Static Analysis |
| [CWE-392](https://cwe.mitre.org/data/definitions/392.html) | Missing Report of Error Condition | 구현 자료 검토 | Automated Static Analysis |
| [CWE-393](https://cwe.mitre.org/data/definitions/393.html) | Return of Wrong Status Code | 실행 관찰 자료 검토 | Fuzzing |
| [CWE-415](https://cwe.mitre.org/data/definitions/415.html) | Double Free | 구현 자료 검토<br>실행 관찰 자료 검토 | Fuzzing<br>Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-424](https://cwe.mitre.org/data/definitions/424.html) | Improper Protection of Alternate Path | 구현 자료 검토 | Automated Static Analysis |
| [CWE-425](https://cwe.mitre.org/data/definitions/425.html) | Direct Request | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-440](https://cwe.mitre.org/data/definitions/440.html) | Expected Behavior Violation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-446](https://cwe.mitre.org/data/definitions/446.html) | UI Discrepancy for Security Feature | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-447](https://cwe.mitre.org/data/definitions/447.html) | Unimplemented or Unsupported Feature in UI | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-448](https://cwe.mitre.org/data/definitions/448.html) | Obsolete Feature in UI | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-449](https://cwe.mitre.org/data/definitions/449.html) | The UI Performs the Wrong Action | CVE·벤더 근거로 검토 자료 구체화 | Manual Analysis |
| [CWE-451](https://cwe.mitre.org/data/definitions/451.html) | User Interface (UI) Misrepresentation of Critical Information | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-455](https://cwe.mitre.org/data/definitions/455.html) | Non-exit on Failed Initialization | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-462](https://cwe.mitre.org/data/definitions/462.html) | Duplicate Key in Associative List (Alist) | 구현 자료 검토 | Automated Static Analysis |
| [CWE-474](https://cwe.mitre.org/data/definitions/474.html) | Use of Function with Inconsistent Implementations | 구현 자료 검토 | Automated Static Analysis |
| [CWE-475](https://cwe.mitre.org/data/definitions/475.html) | Undefined Behavior for Input to API | 구현 자료 검토 | Automated Static Analysis |
| [CWE-476](https://cwe.mitre.org/data/definitions/476.html) | NULL Pointer Dereference | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Dynamic Analysis<br>Manual Dynamic Analysis<br>Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-477](https://cwe.mitre.org/data/definitions/477.html) | Use of Obsolete Function | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-484](https://cwe.mitre.org/data/definitions/484.html) | Omitted Break Statement in Switch | 구현 자료 검토<br>실행 관찰 자료 검토 | White Box<br>Black Box<br>Automated Static Analysis |
| [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | Active Debug Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-506](https://cwe.mitre.org/data/definitions/506.html) | Embedded Malicious Code | 컴파일 산출물 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis |
| [CWE-507](https://cwe.mitre.org/data/definitions/507.html) | Trojan Horse | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-508](https://cwe.mitre.org/data/definitions/508.html) | Non-Replicating Malicious Code | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-509](https://cwe.mitre.org/data/definitions/509.html) | Replicating Malicious Code (Virus or Worm) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-510](https://cwe.mitre.org/data/definitions/510.html) | Trapdoor | 컴파일 산출물 검토<br>설계 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-511](https://cwe.mitre.org/data/definitions/511.html) | Logic/Time Bomb | 구현 자료 검토 | Automated Static Analysis |
| [CWE-512](https://cwe.mitre.org/data/definitions/512.html) | Spyware | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-546](https://cwe.mitre.org/data/definitions/546.html) | Suspicious Comment | 구현 자료 검토 | Automated Static Analysis |
| [CWE-547](https://cwe.mitre.org/data/definitions/547.html) | Use of Hard-coded, Security-relevant Constants | 구현 자료 검토 | Automated Static Analysis |
| [CWE-560](https://cwe.mitre.org/data/definitions/560.html) | Use of umask() with chmod-style Argument | 구현 자료 검토 | Automated Static Analysis |
| [CWE-561](https://cwe.mitre.org/data/definitions/561.html) | Dead Code | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Architecture or Design Review<br>Automated Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Manual Results Interpretation<br>Automated Static Analysis<br>Automated Static Analysis - Source Code<br>Dynamic Analysis with Automated Results Interpretation<br>Manual Static Analysis - Source Code |
| [CWE-562](https://cwe.mitre.org/data/definitions/562.html) | Return of Stack Variable Address | 구현 자료 검토<br>실행 관찰 자료 검토 | Fuzzing<br>Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-563](https://cwe.mitre.org/data/definitions/563.html) | Assignment to Variable without Use | 구현 자료 검토 | Automated Static Analysis |
| [CWE-568](https://cwe.mitre.org/data/definitions/568.html) | finalize() Method Without super.finalize() | 구현 자료 검토 | Automated Static Analysis |
| [CWE-570](https://cwe.mitre.org/data/definitions/570.html) | Expression is Always False | 구현 자료 검토 | Automated Static Analysis |
| [CWE-571](https://cwe.mitre.org/data/definitions/571.html) | Expression is Always True | 구현 자료 검토 | Automated Static Analysis |
| [CWE-573](https://cwe.mitre.org/data/definitions/573.html) | Improper Following of Specification by Caller | 구현 자료 검토 | Automated Static Analysis |
| [CWE-574](https://cwe.mitre.org/data/definitions/574.html) | EJB Bad Practices: Use of Synchronization Primitives | 구현 자료 검토 | Automated Static Analysis |
| [CWE-575](https://cwe.mitre.org/data/definitions/575.html) | EJB Bad Practices: Use of AWT Swing | 구현 자료 검토 | Automated Static Analysis |
| [CWE-576](https://cwe.mitre.org/data/definitions/576.html) | EJB Bad Practices: Use of Java I/O | 구현 자료 검토 | Automated Static Analysis |
| [CWE-577](https://cwe.mitre.org/data/definitions/577.html) | EJB Bad Practices: Use of Sockets | 구현 자료 검토 | Automated Static Analysis |
| [CWE-578](https://cwe.mitre.org/data/definitions/578.html) | EJB Bad Practices: Use of Class Loader | 구현 자료 검토 | Automated Static Analysis |
| [CWE-579](https://cwe.mitre.org/data/definitions/579.html) | J2EE Bad Practices: Non-serializable Object Stored in Session | 구현 자료 검토 | Automated Static Analysis |
| [CWE-580](https://cwe.mitre.org/data/definitions/580.html) | clone() Method Without super.clone() | 구현 자료 검토 | Automated Static Analysis |
| [CWE-581](https://cwe.mitre.org/data/definitions/581.html) | Object Model Violation: Just One of Equals and Hashcode Defined | 구현 자료 검토 | Automated Static Analysis |
| [CWE-585](https://cwe.mitre.org/data/definitions/585.html) | Empty Synchronized Block | 구현 자료 검토 | Automated Static Analysis |
| [CWE-586](https://cwe.mitre.org/data/definitions/586.html) | Explicit Call to Finalize() | 구현 자료 검토 | Automated Static Analysis |
| [CWE-587](https://cwe.mitre.org/data/definitions/587.html) | Assignment of a Fixed Address to a Pointer | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-588](https://cwe.mitre.org/data/definitions/588.html) | Attempt to Access Child of a Non-structure Pointer | 구현 자료 검토 | Automated Static Analysis |
| [CWE-589](https://cwe.mitre.org/data/definitions/589.html) | Call to Non-ubiquitous API | 구현 자료 검토 | Automated Static Analysis |
| [CWE-594](https://cwe.mitre.org/data/definitions/594.html) | J2EE Framework: Saving Unserializable Objects to Disk | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-605](https://cwe.mitre.org/data/definitions/605.html) | Multiple Binds to the Same Port | 구현 자료 검토 | Automated Static Analysis |
| [CWE-628](https://cwe.mitre.org/data/definitions/628.html) | Function Call with Incorrectly Specified Arguments | CVE·벤더 근거로 검토 자료 구체화 | Other |
| [CWE-636](https://cwe.mitre.org/data/definitions/636.html) | Not Failing Securely | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-637](https://cwe.mitre.org/data/definitions/637.html) | Unnecessary Complexity in Protection Mechanism (Not Using 'Economy of Mechanism') | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-638](https://cwe.mitre.org/data/definitions/638.html) | Not Using Complete Mediation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-653](https://cwe.mitre.org/data/definitions/653.html) | Improper Isolation or Compartmentalization | 컴파일 산출물 검토<br>설계 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Source Code<br>Architecture or Design Review |
| [CWE-654](https://cwe.mitre.org/data/definitions/654.html) | Reliance on a Single Factor in a Security Decision | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-655](https://cwe.mitre.org/data/definitions/655.html) | Insufficient Psychological Acceptability | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-656](https://cwe.mitre.org/data/definitions/656.html) | Reliance on Security Through Obscurity | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-657](https://cwe.mitre.org/data/definitions/657.html) | Violation of Secure Design Principles | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-671](https://cwe.mitre.org/data/definitions/671.html) | Lack of Administrator Control over Security | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-675](https://cwe.mitre.org/data/definitions/675.html) | Multiple Operations on Resource in Single-Operation Context | 구현 자료 검토 | Automated Static Analysis |
| [CWE-676](https://cwe.mitre.org/data/definitions/676.html) | Use of Potentially Dangerous Function | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-683](https://cwe.mitre.org/data/definitions/683.html) | Function Call With Incorrect Order of Arguments | CVE·벤더 근거로 검토 자료 구체화 | Automated Analysis<br>Automated Analysis |
| [CWE-684](https://cwe.mitre.org/data/definitions/684.html) | Incorrect Provision of Specified Functionality | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-685](https://cwe.mitre.org/data/definitions/685.html) | Function Call With Incorrect Number of Arguments | CVE·벤더 근거로 검토 자료 구체화 | Other |
| [CWE-686](https://cwe.mitre.org/data/definitions/686.html) | Function Call With Incorrect Argument Type | CVE·벤더 근거로 검토 자료 구체화 | Other |
| [CWE-687](https://cwe.mitre.org/data/definitions/687.html) | Function Call With Incorrectly Specified Argument Value | 구현 자료 검토 | Manual Static Analysis |
| [CWE-688](https://cwe.mitre.org/data/definitions/688.html) | Function Call With Incorrect Variable or Reference as Argument | CVE·벤더 근거로 검토 자료 구체화 | Other |
| [CWE-694](https://cwe.mitre.org/data/definitions/694.html) | Use of Multiple Resources with Duplicate Identifier | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-695](https://cwe.mitre.org/data/definitions/695.html) | Use of Low-Level Functionality | 구현 자료 검토 | Automated Static Analysis |
| [CWE-733](https://cwe.mitre.org/data/definitions/733.html) | Compiler Optimization Removal or Modification of Security-critical Code | 구현 자료 검토<br>실행 관찰 자료 검토 | Black Box<br>White Box |
| [CWE-758](https://cwe.mitre.org/data/definitions/758.html) | Reliance on Undefined, Unspecified, or Implementation-Defined Behavior | 실행 관찰 자료 검토 | Fuzzing |
| [CWE-764](https://cwe.mitre.org/data/definitions/764.html) | Multiple Locks of a Critical Resource | 구현 자료 검토 | Automated Static Analysis |
| [CWE-765](https://cwe.mitre.org/data/definitions/765.html) | Multiple Unlocks of a Critical Resource | 구현 자료 검토 | Automated Static Analysis |
| [CWE-766](https://cwe.mitre.org/data/definitions/766.html) | Critical Data Element Declared Public | 구현 자료 검토 | Automated Static Analysis |
| [CWE-785](https://cwe.mitre.org/data/definitions/785.html) | Use of Path Manipulation Function without Maximum-sized Buffer | 구현 자료 검토 | Automated Static Analysis |
| [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | Use of Hard-coded Credentials | 컴파일 산출물 검토<br>설계 자료 검토<br>구현 자료 검토<br>실행 관찰 자료 검토<br>소스 검토 | Black Box<br>Automated Static Analysis<br>Manual Static Analysis<br>Manual Dynamic Analysis<br>Automated Static Analysis - Binary or Bytecode<br>Manual Static Analysis - Binary or Bytecode<br>Dynamic Analysis with Manual Results Interpretation<br>Manual Static Analysis - Source Code<br>Automated Static Analysis - Source Code<br>Automated Static Analysis<br>Architecture or Design Review |
| [CWE-912](https://cwe.mitre.org/data/definitions/912.html) | Hidden Functionality | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1007](https://cwe.mitre.org/data/definitions/1007.html) | Insufficient Visual Distinction of Homoglyphs Presented to User | 실행 관찰 자료 검토 | Manual Dynamic Analysis |
| [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | Improper Restriction of Rendered UI Layers or Frames | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1037](https://cwe.mitre.org/data/definitions/1037.html) | Processor Optimization Removal or Modification of Security-critical Code | 구현 자료 검토 | White Box |
| [CWE-1038](https://cwe.mitre.org/data/definitions/1038.html) | Insecure Automated Optimizations | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1041](https://cwe.mitre.org/data/definitions/1041.html) | Use of Redundant Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1043](https://cwe.mitre.org/data/definitions/1043.html) | Data Element Aggregating an Excessively Large Number of Non-Primitive Elements | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1044](https://cwe.mitre.org/data/definitions/1044.html) | Architecture with Number of Horizontal Layers Outside of Expected Range | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1045](https://cwe.mitre.org/data/definitions/1045.html) | Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1047](https://cwe.mitre.org/data/definitions/1047.html) | Modules with Circular Dependencies | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1048](https://cwe.mitre.org/data/definitions/1048.html) | Invokable Control Element with Large Number of Outward Calls | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1053](https://cwe.mitre.org/data/definitions/1053.html) | Missing Documentation for Design | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1054](https://cwe.mitre.org/data/definitions/1054.html) | Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1055](https://cwe.mitre.org/data/definitions/1055.html) | Multiple Inheritance from Concrete Classes | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1056](https://cwe.mitre.org/data/definitions/1056.html) | Invokable Control Element with Variadic Parameters | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1057](https://cwe.mitre.org/data/definitions/1057.html) | Data Access Operations Outside of Expected Data Manager Component | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1059](https://cwe.mitre.org/data/definitions/1059.html) | Insufficient Technical Documentation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1060](https://cwe.mitre.org/data/definitions/1060.html) | Excessive Number of Inefficient Server-Side Data Accesses | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1061](https://cwe.mitre.org/data/definitions/1061.html) | Insufficient Encapsulation | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1062](https://cwe.mitre.org/data/definitions/1062.html) | Parent Class with References to Child Class | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1064](https://cwe.mitre.org/data/definitions/1064.html) | Invokable Control Element with Signature Containing an Excessive Number of Parameters | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1065](https://cwe.mitre.org/data/definitions/1065.html) | Runtime Resource Management Control Element in a Component Built to Run on Application Servers | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1066](https://cwe.mitre.org/data/definitions/1066.html) | Missing Serialization Control Element | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1068](https://cwe.mitre.org/data/definitions/1068.html) | Inconsistency Between Implementation and Documented Design | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1069](https://cwe.mitre.org/data/definitions/1069.html) | Empty Exception Block | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1070](https://cwe.mitre.org/data/definitions/1070.html) | Serializable Data Element Containing non-Serializable Item Elements | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1071](https://cwe.mitre.org/data/definitions/1071.html) | Empty Code Block | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1074](https://cwe.mitre.org/data/definitions/1074.html) | Class with Excessively Deep Inheritance | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1075](https://cwe.mitre.org/data/definitions/1075.html) | Unconditional Control Flow Transfer outside of Switch Block | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1076](https://cwe.mitre.org/data/definitions/1076.html) | Insufficient Adherence to Expected Conventions | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1078](https://cwe.mitre.org/data/definitions/1078.html) | Inappropriate Source Code Style or Formatting | 구현 자료 검토<br>소스 검토 | Automated Static Analysis<br>Automated Static Analysis - Source Code |
| [CWE-1079](https://cwe.mitre.org/data/definitions/1079.html) | Parent Class without Virtual Destructor Method | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1080](https://cwe.mitre.org/data/definitions/1080.html) | Source Code File with Excessive Number of Lines of Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1082](https://cwe.mitre.org/data/definitions/1082.html) | Class Instance Self Destruction Control Element | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1083](https://cwe.mitre.org/data/definitions/1083.html) | Data Access from Outside Expected Data Manager Component | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1085](https://cwe.mitre.org/data/definitions/1085.html) | Invokable Control Element with Excessive Volume of Commented-out Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1086](https://cwe.mitre.org/data/definitions/1086.html) | Class with Excessive Number of Child Classes | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1087](https://cwe.mitre.org/data/definitions/1087.html) | Class with Virtual Method without a Virtual Destructor | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1090](https://cwe.mitre.org/data/definitions/1090.html) | Method Containing Access of a Member Element from Another Class | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1091](https://cwe.mitre.org/data/definitions/1091.html) | Use of Object without Invoking Destructor Method | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1092](https://cwe.mitre.org/data/definitions/1092.html) | Use of Same Invokable Control Element in Multiple Architectural Layers | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1093](https://cwe.mitre.org/data/definitions/1093.html) | Excessively Complex Data Representation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1095](https://cwe.mitre.org/data/definitions/1095.html) | Loop Condition Value Update within the Loop | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1097](https://cwe.mitre.org/data/definitions/1097.html) | Persistent Storable Data Element without Associated Comparison Control Element | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1098](https://cwe.mitre.org/data/definitions/1098.html) | Data Element containing Pointer Item without Proper Copy Control Element | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1099](https://cwe.mitre.org/data/definitions/1099.html) | Inconsistent Naming Conventions for Identifiers | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1100](https://cwe.mitre.org/data/definitions/1100.html) | Insufficient Isolation of System-Dependent Functions | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1101](https://cwe.mitre.org/data/definitions/1101.html) | Reliance on Runtime Component in Generated Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1102](https://cwe.mitre.org/data/definitions/1102.html) | Reliance on Machine-Dependent Data Representation | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1103](https://cwe.mitre.org/data/definitions/1103.html) | Use of Platform-Dependent Third Party Components | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) | Use of Unmaintained Third Party Components | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1105](https://cwe.mitre.org/data/definitions/1105.html) | Insufficient Encapsulation of Machine-Dependent Functionality | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1106](https://cwe.mitre.org/data/definitions/1106.html) | Insufficient Use of Symbolic Constants | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1107](https://cwe.mitre.org/data/definitions/1107.html) | Insufficient Isolation of Symbolic Constant Definitions | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1108](https://cwe.mitre.org/data/definitions/1108.html) | Excessive Reliance on Global Variables | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1109](https://cwe.mitre.org/data/definitions/1109.html) | Use of Same Variable for Multiple Purposes | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1110](https://cwe.mitre.org/data/definitions/1110.html) | Incomplete Design Documentation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1111](https://cwe.mitre.org/data/definitions/1111.html) | Incomplete I/O Documentation | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1112](https://cwe.mitre.org/data/definitions/1112.html) | Incomplete Documentation of Program Execution | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1113](https://cwe.mitre.org/data/definitions/1113.html) | Inappropriate Comment Style | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1114](https://cwe.mitre.org/data/definitions/1114.html) | Inappropriate Whitespace Style | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1115](https://cwe.mitre.org/data/definitions/1115.html) | Source Code Element without Standard Prologue | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1116](https://cwe.mitre.org/data/definitions/1116.html) | Inaccurate Source Code Comments | 구현 자료 검토 | Manual Static Analysis |
| [CWE-1117](https://cwe.mitre.org/data/definitions/1117.html) | Callable with Insufficient Behavioral Summary | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1118](https://cwe.mitre.org/data/definitions/1118.html) | Insufficient Documentation of Error Handling Techniques | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1119](https://cwe.mitre.org/data/definitions/1119.html) | Excessive Use of Unconditional Branching | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1120](https://cwe.mitre.org/data/definitions/1120.html) | Excessive Code Complexity | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1121](https://cwe.mitre.org/data/definitions/1121.html) | Excessive McCabe Cyclomatic Complexity | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1122](https://cwe.mitre.org/data/definitions/1122.html) | Excessive Halstead Complexity | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1123](https://cwe.mitre.org/data/definitions/1123.html) | Excessive Use of Self-Modifying Code | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1124](https://cwe.mitre.org/data/definitions/1124.html) | Excessively Deep Nesting | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1125](https://cwe.mitre.org/data/definitions/1125.html) | Excessive Attack Surface | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1126](https://cwe.mitre.org/data/definitions/1126.html) | Declaration of Variable with Unnecessarily Wide Scope | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1127](https://cwe.mitre.org/data/definitions/1127.html) | Compilation with Insufficient Warnings or Errors | CVE·벤더 근거로 검토 자료 구체화 | Manual Analysis |
| [CWE-1164](https://cwe.mitre.org/data/definitions/1164.html) | Irrelevant Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1177](https://cwe.mitre.org/data/definitions/1177.html) | Use of Prohibited Code | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1189](https://cwe.mitre.org/data/definitions/1189.html) | Improper Isolation of Shared Resources on System-on-a-Chip (SoC) | 실행 관찰 자료 검토 | Automated Dynamic Analysis |
| [CWE-1192](https://cwe.mitre.org/data/definitions/1192.html) | Improper Identifier for IP Block used in System-On-Chip (SOC) | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1209](https://cwe.mitre.org/data/definitions/1209.html) | Failure to Disable Reserved Bits | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1242](https://cwe.mitre.org/data/definitions/1242.html) | Inclusion of Undocumented Features or Chicken Bits | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1245](https://cwe.mitre.org/data/definitions/1245.html) | Improper Finite State Machines (FSMs) in Hardware Logic | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1277](https://cwe.mitre.org/data/definitions/1277.html) | Firmware Not Updateable | CVE·벤더 근거로 검토 자료 구체화<br>설계 자료 검토<br>실행 관찰 자료 검토 | Manual Analysis<br>Architecture or Design Review<br>Manual Dynamic Analysis |
| [CWE-1303](https://cwe.mitre.org/data/definitions/1303.html) | Non-Transparent Sharing of Microarchitectural Resources | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1310](https://cwe.mitre.org/data/definitions/1310.html) | Missing Ability to Patch ROM Code | CVE·벤더 메커니즘 우선 확인 | 공식 탐지 방법 미기재: 정의 원문 + CVE·벤더 근거를 먼저 확인 |
| [CWE-1329](https://cwe.mitre.org/data/definitions/1329.html) | Reliance on Component That is Not Updateable | 설계 자료 검토 | Architecture or Design Review |
| [CWE-1331](https://cwe.mitre.org/data/definitions/1331.html) | Improper Isolation of Shared Resources in Network On Chip (NoC) | CVE·벤더 근거로 검토 자료 구체화 | Manual Analysis |
| [CWE-1341](https://cwe.mitre.org/data/definitions/1341.html) | Multiple Releases of Same Resource or Handle | 구현 자료 검토<br>실행 관찰 자료 검토 | Automated Static Analysis<br>Automated Dynamic Analysis |
| [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) | Reliance on Insufficiently Trustworthy Component | 구현 자료 검토 | Automated Static Analysis |
| [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | Dependency on Vulnerable Third-Party Component | CVE·벤더 근거로 검토 자료 구체화 | Automated Analysis |
| [CWE-1431](https://cwe.mitre.org/data/definitions/1431.html) | Driving Intermediate Cryptographic State/Results to Hardware Module Outputs | CVE·벤더 근거로 검토 자료 구체화<br>형식 검증 자료 검토<br>시뮬레이션 자료 검토<br>소스 검토 | Automated Static Analysis - Source Code<br>Simulation / Emulation<br>Formal Verification<br>Manual Analysis |
| [CWE-1434](https://cwe.mitre.org/data/definitions/1434.html) | Insecure Setting of Generative AI/ML Model Inference Parameters | 실행 관찰 자료 검토 | Automated Dynamic Analysis<br>Manual Dynamic Analysis |

</details>


<!-- END GENERATED SECTION 3 RESULTS -->

### 상속 원칙과 예외

증거 계획은 해당 항목에 직접 기재된 자료만 근거로 한다. 공식 ChildOf 관계에서 분석 방법·운영 충분성·소스 필수 여부를 상속하지 않는다. 다중 Pillar 소속은 그대로 유지한다.

## 4. 현재 라우터 동작

<!-- BEGIN GENERATED SECTION 4 RESULTS -->

### 4.1 현재 실행 결과

944개 증거 수집 계획을 제공한다. 탐지 방법은 가능한 자료 수집 대안이지 최종 필수 증거의 선언이 아니다. 자산별 CVE 메커니즘에 적합한 방법과 자료가 선택되기 전에는 자동 상태 판단 경로로 전환하지 않는다.

| 전체 고유 세부 CWE | 최종 소스 필수 자동 확정 | 운영만으로 충분하다고 확정 | CVE별 증거 적합성 확인 필요 |
| ---: | ---: | ---: | ---: |
| 944 | 0 | 0 | 944 |

이 숫자는 평가 정확도가 아니다. 기존의 584/144/26/190 경로 집계도 현재 결과로 사용하지 않는다.

### 4.2 실제/통제 입력 재실행

실제 CVE는 로컬 스냅샷 입력이며, 통제 입력은 구성한 사례다. 모두 현재 라우터의 미지정 처리를 확인하는 용도이며 정답 데이터가 아니다.

| 입력 | 구분 | 보고된 CWE | 소스 결과 없음 | 소스 결과 있다고 가정 |
| --- | --- | --- | --- | --- |
| CVE-2023-27309 | 실제 CVE 로컬 기록 | CWE-862 | 분류 유보 | 분류 유보 |
| CVE-2023-27411 | 실제 CVE 로컬 기록 | CWE-89 | 분류 유보 | 분류 유보 |
| CVE-2026-24455 | 실제 CVE 로컬 기록 | CWE-319 | 분류 유보 | 분류 유보 |
| CVE-2022-21940 | 실제 CVE 로컬 기록 | CWE-614, CWE-311 | 분류 유보 | 분류 유보 |
| CVE-2026-9651 | 실제 CVE 로컬 기록 | CWE-732 | 분류 유보 | 분류 유보 |
| CVE-2026-61892 | 실제 CVE 로컬 기록 | CWE-732 | 분류 유보 | 분류 유보 |
| CVE-2019-1563 | 실제 CVE 로컬 기록 | CWE-203, CWE-327 | 분류 유보 | 분류 유보 |
| CVE-2020-10932 | 실제 CVE 로컬 기록 | CWE-203, CWE-327 | 분류 유보 | 분류 유보 |
| control-memory | 구성한 통제 입력 | CWE-787 | 분류 유보 | 분류 유보 |
| control-remote-memory | 구성한 통제 입력 | CWE-787 | 분류 유보 | 분류 유보 |
| control-authorization-code | 구성한 통제 입력 | CWE-862 | 분류 유보 | 분류 유보 |
| control-authorization-config | 구성한 통제 입력 | CWE-862 | 분류 유보 | 분류 유보 |
| control-crypto-unspecified | 구성한 통제 입력 | CWE-327 | 분류 유보 | 분류 유보 |
| control-crypto-config | 구성한 통제 입력 | CWE-327 | 분류 유보 | 분류 유보 |
| control-default-key | 구성한 통제 입력 | CWE-1394 | 분류 유보 | 분류 유보 |
| control-embedded-key | 구성한 통제 입력 | CWE-1394 | 분류 유보 | 분류 유보 |
| control-java-declaration | 구성한 통제 입력 | CWE-493 | 분류 유보 | 분류 유보 |
| control-hardware | 구성한 통제 입력 | CWE-1252 | 분류 유보 | 분류 유보 |
| control-reported-cwe-preserved | 구성한 통제 입력 | CWE-119 | 분류 유보 | 분류 유보 |
| control-mixed-unknown | 구성한 통제 입력 | CWE-787, CWE-999999 | 분류 유보 | 분류 유보 |

신규 검토에는 해당 CWE의 증거 수집 계획을 함께 제공하지만, 최종 필수 증거가 정해지지 않았으므로 `routing_unknown` / `under_investigation`으로 시작한다. 원문에 연결된 CWE ID를 바꾸지 않는다. 실행 관찰 자료와 운영자 질문은 같은 것이 아니며, 이 계획은 동적 시험·바이너리 분석을 자동 실행하지 않는다.

전체 입력과 반환값: [criteria_results.json](../data/cwe_routing/v2/criteria_results.json).
재생성: `python tools/build_cwe_evidence_policy.py`.

정책 버전: `cwe-evidence-v2.2-unassigned` / 정책 해시: `cc13abce870946859766f8165eb2add8407b08c13747f42d704bc280eb240f58`.

<!-- END GENERATED SECTION 4 RESULTS -->

## 5. CVE에 기록된 CWE만 사용

NVD·CISA 등 CVE 원문에 이미 기록된 CWE ID와 출처를 사용한다. 이 시스템은 CWE를 새로 부여하거나 기존 ID를 다른 CWE로 교체하지 않는다. Pillar는 그 ID의 공식 상위 관계를 조회한 결과이며 새 CWE 부여가 아니다.

CWE가 제공되지 않으면 미확인으로 표시한다. 설명문이나 LLM으로 CWE를 추측하지 않는다. CWE 부여 등급표·등급 집계는 문서와 웹·파생 출력에서 제거했다.

## 6. 실행 기능과 분류 기능의 구분

소스 분석기, 운영 질문/답변 처리기, 상태 결합·검증기, 최종 VEX 작성·출력 기능은 남아 있다. 네 가지 증거 워크플로의 실행 구조도 남아 있지만, 현재 CWE로부터 해당 경로를 자동 선택하는 연결은 없다. 신규 CWE-first 검토에서 소스 업로드나 운영 질문 버튼으로 미지정 경로를 우회하지 않는다.

신규 검토는 `under_investigation`으로 남는다. 기존 정책의 검토 결과는 자동 재사용하지 않고 정책 버전/해시 변경을 표시한다. 역사적 원본 기록은 덮어쓰지 않는다.

## 7. 검증 범위

검사는 공식 자료 보존, 944개 개별 증거 계획과 직접 원문 일치, 최종 요구 미확정 상태, 소스 유무·키워드·사용자 제공 요구 필드가 경로를 임의로 확정하지 못함, 운영 질문/소스 결과로 미지정 경로를 우회하지 못함을 확인한다. 이 검사는 분류 정확도나 VEX 정확도가 아니다.

## 8. 파일과 재현

- 공식 계층: `data/cwe_taxonomy/v5.0/catalog.json`
- 공식 메타데이터: `data/cwe_taxonomy/v5.0/evidence_metadata.json`
- 현재 상태 정책: `data/cwe_evidence_policy_v2.json`
- 944개 레코드: `data/cwe_routing/v2/profiles.json`, `profiles.csv`, `summary.json`
- 현재 실행 기록: `data/cwe_routing/v2/criteria_results.json`
- 구현: `src/cwe_evidence_policy.py`, `src/vex_routing.py`
- 재생성: `python tools/build_cwe_evidence_policy.py`

자료 버전은 공식 CWE v5.0 스냅샷에 고정되어 있다. 분류표의 공식 소속 범위와 프로젝트가 판단한 분석 방법을 구분한다.
