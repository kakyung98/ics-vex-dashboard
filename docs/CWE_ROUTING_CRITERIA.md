# CWE 기반 증거 경로 기준의 현재 상태

정책 버전: `cwe-evidence-v2.2-unassigned` / 갱신: **2026-11-06 (KST)**.

## 1. 현재 사용 범위

CVE에 보고된 CWE ID, 공식 정의, View 1000의 계층과 Pillar 관계를 보존한다. 이 자료만으로 소스 분석 또는 운영 검토가 충분하다고 결정하지 않는다. **자동 증거 경로 분류는 중단했다.**

## 2. 삭제한 설명 불충분한 기준

| 삭제한 항목 | 삭제 이유 |
| --- | --- |
| 수작업 CWE 기준점 → 소스/운영 지정 | 각 유형의 필수 증거를 도출한 검증 가능한 근거가 확립되지 않음 |
| 가장 가까운 상위 CWE에서 분석 방법 상속 | 공식 ChildOf 관계가 동일한 증거 요구를 보장하지 않음 |
| 운영 전용 26개 허용 목록 | 운영 기록만으로 확인 가능한 범위와 남은 구현 불확실성이 유형별로 검증되지 않음 |
| 구현/설정 키워드 정규식 보정 | 단어의 출현만으로 해당 자산의 필수 증거나 운영 검토의 충분성을 증명하지 못함 |
| 하드웨어 명칭/HDL로 증거 경로 지정 | 관련 메타데이터와 실제 필요한 분석 방법을 동일시하는 추론 근거가 부족함 |
| 기존 728·26·190 및 직접/상속 분류 성과 표시 | 위 규칙의 산출물이며 독립적으로 정당화된 분류 결과가 아님 |

이를 대신할 새 분류를 임의로 추가하지 않았다. 현재 세부 CWE 944개는 증거 경로 **미지정**이다. CWE 공식 정의와 계층이 없다는 뜻이 아니다.

## 3. 공식 CWE 자료와 현재 상태

<!-- BEGIN GENERATED SECTION 3 RESULTS -->

### 3.1 공식 계층의 범위

10개 Pillar와 고유 세부 CWE 944개의 공식 소속 관계만 유지한다. 다중 소속을 포함한 행은 1,201개다. 아래 미확정 수는 취약점 분석 실패율이나 정확도가 아니라 **경로 기준 미지정 상태**다.

| Pillar | 공식 이름 | 세부 CWE 소속 수 | 증거 경로 미지정 |
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

기존 소스 728·운영 26·전문/메커니즘 190 분류와 직접 243·상속 701 집계는 삭제했다. 공식 계층은 증거 수집 방법을 보장하지 않으므로 분석 방법을 상속하지 않는다.

<details>
<summary>CWE-284 · Improper Access Control · 182개 소속</summary>

| 세부 CWE | 공식 이름 | 현재 증거 경로 |
| --- | --- | --- |
| [CWE-9](https://cwe.mitre.org/data/definitions/9.html) | J2EE Misconfiguration: Weak Access Permissions for EJB Methods | 미지정 |
| [CWE-13](https://cwe.mitre.org/data/definitions/13.html) | ASP.NET Misconfiguration: Password in Configuration File | 미지정 |
| [CWE-202](https://cwe.mitre.org/data/definitions/202.html) | Exposure of Sensitive Information Through Data Queries | 미지정 |
| [CWE-219](https://cwe.mitre.org/data/definitions/219.html) | Storage of File with Sensitive Data Under Web Root | 미지정 |
| [CWE-220](https://cwe.mitre.org/data/definitions/220.html) | Storage of File With Sensitive Data Under FTP Root | 미지정 |
| [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | Execution with Unnecessary Privileges | 미지정 |
| [CWE-256](https://cwe.mitre.org/data/definitions/256.html) | Plaintext Storage of a Password | 미지정 |
| [CWE-257](https://cwe.mitre.org/data/definitions/257.html) | Storing Passwords in a Recoverable Format | 미지정 |
| [CWE-258](https://cwe.mitre.org/data/definitions/258.html) | Empty Password in Configuration File | 미지정 |
| [CWE-259](https://cwe.mitre.org/data/definitions/259.html) | Use of Hard-coded Password | 미지정 |
| [CWE-260](https://cwe.mitre.org/data/definitions/260.html) | Password in Configuration File | 미지정 |
| [CWE-261](https://cwe.mitre.org/data/definitions/261.html) | Weak Encoding for Password | 미지정 |
| [CWE-262](https://cwe.mitre.org/data/definitions/262.html) | Not Using Password Aging | 미지정 |
| [CWE-263](https://cwe.mitre.org/data/definitions/263.html) | Password Aging with Long Expiration | 미지정 |
| [CWE-266](https://cwe.mitre.org/data/definitions/266.html) | Incorrect Privilege Assignment | 미지정 |
| [CWE-267](https://cwe.mitre.org/data/definitions/267.html) | Privilege Defined With Unsafe Actions | 미지정 |
| [CWE-268](https://cwe.mitre.org/data/definitions/268.html) | Privilege Chaining | 미지정 |
| [CWE-269](https://cwe.mitre.org/data/definitions/269.html) | Improper Privilege Management | 미지정 |
| [CWE-270](https://cwe.mitre.org/data/definitions/270.html) | Privilege Context Switching Error | 미지정 |
| [CWE-271](https://cwe.mitre.org/data/definitions/271.html) | Privilege Dropping / Lowering Errors | 미지정 |
| [CWE-272](https://cwe.mitre.org/data/definitions/272.html) | Least Privilege Violation | 미지정 |
| [CWE-273](https://cwe.mitre.org/data/definitions/273.html) | Improper Check for Dropped Privileges | 미지정 |
| [CWE-274](https://cwe.mitre.org/data/definitions/274.html) | Improper Handling of Insufficient Privileges | 미지정 |
| [CWE-276](https://cwe.mitre.org/data/definitions/276.html) | Incorrect Default Permissions | 미지정 |
| [CWE-277](https://cwe.mitre.org/data/definitions/277.html) | Insecure Inherited Permissions | 미지정 |
| [CWE-278](https://cwe.mitre.org/data/definitions/278.html) | Insecure Preserved Inherited Permissions | 미지정 |
| [CWE-279](https://cwe.mitre.org/data/definitions/279.html) | Incorrect Execution-Assigned Permissions | 미지정 |
| [CWE-281](https://cwe.mitre.org/data/definitions/281.html) | Improper Preservation of Permissions | 미지정 |
| [CWE-282](https://cwe.mitre.org/data/definitions/282.html) | Improper Ownership Management | 미지정 |
| [CWE-283](https://cwe.mitre.org/data/definitions/283.html) | Unverified Ownership | 미지정 |
| [CWE-285](https://cwe.mitre.org/data/definitions/285.html) | Improper Authorization | 미지정 |
| [CWE-286](https://cwe.mitre.org/data/definitions/286.html) | Incorrect User Management | 미지정 |
| [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | Improper Authentication | 미지정 |
| [CWE-288](https://cwe.mitre.org/data/definitions/288.html) | Authentication Bypass Using an Alternate Path or Channel | 미지정 |
| [CWE-289](https://cwe.mitre.org/data/definitions/289.html) | Authentication Bypass by Alternate Name | 미지정 |
| [CWE-290](https://cwe.mitre.org/data/definitions/290.html) | Authentication Bypass by Spoofing | 미지정 |
| [CWE-291](https://cwe.mitre.org/data/definitions/291.html) | Reliance on IP Address for Authentication | 미지정 |
| [CWE-293](https://cwe.mitre.org/data/definitions/293.html) | Using Referer Field for Authentication | 미지정 |
| [CWE-294](https://cwe.mitre.org/data/definitions/294.html) | Authentication Bypass by Capture-replay | 미지정 |
| [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | Improper Certificate Validation | 미지정 |
| [CWE-296](https://cwe.mitre.org/data/definitions/296.html) | Improper Following of a Certificate's Chain of Trust | 미지정 |
| [CWE-297](https://cwe.mitre.org/data/definitions/297.html) | Improper Validation of Certificate with Host Mismatch | 미지정 |
| [CWE-298](https://cwe.mitre.org/data/definitions/298.html) | Improper Validation of Certificate Expiration | 미지정 |
| [CWE-299](https://cwe.mitre.org/data/definitions/299.html) | Improper Check for Certificate Revocation | 미지정 |
| [CWE-300](https://cwe.mitre.org/data/definitions/300.html) | Channel Accessible by Non-Endpoint | 미지정 |
| [CWE-301](https://cwe.mitre.org/data/definitions/301.html) | Reflection Attack in an Authentication Protocol | 미지정 |
| [CWE-302](https://cwe.mitre.org/data/definitions/302.html) | Authentication Bypass by Assumed-Immutable Data | 미지정 |
| [CWE-303](https://cwe.mitre.org/data/definitions/303.html) | Incorrect Implementation of Authentication Algorithm | 미지정 |
| [CWE-304](https://cwe.mitre.org/data/definitions/304.html) | Missing Critical Step in Authentication | 미지정 |
| [CWE-305](https://cwe.mitre.org/data/definitions/305.html) | Authentication Bypass by Primary Weakness | 미지정 |
| [CWE-306](https://cwe.mitre.org/data/definitions/306.html) | Missing Authentication for Critical Functionality | 미지정 |
| [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | Improper Restriction of Excessive Authentication Attempts | 미지정 |
| [CWE-308](https://cwe.mitre.org/data/definitions/308.html) | Use of Single-factor Authentication | 미지정 |
| [CWE-309](https://cwe.mitre.org/data/definitions/309.html) | Use of Password System for Primary Authentication | 미지정 |
| [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | Use of Hard-coded Cryptographic Key | 미지정 |
| [CWE-322](https://cwe.mitre.org/data/definitions/322.html) | Key Exchange without Entity Authentication | 미지정 |
| [CWE-346](https://cwe.mitre.org/data/definitions/346.html) | Origin Validation Error | 미지정 |
| [CWE-350](https://cwe.mitre.org/data/definitions/350.html) | Reliance on Reverse DNS Resolution for a Security-Critical Action | 미지정 |
| [CWE-356](https://cwe.mitre.org/data/definitions/356.html) | Missing User Interaction for Potentially Unsafe Action | 미지정 |
| [CWE-370](https://cwe.mitre.org/data/definitions/370.html) | Missing Check for Certificate Revocation after Initial Check | 미지정 |
| [CWE-384](https://cwe.mitre.org/data/definitions/384.html) | Session Fixation | 미지정 |
| [CWE-419](https://cwe.mitre.org/data/definitions/419.html) | Unprotected Primary Channel | 미지정 |
| [CWE-420](https://cwe.mitre.org/data/definitions/420.html) | Unprotected Alternate Channel | 미지정 |
| [CWE-421](https://cwe.mitre.org/data/definitions/421.html) | Race Condition During Access to Alternate Channel | 미지정 |
| [CWE-422](https://cwe.mitre.org/data/definitions/422.html) | Unprotected Windows Messaging Channel | 미지정 |
| [CWE-424](https://cwe.mitre.org/data/definitions/424.html) | Improper Protection of Alternate Path | 미지정 |
| [CWE-425](https://cwe.mitre.org/data/definitions/425.html) | Direct Request | 미지정 |
| [CWE-433](https://cwe.mitre.org/data/definitions/433.html) | Unparsed Raw Web Content Delivery | 미지정 |
| [CWE-493](https://cwe.mitre.org/data/definitions/493.html) | Critical Public Variable Without Final Modifier | 미지정 |
| [CWE-500](https://cwe.mitre.org/data/definitions/500.html) | Public Static Field Not Marked Final | 미지정 |
| [CWE-520](https://cwe.mitre.org/data/definitions/520.html) | .NET Misconfiguration: Use of Impersonation | 미지정 |
| [CWE-521](https://cwe.mitre.org/data/definitions/521.html) | Weak Password Requirements | 미지정 |
| [CWE-522](https://cwe.mitre.org/data/definitions/522.html) | Insufficiently Protected Credentials | 미지정 |
| [CWE-523](https://cwe.mitre.org/data/definitions/523.html) | Unprotected Transport of Credentials | 미지정 |
| [CWE-527](https://cwe.mitre.org/data/definitions/527.html) | Exposure of Version-Control Repository to an Unauthorized Control Sphere | 미지정 |
| [CWE-528](https://cwe.mitre.org/data/definitions/528.html) | Exposure of Core Dump File to an Unauthorized Control Sphere | 미지정 |
| [CWE-529](https://cwe.mitre.org/data/definitions/529.html) | Exposure of Access Control List Files to an Unauthorized Control Sphere | 미지정 |
| [CWE-530](https://cwe.mitre.org/data/definitions/530.html) | Exposure of Backup File to an Unauthorized Control Sphere | 미지정 |
| [CWE-539](https://cwe.mitre.org/data/definitions/539.html) | Use of Persistent Cookies Containing Sensitive Information | 미지정 |
| [CWE-549](https://cwe.mitre.org/data/definitions/549.html) | Missing Password Field Masking | 미지정 |
| [CWE-551](https://cwe.mitre.org/data/definitions/551.html) | Incorrect Behavior Order: Authorization Before Parsing and Canonicalization | 미지정 |
| [CWE-552](https://cwe.mitre.org/data/definitions/552.html) | Files or Directories Accessible to External Parties | 미지정 |
| [CWE-553](https://cwe.mitre.org/data/definitions/553.html) | Command Shell in Externally Accessible Directory | 미지정 |
| [CWE-555](https://cwe.mitre.org/data/definitions/555.html) | J2EE Misconfiguration: Plaintext Password in Configuration File | 미지정 |
| [CWE-556](https://cwe.mitre.org/data/definitions/556.html) | ASP.NET Misconfiguration: Use of Identity Impersonation | 미지정 |
| [CWE-566](https://cwe.mitre.org/data/definitions/566.html) | Authorization Bypass Through User-Controlled SQL Primary Key | 미지정 |
| [CWE-582](https://cwe.mitre.org/data/definitions/582.html) | Array Declared Public, Final, and Static | 미지정 |
| [CWE-583](https://cwe.mitre.org/data/definitions/583.html) | finalize() Method Declared Public | 미지정 |
| [CWE-593](https://cwe.mitre.org/data/definitions/593.html) | Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created | 미지정 |
| [CWE-599](https://cwe.mitre.org/data/definitions/599.html) | Missing Validation of OpenSSL Certificate | 미지정 |
| [CWE-603](https://cwe.mitre.org/data/definitions/603.html) | Use of Client-Side Authentication | 미지정 |
| [CWE-608](https://cwe.mitre.org/data/definitions/608.html) | Struts: Non-private Field in ActionForm Class | 미지정 |
| [CWE-612](https://cwe.mitre.org/data/definitions/612.html) | Improper Authorization of Index Containing Sensitive Information | 미지정 |
| [CWE-618](https://cwe.mitre.org/data/definitions/618.html) | Exposed Unsafe ActiveX Method | 미지정 |
| [CWE-620](https://cwe.mitre.org/data/definitions/620.html) | Unverified Password Change | 미지정 |
| [CWE-623](https://cwe.mitre.org/data/definitions/623.html) | Unsafe ActiveX Control Marked Safe For Scripting | 미지정 |
| [CWE-638](https://cwe.mitre.org/data/definitions/638.html) | Not Using Complete Mediation | 미지정 |
| [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | Authorization Bypass Through User-Controlled Key | 미지정 |
| [CWE-640](https://cwe.mitre.org/data/definitions/640.html) | Weak Password Recovery Mechanism for Forgotten Password | 미지정 |
| [CWE-645](https://cwe.mitre.org/data/definitions/645.html) | Overly Restrictive Account Lockout Mechanism | 미지정 |
| [CWE-647](https://cwe.mitre.org/data/definitions/647.html) | Use of Non-Canonical URL Paths for Authorization Decisions | 미지정 |
| [CWE-648](https://cwe.mitre.org/data/definitions/648.html) | Incorrect Use of Privileged APIs | 미지정 |
| [CWE-708](https://cwe.mitre.org/data/definitions/708.html) | Incorrect Ownership Assignment | 미지정 |
| [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | Incorrect Permission Assignment for Critical Resource | 미지정 |
| [CWE-749](https://cwe.mitre.org/data/definitions/749.html) | Exposed Dangerous Method or Function | 미지정 |
| [CWE-766](https://cwe.mitre.org/data/definitions/766.html) | Critical Data Element Declared Public | 미지정 |
| [CWE-782](https://cwe.mitre.org/data/definitions/782.html) | Exposed IOCTL with Insufficient Access Control | 미지정 |
| [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | Use of Hard-coded Credentials | 미지정 |
| [CWE-804](https://cwe.mitre.org/data/definitions/804.html) | Guessable CAPTCHA | 미지정 |
| [CWE-836](https://cwe.mitre.org/data/definitions/836.html) | Use of Password Hash Instead of Password for Authentication | 미지정 |
| [CWE-842](https://cwe.mitre.org/data/definitions/842.html) | Placement of User into Incorrect Group | 미지정 |
| [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | Missing Authorization | 미지정 |
| [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | Incorrect Authorization | 미지정 |
| [CWE-923](https://cwe.mitre.org/data/definitions/923.html) | Improper Restriction of Communication Channel to Intended Endpoints | 미지정 |
| [CWE-925](https://cwe.mitre.org/data/definitions/925.html) | Improper Verification of Intent by Broadcast Receiver | 미지정 |
| [CWE-926](https://cwe.mitre.org/data/definitions/926.html) | Improper Export of Android Application Components | 미지정 |
| [CWE-927](https://cwe.mitre.org/data/definitions/927.html) | Use of Implicit Intent for Sensitive Communication | 미지정 |
| [CWE-939](https://cwe.mitre.org/data/definitions/939.html) | Improper Authorization in Handler for Custom URL Scheme | 미지정 |
| [CWE-940](https://cwe.mitre.org/data/definitions/940.html) | Improper Verification of Source of a Communication Channel | 미지정 |
| [CWE-941](https://cwe.mitre.org/data/definitions/941.html) | Incorrectly Specified Destination in a Communication Channel | 미지정 |
| [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | Permissive Cross-domain Security Policy with Untrusted Domains | 미지정 |
| [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) | Sensitive Cookie Without 'HttpOnly' Flag | 미지정 |
| [CWE-1022](https://cwe.mitre.org/data/definitions/1022.html) | Use of Web Link to Untrusted Target with window.opener Access | 미지정 |
| [CWE-1191](https://cwe.mitre.org/data/definitions/1191.html) | On-Chip Debug and Test Interface With Improper Access Control | 미지정 |
| [CWE-1220](https://cwe.mitre.org/data/definitions/1220.html) | Insufficient Granularity of Access Control | 미지정 |
| [CWE-1222](https://cwe.mitre.org/data/definitions/1222.html) | Insufficient Granularity of Address Regions Protected by Register Locks | 미지정 |
| [CWE-1224](https://cwe.mitre.org/data/definitions/1224.html) | Improper Restriction of Write-Once Bit Fields | 미지정 |
| [CWE-1230](https://cwe.mitre.org/data/definitions/1230.html) | Exposure of Sensitive Information Through Metadata | 미지정 |
| [CWE-1231](https://cwe.mitre.org/data/definitions/1231.html) | Improper Prevention of Lock Bit Modification | 미지정 |
| [CWE-1233](https://cwe.mitre.org/data/definitions/1233.html) | Security-Sensitive Hardware Controls with Missing Lock Bit Protection | 미지정 |
| [CWE-1243](https://cwe.mitre.org/data/definitions/1243.html) | Sensitive Non-Volatile Information Not Protected During Debug | 미지정 |
| [CWE-1244](https://cwe.mitre.org/data/definitions/1244.html) | Internal Asset Exposed to Unsafe Debug Access Level or State | 미지정 |
| [CWE-1252](https://cwe.mitre.org/data/definitions/1252.html) | CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations | 미지정 |
| [CWE-1256](https://cwe.mitre.org/data/definitions/1256.html) | Improper Restriction of Software Interfaces to Hardware Features | 미지정 |
| [CWE-1257](https://cwe.mitre.org/data/definitions/1257.html) | Improper Access Control Applied to Mirrored or Aliased Memory Regions | 미지정 |
| [CWE-1259](https://cwe.mitre.org/data/definitions/1259.html) | Improper Restriction of Security Token Assignment | 미지정 |
| [CWE-1260](https://cwe.mitre.org/data/definitions/1260.html) | Improper Handling of Overlap Between Protected Memory Ranges | 미지정 |
| [CWE-1262](https://cwe.mitre.org/data/definitions/1262.html) | Improper Access Control for Register Interface | 미지정 |
| [CWE-1263](https://cwe.mitre.org/data/definitions/1263.html) | Improper Physical Access Control | 미지정 |
| [CWE-1267](https://cwe.mitre.org/data/definitions/1267.html) | Policy Uses Obsolete Encoding | 미지정 |
| [CWE-1268](https://cwe.mitre.org/data/definitions/1268.html) | Policy Privileges are not Assigned Consistently Between Control and Data Agents | 미지정 |
| [CWE-1270](https://cwe.mitre.org/data/definitions/1270.html) | Generation of Incorrect Security Tokens | 미지정 |
| [CWE-1274](https://cwe.mitre.org/data/definitions/1274.html) | Improper Access Control for Volatile Memory Containing Boot Code | 미지정 |
| [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) | Sensitive Cookie with Improper SameSite Attribute | 미지정 |
| [CWE-1276](https://cwe.mitre.org/data/definitions/1276.html) | Hardware Child Block Incorrectly Connected to Parent System | 미지정 |
| [CWE-1280](https://cwe.mitre.org/data/definitions/1280.html) | Access Control Check Implemented After Asset is Accessed | 미지정 |
| [CWE-1283](https://cwe.mitre.org/data/definitions/1283.html) | Mutable Attestation or Measurement Reporting Data | 미지정 |
| [CWE-1290](https://cwe.mitre.org/data/definitions/1290.html) | Incorrect Decoding of Security Identifiers | 미지정 |
| [CWE-1292](https://cwe.mitre.org/data/definitions/1292.html) | Incorrect Conversion of Security Identifiers | 미지정 |
| [CWE-1294](https://cwe.mitre.org/data/definitions/1294.html) | Insecure Security Identifier Mechanism | 미지정 |
| [CWE-1296](https://cwe.mitre.org/data/definitions/1296.html) | Incorrect Chaining or Granularity of Debug Components | 미지정 |
| [CWE-1297](https://cwe.mitre.org/data/definitions/1297.html) | Unprotected Confidential Information on Device is Accessible by OSAT Vendors | 미지정 |
| [CWE-1299](https://cwe.mitre.org/data/definitions/1299.html) | Missing Protection Mechanism for Alternate Hardware Interface | 미지정 |
| [CWE-1302](https://cwe.mitre.org/data/definitions/1302.html) | Missing Source Identifier in Entity Transactions on a System-On-Chip (SOC) | 미지정 |
| [CWE-1304](https://cwe.mitre.org/data/definitions/1304.html) | Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation | 미지정 |
| [CWE-1311](https://cwe.mitre.org/data/definitions/1311.html) | Improper Translation of Security Attributes by Fabric Bridge | 미지정 |
| [CWE-1312](https://cwe.mitre.org/data/definitions/1312.html) | Missing Protection for Mirrored Regions in On-Chip Fabric Firewall | 미지정 |
| [CWE-1313](https://cwe.mitre.org/data/definitions/1313.html) | Hardware Allows Activation of Test or Debug Logic at Runtime | 미지정 |
| [CWE-1314](https://cwe.mitre.org/data/definitions/1314.html) | Missing Write Protection for Parametric Data Values | 미지정 |
| [CWE-1315](https://cwe.mitre.org/data/definitions/1315.html) | Improper Setting of Bus Controlling Capability in Fabric End-point | 미지정 |
| [CWE-1316](https://cwe.mitre.org/data/definitions/1316.html) | Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges | 미지정 |
| [CWE-1317](https://cwe.mitre.org/data/definitions/1317.html) | Improper Access Control in Fabric Bridge | 미지정 |
| [CWE-1320](https://cwe.mitre.org/data/definitions/1320.html) | Improper Protection for Outbound Error Messages and Alert Signals | 미지정 |
| [CWE-1323](https://cwe.mitre.org/data/definitions/1323.html) | Improper Management of Sensitive Trace Data | 미지정 |
| [CWE-1327](https://cwe.mitre.org/data/definitions/1327.html) | Binding to an Unrestricted IP Address | 미지정 |
| [CWE-1328](https://cwe.mitre.org/data/definitions/1328.html) | Security Version Number Mutable to Older Versions | 미지정 |
| [CWE-1334](https://cwe.mitre.org/data/definitions/1334.html) | Unauthorized Error Injection Can Degrade Hardware Redundancy | 미지정 |
| [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html) | Missing Origin Validation in WebSockets | 미지정 |
| [CWE-1390](https://cwe.mitre.org/data/definitions/1390.html) | Weak Authentication | 미지정 |
| [CWE-1391](https://cwe.mitre.org/data/definitions/1391.html) | Use of Weak Credentials | 미지정 |
| [CWE-1392](https://cwe.mitre.org/data/definitions/1392.html) | Use of Default Credentials | 미지정 |
| [CWE-1393](https://cwe.mitre.org/data/definitions/1393.html) | Use of Default Password | 미지정 |
| [CWE-1394](https://cwe.mitre.org/data/definitions/1394.html) | Use of Default Cryptographic Key | 미지정 |
| [CWE-1462](https://cwe.mitre.org/data/definitions/1462.html) | Improper Session Management | 미지정 |
| [CWE-1463](https://cwe.mitre.org/data/definitions/1463.html) | Insufficient Session Timeout Value | 미지정 |
| [CWE-1464](https://cwe.mitre.org/data/definitions/1464.html) | Improper Session Invalidation | 미지정 |
| [CWE-1465](https://cwe.mitre.org/data/definitions/1465.html) | Improper Session Invalidation after User Logout | 미지정 |
| [CWE-1466](https://cwe.mitre.org/data/definitions/1466.html) | Improper Session Invalidation after Authentication Credential Change | 미지정 |
| [CWE-1467](https://cwe.mitre.org/data/definitions/1467.html) | Use of Singular Authentication Artifact for Multiple User Sessions | 미지정 |
| [CWE-1469](https://cwe.mitre.org/data/definitions/1469.html) | Improper Check for Credential Expiration | 미지정 |
| [CWE-1470](https://cwe.mitre.org/data/definitions/1470.html) | Improper External Identity Verification | 미지정 |
| [CWE-1472](https://cwe.mitre.org/data/definitions/1472.html) | Generation of Credential with Long Expiration | 미지정 |

</details>

<details>
<summary>CWE-435 · Improper Interaction Between Multiple Correctly-Behaving Entities · 17개 소속</summary>

| 세부 CWE | 공식 이름 | 현재 증거 경로 |
| --- | --- | --- |
| [CWE-14](https://cwe.mitre.org/data/definitions/14.html) | Compiler Removal of Code to Clear Buffers | 미지정 |
| [CWE-86](https://cwe.mitre.org/data/definitions/86.html) | Improper Neutralization of Invalid Characters in Identifiers in Web Pages | 미지정 |
| [CWE-113](https://cwe.mitre.org/data/definitions/113.html) | Improper Neutralization of CRLF Sequences in HTTP Headers | 미지정 |
| [CWE-115](https://cwe.mitre.org/data/definitions/115.html) | Misinterpretation of Input | 미지정 |
| [CWE-188](https://cwe.mitre.org/data/definitions/188.html) | Reliance on Data/Memory Layout | 미지정 |
| [CWE-198](https://cwe.mitre.org/data/definitions/198.html) | Use of Incorrect Byte Ordering | 미지정 |
| [CWE-436](https://cwe.mitre.org/data/definitions/436.html) | Interpretation Conflict | 미지정 |
| [CWE-437](https://cwe.mitre.org/data/definitions/437.html) | Incomplete Model of Endpoint Features | 미지정 |
| [CWE-439](https://cwe.mitre.org/data/definitions/439.html) | Behavioral Change in New Version or Environment | 미지정 |
| [CWE-444](https://cwe.mitre.org/data/definitions/444.html) | Inconsistent Interpretation of HTTP Requests | 미지정 |
| [CWE-626](https://cwe.mitre.org/data/definitions/626.html) | Null Byte Interaction Error (Poison Null Byte) | 미지정 |
| [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | Trusting HTTP Permission Methods on the Server Side | 미지정 |
| [CWE-733](https://cwe.mitre.org/data/definitions/733.html) | Compiler Optimization Removal or Modification of Security-critical Code | 미지정 |
| [CWE-1037](https://cwe.mitre.org/data/definitions/1037.html) | Processor Optimization Removal or Modification of Security-critical Code | 미지정 |
| [CWE-1038](https://cwe.mitre.org/data/definitions/1038.html) | Insecure Automated Optimizations | 미지정 |
| [CWE-1461](https://cwe.mitre.org/data/definitions/1461.html) | Hardware Simulation / Synthesis Mismatch | 미지정 |
| [CWE-1471](https://cwe.mitre.org/data/definitions/1471.html) | Insufficiently Controlled Parser Differential | 미지정 |

</details>

<details>
<summary>CWE-664 · Improper Control of a Resource Through its Lifetime · 380개 소속</summary>

| 세부 CWE | 공식 이름 | 현재 증거 경로 |
| --- | --- | --- |
| [CWE-8](https://cwe.mitre.org/data/definitions/8.html) | J2EE Misconfiguration: Entity Bean Declared Remote | 미지정 |
| [CWE-13](https://cwe.mitre.org/data/definitions/13.html) | ASP.NET Misconfiguration: Password in Configuration File | 미지정 |
| [CWE-15](https://cwe.mitre.org/data/definitions/15.html) | External Control of System or Configuration Setting | 미지정 |
| [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | Improper Limitation of a Pathname to a Restricted Directory | 미지정 |
| [CWE-23](https://cwe.mitre.org/data/definitions/23.html) | Relative Path Traversal | 미지정 |
| [CWE-24](https://cwe.mitre.org/data/definitions/24.html) | Path Traversal: '../filedir' | 미지정 |
| [CWE-25](https://cwe.mitre.org/data/definitions/25.html) | Path Traversal: '/../filedir' | 미지정 |
| [CWE-26](https://cwe.mitre.org/data/definitions/26.html) | Path Traversal: '/dir/../filename' | 미지정 |
| [CWE-27](https://cwe.mitre.org/data/definitions/27.html) | Path Traversal: 'dir/../../filename' | 미지정 |
| [CWE-28](https://cwe.mitre.org/data/definitions/28.html) | Path Traversal: '..\filedir' | 미지정 |
| [CWE-29](https://cwe.mitre.org/data/definitions/29.html) | Path Traversal: '\..\filename' | 미지정 |
| [CWE-30](https://cwe.mitre.org/data/definitions/30.html) | Path Traversal: '\dir\..\filename' | 미지정 |
| [CWE-31](https://cwe.mitre.org/data/definitions/31.html) | Path Traversal: 'dir\..\..\filename' | 미지정 |
| [CWE-32](https://cwe.mitre.org/data/definitions/32.html) | Path Traversal: '...' (Triple Dot) | 미지정 |
| [CWE-33](https://cwe.mitre.org/data/definitions/33.html) | Path Traversal: '....' (Multiple Dot) | 미지정 |
| [CWE-34](https://cwe.mitre.org/data/definitions/34.html) | Path Traversal: '....//' | 미지정 |
| [CWE-35](https://cwe.mitre.org/data/definitions/35.html) | Path Traversal: '.../...//' | 미지정 |
| [CWE-36](https://cwe.mitre.org/data/definitions/36.html) | Absolute Path Traversal | 미지정 |
| [CWE-37](https://cwe.mitre.org/data/definitions/37.html) | Path Traversal: '/absolute/pathname/here' | 미지정 |
| [CWE-38](https://cwe.mitre.org/data/definitions/38.html) | Path Traversal: '\absolute\pathname\here' | 미지정 |
| [CWE-39](https://cwe.mitre.org/data/definitions/39.html) | Path Traversal: 'C:dirname' | 미지정 |
| [CWE-40](https://cwe.mitre.org/data/definitions/40.html) | Path Traversal: '\\UNC\share\name\' (Windows UNC Share) | 미지정 |
| [CWE-41](https://cwe.mitre.org/data/definitions/41.html) | Improper Resolution of Path Equivalence | 미지정 |
| [CWE-42](https://cwe.mitre.org/data/definitions/42.html) | Path Equivalence: 'filename.' (Trailing Dot) | 미지정 |
| [CWE-43](https://cwe.mitre.org/data/definitions/43.html) | Path Equivalence: 'filename....' (Multiple Trailing Dot) | 미지정 |
| [CWE-44](https://cwe.mitre.org/data/definitions/44.html) | Path Equivalence: 'file.name' (Internal Dot) | 미지정 |
| [CWE-45](https://cwe.mitre.org/data/definitions/45.html) | Path Equivalence: 'file...name' (Multiple Internal Dot) | 미지정 |
| [CWE-46](https://cwe.mitre.org/data/definitions/46.html) | Path Equivalence: 'filename ' (Trailing Space) | 미지정 |
| [CWE-47](https://cwe.mitre.org/data/definitions/47.html) | Path Equivalence: ' filename' (Leading Space) | 미지정 |
| [CWE-48](https://cwe.mitre.org/data/definitions/48.html) | Path Equivalence: 'file name' (Internal Whitespace) | 미지정 |
| [CWE-49](https://cwe.mitre.org/data/definitions/49.html) | Path Equivalence: 'filename/' (Trailing Slash) | 미지정 |
| [CWE-50](https://cwe.mitre.org/data/definitions/50.html) | Path Equivalence: '//multiple/leading/slash' | 미지정 |
| [CWE-51](https://cwe.mitre.org/data/definitions/51.html) | Path Equivalence: '/multiple//internal/slash' | 미지정 |
| [CWE-52](https://cwe.mitre.org/data/definitions/52.html) | Path Equivalence: '/multiple/trailing/slash//' | 미지정 |
| [CWE-53](https://cwe.mitre.org/data/definitions/53.html) | Path Equivalence: '\multiple\\internal\backslash' | 미지정 |
| [CWE-54](https://cwe.mitre.org/data/definitions/54.html) | Path Equivalence: 'filedir\' (Trailing Backslash) | 미지정 |
| [CWE-55](https://cwe.mitre.org/data/definitions/55.html) | Path Equivalence: '/./' (Single Dot Directory) | 미지정 |
| [CWE-56](https://cwe.mitre.org/data/definitions/56.html) | Path Equivalence: 'filedir*' (Wildcard) | 미지정 |
| [CWE-57](https://cwe.mitre.org/data/definitions/57.html) | Path Equivalence: 'fakedir/../realdir/filename' | 미지정 |
| [CWE-58](https://cwe.mitre.org/data/definitions/58.html) | Path Equivalence: Windows 8.3 Filename | 미지정 |
| [CWE-59](https://cwe.mitre.org/data/definitions/59.html) | Improper Link Resolution Before File Access | 미지정 |
| [CWE-61](https://cwe.mitre.org/data/definitions/61.html) | UNIX Symbolic Link (Symlink) Following | 미지정 |
| [CWE-62](https://cwe.mitre.org/data/definitions/62.html) | UNIX Hard Link | 미지정 |
| [CWE-64](https://cwe.mitre.org/data/definitions/64.html) | Windows Shortcut Following (.LNK) | 미지정 |
| [CWE-65](https://cwe.mitre.org/data/definitions/65.html) | Windows Hard Link | 미지정 |
| [CWE-66](https://cwe.mitre.org/data/definitions/66.html) | Improper Handling of File Names that Identify Virtual Resources | 미지정 |
| [CWE-67](https://cwe.mitre.org/data/definitions/67.html) | Improper Handling of Windows Device Names | 미지정 |
| [CWE-69](https://cwe.mitre.org/data/definitions/69.html) | Improper Handling of Windows ::DATA Alternate Data Stream | 미지정 |
| [CWE-72](https://cwe.mitre.org/data/definitions/72.html) | Improper Handling of Apple HFS+ Alternate Data Stream Path | 미지정 |
| [CWE-73](https://cwe.mitre.org/data/definitions/73.html) | External Control of File Name or Path | 미지정 |
| [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | Improper Control of Generation of Code | 미지정 |
| [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | Improper Neutralization of Directives in Dynamically Evaluated Code | 미지정 |
| [CWE-96](https://cwe.mitre.org/data/definitions/96.html) | Improper Neutralization of Directives in Statically Saved Code | 미지정 |
| [CWE-97](https://cwe.mitre.org/data/definitions/97.html) | Improper Neutralization of Server-Side Includes (SSI) Within a Web Page | 미지정 |
| [CWE-98](https://cwe.mitre.org/data/definitions/98.html) | Improper Control of Filename for Include/Require Statement in PHP Program | 미지정 |
| [CWE-114](https://cwe.mitre.org/data/definitions/114.html) | Process Control | 미지정 |
| [CWE-118](https://cwe.mitre.org/data/definitions/118.html) | Incorrect Access of Indexable Resource | 미지정 |
| [CWE-119](https://cwe.mitre.org/data/definitions/119.html) | Improper Restriction of Operations within the Bounds of a Memory Buffer | 미지정 |
| [CWE-120](https://cwe.mitre.org/data/definitions/120.html) | Buffer Copy without Checking Size of Input | 미지정 |
| [CWE-121](https://cwe.mitre.org/data/definitions/121.html) | Stack-based Buffer Overflow | 미지정 |
| [CWE-122](https://cwe.mitre.org/data/definitions/122.html) | Heap-based Buffer Overflow | 미지정 |
| [CWE-123](https://cwe.mitre.org/data/definitions/123.html) | Write-what-where Condition | 미지정 |
| [CWE-124](https://cwe.mitre.org/data/definitions/124.html) | Buffer Underwrite | 미지정 |
| [CWE-125](https://cwe.mitre.org/data/definitions/125.html) | Out-of-bounds Read | 미지정 |
| [CWE-126](https://cwe.mitre.org/data/definitions/126.html) | Buffer Over-read | 미지정 |
| [CWE-127](https://cwe.mitre.org/data/definitions/127.html) | Buffer Under-read | 미지정 |
| [CWE-134](https://cwe.mitre.org/data/definitions/134.html) | Use of Externally-Controlled Format String | 미지정 |
| [CWE-178](https://cwe.mitre.org/data/definitions/178.html) | Improper Handling of Case Sensitivity | 미지정 |
| [CWE-192](https://cwe.mitre.org/data/definitions/192.html) | Integer Coercion Error | 미지정 |
| [CWE-194](https://cwe.mitre.org/data/definitions/194.html) | Unexpected Sign Extension | 미지정 |
| [CWE-195](https://cwe.mitre.org/data/definitions/195.html) | Signed to Unsigned Conversion Error | 미지정 |
| [CWE-196](https://cwe.mitre.org/data/definitions/196.html) | Unsigned to Signed Conversion Error | 미지정 |
| [CWE-197](https://cwe.mitre.org/data/definitions/197.html) | Numeric Truncation Error | 미지정 |
| [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | Exposure of Sensitive Information to an Unauthorized Actor | 미지정 |
| [CWE-201](https://cwe.mitre.org/data/definitions/201.html) | Insertion of Sensitive Information Into Sent Data | 미지정 |
| [CWE-203](https://cwe.mitre.org/data/definitions/203.html) | Observable Discrepancy | 미지정 |
| [CWE-204](https://cwe.mitre.org/data/definitions/204.html) | Observable Response Discrepancy | 미지정 |
| [CWE-205](https://cwe.mitre.org/data/definitions/205.html) | Observable Behavioral Discrepancy | 미지정 |
| [CWE-206](https://cwe.mitre.org/data/definitions/206.html) | Observable Internal Behavioral Discrepancy | 미지정 |
| [CWE-207](https://cwe.mitre.org/data/definitions/207.html) | Observable Behavioral Discrepancy With Equivalent Products | 미지정 |
| [CWE-208](https://cwe.mitre.org/data/definitions/208.html) | Observable Timing Discrepancy | 미지정 |
| [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | Generation of Error Message Containing Sensitive Information | 미지정 |
| [CWE-210](https://cwe.mitre.org/data/definitions/210.html) | Self-generated Error Message Containing Sensitive Information | 미지정 |
| [CWE-211](https://cwe.mitre.org/data/definitions/211.html) | Externally-Generated Error Message Containing Sensitive Information | 미지정 |
| [CWE-212](https://cwe.mitre.org/data/definitions/212.html) | Improper Removal of Sensitive Information Before Storage or Transfer | 미지정 |
| [CWE-213](https://cwe.mitre.org/data/definitions/213.html) | Exposure of Sensitive Information Due to Incompatible Policies | 미지정 |
| [CWE-214](https://cwe.mitre.org/data/definitions/214.html) | Invocation of Process Using Visible Sensitive Information | 미지정 |
| [CWE-215](https://cwe.mitre.org/data/definitions/215.html) | Insertion of Sensitive Information Into Debugging Code | 미지정 |
| [CWE-219](https://cwe.mitre.org/data/definitions/219.html) | Storage of File with Sensitive Data Under Web Root | 미지정 |
| [CWE-220](https://cwe.mitre.org/data/definitions/220.html) | Storage of File With Sensitive Data Under FTP Root | 미지정 |
| [CWE-221](https://cwe.mitre.org/data/definitions/221.html) | Information Loss or Omission | 미지정 |
| [CWE-222](https://cwe.mitre.org/data/definitions/222.html) | Truncation of Security-relevant Information | 미지정 |
| [CWE-223](https://cwe.mitre.org/data/definitions/223.html) | Omission of Security-relevant Information | 미지정 |
| [CWE-224](https://cwe.mitre.org/data/definitions/224.html) | Obscured Security-relevant Information by Alternate Name | 미지정 |
| [CWE-226](https://cwe.mitre.org/data/definitions/226.html) | Sensitive Information in Resource Not Removed Before Reuse | 미지정 |
| [CWE-243](https://cwe.mitre.org/data/definitions/243.html) | Creation of chroot Jail Without Changing Working Directory | 미지정 |
| [CWE-244](https://cwe.mitre.org/data/definitions/244.html) | Improper Clearing of Heap Memory Before Release | 미지정 |
| [CWE-256](https://cwe.mitre.org/data/definitions/256.html) | Plaintext Storage of a Password | 미지정 |
| [CWE-257](https://cwe.mitre.org/data/definitions/257.html) | Storing Passwords in a Recoverable Format | 미지정 |
| [CWE-258](https://cwe.mitre.org/data/definitions/258.html) | Empty Password in Configuration File | 미지정 |
| [CWE-260](https://cwe.mitre.org/data/definitions/260.html) | Password in Configuration File | 미지정 |
| [CWE-261](https://cwe.mitre.org/data/definitions/261.html) | Weak Encoding for Password | 미지정 |
| [CWE-262](https://cwe.mitre.org/data/definitions/262.html) | Not Using Password Aging | 미지정 |
| [CWE-263](https://cwe.mitre.org/data/definitions/263.html) | Password Aging with Long Expiration | 미지정 |
| [CWE-276](https://cwe.mitre.org/data/definitions/276.html) | Incorrect Default Permissions | 미지정 |
| [CWE-277](https://cwe.mitre.org/data/definitions/277.html) | Insecure Inherited Permissions | 미지정 |
| [CWE-278](https://cwe.mitre.org/data/definitions/278.html) | Insecure Preserved Inherited Permissions | 미지정 |
| [CWE-279](https://cwe.mitre.org/data/definitions/279.html) | Incorrect Execution-Assigned Permissions | 미지정 |
| [CWE-281](https://cwe.mitre.org/data/definitions/281.html) | Improper Preservation of Permissions | 미지정 |
| [CWE-298](https://cwe.mitre.org/data/definitions/298.html) | Improper Validation of Certificate Expiration | 미지정 |
| [CWE-299](https://cwe.mitre.org/data/definitions/299.html) | Improper Check for Certificate Revocation | 미지정 |
| [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | Cleartext Storage of Sensitive Information | 미지정 |
| [CWE-313](https://cwe.mitre.org/data/definitions/313.html) | Cleartext Storage in a File or on Disk | 미지정 |
| [CWE-314](https://cwe.mitre.org/data/definitions/314.html) | Cleartext Storage in the Registry | 미지정 |
| [CWE-315](https://cwe.mitre.org/data/definitions/315.html) | Cleartext Storage of Sensitive Information in a Cookie | 미지정 |
| [CWE-316](https://cwe.mitre.org/data/definitions/316.html) | Cleartext Storage of Sensitive Information in Memory | 미지정 |
| [CWE-317](https://cwe.mitre.org/data/definitions/317.html) | Cleartext Storage of Sensitive Information in GUI | 미지정 |
| [CWE-318](https://cwe.mitre.org/data/definitions/318.html) | Cleartext Storage of Sensitive Information in Executable | 미지정 |
| [CWE-324](https://cwe.mitre.org/data/definitions/324.html) | Use of a Key Past its Expiration Date | 미지정 |
| [CWE-359](https://cwe.mitre.org/data/definitions/359.html) | Exposure of Private Personal Information to an Unauthorized Actor | 미지정 |
| [CWE-362](https://cwe.mitre.org/data/definitions/362.html) | Concurrent Execution using Shared Resource with Improper Synchronization | 미지정 |
| [CWE-363](https://cwe.mitre.org/data/definitions/363.html) | Race Condition Enabling Link Following | 미지정 |
| [CWE-364](https://cwe.mitre.org/data/definitions/364.html) | Signal Handler Race Condition | 미지정 |
| [CWE-366](https://cwe.mitre.org/data/definitions/366.html) | Race Condition within a Thread | 미지정 |
| [CWE-367](https://cwe.mitre.org/data/definitions/367.html) | Time-of-check Time-of-use (TOCTOU) Race Condition | 미지정 |
| [CWE-368](https://cwe.mitre.org/data/definitions/368.html) | Context Switching Race Condition | 미지정 |
| [CWE-370](https://cwe.mitre.org/data/definitions/370.html) | Missing Check for Certificate Revocation after Initial Check | 미지정 |
| [CWE-372](https://cwe.mitre.org/data/definitions/372.html) | Incomplete Internal State Distinction | 미지정 |
| [CWE-374](https://cwe.mitre.org/data/definitions/374.html) | Passing Mutable Objects to an Untrusted Method | 미지정 |
| [CWE-375](https://cwe.mitre.org/data/definitions/375.html) | Returning a Mutable Object to an Untrusted Caller | 미지정 |
| [CWE-384](https://cwe.mitre.org/data/definitions/384.html) | Session Fixation | 미지정 |
| [CWE-385](https://cwe.mitre.org/data/definitions/385.html) | Covert Timing Channel | 미지정 |
| [CWE-386](https://cwe.mitre.org/data/definitions/386.html) | Symbolic Name not Mapping to Correct Object | 미지정 |
| [CWE-396](https://cwe.mitre.org/data/definitions/396.html) | Declaration of Catch for Generic Exception | 미지정 |
| [CWE-397](https://cwe.mitre.org/data/definitions/397.html) | Declaration of Throws for Generic Exception | 미지정 |
| [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | Uncontrolled Resource Consumption | 미지정 |
| [CWE-401](https://cwe.mitre.org/data/definitions/401.html) | Missing Release of Memory after Effective Lifetime | 미지정 |
| [CWE-402](https://cwe.mitre.org/data/definitions/402.html) | Transmission of Private Resources into a New Sphere | 미지정 |
| [CWE-403](https://cwe.mitre.org/data/definitions/403.html) | Exposure of File Descriptor to Unintended Control Sphere | 미지정 |
| [CWE-404](https://cwe.mitre.org/data/definitions/404.html) | Improper Resource Shutdown or Release | 미지정 |
| [CWE-405](https://cwe.mitre.org/data/definitions/405.html) | Asymmetric Resource Consumption (Amplification) | 미지정 |
| [CWE-406](https://cwe.mitre.org/data/definitions/406.html) | Insufficient Control of Network Message Volume (Network Amplification) | 미지정 |
| [CWE-407](https://cwe.mitre.org/data/definitions/407.html) | Inefficient Algorithmic Complexity | 미지정 |
| [CWE-408](https://cwe.mitre.org/data/definitions/408.html) | Incorrect Behavior Order: Early Amplification | 미지정 |
| [CWE-409](https://cwe.mitre.org/data/definitions/409.html) | Improper Handling of Highly Compressed Data (Data Amplification) | 미지정 |
| [CWE-410](https://cwe.mitre.org/data/definitions/410.html) | Insufficient Resource Pool | 미지정 |
| [CWE-412](https://cwe.mitre.org/data/definitions/412.html) | Unrestricted Externally Accessible Lock | 미지정 |
| [CWE-413](https://cwe.mitre.org/data/definitions/413.html) | Improper Resource Locking | 미지정 |
| [CWE-414](https://cwe.mitre.org/data/definitions/414.html) | Missing Lock Check | 미지정 |
| [CWE-415](https://cwe.mitre.org/data/definitions/415.html) | Double Free | 미지정 |
| [CWE-416](https://cwe.mitre.org/data/definitions/416.html) | Use After Free | 미지정 |
| [CWE-421](https://cwe.mitre.org/data/definitions/421.html) | Race Condition During Access to Alternate Channel | 미지정 |
| [CWE-426](https://cwe.mitre.org/data/definitions/426.html) | Untrusted Search Path | 미지정 |
| [CWE-427](https://cwe.mitre.org/data/definitions/427.html) | Uncontrolled Search Path Element | 미지정 |
| [CWE-428](https://cwe.mitre.org/data/definitions/428.html) | Unquoted Search Path or Element | 미지정 |
| [CWE-432](https://cwe.mitre.org/data/definitions/432.html) | Dangerous Signal Handler not Disabled During Sensitive Operations | 미지정 |
| [CWE-433](https://cwe.mitre.org/data/definitions/433.html) | Unparsed Raw Web Content Delivery | 미지정 |
| [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | Unrestricted Upload of File with Dangerous Type | 미지정 |
| [CWE-441](https://cwe.mitre.org/data/definitions/441.html) | Unintended Proxy or Intermediary | 미지정 |
| [CWE-451](https://cwe.mitre.org/data/definitions/451.html) | User Interface (UI) Misrepresentation of Critical Information | 미지정 |
| [CWE-453](https://cwe.mitre.org/data/definitions/453.html) | Insecure Default Variable Initialization | 미지정 |
| [CWE-454](https://cwe.mitre.org/data/definitions/454.html) | External Initialization of Trusted Variables or Data Stores | 미지정 |
| [CWE-455](https://cwe.mitre.org/data/definitions/455.html) | Non-exit on Failed Initialization | 미지정 |
| [CWE-456](https://cwe.mitre.org/data/definitions/456.html) | Missing Initialization of a Variable | 미지정 |
| [CWE-457](https://cwe.mitre.org/data/definitions/457.html) | Use of Uninitialized Variable | 미지정 |
| [CWE-459](https://cwe.mitre.org/data/definitions/459.html) | Incomplete Cleanup | 미지정 |
| [CWE-460](https://cwe.mitre.org/data/definitions/460.html) | Improper Cleanup on Thrown Exception | 미지정 |
| [CWE-466](https://cwe.mitre.org/data/definitions/466.html) | Return of Pointer Value Outside of Expected Range | 미지정 |
| [CWE-470](https://cwe.mitre.org/data/definitions/470.html) | Use of Externally-Controlled Input to Select Classes or Code | 미지정 |
| [CWE-471](https://cwe.mitre.org/data/definitions/471.html) | Modification of Assumed-Immutable Data (MAID) | 미지정 |
| [CWE-472](https://cwe.mitre.org/data/definitions/472.html) | External Control of Assumed-Immutable Web Parameter | 미지정 |
| [CWE-473](https://cwe.mitre.org/data/definitions/473.html) | PHP External Variable Modification | 미지정 |
| [CWE-479](https://cwe.mitre.org/data/definitions/479.html) | Signal Handler Use of a Non-reentrant Function | 미지정 |
| [CWE-487](https://cwe.mitre.org/data/definitions/487.html) | Reliance on Package-level Scope | 미지정 |
| [CWE-488](https://cwe.mitre.org/data/definitions/488.html) | Exposure of Data Element to Wrong Session | 미지정 |
| [CWE-491](https://cwe.mitre.org/data/definitions/491.html) | Public cloneable() Method Without Final | 미지정 |
| [CWE-492](https://cwe.mitre.org/data/definitions/492.html) | Use of Inner Class Containing Sensitive Data | 미지정 |
| [CWE-493](https://cwe.mitre.org/data/definitions/493.html) | Critical Public Variable Without Final Modifier | 미지정 |
| [CWE-494](https://cwe.mitre.org/data/definitions/494.html) | Download of Code Without Integrity Check | 미지정 |
| [CWE-495](https://cwe.mitre.org/data/definitions/495.html) | Private Data Structure Returned From A Public Method | 미지정 |
| [CWE-496](https://cwe.mitre.org/data/definitions/496.html) | Public Data Assigned to Private Array-Typed Field | 미지정 |
| [CWE-497](https://cwe.mitre.org/data/definitions/497.html) | Exposure of Sensitive System Information to an Unauthorized Control Sphere | 미지정 |
| [CWE-498](https://cwe.mitre.org/data/definitions/498.html) | Cloneable Class Containing Sensitive Information | 미지정 |
| [CWE-499](https://cwe.mitre.org/data/definitions/499.html) | Serializable Class Containing Sensitive Data | 미지정 |
| [CWE-500](https://cwe.mitre.org/data/definitions/500.html) | Public Static Field Not Marked Final | 미지정 |
| [CWE-501](https://cwe.mitre.org/data/definitions/501.html) | Trust Boundary Violation | 미지정 |
| [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | Deserialization of Untrusted Data | 미지정 |
| [CWE-514](https://cwe.mitre.org/data/definitions/514.html) | Covert Channel | 미지정 |
| [CWE-515](https://cwe.mitre.org/data/definitions/515.html) | Covert Storage Channel | 미지정 |
| [CWE-522](https://cwe.mitre.org/data/definitions/522.html) | Insufficiently Protected Credentials | 미지정 |
| [CWE-523](https://cwe.mitre.org/data/definitions/523.html) | Unprotected Transport of Credentials | 미지정 |
| [CWE-524](https://cwe.mitre.org/data/definitions/524.html) | Use of Cache Containing Sensitive Information | 미지정 |
| [CWE-525](https://cwe.mitre.org/data/definitions/525.html) | Use of Web Browser Cache Containing Sensitive Information | 미지정 |
| [CWE-526](https://cwe.mitre.org/data/definitions/526.html) | Cleartext Storage of Sensitive Information in an Environment Variable | 미지정 |
| [CWE-527](https://cwe.mitre.org/data/definitions/527.html) | Exposure of Version-Control Repository to an Unauthorized Control Sphere | 미지정 |
| [CWE-528](https://cwe.mitre.org/data/definitions/528.html) | Exposure of Core Dump File to an Unauthorized Control Sphere | 미지정 |
| [CWE-529](https://cwe.mitre.org/data/definitions/529.html) | Exposure of Access Control List Files to an Unauthorized Control Sphere | 미지정 |
| [CWE-530](https://cwe.mitre.org/data/definitions/530.html) | Exposure of Backup File to an Unauthorized Control Sphere | 미지정 |
| [CWE-531](https://cwe.mitre.org/data/definitions/531.html) | Inclusion of Sensitive Information in Test Code | 미지정 |
| [CWE-532](https://cwe.mitre.org/data/definitions/532.html) | Insertion of Sensitive Information into Log File | 미지정 |
| [CWE-535](https://cwe.mitre.org/data/definitions/535.html) | Exposure of Information Through Shell Error Message | 미지정 |
| [CWE-536](https://cwe.mitre.org/data/definitions/536.html) | Servlet Runtime Error Message Containing Sensitive Information | 미지정 |
| [CWE-537](https://cwe.mitre.org/data/definitions/537.html) | Java Runtime Error Message Containing Sensitive Information | 미지정 |
| [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | Insertion of Sensitive Information into Externally-Accessible File or Directory | 미지정 |
| [CWE-539](https://cwe.mitre.org/data/definitions/539.html) | Use of Persistent Cookies Containing Sensitive Information | 미지정 |
| [CWE-540](https://cwe.mitre.org/data/definitions/540.html) | Inclusion of Sensitive Information in Source Code | 미지정 |
| [CWE-541](https://cwe.mitre.org/data/definitions/541.html) | Inclusion of Sensitive Information in an Include File | 미지정 |
| [CWE-543](https://cwe.mitre.org/data/definitions/543.html) | Use of Singleton Pattern Without Synchronization in a Multithreaded Context | 미지정 |
| [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | Exposure of Information Through Directory Listing | 미지정 |
| [CWE-549](https://cwe.mitre.org/data/definitions/549.html) | Missing Password Field Masking | 미지정 |
| [CWE-550](https://cwe.mitre.org/data/definitions/550.html) | Server-generated Error Message Containing Sensitive Information | 미지정 |
| [CWE-552](https://cwe.mitre.org/data/definitions/552.html) | Files or Directories Accessible to External Parties | 미지정 |
| [CWE-553](https://cwe.mitre.org/data/definitions/553.html) | Command Shell in Externally Accessible Directory | 미지정 |
| [CWE-555](https://cwe.mitre.org/data/definitions/555.html) | J2EE Misconfiguration: Plaintext Password in Configuration File | 미지정 |
| [CWE-558](https://cwe.mitre.org/data/definitions/558.html) | Use of getlogin() in Multithreaded Application | 미지정 |
| [CWE-565](https://cwe.mitre.org/data/definitions/565.html) | Reliance on Cookies without Validation and Integrity Checking | 미지정 |
| [CWE-567](https://cwe.mitre.org/data/definitions/567.html) | Unsynchronized Access to Shared Data in a Multithreaded Context | 미지정 |
| [CWE-568](https://cwe.mitre.org/data/definitions/568.html) | finalize() Method Without super.finalize() | 미지정 |
| [CWE-572](https://cwe.mitre.org/data/definitions/572.html) | Call to Thread run() instead of start() | 미지정 |
| [CWE-574](https://cwe.mitre.org/data/definitions/574.html) | EJB Bad Practices: Use of Synchronization Primitives | 미지정 |
| [CWE-580](https://cwe.mitre.org/data/definitions/580.html) | clone() Method Without super.clone() | 미지정 |
| [CWE-582](https://cwe.mitre.org/data/definitions/582.html) | Array Declared Public, Final, and Static | 미지정 |
| [CWE-583](https://cwe.mitre.org/data/definitions/583.html) | finalize() Method Declared Public | 미지정 |
| [CWE-588](https://cwe.mitre.org/data/definitions/588.html) | Attempt to Access Child of a Non-structure Pointer | 미지정 |
| [CWE-590](https://cwe.mitre.org/data/definitions/590.html) | Free of Memory not on the Heap | 미지정 |
| [CWE-591](https://cwe.mitre.org/data/definitions/591.html) | Sensitive Data Storage in Improperly Locked Memory | 미지정 |
| [CWE-593](https://cwe.mitre.org/data/definitions/593.html) | Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created | 미지정 |
| [CWE-598](https://cwe.mitre.org/data/definitions/598.html) | Use of HTTP Request With Sensitive Query String | 미지정 |
| [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | URL Redirection to Untrusted Site | 미지정 |
| [CWE-605](https://cwe.mitre.org/data/definitions/605.html) | Multiple Binds to the Same Port | 미지정 |
| [CWE-607](https://cwe.mitre.org/data/definitions/607.html) | Public Static Final Field References Mutable Object | 미지정 |
| [CWE-608](https://cwe.mitre.org/data/definitions/608.html) | Struts: Non-private Field in ActionForm Class | 미지정 |
| [CWE-609](https://cwe.mitre.org/data/definitions/609.html) | Double-Checked Locking | 미지정 |
| [CWE-610](https://cwe.mitre.org/data/definitions/610.html) | Externally Controlled Reference to a Resource in Another Sphere | 미지정 |
| [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | Improper Restriction of XML External Entity Reference | 미지정 |
| [CWE-615](https://cwe.mitre.org/data/definitions/615.html) | Inclusion of Sensitive Information in Source Code Comments | 미지정 |
| [CWE-619](https://cwe.mitre.org/data/definitions/619.html) | Dangling Database Cursor | 미지정 |
| [CWE-621](https://cwe.mitre.org/data/definitions/621.html) | Variable Extraction Error | 미지정 |
| [CWE-627](https://cwe.mitre.org/data/definitions/627.html) | Dynamic Variable Evaluation | 미지정 |
| [CWE-642](https://cwe.mitre.org/data/definitions/642.html) | External Control of Critical State Data | 미지정 |
| [CWE-651](https://cwe.mitre.org/data/definitions/651.html) | Exposure of WSDL File Containing Sensitive Information | 미지정 |
| [CWE-662](https://cwe.mitre.org/data/definitions/662.html) | Improper Synchronization | 미지정 |
| [CWE-663](https://cwe.mitre.org/data/definitions/663.html) | Use of a Non-reentrant Function in a Concurrent Context | 미지정 |
| [CWE-665](https://cwe.mitre.org/data/definitions/665.html) | Improper Initialization | 미지정 |
| [CWE-666](https://cwe.mitre.org/data/definitions/666.html) | Operation on Resource in Wrong Phase of Lifetime | 미지정 |
| [CWE-667](https://cwe.mitre.org/data/definitions/667.html) | Improper Locking | 미지정 |
| [CWE-668](https://cwe.mitre.org/data/definitions/668.html) | Exposure of Resource to Wrong Sphere | 미지정 |
| [CWE-669](https://cwe.mitre.org/data/definitions/669.html) | Incorrect Resource Transfer Between Spheres | 미지정 |
| [CWE-672](https://cwe.mitre.org/data/definitions/672.html) | Operation on a Resource after Expiration or Release | 미지정 |
| [CWE-673](https://cwe.mitre.org/data/definitions/673.html) | External Influence of Sphere Definition | 미지정 |
| [CWE-681](https://cwe.mitre.org/data/definitions/681.html) | Incorrect Conversion between Numeric Types | 미지정 |
| [CWE-689](https://cwe.mitre.org/data/definitions/689.html) | Permission Race Condition During Resource Copy | 미지정 |
| [CWE-704](https://cwe.mitre.org/data/definitions/704.html) | Incorrect Type Conversion or Cast | 미지정 |
| [CWE-706](https://cwe.mitre.org/data/definitions/706.html) | Use of Incorrectly-Resolved Name or Reference | 미지정 |
| [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | Incorrect Permission Assignment for Critical Resource | 미지정 |
| [CWE-761](https://cwe.mitre.org/data/definitions/761.html) | Free of Pointer not at Start of Buffer | 미지정 |
| [CWE-762](https://cwe.mitre.org/data/definitions/762.html) | Mismatched Memory Management Routines | 미지정 |
| [CWE-763](https://cwe.mitre.org/data/definitions/763.html) | Release of Invalid Pointer or Reference | 미지정 |
| [CWE-764](https://cwe.mitre.org/data/definitions/764.html) | Multiple Locks of a Critical Resource | 미지정 |
| [CWE-765](https://cwe.mitre.org/data/definitions/765.html) | Multiple Unlocks of a Critical Resource | 미지정 |
| [CWE-766](https://cwe.mitre.org/data/definitions/766.html) | Critical Data Element Declared Public | 미지정 |
| [CWE-767](https://cwe.mitre.org/data/definitions/767.html) | Access to Critical Private Variable via Public Method | 미지정 |
| [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | Allocation of Resources Without Limits or Throttling | 미지정 |
| [CWE-771](https://cwe.mitre.org/data/definitions/771.html) | Missing Reference to Active Allocated Resource | 미지정 |
| [CWE-772](https://cwe.mitre.org/data/definitions/772.html) | Missing Release of Resource after Effective Lifetime | 미지정 |
| [CWE-773](https://cwe.mitre.org/data/definitions/773.html) | Missing Reference to Active File Descriptor or Handle | 미지정 |
| [CWE-774](https://cwe.mitre.org/data/definitions/774.html) | Allocation of File Descriptors or Handles Without Limits or Throttling | 미지정 |
| [CWE-775](https://cwe.mitre.org/data/definitions/775.html) | Missing Release of File Descriptor or Handle after Effective Lifetime | 미지정 |
| [CWE-776](https://cwe.mitre.org/data/definitions/776.html) | Improper Restriction of Recursive Entity References in DTDs | 미지정 |
| [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | Insufficient Logging | 미지정 |
| [CWE-779](https://cwe.mitre.org/data/definitions/779.html) | Logging of Excessive Data | 미지정 |
| [CWE-784](https://cwe.mitre.org/data/definitions/784.html) | Reliance on Cookies without Validation and Integrity Checking in a Security Decision | 미지정 |
| [CWE-785](https://cwe.mitre.org/data/definitions/785.html) | Use of Path Manipulation Function without Maximum-sized Buffer | 미지정 |
| [CWE-786](https://cwe.mitre.org/data/definitions/786.html) | Access of Memory Location Before Start of Buffer | 미지정 |
| [CWE-787](https://cwe.mitre.org/data/definitions/787.html) | Out-of-bounds Write | 미지정 |
| [CWE-788](https://cwe.mitre.org/data/definitions/788.html) | Access of Memory Location After End of Buffer | 미지정 |
| [CWE-789](https://cwe.mitre.org/data/definitions/789.html) | Memory Allocation with Excessive Size Value | 미지정 |
| [CWE-805](https://cwe.mitre.org/data/definitions/805.html) | Buffer Access with Incorrect Length Value | 미지정 |
| [CWE-806](https://cwe.mitre.org/data/definitions/806.html) | Buffer Access Using Size of Source Buffer | 미지정 |
| [CWE-820](https://cwe.mitre.org/data/definitions/820.html) | Missing Synchronization | 미지정 |
| [CWE-821](https://cwe.mitre.org/data/definitions/821.html) | Incorrect Synchronization | 미지정 |
| [CWE-822](https://cwe.mitre.org/data/definitions/822.html) | Untrusted Pointer Dereference | 미지정 |
| [CWE-823](https://cwe.mitre.org/data/definitions/823.html) | Use of Out-of-range Pointer Offset | 미지정 |
| [CWE-824](https://cwe.mitre.org/data/definitions/824.html) | Access of Uninitialized Pointer | 미지정 |
| [CWE-825](https://cwe.mitre.org/data/definitions/825.html) | Expired Pointer Dereference | 미지정 |
| [CWE-826](https://cwe.mitre.org/data/definitions/826.html) | Premature Release of Resource During Expected Lifetime | 미지정 |
| [CWE-827](https://cwe.mitre.org/data/definitions/827.html) | Improper Control of Document Type Definition | 미지정 |
| [CWE-828](https://cwe.mitre.org/data/definitions/828.html) | Signal Handler with Functionality that is not Asynchronous-Safe | 미지정 |
| [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | Inclusion of Functionality from Untrusted Control Sphere | 미지정 |
| [CWE-830](https://cwe.mitre.org/data/definitions/830.html) | Inclusion of Web Functionality from an Untrusted Source | 미지정 |
| [CWE-831](https://cwe.mitre.org/data/definitions/831.html) | Signal Handler Function Associated with Multiple Signals | 미지정 |
| [CWE-832](https://cwe.mitre.org/data/definitions/832.html) | Unlock of a Resource that is not Locked | 미지정 |
| [CWE-833](https://cwe.mitre.org/data/definitions/833.html) | Deadlock | 미지정 |
| [CWE-843](https://cwe.mitre.org/data/definitions/843.html) | Access of Resource Using Incompatible Type | 미지정 |
| [CWE-908](https://cwe.mitre.org/data/definitions/908.html) | Use of Uninitialized Resource | 미지정 |
| [CWE-909](https://cwe.mitre.org/data/definitions/909.html) | Missing Initialization of Resource | 미지정 |
| [CWE-910](https://cwe.mitre.org/data/definitions/910.html) | Use of Expired File Descriptor | 미지정 |
| [CWE-911](https://cwe.mitre.org/data/definitions/911.html) | Improper Update of Reference Count | 미지정 |
| [CWE-913](https://cwe.mitre.org/data/definitions/913.html) | Improper Control of Dynamically-Managed Code Resources | 미지정 |
| [CWE-914](https://cwe.mitre.org/data/definitions/914.html) | Improper Control of Dynamically-Identified Variables | 미지정 |
| [CWE-915](https://cwe.mitre.org/data/definitions/915.html) | Improperly Controlled Modification of Dynamically-Determined Object Attributes | 미지정 |
| [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | Server-Side Request Forgery | 미지정 |
| [CWE-920](https://cwe.mitre.org/data/definitions/920.html) | Improper Restriction of Power Consumption | 미지정 |
| [CWE-921](https://cwe.mitre.org/data/definitions/921.html) | Storage of Sensitive Data in a Mechanism without Access Control | 미지정 |
| [CWE-922](https://cwe.mitre.org/data/definitions/922.html) | Insecure Storage of Sensitive Information | 미지정 |
| [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) | Sensitive Cookie Without 'HttpOnly' Flag | 미지정 |
| [CWE-1007](https://cwe.mitre.org/data/definitions/1007.html) | Insufficient Visual Distinction of Homoglyphs Presented to User | 미지정 |
| [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | Improper Restriction of Rendered UI Layers or Frames | 미지정 |
| [CWE-1042](https://cwe.mitre.org/data/definitions/1042.html) | Static Member Data Element outside of a Singleton Class Element | 미지정 |
| [CWE-1046](https://cwe.mitre.org/data/definitions/1046.html) | Creation of Immutable Text Using String Concatenation | 미지정 |
| [CWE-1049](https://cwe.mitre.org/data/definitions/1049.html) | Excessive Data Query Operations in a Large Data Table | 미지정 |
| [CWE-1050](https://cwe.mitre.org/data/definitions/1050.html) | Excessive Platform Resource Consumption within a Loop | 미지정 |
| [CWE-1051](https://cwe.mitre.org/data/definitions/1051.html) | Initialization with Hard-Coded Network Resource Configuration Data | 미지정 |
| [CWE-1052](https://cwe.mitre.org/data/definitions/1052.html) | Excessive Use of Hard-Coded Literals in Initialization | 미지정 |
| [CWE-1058](https://cwe.mitre.org/data/definitions/1058.html) | Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element | 미지정 |
| [CWE-1063](https://cwe.mitre.org/data/definitions/1063.html) | Creation of Class Instance within a Static Code Block | 미지정 |
| [CWE-1067](https://cwe.mitre.org/data/definitions/1067.html) | Excessive Execution of Sequential Searches of Data Resource | 미지정 |
| [CWE-1072](https://cwe.mitre.org/data/definitions/1072.html) | Data Resource Access without Use of Connection Pooling | 미지정 |
| [CWE-1073](https://cwe.mitre.org/data/definitions/1073.html) | Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses | 미지정 |
| [CWE-1084](https://cwe.mitre.org/data/definitions/1084.html) | Invokable Control Element with Excessive File or Data Access Operations | 미지정 |
| [CWE-1088](https://cwe.mitre.org/data/definitions/1088.html) | Synchronous Access of Remote Resource without Timeout | 미지정 |
| [CWE-1089](https://cwe.mitre.org/data/definitions/1089.html) | Large Data Table with Excessive Number of Indices | 미지정 |
| [CWE-1091](https://cwe.mitre.org/data/definitions/1091.html) | Use of Object without Invoking Destructor Method | 미지정 |
| [CWE-1094](https://cwe.mitre.org/data/definitions/1094.html) | Excessive Index Range Scan for a Data Resource | 미지정 |
| [CWE-1096](https://cwe.mitre.org/data/definitions/1096.html) | Singleton Class Instance Creation without Proper Locking or Synchronization | 미지정 |
| [CWE-1176](https://cwe.mitre.org/data/definitions/1176.html) | Inefficient CPU Computation | 미지정 |
| [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) | Initialization of a Resource with an Insecure Default | 미지정 |
| [CWE-1189](https://cwe.mitre.org/data/definitions/1189.html) | Improper Isolation of Shared Resources on System-on-a-Chip (SoC) | 미지정 |
| [CWE-1221](https://cwe.mitre.org/data/definitions/1221.html) | Incorrect Register Defaults or Module Parameters | 미지정 |
| [CWE-1223](https://cwe.mitre.org/data/definitions/1223.html) | Race Condition for Write-Once Attributes | 미지정 |
| [CWE-1229](https://cwe.mitre.org/data/definitions/1229.html) | Creation of Emergent Resource | 미지정 |
| [CWE-1232](https://cwe.mitre.org/data/definitions/1232.html) | Improper Lock Behavior After Power State Transition | 미지정 |
| [CWE-1233](https://cwe.mitre.org/data/definitions/1233.html) | Security-Sensitive Hardware Controls with Missing Lock Bit Protection | 미지정 |
| [CWE-1234](https://cwe.mitre.org/data/definitions/1234.html) | Hardware Internal or Debug Modes Allow Override of Locks | 미지정 |
| [CWE-1235](https://cwe.mitre.org/data/definitions/1235.html) | Incorrect Use of Autoboxing and Unboxing for Performance Critical Operations | 미지정 |
| [CWE-1239](https://cwe.mitre.org/data/definitions/1239.html) | Improper Zeroization of Hardware Register | 미지정 |
| [CWE-1246](https://cwe.mitre.org/data/definitions/1246.html) | Improper Write Handling in Limited-write Non-Volatile Memories | 미지정 |
| [CWE-1249](https://cwe.mitre.org/data/definitions/1249.html) | Application-Level Admin Tool with Inconsistent View of Underlying Operating System | 미지정 |
| [CWE-1250](https://cwe.mitre.org/data/definitions/1250.html) | Improper Preservation of Consistency Between Independent Representations of Shared State | 미지정 |
| [CWE-1251](https://cwe.mitre.org/data/definitions/1251.html) | Mirrored Regions with Different Values | 미지정 |
| [CWE-1254](https://cwe.mitre.org/data/definitions/1254.html) | Incorrect Comparison Logic Granularity | 미지정 |
| [CWE-1255](https://cwe.mitre.org/data/definitions/1255.html) | Comparison Logic is Vulnerable to Power Side-Channel Attacks | 미지정 |
| [CWE-1258](https://cwe.mitre.org/data/definitions/1258.html) | Exposure of Sensitive System Information Due to Uncleared Debug Information | 미지정 |
| [CWE-1264](https://cwe.mitre.org/data/definitions/1264.html) | Hardware Logic with Insecure De-Synchronization between Control and Data Channels | 미지정 |
| [CWE-1265](https://cwe.mitre.org/data/definitions/1265.html) | Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls | 미지정 |
| [CWE-1266](https://cwe.mitre.org/data/definitions/1266.html) | Improper Scrubbing of Sensitive Data from Decommissioned Device | 미지정 |
| [CWE-1271](https://cwe.mitre.org/data/definitions/1271.html) | Uninitialized Value on Reset for Registers Holding Security Settings | 미지정 |
| [CWE-1272](https://cwe.mitre.org/data/definitions/1272.html) | Sensitive Information Uncleared Before Debug/Power State Transition | 미지정 |
| [CWE-1273](https://cwe.mitre.org/data/definitions/1273.html) | Device Unlock Credential Sharing | 미지정 |
| [CWE-1277](https://cwe.mitre.org/data/definitions/1277.html) | Firmware Not Updateable | 미지정 |
| [CWE-1279](https://cwe.mitre.org/data/definitions/1279.html) | Cryptographic Operations are Run Before Supporting Units are Ready | 미지정 |
| [CWE-1282](https://cwe.mitre.org/data/definitions/1282.html) | Assumed-Immutable Data is Stored in Writable Memory | 미지정 |
| [CWE-1295](https://cwe.mitre.org/data/definitions/1295.html) | Debug Messages Revealing Unnecessary Information | 미지정 |
| [CWE-1298](https://cwe.mitre.org/data/definitions/1298.html) | Hardware Logic Contains Race Conditions | 미지정 |
| [CWE-1300](https://cwe.mitre.org/data/definitions/1300.html) | Improper Protection of Physical Side Channels | 미지정 |
| [CWE-1301](https://cwe.mitre.org/data/definitions/1301.html) | Insufficient or Incomplete Data Removal within Hardware Component | 미지정 |
| [CWE-1303](https://cwe.mitre.org/data/definitions/1303.html) | Non-Transparent Sharing of Microarchitectural Resources | 미지정 |
| [CWE-1310](https://cwe.mitre.org/data/definitions/1310.html) | Missing Ability to Patch ROM Code | 미지정 |
| [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) | Improperly Controlled Modification of Object Prototype Attributes | 미지정 |
| [CWE-1325](https://cwe.mitre.org/data/definitions/1325.html) | Improperly Controlled Sequential Memory Allocation | 미지정 |
| [CWE-1329](https://cwe.mitre.org/data/definitions/1329.html) | Reliance on Component That is Not Updateable | 미지정 |
| [CWE-1330](https://cwe.mitre.org/data/definitions/1330.html) | Remanent Data Readable after Memory Erase | 미지정 |
| [CWE-1331](https://cwe.mitre.org/data/definitions/1331.html) | Improper Isolation of Shared Resources in Network On Chip (NoC) | 미지정 |
| [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html) | Inefficient Regular Expression Complexity | 미지정 |
| [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) | Improper Neutralization of Special Elements Used in a Template Engine | 미지정 |
| [CWE-1342](https://cwe.mitre.org/data/definitions/1342.html) | Information Exposure through Microarchitectural State after Transient Execution | 미지정 |
| [CWE-1386](https://cwe.mitre.org/data/definitions/1386.html) | Insecure Operation on Windows Junction / Mount Point | 미지정 |
| [CWE-1389](https://cwe.mitre.org/data/definitions/1389.html) | Incorrect Parsing of Numbers with Different Radices | 미지정 |
| [CWE-1419](https://cwe.mitre.org/data/definitions/1419.html) | Incorrect Initialization of Resource | 미지정 |
| [CWE-1420](https://cwe.mitre.org/data/definitions/1420.html) | Exposure of Sensitive Information during Transient Execution | 미지정 |
| [CWE-1421](https://cwe.mitre.org/data/definitions/1421.html) | Exposure of Sensitive Information in Shared Microarchitectural Structures during Transient Execution | 미지정 |
| [CWE-1422](https://cwe.mitre.org/data/definitions/1422.html) | Exposure of Sensitive Information caused by Incorrect Data Forwarding during Transient Execution | 미지정 |
| [CWE-1423](https://cwe.mitre.org/data/definitions/1423.html) | Exposure of Sensitive Information caused by Shared Microarchitectural Predictor State that Influences Transient Execution | 미지정 |
| [CWE-1429](https://cwe.mitre.org/data/definitions/1429.html) | Missing Security-Relevant Feedback for Unexecuted Operations in Hardware Interface | 미지정 |
| [CWE-1431](https://cwe.mitre.org/data/definitions/1431.html) | Driving Intermediate Cryptographic State/Results to Hardware Module Outputs | 미지정 |
| [CWE-1434](https://cwe.mitre.org/data/definitions/1434.html) | Insecure Setting of Generative AI/ML Model Inference Parameters | 미지정 |
| [CWE-1472](https://cwe.mitre.org/data/definitions/1472.html) | Generation of Credential with Long Expiration | 미지정 |
| [CWE-1473](https://cwe.mitre.org/data/definitions/1473.html) | Improper Expiration of Cached Data | 미지정 |
| [CWE-1474](https://cwe.mitre.org/data/definitions/1474.html) | Non-Equivalent Data Transformation | 미지정 |
| [CWE-1475](https://cwe.mitre.org/data/definitions/1475.html) | Incomplete Data/State Propagation | 미지정 |

</details>

<details>
<summary>CWE-682 · Incorrect Calculation · 13개 소속</summary>

| 세부 CWE | 공식 이름 | 현재 증거 경로 |
| --- | --- | --- |
| [CWE-128](https://cwe.mitre.org/data/definitions/128.html) | Wrap-around Error | 미지정 |
| [CWE-131](https://cwe.mitre.org/data/definitions/131.html) | Incorrect Calculation of Buffer Size | 미지정 |
| [CWE-135](https://cwe.mitre.org/data/definitions/135.html) | Incorrect Calculation of Multi-Byte String Length | 미지정 |
| [CWE-190](https://cwe.mitre.org/data/definitions/190.html) | Integer Overflow or Wraparound | 미지정 |
| [CWE-191](https://cwe.mitre.org/data/definitions/191.html) | Integer Underflow (Wrap or Wraparound) | 미지정 |
| [CWE-193](https://cwe.mitre.org/data/definitions/193.html) | Off-by-one Error | 미지정 |
| [CWE-369](https://cwe.mitre.org/data/definitions/369.html) | Divide By Zero | 미지정 |
| [CWE-467](https://cwe.mitre.org/data/definitions/467.html) | Use of sizeof() on a Pointer Type | 미지정 |
| [CWE-468](https://cwe.mitre.org/data/definitions/468.html) | Incorrect Pointer Scaling | 미지정 |
| [CWE-469](https://cwe.mitre.org/data/definitions/469.html) | Use of Pointer Subtraction to Determine Size | 미지정 |
| [CWE-680](https://cwe.mitre.org/data/definitions/680.html) | Integer Overflow to Buffer Overflow | 미지정 |
| [CWE-1335](https://cwe.mitre.org/data/definitions/1335.html) | Incorrect Bitwise Shift of Integer | 미지정 |
| [CWE-1339](https://cwe.mitre.org/data/definitions/1339.html) | Insufficient Precision or Accuracy of a Real Number | 미지정 |

</details>

<details>
<summary>CWE-691 · Insufficient Control Flow Management · 86개 소속</summary>

| 세부 CWE | 공식 이름 | 현재 증거 경로 |
| --- | --- | --- |
| [CWE-179](https://cwe.mitre.org/data/definitions/179.html) | Incorrect Behavior Order: Early Validation | 미지정 |
| [CWE-180](https://cwe.mitre.org/data/definitions/180.html) | Incorrect Behavior Order: Validate Before Canonicalize | 미지정 |
| [CWE-181](https://cwe.mitre.org/data/definitions/181.html) | Incorrect Behavior Order: Validate Before Filter | 미지정 |
| [CWE-248](https://cwe.mitre.org/data/definitions/248.html) | Uncaught Exception | 미지정 |
| [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | Improper Restriction of Excessive Authentication Attempts | 미지정 |
| [CWE-362](https://cwe.mitre.org/data/definitions/362.html) | Concurrent Execution using Shared Resource with Improper Synchronization | 미지정 |
| [CWE-363](https://cwe.mitre.org/data/definitions/363.html) | Race Condition Enabling Link Following | 미지정 |
| [CWE-364](https://cwe.mitre.org/data/definitions/364.html) | Signal Handler Race Condition | 미지정 |
| [CWE-366](https://cwe.mitre.org/data/definitions/366.html) | Race Condition within a Thread | 미지정 |
| [CWE-367](https://cwe.mitre.org/data/definitions/367.html) | Time-of-check Time-of-use (TOCTOU) Race Condition | 미지정 |
| [CWE-368](https://cwe.mitre.org/data/definitions/368.html) | Context Switching Race Condition | 미지정 |
| [CWE-382](https://cwe.mitre.org/data/definitions/382.html) | J2EE Bad Practices: Use of System.exit() | 미지정 |
| [CWE-395](https://cwe.mitre.org/data/definitions/395.html) | Use of NullPointerException Catch to Detect NULL Pointer Dereference | 미지정 |
| [CWE-396](https://cwe.mitre.org/data/definitions/396.html) | Declaration of Catch for Generic Exception | 미지정 |
| [CWE-397](https://cwe.mitre.org/data/definitions/397.html) | Declaration of Throws for Generic Exception | 미지정 |
| [CWE-408](https://cwe.mitre.org/data/definitions/408.html) | Incorrect Behavior Order: Early Amplification | 미지정 |
| [CWE-412](https://cwe.mitre.org/data/definitions/412.html) | Unrestricted Externally Accessible Lock | 미지정 |
| [CWE-413](https://cwe.mitre.org/data/definitions/413.html) | Improper Resource Locking | 미지정 |
| [CWE-414](https://cwe.mitre.org/data/definitions/414.html) | Missing Lock Check | 미지정 |
| [CWE-421](https://cwe.mitre.org/data/definitions/421.html) | Race Condition During Access to Alternate Channel | 미지정 |
| [CWE-430](https://cwe.mitre.org/data/definitions/430.html) | Deployment of Wrong Handler | 미지정 |
| [CWE-431](https://cwe.mitre.org/data/definitions/431.html) | Missing Handler | 미지정 |
| [CWE-432](https://cwe.mitre.org/data/definitions/432.html) | Dangerous Signal Handler not Disabled During Sensitive Operations | 미지정 |
| [CWE-455](https://cwe.mitre.org/data/definitions/455.html) | Non-exit on Failed Initialization | 미지정 |
| [CWE-479](https://cwe.mitre.org/data/definitions/479.html) | Signal Handler Use of a Non-reentrant Function | 미지정 |
| [CWE-480](https://cwe.mitre.org/data/definitions/480.html) | Use of Incorrect Operator | 미지정 |
| [CWE-481](https://cwe.mitre.org/data/definitions/481.html) | Assigning instead of Comparing | 미지정 |
| [CWE-482](https://cwe.mitre.org/data/definitions/482.html) | Comparing instead of Assigning | 미지정 |
| [CWE-483](https://cwe.mitre.org/data/definitions/483.html) | Incorrect Block Delimitation | 미지정 |
| [CWE-484](https://cwe.mitre.org/data/definitions/484.html) | Omitted Break Statement in Switch | 미지정 |
| [CWE-543](https://cwe.mitre.org/data/definitions/543.html) | Use of Singleton Pattern Without Synchronization in a Multithreaded Context | 미지정 |
| [CWE-551](https://cwe.mitre.org/data/definitions/551.html) | Incorrect Behavior Order: Authorization Before Parsing and Canonicalization | 미지정 |
| [CWE-558](https://cwe.mitre.org/data/definitions/558.html) | Use of getlogin() in Multithreaded Application | 미지정 |
| [CWE-567](https://cwe.mitre.org/data/definitions/567.html) | Unsynchronized Access to Shared Data in a Multithreaded Context | 미지정 |
| [CWE-572](https://cwe.mitre.org/data/definitions/572.html) | Call to Thread run() instead of start() | 미지정 |
| [CWE-574](https://cwe.mitre.org/data/definitions/574.html) | EJB Bad Practices: Use of Synchronization Primitives | 미지정 |
| [CWE-584](https://cwe.mitre.org/data/definitions/584.html) | Return Inside Finally Block | 미지정 |
| [CWE-591](https://cwe.mitre.org/data/definitions/591.html) | Sensitive Data Storage in Improperly Locked Memory | 미지정 |
| [CWE-597](https://cwe.mitre.org/data/definitions/597.html) | Use of Wrong Operator in String Comparison | 미지정 |
| [CWE-600](https://cwe.mitre.org/data/definitions/600.html) | Uncaught Exception in Servlet | 미지정 |
| [CWE-609](https://cwe.mitre.org/data/definitions/609.html) | Double-Checked Locking | 미지정 |
| [CWE-617](https://cwe.mitre.org/data/definitions/617.html) | Reachable Assertion | 미지정 |
| [CWE-647](https://cwe.mitre.org/data/definitions/647.html) | Use of Non-Canonical URL Paths for Authorization Decisions | 미지정 |
| [CWE-662](https://cwe.mitre.org/data/definitions/662.html) | Improper Synchronization | 미지정 |
| [CWE-663](https://cwe.mitre.org/data/definitions/663.html) | Use of a Non-reentrant Function in a Concurrent Context | 미지정 |
| [CWE-667](https://cwe.mitre.org/data/definitions/667.html) | Improper Locking | 미지정 |
| [CWE-670](https://cwe.mitre.org/data/definitions/670.html) | Always-Incorrect Control Flow Implementation | 미지정 |
| [CWE-674](https://cwe.mitre.org/data/definitions/674.html) | Uncontrolled Recursion | 미지정 |
| [CWE-689](https://cwe.mitre.org/data/definitions/689.html) | Permission Race Condition During Resource Copy | 미지정 |
| [CWE-696](https://cwe.mitre.org/data/definitions/696.html) | Incorrect Behavior Order | 미지정 |
| [CWE-698](https://cwe.mitre.org/data/definitions/698.html) | Execution After Redirect (EAR) | 미지정 |
| [CWE-705](https://cwe.mitre.org/data/definitions/705.html) | Incorrect Control Flow Scoping | 미지정 |
| [CWE-764](https://cwe.mitre.org/data/definitions/764.html) | Multiple Locks of a Critical Resource | 미지정 |
| [CWE-765](https://cwe.mitre.org/data/definitions/765.html) | Multiple Unlocks of a Critical Resource | 미지정 |
| [CWE-768](https://cwe.mitre.org/data/definitions/768.html) | Incorrect Short Circuit Evaluation | 미지정 |
| [CWE-776](https://cwe.mitre.org/data/definitions/776.html) | Improper Restriction of Recursive Entity References in DTDs | 미지정 |
| [CWE-783](https://cwe.mitre.org/data/definitions/783.html) | Operator Precedence Logic Error | 미지정 |
| [CWE-799](https://cwe.mitre.org/data/definitions/799.html) | Improper Control of Interaction Frequency | 미지정 |
| [CWE-820](https://cwe.mitre.org/data/definitions/820.html) | Missing Synchronization | 미지정 |
| [CWE-821](https://cwe.mitre.org/data/definitions/821.html) | Incorrect Synchronization | 미지정 |
| [CWE-828](https://cwe.mitre.org/data/definitions/828.html) | Signal Handler with Functionality that is not Asynchronous-Safe | 미지정 |
| [CWE-831](https://cwe.mitre.org/data/definitions/831.html) | Signal Handler Function Associated with Multiple Signals | 미지정 |
| [CWE-832](https://cwe.mitre.org/data/definitions/832.html) | Unlock of a Resource that is not Locked | 미지정 |
| [CWE-833](https://cwe.mitre.org/data/definitions/833.html) | Deadlock | 미지정 |
| [CWE-834](https://cwe.mitre.org/data/definitions/834.html) | Excessive Iteration | 미지정 |
| [CWE-835](https://cwe.mitre.org/data/definitions/835.html) | Loop with Unreachable Exit Condition | 미지정 |
| [CWE-837](https://cwe.mitre.org/data/definitions/837.html) | Improper Enforcement of a Single, Unique Action | 미지정 |
| [CWE-841](https://cwe.mitre.org/data/definitions/841.html) | Improper Enforcement of Behavioral Workflow | 미지정 |
| [CWE-1058](https://cwe.mitre.org/data/definitions/1058.html) | Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element | 미지정 |
| [CWE-1077](https://cwe.mitre.org/data/definitions/1077.html) | Floating Point Comparison with Incorrect Operator | 미지정 |
| [CWE-1088](https://cwe.mitre.org/data/definitions/1088.html) | Synchronous Access of Remote Resource without Timeout | 미지정 |
| [CWE-1096](https://cwe.mitre.org/data/definitions/1096.html) | Singleton Class Instance Creation without Proper Locking or Synchronization | 미지정 |
| [CWE-1190](https://cwe.mitre.org/data/definitions/1190.html) | DMA Device Enabled Too Early in Boot Phase | 미지정 |
| [CWE-1193](https://cwe.mitre.org/data/definitions/1193.html) | Power-On of Untrusted Execution Core Before Enabling Fabric Access Control | 미지정 |
| [CWE-1223](https://cwe.mitre.org/data/definitions/1223.html) | Race Condition for Write-Once Attributes | 미지정 |
| [CWE-1232](https://cwe.mitre.org/data/definitions/1232.html) | Improper Lock Behavior After Power State Transition | 미지정 |
| [CWE-1233](https://cwe.mitre.org/data/definitions/1233.html) | Security-Sensitive Hardware Controls with Missing Lock Bit Protection | 미지정 |
| [CWE-1234](https://cwe.mitre.org/data/definitions/1234.html) | Hardware Internal or Debug Modes Allow Override of Locks | 미지정 |
| [CWE-1264](https://cwe.mitre.org/data/definitions/1264.html) | Hardware Logic with Insecure De-Synchronization between Control and Data Channels | 미지정 |
| [CWE-1265](https://cwe.mitre.org/data/definitions/1265.html) | Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls | 미지정 |
| [CWE-1279](https://cwe.mitre.org/data/definitions/1279.html) | Cryptographic Operations are Run Before Supporting Units are Ready | 미지정 |
| [CWE-1280](https://cwe.mitre.org/data/definitions/1280.html) | Access Control Check Implemented After Asset is Accessed | 미지정 |
| [CWE-1281](https://cwe.mitre.org/data/definitions/1281.html) | Sequence of Processor Instructions Leads to Unexpected Behavior | 미지정 |
| [CWE-1298](https://cwe.mitre.org/data/definitions/1298.html) | Hardware Logic Contains Race Conditions | 미지정 |
| [CWE-1322](https://cwe.mitre.org/data/definitions/1322.html) | Use of Blocking Code in Single-threaded, Non-blocking Context | 미지정 |
| [CWE-1476](https://cwe.mitre.org/data/definitions/1476.html) | Improper Request Propagation before Data Reception in Write Transactions in a Bus Architecture | 미지정 |

</details>

<details>
<summary>CWE-693 · Protection Mechanism Failure · 103개 소속</summary>

| 세부 CWE | 공식 이름 | 현재 증거 경로 |
| --- | --- | --- |
| [CWE-5](https://cwe.mitre.org/data/definitions/5.html) | J2EE Misconfiguration: Data Transmission Without Encryption | 미지정 |
| [CWE-6](https://cwe.mitre.org/data/definitions/6.html) | J2EE Misconfiguration: Insufficient Session-ID Length | 미지정 |
| [CWE-184](https://cwe.mitre.org/data/definitions/184.html) | Incomplete List of Disallowed Inputs | 미지정 |
| [CWE-259](https://cwe.mitre.org/data/definitions/259.html) | Use of Hard-coded Password | 미지정 |
| [CWE-302](https://cwe.mitre.org/data/definitions/302.html) | Authentication Bypass by Assumed-Immutable Data | 미지정 |
| [CWE-308](https://cwe.mitre.org/data/definitions/308.html) | Use of Single-factor Authentication | 미지정 |
| [CWE-309](https://cwe.mitre.org/data/definitions/309.html) | Use of Password System for Primary Authentication | 미지정 |
| [CWE-311](https://cwe.mitre.org/data/definitions/311.html) | Missing Encryption of Sensitive Data | 미지정 |
| [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | Cleartext Storage of Sensitive Information | 미지정 |
| [CWE-313](https://cwe.mitre.org/data/definitions/313.html) | Cleartext Storage in a File or on Disk | 미지정 |
| [CWE-314](https://cwe.mitre.org/data/definitions/314.html) | Cleartext Storage in the Registry | 미지정 |
| [CWE-315](https://cwe.mitre.org/data/definitions/315.html) | Cleartext Storage of Sensitive Information in a Cookie | 미지정 |
| [CWE-316](https://cwe.mitre.org/data/definitions/316.html) | Cleartext Storage of Sensitive Information in Memory | 미지정 |
| [CWE-317](https://cwe.mitre.org/data/definitions/317.html) | Cleartext Storage of Sensitive Information in GUI | 미지정 |
| [CWE-318](https://cwe.mitre.org/data/definitions/318.html) | Cleartext Storage of Sensitive Information in Executable | 미지정 |
| [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | Cleartext Transmission of Sensitive Information | 미지정 |
| [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | Use of Hard-coded Cryptographic Key | 미지정 |
| [CWE-323](https://cwe.mitre.org/data/definitions/323.html) | Reusing a Nonce, Key Pair in Encryption | 미지정 |
| [CWE-325](https://cwe.mitre.org/data/definitions/325.html) | Missing Cryptographic Step | 미지정 |
| [CWE-326](https://cwe.mitre.org/data/definitions/326.html) | Inadequate Encryption Strength | 미지정 |
| [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | Use of a Broken or Risky Cryptographic Algorithm | 미지정 |
| [CWE-328](https://cwe.mitre.org/data/definitions/328.html) | Use of Weak Hash | 미지정 |
| [CWE-329](https://cwe.mitre.org/data/definitions/329.html) | Generation of Predictable IV with CBC Mode | 미지정 |
| [CWE-330](https://cwe.mitre.org/data/definitions/330.html) | Use of Insufficiently Random Values | 미지정 |
| [CWE-331](https://cwe.mitre.org/data/definitions/331.html) | Insufficient Entropy | 미지정 |
| [CWE-332](https://cwe.mitre.org/data/definitions/332.html) | Insufficient Entropy in PRNG | 미지정 |
| [CWE-333](https://cwe.mitre.org/data/definitions/333.html) | Improper Handling of Insufficient Entropy in TRNG | 미지정 |
| [CWE-334](https://cwe.mitre.org/data/definitions/334.html) | Small Space of Random Values | 미지정 |
| [CWE-335](https://cwe.mitre.org/data/definitions/335.html) | Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG) | 미지정 |
| [CWE-336](https://cwe.mitre.org/data/definitions/336.html) | Same Seed in Pseudo-Random Number Generator (PRNG) | 미지정 |
| [CWE-337](https://cwe.mitre.org/data/definitions/337.html) | Predictable Seed in Pseudo-Random Number Generator (PRNG) | 미지정 |
| [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) | 미지정 |
| [CWE-339](https://cwe.mitre.org/data/definitions/339.html) | Small Seed Space in PRNG | 미지정 |
| [CWE-340](https://cwe.mitre.org/data/definitions/340.html) | Generation of Predictable Numbers or Identifiers | 미지정 |
| [CWE-341](https://cwe.mitre.org/data/definitions/341.html) | Predictable from Observable State | 미지정 |
| [CWE-342](https://cwe.mitre.org/data/definitions/342.html) | Predictable Exact Value from Previous Values | 미지정 |
| [CWE-343](https://cwe.mitre.org/data/definitions/343.html) | Predictable Value Range from Previous Values | 미지정 |
| [CWE-344](https://cwe.mitre.org/data/definitions/344.html) | Use of Invariant Value in Dynamically Changing Context | 미지정 |
| [CWE-345](https://cwe.mitre.org/data/definitions/345.html) | Insufficient Verification of Data Authenticity | 미지정 |
| [CWE-346](https://cwe.mitre.org/data/definitions/346.html) | Origin Validation Error | 미지정 |
| [CWE-347](https://cwe.mitre.org/data/definitions/347.html) | Improper Verification of Cryptographic Signature | 미지정 |
| [CWE-348](https://cwe.mitre.org/data/definitions/348.html) | Use of Less Trusted Source | 미지정 |
| [CWE-349](https://cwe.mitre.org/data/definitions/349.html) | Acceptance of Extraneous Untrusted Data With Trusted Data | 미지정 |
| [CWE-350](https://cwe.mitre.org/data/definitions/350.html) | Reliance on Reverse DNS Resolution for a Security-Critical Action | 미지정 |
| [CWE-351](https://cwe.mitre.org/data/definitions/351.html) | Insufficient Type Distinction | 미지정 |
| [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | Cross-Site Request Forgery | 미지정 |
| [CWE-353](https://cwe.mitre.org/data/definitions/353.html) | Missing Support for Integrity Check | 미지정 |
| [CWE-354](https://cwe.mitre.org/data/definitions/354.html) | Improper Validation of Integrity Check Value | 미지정 |
| [CWE-357](https://cwe.mitre.org/data/definitions/357.html) | Insufficient UI Warning of Dangerous Operations | 미지정 |
| [CWE-358](https://cwe.mitre.org/data/definitions/358.html) | Improperly Implemented Security Check for Standard | 미지정 |
| [CWE-360](https://cwe.mitre.org/data/definitions/360.html) | Trust of System Event Data | 미지정 |
| [CWE-422](https://cwe.mitre.org/data/definitions/422.html) | Unprotected Windows Messaging Channel | 미지정 |
| [CWE-424](https://cwe.mitre.org/data/definitions/424.html) | Improper Protection of Alternate Path | 미지정 |
| [CWE-425](https://cwe.mitre.org/data/definitions/425.html) | Direct Request | 미지정 |
| [CWE-450](https://cwe.mitre.org/data/definitions/450.html) | Multiple Interpretations of UI Input | 미지정 |
| [CWE-453](https://cwe.mitre.org/data/definitions/453.html) | Insecure Default Variable Initialization | 미지정 |
| [CWE-494](https://cwe.mitre.org/data/definitions/494.html) | Download of Code Without Integrity Check | 미지정 |
| [CWE-526](https://cwe.mitre.org/data/definitions/526.html) | Cleartext Storage of Sensitive Information in an Environment Variable | 미지정 |
| [CWE-565](https://cwe.mitre.org/data/definitions/565.html) | Reliance on Cookies without Validation and Integrity Checking | 미지정 |
| [CWE-587](https://cwe.mitre.org/data/definitions/587.html) | Assignment of a Fixed Address to a Pointer | 미지정 |
| [CWE-602](https://cwe.mitre.org/data/definitions/602.html) | Client-Side Enforcement of Server-Side Security | 미지정 |
| [CWE-603](https://cwe.mitre.org/data/definitions/603.html) | Use of Client-Side Authentication | 미지정 |
| [CWE-614](https://cwe.mitre.org/data/definitions/614.html) | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute | 미지정 |
| [CWE-616](https://cwe.mitre.org/data/definitions/616.html) | Incomplete Identification of Uploaded File Variables (PHP) | 미지정 |
| [CWE-646](https://cwe.mitre.org/data/definitions/646.html) | Reliance on File Name or Extension of Externally-Supplied File | 미지정 |
| [CWE-649](https://cwe.mitre.org/data/definitions/649.html) | Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking | 미지정 |
| [CWE-653](https://cwe.mitre.org/data/definitions/653.html) | Improper Isolation or Compartmentalization | 미지정 |
| [CWE-654](https://cwe.mitre.org/data/definitions/654.html) | Reliance on a Single Factor in a Security Decision | 미지정 |
| [CWE-655](https://cwe.mitre.org/data/definitions/655.html) | Insufficient Psychological Acceptability | 미지정 |
| [CWE-656](https://cwe.mitre.org/data/definitions/656.html) | Reliance on Security Through Obscurity | 미지정 |
| [CWE-692](https://cwe.mitre.org/data/definitions/692.html) | Incomplete Denylist to Cross-Site Scripting | 미지정 |
| [CWE-757](https://cwe.mitre.org/data/definitions/757.html) | Selection of Less-Secure Algorithm During Negotiation | 미지정 |
| [CWE-759](https://cwe.mitre.org/data/definitions/759.html) | Use of a One-Way Hash without a Salt | 미지정 |
| [CWE-760](https://cwe.mitre.org/data/definitions/760.html) | Use of a One-Way Hash with a Predictable Salt | 미지정 |
| [CWE-780](https://cwe.mitre.org/data/definitions/780.html) | Use of RSA Algorithm without OAEP | 미지정 |
| [CWE-784](https://cwe.mitre.org/data/definitions/784.html) | Reliance on Cookies without Validation and Integrity Checking in a Security Decision | 미지정 |
| [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | Use of Hard-coded Credentials | 미지정 |
| [CWE-807](https://cwe.mitre.org/data/definitions/807.html) | Reliance on Untrusted Inputs in a Security Decision | 미지정 |
| [CWE-916](https://cwe.mitre.org/data/definitions/916.html) | Use of Password Hash With Insufficient Computational Effort | 미지정 |
| [CWE-924](https://cwe.mitre.org/data/definitions/924.html) | Improper Enforcement of Message Integrity During Transmission in a Communication Channel | 미지정 |
| [CWE-925](https://cwe.mitre.org/data/definitions/925.html) | Improper Verification of Intent by Broadcast Receiver | 미지정 |
| [CWE-939](https://cwe.mitre.org/data/definitions/939.html) | Improper Authorization in Handler for Custom URL Scheme | 미지정 |
| [CWE-940](https://cwe.mitre.org/data/definitions/940.html) | Improper Verification of Source of a Communication Channel | 미지정 |
| [CWE-1039](https://cwe.mitre.org/data/definitions/1039.html) | Inadequate Detection or Handling of Adversarial Input Perturbations in Automated Recognition Mechanism | 미지정 |
| [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) | Initialization of a Resource with an Insecure Default | 미지정 |
| [CWE-1189](https://cwe.mitre.org/data/definitions/1189.html) | Improper Isolation of Shared Resources on System-on-a-Chip (SoC) | 미지정 |
| [CWE-1204](https://cwe.mitre.org/data/definitions/1204.html) | Generation of Weak Initialization Vector (IV) | 미지정 |
| [CWE-1240](https://cwe.mitre.org/data/definitions/1240.html) | Use of a Cryptographic Primitive with a Risky Implementation | 미지정 |
| [CWE-1241](https://cwe.mitre.org/data/definitions/1241.html) | Use of Predictable Algorithm in Random Number Generator | 미지정 |
| [CWE-1248](https://cwe.mitre.org/data/definitions/1248.html) | Semiconductor Defects in Hardware Logic with Security-Sensitive Implications | 미지정 |
| [CWE-1253](https://cwe.mitre.org/data/definitions/1253.html) | Incorrect Selection of Fuse Values | 미지정 |
| [CWE-1269](https://cwe.mitre.org/data/definitions/1269.html) | Product Released in Non-Release Configuration | 미지정 |
| [CWE-1278](https://cwe.mitre.org/data/definitions/1278.html) | Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques | 미지정 |
| [CWE-1291](https://cwe.mitre.org/data/definitions/1291.html) | Public Key Re-Use for Signing both Debug and Production Code | 미지정 |
| [CWE-1293](https://cwe.mitre.org/data/definitions/1293.html) | Missing Source Correlation of Multiple Independent Data | 미지정 |
| [CWE-1303](https://cwe.mitre.org/data/definitions/1303.html) | Non-Transparent Sharing of Microarchitectural Resources | 미지정 |
| [CWE-1318](https://cwe.mitre.org/data/definitions/1318.html) | Missing Support for Security Features in On-chip Fabrics or Buses | 미지정 |
| [CWE-1319](https://cwe.mitre.org/data/definitions/1319.html) | Improper Protection against Electromagnetic Fault Injection (EM-FI) | 미지정 |
| [CWE-1326](https://cwe.mitre.org/data/definitions/1326.html) | Missing Immutable Root of Trust in Hardware | 미지정 |
| [CWE-1331](https://cwe.mitre.org/data/definitions/1331.html) | Improper Isolation of Shared Resources in Network On Chip (NoC) | 미지정 |
| [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html) | Missing Origin Validation in WebSockets | 미지정 |
| [CWE-1428](https://cwe.mitre.org/data/definitions/1428.html) | Reliance on HTTP instead of HTTPS | 미지정 |
| [CWE-1431](https://cwe.mitre.org/data/definitions/1431.html) | Driving Intermediate Cryptographic State/Results to Hardware Module Outputs | 미지정 |

</details>

<details>
<summary>CWE-697 · Incorrect Comparison · 21개 소속</summary>

| 세부 CWE | 공식 이름 | 현재 증거 경로 |
| --- | --- | --- |
| [CWE-183](https://cwe.mitre.org/data/definitions/183.html) | Permissive List of Allowed Inputs | 미지정 |
| [CWE-184](https://cwe.mitre.org/data/definitions/184.html) | Incomplete List of Disallowed Inputs | 미지정 |
| [CWE-185](https://cwe.mitre.org/data/definitions/185.html) | Incorrect Regular Expression | 미지정 |
| [CWE-186](https://cwe.mitre.org/data/definitions/186.html) | Overly Restrictive Regular Expression | 미지정 |
| [CWE-187](https://cwe.mitre.org/data/definitions/187.html) | Partial String Comparison | 미지정 |
| [CWE-478](https://cwe.mitre.org/data/definitions/478.html) | Missing Default Case in Multiple Condition Expression | 미지정 |
| [CWE-486](https://cwe.mitre.org/data/definitions/486.html) | Comparison of Classes by Name | 미지정 |
| [CWE-581](https://cwe.mitre.org/data/definitions/581.html) | Object Model Violation: Just One of Equals and Hashcode Defined | 미지정 |
| [CWE-595](https://cwe.mitre.org/data/definitions/595.html) | Comparison of Object References Instead of Object Contents | 미지정 |
| [CWE-597](https://cwe.mitre.org/data/definitions/597.html) | Use of Wrong Operator in String Comparison | 미지정 |
| [CWE-625](https://cwe.mitre.org/data/definitions/625.html) | Permissive Regular Expression | 미지정 |
| [CWE-692](https://cwe.mitre.org/data/definitions/692.html) | Incomplete Denylist to Cross-Site Scripting | 미지정 |
| [CWE-777](https://cwe.mitre.org/data/definitions/777.html) | Regular Expression without Anchors | 미지정 |
| [CWE-839](https://cwe.mitre.org/data/definitions/839.html) | Numeric Range Comparison Without Minimum Check | 미지정 |
| [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | Permissive Cross-domain Security Policy with Untrusted Domains | 미지정 |
| [CWE-1023](https://cwe.mitre.org/data/definitions/1023.html) | Incomplete Comparison with Missing Factors | 미지정 |
| [CWE-1024](https://cwe.mitre.org/data/definitions/1024.html) | Comparison of Incompatible Types | 미지정 |
| [CWE-1025](https://cwe.mitre.org/data/definitions/1025.html) | Comparison Using Wrong Factors | 미지정 |
| [CWE-1039](https://cwe.mitre.org/data/definitions/1039.html) | Inadequate Detection or Handling of Adversarial Input Perturbations in Automated Recognition Mechanism | 미지정 |
| [CWE-1077](https://cwe.mitre.org/data/definitions/1077.html) | Floating Point Comparison with Incorrect Operator | 미지정 |
| [CWE-1254](https://cwe.mitre.org/data/definitions/1254.html) | Incorrect Comparison Logic Granularity | 미지정 |

</details>

<details>
<summary>CWE-703 · Improper Check or Handling of Exceptional Conditions · 58개 소속</summary>

| 세부 CWE | 공식 이름 | 현재 증거 경로 |
| --- | --- | --- |
| [CWE-7](https://cwe.mitre.org/data/definitions/7.html) | J2EE Misconfiguration: Missing Custom Error Page | 미지정 |
| [CWE-12](https://cwe.mitre.org/data/definitions/12.html) | ASP.NET Misconfiguration: Missing Custom Error Page | 미지정 |
| [CWE-130](https://cwe.mitre.org/data/definitions/130.html) | Improper Handling of Length Parameter Inconsistency | 미지정 |
| [CWE-166](https://cwe.mitre.org/data/definitions/166.html) | Improper Handling of Missing Special Element | 미지정 |
| [CWE-167](https://cwe.mitre.org/data/definitions/167.html) | Improper Handling of Additional Special Element | 미지정 |
| [CWE-168](https://cwe.mitre.org/data/definitions/168.html) | Improper Handling of Inconsistent Special Elements | 미지정 |
| [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | Generation of Error Message Containing Sensitive Information | 미지정 |
| [CWE-210](https://cwe.mitre.org/data/definitions/210.html) | Self-generated Error Message Containing Sensitive Information | 미지정 |
| [CWE-211](https://cwe.mitre.org/data/definitions/211.html) | Externally-Generated Error Message Containing Sensitive Information | 미지정 |
| [CWE-228](https://cwe.mitre.org/data/definitions/228.html) | Improper Handling of Syntactically Invalid Structure | 미지정 |
| [CWE-229](https://cwe.mitre.org/data/definitions/229.html) | Improper Handling of Values | 미지정 |
| [CWE-230](https://cwe.mitre.org/data/definitions/230.html) | Improper Handling of Missing Values | 미지정 |
| [CWE-231](https://cwe.mitre.org/data/definitions/231.html) | Improper Handling of Extra Values | 미지정 |
| [CWE-232](https://cwe.mitre.org/data/definitions/232.html) | Improper Handling of Undefined Values | 미지정 |
| [CWE-233](https://cwe.mitre.org/data/definitions/233.html) | Improper Handling of Parameters | 미지정 |
| [CWE-234](https://cwe.mitre.org/data/definitions/234.html) | Failure to Handle Missing Parameter | 미지정 |
| [CWE-235](https://cwe.mitre.org/data/definitions/235.html) | Improper Handling of Extra Parameters | 미지정 |
| [CWE-236](https://cwe.mitre.org/data/definitions/236.html) | Improper Handling of Undefined Parameters | 미지정 |
| [CWE-237](https://cwe.mitre.org/data/definitions/237.html) | Improper Handling of Structural Elements | 미지정 |
| [CWE-238](https://cwe.mitre.org/data/definitions/238.html) | Improper Handling of Incomplete Structural Elements | 미지정 |
| [CWE-239](https://cwe.mitre.org/data/definitions/239.html) | Failure to Handle Incomplete Element | 미지정 |
| [CWE-240](https://cwe.mitre.org/data/definitions/240.html) | Improper Handling of Inconsistent Structural Elements | 미지정 |
| [CWE-241](https://cwe.mitre.org/data/definitions/241.html) | Improper Handling of Unexpected Data Type | 미지정 |
| [CWE-248](https://cwe.mitre.org/data/definitions/248.html) | Uncaught Exception | 미지정 |
| [CWE-252](https://cwe.mitre.org/data/definitions/252.html) | Unchecked Return Value | 미지정 |
| [CWE-253](https://cwe.mitre.org/data/definitions/253.html) | Incorrect Check of Function Return Value | 미지정 |
| [CWE-273](https://cwe.mitre.org/data/definitions/273.html) | Improper Check for Dropped Privileges | 미지정 |
| [CWE-274](https://cwe.mitre.org/data/definitions/274.html) | Improper Handling of Insufficient Privileges | 미지정 |
| [CWE-280](https://cwe.mitre.org/data/definitions/280.html) | Improper Handling of Insufficient Permissions or Privileges | 미지정 |
| [CWE-333](https://cwe.mitre.org/data/definitions/333.html) | Improper Handling of Insufficient Entropy in TRNG | 미지정 |
| [CWE-354](https://cwe.mitre.org/data/definitions/354.html) | Improper Validation of Integrity Check Value | 미지정 |
| [CWE-390](https://cwe.mitre.org/data/definitions/390.html) | Detection of Error Condition Without Action | 미지정 |
| [CWE-392](https://cwe.mitre.org/data/definitions/392.html) | Missing Report of Error Condition | 미지정 |
| [CWE-393](https://cwe.mitre.org/data/definitions/393.html) | Return of Wrong Status Code | 미지정 |
| [CWE-394](https://cwe.mitre.org/data/definitions/394.html) | Unexpected Status Code or Return Value | 미지정 |
| [CWE-395](https://cwe.mitre.org/data/definitions/395.html) | Use of NullPointerException Catch to Detect NULL Pointer Dereference | 미지정 |
| [CWE-396](https://cwe.mitre.org/data/definitions/396.html) | Declaration of Catch for Generic Exception | 미지정 |
| [CWE-397](https://cwe.mitre.org/data/definitions/397.html) | Declaration of Throws for Generic Exception | 미지정 |
| [CWE-455](https://cwe.mitre.org/data/definitions/455.html) | Non-exit on Failed Initialization | 미지정 |
| [CWE-460](https://cwe.mitre.org/data/definitions/460.html) | Improper Cleanup on Thrown Exception | 미지정 |
| [CWE-476](https://cwe.mitre.org/data/definitions/476.html) | NULL Pointer Dereference | 미지정 |
| [CWE-535](https://cwe.mitre.org/data/definitions/535.html) | Exposure of Information Through Shell Error Message | 미지정 |
| [CWE-536](https://cwe.mitre.org/data/definitions/536.html) | Servlet Runtime Error Message Containing Sensitive Information | 미지정 |
| [CWE-537](https://cwe.mitre.org/data/definitions/537.html) | Java Runtime Error Message Containing Sensitive Information | 미지정 |
| [CWE-544](https://cwe.mitre.org/data/definitions/544.html) | Missing Standardized Error Handling Mechanism | 미지정 |
| [CWE-550](https://cwe.mitre.org/data/definitions/550.html) | Server-generated Error Message Containing Sensitive Information | 미지정 |
| [CWE-600](https://cwe.mitre.org/data/definitions/600.html) | Uncaught Exception in Servlet | 미지정 |
| [CWE-636](https://cwe.mitre.org/data/definitions/636.html) | Not Failing Securely | 미지정 |
| [CWE-690](https://cwe.mitre.org/data/definitions/690.html) | Unchecked Return Value to NULL Pointer Dereference | 미지정 |
| [CWE-754](https://cwe.mitre.org/data/definitions/754.html) | Improper Check for Unusual or Exceptional Conditions | 미지정 |
| [CWE-755](https://cwe.mitre.org/data/definitions/755.html) | Improper Handling of Exceptional Conditions | 미지정 |
| [CWE-756](https://cwe.mitre.org/data/definitions/756.html) | Missing Custom Error Page | 미지정 |
| [CWE-1247](https://cwe.mitre.org/data/definitions/1247.html) | Improper Protection Against Voltage and Clock Glitches | 미지정 |
| [CWE-1261](https://cwe.mitre.org/data/definitions/1261.html) | Improper Handling of Single Event Upsets | 미지정 |
| [CWE-1332](https://cwe.mitre.org/data/definitions/1332.html) | Improper Handling of Faults that Lead to Instruction Skips | 미지정 |
| [CWE-1338](https://cwe.mitre.org/data/definitions/1338.html) | Improper Protections Against Hardware Overheating | 미지정 |
| [CWE-1351](https://cwe.mitre.org/data/definitions/1351.html) | Improper Handling of Hardware Behavior in Exceptionally Cold Environments | 미지정 |
| [CWE-1384](https://cwe.mitre.org/data/definitions/1384.html) | Improper Handling of Physical or Environmental Conditions | 미지정 |

</details>

<details>
<summary>CWE-707 · Improper Neutralization · 145개 소속</summary>

| 세부 CWE | 공식 이름 | 현재 증거 경로 |
| --- | --- | --- |
| [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Improper Input Validation | 미지정 |
| [CWE-37](https://cwe.mitre.org/data/definitions/37.html) | Path Traversal: '/absolute/pathname/here' | 미지정 |
| [CWE-42](https://cwe.mitre.org/data/definitions/42.html) | Path Equivalence: 'filename.' (Trailing Dot) | 미지정 |
| [CWE-43](https://cwe.mitre.org/data/definitions/43.html) | Path Equivalence: 'filename....' (Multiple Trailing Dot) | 미지정 |
| [CWE-45](https://cwe.mitre.org/data/definitions/45.html) | Path Equivalence: 'file...name' (Multiple Internal Dot) | 미지정 |
| [CWE-46](https://cwe.mitre.org/data/definitions/46.html) | Path Equivalence: 'filename ' (Trailing Space) | 미지정 |
| [CWE-49](https://cwe.mitre.org/data/definitions/49.html) | Path Equivalence: 'filename/' (Trailing Slash) | 미지정 |
| [CWE-50](https://cwe.mitre.org/data/definitions/50.html) | Path Equivalence: '//multiple/leading/slash' | 미지정 |
| [CWE-52](https://cwe.mitre.org/data/definitions/52.html) | Path Equivalence: '/multiple/trailing/slash//' | 미지정 |
| [CWE-53](https://cwe.mitre.org/data/definitions/53.html) | Path Equivalence: '\multiple\\internal\backslash' | 미지정 |
| [CWE-54](https://cwe.mitre.org/data/definitions/54.html) | Path Equivalence: 'filedir\' (Trailing Backslash) | 미지정 |
| [CWE-56](https://cwe.mitre.org/data/definitions/56.html) | Path Equivalence: 'filedir*' (Wildcard) | 미지정 |
| [CWE-74](https://cwe.mitre.org/data/definitions/74.html) | Improper Neutralization of Special Elements in Output Used by a Downstream Component | 미지정 |
| [CWE-75](https://cwe.mitre.org/data/definitions/75.html) | Failure to Sanitize Special Elements into a Different Plane | 미지정 |
| [CWE-76](https://cwe.mitre.org/data/definitions/76.html) | Improper Neutralization of Equivalent Special Elements | 미지정 |
| [CWE-77](https://cwe.mitre.org/data/definitions/77.html) | Improper Neutralization of Special Elements used in a Command | 미지정 |
| [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | Improper Neutralization of Special Elements used in an OS Command | 미지정 |
| [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Improper Neutralization of Input During Web Page Generation | 미지정 |
| [CWE-80](https://cwe.mitre.org/data/definitions/80.html) | Improper Neutralization of Script-Related HTML Tags in a Web Page | 미지정 |
| [CWE-81](https://cwe.mitre.org/data/definitions/81.html) | Improper Neutralization of Script in an Error Message Web Page | 미지정 |
| [CWE-82](https://cwe.mitre.org/data/definitions/82.html) | Improper Neutralization of Script in Attributes of IMG Tags in a Web Page | 미지정 |
| [CWE-83](https://cwe.mitre.org/data/definitions/83.html) | Improper Neutralization of Script in Attributes in a Web Page | 미지정 |
| [CWE-84](https://cwe.mitre.org/data/definitions/84.html) | Improper Neutralization of Encoded URI Schemes in a Web Page | 미지정 |
| [CWE-85](https://cwe.mitre.org/data/definitions/85.html) | Doubled Character XSS Manipulations | 미지정 |
| [CWE-86](https://cwe.mitre.org/data/definitions/86.html) | Improper Neutralization of Invalid Characters in Identifiers in Web Pages | 미지정 |
| [CWE-87](https://cwe.mitre.org/data/definitions/87.html) | Improper Neutralization of Alternate XSS Syntax | 미지정 |
| [CWE-88](https://cwe.mitre.org/data/definitions/88.html) | Improper Neutralization of Argument Delimiters in a Command | 미지정 |
| [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | Improper Neutralization of Special Elements used in an SQL Command | 미지정 |
| [CWE-90](https://cwe.mitre.org/data/definitions/90.html) | Improper Neutralization of Special Elements used in an LDAP Query | 미지정 |
| [CWE-91](https://cwe.mitre.org/data/definitions/91.html) | XML Injection | 미지정 |
| [CWE-93](https://cwe.mitre.org/data/definitions/93.html) | Improper Neutralization of CRLF Sequences | 미지정 |
| [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | Improper Control of Generation of Code | 미지정 |
| [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | Improper Neutralization of Directives in Dynamically Evaluated Code | 미지정 |
| [CWE-96](https://cwe.mitre.org/data/definitions/96.html) | Improper Neutralization of Directives in Statically Saved Code | 미지정 |
| [CWE-97](https://cwe.mitre.org/data/definitions/97.html) | Improper Neutralization of Server-Side Includes (SSI) Within a Web Page | 미지정 |
| [CWE-99](https://cwe.mitre.org/data/definitions/99.html) | Improper Control of Resource Identifiers | 미지정 |
| [CWE-102](https://cwe.mitre.org/data/definitions/102.html) | Struts: Duplicate Validation Forms | 미지정 |
| [CWE-105](https://cwe.mitre.org/data/definitions/105.html) | Struts: Form Field Without Validator | 미지정 |
| [CWE-106](https://cwe.mitre.org/data/definitions/106.html) | Struts: Plug-in Framework not in Use | 미지정 |
| [CWE-108](https://cwe.mitre.org/data/definitions/108.html) | Struts: Unvalidated Action Form | 미지정 |
| [CWE-109](https://cwe.mitre.org/data/definitions/109.html) | Struts: Validator Turned Off | 미지정 |
| [CWE-112](https://cwe.mitre.org/data/definitions/112.html) | Missing XML Validation | 미지정 |
| [CWE-113](https://cwe.mitre.org/data/definitions/113.html) | Improper Neutralization of CRLF Sequences in HTTP Headers | 미지정 |
| [CWE-116](https://cwe.mitre.org/data/definitions/116.html) | Improper Encoding or Escaping of Output | 미지정 |
| [CWE-117](https://cwe.mitre.org/data/definitions/117.html) | Improper Output Neutralization for Logs | 미지정 |
| [CWE-129](https://cwe.mitre.org/data/definitions/129.html) | Improper Validation of Array Index | 미지정 |
| [CWE-130](https://cwe.mitre.org/data/definitions/130.html) | Improper Handling of Length Parameter Inconsistency | 미지정 |
| [CWE-138](https://cwe.mitre.org/data/definitions/138.html) | Improper Neutralization of Special Elements | 미지정 |
| [CWE-140](https://cwe.mitre.org/data/definitions/140.html) | Improper Neutralization of Delimiters | 미지정 |
| [CWE-141](https://cwe.mitre.org/data/definitions/141.html) | Improper Neutralization of Parameter/Argument Delimiters | 미지정 |
| [CWE-142](https://cwe.mitre.org/data/definitions/142.html) | Improper Neutralization of Value Delimiters | 미지정 |
| [CWE-143](https://cwe.mitre.org/data/definitions/143.html) | Improper Neutralization of Record Delimiters | 미지정 |
| [CWE-144](https://cwe.mitre.org/data/definitions/144.html) | Improper Neutralization of Line Delimiters | 미지정 |
| [CWE-145](https://cwe.mitre.org/data/definitions/145.html) | Improper Neutralization of Section Delimiters | 미지정 |
| [CWE-146](https://cwe.mitre.org/data/definitions/146.html) | Improper Neutralization of Expression/Command Delimiters | 미지정 |
| [CWE-147](https://cwe.mitre.org/data/definitions/147.html) | Improper Neutralization of Input Terminators | 미지정 |
| [CWE-148](https://cwe.mitre.org/data/definitions/148.html) | Improper Neutralization of Input Leaders | 미지정 |
| [CWE-149](https://cwe.mitre.org/data/definitions/149.html) | Improper Neutralization of Quoting Syntax | 미지정 |
| [CWE-150](https://cwe.mitre.org/data/definitions/150.html) | Improper Neutralization of Escape, Meta, or Control Sequences | 미지정 |
| [CWE-151](https://cwe.mitre.org/data/definitions/151.html) | Improper Neutralization of Comment Delimiters | 미지정 |
| [CWE-152](https://cwe.mitre.org/data/definitions/152.html) | Improper Neutralization of Macro Symbols | 미지정 |
| [CWE-153](https://cwe.mitre.org/data/definitions/153.html) | Improper Neutralization of Substitution Characters | 미지정 |
| [CWE-154](https://cwe.mitre.org/data/definitions/154.html) | Improper Neutralization of Variable Name Delimiters | 미지정 |
| [CWE-155](https://cwe.mitre.org/data/definitions/155.html) | Improper Neutralization of Wildcards or Matching Symbols | 미지정 |
| [CWE-156](https://cwe.mitre.org/data/definitions/156.html) | Improper Neutralization of Whitespace | 미지정 |
| [CWE-157](https://cwe.mitre.org/data/definitions/157.html) | Failure to Sanitize Paired Delimiters | 미지정 |
| [CWE-158](https://cwe.mitre.org/data/definitions/158.html) | Improper Neutralization of Null Byte or NUL Character | 미지정 |
| [CWE-159](https://cwe.mitre.org/data/definitions/159.html) | Improper Handling of Invalid Use of Special Elements | 미지정 |
| [CWE-160](https://cwe.mitre.org/data/definitions/160.html) | Improper Neutralization of Leading Special Elements | 미지정 |
| [CWE-161](https://cwe.mitre.org/data/definitions/161.html) | Improper Neutralization of Multiple Leading Special Elements | 미지정 |
| [CWE-162](https://cwe.mitre.org/data/definitions/162.html) | Improper Neutralization of Trailing Special Elements | 미지정 |
| [CWE-163](https://cwe.mitre.org/data/definitions/163.html) | Improper Neutralization of Multiple Trailing Special Elements | 미지정 |
| [CWE-164](https://cwe.mitre.org/data/definitions/164.html) | Improper Neutralization of Internal Special Elements | 미지정 |
| [CWE-165](https://cwe.mitre.org/data/definitions/165.html) | Improper Neutralization of Multiple Internal Special Elements | 미지정 |
| [CWE-166](https://cwe.mitre.org/data/definitions/166.html) | Improper Handling of Missing Special Element | 미지정 |
| [CWE-167](https://cwe.mitre.org/data/definitions/167.html) | Improper Handling of Additional Special Element | 미지정 |
| [CWE-168](https://cwe.mitre.org/data/definitions/168.html) | Improper Handling of Inconsistent Special Elements | 미지정 |
| [CWE-170](https://cwe.mitre.org/data/definitions/170.html) | Improper Null Termination | 미지정 |
| [CWE-172](https://cwe.mitre.org/data/definitions/172.html) | Improper Encoding or Decoding of Data | 미지정 |
| [CWE-173](https://cwe.mitre.org/data/definitions/173.html) | Improper Handling of Alternate Encoding | 미지정 |
| [CWE-174](https://cwe.mitre.org/data/definitions/174.html) | Double Decoding of the Same Data | 미지정 |
| [CWE-175](https://cwe.mitre.org/data/definitions/175.html) | Improper Handling of Mixed Encoding | 미지정 |
| [CWE-176](https://cwe.mitre.org/data/definitions/176.html) | Improper Handling of Unicode Encoding | 미지정 |
| [CWE-177](https://cwe.mitre.org/data/definitions/177.html) | Improper Handling of URL Encoding (Hex Encoding) | 미지정 |
| [CWE-179](https://cwe.mitre.org/data/definitions/179.html) | Incorrect Behavior Order: Early Validation | 미지정 |
| [CWE-180](https://cwe.mitre.org/data/definitions/180.html) | Incorrect Behavior Order: Validate Before Canonicalize | 미지정 |
| [CWE-181](https://cwe.mitre.org/data/definitions/181.html) | Incorrect Behavior Order: Validate Before Filter | 미지정 |
| [CWE-182](https://cwe.mitre.org/data/definitions/182.html) | Collapse of Data into Unsafe Value | 미지정 |
| [CWE-228](https://cwe.mitre.org/data/definitions/228.html) | Improper Handling of Syntactically Invalid Structure | 미지정 |
| [CWE-229](https://cwe.mitre.org/data/definitions/229.html) | Improper Handling of Values | 미지정 |
| [CWE-230](https://cwe.mitre.org/data/definitions/230.html) | Improper Handling of Missing Values | 미지정 |
| [CWE-231](https://cwe.mitre.org/data/definitions/231.html) | Improper Handling of Extra Values | 미지정 |
| [CWE-232](https://cwe.mitre.org/data/definitions/232.html) | Improper Handling of Undefined Values | 미지정 |
| [CWE-233](https://cwe.mitre.org/data/definitions/233.html) | Improper Handling of Parameters | 미지정 |
| [CWE-234](https://cwe.mitre.org/data/definitions/234.html) | Failure to Handle Missing Parameter | 미지정 |
| [CWE-235](https://cwe.mitre.org/data/definitions/235.html) | Improper Handling of Extra Parameters | 미지정 |
| [CWE-236](https://cwe.mitre.org/data/definitions/236.html) | Improper Handling of Undefined Parameters | 미지정 |
| [CWE-237](https://cwe.mitre.org/data/definitions/237.html) | Improper Handling of Structural Elements | 미지정 |
| [CWE-238](https://cwe.mitre.org/data/definitions/238.html) | Improper Handling of Incomplete Structural Elements | 미지정 |
| [CWE-239](https://cwe.mitre.org/data/definitions/239.html) | Failure to Handle Incomplete Element | 미지정 |
| [CWE-240](https://cwe.mitre.org/data/definitions/240.html) | Improper Handling of Inconsistent Structural Elements | 미지정 |
| [CWE-241](https://cwe.mitre.org/data/definitions/241.html) | Improper Handling of Unexpected Data Type | 미지정 |
| [CWE-462](https://cwe.mitre.org/data/definitions/462.html) | Duplicate Key in Associative List (Alist) | 미지정 |
| [CWE-463](https://cwe.mitre.org/data/definitions/463.html) | Deletion of Data Structure Sentinel | 미지정 |
| [CWE-464](https://cwe.mitre.org/data/definitions/464.html) | Addition of Data Structure Sentinel | 미지정 |
| [CWE-554](https://cwe.mitre.org/data/definitions/554.html) | ASP.NET Misconfiguration: Not Using Input Validation Framework | 미지정 |
| [CWE-564](https://cwe.mitre.org/data/definitions/564.html) | Use of Hibernate with HQL/SQL Query String Containing External Input | 미지정 |
| [CWE-606](https://cwe.mitre.org/data/definitions/606.html) | Unchecked Input for Loop Condition | 미지정 |
| [CWE-621](https://cwe.mitre.org/data/definitions/621.html) | Variable Extraction Error | 미지정 |
| [CWE-622](https://cwe.mitre.org/data/definitions/622.html) | Improper Validation of Function Hook Arguments | 미지정 |
| [CWE-624](https://cwe.mitre.org/data/definitions/624.html) | Executable Regular Expression Error | 미지정 |
| [CWE-626](https://cwe.mitre.org/data/definitions/626.html) | Null Byte Interaction Error (Poison Null Byte) | 미지정 |
| [CWE-627](https://cwe.mitre.org/data/definitions/627.html) | Dynamic Variable Evaluation | 미지정 |
| [CWE-641](https://cwe.mitre.org/data/definitions/641.html) | Improper Restriction of Names for Files and Other Resources | 미지정 |
| [CWE-643](https://cwe.mitre.org/data/definitions/643.html) | Improper Neutralization of Data within XPath Expressions | 미지정 |
| [CWE-644](https://cwe.mitre.org/data/definitions/644.html) | Improper Neutralization of HTTP Headers for Scripting Syntax | 미지정 |
| [CWE-647](https://cwe.mitre.org/data/definitions/647.html) | Use of Non-Canonical URL Paths for Authorization Decisions | 미지정 |
| [CWE-652](https://cwe.mitre.org/data/definitions/652.html) | Improper Neutralization of Data within XQuery Expressions | 미지정 |
| [CWE-694](https://cwe.mitre.org/data/definitions/694.html) | Use of Multiple Resources with Duplicate Identifier | 미지정 |
| [CWE-781](https://cwe.mitre.org/data/definitions/781.html) | Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code | 미지정 |
| [CWE-790](https://cwe.mitre.org/data/definitions/790.html) | Improper Filtering of Special Elements | 미지정 |
| [CWE-791](https://cwe.mitre.org/data/definitions/791.html) | Incomplete Filtering of Special Elements | 미지정 |
| [CWE-792](https://cwe.mitre.org/data/definitions/792.html) | Incomplete Filtering of One or More Instances of Special Elements | 미지정 |
| [CWE-793](https://cwe.mitre.org/data/definitions/793.html) | Only Filtering One Instance of a Special Element | 미지정 |
| [CWE-794](https://cwe.mitre.org/data/definitions/794.html) | Incomplete Filtering of Multiple Instances of Special Elements | 미지정 |
| [CWE-795](https://cwe.mitre.org/data/definitions/795.html) | Only Filtering Special Elements at a Specified Location | 미지정 |
| [CWE-796](https://cwe.mitre.org/data/definitions/796.html) | Only Filtering Special Elements Relative to a Marker | 미지정 |
| [CWE-797](https://cwe.mitre.org/data/definitions/797.html) | Only Filtering Special Elements at an Absolute Position | 미지정 |
| [CWE-838](https://cwe.mitre.org/data/definitions/838.html) | Inappropriate Encoding for Output Context | 미지정 |
| [CWE-839](https://cwe.mitre.org/data/definitions/839.html) | Numeric Range Comparison Without Minimum Check | 미지정 |
| [CWE-914](https://cwe.mitre.org/data/definitions/914.html) | Improper Control of Dynamically-Identified Variables | 미지정 |
| [CWE-917](https://cwe.mitre.org/data/definitions/917.html) | Improper Neutralization of Special Elements used in an Expression Language Statement | 미지정 |
| [CWE-943](https://cwe.mitre.org/data/definitions/943.html) | Improper Neutralization of Special Elements in Data Query Logic | 미지정 |
| [CWE-1173](https://cwe.mitre.org/data/definitions/1173.html) | Improper Use of Validation Framework | 미지정 |
| [CWE-1174](https://cwe.mitre.org/data/definitions/1174.html) | ASP.NET Misconfiguration: Improper Model Validation | 미지정 |
| [CWE-1236](https://cwe.mitre.org/data/definitions/1236.html) | Improper Neutralization of Formula Elements in a CSV File | 미지정 |
| [CWE-1284](https://cwe.mitre.org/data/definitions/1284.html) | Improper Validation of Specified Quantity in Input | 미지정 |
| [CWE-1285](https://cwe.mitre.org/data/definitions/1285.html) | Improper Validation of Specified Index, Position, or Offset in Input | 미지정 |
| [CWE-1286](https://cwe.mitre.org/data/definitions/1286.html) | Improper Validation of Syntactic Correctness of Input | 미지정 |
| [CWE-1287](https://cwe.mitre.org/data/definitions/1287.html) | Improper Validation of Specified Type of Input | 미지정 |
| [CWE-1288](https://cwe.mitre.org/data/definitions/1288.html) | Improper Validation of Consistency within Input | 미지정 |
| [CWE-1289](https://cwe.mitre.org/data/definitions/1289.html) | Improper Validation of Unsafe Equivalence in Input | 미지정 |
| [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) | Improper Neutralization of Special Elements Used in a Template Engine | 미지정 |
| [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html) | Improper Validation of Generative AI Output | 미지정 |
| [CWE-1427](https://cwe.mitre.org/data/definitions/1427.html) | Improper Neutralization of Input Used for LLM Prompting | 미지정 |

</details>

<details>
<summary>CWE-710 · Improper Adherence to Coding Standards · 196개 소속</summary>

| 세부 CWE | 공식 이름 | 현재 증거 경로 |
| --- | --- | --- |
| [CWE-11](https://cwe.mitre.org/data/definitions/11.html) | ASP.NET Misconfiguration: Creating Debug Binary | 미지정 |
| [CWE-14](https://cwe.mitre.org/data/definitions/14.html) | Compiler Removal of Code to Clear Buffers | 미지정 |
| [CWE-102](https://cwe.mitre.org/data/definitions/102.html) | Struts: Duplicate Validation Forms | 미지정 |
| [CWE-103](https://cwe.mitre.org/data/definitions/103.html) | Struts: Incomplete validate() Method Definition | 미지정 |
| [CWE-104](https://cwe.mitre.org/data/definitions/104.html) | Struts: Form Bean Does Not Extend Validation Class | 미지정 |
| [CWE-107](https://cwe.mitre.org/data/definitions/107.html) | Struts: Unused Validation Form | 미지정 |
| [CWE-110](https://cwe.mitre.org/data/definitions/110.html) | Struts: Validator Without Form Field | 미지정 |
| [CWE-111](https://cwe.mitre.org/data/definitions/111.html) | Direct Use of Unsafe JNI | 미지정 |
| [CWE-174](https://cwe.mitre.org/data/definitions/174.html) | Double Decoding of the Same Data | 미지정 |
| [CWE-188](https://cwe.mitre.org/data/definitions/188.html) | Reliance on Data/Memory Layout | 미지정 |
| [CWE-198](https://cwe.mitre.org/data/definitions/198.html) | Use of Incorrect Byte Ordering | 미지정 |
| [CWE-242](https://cwe.mitre.org/data/definitions/242.html) | Use of Inherently Dangerous Function | 미지정 |
| [CWE-243](https://cwe.mitre.org/data/definitions/243.html) | Creation of chroot Jail Without Changing Working Directory | 미지정 |
| [CWE-245](https://cwe.mitre.org/data/definitions/245.html) | J2EE Bad Practices: Direct Management of Connections | 미지정 |
| [CWE-246](https://cwe.mitre.org/data/definitions/246.html) | J2EE Bad Practices: Direct Use of Sockets | 미지정 |
| [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | Execution with Unnecessary Privileges | 미지정 |
| [CWE-253](https://cwe.mitre.org/data/definitions/253.html) | Incorrect Check of Function Return Value | 미지정 |
| [CWE-259](https://cwe.mitre.org/data/definitions/259.html) | Use of Hard-coded Password | 미지정 |
| [CWE-296](https://cwe.mitre.org/data/definitions/296.html) | Improper Following of a Certificate's Chain of Trust | 미지정 |
| [CWE-304](https://cwe.mitre.org/data/definitions/304.html) | Missing Critical Step in Authentication | 미지정 |
| [CWE-308](https://cwe.mitre.org/data/definitions/308.html) | Use of Single-factor Authentication | 미지정 |
| [CWE-309](https://cwe.mitre.org/data/definitions/309.html) | Use of Password System for Primary Authentication | 미지정 |
| [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | Use of Hard-coded Cryptographic Key | 미지정 |
| [CWE-325](https://cwe.mitre.org/data/definitions/325.html) | Missing Cryptographic Step | 미지정 |
| [CWE-329](https://cwe.mitre.org/data/definitions/329.html) | Generation of Predictable IV with CBC Mode | 미지정 |
| [CWE-358](https://cwe.mitre.org/data/definitions/358.html) | Improperly Implemented Security Check for Standard | 미지정 |
| [CWE-383](https://cwe.mitre.org/data/definitions/383.html) | J2EE Bad Practices: Direct Use of Threads | 미지정 |
| [CWE-392](https://cwe.mitre.org/data/definitions/392.html) | Missing Report of Error Condition | 미지정 |
| [CWE-393](https://cwe.mitre.org/data/definitions/393.html) | Return of Wrong Status Code | 미지정 |
| [CWE-415](https://cwe.mitre.org/data/definitions/415.html) | Double Free | 미지정 |
| [CWE-424](https://cwe.mitre.org/data/definitions/424.html) | Improper Protection of Alternate Path | 미지정 |
| [CWE-425](https://cwe.mitre.org/data/definitions/425.html) | Direct Request | 미지정 |
| [CWE-440](https://cwe.mitre.org/data/definitions/440.html) | Expected Behavior Violation | 미지정 |
| [CWE-446](https://cwe.mitre.org/data/definitions/446.html) | UI Discrepancy for Security Feature | 미지정 |
| [CWE-447](https://cwe.mitre.org/data/definitions/447.html) | Unimplemented or Unsupported Feature in UI | 미지정 |
| [CWE-448](https://cwe.mitre.org/data/definitions/448.html) | Obsolete Feature in UI | 미지정 |
| [CWE-449](https://cwe.mitre.org/data/definitions/449.html) | The UI Performs the Wrong Action | 미지정 |
| [CWE-451](https://cwe.mitre.org/data/definitions/451.html) | User Interface (UI) Misrepresentation of Critical Information | 미지정 |
| [CWE-455](https://cwe.mitre.org/data/definitions/455.html) | Non-exit on Failed Initialization | 미지정 |
| [CWE-462](https://cwe.mitre.org/data/definitions/462.html) | Duplicate Key in Associative List (Alist) | 미지정 |
| [CWE-474](https://cwe.mitre.org/data/definitions/474.html) | Use of Function with Inconsistent Implementations | 미지정 |
| [CWE-475](https://cwe.mitre.org/data/definitions/475.html) | Undefined Behavior for Input to API | 미지정 |
| [CWE-476](https://cwe.mitre.org/data/definitions/476.html) | NULL Pointer Dereference | 미지정 |
| [CWE-477](https://cwe.mitre.org/data/definitions/477.html) | Use of Obsolete Function | 미지정 |
| [CWE-484](https://cwe.mitre.org/data/definitions/484.html) | Omitted Break Statement in Switch | 미지정 |
| [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | Active Debug Code | 미지정 |
| [CWE-506](https://cwe.mitre.org/data/definitions/506.html) | Embedded Malicious Code | 미지정 |
| [CWE-507](https://cwe.mitre.org/data/definitions/507.html) | Trojan Horse | 미지정 |
| [CWE-508](https://cwe.mitre.org/data/definitions/508.html) | Non-Replicating Malicious Code | 미지정 |
| [CWE-509](https://cwe.mitre.org/data/definitions/509.html) | Replicating Malicious Code (Virus or Worm) | 미지정 |
| [CWE-510](https://cwe.mitre.org/data/definitions/510.html) | Trapdoor | 미지정 |
| [CWE-511](https://cwe.mitre.org/data/definitions/511.html) | Logic/Time Bomb | 미지정 |
| [CWE-512](https://cwe.mitre.org/data/definitions/512.html) | Spyware | 미지정 |
| [CWE-546](https://cwe.mitre.org/data/definitions/546.html) | Suspicious Comment | 미지정 |
| [CWE-547](https://cwe.mitre.org/data/definitions/547.html) | Use of Hard-coded, Security-relevant Constants | 미지정 |
| [CWE-560](https://cwe.mitre.org/data/definitions/560.html) | Use of umask() with chmod-style Argument | 미지정 |
| [CWE-561](https://cwe.mitre.org/data/definitions/561.html) | Dead Code | 미지정 |
| [CWE-562](https://cwe.mitre.org/data/definitions/562.html) | Return of Stack Variable Address | 미지정 |
| [CWE-563](https://cwe.mitre.org/data/definitions/563.html) | Assignment to Variable without Use | 미지정 |
| [CWE-568](https://cwe.mitre.org/data/definitions/568.html) | finalize() Method Without super.finalize() | 미지정 |
| [CWE-570](https://cwe.mitre.org/data/definitions/570.html) | Expression is Always False | 미지정 |
| [CWE-571](https://cwe.mitre.org/data/definitions/571.html) | Expression is Always True | 미지정 |
| [CWE-573](https://cwe.mitre.org/data/definitions/573.html) | Improper Following of Specification by Caller | 미지정 |
| [CWE-574](https://cwe.mitre.org/data/definitions/574.html) | EJB Bad Practices: Use of Synchronization Primitives | 미지정 |
| [CWE-575](https://cwe.mitre.org/data/definitions/575.html) | EJB Bad Practices: Use of AWT Swing | 미지정 |
| [CWE-576](https://cwe.mitre.org/data/definitions/576.html) | EJB Bad Practices: Use of Java I/O | 미지정 |
| [CWE-577](https://cwe.mitre.org/data/definitions/577.html) | EJB Bad Practices: Use of Sockets | 미지정 |
| [CWE-578](https://cwe.mitre.org/data/definitions/578.html) | EJB Bad Practices: Use of Class Loader | 미지정 |
| [CWE-579](https://cwe.mitre.org/data/definitions/579.html) | J2EE Bad Practices: Non-serializable Object Stored in Session | 미지정 |
| [CWE-580](https://cwe.mitre.org/data/definitions/580.html) | clone() Method Without super.clone() | 미지정 |
| [CWE-581](https://cwe.mitre.org/data/definitions/581.html) | Object Model Violation: Just One of Equals and Hashcode Defined | 미지정 |
| [CWE-585](https://cwe.mitre.org/data/definitions/585.html) | Empty Synchronized Block | 미지정 |
| [CWE-586](https://cwe.mitre.org/data/definitions/586.html) | Explicit Call to Finalize() | 미지정 |
| [CWE-587](https://cwe.mitre.org/data/definitions/587.html) | Assignment of a Fixed Address to a Pointer | 미지정 |
| [CWE-588](https://cwe.mitre.org/data/definitions/588.html) | Attempt to Access Child of a Non-structure Pointer | 미지정 |
| [CWE-589](https://cwe.mitre.org/data/definitions/589.html) | Call to Non-ubiquitous API | 미지정 |
| [CWE-594](https://cwe.mitre.org/data/definitions/594.html) | J2EE Framework: Saving Unserializable Objects to Disk | 미지정 |
| [CWE-605](https://cwe.mitre.org/data/definitions/605.html) | Multiple Binds to the Same Port | 미지정 |
| [CWE-628](https://cwe.mitre.org/data/definitions/628.html) | Function Call with Incorrectly Specified Arguments | 미지정 |
| [CWE-636](https://cwe.mitre.org/data/definitions/636.html) | Not Failing Securely | 미지정 |
| [CWE-637](https://cwe.mitre.org/data/definitions/637.html) | Unnecessary Complexity in Protection Mechanism (Not Using 'Economy of Mechanism') | 미지정 |
| [CWE-638](https://cwe.mitre.org/data/definitions/638.html) | Not Using Complete Mediation | 미지정 |
| [CWE-653](https://cwe.mitre.org/data/definitions/653.html) | Improper Isolation or Compartmentalization | 미지정 |
| [CWE-654](https://cwe.mitre.org/data/definitions/654.html) | Reliance on a Single Factor in a Security Decision | 미지정 |
| [CWE-655](https://cwe.mitre.org/data/definitions/655.html) | Insufficient Psychological Acceptability | 미지정 |
| [CWE-656](https://cwe.mitre.org/data/definitions/656.html) | Reliance on Security Through Obscurity | 미지정 |
| [CWE-657](https://cwe.mitre.org/data/definitions/657.html) | Violation of Secure Design Principles | 미지정 |
| [CWE-671](https://cwe.mitre.org/data/definitions/671.html) | Lack of Administrator Control over Security | 미지정 |
| [CWE-675](https://cwe.mitre.org/data/definitions/675.html) | Multiple Operations on Resource in Single-Operation Context | 미지정 |
| [CWE-676](https://cwe.mitre.org/data/definitions/676.html) | Use of Potentially Dangerous Function | 미지정 |
| [CWE-683](https://cwe.mitre.org/data/definitions/683.html) | Function Call With Incorrect Order of Arguments | 미지정 |
| [CWE-684](https://cwe.mitre.org/data/definitions/684.html) | Incorrect Provision of Specified Functionality | 미지정 |
| [CWE-685](https://cwe.mitre.org/data/definitions/685.html) | Function Call With Incorrect Number of Arguments | 미지정 |
| [CWE-686](https://cwe.mitre.org/data/definitions/686.html) | Function Call With Incorrect Argument Type | 미지정 |
| [CWE-687](https://cwe.mitre.org/data/definitions/687.html) | Function Call With Incorrectly Specified Argument Value | 미지정 |
| [CWE-688](https://cwe.mitre.org/data/definitions/688.html) | Function Call With Incorrect Variable or Reference as Argument | 미지정 |
| [CWE-694](https://cwe.mitre.org/data/definitions/694.html) | Use of Multiple Resources with Duplicate Identifier | 미지정 |
| [CWE-695](https://cwe.mitre.org/data/definitions/695.html) | Use of Low-Level Functionality | 미지정 |
| [CWE-733](https://cwe.mitre.org/data/definitions/733.html) | Compiler Optimization Removal or Modification of Security-critical Code | 미지정 |
| [CWE-758](https://cwe.mitre.org/data/definitions/758.html) | Reliance on Undefined, Unspecified, or Implementation-Defined Behavior | 미지정 |
| [CWE-764](https://cwe.mitre.org/data/definitions/764.html) | Multiple Locks of a Critical Resource | 미지정 |
| [CWE-765](https://cwe.mitre.org/data/definitions/765.html) | Multiple Unlocks of a Critical Resource | 미지정 |
| [CWE-766](https://cwe.mitre.org/data/definitions/766.html) | Critical Data Element Declared Public | 미지정 |
| [CWE-785](https://cwe.mitre.org/data/definitions/785.html) | Use of Path Manipulation Function without Maximum-sized Buffer | 미지정 |
| [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | Use of Hard-coded Credentials | 미지정 |
| [CWE-912](https://cwe.mitre.org/data/definitions/912.html) | Hidden Functionality | 미지정 |
| [CWE-1007](https://cwe.mitre.org/data/definitions/1007.html) | Insufficient Visual Distinction of Homoglyphs Presented to User | 미지정 |
| [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | Improper Restriction of Rendered UI Layers or Frames | 미지정 |
| [CWE-1037](https://cwe.mitre.org/data/definitions/1037.html) | Processor Optimization Removal or Modification of Security-critical Code | 미지정 |
| [CWE-1038](https://cwe.mitre.org/data/definitions/1038.html) | Insecure Automated Optimizations | 미지정 |
| [CWE-1041](https://cwe.mitre.org/data/definitions/1041.html) | Use of Redundant Code | 미지정 |
| [CWE-1043](https://cwe.mitre.org/data/definitions/1043.html) | Data Element Aggregating an Excessively Large Number of Non-Primitive Elements | 미지정 |
| [CWE-1044](https://cwe.mitre.org/data/definitions/1044.html) | Architecture with Number of Horizontal Layers Outside of Expected Range | 미지정 |
| [CWE-1045](https://cwe.mitre.org/data/definitions/1045.html) | Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor | 미지정 |
| [CWE-1047](https://cwe.mitre.org/data/definitions/1047.html) | Modules with Circular Dependencies | 미지정 |
| [CWE-1048](https://cwe.mitre.org/data/definitions/1048.html) | Invokable Control Element with Large Number of Outward Calls | 미지정 |
| [CWE-1053](https://cwe.mitre.org/data/definitions/1053.html) | Missing Documentation for Design | 미지정 |
| [CWE-1054](https://cwe.mitre.org/data/definitions/1054.html) | Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer | 미지정 |
| [CWE-1055](https://cwe.mitre.org/data/definitions/1055.html) | Multiple Inheritance from Concrete Classes | 미지정 |
| [CWE-1056](https://cwe.mitre.org/data/definitions/1056.html) | Invokable Control Element with Variadic Parameters | 미지정 |
| [CWE-1057](https://cwe.mitre.org/data/definitions/1057.html) | Data Access Operations Outside of Expected Data Manager Component | 미지정 |
| [CWE-1059](https://cwe.mitre.org/data/definitions/1059.html) | Insufficient Technical Documentation | 미지정 |
| [CWE-1060](https://cwe.mitre.org/data/definitions/1060.html) | Excessive Number of Inefficient Server-Side Data Accesses | 미지정 |
| [CWE-1061](https://cwe.mitre.org/data/definitions/1061.html) | Insufficient Encapsulation | 미지정 |
| [CWE-1062](https://cwe.mitre.org/data/definitions/1062.html) | Parent Class with References to Child Class | 미지정 |
| [CWE-1064](https://cwe.mitre.org/data/definitions/1064.html) | Invokable Control Element with Signature Containing an Excessive Number of Parameters | 미지정 |
| [CWE-1065](https://cwe.mitre.org/data/definitions/1065.html) | Runtime Resource Management Control Element in a Component Built to Run on Application Servers | 미지정 |
| [CWE-1066](https://cwe.mitre.org/data/definitions/1066.html) | Missing Serialization Control Element | 미지정 |
| [CWE-1068](https://cwe.mitre.org/data/definitions/1068.html) | Inconsistency Between Implementation and Documented Design | 미지정 |
| [CWE-1069](https://cwe.mitre.org/data/definitions/1069.html) | Empty Exception Block | 미지정 |
| [CWE-1070](https://cwe.mitre.org/data/definitions/1070.html) | Serializable Data Element Containing non-Serializable Item Elements | 미지정 |
| [CWE-1071](https://cwe.mitre.org/data/definitions/1071.html) | Empty Code Block | 미지정 |
| [CWE-1074](https://cwe.mitre.org/data/definitions/1074.html) | Class with Excessively Deep Inheritance | 미지정 |
| [CWE-1075](https://cwe.mitre.org/data/definitions/1075.html) | Unconditional Control Flow Transfer outside of Switch Block | 미지정 |
| [CWE-1076](https://cwe.mitre.org/data/definitions/1076.html) | Insufficient Adherence to Expected Conventions | 미지정 |
| [CWE-1078](https://cwe.mitre.org/data/definitions/1078.html) | Inappropriate Source Code Style or Formatting | 미지정 |
| [CWE-1079](https://cwe.mitre.org/data/definitions/1079.html) | Parent Class without Virtual Destructor Method | 미지정 |
| [CWE-1080](https://cwe.mitre.org/data/definitions/1080.html) | Source Code File with Excessive Number of Lines of Code | 미지정 |
| [CWE-1082](https://cwe.mitre.org/data/definitions/1082.html) | Class Instance Self Destruction Control Element | 미지정 |
| [CWE-1083](https://cwe.mitre.org/data/definitions/1083.html) | Data Access from Outside Expected Data Manager Component | 미지정 |
| [CWE-1085](https://cwe.mitre.org/data/definitions/1085.html) | Invokable Control Element with Excessive Volume of Commented-out Code | 미지정 |
| [CWE-1086](https://cwe.mitre.org/data/definitions/1086.html) | Class with Excessive Number of Child Classes | 미지정 |
| [CWE-1087](https://cwe.mitre.org/data/definitions/1087.html) | Class with Virtual Method without a Virtual Destructor | 미지정 |
| [CWE-1090](https://cwe.mitre.org/data/definitions/1090.html) | Method Containing Access of a Member Element from Another Class | 미지정 |
| [CWE-1091](https://cwe.mitre.org/data/definitions/1091.html) | Use of Object without Invoking Destructor Method | 미지정 |
| [CWE-1092](https://cwe.mitre.org/data/definitions/1092.html) | Use of Same Invokable Control Element in Multiple Architectural Layers | 미지정 |
| [CWE-1093](https://cwe.mitre.org/data/definitions/1093.html) | Excessively Complex Data Representation | 미지정 |
| [CWE-1095](https://cwe.mitre.org/data/definitions/1095.html) | Loop Condition Value Update within the Loop | 미지정 |
| [CWE-1097](https://cwe.mitre.org/data/definitions/1097.html) | Persistent Storable Data Element without Associated Comparison Control Element | 미지정 |
| [CWE-1098](https://cwe.mitre.org/data/definitions/1098.html) | Data Element containing Pointer Item without Proper Copy Control Element | 미지정 |
| [CWE-1099](https://cwe.mitre.org/data/definitions/1099.html) | Inconsistent Naming Conventions for Identifiers | 미지정 |
| [CWE-1100](https://cwe.mitre.org/data/definitions/1100.html) | Insufficient Isolation of System-Dependent Functions | 미지정 |
| [CWE-1101](https://cwe.mitre.org/data/definitions/1101.html) | Reliance on Runtime Component in Generated Code | 미지정 |
| [CWE-1102](https://cwe.mitre.org/data/definitions/1102.html) | Reliance on Machine-Dependent Data Representation | 미지정 |
| [CWE-1103](https://cwe.mitre.org/data/definitions/1103.html) | Use of Platform-Dependent Third Party Components | 미지정 |
| [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) | Use of Unmaintained Third Party Components | 미지정 |
| [CWE-1105](https://cwe.mitre.org/data/definitions/1105.html) | Insufficient Encapsulation of Machine-Dependent Functionality | 미지정 |
| [CWE-1106](https://cwe.mitre.org/data/definitions/1106.html) | Insufficient Use of Symbolic Constants | 미지정 |
| [CWE-1107](https://cwe.mitre.org/data/definitions/1107.html) | Insufficient Isolation of Symbolic Constant Definitions | 미지정 |
| [CWE-1108](https://cwe.mitre.org/data/definitions/1108.html) | Excessive Reliance on Global Variables | 미지정 |
| [CWE-1109](https://cwe.mitre.org/data/definitions/1109.html) | Use of Same Variable for Multiple Purposes | 미지정 |
| [CWE-1110](https://cwe.mitre.org/data/definitions/1110.html) | Incomplete Design Documentation | 미지정 |
| [CWE-1111](https://cwe.mitre.org/data/definitions/1111.html) | Incomplete I/O Documentation | 미지정 |
| [CWE-1112](https://cwe.mitre.org/data/definitions/1112.html) | Incomplete Documentation of Program Execution | 미지정 |
| [CWE-1113](https://cwe.mitre.org/data/definitions/1113.html) | Inappropriate Comment Style | 미지정 |
| [CWE-1114](https://cwe.mitre.org/data/definitions/1114.html) | Inappropriate Whitespace Style | 미지정 |
| [CWE-1115](https://cwe.mitre.org/data/definitions/1115.html) | Source Code Element without Standard Prologue | 미지정 |
| [CWE-1116](https://cwe.mitre.org/data/definitions/1116.html) | Inaccurate Source Code Comments | 미지정 |
| [CWE-1117](https://cwe.mitre.org/data/definitions/1117.html) | Callable with Insufficient Behavioral Summary | 미지정 |
| [CWE-1118](https://cwe.mitre.org/data/definitions/1118.html) | Insufficient Documentation of Error Handling Techniques | 미지정 |
| [CWE-1119](https://cwe.mitre.org/data/definitions/1119.html) | Excessive Use of Unconditional Branching | 미지정 |
| [CWE-1120](https://cwe.mitre.org/data/definitions/1120.html) | Excessive Code Complexity | 미지정 |
| [CWE-1121](https://cwe.mitre.org/data/definitions/1121.html) | Excessive McCabe Cyclomatic Complexity | 미지정 |
| [CWE-1122](https://cwe.mitre.org/data/definitions/1122.html) | Excessive Halstead Complexity | 미지정 |
| [CWE-1123](https://cwe.mitre.org/data/definitions/1123.html) | Excessive Use of Self-Modifying Code | 미지정 |
| [CWE-1124](https://cwe.mitre.org/data/definitions/1124.html) | Excessively Deep Nesting | 미지정 |
| [CWE-1125](https://cwe.mitre.org/data/definitions/1125.html) | Excessive Attack Surface | 미지정 |
| [CWE-1126](https://cwe.mitre.org/data/definitions/1126.html) | Declaration of Variable with Unnecessarily Wide Scope | 미지정 |
| [CWE-1127](https://cwe.mitre.org/data/definitions/1127.html) | Compilation with Insufficient Warnings or Errors | 미지정 |
| [CWE-1164](https://cwe.mitre.org/data/definitions/1164.html) | Irrelevant Code | 미지정 |
| [CWE-1177](https://cwe.mitre.org/data/definitions/1177.html) | Use of Prohibited Code | 미지정 |
| [CWE-1189](https://cwe.mitre.org/data/definitions/1189.html) | Improper Isolation of Shared Resources on System-on-a-Chip (SoC) | 미지정 |
| [CWE-1192](https://cwe.mitre.org/data/definitions/1192.html) | Improper Identifier for IP Block used in System-On-Chip (SOC) | 미지정 |
| [CWE-1209](https://cwe.mitre.org/data/definitions/1209.html) | Failure to Disable Reserved Bits | 미지정 |
| [CWE-1242](https://cwe.mitre.org/data/definitions/1242.html) | Inclusion of Undocumented Features or Chicken Bits | 미지정 |
| [CWE-1245](https://cwe.mitre.org/data/definitions/1245.html) | Improper Finite State Machines (FSMs) in Hardware Logic | 미지정 |
| [CWE-1277](https://cwe.mitre.org/data/definitions/1277.html) | Firmware Not Updateable | 미지정 |
| [CWE-1303](https://cwe.mitre.org/data/definitions/1303.html) | Non-Transparent Sharing of Microarchitectural Resources | 미지정 |
| [CWE-1310](https://cwe.mitre.org/data/definitions/1310.html) | Missing Ability to Patch ROM Code | 미지정 |
| [CWE-1329](https://cwe.mitre.org/data/definitions/1329.html) | Reliance on Component That is Not Updateable | 미지정 |
| [CWE-1331](https://cwe.mitre.org/data/definitions/1331.html) | Improper Isolation of Shared Resources in Network On Chip (NoC) | 미지정 |
| [CWE-1341](https://cwe.mitre.org/data/definitions/1341.html) | Multiple Releases of Same Resource or Handle | 미지정 |
| [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) | Reliance on Insufficiently Trustworthy Component | 미지정 |
| [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | Dependency on Vulnerable Third-Party Component | 미지정 |
| [CWE-1431](https://cwe.mitre.org/data/definitions/1431.html) | Driving Intermediate Cryptographic State/Results to Hardware Module Outputs | 미지정 |
| [CWE-1434](https://cwe.mitre.org/data/definitions/1434.html) | Insecure Setting of Generative AI/ML Model Inference Parameters | 미지정 |

</details>


<!-- END GENERATED SECTION 3 RESULTS -->

### 상속 원칙과 예외

공식 계층 관계만 보존한다. 분석 방법·운영 충분성·소스 필수 여부는 상속하지 않는다. 다중 Pillar 소속도 그대로 유지한다.

## 4. 현재 라우터 동작

<!-- BEGIN GENERATED SECTION 4 RESULTS -->

### 4.1 현재 실행 결과

근거가 확립되지 않은 수작업 기준·상속·운영 목록·키워드 보정을 제거했다. 현재 자동 분석 경로 선택은 중단되어 있다. 소스 자료 유무나 특정 단어만으로 이 상태를 해제하지 않는다.

| 전체 고유 세부 CWE | 자동 소스 지정 | 자동 운영 지정 | 기준 미지정 |
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
| control-mapping-advisory | 구성한 통제 입력 | CWE-119 | 분류 유보 | 분류 유보 |
| control-mixed-unknown | 구성한 통제 입력 | CWE-787, CWE-999999 | 분류 유보 | 분류 유보 |

현재 모든 신규 검토는 `routing_unknown` / `under_investigation`으로 시작하며 소스 또는 운영 경로를 추정하지 않는다. 공식 CWE ID·정의·계층·출처는 보존한다. 기존 소스 분석기와 문서 출력 기능 자체를 삭제한 것은 아니다.

전체 입력과 반환값: [criteria_results.json](../data/cwe_routing/v2/criteria_results.json).
재생성: `python tools/build_cwe_evidence_policy.py`.

정책 버전: `cwe-evidence-v2.2-unassigned` / 정책 해시: `cc13abce870946859766f8165eb2add8407b08c13747f42d704bc280eb240f58`.

<!-- END GENERATED SECTION 4 RESULTS -->

## 5. 보고된 CWE 유지와 근거 부족 처리

`Allowed`, `Allowed-with-Review`, `Discouraged`, `Prohibited`는 CWE 부여 지침을 보존한 참고 정보다. 어느 등급도 이미 보고된 CWE를 제거하거나 분석 경로를 차단하는 조건으로 사용하지 않는다. 현재 미지정의 원인은 매핑 등급이 아니라 정당화된 증거 경로 기준이 없다는 것이다.

## 6. 실행 기능과 분류 기능의 구분

소스 분석기, 운영 질문/답변 처리기, 상태 결합·검증기, 최종 VEX 작성·출력 기능은 남아 있다. 네 가지 증거 워크플로의 실행 구조도 남아 있지만, 현재 CWE로부터 해당 경로를 자동 선택하는 연결은 없다. 신규 CWE-first 검토에서 소스 업로드나 운영 질문 버튼으로 미지정 경로를 우회하지 않는다.

신규 검토는 `under_investigation`으로 남는다. 기존 정책의 검토 결과는 자동 재사용하지 않고 정책 버전/해시 변경을 표시한다. 역사적 원본 기록은 덮어쓰지 않는다.

## 7. 검증 범위

검사는 공식 자료 보존, 944개 미지정 상태, 소스 유무·키워드·사용자 제공 요구 필드가 경로를 임의로 확정하지 못함, 운영 질문/소스 결과로 미지정 경로를 우회하지 못함을 확인한다. 이 검사는 분류 정확도나 VEX 정확도가 아니다.

## 8. 파일과 재현

- 공식 계층: `data/cwe_taxonomy/v5.0/catalog.json`
- 공식 메타데이터: `data/cwe_taxonomy/v5.0/evidence_metadata.json`
- 현재 상태 정책: `data/cwe_evidence_policy_v2.json`
- 944개 레코드: `data/cwe_routing/v2/profiles.json`, `profiles.csv`, `summary.json`
- 현재 실행 기록: `data/cwe_routing/v2/criteria_results.json`
- 구현: `src/cwe_evidence_policy.py`, `src/vex_routing.py`
- 재생성: `python tools/build_cwe_evidence_policy.py`

자료 버전은 공식 CWE v5.0 스냅샷에 고정되어 있다. 분류표의 공식 소속 범위와 프로젝트가 판단한 분석 방법을 구분한다.
