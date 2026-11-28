# ICS 자산 유형별 자산 운영 정보 프로파일 v0.4 — 세부 항목별 영어 원문 근거

수정일: 2026-11-17. 원문 범위: 첨부 NIST SP 800-82r4 IPD(September 2026), Appendix C.2.2 Tables 12–17. 원문 54개 행과 167개 세부 정보의 추적 근거를 기록한다. 실제 자산 상태나 전문가 타당성 검증 결과는 아니다.

## 1. 읽는 방법과 출처

- 각 C항목에 실제 PDF의 Vulnerability(행 제목)와 Description(설명) 원문을 보존했다.
- 각 세부 수집정보에 영어 구절, 구절이 나온 열, 원문을 질문·관측으로 바꾼 해석상의 주의를 연결했다.
- 영어는 PDF 표에서 직접 추출하고 줄바꿈·연속 공백만 정규화했다. 대괄호나 생략어로 의미를 보충하지 않는다. 발췌는 문장 전체가 아닐 수 있으므로 함께 실은 Description 전체로 문맥을 확인한다.
- 세부 수집정보는 원문 개념을 관측형으로 바꾼 한국어 재서술이다. 영어 원문에 공식 한국어 필드나 값 체계가 존재하는 것은 아니다.
- 원문이 개념·위험만 설명한 경우 실제 상태/효력을 확정할 수 없음을 표시했다. 직접 근거를 벗어난 표현은 좁혀 수정했다.
- 인쇄 페이지와 PDF 파일의 1부터 센 페이지를 모두 기재한다.
- 출처: https://doi.org/10.6028/NIST.SP.800-82r4.ipd ; MITRE 유형 출처: https://attack.mitre.org/assets/ . 그 밖의 표·절은 자산 운영 정보 필드 근거로 사용하지 않는다.

## 2. 표별 범위

| 표 | 원문 행 수 |
|---|---:|
| Table 12 | 11 |
| Table 13 | 21 |
| Table 14 | 5 |
| Table 15 | 3 |
| Table 16 | 11 |
| Table 17 | 3 |
| 합계 | 54 |

167개 세부 수집정보는 독립적·필수적인 질문 수가 아니다. 동일 관측이 여러 항목에 사용될 수 있다. C번호와 세부 번호는 연구용 추적 ID다.

## 3. 원문과 세부 항목별 근거

### C12-01 · 구조·설계의 보안 반영

- 근거 위치: **Table 12, 인쇄 p.170, PDF p.188**
- 활용 구분(연구자 분류): 설계·관리

**Vulnerability — 원문 행 제목**

> Inadequate incorporation of security into architecture and design

**Description — 원문 설명 전체**

> Incorporating security into the OT architecture and design must start with a budget and schedule designated for OT. The architectures must address the identification and authorization of users, access control mechanism, network topologies, and system configuration and integrity mechanisms.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C12-01.01 | OT 보안을 위한 예산·일정 반영 여부 | “budget and schedule designated for OT” | Description | 조직·설계 범위 정보이며 개별 CVE 악용의 필수 조건으로 단정하지 않는다. |
| C12-01.02 | 사용자 식별·인가 반영 여부 | “identification and authorization of users” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-01.03 | 접근통제 메커니즘 | “access control mechanism” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-01.04 | 네트워크 토폴로지 | “network topologies” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-01.05 | 시스템 설정·무결성 메커니즘 | “system configuration and integrity mechanisms” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C12-02 · 구조 변경 관리

- 근거 위치: **Table 12, 인쇄 p.170, PDF p.188**
- 활용 구분(연구자 분류): 설계·관리

**Vulnerability — 원문 행 제목**

> Inadequate management of change that allows insecure architecture to evolve

**Description — 원문 설명 전체**

> The network infrastructure within the OT environment has often been developed and modified based on business and operational requirements with little consideration for the potential security impacts of the changes. Over time, security gaps may have been inadvertently introduced within the infrastructure. Without remediation, these gaps may represent backdoors into the OT. Sensors and controllers that were historically simple devices are now often manufactured as intelligent devices. In some cases, sensors and controllers may be replaced with IIoT devices that allow direct internet connections. Security should be incorporated into change management for all OT devices, not just traditional IT components.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C12-02.01 | OT 네트워크 인프라의 개발·변경 현황 | “network infrastructure within the OT environment” | Description | 원문은 변경의 존재와 영향을 설명한다. 변경 이력 기록 형식까지 요구하지 않는다. |
| C12-02.02 | 변경 시 보안 영향 검토 여부 | “little consideration for the potential security impacts of the changes” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-02.03 | IIoT 장치 교체·직접 인터넷 연결 도입 여부 | “replaced with IIoT devices that allow direct internet connections” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C12-03 · 보안 경계

- 근거 위치: **Table 12, 인쇄 p.170, PDF p.188**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> No security perimeter defined

**Description — 원문 설명 전체**

> If the OT does not have a security perimeter clearly defined, it is not possible to ensure that the necessary security controls are deployed and configured properly. This can lead to unauthorized access to systems and data as well as other problems.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C12-03.01 | OT 보안 경계의 정의 여부 | “security perimeter clearly defined” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-03.02 | 해당 경계에 배치·설정된 보안 통제 | “necessary security controls are deployed and configured properly” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C12-04 · 제어·비제어 트래픽 혼재

- 근거 위치: **Table 12, 인쇄 p.170, PDF p.188**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Control networks used for non- control traffic

**Description — 원문 설명 전체**

> Control and non-control traffic have different requirements, such as determinism and reliability. Having both types of traffic on a single network creates challenges for meeting the requirements of control traffic. For example, non-control traffic could inadvertently consume resources that control traffic needs, causing disruptions in OT functions.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C12-04.01 | 제어망에서 비제어 트래픽을 사용하는지 | “Control and non-control traffic” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-04.02 | 제어 트래픽과 비제어 트래픽이 동일 네트워크를 공유하는지 | “Having both types of traffic on a single network” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C12-05 · 비제어망 서비스 의존

- 근거 위치: **Table 12, 인쇄 p.171, PDF p.189**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Control network services dependent on a non-control network

**Description — 원문 설명 전체**

> When IT services (e.g., DNS, DHCP) are used by control networks, they are often implemented in the IT network. This causes the OT network to become dependent on the IT network, which may not have the reliability and availability requirements needed by OT.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C12-05.01 | 제어망이 사용하는 외부 IT 서비스 종류 | “IT services (e.g., DNS, DHCP)” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-05.02 | DNS·DHCP 등 서비스가 위치한 네트워크 | “implemented in the IT network” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-05.03 | 제어망의 해당 서비스 의존 여부 | “dependent on the IT network” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C12-06 · 이벤트 이력 수집

- 근거 위치: **Table 12, 인쇄 p.171, PDF p.189**
- 활용 구분(연구자 분류): 관측·탐지

**Vulnerability — 원문 행 제목**

> Inadequate collection of event data history

**Description — 원문 설명 전체**

> Forensic analysis depends on the collection and retention of sufficient data. Without proper and accurate data collection, it may be impossible to determine what caused a security incident to occur. Incidents might go unnoticed, leading to additional damage and/or disruption. Regular security monitoring is also needed to identify problems with security controls, such as misconfigurations and failures. Event data for an OT environment could include physical process data, system use data, and network data.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C12-06.01 | 물리 공정 데이터 수집·보존 여부 | “physical process data” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-06.02 | 시스템 사용 데이터 수집·보존 여부 | “system use data” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-06.03 | 네트워크 데이터 수집·보존 여부 | “network data” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-06.04 | 설정 오류·통제 실패를 확인하는 보안 모니터링 여부 | “Regular security monitoring is also needed to identify problems with security controls” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C12-07 · IoT·IIoT 통합 구조

- 근거 위치: **Table 12, 인쇄 p.171, PDF p.189**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Inadequate security architecture considerations for IoT and IIoT device integration

**Description — 원문 설명 전체**

> IoT and IIoT devices often have limited built-in security capabilities and may introduce new network pathways and communication channels that have not been accounted for. Without adequate network segmentation and access controls, the integration of these devices can significantly expand the OT attack surface and provide adversaries with additional entry points into the environment.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C12-07.01 | IoT·IIoT 장치 통합 여부 | “IoT and IIoT device integration” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-07.02 | 통합으로 추가된 네트워크 경로·통신 채널 | “new network pathways and communication channels” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-07.03 | 관련 네트워크 분리·접근통제 상태 | “network segmentation and access controls” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C12-08 · 클라우드 연결 구조

- 근거 위치: **Table 12, 인쇄 p.171, PDF p.189**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Inadequate security architecture considerations for cloud-connected OT environments

**Description — 원문 설명 전체**

> When cloud integration is not adequately accounted for in the OT security architecture, it introduces dependencies on external infrastructure outside of the organization’s direct control and may create network pathways that bypass existing perimeter controls.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C12-08.01 | OT의 클라우드 통합 여부 | “cloud integration” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-08.02 | 외부 클라우드 인프라 의존 여부 | “dependencies on external infrastructure” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-08.03 | 기존 경계 통제를 우회할 수 있는 연결 경로 | “network pathways that bypass existing perimeter controls” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C12-09 · 암호 전환 가능성

- 근거 위치: **Table 12, 인쇄 p.171, PDF p.189**
- 활용 구분(연구자 분류): 설계·관리

**Vulnerability — 원문 행 제목**

> Lack of post-quantum cryptography consideration in OT architecture

**Description — 원문 설명 전체**

> Advances in quantum computing are expected to render widely used asymmetric encryption algorithms obsolete, posing a long-term risk to OT systems that cannot be updated or replaced. Organizations should consider cryptographic agility as a requirement when procuring new OT systems to ensure that cryptographic standards can be updated without requiring full hardware replacement.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C12-09.01 | 비대칭 암호 알고리즘 사용·전환에 관한 고려 여부 | “widely used asymmetric encryption algorithms” | Description | 특정 알고리즘 목록·허용/금지 기준은 원문에서 추가하지 않는다. |
| C12-09.02 | 기존 장치의 업데이트·교체 가능 여부 | “systems that cannot be updated or replaced” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-09.03 | 전체 하드웨어 교체 없이 암호 표준을 변경할 수 있는지 | “cryptographic standards can be updated without requiring full hardware replacement” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C12-10 · AI 통합의 보안 고려

- 근거 위치: **Table 12, 인쇄 p.171, PDF p.189**
- 활용 구분(연구자 분류): 조건 후보·설계

**Vulnerability — 원문 행 제목**

> Inadequate security considerations for AI systems integrated into OT environments

**Description — 원문 설명 전체**

> AI systems are susceptible to manipulation through prompt injection and compromised training data, which can cause models to produce incorrect outputs, develop blind spots that allow unsafe conditions or malicious activity to go undetected, or reveal sensitive information to unauthorized users. The data pipelines and external connectivity required to support AI systems can also introduce new network pathways into the OT environment that may not be properly secured.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C12-10.01 | OT 내 AI 시스템 통합 여부 | “AI systems integrated into OT environments” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-10.02 | 프롬프트 주입·학습 데이터 훼손에 대한 확인·검토 정보 | “prompt injection and compromised training data” | Description | 원문은 공격 가능성을 설명한다. 안전성 검증이 완료됐다는 사실을 뜻하지 않는다. |
| C12-10.03 | AI 지원 데이터 파이프라인·외부 연결 경로의 보호 여부 | “data pipelines and external connectivity” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C12-11 · AI 확률적 동작 고려

- 근거 위치: **Table 12, 인쇄 p.171, PDF p.189**
- 활용 구분(연구자 분류): 영향·설계

**Vulnerability — 원문 행 제목**

> Inadequate consideration of AI behavior in deterministic OT environments

**Description — 원문 설명 전체**

> OT control systems are designed around deterministic logic, meaning that a given input reliably produces the same expected output. AI systems operate probabilistically, meaning that outputs are based on statistical inference and may vary under different conditions. Deploying AI in safety-critical OT environments without accounting for this fundamental difference introduces the risk of unpredictable outputs that could result in incorrect process recommendations, missed anomalies, or unsafe operational decisions.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C12-11.01 | 안전 관련 OT에서 AI를 사용하는지 | “Deploying AI in safety-critical OT environments” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-11.02 | 확률적 출력과 출력 변동성을 설계에서 고려했는지 | “outputs are based on statistical inference” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C12-11.03 | 공정 권고·이상 탐지·운영 의사결정에 대한 AI 출력 영향 검토 정보 | “incorrect process recommendations, missed anomalies, or unsafe operational decisions” | Description | 원문이 열거한 잠재적 영향에 관한 질문이다. 실제 AI 사용처의 필수 분류표가 아니다. |

### C13-01 · 자산 관리

- 근거 위치: **Table 13, 인쇄 p.172, PDF p.190**
- 활용 구분(연구자 분류): 자산 식별

**Vulnerability — 원문 행 제목**

> Hardware, firmware, and software that are not under asset management

**Description — 원문 설명 전체**

> The organization does not know what it has (e.g., make, model), where they are, or what version it is, resulting in an inconsistent and ineffective defense posture. To properly secure an OT, there should be an accurate inventory of the assets in the environment. Procedures should be in place to manage additions, deletions, and modifications of assets, which include asset inventory management. These procedures are critical to executing business continuity and disaster recovery plans.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-01.01 | 하드웨어·펌웨어·소프트웨어의 제조사·모델 | “make, model” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-01.02 | 자산 위치 | “where they are” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-01.03 | 현재 버전 | “what version it is” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-01.04 | 추가·삭제·수정 내역의 관리 여부 | “additions, deletions, and modifications of assets” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-02 · 설정 관리

- 근거 위치: **Table 13, 인쇄 p.172, PDF p.190**
- 활용 구분(연구자 분류): 조건 후보·관리

**Vulnerability — 원문 행 제목**

> Hardware, firmware, and software are not under configuration management

**Description — 원문 설명 전체**

> The organization does not know the patch management status, security settings, or configuration versions that it has, resulting in an inconsistent and ineffective defense posture. A lack of configuration change management procedures can lead to security oversights, exposures, and risks. A process for controlling modifications to hardware, firmware, software, and documentation should be implemented to ensure that an OT is protected against inadequate or improper modifications before, during, and after system implementation. To properly secure an OT, there should be an accurate listing or repository of the current configurations.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-02.01 | 현재 패치 관리 상태 | “patch management status” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-02.02 | 보안 설정 | “security settings” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-02.03 | 설정 버전 | “configuration versions” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-02.04 | 현재 설정 목록·저장소 존재 여부 | “accurate listing or repository of the current configurations” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-02.05 | 하드웨어·펌웨어·소프트웨어 변경 관리 여부 | “controlling modifications to hardware, firmware, software, and documentation” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-03 · 패치 제공 지연

- 근거 위치: **Table 13, 인쇄 p.172, PDF p.190**
- 활용 구분(연구자 분류): 대응·관리

**Vulnerability — 원문 행 제목**

> OS and vendor software patches may not be developed until long after security vulnerabilities are found

**Description — 원문 설명 전체**

> Because of the tight coupling between OT software and the underlying OT, changes must undergo expensive and time-consuming comprehensive regression testing. The elapsed time for such testing and the subsequent distribution of updated software provides a long window of vulnerability. Vulnerability management procedures should include flexibility for interim alternative mitigations.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-03.01 | 해당 취약점 패치 개발·제공 상태 | “patches may not be developed until long after security vulnerabilities are found” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-03.02 | 패치 변경에 대한 회귀시험 관련 정보 | “regression testing” | Description | 원문은 회귀시험으로 인한 지연을 설명한다. 시험 절차를 새로 정의하지 않는다. |
| C13-03.03 | 패치 제공 전 임시 대체 조치 여부 | “interim alternative mitigations” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-04 · 공급자 패치 미지원

- 근거 위치: **Table 13, 인쇄 p.172, PDF p.190**
- 활용 구분(연구자 분류): 대응·관리

**Vulnerability — 원문 행 제목**

> Vendor declines to develop patches for vulnerability

**Description — 원문 설명 전체**

> Out-of-date OSs and applications may contain newly discovered vulnerabilities that could be exploited. Security patch support may not be available for legacy OT, so vulnerability management procedures should include contingency plans for mitigating vulnerabilities where patches may never be available or replacement plans.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-04.01 | 사용 중인 OS·애플리케이션의 패치 지원 여부 | “Security patch support may not be available for legacy OT” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-04.02 | 해당 취약점 패치 제공 여부 | “Vendor declines to develop patches for vulnerability” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-04.03 | 패치가 제공되지 않을 때의 완화·교체 계획 | “mitigating vulnerabilities where patches may never be available or replacement plans” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-05 · 취약점 관리

- 근거 위치: **Table 13, 인쇄 p.172, PDF p.190**
- 활용 구분(연구자 분류): 조건 후보·대응

**Vulnerability — 원문 행 제목**

> Lack of a vulnerability management program

**Description — 원문 설명 전체**

> Vulnerability management procedures should be in place to determine a plan of action or inaction upon the discovery of a vulnerability. Some OT- specific considerations regarding patching include general availability (e.g., patching delayed to the next planned operational downtime), security patch support being unavailable for OT systems that use outdated OSs, isolated systems that may not require immediate patching, and prioritizing patching for OT that is exposed to the internet.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-05.01 | 취약점 발견 시 조치·미조치 계획 | “plan of action or inaction” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-05.02 | 정기 운영 중단까지 패치를 연기하는지 | “patching delayed to the next planned operational downtime” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-05.03 | 보안 패치 지원 여부 | “security patch support being unavailable” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-05.04 | 시스템 격리 상태 | “isolated systems” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-05.05 | 인터넷 노출 여부 | “OT that is exposed to the internet” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-06 · 보안 변경 시험

- 근거 위치: **Table 13, 인쇄 p.172, PDF p.190**
- 활용 구분(연구자 분류): 관리·검증

**Vulnerability — 원문 행 제목**

> Inadequate testing of security changes

**Description — 원문 설명 전체**

> Modifications to hardware, firmware, and software deployed without testing could compromise normal operation of the OT. Documented procedures should be developed for testing all changes for security impacts. The live operational systems should never be used for testing. The testing of system modifications may need to be coordinated with system vendors and integrators.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-06.01 | 하드웨어·펌웨어·소프트웨어 변경의 시험 수행 여부 | “Modifications to hardware, firmware, and software deployed without testing” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-06.02 | 변경의 보안 영향 시험 절차 | “procedures should be developed for testing all changes for security impacts” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-06.03 | 운영 시스템과 시험 환경의 구분 | “The live operational systems should never be used for testing” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-06.04 | 공급자·통합업체와 시험을 조정하는지 | “coordinated with system vendors and integrators” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-07 · 원격 접근 통제

- 근거 위치: **Table 13, 인쇄 p.172, PDF p.190**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Poor remote access controls

**Description — 원문 설명 전체**

> There are many reasons why an OT may need to be remotely accessed, including vendors and system integrators performing system maintenance functions or OT engineers accessing geographically remote system components. The concept of least privilege should be applied to remote access controls. Remote access capabilities must be adequately controlled to prevent unauthorized individuals from gaining access or authorized individuals from gaining excessive access to the OT.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-07.01 | 원격 접근 기능 사용 여부 | “OT may need to be remotely accessed” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-07.02 | 원격 접근자에 대한 접근통제 상태 | “prevent unauthorized individuals from gaining access” | Description | 구체적 계정·대상·경로 표현은 수집 설계이며 원문 공식 필드가 아니다. |
| C13-07.03 | 원격 접근 권한 범위 | “authorized individuals from gaining excessive access” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-07.04 | 비인가 접근·과도한 권한을 제한하는 통제 | “Remote access capabilities must be adequately controlled” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-08 · 포트·프로토콜·기능 설정

- 근거 위치: **Table 13, 인쇄 p.173, PDF p.191**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Poor configurations are used

**Description — 원문 설명 전체**

> Improperly configured systems may leave unnecessary ports and protocols open. These unnecessary functions may contain vulnerabilities that increase the overall risk to the system. Using default configurations often exposes vulnerabilities and exploitable services. All settings should be examined.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-08.01 | 열려 있는 포트·프로토콜 | “unnecessary ports and protocols open” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-08.02 | 기본 설정에서 노출되는 취약 기능·서비스 관련 정보 | “vulnerabilities and exploitable services” | Description | 서비스 지원·활성 상태를 일괄 독립 필드로 확장한 표현에서 원문 범위로 좁혔다. |
| C13-08.03 | 기본 설정 사용 여부 | “Using default configurations” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-08.04 | 설정 검토 여부 | “All settings should be examined” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-09 · 중요 설정 저장·백업

- 근거 위치: **Table 13, 인쇄 p.173, PDF p.191**
- 활용 구분(연구자 분류): 복구

**Vulnerability — 원문 행 제목**

> Critical configurations are not stored or backed up

**Description — 원문 설명 전체**

> Procedures should be available for restoring OT configuration settings in the event of accidental or adversary-initiated configuration changes to maintain system availability and prevent the loss of data. Documented procedures should be developed for maintaining configuration settings.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-09.01 | 중요 설정의 저장 여부 | “Critical configurations are not stored” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-09.02 | 설정 백업 여부 | “or backed up” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-09.03 | 설정 복원 절차 존재 여부 | “Procedures should be available for restoring OT configuration settings” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-10 · 휴대 장치의 민감정보 보호

- 근거 위치: **Table 13, 인쇄 p.173, PDF p.191**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Data unprotected on portable device

**Description — 원문 설명 전체**

> System security could be compromised if sensitive data (e.g., passwords, dial-up numbers) is stored in cleartext on lost or stolen portable devices, such as laptops and mobile devices. Policy, procedures, and mechanisms are required for protection.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-10.01 | 휴대 장치에 민감정보를 저장하는지 | “sensitive data” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-10.02 | 비밀번호·접속 번호 등 민감정보가 평문 저장되는지 | “stored in cleartext” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-10.03 | 휴대 장치 데이터 보호 수단 여부 | “mechanisms are required for protection” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-11 · 기본 비밀번호 사용

- 근거 위치: **Table 13, 인쇄 p.173, PDF p.191**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Vendor default passwords are used

**Description — 원문 설명 전체**

> Most vendor default passwords are easy to discover within vendor product manuals, which are also available to adversaries. Using the default password can drastically increase OT vulnerability.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-11.01 | 공급자 기본 비밀번호 사용 여부 | “Using the default password” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-12 · 비밀번호 정책 준수

- 근거 위치: **Table 13, 인쇄 p.173, PDF p.191**
- 활용 구분(연구자 분류): 관리

**Vulnerability — 원문 행 제목**

> Password generation, use, and protection do not comply with policy

**Description — 원문 설명 전체**

> Password policy and procedures must be followed to be effective. Violations of password policy and procedures can increase OT vulnerability.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-12.01 | 비밀번호 생성·사용·보호에 적용되는 정책·절차 | “Password policy and procedures” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-12.02 | 해당 정책 준수 여부 | “must be followed to be effective” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-13 · 접근 권한 설정

- 근거 위치: **Table 13, 인쇄 p.173, PDF p.191**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Inadequate access controls applied

**Description — 원문 설명 전체**

> Access controls must match how the organization allocates responsibilities and privilege to its personnel. Poorly specified access controls can result in an OT user having too many or too few privileges. For example: • System configured with default access control settings gives an operator administrative privileges. • System configured improperly results in an operator being unable to take corrective actions in an emergency situation.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-13.01 | 실제 부여된 사용자 권한 | “responsibilities and privilege to its personnel” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-13.02 | 직무·책임에 맞는 권한인지 | “Access controls must match” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-13.03 | 운영자에게 기본 설정으로 관리자 권한이 부여되는지 | “operator administrative privileges” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-13.04 | 비상 시 필요한 조작을 권한 설정이 제한하는지 | “operator being unable to take corrective actions in an emergency situation” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-14 · 외부 데이터 연결

- 근거 위치: **Table 13, 인쇄 p.173, PDF p.191**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Improper data linking

**Description — 원문 설명 전체**

> OT data storage systems may be linked to non-OT data sources. For example, database links allow data from one database (e.g., data historian) to be automatically replicated on others. Data linkage may create a vulnerability if it is not properly configured and may allow unauthorized data access or manipulation.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-14.01 | OT 저장 시스템과 비OT 데이터 소스의 연결 여부 | “linked to non-OT data sources” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-14.02 | 데이터베이스 연결·복제 대상 | “database links allow data from one database” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-14.03 | 관련 연결 설정 | “not properly configured” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-14.04 | 비인가 데이터 접근·조작 제한 여부 | “unauthorized data access or manipulation” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-15 · 악성코드 보호 상태

- 근거 위치: **Table 13, 인쇄 p.173, PDF p.191**
- 활용 구분(연구자 분류): 관측·예방

**Vulnerability — 원문 행 제목**

> Malware protection is not installed or up to date

**Description — 원문 설명 전체**

> The installation of malware (i.e., malicious software) is a common attack. Malware protection software (e.g., antivirus software) should be kept current in a dynamic environment. Outdated malware protection software and definitions leave the system open to malware threats.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-15.01 | 악성코드 보호 소프트웨어 설치 여부 | “Malware protection is not installed” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-15.02 | 소프트웨어 최신 상태 | “Malware protection software” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-15.03 | 탐지 정의의 최신 상태 | “Outdated malware protection software and definitions” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-16 · 악성코드 보호 시험

- 근거 위치: **Table 13, 인쇄 p.173, PDF p.191**
- 활용 구분(연구자 분류): 관리·영향

**Vulnerability — 원문 행 제목**

> Malware protection implemented without sufficient testing

**Description — 원문 설명 전체**

> Malware protection software that is deployed without sufficient testing could impact the normal operation of the OT and block the system from performing necessary control actions.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-16.01 | 악성코드 보호 소프트웨어의 배포 전 시험 여부 | “deployed without sufficient testing” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-16.02 | 정상 운영·필수 제어 동작에 미치는 영향 | “block the system from performing necessary control actions” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-17 · 서비스 거부 영향

- 근거 위치: **Table 13, 인쇄 p.173, PDF p.191**
- 활용 구분(연구자 분류): 영향·취약점 증거

**Vulnerability — 원문 행 제목**

> Denial of service (DoS)

**Description — 원문 설명 전체**

> OT software could be vulnerable to DoS attacks, resulting in the prevention of authorized access to a system resource or delaying system operations and functions.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-17.01 | 인가된 자원 접근 차단·운영 지연에 관한 확인 정보 | “prevention of authorized access to a system resource or delaying system operations and functions” | Description | DoS의 결과 설명이다. 현재 악용 성공이나 운영자가 확인할 공격 시험을 요구하지 않는다. |
| C13-17.02 | 운영 동작·기능 지연에 관한 확인 정보 | “delaying system operations and functions” | Description | 운영 영향 정보이며 그 자체가 VEX 전제조건은 아니다. |

### C13-18 · 침입 탐지·방지

- 근거 위치: **Table 13, 인쇄 p.173, PDF p.191**
- 활용 구분(연구자 분류): 관측·예방

**Vulnerability — 원문 행 제목**

> Intrusion detection and prevention software is not installed

**Description — 원문 설명 전체**

> Incidents can result in the loss of system availability and integrity; the capture, modification, and deletion of data; and the incorrect execution of control commands. IDS/IPS software may stop or prevent various types of attacks, including DoS attacks, and also identify attacked internal hosts, such as those infected with worms. IDS/IPS software must be tested prior to deployment to ensure that it does not compromise normal operation of the OT.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-18.01 | IDS·IPS 설치 여부 | “Intrusion detection and prevention software is not installed” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-18.02 | IDS·IPS의 공격 탐지·방지 기능에 관한 확인 정보 | “IDS/IPS software may stop or prevent various types of attacks” | Description | 원문 may는 효과의 가능성이다. 설치만으로 특정 CVE 예방 효력을 확정하지 않는다. |
| C13-18.03 | 배포 전 정상 운영 영향 시험 여부 | “must be tested prior to deployment” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-19 · 로그 유지

- 근거 위치: **Table 13, 인쇄 p.173, PDF p.191**
- 활용 구분(연구자 분류): 관측·탐지

**Vulnerability — 원문 행 제목**

> Logs are not maintained

**Description — 원문 설명 전체**

> Without proper and accurate logs, it might be impossible to determine what caused a security event to occur and perform adequate forensics.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-19.01 | 로그 유지 여부 | “Logs are not maintained” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-19.02 | 보안 사건 원인 분석에 필요한 로그 확보 여부 | “Without proper and accurate logs” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-20 · IoT·IIoT 설정 관리

- 근거 위치: **Table 13, 인쇄 p.174, PDF p.192**
- 활용 구분(연구자 분류): 조건 후보·관리

**Vulnerability — 원문 행 제목**

> Inadequate security configuration management for IoT and IIoT devices

**Description — 원문 설명 전체**

> Unlike traditional OT devices that support centralized configuration management, many IoT and IIoT devices run proprietary embedded firmware that can only be configured through vendor-specific interfaces, making it difficult to consistently enforce security settings or audit device configurations at scale. These devices are also often deployed with vendor default credentials and unnecessary services enabled that cannot be disabled due to device limitations.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-20.01 | 공급자 전용 설정 인터페이스 사용 여부 | “configured through vendor-specific interfaces” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-20.02 | 설정 일관 적용·감사 가능 여부 | “enforce security settings or audit device configurations at scale” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-20.03 | 기본 인증정보 사용 여부 | “vendor default credentials” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-20.04 | 불필요한 서비스 활성 여부 | “unnecessary services enabled” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-20.05 | 장치 제약으로 서비스 비활성화가 불가능한지 | “cannot be disabled due to device limitations” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C13-21 · OT 클라우드 서비스 통제

- 근거 위치: **Table 13, 인쇄 p.174, PDF p.192**
- 활용 구분(연구자 분류): 조건 후보·관리

**Vulnerability — 원문 행 제목**

> Limited organizational control over cloud platforms and services in OT environments

**Description — 원문 설명 전체**

> Cloud-connected OT systems introduce gaps that organizations have limited visibility into and control over (e.g., specific security settings and configurations within the cloud platform). These gaps increase the risk of misconfigured services, inadequate access controls, and limited visibility that could hinder monitoring and detection, expose operational data, or provide adversaries with unintended access pathways into the OT environment.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C13-21.01 | 조직에서 확인·통제 가능한 클라우드 보안 설정 범위 | “limited visibility into and control over” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-21.02 | 클라우드 접근통제 설정 | “inadequate access controls” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-21.03 | 클라우드 구성·모니터링 가시성 | “limited visibility that could hinder monitoring and detection” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C13-21.04 | 노출·비의도 접근 경로에 관한 확인 정보 | “provide adversaries with unintended access pathways” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C14-01 · 장치 물리 접근

- 근거 위치: **Table 14, 인쇄 p.174, PDF p.192**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Unauthorized personnel have physical access to equipment

**Description — 원문 설명 전체**

> Physical access to OT equipment should be restricted to only the necessary personnel while taking safety requirements into account, such as emergency shutdown or restarts. Improper access to OT equipment can lead to any of the following: • Physical theft of data and hardware • Physical damage to or destruction of data and hardware • Modification of the operational process • Unauthorized changes to the functional environment (e.g., data connections, unauthorized use of removable media, adding/removing resources) • Disconnection of physical data links • Undetectable interception of data (e.g., keystroke, other input logging)

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C14-01.01 | OT 장치에 접근 가능한 인원 | “only the necessary personnel” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C14-01.02 | 필요 인원으로 물리 접근을 제한하는지 | “Physical access to OT equipment should be restricted” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C14-01.03 | 물리 접근을 통한 데이터 연결·이동식 매체 사용·자원 추가/제거 가능성 | “data connections, unauthorized use of removable media, adding/removing resources” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C14-02 · 전자기·전원 변동 보호

- 근거 위치: **Table 14, 인쇄 p.174, PDF p.192**
- 활용 구분(연구자 분류): 환경·영향

**Vulnerability — 원문 행 제목**

> Radio frequency, electromagnetic pulse (EMP), static discharge, brownouts, and voltage spikes

**Description — 원문 설명 전체**

> Some hardware used for OT systems is vulnerable to radio frequency, electromagnetic pulses (EMP), static discharge, brownouts, and voltage spikes. The impacts can range from the temporary disruption of command and control to permanent damage to circuit boards. Proper shielding, grounding, power conditioning, and/or surge suppression is recommended.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C14-02.01 | 무선 주파수·전자기 펄스·정전기 노출 관련 정보 | “radio frequency, electromagnetic pulses (EMP), static discharge” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C14-02.02 | 저전압·전압 급증 관련 정보 | “brownouts, and voltage spikes” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C14-02.03 | 차폐·접지·전원 조정·서지 억제 적용 여부 | “shielding, grounding, power conditioning, and/or surge suppression” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C14-03 · 백업 전원

- 근거 위치: **Table 14, 인쇄 p.174, PDF p.192**
- 활용 구분(연구자 분류): 가용성·복구

**Vulnerability — 원문 행 제목**

> Lack of backup power

**Description — 원문 설명 전체**

> Without backup power to critical assets, a general loss of power will shut down the OT and could create an unsafe situation. Loss of power could also lead to insecure default settings. If the program file or data is stored in volatile memory, the process may not be able to restart after a power outage without appropriate backup power.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C14-03.01 | 중요 자산의 백업 전원 유무 | “Lack of backup power” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C14-03.02 | 전원 손실 시 장치·공정 상태 | “a general loss of power will shut down the OT and could create an unsafe situation” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C14-03.03 | 휘발성 메모리의 프로그램·데이터 손실 가능성 | “program file or data is stored in volatile memory” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C14-03.04 | 전원 손실 시 안전하지 않은 기본 설정 및 재시작 관련 정보 | “insecure default settings” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C14-04 · 환경 제어

- 근거 위치: **Table 14, 인쇄 p.174, PDF p.192**
- 활용 구분(연구자 분류): 환경·영향

**Vulnerability — 원문 행 제목**

> Loss of environmental control

**Description — 원문 설명 전체**

> The loss of environmental control (e.g., temperatures, humidity) could lead to equipment damage, such as processors overheating. Some processors will shut down to protect themselves. Others may continue to operate in a minimal capacity and produce intermittent errors, continually reboot, or become permanently inoperable.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C14-04.01 | 온도·습도 제어 상태 | “temperatures, humidity” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C14-04.02 | 환경 제어 상실 시 정지·오동작·재부팅 관련 정보 | “intermittent errors, continually reboot” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C14-05 · 물리 포트 보호

- 근거 위치: **Table 14, 인쇄 p.174, PDF p.192**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Unsecured physical ports

**Description — 원문 설명 전체**

> Unsecured universal serial bus (USB) and PS/2 ports could allow unauthorized connection of thumb drives or keystroke loggers.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C14-05.01 | USB·PS/2 포트 존재 여부 | “universal serial bus (USB) and PS/2 ports” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C14-05.02 | 해당 포트의 비인가 장치 연결 제한 여부 | “unauthorized connection of thumb drives or keystroke loggers” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C15-01 · 입력·수신 데이터 검증

- 근거 위치: **Table 15, 인쇄 p.175, PDF p.193**
- 활용 구분(연구자 분류): 코드·취약점 증거

**Vulnerability — 원문 행 제목**

> Improper data validation

**Description — 원문 설명 전체**

> OT software may not properly validate user inputs or received data to ensure validity. Invalid data may result in numerous vulnerabilities, including buffer overflows, command injections, cross-site scripting, and path traversals.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C15-01.01 | 사용자 입력 검증에 관한 확인 정보 | “validate user inputs” | Description | 운영자가 추측하지 않는다. 공급자·권고문·분석 근거가 없으면 미확인이다. |
| C15-01.02 | 수신 데이터 검증에 관한 확인 정보 | “or received data” | Description | 설정 관측만으로 코드 검증을 증명하지 않는다. |
| C15-01.03 | 입력 검증 결함에 관한 확인 정보 | “Improper data validation” | Vulnerability | 확인 정보의 자료원은 수집 절차다. 표가 별도의 권고문 증거 필드를 정의한 것은 아니다. |

### C15-02 · 보안 기능 활성

- 근거 위치: **Table 15, 인쇄 p.175, PDF p.193**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Installed security capabilities are not enabled by default

**Description — 원문 설명 전체**

> Security capabilities that were installed with the product are useless if they are not enabled or at least identified as being disabled.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C15-02.01 | 제품에 설치된 보안 기능 | “Security capabilities that were installed with the product” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C15-02.02 | 해당 보안 기능의 활성·비활성 상태 | “not enabled or at least identified as being disabled” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C15-03 · 소프트웨어 인증·권한·접근통제

- 근거 위치: **Table 15, 인쇄 p.175, PDF p.193**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Inadequate authentication, privileges, and access control in software

**Description — 원문 설명 전체**

> Unauthorized access to configuration and programming software could provide the ability to corrupt a device.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C15-03.01 | 설정·프로그래밍 소프트웨어의 인증 설정 | “Inadequate authentication” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C15-03.02 | 해당 소프트웨어의 권한 설정 | “privileges” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C15-03.03 | 해당 소프트웨어의 접근통제 설정 | “access control in software” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C16-01 · 데이터 흐름 통제

- 근거 위치: **Table 16, 인쇄 p.175, PDF p.193**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Data flow controls are not employed

**Description — 원문 설명 전체**

> Data flow controls based on data characteristics are needed to restrict the information that is permitted between systems. These controls can prevent the exfiltration of information and illegal operations.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C16-01.01 | 시스템 간 데이터 흐름 통제 적용 여부 | “Data flow controls based on data characteristics” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-01.02 | 허용되는 정보에 대한 통제 기준 | “information that is permitted between systems” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C16-02 · 방화벽 설치·설정

- 근거 위치: **Table 16, 인쇄 p.175, PDF p.193**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Firewalls are nonexistent or improperly configured

**Description — 원문 설명 전체**

> A lack of properly configured firewalls could permit unnecessary data to pass between networks, such as control and enterprise networks, thus allowing attacks and malware to spread between networks, making sensitive data susceptible to monitoring/eavesdropping, and providing individuals with unauthorized access to systems.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C16-02.01 | 방화벽 존재 여부 | “Firewalls are nonexistent” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-02.02 | 방화벽 설정 | “properly configured firewalls” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-02.03 | 제어망·업무망 등 네트워크 간 불필요한 데이터 통과 허용 여부 | “unnecessary data to pass between networks” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C16-03 · 방화벽·라우터 로그

- 근거 위치: **Table 16, 인쇄 p.175, PDF p.193**
- 활용 구분(연구자 분류): 관측·탐지

**Vulnerability — 원문 행 제목**

> Inadequate firewall and router logs

**Description — 원문 설명 전체**

> Without proper and accurate logs, it might be impossible to determine what caused a security incident to occur.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C16-03.01 | 방화벽 로그 확보 여부 | “firewall and router logs” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-03.02 | 라우터 로그 확보 여부 | “firewall and router logs” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-03.03 | 보안 사건 원인 분석에 필요한 기록의 충분성 | “Without proper and accurate logs” | Description | 충분성 판단 기준은 원문에서 수치로 정의하지 않는다. |

### C16-04 · 평문 통신

- 근거 위치: **Table 16, 인쇄 p.175, PDF p.193**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Standard, well-documented communication protocols are used in plaintext

**Description — 원문 설명 전체**

> Adversaries that can monitor the OT network activity can use a protocol analyzer or other utilities to decode the data transferred by protocols, such as telnet, FTP, HTTP, and NFS. The use of such protocols also makes it easier for adversaries to perform attacks against the OT and manipulate OT network activity.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C16-04.01 | 평문 전송 통신 프로토콜 종류 | “telnet, FTP, HTTP, and NFS” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-04.02 | 평문 전송 여부 | “protocols are used in plaintext” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C16-05 · 사용자·데이터·장치 인증

- 근거 위치: **Table 16, 인쇄 p.175, PDF p.193**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Authentication of users, data, or devices is substandard or nonexistent

**Description — 원문 설명 전체**

> Many OT protocols have no authentication at any level. Without authentication, there is the potential to replay, modify, or spoof data or devices, such as sensors and user identities.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C16-05.01 | 사용자 인증 적용 여부 | “Authentication of users” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-05.02 | 데이터 인증 적용 여부 | “data, or devices” | Vulnerability | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-05.03 | 장치 인증 적용 여부 | “or devices” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C16-06 · OT 프로토콜 보안 기능

- 근거 위치: **Table 16, 인쇄 p.175, PDF p.193**
- 활용 구분(연구자 분류): 조건 후보·구현 증거

**Vulnerability — 원문 행 제목**

> Use of unsecure OT protocols

**Description — 원문 설명 전체**

> OT protocols often have few or no security capabilities, such as authentication and encryption, to protect data from unauthorized access or tampering. The incorrect implementation of the protocols can also lead to additional vulnerabilities.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C16-06.01 | OT 프로토콜의 인증 보안 기능 | “authentication and encryption” | Description | 원문은 보안 기능이 적거나 없음을 설명한다. 지원·구성·실제 효과는 같은 상태가 아니다. |
| C16-06.02 | OT 프로토콜의 암호화 보안 기능 | “authentication and encryption” | Description | 특정 암호 방식·강도·필수 지원 목록은 이 행만으로 생성하지 않는다. |
| C16-06.03 | 프로토콜 구현 결함에 관한 확인 정보 | “incorrect implementation of the protocols” | Description | 구현 결함은 코드·공급자 분석 등 근거 없이는 미확인이다. |

### C16-07 · 통신 무결성

- 근거 위치: **Table 16, 인쇄 p.175, PDF p.193**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Lack of integrity checking for communications

**Description — 원문 설명 전체**

> Integrity checks are not built into most OT protocols, so adversaries could manipulate communications undetected. To ensure integrity, the OT can use lower-layer protocols (e.g., IPsec) that offer data integrity protection when traversing untrusted physical media.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C16-07.01 | 통신 무결성 검증 적용 여부 | “Integrity checks” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-07.02 | 하위 계층 프로토콜 등을 통한 무결성 보호 여부 | “lower-layer protocols (e.g., IPsec) that offer data integrity protection” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C16-08 · 무선 상호 인증

- 근거 위치: **Table 16, 인쇄 p.175, PDF p.193**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Inadequate authentication between wireless clients and access points

**Description — 원문 설명 전체**

> Strong mutual authentication between wireless clients and access points is needed to ensure that legitimate OT clients do not connect to a rogue access point deployed by an adversary and that adversary clients do not connect to any of the OT wireless networks.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C16-08.01 | 무선 클라이언트·액세스 포인트 구성 | “wireless clients and access points” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-08.02 | 클라이언트와 액세스 포인트 간 상호 인증 적용 여부 | “Strong mutual authentication” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C16-09 · 무선 데이터 보호

- 근거 위치: **Table 16, 인쇄 p.175, PDF p.193**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Inadequate data protection between wireless clients and access points

**Description — 원문 설명 전체**

> Sensitive data between wireless clients and access points should be protected using strong encryption to ensure that adversaries cannot gain unauthorized access to the unencrypted data.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C16-09.01 | 무선 클라이언트와 액세스 포인트 사이의 민감정보 전송 여부 | “Sensitive data between wireless clients and access points” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-09.02 | 해당 통신의 암호화 적용 여부 | “protected using strong encryption” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C16-10 · OT·클라우드 통신

- 근거 위치: **Table 16, 인쇄 p.176, PDF p.194**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Insecure or unnecessary communications between OT systems and cloud platforms

**Description — 원문 설명 전체**

> Communications between OT systems and cloud platforms may lack adequate encryption, authentication, or integrity verification, leaving operational data susceptible to interception and unauthorized access. Unnecessary outbound connections to external domains initiated by cloud platform agents or services may not be accounted for in existing firewall rules or network monitoring configurations, creating uncontrolled pathways outside the OT environment.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C16-10.01 | OT·클라우드 통신의 암호화 적용 여부 | “Communications between OT systems and cloud platforms may lack adequate encryption” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-10.02 | 해당 통신의 인증 적용 여부 | “authentication” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-10.03 | 해당 통신의 무결성 검증 적용 여부 | “integrity verification” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-10.04 | 클라우드 에이전트·서비스의 외부 도메인 아웃바운드 연결 | “outbound connections to external domains initiated by cloud platform agents or services” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-10.05 | 해당 연결의 방화벽·모니터링 반영 여부 | “existing firewall rules or network monitoring configurations” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C16-11 · 제3자 통신 의존

- 근거 위치: **Table 16, 인쇄 p.176, PDF p.194**
- 활용 구분(연구자 분류): 의존·영향

**Vulnerability — 원문 행 제목**

> Overreliance on third-party communication infrastructure for OT connectivity

**Description — 원문 설명 전체**

> Many OT environments rely on third-party carrier networks such as cellular and private LTE for communications between remote sites and central control systems. Third-party communication links are subject to outages, degraded performance, and compromise events outside the organization's control. Organizations that have not accounted for the unavailability or compromise of third-party communication links may find themselves unable to monitor or control remote sites during an incident.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C16-11.01 | 원격 사이트·중앙 제어 간 제3자 통신망 의존 여부 | “rely on third-party carrier networks” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-11.02 | 사용 중인 셀룰러·사설 LTE 등 통신 연결 | “cellular and private LTE” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C16-11.03 | 통신망 이용 불가·침해 시 원격 감시·제어에 관한 고려 여부 | “unavailability or compromise of third-party communication links” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C17-01 · 센서·최종 제어요소 물리 접근

- 근거 위치: **Table 17, 인쇄 p.176, PDF p.194**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Unauthorized physical access to sensors or final elements

**Description — 원문 설명 전체**

> Physical access to sensors and final elements allows for direct manipulation of the physical process. Many devices are configured on a fieldbus such that physical access to the sensor network allows for manipulation of controlling parameters. Physical access to the whole loop should be managed to prevent incidents.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C17-01.01 | 센서·최종 제어요소의 물리 접근 제한 | “Physical access to sensors and final elements” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C17-01.02 | 센서 네트워크·필드버스 물리 접근 가능성 | “physical access to the sensor network” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C17-01.03 | 물리 접근 시 제어 파라미터 조작 가능성 | “manipulation of controlling parameters” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C17-01.04 | 제어 루프 전체의 물리 접근 관리 여부 | “Physical access to the whole loop should be managed” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

### C17-02 · 센서·최종 제어요소 무선 설정

- 근거 위치: **Table 17, 인쇄 p.176, PDF p.194**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Unauthorized wireless access to sensors or final elements

**Description — 원문 설명 전체**

> Wireless access to sensors and final elements allows for direct manipulation of the physical process. Many smart devices allow for wireless configuration (e.g., Bluetooth, Wi-Fi, WirelessHART). Wireless access should be securely configured or disabled using hardware write-protect where possible to prevent unauthorized modification of the sensors and final elements that are connected to both the physical process and the OT environment.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C17-02.01 | 무선 설정 기능 존재 여부 | “wireless configuration” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C17-02.02 | Bluetooth·Wi-Fi·WirelessHART 등 사용 기술 | “Bluetooth, Wi-Fi, WirelessHART” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C17-02.03 | 무선 접근 보안 설정 | “Wireless access should be securely configured” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C17-02.04 | 하드웨어 쓰기 보호를 통한 무선 설정 제한 여부 | “disabled using hardware write-protect” | Description | 센서·최종 제어요소의 무선 설정 보호에 한정한다. 일반 PLC 키 스위치로 확대 금지. |

### C17-03 · 자산 관리 시스템 분리·변경 능력

- 근거 위치: **Table 17, 인쇄 p.176, PDF p.194**
- 활용 구분(연구자 분류): 조건 후보

**Vulnerability — 원문 행 제목**

> Inappropriate segmentation of the asset management system

**Description — 원문 설명 전체**

> Most architectures are designed for PLCs, RTUs, DCS, and SCADA controllers to manipulate the process and for asset management systems to monitor the assets connected to the controllers. Many asset management systems also have the technical ability to modify the configuration of sensors and final elements, although modification may not be their primary function. The asset management system should be controlled appropriately based on its ability (or lack of ability) to manipulate the process.

| 세부 ID | 세부 수집정보 | 영어 원문 발췌 | 원문 열 | 해석상 주의 |
|---|---|---|---|---|
| C17-03.01 | 자산 관리 시스템과 제어기에 연결된 자산의 감시 관계 | “asset management systems to monitor the assets connected to the controllers” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C17-03.02 | 센서·최종 제어요소 설정 변경 능력 유무 | “ability to modify the configuration of sensors and final elements” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |
| C17-03.03 | 해당 능력에 맞는 자산 관리 시스템 통제·분리 상태 | “controlled appropriately based on its ability (or lack of ability) to manipulate the process” | Description | 원문에 있는 개념을 수집형으로 재서술. 값·대상·적용성은 별도 확인하며 현재 상태는 추정하지 않음. |

## 4. v0.4 추가 변경

- 54개 원문 행 각각에 영어 Description 전체를 추가했다.
- 167개 세부 항목 각각에 원문 발췌·열·페이지·해석상의 주의를 연결했다.
- 직접적인 상태로 단정하기 어려운 일부 문구를 원문 개념/확인 정보 수준으로 좁혔다. 새로운 세부 항목은 추가하지 않았다.

## 5. 운영자에게 확인할 수 없는 항목 처리

- C15-01 입력 검증과 C16-06 프로토콜 구현 결함은 운영자에게 코드 분석 결과를 추측하게 묻지 않는다. 권고문·기존 분석·공급자 확인이 없으면 미확인이다.
- C13-17 DoS는 취약점/영향 설명이다. 범용 request_limit·rate_limit·DoS_threshold 필드를 새로 만들지 않는다.
- C12-09의 암호 전환과 C12-10/11의 AI 항목은 해당 기술을 사용하고 관련 CVE/평가 목적이 있을 때만 검토한다. 일반 자산에 일괄 요구하지 않는다.
- 로그·백업·시험·환경 제어 등은 관측·운영·복구 정보이며 그 존재가 CVE의 악용을 차단한다는 뜻이 아니다.
- 기본 비밀번호 사용 여부만 수집한다. 비밀번호·키·토큰 원문을 저장하지 않는다. 평문 민감정보 항목도 내용 자체가 아닌 존재·보호 상태만 기록한다.

## 6. 18개 자산 유형과의 연결

여섯 표에는 18개 MITRE 자산 유형별 필수 항목 대응표가 없다. 아래 대응은 적용 대상을 찾기 위한 연구용 후보 선택이며 NIST의 공식 매핑이 아니다. 기능 지원·노출·권한 상태를 유형만으로 추정하지 않는다. 고정 4개 질문 묶음은 폐기하고 행 ID 기반 선택으로 바꾼다.

공통 검토 후보(모든 유형에서 적용성부터 확인): C13-01, C13-02, C13-07, C13-08, C13-11, C13-13, C15-02, C15-03, C16-01, C16-02, C16-05, C16-06, C16-07, C14-01, C14-05.

C12-01~11 및 기타 관리·환경·관측 항목은 자산별로 반복 질문하기보다 해당 사이트·시스템 범위에서 기존 관측을 재사용한다. 공통/추가 후보 밖에 있더라도 표 안의 관련 항목은 선택할 수 있다.

| MITRE ID | 자산 유형 | 유형별 추가 검토 후보 |
|---|---|---|
| A0001 | Workstation (워크스테이션) | C13-10 휴대 장치의 민감정보 보호; C13-15 악성코드 보호 상태; C13-16 악성코드 보호 시험 |
| A0002 | Human-Machine Interface (HMI) (HMI) | C13-15 악성코드 보호 상태; C13-18 침입 탐지·방지 |
| A0003 | Programmable Logic Controller (PLC) (PLC) | C17-03 자산 관리 시스템 분리·변경 능력 |
| A0004 | Remote Terminal Unit (RTU) (RTU) | C16-08 무선 상호 인증; C16-09 무선 데이터 보호; C16-11 제3자 통신 의존 |
| A0005 | Intelligent Electronic Device (IED) (IED) | C17-01 센서·최종 제어요소 물리 접근; C17-02 센서·최종 제어요소 무선 설정 |
| A0006 | Data Historian (데이터 히스토리언) | C13-14 외부 데이터 연결; C12-05 비제어망 서비스 의존; C16-10 OT·클라우드 통신 |
| A0007 | Control Server (제어 서버) | C12-05 비제어망 서비스 의존; C13-14 외부 데이터 연결; C17-03 자산 관리 시스템 분리·변경 능력 |
| A0008 | Application Server (애플리케이션 서버) | C13-14 외부 데이터 연결; C12-08 클라우드 연결 구조; C16-10 OT·클라우드 통신 |
| A0009 | Data Gateway (데이터 게이트웨이) | C16-04 평문 통신; C16-10 OT·클라우드 통신; C16-11 제3자 통신 의존 |
| A0010 | Safety Controller (안전 제어기) | C17-03 자산 관리 시스템 분리·변경 능력 |
| A0011 | Virtual Private Network (VPN) Server (VPN 서버) | C16-04 평문 통신; C16-08 무선 상호 인증; C16-09 무선 데이터 보호 |
| A0012 | Jump Host (점프 호스트) | C13-15 악성코드 보호 상태; C13-18 침입 탐지·방지 |
| A0013 | Field I/O (현장 입출력 장치) | C17-01 센서·최종 제어요소 물리 접근; C17-02 센서·최종 제어요소 무선 설정; C17-03 자산 관리 시스템 분리·변경 능력 |
| A0014 | Routers (라우터) | C16-03 방화벽·라우터 로그; C16-11 제3자 통신 의존 |
| A0015 | Switch (스위치) | C16-03 방화벽·라우터 로그 |
| A0016 | Firewall (방화벽) | C16-03 방화벽·라우터 로그; C13-18 침입 탐지·방지 |
| A0017 | Distributed Control System (DCS) Controller (DCS 제어기) | C12-05 비제어망 서비스 의존; C17-03 자산 관리 시스템 분리·변경 능력 |
| A0018 | Programmable Automation Controller (PAC) (PAC) | C17-03 자산 관리 시스템 분리·변경 능력 |

## 7. 응답 저장 형식

각 C항목의 세부정보 번호와 실제 값·대상·증거를 연결한다. 세부정보 번호는 위 표의 .01, .02 등에 대응하는 이 버전의 연구용 인덱스다. known/unknown/not_applicable/conflicting과 in_scope/out_of_scope는 시스템이 설계한 메타데이터이며 NIST 원문 상태값이 아니다.

```json
{
  "profile_version": "0.4",
  "asset_id": "EXAMPLE-01",
  "asset_type_ids": [
    "A0003"
  ],
  "observations": [
    {
      "item_id": "C13-08",
      "detail_index": 2,
      "subject": "CVE에서 지목한 해당 서비스",
      "status": "unknown",
      "value": null,
      "evidence_refs": [],
      "observed_at": null
    }
  ],
  "unmapped_conditions": [],
  "vex_status": null
}
```

## 8. CVE 조건 연결 및 스키마 제한

1. CVE·ICSA·제조사 권고문에서 제품별 필수 조건과 근거 문장을 추출한다. 원문에 없는 조건을 NIST 목록에서 임의 추가하지 않는다.
2. 해당 조건과 의미·대상·범위가 일치하는 C항목/세부정보를 선택한다.
3. 자산 유형 후보와 실제 제품 구성으로 적용성을 확인하고, 알려진 관측을 재사용한 뒤 필요한 정보만 요청한다.
4. 여섯 표에 대응 내용이 없는 경우 out_of_scope로 기록하고 자동 속성 추가·강제 매핑을 금지한다.
5. 필수 조건이 미확인·범위 밖이면 unknown으로 남긴다. 다른 확정 근거로 결정할 수 없는 경우 under_investigation으로 보류한다.
6. 예방 기능·암호화·인증 존재만으로 not_affected를 출력하지 않는다. 해당 CVE에 대한 효과·근거·시나리오 범위를 따로 검토한다.

표에 직접 제시되지 않은 일반 운영 모드·키 스위치·실행 허용목록·MFA/세션 시간 제한 같은 독립 필드는 만들지 않는다. 센서·최종 제어요소의 하드웨어 쓰기 보호는 C17-02에 직접 근거가 있으므로 보존한다. 동작별 인증 요구·비인증 허용 동작·접근 경로를 임의의 독립 필드로 확장하던 O구조는 더 이상 사용하지 않는다. 기존 인증/접근통제 원문 항목 안에서 확인 가능한 값으로만 기록한다.

## 9. v0.2/v0.3에서의 변경

- 16개 O속성 통합 사전과 그 필드 기반 72개 질문 묶음을 폐기하고 원문 행 54개와 행별 세부 목록으로 교체했다.
- 원문 행의 영어 제목·표·페이지를 전부 보존했다. 이전 27개 선택 근거 레지스트리는 전체 행 목록으로 대체했다.
- 과거에 제외했던 환경·로그·백업·입력 검증 항목도 원문 목록에 복원하되 직접 VEX 입력으로 적합한지 구분했다.
- 18개 자산 유형은 유지했으나 유형별 후보 선택과 원문 행을 구분했다. 실제 제품 지원을 단정하지 않는다.
- 실제 자산 관측값은 없다. 기존 실제 관측을 이관할 경우 O필드 원본은 legacy로 보존하고, C행·세부정보에 의미가 일치하는 경우에만 검토 후 연결한다.

## 10. 검증 상태

이번 v0.4에서는 54개 행의 제목·설명 원문, 167개 발췌의 실제 원문 포함 여부, 세부 항목과 발췌의 일대일 대응을 검사했다. 원문은 PDF 표의 셀에서 추출했으며 줄바꿈·공백만 정리했다. 문맥 타당성·자산 운영 정보 도출 타당성에 대한 독립 전문가 검증은 별도다.

표별 행 개수, ID 유일성, 자산 후보의 참조 유효성, 예시 JSON, 세부정보 항목 수를 확인한다. 전문가에 의한 도출 타당성·정답 평가나 실제 VEX 성능 측정은 수행하지 않았다. NIST 원문은 완전한 취약점·조건 목록이 아니라고 설명하므로 본 목록도 모든 CVE를 포괄한다고 주장하지 않는다.

이 산출물은 프로파일 명세 수정이다. 별도 실행 코드 저장소가 제공되지 않아 애플리케이션 구현·배포 변경은 포함하지 않는다.

