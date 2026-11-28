# 자산 운영 정보 필드의 가이드 근거

확인일: 2026-11-16. 아래 문서는 **무엇을 조사하고 기록할지** 참고하는 근거다. 특정 CVE의 악용조건이나 비영향의 근거를 대신하지 않는다. 구체 질문·스키마·조건 매핑은 프로젝트 설계다.

| 조사 그룹 | 가이드의 관련 위치 | 이 프로젝트의 사용 범위 |
| --- | --- | --- |
| 제품·역할·주소·서비스·계정 현황 | CISA 공동 자산관리 가이드의 자산 식별 절차 및 부록 A | 원래 제품 참조와 실제 자산 현황을 대조할 자료 선정 |
| 접근 규칙·인증·역할·물리 접근 | NIST SP 800-82r3 §6.2.1 | 인터페이스·출발지·권한별 조사 질문 |
| 불필요 기능·서비스 | NIST §6.2.4.1 | 기능의 실제 활성 상태와 제품별 설정 의미 조사 |
| 설정 기준·변경 기록 | NIST §6.2.4.2 | 평가 스냅샷과 설정 변경에 따른 재평가 범위 |
| 정비 장비·예외 경로 | NIST §6.2.5 | 정상 운전과 정비 접근을 함께 조사 |
| 이동식 매체·파일 반입 | NIST §6.2.7 | 외부 입력의 실제 처리 경로 조사 |
| VPN·점프호스트·원격 접속 | NIST §6.2.10 | 원격 경로와 관련 통제·예외 기록 |

공동 가이드는 자산관리의 범위·조직 역할·검증·갱신 절차와 자산 속성 수집을 다룬다. 자산 유형별로 동일한 CVE 전제를 공유한다고 규정하지 않는다. NIST의 기능 축소·접근 통제 권고도 해당 CVE의 필수조건을 뜻하지 않는다. CVE 조건은 별도의 ICSA-CVE 원문 인용과 자동 의미 검증이 필요하다.

출처:

- [CISA 원래 PDF 주소](https://www.cisa.gov/sites/default/files/2025-08/joint-guide-foundations-for-OT-cybersecurity-asset-inventory-guidance_508c.pdf). 이번 도구 접근은 HTTP 403이어서 [공동 발행 기관 EPA의 동일 제목 가이드](https://www.epa.gov/system/files/documents/2025-09/joint-guide-foundations-for-ot-cybersecurity-asset-inventory-guidance_508c.pdf)를 확인했다. 두 URL의 파일이 바이트 단위로 같다는 주장은 하지 않는다.
- [NIST SP 800-82r3 원문](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf). 문서의 인쇄 페이지 기준 접근 통제 97쪽, 최소 기능·설정 관리 111쪽, 정비 117쪽, 매체 119쪽, 원격 접근 122쪽이다.
- MITRE 자산 ID·이름은 프로젝트의 고정된 `data/standards/ics-attack-20.1.json`에서 읽는다. 자산 프로필의 추가 항목과 질문은 공식 MITRE 필드 표준으로 표현하지 않는다.
