"""Source-linked operational review routing; no class or keyword clears a CVE."""
import hashlib
import re

SCHEMA = 'ics-operational-review/2'


def q(key, text, field, records, answer_type='text'):
    return {'key': key, 'question': text, 'fact_field': field,
            'answer_type': answer_type, 'required_records': records,
            'unknown_allowed': True, 'can_refute': False}


COMMON = [
    q('identity', '대상 자산 ID, 정확한 제품명·하드웨어·설치 빌드와 이를 확인한 기록은 무엇인가?',
      'installed_identity', ['관리화면·설치 기록', '제조사 제품·빌드 식별 자료']),
    q('scope', '어떤 구성 기준선과 정상·정비·시운전 모드를 평가하며, 원격정비·대체 인터페이스도 범위에 포함했는가?',
      'assessment_scope', ['구성 백업', '모드별 절차', '원격정비·이중화 구성']),
    q('entry', '인용된 기능이 실제로 처리하는 입력·접근 인터페이스는 무엇이며, 원문에 없는 경로는 미확인으로 남겼는가?',
      'entry_interface', ['CVE별 상세 설명', '설치 기능·입력 경로 기록']),
    q('supplier', '이 CVE에 대한 제조사 영향 제품·빌드 및 수정·비영향 설명과 설치 기록을 연결할 수 있는가?',
      'supplier_applicability', ['CVE별 제품·빌드 영향 근거', '수정 매핑', '실제 설치 기록']),
    q('controls', '확인된 입력·접근 경로에 어떤 보호조치가 적용되며 예외·우회·일시 연결은 무엇인가?',
      'operational_controls', ['ACL·접근 정책', '보호 설정', '정비 예외와 검증 기록']),
]


def flow(key, name, patterns, questions, premise, refutation, trap):
    return {'id': key, 'name': name, 'patterns': patterns, 'questions': questions,
            'reviewed_prerequisite_template': premise,
            'nonimpact_evidence_template': refutation,
            'invalid_shortcut': trap,
            'decision_policy': 'reviewed_scoped_evidence_v2',
            'condition_fields_to_review': [item['fact_field'] for item in questions],
            'decision_checks': [
                {'check': 'installed_fix', 'requires': ['supplier_fix_mapping', 'installation_record'], 'status': 'fixed'},
                {'check': 'reviewed_product_nonimpact', 'requires': ['scoped supplier_product_status or reviewed_product_analysis', refutation], 'status': 'not_affected'},
                {'check': 'all_alternative_routes_structurally_refuted', 'requires': ['reviewed_complete_route_analysis', 'reviewed_cve_prerequisite', 'reviewed_nonexecution_analysis'], 'status': 'not_affected'},
                {'check': 'reviewed_product_affected', 'requires': ['scoped supplier_product_status or reviewed_product_analysis', 'action_statement'], 'status': 'affected'},
                {'check': 'only_answers_or_external_controls', 'status': 'under_investigation', 'operational_state': 'separately assessed'},
            ],
            'automatic_prerequisite_formula': None, 'human_semantic_review_required': True}


FLOWS = [
    flow('web_interface', '웹 화면과 API 요청 처리', [
        r'\b(?:web[- ](?:based[- ]?)?(?:management|admin(?:istration|istrative)?|interface|server|application|console|UI)|HTTP[S]?\s+(?:request|server|header)|REST(?:ful)? API|SOAP (?:API|request)|CGI(?: script)?|websocket|cross.site scripting|cross.site request forgery|SSRF|server.side request forgery|request smuggling)\b',
        r'\b(?:XSS|CSRF|web interface|web-based interface|web application|web portal)\b'], [
        q('endpoints', '원문 근거에 대응하는 웹 화면·URL·API와 실제 활성·노출 상태는 무엇인가?', 'web_endpoints', ['웹 기능 구성', '엔드포인트·포트 목록']),
        q('sessions', '해당 요청을 보낼 수 있는 주체, 로그인·역할·세션 조건과 운영자의 브라우저 작업은 무엇인가?', 'web_sessions', ['역할표', '세션 설정', '화면 이용 절차']),
        q('origins', '입력 저장·표시 위치, 요청 출처와 서버가 연결할 수 있는 목적지는 어디인가?', 'web_data_paths', ['입력·화면 경로', '서버 송신 정책', '프록시 구성'])],
        'CVE별 영향 엔드포인트와 요청·세션·사용자 동작 조건을 확인한다. SSRF·CSRF·XSS는 개별 세부 조건을 검토한다.',
        '공급자 또는 검토된 제품 분석으로 해당 빌드의 영향 웹 기능·코드 경로 부재 등을 입증한다.',
        '웹 로그인·WAF·HTTPS 사용만으로 인증 우회·스크립트 주입의 비영향을 선언하지 않는다.'),
    flow('client_content', '클라이언트와 임베디드 콘텐츠 처리', [
        r'\b(?:ActiveX|COM (?:component|control)|web browser|HTML (?:render|content|page)|browser (?:engine|renderer)|email (?:attachment|preview)|e-mail (?:attachment|preview))\b'], [
        q('client', '영향 클라이언트·브라우저·COM·ActiveX 구성요소는 어느 호스트와 프로그램에서 로드되는가?', 'client_components', ['설치·구성요소 기록', '실행 프로그램·연결 관계']),
        q('content', '콘텐츠·페이지·객체 호출 입력은 어디에서 들어오며 자동 처리·미리보기·사용자 열람 경로가 있는가?', 'client_content_paths', ['콘텐츠 유입 경로', '미리보기·브라우저·애플리케이션 설정']),
        q('identity', '영향 구성요소를 호출하는 사용자·프로세스와 격리·권한 설정은 무엇인가?', 'client_execution', ['실행 계정·권한', '격리·정책', '호출 프로그램 기록'])],
        'CVE별 클라이언트·구성요소와 입력·호출 방식을 확인하며 웹 페이지 사용을 자동 전제하지 않는다.',
        '영향 구성요소의 빌드별 부재·수정 또는 모든 로딩 경로의 비실행 근거를 확보한다.',
        '기본 브라우저 미사용만으로 다른 프로그램의 임베디드 엔진·COM 호출이 없다고 단정하지 않는다.'),
    flow('file_ingest', '외부 파일과 프로젝트 가져오기', [
        r'\b(?:opening|opens?|loading|loads?|importing|imports?|parsing|parses?|processing)\s+(?:a |an |the )?(?:specially[- ]crafted |malicious |crafted |untrusted )?(?:[\w.-]+\s+){0,3}(?:file|project|document|image|archive)\b',
        r'\b(?:crafted|malicious|malformed)\s+(?:[\w.-]+\s+){0,3}(?:files?|projects?|documents?|images?|archives?)\b',
        r'\b(?:file (?:upload|import|parser)|project file|document parser|archive extraction)\b'], [
        q('formats', '언급된 파일 형식·프로젝트를 처리하는 제품 기능과 자동·수동 처리 방식은 무엇인가?', 'file_processing', ['파일 연결·가져오기 구성', '영향 기능 명세']),
        q('ingress', '파일은 USB·공유폴더·메일·공급자 정비 경로 중 어디에서 들어오며 누가 변경할 수 있는가?', 'file_origins', ['반입 절차', '공유폴더 권한', '정비자료 전달 기록']),
        q('action', '누가 어느 모드에서 파일을 열고, 미리보기·백그라운드 처리나 다른 파서 경로도 있는가?', 'file_actions', ['작업 절차', '자동 처리 설정', '모드별 이용 기록'])],
        '해당 파일 형식 처리와 원문에 명시된 사용자 작업·자동 처리 경로를 확인한다.',
        '영향 파서·형식이 정확한 빌드에 포함되지 않는다는 공급자 근거와 설치 범위를 연결한다.',
        '평소 파일을 열지 않음·검사 실패·백신 사용은 코드 경로 부재의 증명이 아니다.'),
    flow('artifact_loading', '업데이트와 모듈 로딩', [
        r'\b(?:firmware (?:update|upgrade|image)|software update|update (?:package|image|mechanism|process)|bootloader|boot loader|secure boot|DLL (?:hijacking|loading|search)|dynamic library|plugin (?:load|install)|plug-in (?:load|install)|untrusted search path|uncontrolled search path)\b'], [
        q('artifacts', '문제의 펌웨어·업데이트·DLL·플러그인은 어떤 기능에서 어떤 경로로 로드되는가?', 'artifact_loader', ['업데이트·로더 구성', '검색 경로', '실제 모듈 목록']),
        q('writers', '누가 패키지·검색 경로를 변경할 수 있고 어떤 승인·서명·무결성 검사가 수행되는가?', 'artifact_trust', ['배포 절차', '경로 ACL', '서명 검증 구성']),
        q('modes', '정비·복구·부팅 모드에 별도 로딩 경로나 검증 예외가 있는가?', 'artifact_modes', ['복구 절차', '부팅·정비 구성'])],
        'CVE별 로딩 단계·쓰기 권한·서명 우회 조건을 확인한다.',
        '검증된 수정 로더 설치 또는 해당 로더·취약 검증 경로 부재에 대한 제품 근거를 확보한다.',
        '서명 기능이 켜져 있다는 사실만으로 서명 검증 우회 취약점을 해제하지 않는다.'),
    flow('transit_trust', '통신 도청과 변조 및 상대 검증', [
        r'\b(?:man.in.the.middle|on.path attacker|eavesdrop\w*|intercept\w*|cleartext transmission|transmi\w*.{0,45}(?:cleartext|plaintext|unencrypted)|(?:cleartext|plaintext|unencrypted).{0,35}(?:transmission|traffic|communication)|certificate validation|certificate verification|TLS handshake|SSL handshake|SSH insertion attack|replay attack)\b'], [
        q('segments', '영향 통신의 송수신 주체와 경유 구간, 동일 구간에 연결 가능한 주체는 누구인가?', 'communication_segments', ['통신 구성도', '원격 연결 경로', '구역·스위치 정책']),
        q('trust', '프로토콜 버전·암호군·상대 인증·인증서 검증·재전송 방지 설정은 무엇인가?', 'communication_trust', ['프로토콜 설정', '신뢰 저장소', '키·인증서 교체 기록']),
        q('fallback', '평문·하위 버전·검증 생략 경로가 정비 또는 장애 시에도 존재하는가?', 'communication_fallback', ['대체 경로와 호환 설정', '장애·정비 절차'])],
        '수신 입력 주입과 수동 도청을 구분하고 CVE별 관측·변조·재전송 조건을 검토한다.',
        '영향 프로토콜·암호 구현의 부재나 공급자 확인 수정 등 제품 수준 근거를 확보한다.',
        '패킷 송신 불가·쓰기 불가만으로 도청 취약점의 비영향을 선언하지 않는다.'),
    flow('account_access', '계정과 자격증명 사용 경로', [
        r'\b(?:hard[- ]?coded.{0,30}(?:passwords?|credentials?|keys?)|default.{0,20}(?:passwords?|credentials?|accounts?)|password reset|password recover\w*|authentication bypass|missing authentication|no authentication|without authentication|does not require authentication|do not require authentication|brute.force|credentials?.{0,20}(?:leak|expos|disclos))\b'], [
        q('accounts', '언급된 계정·자격증명·인증 경로는 어떤 서비스와 역할에서 사용되는가?', 'identity_usage', ['계정 목록과 역할', '인증 구성', 'CVE별 영향 인터페이스']),
        q('replacement', '기본·내장·복구 계정과 키를 변경·비활성화할 수 있으며 실제 변경 기록이 있는가?', 'identity_changes', ['계정·키 변경 기록', '제조사 변경 가능 범위']),
        q('alternatives', '동일 권한을 얻는 대체 인터페이스·복구 경로·무인 서비스 계정은 무엇인가?', 'identity_alternatives', ['복구 절차', '서비스 계정', '대체 인증 경로'])],
        '해당 자격증명·우회 경로와 실제 보호 대상 작업을 연결한다.',
        '영향 계정·인증 구현의 빌드별 부재 또는 취약 기전 제거를 공급자·제품 분석으로 입증한다.',
        '강한 사용자 암호·로그인 활성만으로 내장 암호나 인증 우회를 부정하지 않는다.'),
    flow('stored_resource', '파일과 저장 데이터 접근', [
        r'\b(?:directory traversal|path traversal|symbolic link|symlink|file permissions|directory permissions|file ownership|world.writable|world.readable|log file|backup file|configuration file|insecure temporary file)\b',
        r'\b(?:read|write|overwrite|delete|access)\s+(?:[\w.-]+\s+){0,3}(?:arbitrary|sensitive)\s+(?:files?|directories|data)\b'], [
        q('resources', '영향 파일·디렉터리·로그·백업·객체와 이를 다루는 인터페이스는 무엇인가?', 'stored_resources', ['대상 경로·객체 목록', '공유·백업 설정']),
        q('permissions', '운영 계정·서비스·원격 사용자의 읽기·쓰기·소유 권한은 어떻게 설정되어 있는가?', 'resource_permissions', ['ACL·소유권', '서비스 계정 권한']),
        q('copies', '임시파일·백업·진단자료·공유 경로에도 같은 데이터나 대체 접근이 존재하는가?', 'resource_copies', ['백업·임시파일 정책', '진단자료 배포 기록'])],
        '원문에서 영향 객체와 읽기·쓰기·경로 지정 조건을 구분한다.',
        '정확한 제품에서 영향 저장 기전·데이터·코드 경로가 없다는 범위 있는 분석이 필요하다.',
        '화면 접근 차단만으로 백업·로그·직접 파일 접근까지 차단됐다고 추정하지 않는다.'),
    flow('local_host', '호스트 로컬 실행과 권한', [
        r'\b(?:local (?:attackers?|users?|access|privileges?|adversar(?:y|ies))|locally (?:authenticated|logged)|unquoted service path|setuid|sudo|kernel drivers?|device drivers?|local process(?:es)?)\b'], [
        q('entry', '영향 호스트에 로그인·프로세스 실행·원격 셸을 얻을 수 있는 계정과 경로는 무엇인가?', 'local_entry', ['로그인·원격 셸 정책', '실행 허용 정책']),
        q('privileges', '영향 서비스·드라이버·명령은 어떤 계정 권한으로 실행되는가?', 'local_privileges', ['서비스·드라이버 구성', '권한과 토큰 기록']),
        q('operations', '정비 프로그램·예약 작업·다른 서비스가 같은 로컬 인터페이스를 호출하는가?', 'local_callers', ['정비·예약 작업', '서비스 의존관계'])],
        '실제 로컬 실행 능력과 원문에 필요한 권한 수준을 확인한다.',
        '영향 인터페이스·드라이버·기능이 정확한 빌드에서 부재함을 제품 근거로 입증한다.',
        '관리자 계정 미사용은 로컬 프로세스·서비스 경로 부재를 뜻하지 않는다.'),
    flow('physical_maintenance', '물리 접근과 정비 포트', [
        r'\b(?:physical access|physically access|JTAG|UART|debug port|serial console|USB (?:port|device|drive)|removable media)\b'], [
        q('ports', '영향 디버그·시리얼·USB·정비 포트가 실제 하드웨어에 존재하며 어느 위치에 있는가?', 'physical_interfaces', ['하드웨어 리비전·포트 목록', '현장 확인 기록']),
        q('access', '운영·정비·협력업체 중 누가 장비·포트·반입 매체에 접근하는가?', 'physical_actors', ['출입·정비 기록', '매체 반입 절차']),
        q('debug', '부트·복구·정비모드에서 디버그·인증 상태가 바뀌는가?', 'physical_modes', ['디버그·부팅 구성', '복구 절차'])],
        '특정 하드웨어 포트·접근·모드 조건을 CVE 근거로 확인한다.',
        '해당 하드웨어 리비전의 영향 기능 부재 또는 수정에 대한 제조사 근거를 연결한다.',
        '출입통제·포트 덮개·현재 미연결은 물리적 기능 부재와 다르다.'),
    flow('network_service', '통신 서비스와 프로토콜 입력', [
        r'\b(?:Modbus(?:/TCP)?|DNP3|EtherNet/IP|PROFINET|PROFIBUS|OPC[- ]?UA|BACnet|IEC[- ]?104|S7comm|FINS|MQTT|MELSEC|SLMP|SNMP|TFTP[D]?|FTP[D]?|Telnet[D]?|SSH[D]?|SMB|RDP|DNS|NTP|ICMP|RTSP|TCP|UDP)\b',
        r'\b(?:crafted|malformed|specially crafted)\s+(?:[\w.-]+\s+){0,3}(?:packet|datagram|network request|message)\b',
        r'\b(?:listening (?:port|service)|network service|protocol.compliant traffic|network packet)\b'], [
        q('service', '원문에 언급된 프로토콜·포트·서버 또는 클라이언트 기능은 어디에서 실행되는가?', 'network_service', ['서비스·포트 구성', '클라이언트·서버 역할']),
        q('paths', '영향 입력을 전달할 수 있는 내부·외부·정비 구역과 중계·대체 경로는 무엇인가?', 'network_paths', ['구성도·ACL', '게이트웨이', '원격정비·이중화 경로']),
        q('input', '어떤 메시지·명령·순서가 문제이며 실제 송신 주체와 인증·권한 조건은 무엇인가?', 'network_inputs', ['CVE별 메시지·트리거 근거', '송신 시스템', '접근 설정'])],
        '영향 서비스·클라이언트/서버 역할과 CVE별 입력·권한 조건을 검토한다.',
        '해당 빌드의 영향 서비스·스택·코드 경로 부재를 제품 근거로 입증한다.',
        '인터넷 미연결·포트 차단·패킷 미관측만으로 취약 경로가 없다고 판단하지 않는다.'),
    flow('sequence_resource', '상태 전이와 동시 요청 및 자원 제한', [
        r'\b(?:race condition|deadlock|TOCTOU|concurrent (?:request|connection|access)|simultaneous (?:request|connection)|repeated (?:request|connection|packet)|excessive (?:request|connection)|infinite loop|resource exhaustion|memory leak|uncontrolled recursion)\b'], [
        q('trigger', '어떤 기능의 요청 순서·동시성·반복·상태 전이 또는 입력 크기가 원문 트리거인가?', 'state_trigger', ['CVE별 트리거 설명', '영향 기능·상태 목록']),
        q('limits', '실제 동시 연결·요청량·메모리 제한과 해당 입력을 만들 수 있는 주체는 누구인가?', 'resource_limits', ['연결·자원 제한', '작업·통신 스케줄']),
        q('recovery', '재시작·이중화·정비모드에서 조건이 달라지며 장애 후 복구와 공정 영향은 무엇인가?', 'state_recovery', ['복구·이중화 설정', '정비 절차', '공정 영향 기록'])],
        '공격 경로를 별도로 확인하고 구체적인 순서·자원 트리거를 검토한다.',
        '영향 상태 기전 제거 또는 공급자 확인 수정 근거를 확보한다.',
        '낮은 평상시 부하·이중화·재현 실패는 비영향 증거가 아니다.'),
]

# Coarse routing is explicitly distinct from a named interface or complete route.
for key, name, question in [
    ('scored_network', '네트워크 경로만 확인', '어떤 네트워크 서비스·클라이언트·입력이 영향 대상인지 제조사 자료로 확인할 수 있는가?'),
    ('scored_adjacent', '인접 네트워크 경로만 확인', '어떤 동일 링크·구역·인접 통신 조건과 인터페이스가 필요한가?'),
    ('scored_local', '로컬 경로만 확인', '어떤 로컬 기능·작업과 실행 권한이 필요한가?'),
    ('scored_physical', '물리 경로만 확인', '어떤 하드웨어·포트·정비 작업이 영향 대상인가?'),
    ('discovery', '운영 경로 미확정', '영향 기능·인터페이스·입력 경로를 확인할 CVE별 제조사 자료가 있는가?'),
    ('rejected_review', 'Rejected 원문 검토', '거절 사유와 대체 CVE가 있는지 원문에서 확인했는가?'),
]:
    FLOWS.append(flow(key, name, [], [q('discover', question, 'missing_route', ['CVE별 제조사 상세 근거'])],
                      '점수화된 경로 또는 정보 부족만 확인됨. 실제 인터페이스와 조건을 추가 조사한다.',
                      '경로 추정만으로 비영향을 판정하지 않는다.', 'CVSS·Rejected 상태를 비영향 근거로 사용하지 않는다.'))

FACETS = {
    'authentication': (r'\b(?:authenticated|unauthenticated|authentication|log(?:ged)? in|login)\b',
        q('authentication', '언급된 영향 인터페이스의 실제 인증 방식과 대체·우회 경로는 무엇인가?', 'authentication', ['인증 구성', '대체·복구 경로'])),
    'privileges': (r'\b(?:privileges?|permissions?|administrator|administrative user|root user)\b',
        q('privileges', '원문이 지칭하는 역할·권한을 실제 계정·서비스 권한과 어떻게 대응시켰는가?', 'privileges', ['계정·서비스 권한표'])),
    'user_action': (r'\b(?:user interaction|user.{0,25}(?:opens?|visits?|clicks?|loads?|imports?)|convinc\w*.{0,35}user|trick\w*.{0,35}user)\b',
        q('user_action', '원문에 언급된 열기·방문·클릭 작업을 누가 수행하며 자동 처리 경로도 존재하는가?', 'user_action', ['작업 절차', '자동 처리 설정'])),
    'configuration': (r'\b(?:only if|only when|provided that|when.{0,65}(?:enabled|configured)|requires?.{0,55}(?:enabled|configured))\b',
        q('configuration', '인용된 설정 조건의 실제 값은 무엇이며 어느 구성·모드·기간에 적용되는가?', 'configuration', ['구성 백업', '변경·모드 기록'])),
    'operation_mode': (r'\b(?:maintenance mode|debug mode|recovery mode|boot mode|programming mode|commissioning|failover|redundancy)\b',
        q('operation_mode', '언급된 정비·디버그·복구·전환 모드에서 인터페이스와 보호 설정이 어떻게 달라지는가?', 'operation_mode', ['모드별 설정', '정비·복구 절차'])),
}

COMPILED = {f['id']: [re.compile(p, re.I) for p in f['patterns']] for f in FLOWS}
PROTOCOL = re.compile(r'\b(?:Modbus(?:/TCP)?|DNP3|EtherNet/IP|PROFINET|OPC[- ]?UA|BACnet|MQTT|SNMP|TFTP|FTP|Telnet|SSH|SMB|RDP|DNS|NTP|ICMP|RTSP|HTTPS?|TCP|UDP)\b', re.I)


def source_record(cve, text, origin):
    sid = cve+':'+hashlib.sha256((origin['key']+'\0'+text).encode()).hexdigest()[:20]
    return {'id': sid, 'cve': cve, 'text': text, 'origin': origin,
            'text_sha256': hashlib.sha256(text.encode()).hexdigest()}


def matches(pattern, source):
    result = []
    for match in pattern.finditer(source['text']):
        # Local negation guard, NOT a semantic entailment classifier.
        prefix = source['text'][max(0, match.start()-65):match.start()]
        if re.search(r'(?i)(?:not vulnerable to|not affected by|does not involve|no evidence of)\s*$', prefix):
            continue
        result.append({'source_id': source['id'], 'span': [match.start(), match.end()],
                       'quote': match.group(), 'necessity': 'not_established', 'can_refute': False})
        if len(result) >= 3:
            break
    return result


def cvss_dimensions(row):
    cvss = row.get('cvss') or {}
    vector = cvss.get('vector') or ''
    values = dict(re.findall(r'(?:^|/)([A-Za-z]+):([^/]+)', vector))
    version = '3' if vector.startswith('CVSS:3.') else '2' if cvss.get('method') == 'CVSSv2' else 'unknown'
    return {'version': version, 'raw_vector': vector,
            'AV': values.get('AV', 'unknown') if version != 'unknown' else 'unknown',
            'PR': values.get('PR', 'unknown') if version == '3' else 'unknown',
            'UI': values.get('UI', 'unknown') if version == '3' else 'unknown',
            'Au': values.get('Au', 'unknown') if version == '2' else 'not_applicable',
            'can_refute': False}


def classify(row, sources, old_labels=None):
    dims = cvss_dimensions(row)
    memberships, facets, hints = [], [], []
    if row.get('nvd_status') != 'Rejected':
        for f in FLOWS:
            found = []
            for source in sources:
                for pattern in COMPILED[f['id']]:
                    found.extend(matches(pattern, source))
            if found:
                # Retain all source hits; ranking favors more distinct sources and matched text.
                found = list({(m['source_id'], tuple(m['span'])): m for m in found}.values())
                memberships.append({'flow': f['id'], 'basis': 'source_workflow_candidate', 'evidence': found,
                                    'semantic_review_required': True, 'can_refute': False})
        for name, (pattern, _) in FACETS.items():
            evidence = [m for s in sources for m in matches(re.compile(pattern, re.I), s)]
            if evidence:
                facets.append({'facet': name, 'basis': 'source_mention', 'evidence': evidence, 'can_refute': False})
        hints = [m for s in sources for m in matches(PROTOCOL, s)]
    if memberships:
        primary = max(memberships, key=lambda m: (len({x['source_id'] for x in m['evidence']}),
                      sum(len(x['quote']) for x in m['evidence'])))['flow']
        specificity = 'source_workflow_candidate'
    else:
        key = 'rejected_review' if row.get('nvd_status') == 'Rejected' else {
            'N': 'scored_network', 'A': 'scored_adjacent', 'L': 'scored_local', 'P': 'scored_physical'
        }.get(dims['AV'], 'discovery')
        primary = key
        specificity = 'cvss_coarse' if key.startswith('scored_') else 'unresolved'
        memberships = [{'flow': key, 'basis': specificity, 'evidence': [],
                        'cvss_source_field': 'cvss.vector' if specificity == 'cvss_coarse' else None,
                        'semantic_review_required': True, 'can_refute': False}]
    # Rejected records carry neither route nor source-derived prerequisite claims.
    return {'schema': SCHEMA, 'cve': row['cve'], 'primary_flow': primary,
            'specificity': specificity, 'memberships': memberships, 'facets': facets,
            'protocol_mentions': hints, 'cvss': dims, 'cwes_auxiliary': row.get('cwes', []),
            'previous_weakness_labels': old_labels or [], 'source_ids': [s['id'] for s in sources],
            'nvd_status': row.get('nvd_status'), 'vex_status': None,
            'review_flags': ['Multiple candidate workflows; relations and alternatives not established'] if len(memberships) > 1 else [],
            'prerequisite_formula': None, 'route_coverage': 'not_established',
            'review_required': True}


def questionnaire(assignment):
    cve = assignment['cve']
    questions = {}
    def add(template, flow_id, evidence, basis):
        key = flow_id+':'+template['key']
        questions[key] = {**template, 'id': cve+':'+key, 'flow': flow_id,
                          'evidence_ids': sorted({e['source_id'] for e in evidence}),
                          'context_quotes': list(dict.fromkeys(e['quote'] for e in evidence))[:4],
                          'basis': basis, 'source_necessity': 'not_established'}
    for template in COMMON:
        add(template, 'common', [], 'common_inventory_question_not_cve_prerequisite')
    profiles = {p['id']: p for p in FLOWS}
    for member in assignment['memberships']:
        for template in profiles[member['flow']]['questions']:
            add(template, member['flow'], member['evidence'], member['basis'])
    for facet in assignment['facets']:
        add(FACETS[facet['facet']][1], 'facet', facet['evidence'], facet['basis'])
    # CVSS hints select additional questions but cannot establish a complete route.
    for facet, metric, allowed in [('privileges', 'PR', {'L', 'H'}), ('user_action', 'UI', {'R'})]:
        if assignment['cvss'][metric] in allowed and 'facet:'+facet not in questions:
            add(FACETS[facet][1], 'facet', [], 'cvss_scored_hint')
            questions['facet:'+facet]['question'] = {
                'privileges': 'CVSS는 권한 조건을 점수화한다. 실제 영향 인터페이스와 해당 역할·권한을 확인했는가?',
                'user_action': 'CVSS는 사용자 상호작용을 점수화한다. 실제 작업과 자동 처리 경로를 확인했는가?'
            }[facet]
    return {'schema': SCHEMA, 'cve': cve, 'questions': list(questions.values()),
            'cvss_hints': assignment['cvss'],
            'decision_policy': 'reviewed_scoped_evidence_v2',
            'answer_contract': {'value': 'text or yes/no/unknown', 'evidence_ids': 'supporting record IDs',
                                'binding': ['asset_ref', 'product', 'build', 'config_baseline', 'mode', 'evaluated_at']},
            'automatic_clearance': False}
