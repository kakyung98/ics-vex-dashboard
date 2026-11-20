"""English presentation for the legacy asset catalogue; assessment keys stay intact."""
import re

CRITERIA = {
    '모든 경유 방화벽·ACL 및 대상 호스트 정책의 유효 규칙 평가가 해당 방향 흐름을 허용함': 'Effective rules on every traversed firewall, ACL and destination host allow this directional flow.',
    '완전한 경로 및 규칙 조사에서 해당 방향 흐름을 차단하는 유효 규칙이 하나 이상 확인됨': 'A complete path and rule review identifies at least one effective rule blocking this directional flow.',
    '해당 흐름의 순방향 경로가 모든 경유 장비의 적용 라우팅 및 NAT 설정에 존재함': 'Effective routing and NAT configurations provide a forward path for this flow at every traversed device.',
    '완전한 경로 조사에서 하나 이상의 필수 경유 지점에 해당 흐름의 순방향 경로가 없음': 'A complete path review confirms that at least one required transit point has no forward path for this flow.',
    '모든 허용 원격 로그인 경로에서 MFA를 필수로 요구함': 'Every permitted remote login path requires MFA.',
    'MFA 없이 원격 로그인을 허용하는 구성 경로가 하나 이상 있음': 'At least one configured path permits remote login without MFA.',
    '모든 허용 프로그램 변경 경로에서 자격증명 인증을 필수로 요구함': 'Every permitted program modification path requires credential authentication.',
    '인증 없이 프로그램 변경을 허용하는 구성 경로가 하나 이상 있음': 'At least one configured path permits program modification without authentication.',
    '설치 목록에 해당 도구가 존재함': 'The installation inventory includes the specified tool.',
    '전체 설치 목록과 제품 구성 명세에서 해당 도구 부재가 확인됨': 'The complete installation inventory and product configuration specification confirm that the specified tool is absent.',
    '실행 계정의 유효 역할에 OS 관리자 또는 root 역할이 있음': 'The execution account has an effective OS administrator or root role.',
    '실행 계정의 유효 역할에 OS 관리자와 root 역할이 모두 없음': 'The execution account has neither an effective OS administrator role nor a root role.',
    '유효 DB 권한에 지정 객체의 데이터 변경 권한이 있음': 'Effective database permissions allow data modification on the specified object.',
    '유효 DB 권한에 지정 객체의 데이터 변경 권한이 없음': 'Effective database permissions do not allow data modification on the specified object.',
    '유효 권한이 해당 디렉터리의 파일 생성 또는 변경을 허용함': 'Effective permissions allow file creation or modification in the specified directory.',
    '유효 권한이 해당 디렉터리의 파일 생성과 변경을 모두 거부함': 'Effective permissions deny both file creation and modification in the specified directory.',
    '유효 실행 정책과 파일 권한이 해당 프로그램 실행을 허용함': 'Effective execution policy and file permissions allow the specified program to execute.',
    '유효 실행 정책 또는 파일 권한이 해당 프로그램 실행을 거부함': 'Effective execution policy or file permissions deny execution of the specified program.',
    '적용 OS 정책이 이동식 저장매체의 AutoRun 실행을 허용함': 'The applied OS policy permits AutoRun execution from removable storage.',
    '적용 OS 정책이 모든 이동식 저장매체의 AutoRun 실행을 차단함': 'The applied OS policy blocks AutoRun execution from all removable storage.',
    '적용된 장치 제어 정책에서 USB 대용량 저장장치의 읽기 또는 쓰기를 허용함': 'The applied device control policy allows reading or writing USB mass storage.',
    '적용된 장치 제어 정책에서 모든 USB 대용량 저장장치의 읽기와 쓰기를 차단함': 'The applied device control policy blocks both reading and writing for all USB mass storage.',
    '전체 모듈 설치 목록에 해당 외부 모듈이 있음': 'The complete module installation inventory includes the specified third-party module.',
    '전체 모듈 설치 목록과 제품 명세에서 해당 외부 모듈 부재가 확인됨': 'The complete module installation inventory and product specification confirm that the specified third-party module is absent.',
    '지정 기간에 프로젝트 파일 열기 기록이 1건 이상 있음': 'At least one project file open event is recorded in the specified period.',
    '지정 기간 전체를 포괄하는 파일 열기 감사 기록에 해당 이벤트가 0건임': 'File open audit records covering the entire specified period contain no such event.',
    '케이블이 해당 포트에 체결되어 있음': 'A cable is physically connected to the specified port.',
    '케이블이 해당 포트에 체결되어 있지 않음': 'No cable is physically connected to the specified port.',
    '키스위치가 제조사 정의 프로그램 변경 방지 위치에 있음': 'The key switch is in the vendor-defined position that prevents program modification.',
    '키스위치가 제조사 정의 프로그램 변경 방지 위치 이외에 있음': 'The key switch is outside the vendor-defined position that prevents program modification.',
    '해당 RDP 엔드포인트가 NLA를 필수로 요구함': 'The specified RDP endpoint requires NLA.',
    '해당 RDP 엔드포인트가 NLA를 필수로 요구하지 않음': 'The specified RDP endpoint does not require NLA.',
    '해당 SNMP 주체의 유효 권한에 쓰기가 포함됨': 'The specified SNMP principal has effective write permission.',
    '해당 SNMP 주체의 유효 권한에 쓰기가 포함되지 않음': 'The specified SNMP principal has no effective write permission.',
    '해당 계정의 로컬 대화형 로그인이 적용 정책상 허용됨': 'The applied policy permits local interactive login for the specified account.',
    '해당 계정의 로컬 대화형 로그인이 적용 정책상 거부됨': 'The applied policy denies local interactive login for the specified account.',
    '해당 계정의 유효 SSH 정책이 TCP 포워딩을 허용함': 'The effective SSH policy permits TCP forwarding for the specified account.',
    '해당 계정의 유효 SSH 정책이 TCP 포워딩을 차단함': 'The effective SSH policy blocks TCP forwarding for the specified account.',
    '해당 서비스의 적용 설정이 인증 자격증명 없이 요청을 수락하도록 지정됨': 'The applied service configuration accepts requests without authentication credentials.',
    '해당 서비스의 적용 설정이 모든 요청에 인증 자격증명을 요구함': 'The applied service configuration requires authentication credentials for every request.',
    '해당 정책에서 클라이언트 드라이브 리디렉션을 허용함': 'The specified policy permits client drive redirection.',
    '해당 정책에서 클라이언트 드라이브 리디렉션을 차단함': 'The specified policy blocks client drive redirection.',
    '해당 정책에서 클립보드 리디렉션을 허용함': 'The specified policy permits clipboard redirection.',
    '해당 정책에서 클립보드 리디렉션을 차단함': 'The specified policy blocks clipboard redirection.',
    '해당 출력 채널의 강제 설정 기능이 허용됨': 'Forcing is permitted on the specified output channel.',
    '해당 출력 채널의 강제 설정 기능이 차단됨': 'Forcing is blocked on the specified output channel.',
    '해당 컨트롤의 로드가 적용 정책상 허용됨': 'The applied policy permits loading the specified control.',
    '해당 컨트롤의 로드가 적용 정책상 차단됨': 'The applied policy blocks loading the specified control.',
    '해당 포트가 802.1X 성공 후에만 일반 데이터 통신을 허용하고 우회 허용 경로가 없음': 'The port permits ordinary data traffic only after successful 802.1X authentication, with no permitted bypass path.',
    '해당 포트에 802.1X 성공 없이 일반 데이터 통신을 허용하는 설정 경로가 하나 이상 있음': 'At least one configured port access path permits ordinary data traffic without successful 802.1X authentication.',
    '해당 포트에 USB 장치가 연결되어 있음': 'A USB device is connected to the specified port.',
    '해당 포트에 USB 장치가 연결되어 있지 않음': 'No USB device is connected to the specified port.',
    '해당 포트의 관리 상태가 enabled임': 'The administrative state of the specified port is enabled.',
    '해당 포트의 관리 상태가 disabled임': 'The administrative state of the specified port is disabled.',
    '해당 Wi-Fi 인터페이스의 관리 상태가 enabled임': 'The administrative state of the specified Wi-Fi interface is enabled.',
    '해당 Wi-Fi 인터페이스의 관리 상태가 disabled임': 'The administrative state of the specified Wi-Fi interface is disabled.',
    '해당 포트의 유효 운용 모드가 trunk임': 'The effective operating mode of the specified port is trunk.',
    '해당 포트의 유효 운용 모드가 trunk 이외임': 'The effective operating mode of the specified port is not trunk.',
    '해당 프로파일의 모든 허용 인증 경로가 클라이언트 인증서를 필수로 요구함': 'Every permitted authentication path in the profile requires a client certificate.',
    '해당 프로파일에 클라이언트 인증서를 요구하지 않는 허용 인증 경로가 하나 이상 있음': 'At least one permitted authentication path in the profile does not require a client certificate.',
    '해당 프로파일의 모든 허용 인증 경로에서 MFA를 필수로 요구함': 'Every permitted authentication path in the profile requires MFA.',
    '해당 프로파일에 MFA를 요구하지 않는 허용 인증 경로가 하나 이상 있음': 'At least one permitted authentication path in the profile does not require MFA.',
    '해당 프로파일이 IKEv1을 허용함': 'The specified profile permits IKEv1.',
    '해당 프로파일이 IKEv1을 허용하지 않음': 'The specified profile does not permit IKEv1.',
    '현재 로드된 모듈 목록에 해당 네이티브 모듈이 있음': 'The current loaded module list includes the specified native module.',
    '현재의 완전한 로드 목록에 해당 네이티브 모듈이 없음': 'The complete current loaded module list does not include the specified native module.',
    '현재 제품의 로드된 플러그인 목록에 해당 플러그인이 있음': 'The current product loaded plugin list includes the specified plugin.',
    '현재 제품의 완전한 로드 목록에 해당 플러그인이 없음': 'The complete current product loaded plugin list does not include the specified plugin.',
}

ACRONYMS = {s.lower(): s for s in 'API BGP CSV DCS DHCP DNP3 DNS FTP GOOSE GRE HA HDA HMI HTTP HTTPS IEC IEC104 IEC101 IGMP IKEv1 IO IP IPS IPsec IPv6 LACP LDAP LLDP MFA MMS Modbus MQTT NETCONF NLA OPC OPCDA OPCUA OSPF RADIUS RDP RESTCONF RIP RUN SAML SCL SMB SNMP SQL SSH SSL STP SV TCP TEST TLS UDP URL USB VLAN VNC VPN VRRP Wi-Fi WinRM XML'.split()}
ACRONYMS.update({'activex': 'ActiveX', 'dot1x': '802.1X', 'io': 'I/O', 'opcua': 'OPC UA', 'opcda': 'OPC DA', 'ipsec': 'IPsec', 'wifi': 'Wi-Fi'})


def label(key):
    text = ' '.join(ACRONYMS.get(word, word) for word in key.split('_'))
    return text[:1].upper() + text[1:]


def criterion(original, key):
    if original in CRITERIA:
        return CRITERIA[original]
    if not re.search('[가-힣]', original):
        return original
    # Catalogue rows express one named feature in the exact selected scope.
    if '비활성' in original or '활성' in original:
        feature = label(key).removesuffix(' enabled').removesuffix(' active')
        state = 'disabled' if '비활성' in original else 'enabled'
        return f'{feature} is {state} for the specified target in the current effective configuration.'
    for mode in ('PROGRAM', 'RUN', 'TEST'):
        if mode in original:
            return f'The current operating mode is {"not " if "이외" in original else ""}{mode}.'
    if '제조사 정의 정비 모드' in original:
        return f'The current operating mode is {"outside " if "이외" in original else ""}the vendor-defined maintenance mode.'
    raise ValueError(f'Untranslated asset criterion: {original}')


def presentation(catalogue):
    result = {}
    for rows in catalogue['asset_types'].values():
        for row in rows:
            name = label(row['key'])
            result[row['asset_type_id'] + ':' + row['key']] = dict(
                label=name,
                yes_criterion=criterion(row['yes_criterion'], row['key']),
                no_criterion=criterion(row['no_criterion'], row['key']),
                evidence_guidance=f'Check current effective {name.lower()} settings, inventory or audit records for the specified target. Record the scope and observation time; leave unverified values unknown.')
    return result
