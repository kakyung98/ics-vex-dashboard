"""Concrete operator inventory forms; never infer CVE prerequisites from asset type."""
from copy import deepcopy
from jsonschema import Draft202012Validator
from src.item4.assets.asset_profile_fields import COMMON; from src.item4.assets.asset_profile_fields import PROFILES; from src.item4.assets.asset_profile_fields import GUIDANCE
from src.item4.analysis.advisory_source_bundles import seal; from src.item4.analysis.advisory_source_bundles import verify_seal


def obj(properties):
    return dict(type='object',properties=properties,required=list(properties),additionalProperties=False)


S=dict(type='string',minLength=1)
STATE=dict(type='string',enum=['true','false','unknown'])
PORT=dict(type=['integer','null'],minimum=0,maximum=65535)
ROWS={
 'services':obj(dict(interface=S,protocol=S,transport=S,port=PORT,enabled=STATE)),
 'routes':obj(dict(origin=S,target=S,service=S,mechanism=S,state=dict(type='string',enum=['allowed','blocked','unknown']))),
 'rules':obj(dict(rule_id=S,origin=S,target=S,service=S,action=dict(type='string',enum=['allow','deny','unknown']),applied=STATE)),
 'workflows':obj(dict(origin=S,target=S,input_kind=S,processor=S,allowed=STATE)),
 'configuration':obj(dict(interface=S,name=S,value=dict(type=['string','number','boolean','null']))),
 'authentication':obj(dict(interface=S,authentication=S,roles=dict(type='array',items=S))),
 'physical':obj(dict(interface=S,location=S,access_control=S,maintenance_exceptions=S)),
 'mode':obj(dict(name=S,permitted_transitions=dict(type='array',items=S))),
}
DEFS={
 'operating_mode':('mode',COMMON['operating_mode'][1]),
 'services':('services',COMMON['services'][1]),
 'access_rules':('rules',COMMON['access_rules'][1]),
 'remote_maintenance':('routes',COMMON['remote_maintenance'][1]),
 'file_ingress':('workflows',COMMON['file_ingress'][1]),
 'authentication':('authentication',COMMON['authentication'][1]),
 'physical_access':('physical',COMMON['physical_access'][1]),
 'project_file_opening':('workflows','프로젝트 파일을 어디서 받아 어떤 도구에서 여는지 기록하십시오.'),
 'engineering_tool_connections':('routes','엔지니어링 도구가 접속하는 대상·프로토콜·출발 구간을 기록하십시오.'),
 'removable_media':('workflows','USB 등 이동식 매체의 반입·검사·처리 경로를 기록하십시오.'),
 'project_import':('workflows','HMI 프로젝트의 반입·가져오기·실행 경로를 기록하십시오.'),
 'remote_display':('routes','원격 화면 서비스와 접근 가능한 구간을 기록하십시오.'),
 'browser_content':('workflows','브라우저가 여는 주소·외부 콘텐츠·다운로드 처리 경로를 기록하십시오.'),
 'program_download':('routes','프로그램을 다운로드하는 도구·대상·서비스·접근 통제를 기록하십시오.'),
 'run_program_mode':('mode','제어기 모드와 현장에서 허용되는 전환을 기록하십시오.'),
 'web_management':('services','웹 관리 인터페이스별 프로토콜·포트·활성 상태를 기록하십시오.'),
 'command_forwarding':('routes','명령을 전달하는 출발지·목적지·프로토콜을 기록하십시오.'),
 'wide_area_links':('routes','광역망·무선·전용회선의 연결과 접근 상태를 기록하십시오.'),
 'local_configuration':('configuration','로컬·직렬 설정 인터페이스와 적용 설정 값을 기록하십시오.'),
 'protection_settings':('configuration','보호 기능의 적용 설정과 관련 인터페이스를 기록하십시오.'),
 'engineering_protocols':('services','엔지니어링 프로토콜의 리스너·포트·활성 상태를 기록하십시오.'),
 'data_ingest':('workflows','수집 데이터의 출발지·입력 형식·처리 프로그램을 기록하십시오.'),
 'database_interfaces':('services','DB 인터페이스와 리스너·포트·활성 상태를 기록하십시오.'),
 'business_replication':('routes','업무망 복제의 방향·대상·서비스·접근 통제를 기록하십시오.'),
 'control_protocols':('services','제어 프로토콜 리스너와 활성 인터페이스를 기록하십시오.'),
 'HMI_connections':('routes','HMI와 제어 서버 사이의 방향성 연결을 기록하십시오.'),
 'runtime_service_accounts':('authentication','서비스 인터페이스별 인증 방식과 실행 계정 역할을 기록하십시오.'),
 'application_endpoints':('services','애플리케이션 엔드포인트와 리스너의 활성 상태를 기록하십시오.'),
 'plugins':('configuration','설치 플러그인·모듈과 적용 설정 값을 기록하십시오.'),
 'protocol_translation':('configuration','프로토콜 변환 기능의 적용 설정을 기록하십시오.'),
 'upstream_downstream_interfaces':('routes','게이트웨이 상·하위 구간의 방향성 연결을 기록하십시오.'),
 'write_forwarding':('configuration','쓰기 명령 전달의 적용 설정과 인터페이스를 기록하십시오.'),
 'safety_logic_download':('routes','안전 로직을 다운로드하는 도구·대상·서비스를 기록하십시오.'),
 'maintenance_mode':('mode','정비 모드와 현장에서 허용되는 전환을 기록하십시오.'),
 'programming_access':('routes','프로그래밍 인터페이스의 출발지·접근 상태를 기록하십시오.'),
 'VPN_listeners':('services','VPN 리스너의 인터페이스·프로토콜·포트·활성 상태를 기록하십시오.'),
 'tunnel_routes':('routes','VPN 터널의 출발 구간·목적 구간·전달 서비스를 기록하십시오.'),
 'client_roles':('authentication','VPN 인터페이스의 인증 방식과 클라이언트 역할을 기록하십시오.'),
 'remote_sessions':('routes','점프호스트 원격 세션의 출발지·대상·서비스를 기록하십시오.'),
 'file_redirection':('workflows','원격 세션의 파일·클립보드·드라이브 전달 경로를 기록하십시오.'),
 'downstream_access':('routes','점프호스트에서 하위 자산으로 가능한 연결을 기록하십시오.'),
 'fieldbus_interfaces':('services','필드버스 인터페이스의 프로토콜과 활성 상태를 기록하십시오.'),
 'remote_configuration':('routes','원격 설정의 출발지·대상 인터페이스·서비스를 기록하십시오.'),
 'firmware_update':('workflows','펌웨어 파일의 반입·검증·적용 경로를 기록하십시오.'),
 'routing':('routes','운영 중인 라우팅 경로와 서비스 전달 범위를 기록하십시오.'),
 'management_plane':('services','관리 인터페이스의 리스너·포트·활성 상태를 기록하십시오.'),
 'ACL':('rules','실제 적용 ACL 규칙과 방향·예외를 기록하십시오.'),
 'VLAN_ports':('configuration','VLAN·포트·트렁크의 적용 설정을 기록하십시오.'),
 'layer3_routing':('routes','스위치의 L3 라우팅 경로와 전달 서비스를 기록하십시오.'),
 'firewall_rules':('rules','실제 적용 방화벽 규칙과 방향·예외를 기록하십시오.'),
 'inspection_modules':('configuration','검사 모듈과 적용 정책·설정 값을 기록하십시오.'),
 'VPN_features':('configuration','방화벽 VPN 기능의 적용 설정을 기록하십시오.'),
 'controller_programming':('routes','DCS 프로그래밍 도구의 출발지·대상·서비스를 기록하십시오.'),
 'peer_links':('routes','제어기 피어 연결의 방향·서비스·접근 상태를 기록하십시오.'),
 'motion_vision_features':('configuration','모션·비전 기능의 적용 설정 값을 기록하십시오.'),
 'third_party_modules':('configuration','외부 모듈의 설치 목록과 적용 설정을 기록하십시오.'),
}


def build_form(asset_type_ids):
    if not asset_type_ids or any(a not in PROFILES for a in asset_type_ids):raise ValueError('Unknown asset type')
    ids=sorted(set(COMMON)|{f for a in asset_type_ids for f in PROFILES[a]})
    fields=[];properties={}
    for fid in ids:
        kind,question=DEFS[fid];data=deepcopy(ROWS[kind])
        if kind!='mode':data=dict(type='array',items=data,minItems=1)
        # Unknown is not an empty inventory. Recorded empty needs an explicit surveyed scope.
        alternatives=[obj(dict(state=dict(const='unknown'),data=dict(type='null'),evidence_ids=dict(type='array',maxItems=0))),
            obj(dict(state=dict(const='recorded'),data=data,evidence_ids=dict(type='array',items=S,minItems=1)))]
        if kind!='mode':alternatives.append(obj(dict(state=dict(const='recorded_empty'),data=dict(type='array',maxItems=0),
            evidence_ids=dict(type='array',items=S,minItems=1),coverage_scope=S)))
        properties[fid]=dict(oneOf=alternatives)
        fields.append(dict(id=fid,question=question,data_kind=kind,
            evidence_required=True,absence_not_inferred=True,maps_to_cve_condition_automatically=False))
    schema=obj(dict(asset_type_ids=dict(const=sorted(set(asset_type_ids))),values=obj(properties)))
    definition=seal(dict(asset_type_ids=sorted(set(asset_type_ids)),fields=fields,schema=schema,guidance=GUIDANCE,
        interpretation='Operator inventory only; recorded rows and asset types never establish CVE prerequisites or absence.'),'definition_sha256')
    values=dict(asset_type_ids=definition['asset_type_ids'],values={fid:dict(state='unknown',data=None,evidence_ids=[]) for fid in ids})
    return dict(definition=definition,input=values)


def validate_input(definition,payload):
    verify_seal(definition,'definition_sha256')
    errors=list(Draft202012Validator(definition['schema']).iter_errors(payload))
    if errors:raise ValueError(errors[0].message)
    return dict(passed=True,recorded_fields=sum(v['state'] in {'recorded','recorded_empty'} for v in payload['values'].values()),
                unknown_fields=sum(v['state']=='unknown' for v in payload['values'].values()),
                automatic_cve_mapping=False,proves_non_exploitability=False)
