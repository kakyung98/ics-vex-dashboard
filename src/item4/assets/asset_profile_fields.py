"""Reusable asset profiles plus source-condition-specific operator fields."""
from pathlib import Path
import json

from src.item4.analysis.advisory_source_bundles import digest; from src.item4.analysis.advisory_source_bundles import seal
from src.item4.evaluation.machine_review_contracts import VERSION

COMMON = {
 'operating_mode':('enum','정상 운전·정비·기동 등 평가 대상 운영모드는 무엇입니까?'),
 'services':('service_list','인터페이스별 서비스·포트·프로토콜·활성 상태는 무엇입니까?'),
 'access_rules':('directed_rules','출발 구간별로 대상 서비스에 허용·차단된 경로와 예외는 무엇입니까?'),
 'remote_maintenance':('route_list','VPN·점프호스트·이동식 정비 장비를 통한 접근 경로는 무엇입니까?'),
 'file_ingress':('workflow_list','외부 파일·USB·공유폴더가 들어와 처리되는 경로는 무엇입니까?'),
 'authentication':('interface_authentication','대상 인터페이스의 인증 방식과 역할별 권한은 무엇입니까?'),
 'physical_access':('interface_access','물리·직렬·로컬 콘솔 인터페이스와 접근 제한은 무엇입니까?'),
}
GUIDANCE=dict(asset_inventory='https://www.cisa.gov/sites/default/files/2025-08/joint-guide-foundations-for-OT-cybersecurity-asset-inventory-guidance_508c.pdf',
              operations='https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf',
              operations_sections=['6.2.1','6.2.4.1','6.2.4.2','6.2.5','6.2.7','6.2.10'],
              mapping_status='Project-defined fields informed by guidance; not official MITRE/CISA field mandates.')
PROFILES = {
 'A0001':['project_file_opening','engineering_tool_connections','removable_media'],
 'A0002':['project_import','remote_display','browser_content'],
 'A0003':['program_download','run_program_mode','web_management'],
 'A0004':['command_forwarding','wide_area_links','local_configuration'],
 'A0005':['protection_settings','engineering_protocols','local_configuration'],
 'A0006':['data_ingest','database_interfaces','business_replication'],
 'A0007':['control_protocols','HMI_connections','runtime_service_accounts'],
 'A0008':['application_endpoints','plugins','runtime_service_accounts'],
 'A0009':['protocol_translation','upstream_downstream_interfaces','write_forwarding'],
 'A0010':['safety_logic_download','maintenance_mode','programming_access'],
 'A0011':['VPN_listeners','tunnel_routes','client_roles'],
 'A0012':['remote_sessions','file_redirection','downstream_access'],
 'A0013':['fieldbus_interfaces','remote_configuration','firmware_update'],
 'A0014':['routing','management_plane','ACL'],
 'A0015':['VLAN_ports','management_plane','layer3_routing'],
 'A0016':['firewall_rules','inspection_modules','VPN_features'],
 'A0017':['controller_programming','peer_links','maintenance_mode'],
 'A0018':['program_download','motion_vision_features','third_party_modules'],
}
OBSERVABLE = {
 'network_reachable':('network','network_rules_and_routes'),
 'feature_enabled':('feature','applied_configuration'),
 'configuration_matches':('configuration','applied_configuration'),
 'operating_mode_matches':('mode','applied_mode_or_operating_record'),
 'external_input_processed':('workflow','file_and_input_processing_records'),
 'user_action_performed':('workflow','operating_procedure_and_records'),
 'physical_access':('physical','physical_access_and_maintenance_records'),
 'local_access':('local','console_and_local_execution_access_records'),
 'maintenance_access':('maintenance','maintenance_routes_and_records'),
 'victim_authenticated':('authentication','legitimate_user_session_records'),
 'victim_has_privilege':('roles','legitimate_user_role_records'),
}


def asset_catalog(stix_path):
    payload=json.loads(Path(stix_path).read_text(encoding='utf-8'))
    result=[]
    for item in payload['objects']:
        if item.get('type')!='x-mitre-asset' or item.get('revoked') or item.get('x_mitre_deprecated'):continue
        ref=next((r for r in item.get('external_references',[]) if r.get('external_id','') in PROFILES),None)
        if ref:
            aid=ref['external_id'];result.append(dict(id=aid,name=item['name'],stix_id=item['id'],
                source_url=ref.get('url'),common_fields=list(COMMON),profile_fields=PROFILES[aid],
                interpretation='Project-defined input profile; asset membership never proves an actual feature/configuration.'))
    return sorted(result,key=lambda r:r['id'])


def define_fields(graph):
    fields=[]
    for c in graph['conditions']:
        observable=c['predicate'] in OBSERVABLE and c['actor']!='attacker'
        # Reachability/physical access rules can be observed for a specified actor origin.
        if c['predicate'] in {'network_reachable','physical_access','local_access','maintenance_access'}:
            observable=True
        kind,evidence_kind=OBSERVABLE.get(c['predicate'],('unobservable','external_condition_evidence'))
        fields.append(dict(id='field-'+digest([graph['cve'],c['id']]),condition_id=c['id'],
            cve=graph['cve'],product_ids=c['product_ids'],predicate=c['predicate'],actor=c['actor'],
            kind=kind,question='해당 자산·인터페이스·운영모드에서 다음 원문 조건이 성립합니까? '+c['condition'],
            source_quote=c['evidence']['quote'],answer_type='true_false_unknown',
            operator_observable=observable,required_evidence_kind=evidence_kind,
            required_scope=['asset_id','product_id','build','config_baseline','mode','target','origin'],
            unknown_is='unknown',mapping='true_means_source_condition_holds',
            source_evidence=c['evidence'],
            verification=dict(source_condition_state=c['state'],predicate_registered=c['predicate'] in OBSERVABLE,
                              hidden_attacker_possession_not_inferred=c['predicate'] in {'attacker_authenticated','attacker_has_privilege','attacker_controls_input'},
                              verification_method='deterministic_predicate_and_actor_contract',human_required=False)))
    return seal(dict(contract_version=VERSION,cve=graph['cve'],graph_sha256=graph['graph_sha256'],fields=fields,
                     unresolved=not bool(fields),empty_fields_means='unknown_not_no_requirements'), 'fields_sha256')


def compose_profile(asset_type_ids):
    if not asset_type_ids or any(i not in PROFILES for i in asset_type_ids):raise ValueError('Select registered ATT&CK ICS asset types')
    extras=sorted({f for i in asset_type_ids for f in PROFILES[i]})
    return dict(asset_type_ids=sorted(set(asset_type_ids)),
                common_fields=[dict(id=k,type=v[0],question=v[1],value='unknown') for k,v in COMMON.items()],
                profile_fields=[dict(id=k,value='unknown',availability='unknown_until_inventory_confirmation') for k in extras],
                guidance=GUIDANCE,requires_actual_feature_inventory=True)


def validate_fields(graph,plan):
    from src.item4.analysis.advisory_source_bundles import verify_seal
    verify_seal(plan,'fields_sha256')
    if plan['graph_sha256']!=graph['graph_sha256'] or plan['cve']!=graph['cve']:raise ValueError('Field graph scope mismatch')
    if {r['condition_id'] for r in plan['fields']}!={c['id'] for c in graph['conditions']}:raise ValueError('Incomplete condition/field mapping')
    if len({r['id'] for r in plan['fields']})!=len(plan['fields']):raise ValueError('Duplicate field IDs')
    for row in plan['fields']:
        if row['predicate'] in {'attacker_authenticated','attacker_has_privilege','attacker_controls_input'} and row['operator_observable']:
            raise ValueError('Operator inventory cannot prove attacker possession')
    if plan!=define_fields(graph):raise ValueError('Field definition differs from source/predicate contract')
    return plan
