"""Compile each source condition into scoped information and record requirements.

Record locations guide verification; they never supply operating values, new
conditions or Boolean relationships. No source-role qualifiers are guessed.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from src.item4.analysis import condition_question_contract as CONTRACT
from src.item4.assets.asset_profile_fields import PROFILES

VERSION='item4-operating-information-requirements/1'

# These are verification contracts, not a catalogue of feature prerequisites.
RULES={
 'configuration':dict(key='applied_feature_or_configuration',label='Current source-described feature or configuration state',
    dimensions=['exact_target','applied_setting','assessment_scope','observation_time'],
    records=[('configuration_export','applied_configuration'),('asset_inventory','feature_inventory')],
    limits=['A default, a supported capability or an installed module alone does not establish the applied state.']),
 'input_availability':dict(key='named_input_availability',label='Availability of the exact source-described input',
    dimensions=['exact_input','input_handler','assessment_scope','observation_time'],
    records=[('service_inventory','input_inventory'),('configuration_export','applied_configuration')],
    limits=['Input availability does not establish network reachability or an enabled feature flag.']),
 'access_path':dict(key='scoped_origin_to_target_access',label='Access from the source-described origin to the exact destination',
    dimensions=['source_described_origin','exact_destination','interface_or_operation','direction','assessment_scope','observation_time'],
    records=[('configuration_export','routes_and_topology'),('firewall_acl','applied_access_rules'),('operating_event_log','scoped_connection_records')],
    limits=['An ACL or route alone does not establish end-to-end reachability.',
            'No connection event alone proves that every assessed path is blocked.']),
 'authentication':dict(key='operation_authentication_policy',label='Authentication policy for the exact source-described operation',
    dimensions=['exact_operation','interface','authentication_policy','assessment_scope','observation_time'],
    records=[('access_control_record','operation_authentication_policy'),('configuration_export','applied_configuration')],
    limits=['An authentication bypass does not mean authentication is disabled.',
            'Policy records do not establish that an adversary possesses credentials.']),
 'principal_permission':dict(key='principal_permission_for_operation',label='Permissions of the same source-described principal for the exact operation',
    dimensions=['same_source_described_principal','exact_operation','resource','role_assignment','assessment_scope','observation_time'],
    records=[('access_control_record','principal_permissions'),('configuration_export','role_assignment')],
    limits=['Do not replace the source-described principal with an administrator or a service account.',
            'Permission records do not establish possession of credentials or an attacker session.']),
 'operating_state':dict(key='current_operating_mode',label='Current source-described operating mode or selector state',
    dimensions=['exact_device','source_described_mode','current_state','assessment_scope','observation_time'],
    records=[('configuration_export','current_mode_or_selector'),('operating_event_log','mode_observation')],
    limits=['Supported modes, defaults and a maintenance procedure do not establish the current mode.',
            'A historical mode transition alone does not establish the mode at the observation time.']),
 'recorded_action':dict(key='source_described_workflow',label='The exact source-described action, processing or input workflow',
    dimensions=['same_qualified_actor','exact_action_or_processing','input_or_resource','assessment_scope','observation_time'],
    records=[('operating_event_log','scoped_action_records'),('maintenance_log','maintenance_action_records'),('operating_procedure','workflow_documentation')],
    limits=['A procedure alone does not establish that the source-described action occurred.',
            'Do not require exploit execution or assume that malicious input has already been processed.']),
 'physical_access':dict(key='scoped_physical_or_console_access',label='The source-described physical or local-console access',
    dimensions=['exact_interface','source_described_actor','location_or_console','assessment_scope','observation_time'],
    records=[('access_control_record','physical_or_console_policy'),('maintenance_log','access_inspection_records')],
    limits=['A physical interface inventory alone does not establish access or presence.']),
}
WORKFLOW_KEYS={
 'file_import':('file_import_workflow','Source-described file import'),
 'input_processed':('input_processing_workflow','Source-described input processing'),
 'external_file_source':('external_input_workflow','Source-described external input origin and handling'),
 'user_performs_action':('qualified_user_action','Source-described action by the same qualified user'),
}

HOSTS={'A0001','A0002','A0006','A0007','A0008','A0011','A0012'}
INFRASTRUCTURE={'A0009','A0014','A0015','A0016'}
LOCATIONS={
 'host':{
  'applied_configuration':'Host or appliance application/service configuration export',
  'feature_inventory':'Host or appliance installed-feature inventory',
  'input_inventory':'Host or appliance application input and service inventory',
  'routes_and_topology':'Host or appliance interface routes and network topology records',
  'applied_access_rules':'Applied host and network access rules for the exact source and destination',
  'scoped_connection_records':'Scoped host or appliance connection and access-verification records',
  'principal_permissions':'Application or operating-system permissions for the source-described principal and operation',
  'role_assignment':'Application or operating-system account/group and role assignment export',
  'operation_authentication_policy':'Application or host interface authentication policy for the specified operation',
  'current_mode_or_selector':'Current host or application operating-mode display/configuration',
  'mode_observation':'Timestamped host or application mode observation',
  'scoped_action_records':'Application file-import, processing or user-action records for the exact source-described workflow',
  'maintenance_action_records':'Host or appliance maintenance task records for that workflow',
  'workflow_documentation':'Documented host or application handling workflow; contextual evidence only',
  'physical_or_console_policy':'Host or appliance local-console and physical-access policy',
  'access_inspection_records':'Host or appliance physical/local access inspection records'},
 'device':{
  'applied_configuration':'Current device or engineering-tool applied configuration export',
  'feature_inventory':'Device feature inventory and corresponding model documentation',
  'input_inventory':'Device interface and source-described input configuration inventory',
  'routes_and_topology':'Device communication configuration and connected-segment topology records',
  'applied_access_rules':'Applied device and network-segment access rules for the exact source and destination',
  'scoped_connection_records':'Scoped device connection and access-verification records',
  'principal_permissions':'Device or project access-policy permissions for the same principal and operation',
  'role_assignment':'Device/project user and role assignments from current administration or engineering records',
  'operation_authentication_policy':'Device interface authentication policy for the specified operation',
  'current_mode_or_selector':'Current device mode display, physical selector reading or engineering-tool mode observation',
  'mode_observation':'Timestamped device mode or selector observation',
  'scoped_action_records':'Device or engineering-tool action/processing records for the exact source-described workflow',
  'maintenance_action_records':'Device engineering or maintenance task records for that workflow',
  'workflow_documentation':'Documented device engineering/maintenance workflow; contextual evidence only',
  'physical_or_console_policy':'Device physical, serial or local-console access policy for the specified interface',
  'access_inspection_records':'Device physical/local access inspection and maintenance records'},
 'infrastructure':{
  'applied_configuration':'Current network-device applied configuration export',
  'feature_inventory':'Network-device feature inventory and model documentation',
  'input_inventory':'Network-device interface and management/service input inventory',
  'routes_and_topology':'Network-device forwarding/routing configuration and topology records',
  'applied_access_rules':'Applied forwarding/access policies for the exact source, destination and interface',
  'scoped_connection_records':'Scoped network-device forwarding/connection and access-verification records',
  'principal_permissions':'Network-device management/interface permissions for the same principal and operation',
  'role_assignment':'Current network-device management user and role assignments',
  'operation_authentication_policy':'Network-device interface authentication policy for the specified operation',
  'current_mode_or_selector':'Current network-device source-described operating mode display/configuration',
  'mode_observation':'Timestamped network-device mode observation',
  'scoped_action_records':'Network-device operation, import or processing records for the exact source-described workflow',
  'maintenance_action_records':'Network-device maintenance task records for that workflow',
  'workflow_documentation':'Documented network-device administration workflow; contextual evidence only',
  'physical_or_console_policy':'Network-device physical/console access policy for the specified interface',
  'access_inspection_records':'Network-device physical/console access inspection records'},
}
PROFILE_LOCATIONS={
 'configuration':[], 'input_availability':[],
 'access_path':['access_rules'], 'authentication':['authentication'],
 'principal_permission':['authentication'], 'operating_state':['operating_mode'],
 'recorded_action':[], 'physical_access':['physical_access'],
}


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()


def signature():
    return digest(dict(code_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),profiles=PROFILES,
        rules=RULES,locations=LOCATIONS,profile_locations=PROFILE_LOCATIONS,workflow_keys=WORKFLOW_KEYS))


def compile_condition(condition, scope):
    """No natural-language role extraction: preserve qualifiers in the full fact."""
    if condition.get('operator','eq')!='eq' or condition.get('expected',True) is not True:
        raise ValueError('Operating information requires a positive source condition')
    group=CONTRACT.source_group(condition);rule=RULES[group]
    aid=scope.get('asset_type_id');known=aid in PROFILES
    family='host' if aid in HOSTS else 'infrastructure' if aid in INFRASTRUCTURE else 'device' if known else 'unknown'
    key,label=WORKFLOW_KEYS.get(condition['predicate'],(rule['key'],rule['label']))
    records=[]
    for record_type,role in rule['records']:
        title=LOCATIONS[family][role] if known else role.replace('_',' ')
        records.append(dict(id=role,record_type=record_type,label=title,
            use='context_only' if role in ('workflow_documentation','feature_inventory') else 'verify_same_source_fact',
            target=condition['target'],supports_condition_id=condition['id']))
    statement=condition['statement']
    verification=dict(source_record_type=condition['observation']['record_type'],
        source_check=condition['observation']['check'],record_sources=records,
        required_dimensions=list(rule['dimensions']),limitations=list(rule['limits']),
        instruction='For '+(scope.get('asset_name') or 'this asset')+', verify the following exact source fact for the same target, qualified actor and assessment scope: '+statement,
        operating_values_supplied=False)
    profile_ids=list(PROFILE_LOCATIONS[group]) if known else []
    if known and condition['predicate'] in ('file_import','external_file_source'):profile_ids.append('file_ingress')
    if group=='operating_state' and aid=='A0003':profile_ids.append('run_program_mode')
    result=dict(version=VERSION,condition_id=condition['id'],information_key=key,label=label,
        question_type=group,scope=deepcopy(scope),asset_family=family,
        source_condition={k:deepcopy(condition[k]) for k in (
            'id','predicate','target','value','statement','category','operator','expected','observation',
            'ics_context','source_refs','operational_quote') if k in condition},
        quantifier=condition['observation'].get('quantifier','single'),
        source_qualifiers=dict(preserved_fact=statement,
            actor_and_origin='not_separately_structured; retain source-described qualifiers verbatim'),
        verification=verification,
        asset_mapping=dict(status='type_specific_record_plan' if known else 'source_record_plan',
            asset_type_id=aid,profile_record_locations=profile_ids,
            coverage='record_locations_only_not_additional_conditions',feature_support_inferred=False),
        answer_semantics=dict(yes='true',no='false',unknown='unknown'),boolean_expression_modified=False)
    result['id']='operating-info-'+digest(result)[:24]
    result['sha256']=digest(result)
    return result


def for_question(condition, question, catalogue):
    aid=question.get('asset_type_id');rows=catalogue['asset_types'].get(aid,[])
    return compile_condition(condition,dict(cve=question.get('cve'),component_ref=question.get('component_ref'),
        scope_id=question.get('scope_id'),asset_type_id=aid,asset_name=rows[0]['asset_name'] if rows else None,
        target=condition['target']))


def validate(requirement, condition, question, catalogue):
    if requirement!=for_question(condition,question,catalogue):
        raise ValueError('Operating information requirement differs from the source condition or scoped record contract')
    return requirement
