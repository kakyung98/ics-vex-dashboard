"""Predicate-driven question blueprints. Templates format locked source facts only."""
from copy import deepcopy
from src.item4.analysis.prerequisite_taxonomy import PREDICATES

VERSION='item4-condition-question-contract/5-information-requirements'
GROUPS={
    'configuration':('feature_enabled','configuration_required'),
    'input_availability':('interface_available',),
    'access_path':('interface_reachable','network_reachable','maintenance_access','remote_maintenance'),
    'authentication':('authentication_required',),
    'principal_permission':('privilege_required',),
    'recorded_action':('file_import','input_processed','external_file_source','user_performs_action'),
    'physical_access':('physical_access','local_console_access'),
}
GUIDANCE={
    'configuration':'Use the current applied configuration; a default or vendor capability alone does not prove this state.',
    'input_availability':'Check the named input in current service/configuration records. Do not test attack success or infer a protocol/port.',
    'access_path':'Preserve the assessed origin, destination and scope. An ACL alone does not prove end-to-end reachability.',
    'authentication':'Check the authentication policy for the exact operation. Authentication bypass is not disabled authentication.',
    'principal_permission':'Use current account/role permissions for the same assessed principal and exact operation; never assume administrator.',
    'recorded_action':'Use records of the specified action by the same qualified actor; a procedure alone does not establish occurrence.',
    'physical_access':'Check the specified physical/local access scope using current access records; do not assume physical presence.',
    'operating_state':'Check the assessed asset current mode/configuration and observation time; a default, supported capability or operating procedure alone does not establish the current state.',
}


def group_for(predicate,category=None):
    group=next((g for g,values in GROUPS.items() if predicate in values),None)
    if group is None or predicate not in PREDICATES:raise ValueError('Unregistered question predicate')
    if category is not None and category not in PREDICATES[predicate]:raise ValueError('Question predicate/category mismatch')
    if predicate in ('configuration_required','feature_enabled'):
        group={'C2':'input_availability','C5':'principal_permission','C7':'operating_state',
               'PR':'principal_permission'}.get(category,group)
    return group


def source_group(condition):
    group=group_for(condition['predicate'],condition.get('category'))
    if (condition.get('observation',{}).get('kind')=='operating_mode' or
        any(c['kind']=='operating_mode' for c in condition.get('ics_context',[]))):
        if condition['predicate'] in ('configuration_required','feature_enabled'):group='operating_state'
    return group


def blueprint(atom):
    predicate=atom['predicate']
    group=source_group(atom)
    return dict(version=VERSION,predicate=predicate,category=atom.get('category'),
        ics_context=deepcopy(atom.get('ics_context',[])),
        question_type=group,question='For this asset, is the following true: '+atom['positive_fact'].rstrip().rstrip('.?!')+'?',
        record_type=atom['observation']['record_type'],guidance=GUIDANCE[group],
        answer_semantics={'yes':'true','no':'false','unknown':'unknown'},
        observation=deepcopy(atom['observation']),
        information_requirement=deepcopy(atom.get('information_requirement')))


def definitions():
    return {p:dict(categories=sorted(PREDICATES[p]),question_type=g,guidance=GUIDANCE[g],
        category_variants={c:dict(question_type=group_for(p,c),guidance=GUIDANCE[group_for(p,c)]) for c in sorted(PREDICATES[p])})
        for g,values in GROUPS.items() for p in values}
