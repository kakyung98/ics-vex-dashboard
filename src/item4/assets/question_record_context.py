"""Asset-specific record candidates, never additional CVE prerequisites."""
from copy import deepcopy
import hashlib
import json
from src.item4.assets.asset_profile_fields import COMMON, PROFILES
from src.item4.assets.operator_asset_form import DEFS

VERSION = 'asset-question-record-context/1'
QUESTION_BINDING_VERSION = 'asset-condition-record-binding/3-information-requirements'
KINDS = {
    'configuration': {'configuration', 'services'},
    'input_availability': {'services', 'configuration'},
    'access_path': {'routes', 'rules'},
    'authentication': {'authentication'},
    'principal_permission': {'authentication'},
    'recorded_action': {'workflows'},
    'physical_access': {'physical'},
    'operating_state': {'mode'},
}
RECORDS = {
    'configuration': 'Current applied configuration export and installed-module inventory',
    'services': 'Current service/interface inventory and applied listener configuration',
    'routes': 'Current routes, connection inventory and scoped access verification records',
    'rules': 'Applied access-control rules, including direction and exceptions',
    'authentication': 'Current interface authentication policy and account/role permission records',
    'workflows': 'Scoped input-processing, import or operating-event records',
    'physical': 'Current physical/local access inspection and maintenance records',
    'mode': 'Current controller mode, applied configuration and timestamped operating records',
}


def signature():
    return hashlib.sha256(json.dumps(dict(version=VERSION, profiles=PROFILES,
        definitions=DEFS, kinds={k:sorted(v) for k,v in KINDS.items()}, records=RECORDS),
        sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def profile_fields(aid, groups):
    if aid not in PROFILES:return []
    kinds = set().union(*(KINDS[g] for g in groups))
    return [dict(key=key, label=key.replace('_', ' '), data_kind=DEFS[key][0],
        evidence_guidance=RECORDS[DEFS[key][0]], source='project_asset_profile',
        applicability='candidate_only_confirm_same_target_and_scope')
        for key in list(COMMON) + PROFILES[aid] if DEFS[key][0] in kinds]


def extraction_context(job, components):
    from src.item4.assets.asset_observations import classifications, catalogue
    types = classifications(job)
    catalog = catalogue()
    definitions = {aid:rows[0] for aid,rows in catalog['asset_types'].items()}
    groups = dict(feature_configuration=['configuration','input_availability'],
                  operating_mode=['operating_state'], engineering_connection=['access_path'])
    return dict(version=VERSION, profile_sha256=signature(), catalogue_sha256=catalog['sha256'], components=[
        dict(component_ref=c['ref'], asset_type_id=types.get(c['ref']) if types.get(c['ref']) in PROFILES else None,
            asset_type_name=definitions.get(types.get(c['ref']),{}).get('asset_name'),
            asset_type_source=definitions.get(types.get(c['ref']),{}).get('source'),
            status='provisional' if types.get(c['ref']) in PROFILES else 'unresolved',
            ics_record_candidates={kind:profile_fields(types.get(c['ref']), values)
                                   for kind,values in groups.items()}) for c in components],
        policy='Use only as IC reading and operator-record context. Extract conditions only '
               'from this CVE scoped source evidence, including ICSA vulnerability details. '
               'Never cite asset types or profiles as prerequisite evidence. Unresolved types '
               'and unmatched fields must not suppress source-supported conditions.')


def bind(question, catalogue_sha256):
    aid = question.get('asset_type_id')
    result = dict(version=QUESTION_BINDING_VERSION, asset_type_id=aid, mode='source_only', fields=[],
        source_observation=deepcopy(question['observation']),
        policy='Record candidates only. Confirm applicability to the exact V2 target and scope; '
               'never infer feature support or state from asset type. Keep unverified answers Unknown.')
    requirement=question.get('information_requirement')
    if requirement:
        result.update(information_requirement_id=requirement['id'],
            verification_plan=deepcopy(requirement['verification']))
    if aid not in PROFILES:
        return result
    definition = question.get('catalogue_definition')
    if definition:
        result.update(mode='catalogue_target', catalogue_sha256=catalogue_sha256,
            fields=[dict(key=definition['key'], label=definition['label'],
                evidence_guidance=definition['evidence_guidance'],
                scope_kind=definition['scope_kind'], source=definition['source'])])
        return result
    if requirement and requirement['question_type'] in {
        'access_path','authentication','principal_permission','operating_state','recorded_action','physical_access','input_availability'}:
        result.update(mode='typed_condition_records',
            fields=[dict(key=requirement['information_key'],label=requirement['label'],
                evidence_guidance=requirement['verification']['instruction'],
                coverage='same_source_condition_record_plan',condition_id=question['condition_id'],
                profile_record_locations=deepcopy(requirement['asset_mapping']['profile_record_locations']))])
    # A shared record kind is not a semantic target match. Keep the source
    # observation instead of listing unrelated fields from the asset profile.
    return result
