"""Research fields from the user-supplied 2026-11-19 VEP specification.

Categories describe a source condition, never create one from an asset/NIST tag.
"""
from copy import deepcopy

CATEGORIES={
 'V1':'Product Applicability','V2':'Vulnerable Function Availability',
 'V3':'Attack Interface Availability','V4':'Attack Path Reachability',
 'V5':'Authentication Prerequisite','V6':'Privilege Prerequisite',
 'V7':'Execution and Trigger Conditions'}
PREDICATE_CATEGORY={
 'feature_enabled':'V2','configuration_required':'V2',
 'interface_available':'V3',
 'interface_reachable':'V4','network_reachable':'V4','on_path_access':'V4',
 'physical_access':'V4','local_console_access':'V4','maintenance_access':'V4','remote_maintenance':'V4',
 'authentication_required':'V5','attacker_authenticated':'V5',
 'privilege_required':'V6','attacker_has_required_privilege':'V6',
 'file_import':'V7','input_processed':'V7','external_file_source':'V7',
 'user_performs_action':'V7','adversary_can_write':'V7','custom':'V7'}
STATES={'true':'satisfied','false':'unsatisfied','unknown':'unknown'}


def enrich(draft):
    result=deepcopy(draft)
    result.setdefault('excluded_facts',[])
    for item in result['prerequisites']:
        item.setdefault('condition_id',item['id'])
        item.setdefault('vep_category',PREDICATE_CATEGORY[item['predicate']])
        item.setdefault('operator','eq');item.setdefault('expected',True)
        item.setdefault('necessity','required')
        item.setdefault('evidence_directness','direct_evidence')
        item.setdefault('review_status','pending')
    return result


def dimensions(*,version,product_ok,scope_ok,conflict,runtime_matches_bom,formula_value,
               final_status,coverage_complete,unresolved=(),deployed='unknown'):
    ready=scope_ok and product_ok and runtime_matches_bom and not conflict
    applicability='conflicting' if conflict or version=='conflicting' else (
        'applicable' if ready and version=='vulnerable' else
        'not_applicable' if ready and version in ('fixed','unaffected') else 'unknown')
    prerequisite=STATES[formula_value] if ready and version=='vulnerable' else 'unknown'
    deployment=('not_applicable' if applicability=='not_applicable' or (ready and deployed=='false') else
        'under_investigation' if deployed!='true' else
        'conditions_satisfied' if prerequisite=='satisfied' else
        'known_paths_blocked' if prerequisite=='unsatisfied' else 'under_investigation')
    return dict(product_applicability=applicability,prerequisite_status=prerequisite,
        deployment_exploitability=deployment,product_vex_status=final_status,
        path_coverage_complete=bool(coverage_complete),unknown_conditions=list(unresolved),
        interpretation='Known source prerequisites, not proof of exploit success or absence of other paths')
