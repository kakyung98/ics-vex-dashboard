"""Five source dimensions: four CVSS concepts plus shared ICS annotations.

Legacy C1--C7 annotations remain readable, but are not generated or silently
converted. OTHER retains operating conditions outside the four main concepts.
"""
from src.item4.analysis import ics_operating_conditions as IC

VERSION = 'item4-source-taxonomy/2'
REFERENCE = 'https://www.first.org/cvss/v4.0/specification-document'
PRIMARY = {
    'AV': 'Attack Vector', 'PR': 'Privileges Required',
    'UI': 'User Interaction', 'AT': 'Attack Requirements',
}
DIMENSIONS = {**PRIMARY, 'IC': 'ICS operating conditions'}
CATEGORIES = {'C0': 'Product applicability', **PRIMARY,
              'OTHER': 'Other or unresolved source condition'}
LEGACY_CATEGORIES = {
    'C0': 'Product applicability', 'C1': 'Vulnerable function availability',
    'C2': 'Attack interface availability', 'C3': 'Attack path access',
    'C4': 'Authentication prerequisite', 'C5': 'Privilege prerequisite',
    'C6': 'Execution and trigger', 'C7': 'Operating state',
}
LEGACY_PREDICATES = {
    'feature_enabled': {'C1', 'C2'}, 'configuration_required': {'C1', 'C2', 'C5', 'C7'},
    'interface_available': {'C2'}, 'interface_reachable': {'C3'}, 'network_reachable': {'C3'},
    'authentication_required': {'C4'}, 'privilege_required': {'C5'},
    'file_import': {'C6'}, 'input_processed': {'C6'}, 'external_file_source': {'C6'},
    'user_performs_action': {'C6'}, 'maintenance_access': {'C3'},
    'remote_maintenance': {'C3'}, 'physical_access': {'C3'}, 'local_console_access': {'C3'},
}

# These are admissible source classifications, not automatic predicate -> metric
# conversions. In particular, an input's availability does not establish AV,
# and an enabled feature does not automatically establish an AT requirement.
ACTIVE_PREDICATES = {
    'feature_enabled': {'AT', 'OTHER'},
    'configuration_required': {'AT', 'PR', 'OTHER'},
    'interface_available': {'OTHER'},
    'interface_reachable': {'AV', 'AT', 'OTHER'},
    'network_reachable': {'AV', 'AT', 'OTHER'},
    'authentication_required': {'PR', 'OTHER'},
    'privilege_required': {'PR', 'OTHER'},
    'file_import': {'UI', 'OTHER'},
    'input_processed': {'AT', 'OTHER'},
    'external_file_source': {'OTHER'},
    'user_performs_action': {'UI', 'OTHER'},
    'maintenance_access': {'AV', 'OTHER'},
    'remote_maintenance': {'AV', 'OTHER'},
    'physical_access': {'AV', 'OTHER'},
    'local_console_access': {'AV', 'OTHER'},
}
PREDICATES = {p: choices | LEGACY_PREDICATES[p]
              for p, choices in ACTIVE_PREDICATES.items()}

EXTRACTION_RULES = '''Classify source facts using these FOUR CVSS v4.0 concepts
and the IC project extension described below (FIVE output dimensions):
AV (Attack Vector): source-described network/adjacent/local/physical attack
access context, not just the existence of an HTTP endpoint or file parser.
PR (Privileges Required): authentication and privileges possessed by the same
attacker BEFORE exploitation; privileges gained by the exploit are an impact.
UI (User Interaction): participation of a person OTHER THAN the attacker;
an attacker uploading a file or sending a request does not establish UI.
AT (Attack Requirements): source-described prerequisite deployment/execution
conditions, e.g. a race or on-path position; never a catch-all for settings.
Feature availability, ports, input formats, ordinary actions or configuration
facts that do not establish one of these concepts stay OTHER, not discarded.
Classify by source meaning, not by predicate name. Category is not evidence
of necessity, sufficient conditions, current deployment truth or a CVSS score.
Keep source-required AND/OR/NOT relations separately and cite their evidence.
Security-mitigation bypass and target-specific secrets concern AC, outside the
four primary groups. Preserve them in excluded_facts with category AC when
not operator-verifiable; do not reclassify them as AT or invent an observation.
Other unobservable source preconditions may be retained in excluded_facts with
reason unobservable_condition and category OTHER or the supported primary
category. Retention does not make these conditions operationally decidable.
Record any retained unobservable prerequisite or uncertain necessary detail in
unknowns/uncertainty_details as a required_condition blocker; never consider
the operational route complete merely because that prerequisite is excluded.
Explicit nonrequirements belong in nonrequirements with their source category;
authentication not required is PR, not a required disabled-authentication state.
Never infer None/Low/High or other metric values from source silence or an
existing CVSS vector. A category not stated in the text remains unknown.
Do not force a condition into each category. Do not output C1--C7 categories.
''' + '\n' + IC.RULES


def accepted_categories():
    """Read old artifacts without asserting a CVSS interpretation for them."""
    return list(CATEGORIES)[1:] + list(LEGACY_CATEGORIES)[1:]


def condition_types():
    """One typed choice replaces two independently generated enum fields."""
    return {category+':'+predicate:dict(category=category,predicate=predicate)
        for predicate,categories in ACTIVE_PREDICATES.items() for category in sorted(categories)}


def bind_type_schema(packet):
    from copy import deepcopy
    wire=deepcopy(packet);item=wire['schema']['properties']['prerequisites']['items']
    item['required']=[k for k in item['required'] if k not in ('predicate','category','vep_category','condition_id')]+['condition_type']
    item['properties'].pop('predicate',None);item['properties'].pop('category',None)
    item['properties'].pop('vep_category',None)
    item['properties'].pop('condition_id',None)
    # The source category is selected once; do not independently generate
    # conflicting legacy AC/AT flags. Saved artifacts can still retain them.
    item['properties'].pop('cvss_metrics',None)
    item['properties']['condition_type']={'enum':list(condition_types())}
    item['properties']['ics_context']=IC.SCHEMA
    item['required'].append('ics_context')
    wire['condition_type_contract']=dict(version=VERSION,
        primary_categories=PRIMARY,extraction_dimensions=DIMENSIONS,
        ics_extension=dict(version=IC.VERSION,kinds=IC.KINDS,shared_atoms=True),
        retained_category='OTHER',reference=REFERENCE,
        meaning='Select a source-supported CVSS concept:predicate pair. Missing categories and deployed values remain unknown; no CVSS scoring.')
    for field in ('nonrequirements', 'excluded_facts'):
        fact=wire['schema']['properties'][field]['items']
        fact['required']=list(dict.fromkeys(fact['required']+['category']))
        fact['properties']['ics_context']=IC.SCHEMA
        fact['required']=list(dict.fromkeys(fact['required']+['ics_context']))
    return wire


def resolve_type(atom):
    if 'condition_type' not in atom:return  # Native/legacy saved artifacts.
    choice=atom.pop('condition_type');registry=condition_types()
    if not isinstance(choice,str) or choice not in registry:raise ValueError('Unknown condition type binding')
    if 'predicate' in atom or 'category' in atom:raise ValueError('Ambiguous condition type binding')
    atom.update(registry[choice])
    # This legacy display label is derived from the chosen predicate. Allowing
    # a separate generated V1 label confuses C1 with product applicability.
    atom.pop('vep_category',None)
    atom.pop('condition_id',None)


def category(atom):
    """Legacy labels can be displayed, but cannot supply missing confidence."""
    if atom.get('category') in CATEGORIES or atom.get('category') in LEGACY_CATEGORIES:
        return atom['category']
    # A predicate alone cannot establish a CVSS category or None requirement.
    return None


def validate(atom):
    if 'category' in atom and atom['category'] not in PREDICATES.get(atom['predicate'], set()):
        raise ValueError('Condition category does not match its operating predicate')
    IC.validate(atom)


def validate_generated(draft):
    """Current inference may not bypass the active schema with old labels."""
    for atom in draft.get('prerequisites', []):
        IC.validate(atom)
        if atom.get('category') not in ACTIVE_PREDICATES.get(atom.get('predicate'), set()):
            raise ValueError('New extraction requires an AV/PR/UI/AT/OTHER condition category')
    for fact in draft.get('excluded_facts', []):
        IC.validate(fact)
        if (fact.get('reason') in {'implementation_defect', 'internal_architecture', 'impact', 'remediation'}
                and fact.get('category') not in (None, 'OTHER')):
            raise ValueError('Defects, architecture, impacts and recommendations cannot establish a CVSS prerequisite category')
    for fact in draft.get('nonrequirements', []):
        IC.validate(fact)


def source_dimensions(draft):
    """Report only explicit annotations; absence is Unknown, never CVSS None."""
    result = {}
    for metric in PRIMARY:
        atoms = [p['id'] for p in draft.get('prerequisites', []) if p.get('category') == metric]
        nonrequirements = [i for i, p in enumerate(draft.get('nonrequirements', [])) if p.get('category') == metric]
        retained = [i for i, p in enumerate(draft.get('excluded_facts', [])) if p.get('category') == metric]
        result[metric] = dict(status='stated' if atoms or nonrequirements or retained else 'unknown',
            condition_ids=atoms, nonrequirement_indices=nonrequirements,
            retained_fact_indices=retained, metric_value=None)
    result['IC']=IC.dimension(draft)
    return result
