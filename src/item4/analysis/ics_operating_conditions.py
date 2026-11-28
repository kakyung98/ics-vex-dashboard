"""Source-bound ICS annotations on shared atoms; never a fifth CVSS metric.

The model proposes annotations. These checks establish literal binding and
reject known shortcuts, not semantic completeness or actual deployed values.
"""
import re

VERSION = 'item4-ics-operating-conditions/1'
KINDS = {
    'feature_configuration': 'Industrial function or protocol configuration',
    'operating_mode': 'Controller operating mode or physical mode selector',
    'engineering_connection': 'Engineering-to-control device connection',
}
SCHEMA = dict(type='array', maxItems=3, uniqueItems=True, items=dict(
    type='object', additionalProperties=False, required=['kind', 'quote'],
    properties=dict(kind=dict(enum=list(KINDS)), quote=dict(type='string', minLength=1))))

RULES = '''Also extract IC (ICS operating conditions), a PROJECT extension, using
ics_context annotations on the SAME source-supported atoms; never category IC.
Return ics_context=[] when no explicit ICS operating prerequisite is supported.
Each annotation has kind and quote, an exact contiguous clause within that
atom's operational_quote (or its source_refs for a retained/nonrequirement fact).
Use the exact target name in operational_quote; do not append 'function',
'service' or 'interface' when that word is absent from the selected clause.
Split 'enabled and configured' into two positive atoms sharing the source quote;
the AND belongs in the scenario, never hidden inside one positive statement.
feature_configuration: the enabled/configured state of a named INDUSTRIAL
function or protocol, not ordinary HTTP/FTP availability on an ICS-branded host.
operating_mode: an explicitly relevant controller mode or physical mode selector
state. A diagnostic function named Monitor Mode alone is not a controller mode.
engineering_connection: a specific source-required engineering workstation /
control-device connection or pairing, not generic network reachability.
Read all CVE-bound source passages, including ICSA vulnerability details. Product
labels, sectors, countries, safety impact and generic hardening advice supply no
prerequisites. Never invert 'avoid PROGRAM mode' into 'PROGRAM is required'.
CVE Description may also supply IC evidence; ICSA is not an exclusive source.
Do not transfer another CVE's conditions or a shared advisory recommendation.
Do not infer a deployed value from BOM membership, defaults or supported modes.
When asset_type_context is supplied, use its component-scoped V1 asset types and
ics_record_candidates to guide reading of this CVE's ICSA vulnerability details
and to describe accessible observation records for IC. Profiles are provisional
context only, never source evidence or a list of required features. They cannot
establish a prerequisite, its necessity, polarity, or actual deployed state.
Keep extracting explicit source-supported IC conditions when the asset type is
unresolved, the profile has no matching field, or multiple asset types are present.
Do not transfer one component's type or operating facts to another component.
IC can overlap AV/PR/UI/AT: retain the supported CVSS category or OTHER, annotate
the shared atom once, and reference that same ID in source-supported scenarios.
IC is not a new AND leaf, proof of necessity, coverage, or exploit success.
'''

_INDUSTRIAL = re.compile(r'\b(?:modbus|profinet|profibus|ethernet/ip|cip|dnp3|'
    r'iec[ -]?(?:60870|61850)|opc(?:[ -]ua)?|s7comm|fins|bacnet|'
    r'plcs?|rtus?|controllers?|scada|hmi|industrial|control[ -](?:system|logic|function)|'
    r'engineering|tristation)\b', re.I)
_MODE = re.compile(r'\b(?:mode|key[ -]?switch|selector|position)\b', re.I)
_ENGINEERING = re.compile(r'\b(?:engineering|programming|tristation)\b', re.I)
_CONNECTION = re.compile(r'\b(?:connect\w*|pair\w*|link\w*|dedicated|channel)\b', re.I)
_CONTROL = re.compile(r'\b(?:plcs?|rtus?|controllers?|control[ -]devices?|safety[ -]systems?)\b', re.I)
_FUNCTION = re.compile(r'\b(?:modbus|profinet|profibus|ethernet/ip|cip|dnp3|'
    r'iec[ -]?(?:60870|61850)|opc(?:[ -]ua)?|s7comm|fins|bacnet|'
    r'(?:industrial|control|safety)[ -](?:function|protocol)|'
    r'(?:logic|program|firmware)[ -](?:download|upload|update|write))\b', re.I)
_ADVICE = re.compile(r'\b(?:should|recommend\w*|advis\w*|never leave|avoid|best practices?)\b', re.I)
_STATE = re.compile(r'\b(?:enabl\w*|configur\w*|activ\w*|available|running|mode|'
    r'connect\w*|pair\w*|requires?|only|when|while|if)\b', re.I)
_COMPOUND_STATE = re.compile(r'\b(?:enabled|disabled|configured|connected|paired)\s+'
    r'(?:and|or)\s+(?:enabled|disabled|configured|connected|paired)\b',re.I)
_PREDICATES = {
    'feature_configuration': {'feature_enabled', 'configuration_required', 'interface_available'},
    'operating_mode': {'configuration_required', 'feature_enabled'},
    'engineering_connection': {'configuration_required', 'interface_reachable',
                               'network_reachable', 'maintenance_access', 'remote_maintenance'},
}


def validate(item):
    annotations = item.get('ics_context', [])
    if not isinstance(annotations, list) or len(annotations) > 3:
        raise ValueError('IC annotations must be a bounded list')
    seen = set()
    for annotation in annotations:
        if not isinstance(annotation, dict) or set(annotation) != {'kind', 'quote'}:
            raise ValueError('IC annotation requires kind and an exact quote')
        kind, quote = annotation['kind'], annotation['quote']
        if kind not in KINDS or kind in seen:
            raise ValueError('Unknown or duplicate IC kind on a shared atom')
        seen.add(kind)
        parents = ([item['operational_quote']] if item.get('operational_quote') else
                   [r.get('quote', '') for r in item.get('source_refs', [])])
        if not isinstance(quote, str) or not quote or not any(quote in p for p in parents):
            raise ValueError('IC quote must be literal within the condition evidence')
        if item.get('reason') in {'impact', 'remediation', 'implementation_defect', 'internal_architecture'}:
            raise ValueError('IC cannot turn impacts, defects or recommendations into conditions')
        if _ADVICE.search(quote) or not _INDUSTRIAL.search(quote) or not _STATE.search(quote):
            raise ValueError('IC requires an explicit ICS operating clause, not advice or a product label')
        if 'predicate' in item and item['predicate'] not in _PREDICATES[kind]:
            raise ValueError('IC kind is incompatible with the shared operating atom')
        if 'predicate' in item and _COMPOUND_STATE.search(item.get('statement','')):
            raise ValueError('IC requires separate atomic operating states; keep AND/OR in scenario logic')
        if kind == 'feature_configuration' and not _FUNCTION.search(quote):
            raise ValueError('IC function requires an industrial function clause, not a generic surface on a PLC')
        if kind == 'operating_mode' and not (_MODE.search(quote) and _CONTROL.search(quote)):
            raise ValueError('IC operating mode needs an explicit mode or selector clause')
        if kind == 'engineering_connection' and not (_ENGINEERING.search(quote) and _CONNECTION.search(quote) and _CONTROL.search(quote)):
            raise ValueError('IC engineering connection needs an explicit engineering link clause')


def dimension(draft):
    atoms = [p['id'] for p in draft.get('prerequisites', []) if p.get('ics_context')]
    nonrequirements = [i for i, p in enumerate(draft.get('nonrequirements', [])) if p.get('ics_context')]
    retained = [i for i, p in enumerate(draft.get('excluded_facts', [])) if p.get('ics_context')]
    return dict(status='stated' if atoms or nonrequirements or retained else 'unknown',
                condition_ids=atoms, nonrequirement_indices=nonrequirements,
                retained_fact_indices=retained, metric_value=None,
                project_extension=True, annotation_field='ics_context')


def hints(record):
    """Ask the model to reread explicit clauses; never manufacture annotations."""
    result=[]
    for source in record.get('sources', []):
        a,b=source.get('cve_scope_span',[0,len(source['text'])])
        for quote in re.split(r'(?<=[.!?;])\s+|\n+',source['text'][a:b]):
            quote=quote.strip()
            if not quote or _ADVICE.search(quote) or not _STATE.search(quote):continue
            kinds=[]
            if _FUNCTION.search(quote):kinds.append('feature_configuration')
            if _CONTROL.search(quote) and _MODE.search(quote):kinds.append('operating_mode')
            if _CONTROL.search(quote) and _ENGINEERING.search(quote) and _CONNECTION.search(quote):
                kinds.append('engineering_connection')
            for kind in kinds:
                result.append(dict(kind='ics_'+kind,source_id=source['id'],quote=quote))
    return result


def covers(atom,hint):
    kind=hint['kind'].removeprefix('ics_')
    return (any(r.get('source_id')==hint['source_id'] for r in atom.get('source_refs',[])) and
            any(c['kind']==kind and (c['quote'] in hint['quote'] or hint['quote'] in c['quote'])
                for c in atom.get('ics_context',[])))


def polarity_target(item):
    """Resolve a generic noun omitted in a clause, only with same-parent proof.

    Keep the saved target unchanged. This is neither a vendor alias lookup nor
    permission to infer a function, condition, polarity or deployed value.
    """
    target=item['target'];quote=item.get('operational_quote','')
    if not any(c['kind']=='feature_configuration' for c in item.get('ics_context',[])):
        return target
    short=re.sub(r'\s+(?:function|service|feature|option)$','',target,flags=re.I)
    if short==target:return target
    literal=lambda name,text:bool(re.search(r'(?<!\w)'+re.escape(name)+r'(?!\w)',text,re.I))
    if (not literal(target,quote) and literal(short,quote) and
            any(literal(target,r.get('quote','')) and quote in r.get('quote','')
                for r in item.get('source_refs',[]))):
        return short
    return target
