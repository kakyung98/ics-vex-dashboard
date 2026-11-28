"""Conservative admission of source-grounded, operator-verifiable prerequisites.

These guards reject known semantic failure modes. They do not certify that an
arbitrary natural-language source has been interpreted completely or correctly.
"""
import re

POLICY = 'operator-verifiable-prerequisites/17'
PREDICATES = {
    'feature_enabled', 'configuration_required', 'interface_available', 'interface_reachable',
    'network_reachable', 'authentication_required', 'privilege_required',
    'file_import', 'input_processed', 'external_file_source',
    'user_performs_action', 'maintenance_access', 'remote_maintenance',
    'physical_access', 'local_console_access',
}
RECORD_TYPES = ['configuration_export', 'firewall_acl', 'asset_inventory',
                'service_inventory', 'operating_procedure', 'maintenance_log',
                'vendor_documentation', 'access_control_record', 'operating_event_log']
OBSERVATION_KINDS = ['configuration', 'network_access', 'service_inventory',
                     'operating_workflow', 'access_policy', 'physical_access', 'operating_mode']
DEFECT = re.compile(
    r'\b(?:fails? to (?:properly )?(?:validat\w*|saniti[sz]\w*|escap\w*|check\w*|enforc\w*|restrict\w*|authenticat\w*)|'
    r'do(?:es)? not (?:properly |correctly )?(?:validat\w*|saniti[sz]\w*|escap\w*|check\w*|enforc\w*|authenticat\w*)|'
    r'(?:improper|insufficient|incorrect|missing|lack of) (?:input |output |bounds? |certificate )?'
    r'(?:validation|saniti[sz]ation|escaping|checks?|access control)|'
    r'buffer overflow|out.of.bounds|use.after.free|memory corruption|'
    r'integrated with node\.?js|heap layout|stack layout|control.flow|internal pointer)\b', re.I)
EXPLICIT = re.compile(
    r'\b(?:requires?|only|when|if|must|provided|configured|enabled|disabled|'
    r'opens?|opening|imports?|importing|uploads?|uploading|connects?|connecting|'
    r'network access|physical access|local access|access to|accessible|exposed|active|listening on|running in)\b', re.I)


class OperationalPrerequisiteError(ValueError):
    pass


NONREQUIREMENT = re.compile(r'\b(?:do(?:es)? not require|requires? no|without requiring)\s+(?:any\s+)?authentication\b',re.I)


def validate_nonrequirement(item):
    """Remote delivery does not prove absence of authentication or interaction."""
    statement=item['statement'].casefold()
    quote=' '.join(ref['quote'] for ref in item['source_refs'])
    topics=[]
    if re.search(r'authenticat|unauthenticated',statement):
        topics.append(r'(?:unauthenticated|without (?:any )?authentication|no (?:prior )?authentication|authentication (?:is |was )?not required|do(?:es)? not require (?:any )?authentication)')
    if re.search(r'privilege',statement):
        topics.append(r'(?:no (?:further |prior )?privileges|without (?:any |prior )?privileges|privileges (?:are |were )?not required|do(?:es)? not require (?:any )?privileges)')
    if re.search(r'user (?:interaction|participation)|no user action',statement):
        topics.append(r'(?:no user (?:interaction|participation|action)|without (?:any )?user (?:interaction|participation)|user (?:interaction|participation) (?:is |was )?not required|do(?:es)? not require (?:any )?user interaction)')
    for pattern in topics:
        if not re.search(pattern,quote,re.I):
            raise OperationalPrerequisiteError('Nonrequirement lacks explicit source support; remote access alone cannot establish authentication, privilege or user-interaction absence')


def validate_condition(item, sources):
    """Reject defect/architecture claims and ambiguous or duplicated polarity."""
    def reject(reason):
        raise OperationalPrerequisiteError('Operational prerequisite rejected: '+reason)
    if item.get('predicate') not in PREDICATES or item.get('operator_observable') is not True:
        reject('the state must be verifiable from operator-accessible records')
    if item.get('operator') != 'eq' or item.get('expected') is not True:
        reject('use a positive atom with operator=eq and expected=true; express negation only in the scenario')
    observation=item.get('observation') or {}
    if (observation.get('kind') not in OBSERVATION_KINDS or
            observation.get('record_type') not in RECORD_TYPES or
            not str(observation.get('check','')).strip()):
        reject('a concrete accessible record and operational check are required')
    quote=item.get('operational_quote','')
    if (re.search(r'\b(?:is|are|remains?)\s+(?:unknown|unverified|undetermined|unspecified|not known|not provided)\b',item.get('statement',''),re.I)
            or str(item.get('value','')).strip().casefold() in {'unknown','unverified','unspecified','not known'}):
        reject('state a positive operating VARIABLE, not the deployed answer Unknown; the actual value is supplied later in V3')
    if not quote or not any(
        quote in ref.get('quote','') and sources.get(ref.get('source_id'),{}).get('text','').count(quote)==1
        for ref in item.get('source_refs',[])):
        reject('the operational prerequisite needs an exact, unique source clause')
    if DEFECT.search(quote) or DEFECT.search(observation['check']):
        reject('implementation defects and internal architecture are not operating prerequisites')
    if NONREQUIREMENT.search(quote):
        reject('an authentication nonrequirement is not a required disabled-authentication setting')
    if re.search(r'\bnot enabled on all\b',quote,re.I) and (
            observation.get('quantifier')!='all' or not re.search(r'\ball\b',item.get('statement',''),re.I)):
        reject('preserve NOT(all enabled); do not rewrite it as all disabled')
    if item['predicate']=='interface_available':
        if re.search(r'\b(?:attacks?|vulnerab\w*|exploitable|csrf|xxe|brute[ -]force|bypass|privileges)\b',
                     item.get('statement','')+' '+observation['check'],re.I):
            reject('interface availability must be an observable input state, not a claim of attack success or vulnerability; keep attack purpose in the source evidence')
        target=item.get('target','').strip()
        # A generic noun suffix does not change the named surface. Preserve
        # qualifiers and protocol boundaries: HTTP is never an alias for HTTPS.
        named=re.sub(r'(?:\s+(?:request\s+input|input\s+interface|interface|input|endpoint|service))+$','',target,flags=re.I)
        if not named or not re.search(r'(?<!\w)'+re.escape(named)+r'(?!\w)',quote,re.I):
            reject('the input interface target must be named exactly in its source clause')
        from src.item4.analysis.source_surface_review import CUES
        if not CUES.search(quote):
            reject('a component name or defect alone does not establish a concrete input route')
        from src.item4.analysis.condition_normalization import input_route
        if not any(input_route(ref['quote'],target) for ref in item.get('source_refs',[])):
            reject('a named static component or firmware artifact does not establish a running input route')
        if not re.search(r'\bavailab(?:le|ility)\b',item.get('statement',''),re.I):
            reject('interface_available must state availability of its named input; a vulnerability description is not that operating fact')
    elif not EXPLICIT.search(quote) and not re.search(r'\b(?:with\s+(?:the\s+)?permission|permission\s+to)\b',quote,re.I) and not (
            item['predicate']=='configuration_required' and
            re.search(r'\b(?:plaintext|plain.text|unencrypted)\b',quote,re.I) and
            re.search(r'\b(?:default|uses?|using|transmission|transmitted)\b',quote,re.I) and
            item.get('target','').casefold() in quote.casefold() and
            observation.get('record_type') in {'configuration_export','service_inventory'}) and not (
            item['predicate']=='user_performs_action' and re.search(r'\b(?:user|operator|administrator)\b[^.!?\n]{0,180}\b(?:follows?|clicks?|visits?)\b',quote,re.I)):
        reject('the source clause does not explicitly support an operating restriction or trigger')
    if item['predicate']=='configuration_required' and re.search(r'\b(?:plaintext|plain.text|unencrypted)\b',quote,re.I) and re.search(r'\bdefault\b',item.get('statement',''),re.I):
        reject('a source default is not the current deployed transport; state the actual transport-use variable and leave its operating value Unknown')
    if item['predicate']=='feature_enabled' and str(item.get('value','')).casefold() not in {'','enabled','true'}:
        reject('feature_enabled must describe the enabled state; disabled belongs in a NOT expression')
    if str(item.get('value','')).strip().casefold() in {
            'disabled','false','off','not enabled','unreachable','unavailable','absent','denied','blocked'}:
        reject('use a positive state for every predicate; required absence belongs only in scenario NOT')
    if re.search(r'\b(?:is|are)\s+(?:disabled|not enabled|unreachable|unavailable|absent|blocked)\b',item.get('statement',''),re.I):
        reject('a negative statement cannot be combined with scenario NOT; regenerate a canonical positive atom')
    if DEFECT.search(item.get('target','')) or DEFECT.search(item.get('statement','')):
        reject('the positive atom must describe an operating state, not a software defect')
    if re.search(r'\bmust\b|\bin order (?:to|for)\b|\b(?:exploitation|exploiting the vulnerability)\b',item.get('statement',''),re.I):
        reject('state an observable current operating fact, not the rule that exploitation requires it; remove must/in-order-to/exploitation wording while retaining the same actor, action, target and qualifiers')
    if re.search(r'\battacker\s+(?:must\s+have|has|needs?)\s+write access to (?:the |a )?directory\b',quote,re.I):
        statement=item.get('statement','')
        if not re.search(r'\b(?:directory|folder)\b',statement,re.I) or not re.search(r'\b(?:attacker|assessed actor)\b',statement,re.I):
            reject('preserve write access by the same assessed attacker to the source directory; file writability or writability by an unspecified user is not that operating fact')
    if item['predicate'] in {'user_performs_action','file_import','input_processed'}:
        qualification=re.search(r'\b(?:user|operator|administrator)\s+with\s+(higher privileges than (?:the )?attacker|administrative privileges)\s+(?:must|has to|needs to)\b',quote,re.I)
        if qualification and qualification[1].casefold() not in item.get('statement','').casefold():
            reject('preserve the same source actor qualification on the action atom: '+qualification[1]+'; independent user/privilege facts cannot establish that the same qualified user performs the action')


def positive_leaf(condition_id, item):
    """One polarity convention at every compiler boundary; no implicit NOT."""
    if item.get('operator','eq')!='eq' or item.get('expected',True) is not True:
        raise OperationalPrerequisiteError('Ambiguous legacy polarity; regenerate the prerequisites')
    return {'condition':condition_id}


def source_polarity(item):
    """Recognize explicit Boolean setting clauses; otherwise preserve unknown."""
    from src.item4.analysis.ics_operating_conditions import polarity_target
    target=re.escape(polarity_target(item)).replace(r'\ ',r'\s+')
    quote=item['operational_quote']
    pattern=rf'(?<!\w){target}(?:\s+(?:service|feature|option))?\s+(?:when\s+)?(?:(?:is|are|was|were|must be|to be|be)\s+)?(enabled|disabled|not enabled|configured|not configured|reachable|unreachable|accessible|available|unavailable|allowed|blocked|present|absent)\b'
    positive={'enabled','configured','reachable','accessible','available','allowed','present'}
    def default_comment(match):
        suffix=quote[match.end():]
        prefix=re.split(r'[.!?\n]',quote[:match.start()])[-1]
        return bool(re.match(r'\s+(?:by default|in the default configuration)\b',suffix,re.I) or
                    re.search(r'\bby default\s*,?\s*$',prefix,re.I))
    values={m[1].casefold() in positive for m in re.finditer(pattern,quote,re.I) if not default_comment(m)}
    if not values and item['predicate']=='feature_enabled':
        coordinated=rf'(?<!\w){target}\s+and\s+[\w .()+/-]{{1,80}}?\s+(enabled|disabled)\b'
        values={m.casefold()=='enabled' for m in re.findall(coordinated,quote,re.I)}
    if not values and item['predicate']=='authentication_required':
        values={m.casefold()=='enabled' for m in re.findall(r'\bauthentication\s+(?:to be |is )?(enabled|disabled)\b',quote,re.I)}
    if not values and item['predicate'] in {'network_reachable','interface_reachable','physical_access','local_console_access'}:
        if re.search(rf'\b(?:network |physical |local )?access to (?:the )?{target}\b',quote,re.I):values={True}
    if len(values)==1:
        result=next(iter(values))
        return not result if re.search(r'\bunless\b',quote,re.I) else result
    if (not values and item['predicate']!='feature_enabled' and
            not re.search(r'\b(?:not|unless|without|disabled|blocked|unreachable|unavailable|absent|denied)\b',quote,re.I)):
        return True
    raise OperationalPrerequisiteError('Operational prerequisite rejected: polarity needs an unambiguous source clause for this operating atom')


def validate_relations(draft):
    by_id={p['id']:p for p in draft['prerequisites']}
    def walk(node,negated=False):
        if 'condition' in node:
            item=by_id[node['condition']];expected=source_polarity(item)
            if expected is not None and expected==negated:
                raise OperationalPrerequisiteError('Operational prerequisite rejected: scenario polarity contradicts the exact source setting clause')
            return
        if node['op']=='and':
            inputs=[by_id[a['condition']] for a in node['args'] if 'condition' in a and by_id[a['condition']]['predicate']=='interface_available']
            for i,left in enumerate(inputs):
                for right in inputs[i+1:]:
                    quote=left['operational_quote']
                    if (left['target']!=right['target'] and quote==right['operational_quote'] and
                            not re.search(r'\b(?:requires?|both|only if|only when|must)\b',quote,re.I)):
                        raise OperationalPrerequisiteError('Operational prerequisite rejected: co-listed input routes do not establish that both must be available; recover the source-supported relation or preserve the missing relation as unknown')
        for child in node['args']:walk(child,not negated if node['op']=='not' else negated)
    for scenario in draft['scenarios']:walk(scenario['expression'])
    if draft.get('scenarios') and not draft.get('unknowns'):
        permission_evidence=any(re.search(r'\bpermission\s+to\b',r['quote'],re.I)
            for p in draft['prerequisites'] for r in p.get('source_refs',[]))
        if permission_evidence and all(p['predicate']=='interface_available' for p in draft['prerequisites']):
            raise OperationalPrerequisiteError('Operational prerequisite rejected: the cited source also states a permission requirement; interface availability alone does not cover it. Extract the same-principal permission condition or record its unresolved requirement explicitly')
