"""Loss-limited rendering of model-proposed atoms and independent admission.

No conditions, confidence, access assumptions or Boolean operators are inferred.
Presentation changes are recorded; qualified statements are not simplified.
"""
from copy import deepcopy
import re

VERSION='item4-condition-normalization/4'
SCOPE=re.compile(r'\b(?:only|when|unless|during|while|if|from|between|behind|authenticated|authorized|privileged|each|every|all|not|without|versions?|before|after|prior|except|users?|operators?|administrators?|sessions?|credentials?)\b',re.I)
ATTACK_PURPOSE=re.compile(r'\b(?:for exploitation|for (?:brute[ -]force )?attacks?|due to .*(?:vulnerab|csrf|restriction))',re.I)


def plain(text):return re.sub(r'\s+',' ',text).strip()


def named_target(target):
    return re.sub(r'(?:\s+(?:request\s+input|input\s+interface|interface|input|endpoint|service))+$','',target.strip(),flags=re.I)


def target_present(target,text):
    name=named_target(target)
    return bool(name and re.search(r'(?<!\w)'+re.escape(name)+r'(?!\w)',text,re.I))


def input_route(text,target):
    """A cited component label/static artifact is not a running attack input."""
    if not target_present(target,text):return False
    dynamic=re.search(r'\b(?:requests?|connections?|login|traffic|brute[ -]forc\w*|csrf|links?|'
        r'inputs?|receiv\w*|transmi\w*|send\w*|via|through|GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b',text,re.I)
    monitor=re.search(r'\b(?:use|using)\s+(?:the\s+)?'+re.escape(named_target(target)),text,re.I)
    return bool(dynamic or monitor)


def normalize_atom(atom):
    """Render a presentation error only; preserve target, value and qualifiers."""
    out=deepcopy(atom);changes=[];original=deepcopy(atom)
    statement=out.get('statement','');predicate=out.get('predicate')
    if predicate=='configuration_required':
        target=out.get('target','');quote=out.get('operational_quote','')
        literal_default=re.fullmatch(r'(.+?) allows (?:for )?plaintext transmission \('+re.escape(target)+r'\) of (.+?) by default\.?',quote,re.I) if target else None
        if (literal_default and statement.rstrip('.').casefold()==quote.rstrip('.').casefold() and
                str(out.get('value','')).casefold() in {'plaintext','unencrypted'}):
            # Render the already selected protocol variable. Do not assert that
            # the vendor default is deployed; V3 still asks its actual value.
            out['statement']=literal_default[1]+' uses '+target+' to transmit '+literal_default[2]+'.'
            out['observation']=dict(kind='configuration',record_type='configuration_export',
                check='Inspect current applied '+target+' transport settings for '+literal_default[1]+'. Leave Unknown if actual use for '+literal_default[2]+' cannot be verified.')
            changes.append('render_proposed_protocol_variable_from_literal_default_without_assuming_deployment')
        # The model has already selected the transport variable. Render that
        # variable, never its unanswered deployed value. Keep the entire source
        # subject/version/operation scope; require literal evidence for it.
        match=re.fullmatch(r'(?:The )?current transport used by (.+?) is unknown\.?',statement,re.I)
        if match and target:
            subject=match[1];parts=re.split(r'\s+for\s+',subject,maxsplit=1,flags=re.I)
            protocol=(re.search(r'\('+re.escape(target)+r'\)',quote,re.I) or
                re.search(r'\b(?:plaintext|plain.text|unencrypted)\s+'+re.escape(target)+r'\b',quote,re.I))
            operation=(len(parts)==1 or (re.fullmatch(r'(?:transmitting|sending) (.+)',parts[1],re.I) and
                re.fullmatch(r'(?:transmitting|sending) (.+)',parts[1],re.I)[1].casefold() in quote.casefold() and re.search(r'\b(?:transmi\w*|send\w*)\b',quote,re.I)))
            if (protocol and operation and plain(parts[0]).casefold() in plain(quote).casefold() and
                    re.search(r'\b(?:plaintext|plain.text|unencrypted)\b',quote,re.I)):
                out['statement']=target+' is used by '+subject+'.'
                changes.append('render_source_proposed_transport_variable_without_assigning_its_value')
                obs=deepcopy(out.get('observation') or {})
                obs.update(kind='configuration',record_type='configuration_export',
                    check='Inspect the current applied transport configuration for '+subject+'. Leave Unknown if actual use of '+target+' cannot be verified.')
                out['observation']=obs
    if predicate=='interface_available':
        # This is the boolean variable already proposed by the model, not a
        # claim that its deployed value is true. Never remove scope qualifiers.
        if (re.search(r'\b(?:is|are)\s+available\b',statement,re.I) and
                ATTACK_PURPOSE.search(statement) and not SCOPE.search(statement)):
            out['statement']='The '+out['target']+' input is available.'
            changes.append('render_input_availability_without_attack_purpose')
        # A plan for checking a current value is not a factual source claim.
        # Vendor documentation alone cannot prove that deployed value.
        obs=deepcopy(out.get('observation') or {})
        obs.update(kind='service_inventory',record_type='service_inventory',
            check='Inspect current service inventory and applied configuration for '+out['target']+
                  ' on the assessed asset and scope. Record Unknown if current availability cannot be established.')
        if obs!=out.get('observation'):
            out['observation']=obs;changes.append('current_operating_record_plan')
    elif predicate=='privilege_required':
        match=re.fullmatch(r'(?:An?|The) attacker with permission to (.+?) is required to exploit (?:the )?vulnerability\.?',statement,re.I)
        if match and not re.search(r'\b(?:or|unless|only|not)\b',match[1],re.I):
            action=match[1].rstrip('.')
            if any(plain(action).casefold() in plain(r.get('quote','')).casefold() for r in out.get('source_refs',[])):
                out['statement']='The assessed principal has permission to '+action+'.'
                changes.append('render_same_principal_permission_without_metalinguistic_wrapper')
    elif predicate=='user_performs_action':
        base=re.split(r'\s+that\s+tricks?\s+(?:the\s+)?(?:web\s+)?browser\s+into\b',out['statement'],maxsplit=1,flags=re.I)
        if len(base)==2:
            out['statement']=base[0].rstrip('.')+'.';changes.append('separate_action_from_browser_attack_effect')
        obs=deepcopy(out.get('observation') or {})
        if obs.get('record_type')=='vendor_documentation':
            obs.update(kind='operating_workflow',record_type='operating_event_log',
                check='Inspect available user/browser event records for the same source-qualified actor and action. Leave Unknown if occurrence or the specified link/file properties cannot be verified.')
            out['observation']=obs;changes.append('current_event_record_plan')
        match=re.fullmatch(r'((?:The|A|An) (?:user|operator|administrator)\b.+?|(?:The|A|An) (?:user|operator|administrator))\s+(?:must|has to|needs to)\s+(follow|click|open|import|visit)\s+(.+)',out['statement'],re.I)
        if match:
            out['statement']=match[1]+' '+match[2].lower()+'s '+match[3]
            changes.append('render_qualified_user_action_without_modal_requirement')
    receipt=dict(condition_id=atom.get('id'),changes=changes,
        original_statement=original.get('statement'),statement=out.get('statement'),
        original_observation=original.get('observation'),observation=out.get('observation')) if changes else None
    return out,receipt


def align_input_quote(atom,sources):
    """Select another literal span only inside already cited source paragraphs."""
    if atom.get('predicate')!='interface_available':return atom,None
    from src.item4.analysis.operational_evidence_catalogue import catalogue
    from src.item4.analysis.operator_verifiable_conditions import DEFECT
    if target_present(atom['target'],atom.get('operational_quote','')) and not DEFECT.search(atom.get('operational_quote','')):
        return atom,None
    candidates=[]
    for i,ref in enumerate(atom.get('source_refs',[])):
        text=sources.get(ref.get('source_id'),{}).get('text','')
        if text.count(ref.get('quote',''))!=1:continue
        for choice in catalogue([dict(evidence_id='cited',source_id=ref['source_id'],quote=ref['quote'])]):
            quote=choice['quote']
            if target_present(atom['target'],quote) and not DEFECT.search(quote) and text.count(quote)==1:
                candidates.append(quote)
    if not candidates:return atom,None
    out=deepcopy(atom);out['operational_quote']=min(candidates,key=len)
    return out,dict(condition_id=atom.get('id'),changes=['literal_quote_alignment_inside_cited_paragraphs'],
        original_quote=atom.get('operational_quote'),quote=out['operational_quote'])


def normalize_draft(draft,record):
    out=deepcopy(draft);receipts=[];sources={s['id']:s for s in record['sources']}
    for i,atom in enumerate(out.get('prerequisites',[])):
        atom,note=align_input_quote(atom,sources)
        if note:receipts.append(note)
        atom,note=normalize_atom(atom)
        if note:receipts.append(note)
        out['prerequisites'][i]=atom
    return out,receipts


def salvage(candidate,record,V):
    """Retain independently valid atoms; never delete an operand as False.

    An unvalidated relation is kept as a global required-condition uncertainty,
    not repaired by choosing AND/OR in code.
    """
    reason='The source-supported relationship or completeness of recovered conditions remains unresolved.'
    result=dict(format=V.VERSION,cve=record['cve'],prerequisites=[],scenarios=[],
        nonrequirements=[],excluded_facts=[],unknowns=[reason])
    accepted=[];rejected=[];seen=set()
    for atom in candidate.get('prerequisites',[]):
        if atom.get('id') in seen:
            rejected.append(dict(condition_id=atom.get('id'),reason='Duplicate condition ID'));continue
        seen.add(atom.get('id'));one=deepcopy(result);one['prerequisites']=[deepcopy(atom)]
        try:V.validate(one,record)
        except Exception as exc:rejected.append(dict(condition_id=atom.get('id'),reason=str(exc)));continue
        accepted.append(deepcopy(atom))
    result['prerequisites']=accepted
    result=V.validate(V.enrich(result),record)
    return result,rejected
