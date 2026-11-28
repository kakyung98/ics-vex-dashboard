"""Source-preserving CVSS question selection and three-valued route evaluation."""
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
import hashlib
import json
import re
from itertools import combinations

ROOT=Path(__file__).resolve().parents[3]
SCHEMA=json.loads((ROOT/'src/item4/assets/cvss_common_question_schema.json').read_text(encoding='utf-8'))
VERSION=SCHEMA['version']
NETWORK_ZONES={'same_zone':'Same OT network zone','it_zone':'Business or IT network',
               'internet':'Internet','remote_maintenance':'Remote maintenance or VPN'}


def network_question(question):
    """Record observed paths, never a predicted attacker location."""
    q=deepcopy(question)
    if q.get('answer_type')=='network_reachability':return q
    q.update(answer_type='network_reachability',access_zones=[dict(code=k,label=v) for k,v in NETWORK_ZONES.items()],
             label='What do current records show about access to the affected interface?',
             yes_criterion='Existing successful-connection records confirm the source-required access type to the actual affected interface from at least one selected zone. An allow rule alone is insufficient.',
             no_criterion='Complete current records verify blocked access for all listed zones and every CVE-relevant interface and path. Partial rules or missing connection logs do not establish blocked access.',
             evidence_guidance='Use the CVE description to identify the affected interface. Report current firewall/VPN rules or existing successful-connection records for that interface and protocol. Do not predict attacker location, assess an exploit path, run an exploit or initiate a new network test. Allow rules alone leave actual reachability Unknown; unselected zones remain Unknown.')
    if question.get('condition_id'):q['source_access_fact']=question.get('label',question['condition_id'])
    if q['cvss_value']=='A':
        q['evidence_guidance']+=' AV:A requires the source-described adjacent access; routed connectivity alone does not establish adjacency.'
    q['options']=[dict(code='unknown',label='Unknown / no current record'),dict(code='x',label='Complete current records verify blocked access across all listed zones'),
                  dict(code='mixed',label='Conflicting records'),dict(code='not_applicable',label='Not applicable / unresolved interface')]
    for size in range(1,len(NETWORK_ZONES)+1):
        for zones in combinations(NETWORK_ZONES,size):
            q['options'].append(dict(code='zones:'+','.join(zones),label='Existing successful connections from: '+', '.join(NETWORK_ZONES[z] for z in zones)))
            q['options'].append(dict(code='allowed:'+','.join(zones),label='Rules allow connections from: '+', '.join(NETWORK_ZONES[z] for z in zones)))
    return q


def answer_state(question,value):
    if question.get('answer_type')=='network_reachability':
        allowed={o['code'] for o in question['options']}
        return 'true' if isinstance(value,str) and value in allowed and value.startswith('zones:') else 'false' if value=='x' else 'unknown'
    return {'o':'true','x':'false'}.get(value,'unknown')
VALUES={'3.0':dict(AV='NALP',PR='NLH',UI='NR',AC='LH'),
        '3.1':dict(AV='NALP',PR='NLH',UI='NR',AC='LH'),
        '4.0':dict(AV='NALP',PR='NLH',UI='NPA',AC='LH',AT='NP')}


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False).encode()).hexdigest()


def parse_vector(vector):
    parts=str(vector).split('/');version=parts[0].removeprefix('CVSS:')
    if not parts[0].startswith('CVSS:') or version not in VALUES:raise ValueError('Unsupported versioned CVSS vector')
    fields={}
    for token in parts[1:]:
        pair=token.split(':')
        if len(pair)!=2 or not all(pair) or pair[0] in fields:raise ValueError('Malformed or duplicate CVSS metric')
        fields[pair[0]]=pair[1]
    if version!='4.0' and 'AT' in fields:raise ValueError('AT is not defined before CVSS 4.0')
    for key,allowed in VALUES[version].items():
        if fields.get(key) not in allowed:raise ValueError('Missing or invalid CVSS metric: '+key)
    return version,{key:fields[key] for key in VALUES[version]}


@lru_cache(maxsize=32)
def year_index(year):
    path=ROOT/f'site/item4-cvss-data/{year}.js'
    if not path.is_file():return {}
    raw=path.read_text(encoding='utf-8')
    match=re.search(r"window\.cvssYears\['\d{4}'\]\s*=\s*(\{.*\});?\s*$",raw,re.S)
    return json.loads(match[1]) if match else {}


@lru_cache(maxsize=256)
def document(path):
    raw=path.read_bytes()
    return json.loads(raw),hashlib.sha256(raw).hexdigest()


def lookup(cve):
    """Read published vectors; verify each source pointer against its local owner."""
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):return []
    row=year_index(cve.split('-')[1]).get(cve,{})
    assessments=[]
    for entry in row.get('a',[]):
        try:
            aid=entry['s'];pointer=entry['ptr'];vector=entry['raw']
            if not re.fullmatch(r'icsa-[a-z0-9-]+',aid):continue
            path=ROOT/'data/cisa_identification_csaf'/f'{aid}.json'
            value,sha=document(path)
            parts=pointer.strip('/').split('/')
            if parts[0]!='vulnerabilities' or value['vulnerabilities'][int(parts[1])].get('cve')!=cve:continue
            node=value
            for part in parts:node=node[int(part)] if isinstance(node,list) else node[part]
            if node['vectorString']!=vector:continue
            version,metrics=parse_vector(vector)
            source=dict(id='cvss:'+digest([cve,aid,pointer,vector]),quote=vector,
                url='https://www.cisa.gov/news-events/ics-advisories/'+aid,
                source_file=path.relative_to(ROOT).as_posix(),source_pointer=pointer+'/vectorString',document_sha256=sha)
            assessments.append(dict(id=source['id'],version=version,vector=vector,metrics=metrics,
                product_ids=entry.get('p',[]),advisory_id=aid,source=source,product_binding='unresolved'))
        except (OSError,ValueError,KeyError,IndexError,TypeError):
            continue
    return assessments


def select_assessments(result):
    rows=deepcopy(result.get('cvss_assessments',[]))
    matches=result.get('advisory_context',{}).get('matches',[])
    aids={m.get('advisory_id') for m in matches if m.get('version_membership')!='false'}
    # A product-bound advisory narrows source context; a shared CVE alone does not.
    selected=[r for r in rows if r.get('advisory_id') in aids] if aids else rows
    return selected or rows


def mandatory_positive(expression):
    if 'condition' in expression:return {expression['condition']}
    parts=[mandatory_positive(a) for a in expression.get('args',[])]
    if expression.get('op')=='not':return set()
    return set().union(*parts) if expression.get('op')=='and' else set.intersection(*parts) if parts else set()


def build(case,result,asset_type_id=None,source_questions=()):
    questions={};routes=[];gaps=[]
    scenarios=(result.get('prerequisite') or {}).get('draft',{}).get('scenarios',[])
    required=set.intersection(*(mandatory_positive(s['expression']) for s in scenarios)) if scenarios else set()
    for assessment in select_assessments(result):
        try:version,metrics=parse_vector(assessment['vector'])
        except (KeyError,ValueError):continue
        terms=[]
        for axis in ('AV','PR','UI'):
            value=metrics[axis]
            if axis in ('PR','UI') and value=='N':continue
            key='cvss_'+axis.lower()+'_'+value.lower()
            qid='common-'+digest([case['id'],axis,value])[:24]
            compatible=[q for q in source_questions if q.get('common_candidate')==(axis,value)
                        and q.get('condition_id') in required
                        and (axis!='AV' or q.get('observation',{}).get('quantifier','single')=='single')]
            if len(compatible)==1:
                q=deepcopy(compatible[0]);qid=q['id'];q.update(question_group='cvss_common',cvss_axis=axis,cvss_value=value)
                questions[qid]=q
            if qid not in questions:
                if axis=='AV':
                    channel=SCHEMA['metrics']['AV'][value]
                    label=f'Is the CVE-required {channel} access possible under the current operating configuration?'
                    yes='The required interface and access path are confirmed reachable in this assessment scope.'
                    no='Every interface and path relevant to this CVE is verified inaccessible under the current operating configuration. Incomplete coverage is unknown.'
                    check='Check the CVE target interface against current network rules, local-access records or physical-access controls, as applicable.'
                elif axis=='PR':
                    level='low' if value=='L' else 'high'
                    label=f'Do current access-control or incident records confirm an unauthorized identity has the required {level} privileges on this component?'
                    yes='Current records confirm the required privileges are available to an unauthorized identity on this component. Ordinary service-account privileges alone are insufficient.'
                    no='The assessed actor is confirmed unable to use the required privileges throughout this scope. Unknown credential possession is unknown.'
                    check='Use current access-control or incident records. Do not guess attacker credentials. Merely requiring login, or having an administrator/service account, does not establish unauthorized privilege possession. Missing records remain Unknown.'
                else:
                    action={'R':'required','P':'passive','A':'active'}[value]
                    label='Is the user interaction required by this CVE possible?' if value=='R' else f'Is the {action} user interaction required by this CVE possible?'
                    yes='The specific user action in the CVE is permitted or possible in the assessed workflow.'
                    no='Enforced controls prevent that specific action throughout this scope. No recorded occurrence alone does not establish prevention.'
                    check='Identify the action in the CVE description, then check the operating procedure and enforced controls. If the action is unspecified, answer unknown.'
                questions[qid]=dict(id=qid,key=key,label=label,case_id=case['id'],cve=case['cve'],
                    component_ref=case['declared_ref'],asset_type_id=asset_type_id,
                    question_group='cvss_common',cvss_axis=axis,cvss_value=value,scope_kind=SCHEMA['metrics'].get(axis,{}).get(value,value),
                    scope_id='cvss:'+digest([case['id'],axis,value]),binding='cvss_assessment_context',
                    yes_criterion=yes,no_criterion=no,evidence_guidance=check,
                    source_refs=[],answer_type='single_choice',default='unknown',
                    options=[dict(code=k,label=v) for k,v in [('unknown','Unknown'),('o','o · Yes'),('x','x · No'),('not_applicable','Not applicable'),('mixed','Conflicting records')]],
                    provenance='operator_attestation_not_independently_verified')
            if axis=='AV' and value in ('N','A'):
                questions[qid]=network_question(questions[qid])
            source=assessment.get('source',{})
            key='cvss_source_refs' if questions[qid].get('condition_id') else 'source_refs'
            questions[qid].setdefault(key,[])
            if source not in questions[qid][key]:questions[qid][key].append(source)
            terms.append(dict(condition=qid))
        for axis,value in [('AC','H'),('AT','P')]:
            if metrics.get(axis)==value:
                from src.item4.decision.condition_logic_evaluation import leaves
                mapping={q['condition_id']:q['id'] for q in source_questions if axis in q.get('cvss_metrics',[])}
                def convert(node):
                    return dict(condition=mapping[node['condition']]) if 'condition' in node else dict(op=node['op'],args=[convert(a) for a in node['args']])
                if scenarios and all(leaves(s['expression'])<=set(mapping) for s in scenarios):
                    alternatives=[convert(s['expression']) for s in scenarios]
                    terms.append(alternatives[0] if len(alternatives)==1 else dict(op='or',args=alternatives))
                    continue
                linked=[q for q in source_questions if axis in q.get('cvss_metrics',[])
                        and q.get('condition_id') in required]
                if linked:
                    terms.extend(dict(condition=q['id']) for q in linked)
                    continue
                # Never invent an operational fact for a coarse complexity flag.
                gap='cvss-gap:'+digest([case['id'],assessment['id'],axis])[:24]
                terms.append(dict(condition=gap))
                gaps.append(dict(id=gap,kind='required_condition',axis=axis,
                    reason=f'{axis}:{value} requires source-specific evidence; the vector does not specify an observable setting.',
                    source_refs=[assessment.get('source',{})]))
        expression=terms[0] if len(terms)==1 else dict(op='and',args=terms)
        routes.append(dict(id=assessment['id'],expression=expression,vector=assessment['vector'],
            version=version,metrics=metrics,product_ids=assessment.get('product_ids',[]),source=assessment.get('source',{})))
    expression=(routes[0]['expression'] if len(routes)==1 else dict(op='or',args=[r['expression'] for r in routes])
                if routes else dict(condition='cvss-missing:'+case['id']))
    if not routes:gaps.append(dict(id=expression['condition'],kind='required_condition',
                                  reason='No verified supported CVSS assessment is available.',source_refs=[]))
    return dict(version=VERSION,case_id=case['id'],cve=case['cve'],questions=list(questions.values()),routes=routes,
                expression=expression,gaps=gaps,coverage_complete=False,
                source_condition_ids=[q['id'] for q in source_questions])


def evaluate(plan,answers):
    from src.item4.decision.condition_logic_evaluation import logic
    states={q['id']:answer_state(q,answers.get(q['id'])) for q in plan['questions']}
    states.update({qid:{'o':'true','x':'false'}.get(answers.get(qid),'unknown') for qid in plan.get('source_condition_ids',[]) if qid not in states})
    value=logic(plan['expression'],states)
    return dict(value=value,status={'true':'requirements_met','false':'known_routes_blocked','unknown':'unknown'}[value],
        condition_values=states,coverage_complete=False,
        observed_access_zones={q['id']:answers.get(q['id'],'unknown').removeprefix('zones:').split(',')
            for q in plan['questions'] if q.get('answer_type')=='network_reachability' and answer_state(q,answers.get(q['id']))=='true'},
        allowed_zones_not_verified_reachable={q['id']:answers[q['id']].removeprefix('allowed:').split(',')
            for q in plan['questions'] if q.get('answer_type')=='network_reachability' and str(answers.get(q['id'],'')).startswith('allowed:')},
        note='CVSS requirements only; no exploit success or product non-impact conclusion.')
