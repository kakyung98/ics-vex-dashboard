"""CVE/product/path extraction and scoped Vulntology-based VEX review.

Asset labels route browsing only. Source clauses are proposals until a named
reviewer checks their meaning; no model or asset label supplies missing facts.
"""
from copy import deepcopy
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import uuid

from src.item4.decision.condition_logic_evaluation import evaluate_review; from src.item4.decision.condition_logic_evaluation import leaves; from src.item4.decision.condition_logic_evaluation import validate_review
from src.item4.analysis.source_condition_logic import infer_record

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / 'results/item4_asset_vulntology_v1'
if not (DATA/'catalogue.json').is_file() and (ROOT/'site/asset_vulntology/catalogue.json').is_file():
    DATA = ROOT/'site/asset_vulntology'
VERSION = 'asset-vulntology-vex/1'
SCHEMA_SHA = 'fc2b278520b7035f5951b3b9e7a15d72a32735930ac86ab4dc41aac21f5ae0e8'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


@lru_cache(maxsize=1)
def catalogue():
    return json.loads((DATA/'catalogue.json').read_text(encoding='utf-8'))


@lru_cache(maxsize=1)
def advisory_groups():
    """Advisory-first browsing metadata; never changes CVE evidence or decisions."""
    return json.loads((ROOT/'site/asset_vulntology/icsa_role_groups.json').read_text(encoding='utf-8'))


@lru_cache(maxsize=1)
def asset_navigation():
    return json.loads((ROOT/'site/asset_vulntology/icsa_asset_navigation.json').read_text(encoding='utf-8'))


@lru_cache(maxsize=4)
def shard(year):
    if not re.fullmatch(r'\d{4}', year):
        raise ValueError('Invalid CVE year')
    path = DATA/f'records_{year}.json'
    return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else {}


def detail(cve):
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve):
        raise ValueError('Invalid CVE ID')
    value = shard(cve.split('-')[1]).get(cve)
    if value is None:
        raise KeyError('CVE not in the fixed 12,418-CVE population')
    if digest({k:v for k,v in value.items() if k!='record_digest'})!=value['record_digest']:
        raise ValueError('CVE scenario snapshot integrity check failed')
    return deepcopy(value)


def search(asset='', q='', offset=0, limit=40):
    if asset and asset != 'unassigned' and asset not in {f'A{i:04}' for i in range(1,19)}:
        raise ValueError('Unknown ICS asset type')
    if offset < 0 or not 1 <= limit <= 100:
        raise ValueError('Invalid pagination')
    rows = [r for r in catalogue()['cves'] if
            (not asset or (not r['asset_ids'] if asset == 'unassigned' else asset in r['asset_ids']))
            and (not q or q.casefold() in (r['cve']+' '+r['description']+' '+r['product_search']).casefold())]
    return dict(total=len(rows), offset=offset, rows=rows[offset:offset+limit])


def question(condition):
    phrase = condition['proposition']
    kind = condition.get('kind', 'source_condition')
    if kind=='network_access' and condition.get('target_hint'):
        return 'Can the assessed origin reach the source-described '+condition['target_hint']+' interface on this product?'
    templates = {
        'network_access': 'Can the assessed origin reach the source-described affected interface on this product?',
        'local_access': 'Is local execution or maintenance access available to the assessed actor on this product?',
        'physical_access': 'Can the assessed actor physically access the source-described device or interface?',
        'file_processing': 'Does this deployment process the externally supplied file or content described in the quotation?',
    }
    return templates.get(kind, 'Does this source-stated prerequisite hold in the assessed deployment: '+phrase+'?')


def _fallbacks(source):
    """Restrict descriptor proposals to one source sentence; never use CVSS/CWE."""
    found = []
    patterns = [
        ('network_access', r'\bremote (?:authenticated |unauthenticated )?attackers?\b|\bremotely exploitable\b|\bwith network access\b', True),
        ('local_access', r'\blocal (?:authenticated |unauthenticated )?attackers?\b', True),
        ('physical_access', r'\bphysical access\b', True),
        ('file_processing', r'\b(?:crafted|malicious) (?:project |configuration |image )?files?\b', True),
        ('attacker_authentication', r'\bauthenticated (?:remote |local )?attackers?\b|\bremote authenticated attackers?\b', False),
    ]
    for sentence in re.finditer(r'[^\n]+?(?:[.!?](?=\s|$)|$)', source['text']):
        text = sentence.group()
        consequence=re.search(r'\b(?:could|can|may|would)\b',text,re.I)
        # An OR between consequences (read OR write) is not an access alternative.
        prefix=text[:consequence.start()] if consequence else text
        # Explicit conditionals/alternatives need the grammar review, not conjunction guessing.
        if re.search(r'\b(?:if|unless|without|either|or|not require|even when)\b', prefix, re.I):
            continue
        conditions = []
        for kind, pattern, observable in patterns:
            match = re.search(pattern, prefix, re.I)
            if not match:
                continue
            start = sentence.start()+match.start(); end = sentence.start()+match.end()
            conditions.append(dict(id='c:'+digest([source['id'],start,end])[:20],
                proposition=source['text'][start:end], kind=kind, operator_observable=observable,
                source_ref=dict(source_id=source['id'],span=[start,end],quote=source['text'][start:end]),
                context_ref=dict(source_id=source['id'],span=[sentence.start(),sentence.end()],quote=text)))
            ports=re.findall(r'\bport\s+\d+(?:/(?:tcp|udp))?\b',prefix,re.I)
            if kind=='network_access' and len(set(p.casefold() for p in ports))==1:
                conditions[-1]['target_hint']=ports[0]
        if conditions:
            expression = {'condition':conditions[0]['id']} if len(conditions)==1 else dict(op='and',args=[{'condition':c['id']} for c in conditions])
            found.append(dict(conditions=conditions, expression=expression,
                              source_ref=conditions[0]['context_ref'], derivation='source_descriptor_candidate', scope_ambiguous=False))
    return found


def extract(record):
    """Extract every source passage, retaining incomplete/ambiguous alternatives."""
    proposed = infer_record(record)
    if record.get('original_nvd_status')=='Rejected' or record.get('identity_ambiguous'):
        return []
    sources = {s['id']:s for s in record['sources']}
    scenarios = []
    for passage in proposed['passages']:
        for hypothesis in passage['hypotheses']:
            ids = leaves(hypothesis['expression'])
            conditions = []
            for raw in passage['conditions']:
                if raw['id'] not in ids:
                    continue
                observable=bool(re.search(r'\benabled\b|\bconfigur|\bnetwork\b|\baccess\b|\bfiles?\b|\buser\b|\bmode\b|\bversion\b|\binstall',raw['proposition'],re.I))
                internal=bool(re.search(r'\battacker\b|\b(?:pointer|heap|stack|memory|buffer|control.flow)\b|\b(?:possess|obtain)\b.*\b(?:credential|password|key|privilege)',raw['proposition'],re.I))
                conditions.append(dict(id=raw['id'],proposition=raw['proposition'],
                    kind='source_condition', operator_observable=observable and not internal,
                    source_ref=raw['source_ref'], context_ref=hypothesis['source_ref']))
            scenarios.append(dict(conditions=conditions, expression=hypothesis['expression'],
                source_ref=hypothesis['source_ref'], derivation=hypothesis['derivation'],
                scope_ambiguous=hypothesis['scope_ambiguous']))
    explicit_sources = {s['source_ref']['source_id'] for s in scenarios}
    for source in sources.values():
        if source['id'] not in explicit_sources:
            scenarios.extend(_fallbacks(source))
    for item in scenarios:
        source = sources[item['source_ref']['source_id']]
        item.update(id='scenario:'+digest([record['cve'],source['id'],item['expression']])[:24],
            product_keys=source.get('product_keys', []), coverage_complete=False,
            review_status='pending_source_review', source_binding=source.get('scope_binding'),
            nonrequirements=[n for p in proposed['passages'] for n in p.get('nonrequirements',[]) if n['source_ref']['source_id']==source['id']])
        for condition in item['conditions']:
            condition['question'] = question(condition)
    return scenarios


@lru_cache(maxsize=1)
def native_options():
    path=ROOT/'results/vulntology_design_v1/nist_schema.json'
    if not path.is_file():path=ROOT/'data/standards/vulntology-schema.json'
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SCHEMA_SHA:raise ValueError('Pinned NIST schema hash changed')
    schema=json.loads(raw);defs=schema['definitions']
    fields={key:defs[name]['enum'] for key,name in [
        ('affectsContext','Context'),('hasEntityRole','EntityRole'),('hasLogicalImpact','LogicalImpact'),
        ('hasScope','Scope'),('hasCriticality','Criticality'),('hasGainedPrivilege','PrivilegeLevel'),('hasEscapeContext','Context')]}
    fields['requiresAttackTheatre']=defs['Scenario']['properties']['requiresAttackTheatre']['enum']
    fields['hasImpactMethodType']=defs['ImpactMethodType']['enum']+['Privilege Escalation','Context Escape']
    return fields


def native_draft(record, product, scenario, semantic_review=None):
    """A partial native shape is explicitly distinct from a valid native export."""
    text = scenario['source_ref']['quote']
    native = dict(id=str(uuid.uuid5(uuid.NAMESPACE_URL,scenario['id']+product['key'])),
        evidencedBySource=[next(s['url'] for s in record['sources'] if s['id']==scenario['source_ref']['source_id'])],
        affectsProduct={'hasProductEnumeration':[dict(scheme='urn:ics-vex:source-product-text',values=[product['name']])]})
    theatre = None
    if re.search(r'\bremote (?:authenticated |unauthenticated )?attackers?\b|\bremotely exploitable\b',text,re.I): theatre='Remote'
    elif re.search(r'\blocal (?:authenticated |unauthenticated )?attackers?\b',text,re.I): theatre='Local'
    elif re.search(r'\bphysical access\b',text,re.I): theatre='Physical'
    if theatre: native['requiresAttackTheatre']=theatre
    cwes=[v for v in record.get('cwes',[]) if re.fullmatch(r'CWE-\d+',v)]
    if cwes:
        native['hasExploitedWeakness']=cwes
        native['evidencedBySource']=list(dict.fromkeys(native['evidencedBySource']+['https://nvd.nist.gov/vuln/detail/'+record['cve']]))
    result={'Vulnerability':dict(hasIdentity=[dict(scheme='https://www.cve.org/',value=record['cve'])],
        hasOriginatingProduct=deepcopy(native['affectsProduct']),hasScenario=[native])}
    provenance={};checked={}
    if semantic_review and semantic_review.get('review_confirmed') is True:
        options=native_options();sources={s['id']:s for s in record['sources']}
        fields=semantic_review.get('fields',{})
        if not isinstance(fields,dict):raise ValueError('Native field reviews must be an object')
        for field,assertion in fields.items():
            if not isinstance(assertion,dict):raise ValueError('Native field review must include value, source and quote')
            if field not in options or assertion.get('value') not in options[field]:raise ValueError('Unsupported native field/value')
            source=sources.get(assertion.get('source_id'));quote=assertion.get('quote')
            if not source or product['key'] not in source['product_keys'] or source.get('subject_ambiguous') or not isinstance(quote,str) or not quote.strip() or quote not in source['text']:
                raise ValueError('Native semantic review needs a matching CVE/product source and exact field-local quotation')
            checked[field]=assertion['value'];start=source['text'].index(quote)
            native['evidencedBySource']=list(dict.fromkeys(native['evidencedBySource']+[source['url']]))
            provenance[field]=dict(source_id=source['id'],span=[start,start+len(quote)],quote=quote,
                source_sha256=source['text_sha256'],review='human_semantic_assertion_not_independent_truth')
        if 'requiresAttackTheatre' in checked:native['requiresAttackTheatre']=checked['requiresAttackTheatre']
        action={'id':str(uuid.uuid5(uuid.NAMESPACE_URL,native['id']+':action'))}
        if checked.get('hasImpactMethodType'):
            method={'hasImpactMethodType':checked['hasImpactMethodType']}
            for field in ('hasGainedPrivilege','hasEscapeContext'):
                if field in checked:method[field]=checked[field]
            action['hasImpactMethod']=[method]
        for field in ('affectsContext','hasEntityRole'):
            if field in checked:action[field]=checked[field]
        impact={'id':str(uuid.uuid5(uuid.NAMESPACE_URL,native['id']+':impact'))}
        for field in ('hasLogicalImpact','hasScope','hasCriticality'):
            if field in checked:impact[field]=checked[field]
        if len(impact)>1:action['resultsInImpact']=[impact]
        if len(action)>1:native['hasAction']=[action]
    from src.vulntology_native_projection import _native_errors
    errors=_native_errors(result)
    if product.get('binding')=='unresolved':errors.append('Source-bound affected product scope is unresolved')
    semantic_required={'requiresAttackTheatre','hasImpactMethodType','affectsContext','hasEntityRole','hasLogicalImpact','hasScope','hasCriticality'}
    reviewed_complete=semantic_required<=set(checked)
    ready=not errors and reviewed_complete and not scenario.get('scope_ambiguous')
    # No action, impact context, criticality or scope is invented to satisfy the schema.
    return dict(document=result,status='source_reviewed_native_validated' if ready else 'partial_native_draft',
        native_export_ready=ready,missing_fields=errors+['Source semantic review required for '+f for f in sorted(semantic_required-set(checked))],
        schema_sha256=SCHEMA_SHA,semantic_review_required=not ready,field_provenance=provenance)


def prepare_review(record, product_key, reviewer, reviewed_at, approved_ids):
    products={p['key']:p for p in record['products']}
    if product_key not in products:
        raise ValueError('Product scope does not belong to this CVE')
    applicable=[s for s in record['scenarios'] if product_key in s['product_keys']]
    approved_ids=set(approved_ids)
    known={s['id'] for s in applicable}
    if not approved_ids <= known:
        raise ValueError('Unknown or out-of-product scenario ID')
    approval=dict(validation_status='approved',reviewer=reviewer,reviewed_at=reviewed_at)
    conditions=[]; questions=[]; formulas=[]
    for scenario in applicable:
        if scenario['id'] not in approved_ids or scenario['scope_ambiguous']:
            # Unreviewed/ambiguous alternatives stay in the expression as unknown.
            cid='unresolved:'+scenario['id']
            conditions.append(dict(id=cid,predicate='unresolved_path',target=product_key,
                necessity='required_for_path',operator_observable=False,source_refs=[scenario['source_ref']]))
            formulas.append({'condition':cid})
            continue
        mapping={c['id']:scenario['id']+':'+c['id'] for c in scenario['conditions']}
        def rename(node):
            return {'condition':mapping[node['condition']]} if 'condition' in node else dict(op=node['op'],args=[rename(n) for n in node['args']])
        formulas.append(rename(scenario['expression']))
        for c in scenario['conditions']:
            cid=mapping[c['id']]; refs=[c['source_ref'],c['context_ref']]
            conditions.append(dict(id=cid,predicate=c['kind'],target=product_key,
                necessity='required_for_path',operator_observable=c['operator_observable'],source_refs=refs,**approval))
            if c['operator_observable']:
                questions.append(dict(id=cid,text=c['question'],target=product_key,cost=1,**approval,
                    mappings=[dict(condition_id=cid,coverage='FULL',answers=dict(yes='true',no='false',unknown='unknown'),source_refs=refs,**approval)]))
    expression=(formulas[0] if len(formulas)==1 else dict(op='or',args=formulas)) if formulas else None
    fully_reviewed=bool(applicable) and len(approved_ids)==len(applicable) and not any(s['scope_ambiguous'] for s in applicable)
    # A partial set of approved source paths cannot be used as a complete CVE formula.
    review=dict(cve=record['cve'],conditions=conditions,questions=questions,
                source_record_status=record.get('original_nvd_status'),formula=None)
    if fully_reviewed:
        review['formula']=dict(expression=expression,coverage_complete=False,
            source_refs=[s['source_ref'] for s in applicable],**approval)
    return review,products[product_key],applicable,fully_reviewed


def evaluate(record, payload, reviewed_at=None):
    if not isinstance(payload,dict): raise ValueError('Assessment must be an object')
    reviewer=str(payload.get('reviewer','')).strip()
    if not reviewer or len(reviewer)>200: raise ValueError('Name the source/evidence reviewer')
    at=now(); reviewed_at=reviewed_at or at
    approved_ids=payload.get('approved_scenarios',[])
    if not isinstance(approved_ids,list) or len(approved_ids)>500: raise ValueError('Invalid scenario review list')
    review,product,paths,complete=prepare_review(record,payload.get('product_key'),reviewer,reviewed_at,approved_ids)
    raw_scope=payload.get('scope') or {}
    if not isinstance(raw_scope,dict):raise ValueError('Asset scope must be an object')
    scope={k:str(raw_scope.get(k,'')).strip() for k in ('asset_ref','product','build','config_baseline','mode')}
    actor=str(raw_scope.get('actor_origin','')).strip()
    if any(not v or len(v)>500 for v in scope.values()) or not actor or len(actor)>500:
        raise ValueError('Provide asset, actual product/build, configuration, operating mode and assessed actor/origin')
    scope['mode']+=' | actor/origin: '+actor
    scope.update(cve=record['cve'],evaluated_at=at)
    records=[]; answers=[]; findings=[]
    def evidence(eid,kind,item,**extra):
        from src.item4.decision.evidence_review_gate import instant
        source=item.get('source','');quote=item.get('quote','')
        if not isinstance(source,str) or not isinstance(quote,str) or not source.strip() or not quote.strip() or len(source)>2000 or len(quote)>8000:
            raise ValueError('Every asserted fact requires a source and exact supporting record')
        observed=item.get('observed_at') or payload.get('observed_at')
        expiry=item.get('valid_until') or payload.get('valid_until')
        times=[instant(observed),instant(reviewed_at),instant(at),instant(expiry)]
        if any(v is None for v in times) or not times[0]<=times[1]<=times[2]<=times[3]:
            raise ValueError('Evidence is expired, future-dated or lacks timezone-aware observation/validity times')
        records.append(dict(id=eid,kind=kind,source=source,quote=quote,reviewer=reviewer,
            binding=scope,observed_at=observed,reviewed_at=reviewed_at,valid_until=expiry,**extra))
    known={q['id'] for q in review['questions']}
    submitted=payload.get('answers',[])
    if not isinstance(submitted,list) or len(submitted)>2000:raise ValueError('Invalid question answers')
    seen=set()
    for i,answer in enumerate(submitted):
        if not isinstance(answer,dict):raise ValueError('Question answer must be an object')
        qid=answer.get('question_id');value=answer.get('value')
        if qid not in known or qid in seen or value not in ('yes','no','unknown'):
            raise ValueError('Duplicate, unapproved or unknown question/answer')
        seen.add(qid);refs=[]
        if value!='unknown':
            kind=answer.get('kind','operational_observation')
            if kind not in {'operational_observation','firewall_policy','reviewed_nonexecution_analysis'}:
                raise ValueError('Invalid observation evidence kind')
            eid='observation-'+str(i);evidence(eid,kind,answer);refs=[eid]
        answers.append(dict(question_id=qid,value=value,evidence_ids=refs))
    applicability=payload.get('applicability') or {}
    if not isinstance(applicability,dict):raise ValueError('Product applicability must be an object')
    bound=applicability.get('product_matches') is True and product.get('binding')!='unresolved'
    if bound:evidence('applicability','installation_record',applicability)
    claim=payload.get('product_assertion')
    if claim:
        if not isinstance(claim,dict):raise ValueError('Product finding must be an object')
        status=claim.get('status')
        if status not in {'affected','fixed','not_affected'}:raise ValueError('Invalid supplier/product status')
        evidence('product','supplier_fix_mapping' if status=='fixed' else 'reviewed_product_analysis',claim,asserted_status=status)
        refs=['product']
        if status=='fixed' and claim.get('installation'):
            evidence('installed-fix','installation_record',claim['installation'],execution_verified=claim['installation'].get('execution_verified') is True)
            refs.append('installed-fix')
        findings.append(dict(status=status,evidence_ids=refs,action_statement=claim.get('action_statement'),
                             impact_statement=claim.get('impact_statement'),justification=claim.get('justification')))
    route=payload.get('complete_route_analysis') or {}
    if not isinstance(route,dict):raise ValueError('Route analysis must be an object')
    formula_ids=[]
    if route.get('review_confirmed') is True:
        if not complete: raise ValueError('Review every scoped path and resolve ambiguous source formulas first')
        evidence('routes','reviewed_complete_route_analysis',route);formula_ids=['routes']
        review['formula']['coverage_complete']=True
    # Excluded draft alternatives mean there is no executable exhaustive formula.
    validate_review(review,record)
    case=dict(binding=scope,evidence=records,answers=answers,product_findings=findings,formula_evidence_ids=formula_ids)
    result=evaluate_review(review,case)
    if not bound:
        result.update(status='under_investigation',accepted_evidence_ids=[],justification=None,
            reason='The actual installed product/build has not been bound to this source product scope.')
    for node in result['evidence_graph']['nodes']:
        if node['id']=='decision':node['label']=result['status']
    result['remaining_answers_block_decision']=result['status']=='under_investigation'
    result.update(policy=VERSION,product_scope=product,reviewed_scenarios=sorted(approved_ids),
        all_registered_paths_reviewed=complete,source_digest=digest(record),
        reviewer_identity_authenticated=False,independent_accuracy_evaluated=False)
    result['decision_trace'].append(dict(check='product_scope_binding',outcome='operator_attested' if bound else 'unconfirmed',final_status=result['status']))
    result['next_steps']=(list(dict.fromkeys(result.get('next_steps',[])+
        ([] if complete else ['Review every source path; missing or ambiguous prerequisites stay unknown.'])+
        ([] if bound else ['Confirm the installed product/build against the selected source scope with a record.'])))
        if result['status']=='under_investigation' else [])
    semantic_reviews=payload.get('native_reviews',[])
    if not isinstance(semantic_reviews,list) or len(semantic_reviews)>500:raise ValueError('Invalid native semantic reviews')
    if any(not isinstance(item,dict) for item in semantic_reviews):raise ValueError('Native scenario review must be an object')
    bypath={item.get('scenario_id'):item for item in semantic_reviews}
    if len(bypath)!=len(semantic_reviews) or not set(bypath)<={s['id'] for s in paths}:
        raise ValueError('Duplicate or out-of-scope native scenario review')
    drafts=[native_draft(record,product,s,bypath.get(s['id']) if s['id'] in approved_ids else None) for s in paths]
    return dict(schema='ics-vex-asset-vulntology-assessment/1',policy=VERSION,cve=record['cve'],
        evaluated_at=at,decision=result,questions=review['questions'],native_scenarios=drafts,
        source_record=record,evidence=records,review=review,
        native_export_ready=bool(drafts) and all(d['native_export_ready'] for d in drafts))
