"""All-population weak VEP supervision and synthetic conditional record data.

Every CVE receives actual examples in BOTH role datasets. Source-rule labels are
not expert Gold. Synthetic atom truth is never a real-CVE exploitability label.
"""
from collections import Counter,defaultdict
from copy import deepcopy
from pathlib import Path
import argparse,hashlib,json,re,sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.decision import population_condition_rules as P
from src.item4.analysis import exploitation_prerequisites as V
from src.item4.models import operating_record_review_model as O
from src.common.data.prerequisite_research_schema import enrich

VERSION='full-population-prerequisite-role-data/1'
DEFAULT=ROOT/'benchmark/prerequisite_roles_20261119_v7'
ROLES=('exploitation-prerequisites','operating-record-review')


def digest(value):return V.digest(value)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def line(stream,value):stream.write(json.dumps(value,ensure_ascii=False,separators=(',',':'))+'\n')


def source_groups(records):
    """Connected CVE/source-document/text groups; allocate before synthesis."""
    parent={r['cve']:r['cve'] for r in records};seen={}
    def find(x):
        while parent[x]!=x:parent[x]=parent[parent[x]];x=parent[x]
        return x
    for r in records:
        for source in r['sources']:
            for key in [source.get('document_sha256'),source.get('text_sha256')]:
                if not key:continue
                if key in seen:parent[find(r['cve'])]=find(seen[key])
                else:seen[key]=r['cve']
    # Additional supplier snapshots used below also bind their CVEs together.
    from src.item4.decision.evidence_based_vex import registry
    vendor=registry()
    for cve,rule in vendor['rules'].items():
        if cve not in parent:continue
        for ref in [rule['source']]+rule['fix_sources']:
            key='supplier:'+ref['source_sha256']
            if key in seen:parent[find(cve)]=find(seen[key])
            else:seen[key]=cve
    groups=defaultdict(list)
    for r in records:groups[find(r['cve'])].append(r['cve'])
    groups=sorted((sorted(ids) for ids in groups.values()),key=lambda ids:(-len(ids),digest(ids)))
    targets={'train':len(records)*.7,'dev':len(records)*.15,'test':len(records)*.15}
    counts=Counter();assignments={};group_ids={}
    for ids in groups:
        split=max(targets,key=lambda k:targets[k]-counts[k]);counts[split]+=len(ids)
        gid=digest(ids)
        for cve in ids:assignments[cve]=split;group_ids[cve]=gid
    return assignments,group_ids,dict(counts)


def select_source(record):
    questions=Counter(q['source']['source_id'] for q in record['compiled']['questions'])
    def score(s):
        return (bool(questions[s['id']]),s.get('scope_binding')=='vendor_CVE_product_entry',
                s['id'].startswith('nvd:'),bool(s['text']),len(s['text']))
    return max(record['sources'],key=score)


def atom_for(q):
    label=q['label']
    known={
      'release_buffers':('feature_enabled','SSL_MODE_RELEASE_BUFFERS',''),
      'multithreaded':('configuration_required','application threading','multiple threads'),
      'tls_client':('configuration_required','OpenSSL role','TLS client'),
      'anonymous_ecdh':('feature_enabled','anonymous ECDH ciphersuites',''),
      'dtls_role':('configuration_required','OpenSSL role','DTLS client'),
      'dtls_client':('configuration_required','OpenSSL role','DTLS client'),
      'dtls_server':('configuration_required','OpenSSL role','DTLS server'),
      'heartbeat_support':('feature_enabled','TLS heartbeat support',''),
      'ssl3_build_support':('feature_enabled','SSLv3 support',''),
      'gp_gateway':('configuration_required','GlobalProtect gateway','configured'),
      'gp_portal':('configuration_required','GlobalProtect portal','configured')}
    if q['id'] in known:
        predicate,target,value=known[q['id']]
        return dict(predicate=predicate,target=target,value=value,statement=label)
    m=re.fullmatch(r'Is (.+) enabled/set on this exact assessed component instance\?',label)
    if m:return dict(predicate='feature_enabled',target=m[1],value='',statement=m[1]+' is enabled')
    if label.startswith('From the recorded origin'):
        return dict(predicate='network_reachable',target='the source-described interface',value='',statement='The source-described interface is reachable from the assessed origin')
    if label.startswith('Is local execution'):
        return dict(predicate='maintenance_access',target='the source-described local execution/maintenance interface',value='',statement='Local execution or maintenance access is available to the assessed origin')
    if label.startswith('Is the affected physical'):
        return dict(predicate='physical_access',target='the source-described physical interface',value='',statement='The affected physical interface is accessible to the assessed origin')
    return None


def supplier_record(original):
    """Reuse existing quote-checked supplier rules as weak source annotations."""
    from src.item4.decision.evidence_based_vex import registry
    catalog=registry();rule=catalog['rules'].get(original['cve'])
    if rule is None:return original
    sid=rule['source']['source_id'];meta=catalog['sources'][sid]
    document=json.loads((ROOT/'data/nist_auto_vex'/meta['file']).read_text(encoding='utf-8'))
    text=document['text'];a,b=0,len(text)
    headings=list(re.finditer(r'^.*\(CVE-\d{4}-\d{4,}\)[^\n]*\n={3,}[^\n]*',text,re.M))
    for i,h in enumerate(headings):
        if rule['cve'] in h.group():
            a=h.start();b=headings[i+1].start() if i+1<len(headings) else len(text);break
    excerpt=text[a:b];key='supplier:'+rule['cve']+':'+rule['product']
    source=dict(id=sid,text=excerpt,text_sha256=hashlib.sha256(excerpt.encode()).hexdigest(),
        url=meta['url'],product_keys=[key],scope_binding='vendor_CVE_product_entry',subject_ambiguous=False,
        parent_text_sha256=meta['sha256'],parent_span=[a,b],source_file='data/nist_auto_vex/'+meta['file'])
    qs=[]
    for q in rule['questions']:
        if q['source']['source_id']!=sid or excerpt.count(q['source']['quote'])!=1:continue
        item=deepcopy(q);start=excerpt.index(q['source']['quote'])
        item['source'].update(span=[start,start+len(q['source']['quote'])],source_sha256=source['text_sha256'])
        qs.append(item)
    ref=dict(source_id=sid,quote=excerpt,span=[0,len(excerpt)],url=meta['url'],source_sha256=source['text_sha256'])
    row=dict(cve=original['cve'],products=[dict(key=key,aliases=rule['product_aliases'],name=rule['product'])],sources=[source],
        compiled=dict(questions=qs,paths=[dict(id='supplier-path',expression=rule['expression'],product_keys=[key],
                      unknown_facts={},source=ref)],gaps=[dict(reason='Additional supplier operand requires review') for _ in rule.get('unresolved_operands',[])]),
        original_catalog_sha256=original['sha256'],source_backing='pinned_supplier_snapshot_and_existing_source_rule')
    row['sha256']=digest(row)
    return row


def vep_case(original):
    source=deepcopy(select_source(original));cve=original['cve']
    # One explicitly disclosed source scope per CVE; all original sources remain
    # in the immutable source snapshot. No claim of all-product/path coverage.
    products=[deepcopy(p) for p in original['products'] if p['key'] in source.get('product_keys',[])][:1]
    selected_keys={p['key'] for p in products}
    source['product_keys']=[k for k in source.get('product_keys',[]) if k in selected_keys]
    record=dict(cve=cve,sources=[source],products=products)
    if not source['text']:
        packet=dict(cve=cve,sources=[source],products=products,evidence=[],schema=V.SCHEMA)
    else:packet=V.extraction_packet(record, legacy_v1=True)  # Frozen targets use the original V1 contract.
    evidence=packet['evidence'];prerequisites=[];mapping={};question_by_id={}
    def evidence_for(quote):
        ref=next((e['evidence_id'] for e in evidence if quote in e['quote']),None)
        if ref:return ref
        if quote and source['text'].count(quote)==1:
            eid='e'+str(len(evidence)+1);evidence.append(dict(evidence_id=eid,source_id=source['id'],quote=quote))
            for field in ('prerequisites','scenarios','nonrequirements'):
                packet['schema']['properties'][field]['items']['properties']['source_refs']['items']['properties']['evidence_id']['enum']=[e['evidence_id'] for e in evidence]
            return eid
        return None
    # Candidate input bindings and operational requirements are separate facts.
    scope_direct=source.get('scope_binding')=='vendor_CVE_product_entry' and bool(products) and not source.get('subject_ambiguous')
    for q in original['compiled']['questions']:
        if q['source']['source_id']!=source['id']:continue
        atom=atom_for(q);ref=evidence_for(q['source']['quote'])
        if not atom or not ref:continue
        pid='p'+str(len(prerequisites)+1);mapping[q['id']]=pid;question_by_id[pid]=q
        prerequisites.append(dict(id=pid,**atom,operator_observable=True,
            source_refs=[dict(evidence_id=ref)],necessity='required',
            evidence_directness='direct_evidence',review_status='pending'))
    # Source mentions without an approved Boolean relation remain candidates;
    # they are NOT silently conjoined with the executable path.
    patterns=[
      ('V5','attacker_authenticated',False,r'\b(?:authenticated (?:remote |local )?(?:attackers?|users?)|(?:requires?|requiring) (?:prior |valid )?authentication)\b'),
      ('V6','attacker_has_required_privilege',False,r'\b(?:administrator|administrative|root|elevated|low|high) privileges\b'),
      ('V3','custom',True,r'\b(?:web interface|HTTP interface|HTTPS interface|serial interface|TCP port \d+|UDP port \d+)\b'),
      ('V7','input_processed',False,r'\b(?:specially[- ]crafted|malformed|crafted)\b[^.;\n]{1,150}'),
      ('V7','user_performs_action',True,r'\b(?:user|victim) (?:opens?|clicks?|visits?)\b[^.;\n]{1,120}')]
    for category,predicate,observable,pattern in patterns:
        for match in list(re.finditer(pattern,source['text'],re.I))[:1]:
            prefix=source['text'][max(0,match.start()-50):match.start()]
            if category in ('V5','V6') and re.search(r'\b(?:not|without)(?:\s+\w+){0,2}\s*$',prefix,re.I):
                continue
            ref=evidence_for(match.group())
            if not ref:continue
            pid='p'+str(len(prerequisites)+1)
            prerequisites.append(dict(id=pid,predicate=predicate,target=match.group(),value='',
                statement='Source-described candidate: '+match.group(),operator_observable=observable,
                source_refs=[dict(evidence_id=ref)],vep_category=category,
                necessity='contextual' if category=='V3' else 'unknown',
                evidence_directness='direct_evidence',review_status='pending'))
    nonrequirements=[]
    for match in list(re.finditer(r'\b(?:without (?:requiring )?authentication|does not require authentication|requires? no authentication|unauthenticated (?:remote |local )?attackers?)\b',source['text'],re.I))[:1]:
        ref=evidence_for(match.group())
        if ref:nonrequirements.append(dict(vep_category='V5',statement=match.group(),source_refs=[dict(evidence_id=ref)]))
    scenarios=[];unknowns=[]
    def convert(expr):
        if 'condition' in expr:return {'condition':mapping[expr['condition']]}
        return dict(op=expr['op'],args=[convert(a) for a in expr['args']])
    if not source.get('subject_ambiguous'):
        for path in original['compiled']['paths']:
            if path['source']['source_id']!=source['id'] or path.get('unknown_facts'):continue
            if not set(V.leaves(path['expression']))<=set(mapping):continue
            if scope_direct and not selected_keys.intersection(path['product_keys']):continue
            ref=evidence_for(path['source']['quote'])
            if not ref:continue
            scenarios.append(dict(id='s'+str(len(scenarios)+1),product_keys=sorted(selected_keys) if scope_direct else [],
                product_binding='source_bound' if scope_direct else 'unresolved',
                expression=convert(path['expression']),source_refs=[dict(evidence_id=ref)]))
    used=set().union(*(V.leaves(s['expression']) for s in scenarios)) if scenarios else set()
    for item in prerequisites:
        if item['id'] not in used and item['necessity']!='contextual':item['necessity']='unknown'
    if not scenarios:unknowns.append('Source-supported executable product/path binding remains unresolved; absence of an extracted path is not a negative finding.')
    elif not scope_direct:unknowns.append('Source-described conditional scenario extracted; deployed product applicability is unresolved.')
    if not prerequisites:unknowns.append('No validated operational prerequisite annotation is available for this source; do not interpret this as absence of prerequisites.')
    if original['compiled']['gaps']:unknowns.append('Additional source requirements remain untranslated or unverified.')
    claims=[dict(vep_category='V1',product_key=p['key'],source_status=p['status'],
        source_fields={k:p[k] for k in ('source_file','status_pointer','product_pointer','document_sha256') if k in p})
        for p in products if p.get('status') in ('known_affected','fixed','known_not_affected','under_investigation')
        and any(k in p for k in ('source_file','status_pointer','product_pointer','document_sha256'))]
    draft=enrich(dict(format=V.VERSION,cve=cve,prerequisites=prerequisites,scenarios=scenarios,nonrequirements=nonrequirements,unknowns=unknowns,applicability_claims=claims))
    if source['text']:V.validate(V.resolve_references(draft,packet),record)
    authority=dict(type='automatic_source_rule_reference',expert_reviewed=False,coverage_complete=False,
        source_record_sha256=original['sha256'],selected_source_id=source['id'],selected_source_sha256=source['text_sha256'],
        original_source_count=len(original['sources']),product_path_scope='one source and at most one registered product per CVE',
        unresolved=bool(unknowns),not_a_ground_truth_impact_label=True)
    return packet,draft,authority,prerequisites


def record_case(cve,source,prerequisites):
    """Truth follows an explicit simulated state and disclosed observation context."""
    index=int(digest(['record-case-v1',cve])[:8],16);variant=index%12
    candidate=next((p for p in prerequisites if p['operator_observable']),None)
    if candidate:
        atom={k:candidate[k] for k in ('predicate','target','value')};origin_kind='source_rule_candidate_not_approved_as_cve_requirement'
    else:
        atom=dict(predicate='feature_enabled',target='simulation_feature',value='')
        origin_kind='synthetic_conditional_atom_not_a_cve_prerequisite'
    asset='asset-'+digest(['asset',cve])[:12];build='simulation-build';baseline='simulation-baseline'
    scope=dict(asset_ref=asset,product='source-associated component',build=build,
        config_baseline=baseline,mode='normal',origin='engineering-workstation',
        observed_at='2026-11-19T10:00:00+09:00',valid_until='2026-11-20T10:00:00+09:00')
    predicate,target=atom['predicate'],atom['target']
    if predicate=='feature_enabled':pos=target+' is enabled';neg=target+' is disabled'
    elif predicate=='network_reachable':pos=target+' is reachable from engineering-workstation';neg='all paths from engineering-workstation to '+target+' are blocked'
    elif predicate=='physical_access':pos=target+' is physically accessible to the assessed origin';neg=target+' is physically inaccessible to the assessed origin'
    elif predicate=='configuration_required':pos=target+' matches '+atom['value'];neg=target+' does not match '+atom['value']
    else:pos=target+' is available to the assessed origin';neg=target+' is unavailable to the assessed origin'
    question='Does the following positive operating state hold: '+pos+'?'
    prefix=f'Asset {asset}; build {build}; baseline {baseline}; mode normal; origin engineering-workstation. '
    positive=prefix+'Observed at 2026-11-19T10:00:00+09:00: the current applied configuration confirms that '+pos+'.'
    negative=prefix+'Observed at 2026-11-19T10:00:00+09:00: complete inspection of the assessed scope confirms that '+neg+'.'
    if variant in (0,1,2):
        text=positive if variant==0 else prefix+'The applied setting was inspected now: '+pos+'.' if variant==1 else prefix+'Current verification result: '+pos+'. No conflicting current record was found.'
    elif variant in (3,4,5):
        text=negative if variant==3 else prefix+'Current full-scope verification: '+neg+'.' if variant==4 else prefix+'All instances in the assessed scope were inspected now; '+neg+'.'
    else:
        text=(prefix+'A previous baseline on 2026-10-01 had this state: '+pos+'. No current configuration was inspected.' if variant==6 else
              prefix+'A proposed change will establish this state: '+pos+'. Approval and application are pending.' if variant==7 else
              positive.replace(asset,asset+'-other') if variant==8 else
              positive.replace(build,'other-build') if variant==9 else
              prefix+'No configuration or access inspection is available for this operating atom.' if variant==10 else
              positive+' A second current record for the same scope explicitly reports the opposite state; reconciliation is pending.')
    value='true' if variant in (0,1,2) else 'false' if variant in (3,4,5) else 'unknown'
    eid='r-'+digest(['evidence',cve])[:12]
    record=dict(id=eid,excerpt=text,kind='configuration_record',source='synthetic configuration inspection',
        synthetic=True,asset_ref=asset,build=build,config_baseline=baseline,
        observed_at=scope['observed_at'],valid_until=scope['valid_until'])
    condition=dict(supported=True,question=question,atom=atom,scope=scope,
        source={k:source[k] for k in ('id','url','text_sha256') if k in source},
        condition_origin=origin_kind,cve_context=cve)
    schema=deepcopy(O.SCHEMA)
    schema['properties']['records']['items']['properties']['evidence_id']={'enum':[eid]}
    schema['properties']['records']['items']['properties']['quote_evidence_id']={'enum':['',eid]}
    packet=dict(condition=condition,records=[record],schema=schema)
    target=dict(records=[dict(evidence_id=eid,value=value,quote_evidence_id=eid if value!='unknown' else '',
        current_applied_state=variant not in (6,7,10),scope_matches=variant not in (8,9),
        reason='Current applied state within the assessed scope.' if value!='unknown' else 'The record does not consistently establish a current applied state within the assessed scope.')])
    authority=dict(type='synthetic_conditional_record_truth',synthetic=True,real_asset_impact_supervision=False,
        variant=variant,latent_atom_value=True if variant in (0,1,2) else False if variant in (3,4,5) else None,
        answer=value,condition_origin=origin_kind,not_a_cve_exploitability_label=True)
    return packet,target,authority


def build(output=DEFAULT):
    output=Path(output)
    if output.exists():raise FileExistsError('Use a fresh dataset version; never overwrite a frozen set')
    db=P.connection()
    try:records=[json.loads(raw) for raw, in db.execute('select payload from records order by cve')]
    finally:db.close()
    ids=[r['cve'] for r in records]
    if len(ids)!=12418 or len(set(ids))!=12418:raise ValueError('The confirmed 12,418 CVEs must be retained')
    assignments,groups,counts=source_groups(records)
    output.mkdir(parents=True)
    writers={};stats={role:Counter() for role in ROLES}
    try:
        for role in ROLES:
            for split in ('train','dev','test'):
                for kind in ('inputs','labels'):
                    p=output/role/split/(kind+'.jsonl');p.parent.mkdir(parents=True,exist_ok=True)
                    writers[role,split,kind]=p.open('w',encoding='utf-8',newline='\n',buffering=4*1024*1024)
        with (output/'source_snapshot.jsonl').open('w',encoding='utf-8',newline='\n',buffering=4*1024*1024) as snapshot,(output/'population.jsonl').open('w',encoding='utf-8',newline='\n',buffering=4*1024*1024) as population:
            for completed,original in enumerate(records,1):
                cve=original['cve'];split=assignments[cve];line(snapshot,original)
                annotated=supplier_record(original)
                packet,target,authority,candidates=vep_case(annotated)
                authority['original_catalog_sha256']=original['sha256']
                pairs=[(ROLES[0],V.SYSTEM,packet,target,authority)]
                rp,rt,ra=record_case(cve,select_source(original),candidates)
                pairs.append((ROLES[1],O.SYSTEM,rp,rt,ra))
                case_ids={}
                for role,system,packet,target,authority in pairs:
                    cid=digest([VERSION,role,cve]);case_ids[role]=cid
                    line(writers[role,split,'inputs'],dict(id=cid,cve=cve,group=groups[cve],split=split,system=system,packet=packet))
                    line(writers[role,split,'labels'],dict(id=cid,cve=cve,split=split,target=target,authority=authority))
                    stats[role][split]+=1
                    if role==ROLES[0]:
                        stats[role]['conditions']+=len(target['prerequisites']);stats[role]['scenarios']+=len(target['scenarios'])
                        stats[role]['bound_scenarios']+=sum(bool(s['product_keys']) for s in target['scenarios'])
                        stats[role]['V1_claims']+=len(target['applicability_claims'])
                        for item in target['prerequisites']:stats[role]['category_'+item['vep_category']]+=1
                        stats[role]['unresolved']+=bool(target['unknowns'])
                    else:stats[role]['label_'+authority['answer']]+=1
                line(population,dict(cve=cve,split=split,group=groups[cve],case_ids=case_ids,
                    source_count=len(original['sources']),source_record_sha256=original['sha256']))
                if completed%1000==0:print(json.dumps(dict(stage='building',completed=completed,total=len(records))),flush=True)
    finally:
        for stream in writers.values():stream.close()
    files={str(p.relative_to(output)).replace('\\','/'):sha(p) for p in output.rglob('*.jsonl')}
    if not stats[ROLES[0]]['scenarios'] or not stats[ROLES[0]]['bound_scenarios']:
        raise ValueError('VEP dataset has no positive relation or source-bound scenario; do not train an all-abstention extractor')
    manifest=dict(version=VERSION,population_count=len(ids),population_sha256=digest(ids),roles=list(ROLES),
        confirmed_population=12418,split_counts=counts,split_strategy='Connected original document/text groups, deterministic 70/15/15 target allocation',
        exact_ratio_not_guaranteed=True,role_counts={k:dict(v) for k,v in stats.items()},sha256=files,
        all_cves_have_actual_examples_in_both_roles=True,synthetic_operating_records=True,
        weak_source_supervision=True,expert_gold=False,independent_semantic_accuracy_verified=False,
        source_path_scope='One selected source and at most one product per CVE; full original records preserved in source_snapshot.jsonl',
        evaluation_reuse_note='Historical public sources may have appeared in earlier work. This new grouped split is not a claim of never-seen independent ICS data.',
        user_spec_sha256=sha(ROOT/'docs/ICS_OT_VEP_USER_SPEC_20261119.md'))
    manifest['builder_sha256']=sha(Path(__file__))
    manifest['prompt_sha256']={ROLES[0]:hashlib.sha256(V.SYSTEM.encode()).hexdigest(),ROLES[1]:hashlib.sha256(O.SYSTEM.encode()).hexdigest()}
    write(output/'manifest.json',manifest)
    audit(output)
    print(json.dumps({k:manifest[k] for k in ['population_count','split_counts','role_counts']},ensure_ascii=False),flush=True)
    return output


def audit(output=DEFAULT):
    output=Path(output);manifest=json.loads((output/'manifest.json').read_text(encoding='utf-8'))
    for name,h in manifest['sha256'].items():
        if sha(output/name)!=h:raise ValueError('Frozen dataset changed: '+name)
    population=[json.loads(s) for s in (output/'population.jsonl').read_text(encoding='utf-8').splitlines()]
    wanted={r['cve'] for r in population};group_splits=defaultdict(set)
    for row in population:group_splits[row['group']].add(row['split'])
    if len(wanted)!=12418 or any(len(s)!=1 for s in group_splits.values()):raise ValueError('Population coverage or source group leakage')
    for role in ROLES:
        seen=set()
        for split in ('train','dev','test'):
            inputs=[json.loads(s) for s in (output/role/split/'inputs.jsonl').read_text(encoding='utf-8').splitlines()]
            labels=[json.loads(s) for s in (output/role/split/'labels.jsonl').read_text(encoding='utf-8').splitlines()]
            if {r['id'] for r in inputs}!={r['id'] for r in labels}:raise ValueError('Input/label mismatch')
            for row in inputs:
                if row['cve'] in seen:raise ValueError('CVE split leakage')
                seen.add(row['cve'])
                if any(k in row for k in ('target','authority','latent_atom_value','answer')):raise ValueError('Label leaked into model input')
        if seen!=wanted:raise ValueError('Ledger-only CVE: missing actual role example')
    result=dict(passed=True,cves=len(wanted),roles=2,all_cves_have_actual_examples=True,
                source_group_cross_split_leakage=0,input_labels_separate=True)
    write(output/'integrity_audit.json',result);return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['build','audit']);parser.add_argument('--output',type=Path,default=DEFAULT)
    args=parser.parse_args();build(args.output) if args.action=='build' else print(json.dumps(audit(args.output)))
