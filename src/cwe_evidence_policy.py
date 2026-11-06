"""Versioned evidence requirements, derived per detailed CWE, never VEX verdicts."""
from collections import Counter,deque
from functools import lru_cache
from pathlib import Path
import hashlib,json,re
from src.cwe_taxonomy import load,ancestry
ROOT=Path(__file__).resolve().parents[1]
POLICY_FILE=ROOT/'data/cwe_evidence_policy_v2.json'


def json_fingerprint(value):
    """Semantic JSON digest stays stable across Git LF/CRLF normalization."""
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf-8')).hexdigest()


@lru_cache(maxsize=1)
def policy():
    blob=POLICY_FILE.read_bytes();p=json.loads(blob)
    p['sha256']=json_fingerprint(p);validate(p,load())
    return p


@lru_cache(maxsize=1)
def metadata():
    t=load();path=ROOT/'data/cwe_taxonomy'/('v'+t['version'])/'evidence_metadata.json'
    blob=path.read_bytes();m=json.loads(blob)
    if m['taxonomy_xml_sha256']!=t['xml_sha256'] or set(m['records'])!=set(t['records']):
        raise ValueError('Evidence metadata does not match pinned taxonomy')
    m['sha256']=json_fingerprint(m);return m


def validate(p,taxonomy):
    names=set();records=taxonomy['records']
    for rule in p['rules']:
        if rule['id'] in names:raise ValueError('Duplicate evidence rule ID')
        names.add(rule['id'])
        for c in rule['anchors']:
            if c not in records or records[c]['abstraction']=='Pillar' or records[c]['status']=='Deprecated':
                raise ValueError('Invalid or overly broad rule anchor: '+c)
        if not rule['facts'] or any(f not in p['facts'] for f in rule['facts']):raise ValueError('Unknown evidence fact')
    for r in p['source_refinements']+p['operational_refinements']:re.compile(r['pattern'])
    re.compile(p['context_pattern']);re.compile(p['specialist_definition_pattern'])
    for cid in p['operator_observable_baseline_allowlist']:
        if cid not in records or records[cid]['abstraction']=='Pillar':raise ValueError('Invalid operator baseline allowlist entry')


def distances(cwe,records):
    paths={cwe:[cwe]};queue=deque([cwe])
    while queue:
        cid=queue.popleft()
        for parent in records.get(cid,{}).get('parents_view_1000',[]):
            if parent not in paths:paths[parent]=paths[cid]+[parent];queue.append(parent)
    return paths


def profile(cwe,*,rules=None,taxonomy=None):
    p=rules or policy();t=taxonomy or load();chain=ancestry(cwe,t);rec=t['records'].get(cwe,{})
    row={**chain,'status':rec.get('status'),'definition':rec.get('description',''),
        'definition_url':rec.get('url'),'profile_version':p['version'],'policy_sha256':p.get('sha256'),
        'source_requirement':'undetermined','operational_requirement':'undetermined',
        'required_facts':[],'matched_rules':[],'shadowed_rules':[],
        'resolution':'unresolved','question_profiles':[], 'independently_validated':False,
        'routing_is_not_a_verdict':True,'source_analyzer_capability_guaranteed':False}
    m=metadata() if t.get('xml_sha256')==load().get('xml_sha256') else {'records':{},'sha256':None}
    info=m['records'].get(cwe,{})
    row['official_metadata']={**info,'metadata_sha256':m['sha256'],
        'interpretation':'Official descriptions and detection suggestions support review; they do not prescribe the project routing rule.'}
    row['cve_mapping_gate']={'usage':info.get('mapping_usage','Unknown'),
        'requires_mapping_review':info.get('mapping_usage') in {'Allowed-with-Review','Prohibited','Discouraged'},
        'blocked_for_cve_routing':False,
        'advisory_only':True,
        'interpretation':'Assignment guidance only. Preserve the reported CWE; route using evidence requirements and CVE mechanism evidence.',
        'rationale':info.get('mapping_rationale','')}
    if chain['errors'] or not chain['pillars'] or rec.get('abstraction')=='Pillar' or rec.get('status')=='Deprecated':
        row['rationale']='Missing/deprecated/unmapped CWE or bare Pillar; no detailed evidence requirement assigned.'
        return row
    paths=distances(cwe,t['records']);matches=[]
    for rule in p['rules']:
        anchors=[a for a in rule['anchors'] if a in paths]
        if anchors:
            distance=min(len(paths[a])-1 for a in anchors)
            matches.append({'rule_id':rule['id'],'distance':distance,
                'anchors':[{'cwe':a,'path':paths[a]} for a in anchors if len(paths[a])-1==distance],
                'facts':rule['facts'],'rationale':rule['rationale']})
    specialist=re.search(p['specialist_definition_pattern'],rec.get('name',''))
    platforms=info.get('platforms',[])
    named_languages={v['Name'] for v in platforms if v['kind']=='Language' and v.get('Name')}
    hdl_only=bool(named_languages and named_languages<={'Verilog','VHDL','SystemVerilog'} and
        not any(v['kind']=='Language' and v.get('Class')=='Not Language-Specific' for v in platforms))
    if specialist or hdl_only:
        selected=[{'rule_id':'hardware-design-evidence','distance':0,
            'anchors':[{'cwe':cwe,'path':[cwe]}],'facts':['hardware_design'],
            'rationale':'The detailed CWE name or explicit HDL platform scope requires hardware/design evidence outside the software analyzers.',
            'definition_span':[specialist.start(),specialist.end()] if specialist else None,
            'definition_quote':specialist.group() if specialist else ', '.join(sorted(named_languages)),
            'metadata_source':'CWE name' if specialist else 'official Applicable_Platforms.Language'}]
    elif matches:
        minimum=min(m['distance'] for m in matches)
        selected=[m for m in matches if m['distance']==minimum]
    else:selected=[]
    row['matched_rules']=selected
    row['shadowed_rules']=[m for m in matches if m not in selected]
    row['required_facts']=[{'id':f,**p['facts'][f]} for f in sorted({f for m in selected for f in m['facts']})]
    locations={f['location'] for f in row['required_facts']}
    row['resolution']='direct' if selected and all(m['distance']==0 for m in selected) else 'inherited' if selected else 'unresolved'
    if not locations or locations&{'specialist','cve_evidence'}:
        row['rationale']=' '.join(m['rationale'] for m in selected) or 'No explicit detailed/ancestor evidence rule; obtain mechanism evidence. No default source requirement.'
    else:
        row['source_requirement']='required' if 'source' in locations else 'not_required'
        row['operational_requirement']='required' if 'operator' in locations else 'conditional_on_CVE_context'
        row['rationale']=' '.join(m['rationale'] for m in selected)
        if row['source_requirement']=='not_required' and cwe not in p['operator_observable_baseline_allowlist']:
            row['source_requirement']='undetermined';row['operational_requirement']='undetermined'
            row['rationale']='The inherited operator rule is not explicitly admitted for this detailed CWE. Obtain mechanism evidence rather than extrapolating configuration answerability.'
    row['question_profiles']=[m['rule_id'] for m in selected]
    return row


@lru_cache(maxsize=1)
def catalog():
    t=load();p=policy();rows={}
    for cid,record in t['records'].items():
        chain=ancestry(cid,t)
        if record['abstraction']!='Pillar' and record['status']!='Deprecated' and chain['pillars'] and not chain['errors']:
            rows[cid]=profile(cid,rules=p,taxonomy=t)
    by_source=dict(Counter(r['source_requirement'] for r in rows.values()))
    per_pillar={}
    for cid,r in t['records'].items():
        if r['abstraction']=='Pillar':
            members=[v for v in rows.values() if cid in v['pillars']]
            per_pillar[cid]={'name':r['name'],'memberships':len(members),
                'by_source_requirement':dict(Counter(v['source_requirement'] for v in members))}
    summary={'schema':'ics-vex-cwe-evidence-catalog/2','version':p['version'],
        'taxonomy_version':t['version'],'taxonomy_xml_sha256':t['xml_sha256'],'policy_sha256':p['sha256'],
        'official_metadata_sha256':metadata()['sha256'],
        'detailed_cwes':len(rows),'pillar_count':len(per_pillar),'by_source_requirement':by_source,
        'snapshot_records':len(t['records']),
        'excluded_deprecated':[cid for cid,r in t['records'].items() if r['status']=='Deprecated'],
        'excluded_unmapped_active':[cid for cid,r in t['records'].items() if r['status']!='Deprecated' and r['abstraction']!='Pillar' and cid not in rows],
        'by_resolution':dict(Counter(r['resolution'] for r in rows.values())),
        'official_mapping_usage':dict(Counter(r['official_metadata'].get('mapping_usage','Unknown') for r in rows.values())),
        'unresolved_baseline_rules':dict(Counter(','.join(m['rule_id'] for m in r['matched_rules']) for r in rows.values() if r['source_requirement']=='undetermined')),
        'per_pillar':per_pillar,'multiple_pillar_membership_retained':True,
        'human_adjudicated':False,'independently_validated':False,
        'coverage_is_not_accuracy':True,'default_source_requirement_removed':True}
    return {'summary':summary,'profiles':rows}
