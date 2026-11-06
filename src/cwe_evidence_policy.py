"""Versioned evidence requirements, derived per detailed CWE, never VEX verdicts."""
from collections import Counter
from functools import lru_cache
from pathlib import Path
import hashlib,json
from src.cwe_taxonomy import load,ancestry
from src.cwe_evidence_plans import plan as evidence_plan, summarize as plan_summary
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
    if p.get('automatic_routing_enabled') is not False:
        raise ValueError('Automatic evidence assignment has no justified decision contract')
    for key in ('rules','facts','operator_observable_baseline_allowlist','source_refinements','operational_refinements','operational_rules'):
        if p.get(key):
            raise ValueError('Retired heuristic assignment must remain empty: '+key)


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
    row['evidence_plan']=evidence_plan(cwe,rec,info)
    row['evidence_plan']['source_snapshot']={'taxonomy_xml_sha256':t.get('xml_sha256'),
                                           'metadata_sha256':m['sha256']}
    row['official_metadata']={**{k:v for k,v in info.items() if k not in {'mapping_usage','mapping_rationale'}},'metadata_sha256':m['sha256'],
        'interpretation':'Official descriptions and detection suggestions support review; they do not prescribe the project routing rule.'}
    if chain['errors'] or not chain['pillars'] or rec.get('abstraction')=='Pillar' or rec.get('status')=='Deprecated':
        row['rationale']='Missing/deprecated/unmapped CWE or bare Pillar; no detailed evidence requirement assigned.'
        return row
    row['rationale']='No justified evidence-routing criteria are assigned. Official CWE membership and metadata are retained; source/operating requirements remain undetermined.'

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
        'unresolved_baseline_rules':dict(Counter(','.join(m['rule_id'] for m in r['matched_rules']) for r in rows.values() if r['source_requirement']=='undetermined')),
        'per_pillar':per_pillar,'multiple_pillar_membership_retained':True,
        'human_adjudicated':False,'independently_validated':False,
        'coverage_is_not_accuracy':True,'default_source_requirement_removed':True,
        'automatic_routing_enabled':False,'unassigned_profiles':len(rows),
        'evidence_plans':plan_summary(rows)}
    return {'summary':summary,'profiles':rows}
