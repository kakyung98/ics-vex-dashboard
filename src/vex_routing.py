"""#4: CWE Pillar + specific weakness + advisory evidence chooses the analysis arm."""
from pathlib import Path
from functools import lru_cache
import re,json,hashlib
from src.cwe_context import ids
from src.cwe_taxonomy import load,ancestry
ROOT=Path(__file__).resolve().parents[1]
SOURCE_HINT=re.compile(r'buffer.{0,24}overflow|out.of.bounds|use.after.free|double.free|integer.{0,16}(?:overflow|underflow)|memory corruption|race condition|null.pointer|uninitialized (?:memory|pointer)|type confusion',re.I)
OPERATIONAL_HINT=re.compile(r'\b(?:remote|network|authenticated|unauthenticated|privileges?|configuration|enabled|disabled|user interaction|local attacker|physical access)\b',re.I)


def workflow(route, *, source_available=False):
    """Source availability and context needs form four workflows, not verdicts."""
    source = route['requirement'] == 'source_required'
    operating = route.get('operational_required', route['requirement'] == 'operational_review')
    branch = ('source_missing' if source and not source_available else
              'source_to_operational' if source and operating else
              'source_only' if source else
              'operational_only' if operating else 'routing_unknown')
    reason = {
        'source_missing':'Source analysis is required, but no source analysis result has been supplied.',
        'source_only':'Review source/build/path evidence for the declared product scope.',
        'source_to_operational':'Source analysis is recorded; operating context is also required by CVE/advisory evidence.',
        'operational_only':'Use common and CVE-specific operator-answerable rule questions.',
        'routing_unknown':'CWE / advisory evidence is insufficient to determine the analysis requirement.'}[branch]
    return {**route, 'source_required': source, 'operational_required': operating, 'reason':reason,
            'workflow_policy_version':'four-branch-v1',
            'source_available': bool(source_available), 'workflow_branch': branch,
            'entry_direction': 'source_to_operational' if source and operating else 'source' if source else 'operational',
            'route': 'defer_missing_source' if source and not source_available else
                'source_analysis' if source else 'operational_questions' if operating else 'defer_routing_unknown'}


@lru_cache(maxsize=1)
def policy():
    blob=(ROOT/'data/item4_routing_policy_v1.json').read_bytes();p=json.loads(blob)
    p['sha256']=hashlib.sha256(blob).hexdigest();return p


def classify(case,*,source_available=False,taxonomy=None,rules=None):
    rules=rules or policy();taxonomy=taxonomy or load()
    contexts=case.get('cwe_context') or {};origins={}
    for entry in contexts.get('entries',[]):origins[entry['id']]=entry.get('sources',[])
    cwes=sorted(set(ids(case.get('cwe'))+ids(case.get('cwes'))+list(origins)))
    blocks=[{'id':'description','text':case.get('description') or '', 'source':'CVE Description'}]
    blocks.extend({'id':s['id'],'text':s['text'],'source':s.get('source',{})} for s in case.get('routing_sources',[])
                  if s.get('source_kind') in {'description','summary'})
    decisions=[]
    for cwe in cwes:
        chain=ancestry(cwe,taxonomy);anc=set(chain['ancestors']);pillars=set(chain['pillars'])
        evidence=[];requirement='undetermined';reason='No supported specific CWE / Pillar ancestry.';rule_id='unmapped'
        hints=[]
        for block in blocks:
            m=SOURCE_HINT.search(block['text'])
            if m:hints.append({'source_id':block['id'],'span':[m.start(),m.end()],'quote':m.group(),'source':block['source']})
        if chain['errors'] or not pillars or taxonomy['records'][cwe].get('status')=='Deprecated':pass
        elif anc&set(rules['source_required_ancestors']) or hints:
            requirement='source_required';rule_id='code-causality';evidence=hints
            reason='The weakness or explicit CVE evidence requires code-level target / data-flow / path review.'
        else:
            matched=None
            for rule in rules['operational_rules']:
                if not anc&set(rule['cwe_ancestors']):continue
                for block in blocks:
                    m=re.search(rule['evidence_pattern'],block['text'])
                    if m:
                        matched=rule;evidence=[{'source_id':block['id'],'span':[m.start(),m.end()],
                            'quote':m.group(),'source':block['source']}];break
                if matched:break
            if matched:
                requirement='operational_review';rule_id=matched['id']
                reason='The specific weakness and advisory evidence expose operator-observable configuration or protocol facts.'
            elif chain['abstraction']!='Pillar' and pillars&set(rules['source_default_pillars']):
                requirement='source_required';rule_id='conservative-pillar-default'
                reason='No evidence-supported operational rule applies; the project policy requires source review for this specific weakness.'
        decisions.append({**chain,'requirement':requirement,'rule_id':rule_id,'reason':reason,'evidence':evidence,
                          'cwe_sources':origins.get(cwe,[])})
    requirements={d['requirement'] for d in decisions}
    requirement=('source_required' if 'source_required' in requirements else
                 'undetermined' if not decisions or 'undetermined' in requirements else 'operational_review')
    route=('source_analysis' if source_available else 'defer_missing_source') if requirement=='source_required' else (
        'operational_questions' if requirement=='operational_review' else 'defer_routing_unknown')
    operational_evidence=[]
    if requirement=='source_required':
        for block in blocks:
            for m in OPERATIONAL_HINT.finditer(block['text']):
                operational_evidence.append({'source_id':block['id'],'span':[m.start(),m.end()], 'quote':m.group()})
    return workflow({'schema':'ics-vex-item4-route/2','requirement':requirement,'route':route,
        'operational_required':requirement=='operational_review' or bool(operational_evidence),
        'operational_requirement_evidence':operational_evidence,
        'source_available':bool(source_available),'cwes':cwes,'pillars':sorted({p for d in decisions for p in d['pillars']}),
        'decisions':decisions,'policy_version':rules['version'],'policy_sha256':rules.get('sha256'),
        'taxonomy_version':taxonomy['version'],'taxonomy_xml_sha256':taxonomy.get('xml_sha256'),
        'authority':rules['authority'],'human_adjudicated':False,
        'initial_vex_status':'under_investigation','routing_confers_negative_verdict':False,
        'reason':{'defer_missing_source':'Source analysis is required, but source code is unavailable.',
                  'source_analysis':'Source analysis is required; inspect the supplied source and actual build scope.',
                  'operational_questions':'Use common and CVE-specific operator-answerable questions.',
                  'defer_routing_unknown':'CWE / advisory evidence is insufficient to determine the analysis requirement.'}[route]}, source_available=source_available)
