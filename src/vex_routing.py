"""#4: CWE Pillar + specific weakness + advisory evidence chooses the analysis arm."""
import re
from src.cwe_context import ids
from src.cwe_taxonomy import load,ancestry
from src.cwe_evidence_policy import policy,profile,metadata


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
        'source_to_operational':'Source analysis is recorded; the CWE evidence profile and CVE context also require operating evidence.',
        'operational_only':'Use common and CVE-specific operator-answerable rule questions.',
        'routing_unknown':'CWE / advisory evidence is insufficient to determine the analysis requirement.'}[branch]
    return {**route, 'source_required': source, 'operational_required': operating, 'reason':reason,
            'workflow_policy_version':'four-branch-v1',
            'source_available': bool(source_available), 'workflow_branch': branch,
            'entry_direction': 'source_to_operational' if source and operating else 'source' if source else 'operational',
            'route': 'defer_missing_source' if source and not source_available else
                'source_analysis' if source else 'operational_questions' if operating else 'defer_routing_unknown'}


def classify(case,*,source_available=False,taxonomy=None,rules=None):
    rules=rules or policy();taxonomy=taxonomy or load()
    contexts=case.get('cwe_context') or {};origins={}
    for entry in contexts.get('entries',[]):origins[entry['id']]=entry.get('sources',[])
    cwes=sorted(set(ids(case.get('cwe'))+ids(case.get('cwes'))+list(origins)))
    blocks=[{'id':'description','text':case.get('description') or '', 'source':'CVE Description'}]
    blocks.extend({'id':s['id'],'text':s['text'],'source':s.get('source',{})} for s in case.get('routing_sources',[])
                  if s.get('source_kind') in {'description','summary'})
    # Repeated descriptions in NVD/CSAF do not add independent routing evidence.
    blocks=list({b['text']:b for b in reversed(blocks) if b['text']}.values())
    decisions=[];context_evidence=[]
    for block in blocks:
        for m in re.finditer(rules['context_pattern'],block['text']):
            context_evidence.append({'source_id':block['id'],'span':[m.start(),m.end()],
                'quote':m.group(),'source':block['source'],'role':'context_discovery_not_proven_prerequisite'})
    for cwe in cwes:
        row=profile(cwe,rules=rules,taxonomy=taxonomy);anc=set(row['ancestors'])
        source=row['source_requirement'];operating=row['operational_requirement']=='required'
        facts={f['id']:f for f in row['required_facts']};evidence=[];refinements=[]
        valid=not row['errors'] and row['pillars'] and row['abstraction']!='Pillar' and row.get('status')!='Deprecated'
        specialized=any(f['location']=='specialist' for f in facts.values())
        if valid and not specialized:
            for rule in rules['source_refinements']:
                for block in blocks:
                    m=re.search(rule['pattern'],block['text'])
                    if m:
                        source='required';facts[rule['fact']]={'id':rule['fact'],**rules['facts'][rule['fact']]}
                        refinements.append(rule['id']);evidence.append({'source_id':block['id'],'span':[m.start(),m.end()],
                            'quote':m.group(),'source':block['source'],'rule_id':rule['id']})
            for rule in rules['operational_refinements']:
                override=bool(set(rule.get('override_source_profiles',[]))&set(row['question_profiles']))
                if source=='undetermined' or override and not refinements:
                    if not anc&set(rule['eligible_anchors']):continue
                    for block in blocks:
                        m=re.search(rule['pattern'],block['text'])
                        if m:
                            source='not_required';operating=True;refinements.append(rule['id'])
                            if override:
                                facts={f:v for f,v in facts.items() if v['location']!='source'}
                            row['question_profiles'].append(rule['question_profile'])
                            for fact in rule['facts']:facts[fact]={'id':fact,**rules['facts'][fact]}
                            evidence.append({'source_id':block['id'],'span':[m.start(),m.end()],
                                'quote':m.group(),'source':block['source'],'rule_id':rule['id']});break
        if source=='required' and context_evidence:operating=True
        if refinements and source!='undetermined':facts.pop('cve_specific_mechanism',None)
        if operating:
            facts['actor_and_access_scope']={'id':'actor_and_access_scope',**rules['facts']['actor_and_access_scope']}
        requirement='source_required' if source=='required' else 'operational_review' if source=='not_required' and operating else 'undetermined'
        decisions.append({**row,'requirement':requirement,'source_requirement':source,
            'operational_required':operating,'required_facts':list(facts.values()),
            'rule_id':row['matched_rules'][0]['rule_id'] if row['matched_rules'] else 'unmapped',
            'reason':row['rationale']+(' CVE evidence refines the mechanism using: '+', '.join(sorted(set(refinements)))+'.' if refinements else ''),
            'baseline_source_requirement':row['source_requirement'],
            'base_profile_resolution':row['resolution'],
            'resolution':'cve_refined' if refinements else row['resolution'],
            'evidence':evidence,'refinement_rules':sorted(set(refinements)),
            'cwe_sources':origins.get(cwe,[])})
    requirements={d['requirement'] for d in decisions}
    requirement=('undetermined' if not decisions or 'undetermined' in requirements else
                 'source_required' if 'source_required' in requirements else 'operational_review')
    operating=any(d['operational_required'] for d in decisions) and requirement!='undetermined'
    return workflow({'schema':'ics-vex-item4-route/3','requirement':requirement,
        'operational_required':operating,
        'operational_requirement_evidence':context_evidence if operating else [],
        'required_facts':list({f['id']:f for d in decisions for f in d['required_facts']}.values()),
        'unresolved_cwes':[d['cwe'] for d in decisions if d['requirement']=='undetermined'],
        'question_profiles':sorted({q for d in decisions for q in d['question_profiles']}),
        'source_available':bool(source_available),'cwes':cwes,'pillars':sorted({p for d in decisions for p in d['pillars']}),
        'decisions':decisions,'policy_version':rules['version'],'policy_sha256':rules.get('sha256'),
        'taxonomy_version':taxonomy['version'],'taxonomy_xml_sha256':taxonomy.get('xml_sha256'),
        'official_metadata_sha256':metadata()['sha256'],
        'authority':rules['authority'],'human_adjudicated':False,'independently_validated':False,
        'initial_vex_status':'under_investigation','routing_confers_negative_verdict':False}, source_available=source_available)
