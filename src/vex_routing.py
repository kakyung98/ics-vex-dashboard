"""Preserve CWE provenance; automatic evidence assignment is currently unassigned."""
from src.cwe_context import ids
from src.cwe_taxonomy import load
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
        'routing_unknown':'Automatic evidence-routing criteria are unassigned. CWE taxonomy and source availability do not establish an analysis requirement.'}[branch]
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
    decisions=[]
    for cwe in cwes:
        row=profile(cwe,rules=rules,taxonomy=taxonomy)
        decisions.append({**row,'requirement':'undetermined','operational_required':False,
            'required_facts':[],'rule_id':'unassigned','reason':row['rationale'],
            'baseline_source_requirement':'undetermined','base_profile_resolution':'unresolved',
            'evidence':[],'refinement_rules':[],'cwe_sources':origins.get(cwe,[])})
    requirements={d['requirement'] for d in decisions}
    requirement=('undetermined' if not decisions or 'undetermined' in requirements else
                 'source_required' if 'source_required' in requirements else 'operational_review')
    operating=any(d['operational_required'] for d in decisions) and requirement!='undetermined'
    return workflow({'schema':'ics-vex-item4-route/3','requirement':requirement,
        'operational_required':operating,
        'operational_requirement_evidence':[],
        'required_facts':list({f['id']:f for d in decisions for f in d['required_facts']}.values()),
        'unresolved_cwes':[d['cwe'] for d in decisions if d['requirement']=='undetermined'],
        'question_profiles':sorted({q for d in decisions for q in d['question_profiles']}),
        'source_available':bool(source_available),'cwes':cwes,'pillars':sorted({p for d in decisions for p in d['pillars']}),
        'decisions':decisions,'policy_version':rules['version'],'policy_sha256':rules.get('sha256'),
        'taxonomy_version':taxonomy['version'],'taxonomy_xml_sha256':taxonomy.get('xml_sha256'),
        'official_metadata_sha256':metadata()['sha256'],
        'authority':rules['authority'],'human_adjudicated':False,'independently_validated':False,
        'initial_vex_status':'under_investigation','routing_confers_negative_verdict':False}, source_available=source_available)
