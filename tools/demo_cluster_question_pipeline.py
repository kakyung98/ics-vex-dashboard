"""Export explicit synthetic demonstrations, never real-CVE benchmark gold."""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.cluster_question_pipeline import compile_plan,evaluate_plan,export_openvex,SCOPE
from tools.discover_ics_clusters import write_json,write_jsonl,sha


def fixtures():
    reviews=[];records=[];members=[];cases=[]
    reviewed=dict(validation_status='approved',reviewer='synthetic-demonstration-only',reviewed_at='2026-01-02T00:00:00Z')
    for cve,op,special in [('SIM-PLC-A','and','feature'),('SIM-PLC-B','or','file')]:
        text=f'EXPLICIT SYNTHETIC PREMISE: {cve} requires network {op.upper()} {special}; these are all fixture alternatives.'
        source=dict(id=cve+':source',text=text)
        ref=dict(source_id=source['id'],span=[0,len(text)],quote=text)
        conditions=[];questions=[]
        for name,target,predicate,question in [
            ('network','fixture-controller:service','network_reachable','Can the documented attack path reach the controller service?'),
            (special,'fixture-controller:'+special,special+'_present','Does the fixture '+special+' condition hold?')]:
            conditions.append(dict(id=name,target=target,predicate=predicate,source_refs=[ref],operator_observable=True,
                                   necessity='required_for_path',**reviewed))
            questions.append(dict(id=cve+':'+name,text=question,target=target,cost=1,**reviewed,
                mappings=[dict(condition_id=name,coverage='FULL',source_refs=[ref],
                               answers=dict(yes='true',no='false',unknown='unknown'),**reviewed)]))
        reviews.append(dict(cve=cve,conditions=conditions,questions=questions,
            formula=dict(expression=dict(op=op,args=[{'condition':'network'},{'condition':special}]),
                         coverage_complete=True,source_refs=[ref],**reviewed)))
        records.append(dict(cve=cve,sources=[source]))
        members.append(dict(cve=cve,cluster_ids=['secondary:fixture-network']))
        binding=dict(cve=cve,asset_ref='fixture-asset',product='fixture-controller',build='1',
                     config_baseline='fixture',mode='normal',evaluated_at='2026-02-01T00:00:00Z')
        def evidence(eid,kind):
            return dict(id=eid,kind=kind,binding=deepcopy(binding),source='Controlled synthetic record',
                        quote='SIMULATED: explicitly supplied fixture fact, not an observed ICS asset.',
                        reviewer='synthetic-demonstration-only',observed_at='2026-01-01T00:00:00Z',
                        reviewed_at='2026-01-02T00:00:00Z',valid_until='2027-01-01T00:00:00Z')
        cases.append(dict(binding=binding,answers=[],formula_evidence_ids=['complete'],
            evidence=[evidence('complete','reviewed_complete_route_analysis'),
                      evidence('network','reviewed_nonexecution_analysis'),evidence(special,'reviewed_nonexecution_analysis')]))
    return reviews,records,members,cases


def run():
    out=ROOT/'results/ics_cluster_question_demo_v2'
    if out.exists():raise FileExistsError('Synthetic demo is frozen; use a new version')
    reviews,records,members,base=fixtures();plan=compile_plan(reviews,records,members)
    def answer(value):
        return dict(plan_id=plan['plan_id'],question_id=plan['common_questions'][0]['id'],
            target=plan['common_questions'][0]['target'],value=value,
            scope={k:base[0]['binding'][k] for k in SCOPE},
            evidence_by_cve={c['binding']['cve']:['network'] for c in base})
    scenarios=[]
    def record(name,cases,common,expected):
        result=evaluate_plan(plan,records,cases,common)
        statuses=[r['status'] for r in result['decisions']]
        if statuses!=expected:raise AssertionError((name,statuses,expected))
        scenarios.append(dict(name=name,cases=cases,common_answers=common,evaluation=result,expected_fixture_statuses=expected,
            openvex=export_openvex(result,'ICS-VEX synthetic demonstration',datetime.now(timezone.utc).isoformat())))
    record('no_answers',deepcopy(base),[],['under_investigation']*2)
    record('common_no_and_vs_or',deepcopy(base),[answer('no')],['not_affected','under_investigation'])
    cases=deepcopy(base)
    cases[1]['answers']=[dict(question_id='SIM-PLC-B:file',value='no',evidence_ids=['file'])]
    record('all_alternative_paths_structurally_false',cases,[answer('no')],['not_affected']*2)
    cases=deepcopy(base)
    for case in cases:
        special='feature' if case['binding']['cve']=='SIM-PLC-A' else 'file'
        case['answers']=[dict(question_id=case['binding']['cve']+':'+special,value='yes',evidence_ids=[special])]
    record('all_conditions_true_but_no_impact_proof',deepcopy(cases),[answer('yes')],['under_investigation']*2)
    supplier=deepcopy(cases[1]['evidence'][0]);supplier.update(id='supplier',kind='supplier_product_status',asserted_status='affected')
    cases[1]['evidence'].append(supplier)
    cases[1]['product_findings']=[dict(status='affected',evidence_ids=['supplier'],action_statement='Apply the explicitly simulated supplier fix.')]
    record('reviewed_impact_proof',cases,[answer('yes')],['under_investigation','affected'])
    cases=deepcopy(base)
    fix=deepcopy(cases[0]['evidence'][0]);fix.update(id='fix',kind='supplier_fix_mapping',asserted_status='fixed')
    installed=deepcopy(cases[0]['evidence'][0]);installed.update(id='installed',kind='installation_record',execution_verified=True)
    cases[0]['evidence'] += [fix,installed]
    cases[0]['product_findings']=[dict(status='fixed',evidence_ids=['fix','installed'])]
    record('verified_active_fix',cases,[],['fixed','under_investigation'])
    cases=deepcopy(base)
    for case in cases:case['evidence'][1]['kind']='firewall_policy'
    record('reversible_filter_is_not_structural_absence',cases,[answer('no')],['under_investigation']*2)
    cases=deepcopy(base)
    cases[0]['answers']=[dict(question_id='SIM-PLC-A:network',value='yes',evidence_ids=['network'])]
    record('conflicting_shared_and_individual_answers',cases,[answer('no')],['under_investigation']*2)
    out.mkdir()
    write_json(out/'question_plan.json',plan);write_jsonl(out/'source_records.jsonl',records)
    write_jsonl(out/'review_contracts.jsonl',reviews);write_jsonl(out/'memberships.jsonl',members)
    write_json(out/'scenarios.json',scenarios)
    for scenario in scenarios:write_json(out/(scenario['name']+'.openvex.json'),scenario['openvex'])
    summary=dict(synthetic=True,real_cve_accuracy=None,scenarios=len(scenarios),all_expected_statuses_matched=True,
                 common_questions=len(plan['common_questions']),specific_questions=sum(len(c['specific_questions']) for c in plan['cves']))
    write_json(out/'summary.json',summary)
    write_json(out/'manifest.json',dict(script_sha256=sha(__file__),artifacts={p.name:sha(p) for p in out.iterdir() if p.is_file()}))
    print(json.dumps(summary,indent=2))


if __name__=='__main__':run()
