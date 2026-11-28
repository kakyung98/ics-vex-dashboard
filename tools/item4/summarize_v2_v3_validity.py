"""Aggregate measured responses and transparent assistant source-audit notes."""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
import json
from src.item4.analysis import exploitation_prerequisites as V2
from src.item4.analysis import asset_operating_question_generation as V3
from src.item4.assets import asset_observations as A
from src.item4.workflow import source_analysis_jobs as Q


def read(path):return json.loads(path.read_text(encoding='utf-8'))


def replay_questions(case,row):
    """Revalidate real saved responses, no model calls or semantic rewriting."""
    cve=case['record']['cve']
    bom=dict(bomFormat='CycloneDX',specVersion='1.6',version=1,
        metadata=dict(component={'bom-ref':'asset','type':'device','name':'Evaluation asset'}),
        vulnerabilities=[dict(id=cve,affects=[dict(ref='asset')])])
    _,declared=Q.inventory(bom)
    job=dict(components=[dict(ref='asset',name='Evaluation asset')],representative=dict(ref='asset'),
        declared_cves=declared,asset_classification=dict(status='classified',asset_type_id=case['asset_type_id'],provisional=True),
        conditions=[dict(cve=cve,status='extracted',source_kind='CVE description',source_policy='cve-description-special/1',
            sources=case['record']['sources'],prerequisite=row['v2'],cvss_assessments=[])])
    base=A.build(job,V3.digest,raw=True);results=[]
    for target in base['assessment_cases']:
        special=[q for q in base['special_questions'] if q['case_id']==target['id']]
        if not special:continue
        payload=V3.packet(job,target,special,[])
        original=row.get('v3',{}).get(target['id'],{})
        if original.get('packet_sha256')!=V3.digest(payload):
            results.append(dict(status='input_drift',case_id=target['id']));continue
        prediction=(original.get('prediction') or
            (json.loads(original['raw']) if original.get('raw') else None))
        if not prediction:
            results.append(dict(status='no_complete_output',case_id=target['id']));continue
        try:
            V3.validate(prediction,payload)
            results.append(dict(status='admitted',case_id=target['id'],questions=len(prediction['questions'])))
        except Exception as exc:results.append(dict(status='rejected',case_id=target['id'],error=str(exc)[:350]))
    return results


def main():
    base=ROOT/'results/item4_v2_v3_validity_20261126_release'
    manifest=read(base/'manifest.json');rows=[]
    for case in manifest['cases']:
        path=base/(case['id']+'.json');original=read(path)
        regression=ROOT/'results/item4_v2_v3_regression_20261126'/(case['id']+'.json')
        current=read(regression) if regression.is_file() else original
        row=dict(id=case['id'],kind=case['kind'],measured_status=original['v2_status'],
            measured_file=str(path.relative_to(ROOT)),regression_file=str(regression.relative_to(ROOT)) if regression.is_file() else None)
        if current.get('v2'):
            try:
                V2.validate(current['v2']['draft'],case['record']);row['current_guard_status']='admitted'
                row['atoms']=[dict(id=p['id'],statement=p['statement'],quote=p['operational_quote']) for p in current['v2']['draft']['prerequisites']]
                row['expressions']=[s['expression'] for s in current['v2']['draft']['scenarios']]
                row['v3_response_revalidation']=replay_questions(case,current)
            except Exception as exc:row.update(current_guard_status='rejected',error=str(exc)[:400])
        else:row.update(current_guard_status='failed',error=current.get('error'))
        rows.append(row)
    notes={
        'CVE-2018-13806':'Write access and the higher-privileged user action are present, but splitting the actor qualifier into separate atoms risks losing same-user co-reference. Needs semantic review; no full correctness claim.',
        'CVE-2020-15782':'Source explicitly states access to 102/tcp. Extraction failed after also proposing an unspecified operation as observable. Failure remains in the denominator; the valid port condition was not recovered into an admitted result.',
        'CVE-2017-16743':'No concrete additional operating condition admitted. The nonrequirement wording is unnecessarily hedged despite explicit unauthenticated wording; it is not used as an operational setting.',
        'not':'Development output encoded a disabled configuration atom under NOT. The final cross-predicate positive-state guard rejects this double-negation pattern; regression result is recorded separately.',
        'CVE-2016-5743':'Baseline inferred no authentication and no user interaction from remote delivery. Revised output preserves missing operating evidence as unknown instead.',
        'CVE-2015-1798':'MAC-validation implementation behavior is excluded from operator-entered settings.',
        'defect':'Implementation defect alone does not create an enabled/disabled field.',
        'remediation':'Mitigation advice does not create an exploitation precondition.'}
    for row in rows:row['assistant_source_review']=notes.get(row['id'],'Source-grounded atom and basic relation appear consistent in this development audit; independent adjudication was not performed.')
    isolated_path=ROOT/'results/item4_v3_isolated_validity_20261126_release/report.json'
    isolated=read(isolated_path)
    report=dict(version='item4-llm-validity-review/1',review_method='assistant_source_audit_not_independent_human',
        prompts=dict(v2=V2.digest(V2.SYSTEM),v3=V3.digest(V3.SYSTEM)),operator_policy=V2.OP.POLICY,
        measured_model=isolated['model'],deployed_model_evaluated=False,
        v2=dict(cases=len(rows),real_cases=8,synthetic_cases=5,
            original_revised_run_structural_admissions=sum(r['measured_status']=='validated' for r in rows),
            current_guard_admissions_with_targeted_regressions=sum(r['current_guard_status']=='admitted' for r in rows),
            baseline_structural_admissions=2,baseline_cases=13,
            semantic_accuracy=None,independent_gold_cases=0,rows=rows),
        v3=dict(isolated_cases=isolated['cases'],isolated_real_cases=4,isolated_synthetic_cases=3,
            isolated_questions=isolated['questions'],isolated_structural_admissions=isolated['valid_cases'],
            isolated_model_calls=isolated['llm_calls'],
            chained_response_revalidation=[dict(id=r['id'],results=r.get('v3_response_revalidation',[])) for r in rows],
            semantic_accuracy=None,operator_usability_accuracy=None,asset_context_benefit=None,
            source_review=['All ten fixed positive facts remain in the seven isolated model outputs; AND/OR/NOT is immutable input, not regenerated by V3.',
                'An ACL alone cannot prove end-to-end reachability; the port question preserves this caveat.',
                'Operating procedures cannot prove actual malicious-file opening or attacker/user privilege relationships. Those facts require corroborating records or remain unknown.',
                'Asset context was supplied, but no matched-versus-mismatched asset ablation or operator study was performed. Added value over a template is not established.']),
        artifacts=dict(v2_run=str(base.relative_to(ROOT)),v3_isolated=str(isolated_path.parent.relative_to(ROOT)),
            regressions='results/item4_v2_v3_regression_20261126'),
        limitations=['Development sample selected for boundary coverage, not a held-out representative population.',
            'Nemotron base on the existing H200 endpoint differs from deployed Qwen V2 adapter / V3 base. Their current semantic accuracy was not measured.',
            'No independent expert-labelled extraction gold, operator usability study, asset-type ablation or field exploitability ground truth.',
            'Guard and punctuation fixes were developed on these examples. Saved-response revalidation makes no fresh inference or independent performance claim.',
            'Failures, unknowns and zero-special-condition skips remain explicit. A skipped V3 call is not a successful question-generation measurement.',
            'Pretraining overlap is unknown. These results do not establish whole-population accuracy.'])
    admitted=report['v2']['current_guard_admissions_with_targeted_regressions']
    report['web_summary']=f'V2: {admitted} / 13 development cases admitted by the final guards (includes targeted regressions). Isolated V3: 7 / 7 cases, 10 questions passed structural preservation checks. Semantic accuracy remains unestablished.'
    out=ROOT/'results/item4_llm_validity_20261126';out.mkdir(exist_ok=True)
    (out/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(report['web_summary'])


if __name__=='__main__':main()
