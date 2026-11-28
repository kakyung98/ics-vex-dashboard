"""Historical contract evaluation for the retired CVSS-common questionnaire.

Synthetic logic agreement is not independent extraction or field accuracy.
"""
from collections import Counter
from copy import deepcopy
from pathlib import Path
import json
from jsonschema import Draft202012Validator
from src.item4.analysis import cvss_operational_questions as C
from src.item4.decision.condition_logic_evaluation import logic,leaves

VERSION='item4-cvss-operational-benchmark/2'
ROOT=Path(__file__).resolve().parents[3]
DATA=ROOT/'research_records/item4_evaluation_cleanup_20261126/cvss_operational'
CASE_SCHEMA=DATA/'case.schema.json'


def evaluate_case(case):
    Draft202012Validator(json.loads(CASE_SCHEMA.read_text(encoding='utf-8'))).validate(case)
    expression=case['special_expression']
    ids=[p['id'] for p in case['special_conditions']]
    if len(set(ids))!=len(ids) or (expression and not leaves(expression)<=set(ids)):
        raise ValueError('Duplicate or unbound special condition ID')
    scope=dict(id=case['id'],cve=case['cve'],declared_ref=case['component_ref'])
    # Expected values and real-world labels are never passed to the selector.
    result=dict(cvss_assessments=case['cvss_assessments'],prerequisite=dict(draft=dict(
        scenarios=[dict(expression=expression)] if expression else [])))
    source_questions=[dict(id=p['id'],condition_id=p['id'],cvss_metrics=p.get('cvss_metrics',[]))
                      for p in case['special_conditions']]
    plan=C.build(scope,result,case['asset_type_id'],source_questions)
    answers={q['id']:case['common_answers'].get(q['cvss_axis']+':'+q['cvss_value'],'unknown') for q in plan['questions']}
    answers.update(case['special_answers'])
    common=C.evaluate(plan,answers)
    special=logic(expression,{key:{'o':'true','x':'false'}.get(case['special_answers'].get(key),'unknown') for key in ids}) if expression else 'unknown'
    value=logic(dict(op='and',args=[dict(condition='common'),dict(condition='special')]),dict(common=common['value'],special=special))
    return dict(id=case['id'],cve=case['cve'],value=value,expected=case['expected_path_state'],
        correct=value==case['expected_path_state'],common_state=common['value'],special_state=special,
        common_questions=[q['cvss_axis']+':'+q['cvss_value'] for q in plan['questions']],
        special_question_count=len(ids),actual_exploitable=case.get('actual_exploitable'),
        product_vex_status='under_investigation',scope='synthetic_question_and_logic_contract')


def run(cases):
    cases=list(cases)
    rows=[evaluate_case(case) for case in cases]
    if len({r['id'] for r in rows})!=len(rows):raise ValueError('Duplicate benchmark case ID')
    return dict(version=VERSION,question_schema=C.VERSION,input_case_digest=C.digest(cases),question_schema_digest=C.digest(C.SCHEMA),cases=len(rows),
        correct=sum(r['correct'] for r in rows),logic_agreement=(sum(r['correct'] for r in rows)/len(rows) if rows else None),
        state_counts=dict(Counter(r['value'] for r in rows)),llm_called=False,
        independent_extraction_accuracy_measured=False,independent_field_accuracy_measured=False,
        historical_cluster_scores_reused=False,rows=rows)


def population_index():
    """Keep every original target CVE, including missing CVSS and empty descriptions."""
    seen=set()
    for path in sorted((ROOT/'site/asset_vulntology').glob('records_*.json')):
        for cve,record in json.loads(path.read_text(encoding='utf-8')).items():
            if cve in seen:raise ValueError('Duplicate target CVE')
            seen.add(cve)
            assessments=C.lookup(cve)
            case=dict(id='population:'+cve,cve=cve,declared_ref=None)
            plan=C.build(case,dict(cvss_assessments=assessments))
            yield dict(cve=cve,cvss_assessments=assessments,
                common_questions=plan['questions'],gaps=plan['gaps'],description_available=bool(record.get('description')),
                special_extraction_status='not_run',actual_exploitable=None,
                independent_gold_available=False)
