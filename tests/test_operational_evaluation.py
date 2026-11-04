import pytest
from src.operational_evaluation import evaluate_assessments,evaluate_questions
from src.vex_roles import fingerprint

def gold(rid='a',label='likely_affected'):
    return {'id':rid,'assessment':label,'review_status':'adjudicated','reviewers':['human-a','human-b'],
            'adjudicator':'human-c','annotation_basis':'human_reviewed_source_and_scenario'}

def test_false_clearance_is_counted_and_abstentions_cannot_hide_it():
    refs=[gold(),gold('b'),gold('c','likely_not_affected')]
    p=[{'id':'a','assessment':'likely_not_affected'},{'id':'b','assessment':'likely_cannot_determine'}]
    m=evaluate_assessments(refs,p)
    assert m['unsafe_clearances']==m['affected_to_not_affected']==1
    assert m['affected_to_not_affected_rate']==.5
    assert m['decision_coverage']==1/3
    assert m['schema_rate']==2/3
    assert m['affected_to_not_affected_wilson95_upper']>.5

def test_pending_or_llm_labels_cannot_be_scored_as_expert_gold():
    row=gold();row['review_status']='pending'
    with pytest.raises(ValueError):evaluate_assessments([row],[])
    row=gold();row['annotation_basis']='llm_generated'
    with pytest.raises(ValueError):evaluate_assessments([row],[])

def test_quotes_alone_do_not_establish_question_quality():
    row=gold();row.update(description='Frames enter parser.',required_conditions=[{'id':'input-path'}])
    p={'id':'a','questions':[{'question':'Does the flaw exist?','evidence':'Frames enter parser.'}]}
    m=evaluate_questions([row],[p],[])
    assert m['literal_quote_rate']==1
    assert m['condition_coverage_recall']==0 and not m['semantic_evaluation_complete']
    review={**gold(),'prediction_sha256':fingerprint(p),'question_reviews':[{
        'condition_ids':['input-path'],'operator_answerable':True,'no_unsupported_assumptions':True,'non_leading':True}]}
    m=evaluate_questions([row],[p],[review])
    assert m['condition_coverage_recall']==1 and m['semantic_evaluation_complete']
    p['questions'][0]['question']='Changed after review'
    with pytest.raises(ValueError):evaluate_questions([row],[p],[review])

def test_missing_predictions_are_not_successful_semantic_evaluation():
    row=gold();row.update(description='Frames enter parser.',required_conditions=[{'id':'input-path'}])
    m=evaluate_questions([row],[],[])
    assert m['missing_or_empty_predictions']==1 and not m['semantic_evaluation_complete']

def test_benchmark_has_no_cve_or_identical_description_overlap():
    import json
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]/'data/operational_review_benchmark_v2'
    sets={}
    for split,n in [('train',800),('validation',100),('test',100)]:
        rows=[json.loads(l) for l in (root/(split+'.annotation.jsonl')).read_text(encoding='utf-8').splitlines()]
        assert len(rows)==n and all(r['review_status']=='pending' for r in rows)
        sets[split]={r['cve'] for r in rows}|{r['description_group_sha256'] for r in rows}
    assert not sets['train']&sets['validation'] and not sets['train']&sets['test'] and not sets['validation']&sets['test']
