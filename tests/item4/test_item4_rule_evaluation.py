from copy import deepcopy
from itertools import product
import pytest
from src.item4.evaluation import benchmark_rule_oracle as C; from src.item4.evaluation import rule_evaluation_runner as E


@pytest.fixture(scope='module')
def cases():return E.generate()[0]


def test_all_routes_and_assets_and_no_public_answers(cases):
    assert {c['expected']['rule_id'] for c in cases}=={'R'+str(i) for i in range(8)}
    assert len({c['asset_type_id'] for c in cases})==18
    assert {c['expected']['status'] for c in cases}==set(C.STATES)
    for case in cases:
        assert not {'reference','expected','split','mutation','template_id'} & E.C.public_case(case).keys()
        assert case['expected']==C.oracle(case)


@pytest.mark.parametrize('a,b',list(product((True,False,None),repeat=2)))
def test_ternary_truth_tables(a,b):
    leaf=lambda x:{'condition':x}
    # Independent specification via the total order False < unknown < True.
    order={False:0,None:1,True:2};reverse={0:False,1:None,2:True}
    assert C.truth({'op':'and','args':[leaf('a'),leaf('b')]},{'a':a,'b':b}) is reverse[min(order[a],order[b])]
    assert C.truth({'op':'or','args':[leaf('a'),leaf('b')]},{'a':a,'b':b}) is reverse[max(order[a],order[b])]
    assert C.truth({'op':'not','args':[leaf('a')]},{'a':a}) is (None if a is None else not a)


def test_required_vs_sufficient_and_scope(cases):
    necessary=next(deepcopy(c) for c in cases if c['template_id']=='necessary' and c['mutation']=='base' and c['asset_values'][0]['value']=='o')
    assert C.oracle(necessary)['status']=='under_investigation'
    positive=next(deepcopy(c) for c in cases if c['expected']['rule_id']=='R5')
    positive['facts']['conflicting']=True
    positive['facts']['supplier_status']='fixed'
    assert C.oracle(positive)['rule_id']=='R0'
    positive['facts']['conflicting']=False;positive['facts']['runtime_exact']=False
    assert C.oracle(positive)['rule_id']=='R2'


def test_missing_completeness_and_bad_bindings(cases):
    for case in cases:
        if case['mutation']=='absent_partial':assert C.oracle(case)['rule_id']=='R2'
        if case['template_id']=='and' and case['mutation'] in {'wrong_target','wrong_scope','wrong_asset_type','stale','missing_evidence','mixed'}:
            assert C.oracle(case)['formula_value']=='unknown'
    case=next(deepcopy(c) for c in cases if c['expected']['rule_id']=='R5')
    case['facts']['condition_binding_valid']=False
    assert C.oracle(case)['rule_id']=='R7'


def test_extraction_mutations_detected_and_id_invariant(cases):
    case=next(c for c in cases if c['template_id']=='and')
    ref=case['reference'];bad=deepcopy(ref);bad['expression']['op']='or'
    assert not E.extraction_score(ref,bad,case['source_text'])['exact']
    renamed=deepcopy(ref)
    renamed['conditions'][0]['id']='renamed'
    renamed['expression']['args'][0]['condition']='renamed'
    assert C.semantic_equal(ref,renamed)
    bad=deepcopy(ref);bad['conditions'][0]['quote']='invented quote'
    score=E.extraction_score(ref,bad,case['source_text'])
    assert not score['exact'] and score['fp']==1


def test_split_by_source_family(cases):
    splits={}
    for c in cases:splits.setdefault(c['source_text'],set()).add(c['split'])
    assert all(len(s)==1 for s in splits.values())


def test_no_predictions_has_no_precision():
    report=E.metrics([{'error':'offline'}])
    assert report['model_completed']==0
    assert all(c['precision'] is None for c in report['classes'].values())


def test_pipeline_never_receives_hidden_oracle(cases):
    case=next(c for c in cases if c['expected']['rule_id']=='R5')
    def fixture_runner(system,packet,*,role):
        # Deliberate test double, only tests plumbing; never a performance measurement.
        assert 'expected' not in str(packet) and 'reference' not in packet.get('case',{})
        if packet['schema']==C.EXTRACTION:p=case['reference']
        elif packet['schema']==C.REVIEW:p=dict(support='supported',issues=[],evidence_quotes=[case['reference']['conditions'][0]['quote']])
        elif packet['schema']==C.MAPPING:p=dict(values=[dict(condition_id=c['id'],key=c['key'],value='true',reason='fixture') for c in case['reference']['conditions']])
        else:p=dict(status='affected',rule_id='R5',evidence_refs=['source-1'],reason='fixture')
        return dict(prediction=p,model='TEST DOUBLE ONLY',llm_used=True)
    result=E.pipeline(case,fixture_runner)
    assert len(result['receipts'])==4


def test_controlled_review_mutations_have_computed_labels(cases):
    for case in cases[::19]:
        for candidate in E.review_candidates(case):
            assert (candidate['expected_support']=='supported') == (candidate['mutation']=='original')


def test_routing_track_calls_only_router(cases):
    case=next(c for c in cases if c['expected']['rule_id']=='R5');tasks=[]
    def runner(system,packet,*,role):
        assert packet['schema']==C.ROUTING;tasks.append('routing')
        return dict(prediction=dict(status='affected',rule_id='R5',evidence_refs=['source-1'],reason='fixture'),
                    model='TEST DOUBLE ONLY',llm_used=True)
    E.pipeline(case,runner,oracle_conditions=True,routing_only=True)
    assert tasks==['routing']


@pytest.mark.parametrize('mutation,rule,status',[
    ('fixed','R3','fixed'),('unaffected','R4','not_affected'),('absent_complete','R1','not_affected'),
    ('absent_partial','R2','under_investigation'),('conflict','R0','under_investigation'),
    ('runtime_unknown','R2','under_investigation'),('product_unbound','R0','under_investigation')])
def test_named_control_expectations(cases,mutation,rule,status):
    case=next(c for c in cases if c['mutation']==mutation)
    assert C.oracle(case)['rule_id']==rule
    assert C.oracle(case)['status']==status


def test_oracle_rejects_string_boolean(cases):
    case=deepcopy(cases[0]);case['facts']['scope_confirmed']='false'
    with pytest.raises(Exception):C.oracle(case)
