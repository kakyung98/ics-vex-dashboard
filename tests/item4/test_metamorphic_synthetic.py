from copy import deepcopy
from src.item4.evaluation import metamorphic_synthetic as E


def prediction(case):
    gold=case['gold'];source=case['record']['sources'][0]
    atoms=[]
    for key,g in gold['atoms'].items():
        quote=gold['evidence_quotes'][0]
        atoms.append(dict(id=key,category=g['category'],predicate=g['predicates'][0],target=g['target'],
            statement=g['positive'],value='',operator='eq',expected=True,extraction_confidence=.95,
            operational_quote=quote,source_refs=[dict(source_id=source['id'],quote=quote)]))
    return dict(prerequisites=atoms,scenarios=[dict(expression=gold['expression'])] if gold['expression'] else [],
                unknowns=['Operational conditions unspecified'] if gold['require_unknown'] else [],
                nonrequirements=[dict(statement='Authentication is not required.')] if gold['nonrequirements'] else [])


def test_all_constructed_gold_and_related_variants_have_consistent_oracle():
    cases=E.dataset();assert len(cases)==624
    for c in cases:
        assert E.judge(c,prediction(c))['case_correct'],c['id']
        assert c['split']==('dev' if int(c['base_id'].split('-')[1])<8 else 'test')
    for family in range(12):
        assert E.make_case(family,0)['record']['sources'][0]['text']!=E.make_case(family,8)['record']['sources'][0]['text']


def test_and_or_corruption_and_missing_qualifier_target_are_detected():
    case=E.make_case(1,9);draft=prediction(case)
    draft['scenarios'][0]['expression']=E.node('or',E.leaf('a'),E.leaf('b'))
    assert not E.judge(case,draft)['logic_correct']
    draft=prediction(case);draft['prerequisites'][0]['target']='feature';draft['prerequisites'][0]['statement']='A feature is enabled'
    result=E.judge(case,draft);assert result['fp']==1 and result['fn']==1


def test_three_valued_logic_rejects_classical_complement_simplification():
    excluded_middle=E.node('or',E.leaf('a'),E.node('not',E.leaf('a')))
    assert E.state(excluded_middle,{'a':None}) is None
    assert E.equivalent(E.node('not',E.node('and',E.leaf('a'),E.leaf('b'))),
        E.node('or',E.node('not',E.leaf('a')),E.node('not',E.leaf('b'))),['a','b'])


def test_duplicate_hallucination_and_invalid_empty_output_cannot_pass():
    case=E.make_case(0,9);draft=prediction(case)
    draft['prerequisites'].append(deepcopy(draft['prerequisites'][0]))
    assert E.judge(case,draft)['fp']==1
    empty=E.make_case(5,9)
    assert not E.judge(empty,None,valid=False)['case_correct']
    cases=[E.make_case(0,8),E.make_case(0,8,'rename')]
    report=E.summarize(cases,[dict(id=cases[0]['id'],arm='D',draft=prediction(cases[0]),valid=True)])
    score=report['scores']['baseline/D/test']
    assert score['cases']==2 and score['logic_accuracy']==.5 and score['grounded_mr_rate']==0


def test_two_hallucinated_referenced_targets_do_not_crash_mr_scoring():
    cases=[E.make_case(0,8),E.make_case(0,8,'rename')];rows=[]
    for c in cases:
        draft=prediction(c);draft['prerequisites'][0]['target']='invented service'
        draft['prerequisites'][0]['statement']='The invented service is enabled.'
        rows.append(dict(id=c['id'],arm='D',draft=draft,valid=True))
    s=E.summarize(cases,rows)['scores']['baseline/D/test']
    assert s['grounded_mr_rate']==0 and s['counts']['fp']==2
    assert not E.equivalent(E.leaf('unmapped'),E.leaf('unmapped'),[])


def test_matching_target_cannot_hide_lost_assessed_actor_or_access_origin():
    for family in (9,11):
        case=E.make_case(family,8);draft=prediction(case)
        p=draft['prerequisites'][0]
        p['statement']=p['statement'].replace('the assessed principal','a principal').replace(' from the assessed origin','')
        result=E.judge(case,draft)
        assert result['fp']==1 and result['fn']==1 and not result['case_correct']


def test_registered_enabled_configuration_alias_is_not_a_false_positive():
    case=E.make_case(0,8);draft=prediction(case)
    draft['prerequisites'][0]['predicate']='configuration_required'
    assert E.judge(case,draft)['case_correct']
    draft['prerequisites'][0]['statement']='The feature is required.'
    draft['prerequisites'][0]['value']=''
    assert not E.judge(case,draft)['case_correct']


def test_nonrequirement_wording_and_actual_permission_possession_are_checked():
    case=E.make_case(6,8);draft=prediction(case)
    draft['nonrequirements'][0]['statement']='Authentication is required.'
    assert not E.judge(case,draft)['case_correct']
    case=E.make_case(9,8);draft=prediction(case)
    draft['prerequisites'][0]['statement']='The assessed principal requires permission to perform '+case['gold']['atoms']['a']['target']+'.'
    assert not E.judge(case,draft)['case_correct']
