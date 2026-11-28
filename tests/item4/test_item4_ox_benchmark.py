from src.item4.evaluation.operator_observation_benchmark import answer_vectors; from src.item4.evaluation.operator_observation_benchmark import truth; from src.item4.evaluation.operator_observation_benchmark import source_bindings; from src.item4.evaluation.operator_observation_benchmark import candidate; from src.item4.evaluation.operator_observation_benchmark import metrics


def test_exhaustive_vectors_and_unknown_logic():
    vectors,coverage=answer_vectors([dict(id='b'),dict(id='a')])
    assert len(vectors)==9 and coverage['exhaustive']
    expr=dict(op='and',args=[dict(condition='a'),dict(op='not',args=[dict(condition='b')])])
    assert truth(expr,{'a':True,'b':False}) is True
    assert truth(expr,{'a':False,'b':None}) is False
    assert truth(expr,{'a':True,'b':None}) is None


def test_source_oracle_does_not_accept_quote_overlap_or_negative_guess():
    ref={'selected_path':{'conditions':[dict(id='a',source_ref=dict(source_id='s',quote='HTTP is enabled'))]}}
    def q(quote):return dict(id='q',operational_quote=quote,source_refs=[dict(source_id='s')])
    assert source_bindings([q('when HTTP is enabled')],ref)[0]=={'a':'q'}
    assert not source_bindings([q('HTTP is enabled and reachable')],ref)[0]
    assert not source_bindings([q('HTTP is enabled'),dict(q('HTTP is enabled'),id='q2')],ref)[0]


def test_missing_reference_does_not_become_generated_positive():
    case=dict(context=dict(scope='current_single',mode='normal',origin='same_zone',deployment='running',runtime='bom'),answers={'q':'o'})
    assert candidate(case,{}, {})[0] is None


def test_original_metric_and_unknown_positive_gate():
    ps=[dict(id='a',status='affected'),dict(id='b',status='affected')]
    rs=[dict(id='a',actual_affected=True),dict(id='b',actual_affected=False)]
    assert metrics(ps,rs)['precision']==.5
    rs[1]['actual_affected']=None
    result=metrics(ps,rs)
    assert result['precision'] is None and result['target_met'] is None


def test_absence_requires_explicit_scoped_inventory_for_any_world():
    for synthetic in (True, False):
        ctx = dict(deployment='not_deployed', scope='current_single')
        case = dict(context=ctx, synthetic=synthetic, component_ref='asset')
        for value in ({}, {'inventory_coverage': 'partial'}, {'inventory_coverage': 'complete'}):
            result = candidate(dict(case, context=dict(ctx, **value)), {}, {})
            assert result[0] is (False if value.get('inventory_coverage') == 'complete' else None)
        complete = dict(ctx, inventory_coverage='complete')
        assert candidate(dict(case, context=dict(complete, scope='mixed')), {}, {})[0] is None
        assert candidate(dict(case, context=complete, component_ref=None), {}, {})[0] is None


def test_large_vectors_cover_each_atom_at_each_value():
    qs=[dict(id=str(i),condition_id='p'+str(i)) for i in range(8)]
    rows,coverage=answer_vectors(qs)
    assert not coverage['exhaustive']
    for q in qs:assert {r[q['id']] for r in rows}=={'o','x','unknown'}


def test_omitted_source_requirement_cannot_become_an_oracle_positive():
    source=dict(selected_path=dict(expression=dict(op='and',args=[dict(condition='a'),dict(condition='b')])))
    case=dict(context=dict(scope='current_single',mode='normal',origin='same_zone',deployment='running',runtime='bom'),answers={'q':'o'})
    # The evaluated extraction omitted b. Its own A-only formula must not
    # supply the primary candidate label.
    assert candidate(case,source,{'a':'q'})[0] is None
    case['answers']['q']='x'
    assert candidate(case,source,{'a':'q'})[0] is False


def test_large_boundary_set_includes_multi_negative_path_witness():
    qs=[dict(id='q'+str(i),condition_id='p'+str(i)) for i in range(7)]
    expression=dict(op='and',args=[dict(condition='p0'),dict(op='not',args=[dict(condition='p1')]),
        dict(op='not',args=[dict(condition='p2')]),dict(condition='p3')])
    rows,_=answer_vectors(qs,[expression])
    assert any(r['q0']=='o' and r['q1']=='x' and r['q2']=='x' and r['q3']=='o' for r in rows)
