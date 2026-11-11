"""Support, closure, missingness and semantic-boundary counterexamples."""
from src.question_pattern_mining import mine,canonical_atom


def test_missing_information_and_attack_mechanisms_are_reviewed_not_mined_as_facts():
    texts=['attacker input/ingress not explicitly mentioned','no specific feature/configuration mentioned',
        'Buffer underflow vulnerability in VNC client code','User-supplied data is not properly validated',
        'An attacker can inject arbitrary SQL queries','unauthenticated attacker can exploit the vulnerability',
        'current process context']
    result=mine([row('A',str(i),text) for i,text in enumerate(texts)],['A'])
    assert not result['atoms'] and result['summary']['flagged_occurrences']==len(texts)
    assert all(r['retained'] for r in result['triage'])


def row(cve,cid,text,kind='access_position',necessity='described_not_proven_required'):
    return dict(cve=cve,condition_id=cid,condition=text,kind=kind,necessity=necessity,
                source_id=cve+':source',source_span=[0,20],source_quote='Controlled test only')


def test_support_counts_cves_not_duplicate_rows_and_preserves_unknown_population():
    rows=[row('A',str(i),'network access available') for i in range(20)]
    rows += [row('B','b','network access available'),row('C','c','network access available')]
    result=mine(rows,['A','B','C','D'])
    assert result['common_questions'][0]['support_count']==3
    assert result['summary']['observed_denominator']==3
    assert result['cves'][3]['state']=='conditions_unknown_or_flagged'
    assert all(not c['excluded'] for c in result['cves'])
    assert all(c['formula'] is None for c in result['cves'])


def test_closed_pattern_equals_intersection_of_its_observed_extent():
    rows=[row(c,c+t,t) for c,items in [('A',['network access','local access']),('B',['network access','local access']),
                                     ('C',['network access','local access']),('D',['network access'])] for t in items]
    result=mine(rows,list('ABCD'))
    transactions={c['cve']:set(c['atom_ids']) for c in result['cves']}
    for pattern in result['patterns']:
        assert set(pattern['atom_ids'])==set.intersection(*(transactions[c] for c in pattern['cves']))
        assert pattern['support_count']==len(pattern['cves'])
        assert not pattern['necessity_inferred'] and not pattern['formula_inferred']
    assert any(len(p['atom_ids'])==2 for p in result['patterns'])


def test_negation_actor_and_necessity_are_not_collapsed():
    a=row('A','a','An authenticated attacker is required','attacker_auth_or_privilege')
    b=row('B','b','An authenticated user is required','attacker_auth_or_privilege')
    c=row('C','c','An authenticated attacker is not required','attacker_auth_or_privilege')
    assert len({canonical_atom(x)['id'] for x in (a,b,c)})==3
    d={**a,'necessity':'explicitly_required'}
    assert canonical_atom(a)['id']!=canonical_atom(d)['id']


def test_consequence_flags_do_not_drop_cves_or_create_questions():
    result=mine([row('A','a','Attacker can execute arbitrary code')],['A','B'],min_cves=2)
    assert result['summary']['flagged_occurrences']==1
    assert result['triage'][0]['retained']
    assert len(result['cves'])==2 and not result['common_questions']


def test_bounded_search_discloses_incomplete_enumeration():
    rows=[row(c,c+t,t) for c in 'ABC' for t in ['network access','local access']]
    result=mine(rows,list('ABC'),max_pair_seeds=0)
    assert result['summary']['pair_search_truncated']
    assert 'not all possible' in result['summary']['enumeration_scope']


def test_input_generalization_preserves_actor_modality_protocol_and_operation():
    a=row('A','a','Remote attacker sends a specially crafted TCP packet','input_or_ingress')
    b=row('B','b','A remote attacker sends a carefully crafted TCP packet','input_or_ingress')
    assert canonical_atom(a)['id']==canonical_atom(b)['id']
    for text in ['Remote user sends a specially crafted TCP packet','Remote attacker can send a specially crafted TCP packet',
                 'Remote attacker sends a specially crafted IP packet']:
        assert canonical_atom(row('C','c',text,'input_or_ingress'))['id']!=canonical_atom(a)['id']
    parse=row('A','p','Parsing specially crafted PAR files','input_or_ingress')
    load=row('A','l','Loading specially crafted PAR files','input_or_ingress')
    assert canonical_atom(parse)['id']!=canonical_atom(load)['id']


def test_missing_state_is_not_mined_as_a_true_condition_and_groups_are_counted():
    rows=[row(c,c,'network access') for c in 'ABC']+[row('D','d','Operating state not specified')]
    result=mine(rows,list('ABCD'),group_ids=dict(A='one-advisory',B='one-advisory',C='other-advisory',D='third'))
    assert result['common_questions'][0]['support_count']==3
    assert result['common_questions'][0]['source_group_count']==2
    assert result['cves'][3]['atom_ids']==[]
    assert result['summary']['flagged_occurrences']==1
