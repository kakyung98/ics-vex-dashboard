from src.research_review import validate


def test_mapping_requires_provided_function_and_actual_patch_context():
    packet={'functions':[{'id':'F1','name':'parse_frame','file':'src/frame.c'}],
            'sources':[{'id':'D1','text':'The parse_frame function processes malformed input.','source_kind':'description'},
                       {'id':'P1','text':'patch context','source_kind':'patch','hunk_header':'@@ int unrelated()', 'file':'src/frame.c'}]}
    row={'function_id':'F1','evidence_ids':['D1'],'relation':'explicit_function_mention','reason':'Literal mention.'}
    assert validate('research-source-map',packet,{'mappings':[row]})[0]
    assert not validate('research-source-map',packet,{'mappings':[{**row,'function_id':'invented'}]})[0]
    assert not validate('research-source-map',packet,{'mappings':[{**row,'evidence_ids':['P1'],'relation':'patch_context'}]})[0]
    assert not validate('research-source-map',packet,{'mappings':[{**row,'function_id':[]} ]})[0]


def test_same_base_review_has_full_question_coverage_and_known_sources():
    packet={'questions':[{'id':'q1'},{'id':'q2'}],'sources':[{'id':'E1'}]}
    row={'question_id':'q1','support':'uncertain','answerability':'operator_answerable','evidence_ids':['E1']}
    assert not validate('research-question-review',packet,{'question_reviews':[row]})[0]
    assert validate('research-question-review',packet,{'question_reviews':[row,{**row,'question_id':'q2'}]})[0]
    from src.llm_output_schema import schema_for
    from jsonschema import Draft7Validator
    Draft7Validator.check_schema(schema_for('research-question-review',{'questions':[],
        'conditions':[{'id':'C1'}],'sources':[{'id':'E1'}]}))


def test_expanded_pool_keeps_global_groups_out_of_other_splits():
    import json
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]/'data/operational_expansion_v1'
    manifest=json.loads((root/'manifest.json').read_text(encoding='utf-8'))
    assert manifest['operational_candidates']==563
    groups={}
    for split in ['train','validation','test','quarantine']:
        rows=[json.loads(l) for l in (root/(split+'.inputs.jsonl')).read_text(encoding='utf-8').splitlines()]
        assert len(rows)==manifest['counts'][split]
        assert all(r['routing_gold'] is None and not r['train_ready'] for r in rows)
        groups[split]={r['group_id'] for r in rows}
    for left in groups:
        for right in groups:
            if left!=right:assert not groups[left]&groups[right]
