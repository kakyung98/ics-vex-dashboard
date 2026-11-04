"""Constrained decoding must preserve the same server-side evidence contract."""
import json
import pytest
from lmformatenforcer import JsonSchemaParser
from src.llm_output_schema import schema_for


def consume(schema,document):
    parser=JsonSchemaParser(schema)
    for char in json.dumps(document,separators=(',',':')):
        if char not in parser.get_allowed_characters():return False
        parser=parser.add_character(char)
    return parser.can_end()


@pytest.fixture
def writer_packet():
    return {'vulnerability':'CVE-2099-12345','product':'Fixture',
            'decision':{'status':'under_investigation','justification':None},
            'evidence':[{'id':'fixture:decision'}]}


def test_writer_grammar_requires_action_and_locks_ids(writer_packet):
    schema=schema_for('vex-writer',writer_packet)
    doc={'vulnerability':'CVE-2099-12345','product':'Fixture','status':'under_investigation',
         'justification':None,'impact_statement':'Unknown installed version.',
         'evidence_refs':['fixture:decision'],'action_statement':None}
    assert consume(schema,doc)
    assert consume(schema,{**doc,'missing_evidence':['Installed version']})
    assert not consume(schema,{k:v for k,v in doc.items() if k!='action_statement'})
    assert not consume(schema,{**doc,'status':'not_affected'})
    assert not consume(schema,{**doc,'evidence_refs':['invented']})
    assert not consume(schema,{**doc,'impact_statement':'x'*1001})


def test_condition_grammar_limits_source_ids_and_kinds():
    schema=schema_for('condition-evidence',{'sources':[
        {'id':'source:1','text':'The attack requires network access.','condition_eligible':True}]})
    doc={'conditions':[{'kind':'configuration','evidence_ids':['source:1'],'necessity':'uncertain'}],
         'function_candidates':[],'function_status':'unresolved','assessment':'partial','can_refute':False}
    assert consume(schema,doc)
    assert not consume(schema,{**doc,'conditions':[{'kind':'invented_kind','evidence_ids':['source:1'],'necessity':'uncertain'}]})
    assert consume(schema,{**doc,'can_refute':True}) # Semantic policy remains server-validated.
