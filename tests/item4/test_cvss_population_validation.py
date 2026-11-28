"""Population accounting and source-schema transport, without model substitutes."""
from copy import deepcopy
import json
from threading import Event

import pytest

from src.item4.analysis import exploitation_prerequisites as V
from tools.item4 import source_schema_grammar as G
from tools.item4 import validate_cvss_source_population as P


def test_grammar_canonicalization_only_normalizes_cve_and_unsupported_constraints():
    schema={'type':'object','properties':{
        'cve':{'const':'CVE-2099-1234'},
        'scope':{'type':'array','uniqueItems':True,'maxItems':0,'items':{'enum':[]}},
        'evidence':{'type':'string','description':'CVE-2099-1234 requires a source-specific fact.'}},
        'required':['cve','scope','evidence'],'additionalProperties':False}
    original=deepcopy(schema);normalized=G.canonical(schema,'CVE-2099-1234')
    assert schema==original
    assert normalized['properties']['cve']=={'const':G.PLACEHOLDER}
    assert normalized['properties']['scope']=={'type':'array','maxItems':0}
    assert normalized['properties']['evidence']==original['properties']['evidence']


@pytest.mark.parametrize('status,has_source,expected',[
    ('Rejected',True,'rejected_identity'),('Modified',False,'source_missing')])
def test_source_unavailable_and_rejected_cves_remain_accounted_for(tmp_path,status,has_source,expected):
    row=dict(cve='CVE-2099-1234',nvd_status=status,input_sha256='fixed',
        record=dict(cve='CVE-2099-1234',products=[],sources=[dict(text_sha256='source')] if has_source else []))
    class Backend:
        stop=Event()
        def call(self,*args,**kwargs):pytest.fail('No inference for unavailable or rejected identity')
    result=P.one(row,dict(run_identity='run'),tmp_path,Backend())
    assert result['state']==expected and result['llm_attempted'] is False
    assert result['sha256']==V.digest({k:v for k,v in result.items() if k!='sha256'})
    report=P.report([row],dict(run_identity='run',source_scope='Description only',evaluation_backend='test'),tmp_path,final=True)
    assert report['completed']==1 and report['remaining']==12417 and report['state']=='running'
    assert report['states']=={expected:1}
    assert report['independent_semantic_accuracy_verified'] is False


def test_checkpoint_corruption_cannot_be_counted_as_completion(tmp_path):
    path=tmp_path/'checkpoints/CVE-2099-1234.json';path.parent.mkdir()
    path.write_text(json.dumps(dict(cve='CVE-2099-1234',state='validated_draft',sha256='wrong')))
    with pytest.raises(ValueError,match='Checkpoint integrity mismatch'):
        P.report([dict(cve='CVE-2099-1234',input_sha256='input')],dict(run_identity='run'),tmp_path)


def test_complete_frozen_population_has_unique_ids_and_pinned_sources(tmp_path):
    (tmp_path/'backend_identity.json').write_text(json.dumps(dict(model='test-identity')))
    rows,manifest=P.prepare(tmp_path)
    assert len(rows)==len({r['cve'] for r in rows})==12418
    assert all(not r['record']['products'] for r in rows)
    assert all(len(r['record']['sources'])<=1 for r in rows)
    assert all(s['id']=='nvd:'+r['cve'] for r in rows for s in r['record']['sources'])
    assert manifest['runtime_parity'] is False
    assert manifest['independent_semantic_accuracy_verified'] is False
    assert len([r for r in rows if not r['record']['sources']])==17
