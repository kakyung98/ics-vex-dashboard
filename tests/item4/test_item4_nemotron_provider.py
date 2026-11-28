import json

import pytest

from src.item4.models import nemotron_inference_provider as provider


class Reply:
    def __init__(self, value):
        self.value=value
    def raise_for_status(self):
        pass
    def json(self):
        return self.value


@pytest.fixture
def backend(tmp_path,monkeypatch):
    manifest=tmp_path/'manifest.json'
    info=dict(model=provider.MODEL,revision=provider.REVISION,served_model=provider.SERVED_MODEL,
              base_files_sha256={'weights':'a'*64},tokenizer_sha256={'tokenizer':'b'*64},role_adapter=None,
              decoding={'temperature':0,'enable_thinking':False,'max_tokens':1024})
    manifest.write_text(json.dumps(info))
    auth=tmp_path/'token'
    auth.write_text('test-token')
    monkeypatch.setattr(provider,'token_path',lambda:auth)
    class Session:
        headers={}
        def get(self,url,**kwargs):
            return Reply({'data':[{'id':provider.SERVED_MODEL}]})
    session=Session()
    monkeypatch.setattr(provider.NemotronBatch,'session',lambda _:session)
    return provider.NemotronBatch(18128,manifest),session


def request():
    return {'system':'Review the supplied observation','packet':{'expert':'inventory','schema':{
        'type':'object','properties':{'finding':{'enum':['unresolved']},'cite':{'enum':['none']}},
        'required':['finding','cite'],'additionalProperties':False}}}


def test_real_model_identity_and_schema_are_bound_to_each_request(backend):
    batch,session=backend
    bodies=[]
    def post(url,json,**kwargs):
        bodies.append(json)
        return Reply({'model':provider.SERVED_MODEL,'choices':[{'finish_reason':'stop',
                      'message':{'content':'{"finding":"unresolved","cite":"none"}'}}]})
    session.post=post
    out=batch([request(),request()])
    assert all(v['llm_used'] and v['model']['model']==provider.MODEL for v in out)
    assert len(bodies)==2 and bodies[0]['response_format']['json_schema']['schema']==request()['packet']['schema']
    assert bodies[0]['chat_template_kwargs']=={'enable_thinking':False}


@pytest.mark.parametrize('model,finish,content',[
    ('other','stop','{"finding":"unresolved","cite":"none"}'),
    (provider.SERVED_MODEL,'length','{"finding":"unresolved","cite":"none"}'),
    (provider.SERVED_MODEL,'stop','{"finding":"absent_complete","cite":"made-up"}'),
])
def test_mismatched_truncated_or_unprovided_evidence_is_a_failure(backend,model,finish,content):
    batch,session=backend
    session.post=lambda *a,**kw:Reply({'model':model,'choices':[{'finish_reason':finish,'message':{'content':content}}]})
    result=batch([request()])
    assert len(result)==1 and isinstance(result[0],Exception)
