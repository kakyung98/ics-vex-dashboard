import json
import pytest
from src.cross_model_review import review_one,availability

def packet():return {'instructions':'Return one blind review.','peer_response_included':False,
                     'inputs':[{'id':'a','description':'malformed frames enter parser','cve':'CVE-2099-12345'}]}
CONFIG={'claude':{'key':'fake-key-claude','model':'test-claude'},'gemini':{'key':'fake-key-gemini','model':'test-gemini'}}

def test_providers_receive_identical_blind_input_and_secrets_stay_in_headers():
    requests=[]
    def post(url,**kw):
        requests.append((url,kw))
        pred={'reviews':[{'id':'a','conditions':[{'evidence':'malformed frames','interpretation':'input','necessity':'explicit','alternatives':''}],
             'suggested_questions':[{'question':'Is frame input used?','evidence':'malformed frames','purpose':'input use'}],
             'missing_information':[],'unsupported_claims':[],'requires_human_review':True}]}
        raw=json.dumps(pred)
        class Response:
            status_code=200
            def json(self):
                return {'content':[{'type':'text','text':raw}],'stop_reason':'end_turn'} if 'anthropic' in url else {'candidates':[{'content':{'parts':[{'text':raw}]},'finishReason':'STOP'}]}
        return Response()
    result=review_one(packet(),CONFIG,post)
    assert result['status']=='model_reviewed' and result['span_jaccard']==1
    assert result['human_gold'] is False and result['trainable'] is False
    assert 'fake-key' not in json.dumps(result)
    a=next(k for u,k in requests if 'anthropic' in u)
    b=next(k for u,k in requests if 'googleapis' in u)
    assert a['json']['messages'][0]['content']==b['json']['contents'][0]['parts'][0]['text']
    assert 'fake-key' not in a['json']['messages'][0]['content']
    assert a['allow_redirects']==b['allow_redirects']==False

def test_missing_configuration_cannot_dispatch_and_http_failure_is_not_consensus():
    with pytest.raises(ValueError):review_one(packet(),{'claude':{},'gemini':{}})
    class Response:status_code=401
    result=review_one(packet(),CONFIG,lambda *a,**k:Response())
    assert result['status']=='review_incomplete' and result['span_jaccard'] is None
    assert 'fake-key' not in json.dumps(result)

def test_peer_answers_are_rejected():
    p=packet();p['peer_response_included']=True
    with pytest.raises(ValueError):review_one(p,CONFIG)
