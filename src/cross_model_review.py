"""Explicit external model review. Consensus is model evidence, never human gold."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
import re
import requests
from src.vex_roles import fingerprint


def setting(name):
    value=os.environ.get(name)
    if value:return value
    # Let users set per-user variables after the desktop app has started.
    if os.name=='nt':
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,'Environment') as key:
                return winreg.QueryValueEx(key,name)[0]
        except OSError:pass
    return None


def configuration():
    return {'claude':{'key':setting('ANTHROPIC_API_KEY'),'model':setting('CLAUDE_REVIEW_MODEL')},
            'gemini':{'key':setting('GEMINI_API_KEY') or setting('GOOGLE_API_KEY'),'model':setting('GEMINI_REVIEW_MODEL')}}


def availability():
    return {p:{'api_key_configured':bool(v['key']),'model':v['model'],'ready':bool(v['key'] and v['model'])}
            for p,v in configuration().items()}


def decode(text):
    try:return json.loads(text.strip())
    except (ValueError,AttributeError):return None


def validate(pred,item):
    if not isinstance(pred,dict) or set(pred)!={'reviews'} or not isinstance(pred['reviews'],list) or len(pred['reviews'])!=1:return False
    r=pred['reviews'][0]
    if not isinstance(r,dict) or r.get('id')!=item['id'] or r.get('requires_human_review') is not True:return False
    for name in ['conditions','suggested_questions','missing_information','unsupported_claims']:
        if not isinstance(r.get(name),list):return False
    if not r['conditions'] or not 1<=len(r['suggested_questions'])<=6:return False
    for c in r['conditions']:
        if not isinstance(c,dict) or not all(isinstance(c.get(k),str) for k in ['evidence','interpretation','necessity','alternatives']):return False
        if not c['evidence'].strip() or c['evidence'] not in item['description'] or c['necessity'] not in {'explicit','uncertain'}:return False
    for q in r['suggested_questions']:
        if not isinstance(q,dict) or not all(isinstance(q.get(k),str) and q[k].strip() for k in ['question','evidence','purpose']):return False
        if q['evidence'] not in item['description']:return False
    return all(isinstance(s,str) for k in ['missing_information','unsupported_claims'] for s in r[k])


def call(provider,model,key,packet,post=requests.post):
    content=json.dumps(packet,ensure_ascii=False)
    if not re.fullmatch(r'[A-Za-z0-9_.-]+',model):raise ValueError('Invalid model ID.')
    if provider=='claude':
        response=post('https://api.anthropic.com/v1/messages',
            headers={'x-api-key':key,'anthropic-version':'2023-06-01','Content-Type':'application/json'},
            json={'model':model,'max_tokens':4096,'system':packet['instructions'],
                  'messages':[{'role':'user','content':content}]},timeout=(15,180),allow_redirects=False)
    elif provider=='gemini':
        response=post('https://generativelanguage.googleapis.com/v1beta/models/'+model+':generateContent',
            headers={'x-goog-api-key':key,'Content-Type':'application/json'},
            json={'systemInstruction':{'parts':[{'text':packet['instructions']}]},
                  'contents':[{'role':'user','parts':[{'text':content}]}],
                  'generationConfig':{'responseMimeType':'application/json','maxOutputTokens':4096}},timeout=(15,180),allow_redirects=False)
    else:raise ValueError('Unknown provider.')
    if response.status_code!=200:
        return {'provider':provider,'model':model,'status':'api_error','http_status':response.status_code}
    data=response.json()
    if provider=='claude':
        raw=''.join(b.get('text','') for b in data.get('content',[]) if b.get('type')=='text')
        stop=data.get('stop_reason');usage=data.get('usage',{});returned_model=data.get('model')
    else:
        candidates=data.get('candidates') or [{}];candidate=candidates[0]
        raw=''.join(b.get('text','') for b in candidate.get('content',{}).get('parts',[]) if not b.get('thought'))
        stop=candidate.get('finishReason');usage=data.get('usageMetadata',{});returned_model=data.get('modelVersion')
    pred=decode(raw)
    ok=validate(pred,packet['inputs'][0]) and stop not in {'max_tokens','MAX_TOKENS'}
    return {'provider':provider,'model':model,'returned_model':returned_model,'status':'grounded_draft' if ok else 'rejected',
            'prediction':pred,'raw':raw,'stop_reason':stop,'usage':usage,'input_sha256':fingerprint(packet),
            'human_gold':False,'semantic_review_required':True}


def review_one(packet,configs,post=requests.post):
    # The packet is identical and contains no peer response or model-generated answer key.
    if len(packet['inputs'])!=1 or packet.get('peer_response_included') is not False:raise ValueError('Expected one blind input.')
    if not all(configs[p].get('key') and configs[p].get('model') for p in ['claude','gemini']):raise ValueError('Configure both API keys and model IDs before dispatch.')
    def run(p):
        try:return call(p,configs[p]['model'],configs[p]['key'],packet,post)
        except requests.RequestException:return {'provider':p,'model':configs[p]['model'],'status':'transport_error','human_gold':False}
    with ThreadPoolExecutor(max_workers=2) as pool:
        outputs=dict(zip(['claude','gemini'],pool.map(run,['claude','gemini'])))
    a,b=outputs.values();both=all(x['status']=='grounded_draft' for x in [a,b])
    spans=lambda x:{c['evidence'] for c in x['prediction']['reviews'][0]['conditions']}
    overlap=len(spans(a)&spans(b))/len(spans(a)|spans(b)) if both else None
    return {'id':packet['inputs'][0]['id'],'input_sha256':fingerprint(packet),'outputs':outputs,
            'status':'model_reviewed' if both else 'review_incomplete','annotation_basis':'cross_model_proposals_not_human_gold',
            'span_jaccard':overlap,'human_gold':False,'human_adjudication_required':True,
            'semantic_agreement':'not_established_by_span_overlap','trainable':False}
