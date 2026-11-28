"""Deterministic supervision of supplied evidence IDs; no model-derived answers."""
from copy import deepcopy
from src.item3.agents.agent_contracts import validate
from src.item3.agents.agent_message_format import encode; from src.item3.agents.agent_message_format import KEYS
from tools.item3.item3_truth_oracle import identity,literal,parts

class CapturedPacket(BaseException):
    def __init__(self,task,packet):self.task=task;self.packet=deepcopy(packet)

def candidate_identity(candidate):
    return tuple(literal(candidate[k]).lower() for k in ('part','vendor','product'))

def teacher(task,packet,fields):
    wanted=identity(fields)
    if task=='I2':
        models=[o['id'] for o in packet['observations'] if o['source']=='name' and o['may_be_model_identifier']]
        versions=[o['id'] for o in packet['observations'] if o['id'] not in models]
        refs=[o['id'] for o in packet['observations']] or ['input:name']
        answer={'version_observation_ids':versions,'model_observation_ids':models,'evidence_refs':refs,'status':'supported'}
    else:
        candidates=[c for c in packet['candidates'] if candidate_identity(c)==wanted and not c['conflicts']]
        if task=='I3':candidates=[c for c in candidates if c['eligible_for_selection']]
        chosen=candidates[0]['candidate_id'] if len(candidates)==1 else None
        available={e['id'] for e in packet['evidence']}
        cpe_evidence=next((e.get('value') for e in packet['evidence'] if e['id']=='input:cpe'),[])
        if isinstance(cpe_evidence,str):cpe_evidence=[cpe_evidence]
        cpe_supports_target=any(identity(p)==wanted for text in cpe_evidence if (p:=parts(text)) is not None)
        ref='input:cpe' if cpe_supports_target else 'input:name'
        refs=[ref,'dictionary:'+chosen] if chosen else [r for r in ('input:name','input:cpe','input:manufacturer','input:version') if r in available][:2]
        answer=({'ranked_candidate_ids':[chosen] if chosen else [],'evidence_refs':refs,'status':'ranked' if chosen else 'unresolved'}
            if task=='I1' else {'candidate_id':chosen,'evidence_refs':refs,'status':'validated' if chosen else 'unresolved'})
    if not validate(task,packet,answer):raise ValueError('Invalid independent teacher target: '+task)
    return answer

def provider(fields,capture=None):
    def infer(task,packet):
        if task==capture:raise CapturedPacket(task,packet)
        return {'prediction':teacher(task,packet,fields),'llm_used':False,'model_mode':'independent_source_supervision'}
    return infer

def training_messages(task,packet,answer):
    from jsonschema import Draft202012Validator
    wire,system,schema,reverse=encode(task,packet)
    alias={v:k for k,v in reverse.items()}
    def translate(value):
        if isinstance(value,str):return alias.get(value,value)
        if isinstance(value,list):return [translate(v) for v in value]
        return value
    target={KEYS.get(k,k):translate(v) for k,v in answer.items()}
    Draft202012Validator(schema).validate(target)
    return [{'role':'system','content':system},
        {'role':'user','content':__import__('json').dumps(wire,ensure_ascii=False,separators=(',',':'))},
        {'role':'assistant','content':__import__('json').dumps(target,ensure_ascii=False,separators=(',',':'))}]
