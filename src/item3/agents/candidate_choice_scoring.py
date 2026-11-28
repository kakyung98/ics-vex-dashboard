"""Finite source-ID decisions for role likelihood scoring; no labels or CVEs."""
import itertools
import json
from copy import deepcopy
from src.item3.agents.agent_contracts import validate
from src.item3.agents.agent_message_format import encode; from src.item3.agents.agent_message_format import KEYS


def model_packet(task,packet):
    """Project role-relevant facts; original packet stays in the audit ledger."""
    projected=deepcopy(packet)
    if task in ('I1','I3'):
        candidates=[c for c in projected['candidates'] if not c['conflicts'] and
            (task!='I3' or c['eligible_for_selection'])]
        keep={c['candidate_id'] for c in candidates}
        projected['candidates']=candidates
        projected['evidence']=[e for e in projected['evidence']
            if (not e['id'].startswith('dictionary:') or e['id'].removeprefix('dictionary:') in keep)
            and (task!='I3' or e['id']!='input:version')]
    return projected


def forced_version_classification(packet):
    """The contract forces explicit/non-model observations into version IDs.

    This establishes classification only, never invents a release or its order.
    Ambiguous name/model observations still require a learned choice.
    """
    if any(o['source']=='name' and o['may_be_model_identifier'] for o in packet['observations']):return None
    refs=[o['id'] for o in packet['observations']]
    if not refs:
        refs=[e['id'] for e in packet['evidence'] if e['id'].startswith('input:')][:1]
    answer=dict(version_observation_ids=[o['id'] for o in packet['observations']],model_observation_ids=[],
        evidence_refs=refs,status='supported')
    return answer if validate('I2',packet,answer) else None


def choices(task,packet):
    available={e['id'] for e in packet['evidence']}
    input_refs=[r for r in ('input:cpe','input:name','input:manufacturer','input:version','input:purl') if r in available]
    refs=input_refs[:1]
    if task=='I1':
        answers=[dict(ranked_candidate_ids=[c['candidate_id']],evidence_refs=refs+['dictionary:'+c['candidate_id']],status='ranked')
            for c in packet['candidates'] if not c['conflicts']]
        answers.append(dict(ranked_candidate_ids=[],evidence_refs=refs,status='unresolved'))
    elif task=='I3':
        answers=[dict(candidate_id=c['candidate_id'],evidence_refs=refs+['dictionary:'+c['candidate_id']],status='validated')
            for c in packet['candidates'] if c['eligible_for_selection'] and not c['conflicts']]
        answers.append(dict(candidate_id=None,evidence_refs=refs,status='unresolved'))
    elif task=='I2':
        observations=packet['observations']
        ambiguous=[o['id'] for o in observations if o['source']=='name' and o['may_be_model_identifier']]
        answers=[]
        # Retain too-complex cases as explicit unresolved; do not drop the input.
        if len(ambiguous)<=4:
            for assignment in itertools.product((False,True),repeat=len(ambiguous)):
                models={oid for oid,flag in zip(ambiguous,assignment) if flag}
                answers.append(dict(version_observation_ids=[o['id'] for o in observations if o['id'] not in models],
                    model_observation_ids=[o['id'] for o in observations if o['id'] in models],
                    evidence_refs=[o['id'] for o in observations] or refs,status='supported'))
        answers.append(dict(version_observation_ids=[],model_observation_ids=[],evidence_refs=refs,status='unresolved'))
    else:raise ValueError('Unknown identification role')
    valid=[a for a in answers if validate(task,packet,a)]
    if not valid:raise ValueError('No valid explicit unresolved role decision')
    wire,system,_,reverse=encode(task,packet,tabular=True)
    aliases={original:short for short,original in reverse.items()}
    def translate(value):
        if isinstance(value,str):return aliases.get(value,value)
        if isinstance(value,list):return [translate(v) for v in value]
        return value
    completions=[json.dumps({KEYS.get(k,k):translate(v) for k,v in a.items()},ensure_ascii=False,separators=(',',':')) for a in valid]
    return wire,system,reverse,valid,completions
