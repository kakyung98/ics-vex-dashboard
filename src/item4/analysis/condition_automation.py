"""Bounded, auditable model stages shared by extraction and question generation.

Retries repair invalid output, never low confidence or missing source evidence.
No CVE, vendor, asset type, condition fact or Boolean relation is synthesized here.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import uuid

VERSION='item4-condition-automation/3'
MAX_ATTEMPTS=3


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,default=str).encode()).hexdigest()


def failure(exc):
    message=str(exc)
    lower=message.lower()
    if 'actual generative' in lower or 'requires actual' in lower:
        stage='inference_policy';retryable=False
    elif any(s in lower for s in ('target must be named exactly','does not explicitly support an operating restriction',
            'implementation defects','static component or firmware artifact')):
        stage='condition';retryable=True
    elif any(s in lower for s in ('quotation','source clause','evidence id','evidence binding','source scope','polarity needs')):
        stage='evidence_binding';retryable=True
    elif any(s in lower for s in ('scenario polarity','co-listed input','unknown prerequisite','belong to a scenario','unregistered product scope')):
        stage='logic';retryable=True
    elif 'prerequisite rejected' in lower or 'condition category' in lower:
        stage='condition';retryable=True
    elif isinstance(exc,(ValueError,KeyError,TypeError)) or type(exc).__name__=='ValidationError':
        stage='schema';retryable=True
    else:
        stage='inference';retryable=not isinstance(exc,(PermissionError,FileNotFoundError))
    return dict(stage=stage,code=type(exc).__name__,message=message[:1600],retryable=retryable)


class StageExhausted(ValueError):
    def __init__(self,stage,history,last_failure,previous):
        super().__init__(last_failure['message'])
        self.stage=stage;self.execution_history=deepcopy(history)
        self.failure=deepcopy(last_failure);self.previous=deepcopy(previous)
        self.raw_output=json.dumps((previous or {}).get('prediction'),ensure_ascii=False)
        self.generation_model=(previous or {}).get('model')


def execute(stage,request,generate,validate,*,max_attempts=MAX_ATTEMPTS):
    """request(attempt, failure, previous) -> system/payload/role/mode.

    validate may attach a merged raw candidate to the request before rejecting
    it. The next repair then sees the full candidate, not a partial repair JSON.
    """
    if type(max_attempts) is not int or not 1<=max_attempts<=MAX_ATTEMPTS:
        raise ValueError('Stage attempt limit must be between 1 and 3')
    history=[];error=None;previous=None;last_request=None
    for index in range(max_attempts):
        # Transport failure must retry the same repair, not broaden an
        # evidence-only/logic-only task back into unconstrained extraction.
        req=(deepcopy(last_request) if error and error['stage']=='inference' and last_request is not None
             else request(index,error,deepcopy(previous)))
        last_request=deepcopy(req)
        entry=dict(stage=stage,attempt=index+1,run_id=uuid.uuid4().hex,
            started_at=datetime.now(timezone.utc).isoformat(),role=req['role'],
            repair_scope=req.get('mode','full'),prompt_sha256=digest(req['system']),
            schema_sha256=digest(req['payload'].get('schema')),
            input_sha256=digest(req['payload']))
        history.append(entry);response=None
        try:
            response=generate(req['system'],deepcopy(req['payload']),role=req['role'])
            entry.update(model=deepcopy(response.get('model')),llm_used=response.get('llm_used'),
                output_sha256=digest(response.get('prediction')),generation=deepcopy(response.get('generation')))
            if response.get('llm_used') is not True:
                raise ValueError('Stage requires actual generative LLM output')
            value=validate(response,req)
            entry['status']='accepted'
            return value,response,history
        except Exception as exc:
            error=failure(exc);entry.update(status='rejected',failure=error)
            if response is not None:
                previous=dict(prediction=deepcopy(response.get('prediction')),
                    candidate=deepcopy(req.get('candidate',response.get('prediction'))),model=deepcopy(response.get('model')))
            if not error['retryable'] or index+1==max_attempts:
                entry['finished_at']=datetime.now(timezone.utc).isoformat()
                raise StageExhausted(stage,history,error,previous) from exc
        finally:
            entry['finished_at']=datetime.now(timezone.utc).isoformat()


def receipt(history,status):
    return dict(version=VERSION,status=status,max_attempts_per_stage=MAX_ATTEMPTS,
        attempts=len(history),failures=[deepcopy(e['failure']) for e in history if 'failure' in e],
        retry_policy='validation_or_transport_only; never raise confidence or fabricate evidence')
