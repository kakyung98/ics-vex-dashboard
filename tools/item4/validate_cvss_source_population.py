"""Resumable 12,418-CVE Description-only run of the current source pipeline.

The available pinned H200 Nemotron runs the production prompts, schemas and
validation stages. This is explicitly not Qwen runtime parity or independent
semantic-accuracy measurement. No prior condition predictions are reused.
"""
from __future__ import annotations

if __package__ in (None, ''):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from copy import deepcopy
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import threading
import time
import uuid

import requests
from jsonschema import Draft202012Validator
from tools.item4.source_schema_grammar import compile_grammar

from src.item4.analysis import exploitation_prerequisites as V
from src.item4.analysis import prerequisite_automation as A
from src.item4.analysis import operational_evidence_catalogue as E
from src.item4.analysis import prerequisite_taxonomy as T
from src.item4.decision import scoped_vex_review as D
from src.item4.models.nemotron_inference_provider import NemotronBatch, SERVED_MODEL

ROOT = Path(__file__).resolve().parents[2]
HOME = ROOT/'results/item4_cvss_population_20261127'
EXPECTED = 12418
CODE = [Path(__file__).relative_to(ROOT).as_posix(),
    'tools/item4/source_schema_grammar.py',
    'src/item4/analysis/exploitation_prerequisites.py',
    'src/item4/analysis/prerequisite_automation.py',
    'src/item4/analysis/prerequisite_taxonomy.py',
    'src/item4/analysis/ics_operating_conditions.py',
    'src/item4/analysis/operational_evidence_catalogue.py',
    'src/item4/analysis/operator_verifiable_conditions.py',
    'src/item4/analysis/source_surface_review.py',
    'src/item4/analysis/condition_normalization.py',
    'src/item4/analysis/condition_automation.py',
    'src/common/data/prerequisite_research_schema.py']


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def decoding_schema(node):
    """Only omit unsupported grammar keys; original post-validation is strict."""
    if isinstance(node,list):return [decoding_schema(v) for v in node]
    if not isinstance(node,dict):return node
    return {k:decoding_schema(v) for k,v in node.items()
        if k!='uniqueItems' and not(node.get('type')=='array' and node.get('maxItems')==0 and k=='items')}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2),encoding='utf-8')
    for attempt in range(20):
        try:
            temporary.replace(path)
            return
        except PermissionError:
            if attempt==19:raise
            time.sleep(.05)


def prepare(out):
    catalogue=D.catalogue();ids=sorted(r['cve'] for r in catalogue['cves'])
    if len(ids)!=EXPECTED or len(set(ids))!=EXPECTED:
        raise ValueError('Expected exactly 12,418 distinct CVEs')
    rows=[]
    for year in sorted({c.split('-')[1] for c in ids}):
        shard=D.shard(year)
        for cve in [c for c in ids if c.split('-')[1]==year]:
            original=shard[cve]
            if D.digest({k:v for k,v in original.items() if k!='record_digest'})!=original['record_digest']:
                raise ValueError('Original source snapshot hash mismatch: '+cve)
            text=original.get('description') or ''
            record=dict(cve=cve,products=[],sources=[])
            if text.strip():
                record['sources']=[dict(id='nvd:'+cve,text=text,
                    text_sha256=hashlib.sha256(text.encode()).hexdigest(),
                    url='https://nvd.nist.gov/vuln/detail/'+cve,
                    product_keys=[],scope_binding='unresolved')]
            row=dict(cve=cve,nvd_status=original.get('original_nvd_status'),
                original_record_digest=original['record_digest'],record=record)
            row['input_sha256']=V.digest(row)
            rows.append(row)
    config=dict(population=EXPECTED,population_sha256=V.digest(ids),
        inputs_sha256=V.digest(rows),taxonomy_version=T.VERSION,
        code_sha256={name:sha(ROOT/name) for name in CODE},
        prompts=dict(extraction=V.digest(V.SYSTEM),review=V.digest(V.COVERAGE.SYSTEM),focus=V.digest(A.FOCUS_SYSTEM)),
        source_scope='CVE Description only; no advisory text, product predictions, CVSS vectors, CWE labels or prior extracted conditions',
        backend_manifest_sha256=sha(out/'backend_identity.json'),
        runtime_parity=False,production_backend='Qwen2.5-Coder-14B-Instruct with configured role adapter',
        evaluation_backend='pinned H200 Nemotron NVFP4, no adapter',
        independent_semantic_accuracy_verified=False)
    config['run_identity']=V.digest(config)
    previous=out/'manifest.json'
    if previous.exists() and json.loads(previous.read_bytes())!=config:
        raise ValueError('Population, source, code, prompt or backend identity changed; use a new output directory')
    write(previous,config)
    inputs=out/'inputs.jsonl'
    if not inputs.exists():
        inputs.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows),encoding='utf-8')
    else:
        existing=[json.loads(line) for line in inputs.read_text(encoding='utf-8').splitlines()]
        if V.digest(existing)!=config['inputs_sha256']:raise ValueError('Frozen input file changed')
    return rows,config


class InfrastructureUnavailable(PermissionError):
    pass


class Backend:
    def __init__(self,out,port,workers,context=8192):
        self.provider=NemotronBatch(port,out/'backend_identity.json',concurrency=workers)
        self.out=out;self.context=context;self.stop=threading.Event()
        self.lock=threading.Lock();self.generations=0;self.tokens=Counter()
        # The serving thread pool inside the legacy helper is not used here.
        self.provider._pool.shutdown()

    def post(self,session,url,body,timeout,receipt):
        for attempt in range(3):
            event=dict(attempt=attempt+1,route=url.split('/')[-1],started_at=now())
            receipt.setdefault('transport_attempts',[]).append(event)
            try:
                response=session.post(url,json=body,timeout=timeout)
                event['http_status']=response.status_code
                if response.status_code in (408,429,502,503,504) and attempt<2:
                    response.close();time.sleep(2**attempt);continue
                return response
            except (requests.ConnectionError,requests.Timeout) as exc:
                event['error']=type(exc).__name__+': '+str(exc)
                if attempt==2:raise
                time.sleep(2**attempt)

    def call(self,cve,system,packet,role):
        if self.stop.is_set():raise InfrastructureUnavailable('Run paused after inference infrastructure failure')
        session=self.provider.session();messages=[dict(role='system',content=system),
            dict(role='user',content=json.dumps(packet,ensure_ascii=False))]
        request_id=uuid.uuid4().hex;started=time.monotonic()
        receipt=dict(id=request_id,cve=cve,role=role,started_at=now(),
            system=system,packet=packet,prompt_sha256=V.digest(system),input_sha256=V.digest(packet))
        path=self.out/'generations'/cve/(request_id+'.json')
        write(path,receipt)
        try:
            token_reply=self.post(session,self.provider.url.removesuffix('/v1')+'/tokenize',dict(
                model=SERVED_MODEL,messages=messages,chat_template_kwargs={'enable_thinking':False},
                add_generation_prompt=True),(10,30),receipt)
            token_reply.raise_for_status();input_tokens=token_reply.json()['count']
            max_tokens=min(4096,self.context-input_tokens-32)
            receipt.update(input_tokens=input_tokens,max_tokens=max_tokens)
            if max_tokens<128:
                raise ValueError('Untruncated source/schema exceeds the evaluation backend context budget')
            grammar,grammar_path,compiler=compile_grammar(packet['schema'],cve,self.out/'grammar_cache')
            receipt.update(grammar_cache=grammar_path,grammar_sha256=V.digest(grammar),compiler=compiler)
            body=dict(model=SERVED_MODEL,messages=messages,temperature=0,max_tokens=max_tokens,
                chat_template_kwargs={'enable_thinking':False},structured_outputs=dict(grammar=grammar))
            response=self.post(session,self.provider.url+'/chat/completions',body,(10,300),receipt)
            if response.status_code>=400:
                raise InfrastructureUnavailable('Inference HTTP '+str(response.status_code)+': '+response.text[:700])
            raw=response.json();receipt['response']=raw
            if raw.get('model')!=SERVED_MODEL:raise InfrastructureUnavailable('Served model identity changed')
            choice=raw['choices'][0]
            with self.lock:
                self.generations+=1
                self.tokens.update({k:v for k,v in raw.get('usage',{}).items() if isinstance(v,int)})
            if choice['finish_reason']!='stop':
                raise ValueError('Incomplete generative output: '+str(choice['finish_reason']))
            prediction=V.L.parse_json(choice['message']['content'])
            Draft202012Validator(packet['schema']).validate(prediction)
            result=dict(prediction=prediction,llm_used=True,
                model=dict(provider='nemotron_vllm_nvfp4_h200',model=self.provider.identity['model'],
                    revision=self.provider.identity['revision'],adapter=None,runtime_parity=False),
                generation=dict(usage=raw.get('usage'),temperature=0,enable_thinking=False,
                    max_tokens=max_tokens,input_tokens=input_tokens,request_id=request_id,
                    raw_receipt=str(path.relative_to(self.out))))
            receipt['status']='generated'
            return result
        except (requests.RequestException,InfrastructureUnavailable) as exc:
            self.stop.set();receipt.update(status='infrastructure_failure',error=str(exc))
            raise InfrastructureUnavailable(str(exc)) from exc
        except Exception as exc:
            receipt.update(status='invalid_output',error=type(exc).__name__+': '+str(exc))
            raise
        finally:
            receipt['seconds']=round(time.monotonic()-started,3);write(path,receipt)


def one(row,config,out,backend):
    path=out/'checkpoints'/(row['cve']+'.json')
    if path.exists():
        previous=json.loads(path.read_bytes())
        if previous.get('input_sha256')!=row['input_sha256'] or previous.get('run_identity')!=config['run_identity']:
            raise ValueError('Checkpoint input/policy mismatch')
        return previous
    begin=time.monotonic()
    result=dict(cve=row['cve'],input_sha256=row['input_sha256'],run_identity=config['run_identity'],
        source_sha256=[s['text_sha256'] for s in row['record']['sources']],started_at=now(),llm_attempted=False)
    if row['nvd_status']=='Rejected':result['state']='rejected_identity'
    elif not row['record']['sources']:result['state']='source_missing'
    else:
        try:
            result['llm_attempted']=True
            artifact=V.extract(row['record'],runner=lambda system,packet,*,role:backend.call(row['cve'],system,packet,role))
            V.validate(artifact['draft'],row['record']);T.validate_generated(artifact['draft'])
            result.update(artifact=artifact,state='unresolved_draft' if artifact['coverage_review']['status']=='failed' else 'validated_draft')
        except Exception as exc:
            if backend.stop.is_set():
                result.update(state='infrastructure_failure',error=type(exc).__name__+': '+str(exc))
                write(out/'infrastructure_failures'/(row['cve']+'-'+uuid.uuid4().hex+'.json'),result)
                raise InfrastructureUnavailable(str(exc)) from exc
            result.update(state='extraction_failed',error=type(exc).__name__+': '+str(exc),
                execution_history=deepcopy(getattr(exc,'execution_history',[])),failure=getattr(exc,'failure',None))
    result.update(completed_at=now(),seconds=round(time.monotonic()-begin,3))
    result['sha256']=V.digest(result);write(path,result)
    return result


def report(rows,config,out,*,final=False):
    states=Counter();categories=Counter();review=Counter();dimensions=Counter();failures=[];ledger=[]
    attempted=0;llm_used=0;calls=0;with_conditions=0;conditions=0;raw_hashes={}
    for row in rows:
        path=out/'checkpoints'/(row['cve']+'.json')
        if not path.exists():continue
        result=json.loads(path.read_bytes())
        if (result.get('sha256')!=V.digest({k:v for k,v in result.items() if k!='sha256'})
                or result.get('input_sha256')!=row['input_sha256'] or result.get('run_identity')!=config['run_identity']):
            raise ValueError('Checkpoint integrity mismatch: '+row['cve'])
        states[result['state']]+=1;attempted+=result['llm_attempted'];artifact=result.get('artifact',{})
        draft=artifact.get('draft',{});atoms=draft.get('prerequisites',[])
        if artifact:
            V.validate(draft,row['record']);T.validate_generated(draft)
            if artifact['sha256']!=V.digest({k:v for k,v in artifact.items() if k!='sha256'}):
                raise ValueError('Artifact integrity mismatch: '+row['cve'])
            if artifact['source_dimensions']!=T.source_dimensions(draft):raise ValueError('Dimension summary mismatch')
        llm_used+=bool(artifact.get('llm_used'));calls+=len(artifact.get('execution_history',result.get('execution_history',[])))
        conditions+=len(atoms);with_conditions+=bool(atoms);categories.update(a['category'] for a in atoms)
        review[artifact.get('coverage_review',{}).get('status','not_available')]+=1
        dimensions.update({k:int(v['status']=='stated') for k,v in artifact.get('source_dimensions',{}).items()})
        if result.get('error'):failures.append(dict(cve=row['cve'],state=result['state'],error=result['error']))
        ledger.append(dict(cve=row['cve'],state=result['state'],llm_attempted=result['llm_attempted'],
            llm_used=bool(artifact.get('llm_used')),conditions=len(atoms),unknowns=len(draft.get('unknowns',[])),
            review_status=artifact.get('coverage_review',{}).get('status','not_available'),input_sha256=row['input_sha256']))
        if final:raw_hashes[row['cve']]=sha(path)
    completed=sum(states.values())
    result=dict(population=EXPECTED,completed=completed,remaining=EXPECTED-completed,
        state='completed' if completed==EXPECTED else 'running',states=dict(states),
        llm_attempted_cves=attempted,llm_used_with_artifact=llm_used,stage_attempts=calls,
        with_conditions=with_conditions,conditions=conditions,categories=dict(categories),
        stated_dimensions=dict(dimensions),review_status=dict(review),updated_at=now(),
        source_scope=config['source_scope'],backend=config['evaluation_backend'],runtime_parity=False,
        mechanical_validation_rechecked=True,independent_semantic_accuracy_verified=False,
        completeness_claim=False,run_identity=config['run_identity'])
    write(out/'progress.json',result)
    if final:
        with (out/'population_ledger.csv').open('w',encoding='utf-8-sig',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=list(ledger[0]) if ledger else ['cve']);writer.writeheader();writer.writerows(ledger)
        write(out/'failures.json',failures);write(out/'report.json',result)
        write(out/'verification.json',dict(population=EXPECTED,recorded=completed,
            all_cves_accounted_for=completed==EXPECTED,missing=[r['cve'] for r in rows if r['cve'] not in raw_hashes],
            checkpoint_hashes=raw_hashes,ledger_sha256=sha(out/'population_ledger.csv'),
            report_sha256=sha(out/'report.json'),independent_semantic_accuracy_verified=False))
    return result


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--output',type=Path,default=HOME)
    cli.add_argument('--workers',type=int,default=16)
    cli.add_argument('--port',type=int,default=18128)
    cli.add_argument('--pilot',type=int,default=0,help='Pilot only; not population completion')
    cli.add_argument('--report-only',action='store_true')
    args=cli.parse_args()
    if not 1<=args.workers<=16:cli.error('workers must be 1..16')
    out=args.output;out.mkdir(parents=True,exist_ok=True)
    rows,config=prepare(out)
    if args.report_only:
        print(json.dumps(report(rows,config,out,final=True),ensure_ascii=False),flush=True);return
    backend=Backend(out,args.port,args.workers)
    pending_rows=[r for r in rows if not (out/'checkpoints'/(r['cve']+'.json')).exists()]
    if args.pilot:pending_rows=pending_rows[:args.pilot]
    write(out/'process.json',dict(pid=os.getpid(),started_at=now(),workers=args.workers,pilot=args.pilot,manifest_sha256=sha(out/'manifest.json')))
    print(json.dumps(dict(event='start',remaining=len(pending_rows),pilot=args.pilot,population=EXPECTED)),flush=True)
    completed=0;last=time.monotonic();iterator=iter(pending_rows)
    pool=ThreadPoolExecutor(max_workers=args.workers)
    futures=set()
    def fill():
        while len(futures)<args.workers and not backend.stop.is_set():
            try:row=next(iterator)
            except StopIteration:return
            futures.add(pool.submit(one,row,config,out,backend))
    fill()
    try:
        while futures:
            done,futures=wait(futures,timeout=10,return_when=FIRST_COMPLETED)
            for future in done:future.result();completed+=1
            fill()
            if time.monotonic()-last>=30:
                result=report(rows,config,out)
                with backend.lock:result.update(generations_this_process=backend.generations,tokens_this_process=dict(backend.tokens))
                write(out/'progress.json',result);print(json.dumps(result,ensure_ascii=False),flush=True);last=time.monotonic()
    finally:pool.shutdown(wait=True,cancel_futures=True)
    result=report(rows,config,out,final=True)
    print(json.dumps(result,ensure_ascii=False),flush=True)


if __name__=='__main__':main()
