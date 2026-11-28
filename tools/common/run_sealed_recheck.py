"""Inference only. New GT/relation answers are never uploaded or loaded here."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
import argparse,hashlib,json,sys,time,threading
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))


def write(p,x):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);t=p.with_name(p.name+'.'+str(threading.get_ident())+'.tmp');t.write_text(json.dumps(x,ensure_ascii=False,indent=2));t.replace(p)


def verify(args):
    seal=json.loads((ROOT/'freeze.json').read_text())
    for rel,expected in seal['runtime_files'].items():
        if hashlib.sha256((ROOT/rel).read_bytes()).hexdigest()!=expected:raise RuntimeError('Frozen source changed: '+rel)
    if hashlib.sha256((args.output/'inputs.json').read_bytes()).hexdigest()!=seal['input_sha256'][args.task]:raise RuntimeError('Frozen input changed')
    return seal


def item3(args,seal):
    import torch
    from src.item3.matching.identification_pipeline import run_unified
    from src.item3.evidence.product_candidate_search import get_index
    from src.item3.evidence.local_vulnerability_lookup import get_source_lookup
    from src.common.runtime.shared_adapter_runtime import PrecisionRoleRuntime
    from src.item3.agents.batched_provider import BatchedIdentificationProvider
    if hashlib.sha256((args.model/'adapter_model.safetensors').read_bytes()).hexdigest()!=seal['models']['item3_adapter_sha256']:raise RuntimeError('Identification adapter differs')
    free,total=torch.cuda.mem_get_info();cap=int(18.5*1024**3)
    if free<cap:raise RuntimeError('Insufficient free memory; existing services retained')
    torch.cuda.set_per_process_memory_fraction(cap/total);write(args.output/'status.json',dict(state='loading_indexes'))
    runtime=PrecisionRoleRuntime(args.model);provider=BatchedIdentificationProvider(infer=runtime.identification_batch);index=get_index();lookup=get_source_lookup()
    inputs=json.loads((args.output/'inputs.json').read_text());start=time.monotonic()
    try:
        for i,c in enumerate(inputs,1):
            p=args.output/'predictions'/(c['id']+'.json')
            if not p.exists():
                row=dict(id=c['id'],error=None)
                try:
                    result=run_unified(c['sbom'],lookup,index=index,agents=provider,mode='agents',mapping_scope='identification')
                    target=next(x for x in result['components'] if x['component']['id']==c['target_id']);v=target['validation'];ver=target['i2']
                    failed=[];hashes=[]
                    for stage in ('i1','i2','i3'):
                        a=target.get(stage,{}).get('agent') or {};g=a.get('generation') or {}
                        if a.get('executed') and not a.get('guard_accepted'):failed.append(dict(stage=stage,error=a.get('error')))
                        if g.get('model_packet_sha256'):hashes.append([stage,g['model_packet_sha256']])
                    row.update(target=dict(identity=[v.get(k) for k in ('status','part','vendor','product')],version=ver.get('normalized'),range=ver.get('declared_range'),conflicts=ver.get('conflicts',[]),
                        cves=sorted([x['cve_id'],x['match_status']] for x in target.get('cves',[])),lookup_error=target.get('i3',{}).get('lookup_error')),agent_failures=failed,model_hashes=hashes,result=result)
                except Exception as exc:row['error']=type(exc).__name__+': '+str(exc)
                write(p,row)
            write(args.output/'status.json',dict(state='predicting',completed=i,total=len(inputs),elapsed_seconds=time.monotonic()-start))
    finally:provider.close()
    write(args.output/'status.json',dict(state='predictions_complete',cases=len(inputs),gold_loaded=False))


def item4(args,seal):
    import requests
    from tools.item4 import extract_source_conditions_for_question_links as S
    from tools.item4.compact_json_grammar import structured_completion
    from src.item4.models.nemotron_inference_provider import MODEL,REVISION,SERVED_MODEL
    if hashlib.sha256(S.PROMPT.encode()).hexdigest()!=seal['models']['item4_prompt_sha256']:raise RuntimeError('Frozen extraction prompt differs')
    class Backend:
        url='http://127.0.0.1:18128/v1'
        def __init__(self):self.local=threading.local();self.token=args.token.read_text().strip()
        def session(self):
            if not hasattr(self.local,'session'):
                self.local.session=requests.Session();self.local.session.trust_env=False;self.local.session.headers['Authorization']='Bearer '+self.token
            return self.local.session
    backend=Backend();r=backend.session().get(backend.url+'/models',timeout=15);r.raise_for_status()
    if SERVED_MODEL not in {m['id'] for m in r.json()['data']}:raise RuntimeError('Wrong served model')
    S.OUT=args.output/'native_cache';S.CACHE=S.OUT/'model_cache';S.CASE_CACHE=S.CACHE/'cases';S.CASE_CACHE.mkdir(parents=True,exist_ok=True)
    def raw(backend,body,schema):
        reply=structured_completion(backend,body,schema)
        write(args.output/'raw_calls'/(hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest()+'.json'),dict(request=body,response=reply,model=MODEL,revision=REVISION))
        return reply
    S.source_completion=raw;inputs=json.loads((args.output/'inputs.json').read_text());schema=S.source_schema();start=time.monotonic();done=0;lock=threading.Lock()
    def one(c):
        nonlocal done
        p=args.output/'predictions'/(c['id']+'.json')
        if not p.exists():
            native=dict(case_id=c['id'],cve=c['cve'],passages=c['passages'],cvss_version=c['cvss_version'],scopes=c['scopes'])
            wire_schema=dict(type='object',properties={'0':schema},required=['0'],additionalProperties=False)
            packet=dict(cases={'0':native},metric_definitions=S.DEFINITIONS,schema=wire_schema)
            row=dict(id=c['id'],valid=False,error=None,model=MODEL,revision=REVISION,prompt_sha256=seal['models']['item4_prompt_sha256'])
            try:row.update(prediction=S.model_call(backend,packet)['0'],valid=True)
            except (requests.RequestException,ConnectionError,TimeoutError) as exc:
                write(args.output/'infrastructure_errors'/(c['id']+'.json'),dict(id=c['id'],error=str(exc)));raise RuntimeError('Infrastructure failure: repair and resume, no selective model-error scoring') from exc
            except Exception as exc:row['error']=type(exc).__name__+': '+str(exc)
            write(p,row)
        with lock:
            done+=1;write(args.output/'status.json',dict(state='predicting',completed=done,total=len(inputs),elapsed_seconds=time.monotonic()-start))
    with ThreadPoolExecutor(max_workers=8) as pool:
        for f in as_completed([pool.submit(one,c) for c in inputs]):f.result()
    write(args.output/'status.json',dict(state='predictions_complete',cases=len(inputs),gold_loaded=False))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--task',choices=('item3','item4'),required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--model',type=Path);p.add_argument('--token',type=Path);a=p.parse_args()
    try:
        seal=verify(a);globals()[a.task](a,seal)
    except Exception as exc:write(a.output/'status.json',dict(state='failed',error=type(exc).__name__+': '+str(exc)));raise
