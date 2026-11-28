"""High-throughput evaluation; separately records the vLLM decoding backend."""
import sys,json,hashlib,time,threading,traceback,copy
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
OUT=ROOT/'outputs';OUT.mkdir(exist_ok=True);LOCK=threading.Lock()


def save(name,value):
    p=OUT/name;t=p.with_name(p.name+'.'+str(threading.get_ident())+'.tmp');t.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    with LOCK:t.replace(p)


def main():
    import requests
    from src.item4.analysis import exploitation_prerequisites as V2
    from src.item4.analysis import asset_operating_question_generation as V3
    from src.common.runtime.json_output_constraints import generation_schema
    from transformers import AutoTokenizer
    tokenizer=AutoTokenizer.from_pretrained(str(ROOT/'tokenizer'),local_files_only=True)
    inputs=json.loads((ROOT/'inputs.json').read_text())
    old=json.loads((ROOT/'outputs_hf_diagnostic/manifest.json').read_text())
    identity={k:old['identity'][k] for k in ('model','device','hashes','adapter_sha256')}
    command=json.loads((ROOT/'server_command.json').read_text())
    identity.update(provider='vllm_0.12.0_bitsandbytes',gpu_memory_utilization=float(command[command.index('--gpu-memory-utilization')+1]),
        decoding=dict(temperature=0,max_tokens=4096,http_timeout_seconds=180),
        grammar='vLLM JSON schema with the same Boolean generation-schema normalization',
        decoding_backend_limit='Same pinned weights, tokenizer and prompts; inference/grammar engine differs from deployed Transformers. This measures the weights under this backend, not exact deployed-runtime parity.')
    local=threading.local()
    def session():
        if not hasattr(local,'session'):
            s=requests.Session();s.trust_env=False;s.headers['Authorization']='Bearer '+(ROOT/'server.auth').read_text().strip();local.session=s
        return local.session
    ready=False
    for _ in range(60):
        try:
            r=session().get('http://127.0.0.1:18971/v1/models',timeout=5);r.raise_for_status()
            ids={a['id'] for a in r.json()['data']}
            if {'qwen-base','vep-extraction'}<=ids:ready=True;break
        except requests.RequestException:pass
        time.sleep(2)
    if not ready:raise ValueError('Qwen vLLM service not ready')
    save('manifest.json',dict(created_at=datetime.now(timezone.utc).isoformat(),identity=identity,policy=V2.OP.POLICY,
        prompts=dict(v2=V2.digest(V2.SYSTEM),v3=V3.digest(V3.SYSTEM)),expected_v2_runs=700,expected_v3_runs=360,
        gold_used=False,inputs_sha256=hashlib.sha256((ROOT/'inputs.json').read_bytes()).hexdigest()))
    def generate(system,packet,*,role):
        model='vep-extraction' if role=='exploitation-prerequisites' else 'qwen-base'
        prompt=tokenizer.apply_chat_template([dict(role='system',content=system),dict(role='user',content=json.dumps(packet,ensure_ascii=False))],tokenize=False,add_generation_prompt=True,enable_thinking=False)
        if len(tokenizer.encode(prompt,add_special_tokens=False))>6144:raise ValueError('Input exceeds the deployed 6144-token bound; no truncation')
        start=time.monotonic()
        def canonical_schema(node):
            if isinstance(node,list):return [canonical_schema(x) for x in node]
            if not isinstance(node,dict):return node
            if node.get('type')=='array' and node.get('maxItems')==0:
                return {k:canonical_schema(v) for k,v in node.items() if k not in ('items','uniqueItems')}
            # LM Format Enforcer also parses but does not implement uniqueItems.
            # The original jsonschema post-validator continues to enforce it.
            return {k:canonical_schema(v) for k,v in node.items() if k!='uniqueItems'}
        response=session().post('http://127.0.0.1:18971/v1/chat/completions',json=dict(model=model,temperature=0,max_tokens=4096,
            chat_template_kwargs=dict(enable_thinking=False),messages=[dict(role='system',content=system),dict(role='user',content=json.dumps(packet,ensure_ascii=False))],
            response_format=dict(type='json_schema',json_schema=dict(name='item4_contract',strict=True,schema=canonical_schema(generation_schema(packet['schema']))))),timeout=(5,180))
        if not response.ok:raise ValueError('Inference HTTP '+str(response.status_code)+': '+response.text[:1500])
        r=response.json();c=r['choices'][0]
        if c['finish_reason']!='stop':raise ValueError('Incomplete generation: '+str(c['finish_reason']))
        raw=c['message']['content']
        return dict(prediction=json.loads(raw),raw=raw,llm_used=True,
            model=dict(provider='h200_vllm_pinned_qwen_weights',model=identity['model'],device='NVIDIA H200',adapter=identity['adapter_sha256'] if model=='vep-extraction' else None),
            generation=dict(elapsed_seconds=time.monotonic()-start,usage=r.get('usage'),backend='vllm_0.12.0_bitsandbytes',constrained_json=True))
    # Transport/schema preflight is stored separately and cannot silently turn
    # a backend integration error into hundreds of model-quality failures.
    first=next(c for c in inputs['cases'] if c['record'].get('sources'))
    packet=V2.extraction_packet(first['record'])
    try:
        preflight=generate(V2.SYSTEM,packet,role='exploitation-prerequisites')
        save('preflight.json',dict(status='completed',cve=first['id'],response=preflight))
    except Exception:
        save('preflight.json',dict(status='failed',error=traceback.format_exc()));raise
    jobs=[(c,k) for c in inputs['cases'] for k in (['original','double_spaces','linebreaks'] if c['robustness_selected'] else ['original'])]
    done=0;start_all=time.monotonic()
    def v2_one(item):
        case,kind=item;name=case['id']+'__'+kind+'.json'
        if (OUT/name).exists():return name
        record=copy.deepcopy(case['record'])
        for s in record.get('sources',[]):
            if kind=='double_spaces':s['text']=s['text'].replace(' ','  ')
            if kind=='linebreaks':s['text']=s['text'].replace(' ','\n')
            s['text_sha256']=hashlib.sha256(s['text'].encode()).hexdigest()
        row=dict(cve=case['id'],variant=kind,stratum=case['stratum'],record=record,trace=[])
        def runner(system,packet,*,role):
            try:r=generate(system,packet,role=role)
            except Exception as e:row['trace'].append(dict(error=str(e)));raise
            row['trace'].append(dict(response=r));return r
        started=time.monotonic()
        try:
            if not record.get('sources'):row.update(status='source_unavailable',error=record.get('reason','Source unavailable'))
            else:row.update(status='validated',artifact=V2.extract(record,runner=runner))
        except Exception as e:row.update(status='failed',error=str(e))
        row['elapsed_seconds']=time.monotonic()-started;save(name,row);return name
    with ThreadPoolExecutor(max_workers=4) as pool:
        for f in as_completed([pool.submit(v2_one,j) for j in jobs]):
            name=f.result();done+=1
            save('status.json',dict(state='running',stage='V2',completed=done,total=1060,last=name,elapsed_seconds=time.monotonic()-start_all))
            if done%25==0:print('V2',done,flush=True)
    def v3_one(item):
        reference,kind=item;name='v3__'+reference['id']+'__'+kind+'.json'
        if (OUT/name).exists():return name
        p=copy.deepcopy(reference['packet'])
        if kind=='without_context':p['asset_classification']=dict(status='unresolved',asset_type_id=None)
        row=dict(id=reference['id'],kind=reference['kind'],variant=kind,packet=p)
        started=time.monotonic()
        try:row.update(status='validated',artifact=V3.generate(p,generate))
        except Exception as e:row.update(status='failed',error=str(e),raw=getattr(e,'raw_output',None))
        row['elapsed_seconds']=time.monotonic()-started;save(name,row);return name
    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs=[(r,k) for r in inputs['v3'] for k in ['with_context','without_context']]
        for f in as_completed([pool.submit(v3_one,j) for j in jobs]):
            name=f.result();done+=1
            save('status.json',dict(state='running',stage='V3',completed=done,total=1060,last=name,elapsed_seconds=time.monotonic()-start_all))
            if done%25==0:print('V3',done,flush=True)
    save('status.json',dict(state='complete',completed=done,total=1060,elapsed_seconds=time.monotonic()-start_all,device='NVIDIA H200',backend='vllm_0.12.0_bitsandbytes'))


if __name__=='__main__':
    try:main()
    except Exception:
        save('status.json',dict(state='failed',error=traceback.format_exc()));raise
