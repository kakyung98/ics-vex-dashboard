"""Microbatched H200 evaluation of frozen cohorts; no test-label access."""
import sys,json,hashlib,time,traceback,threading,queue,multiprocessing
from pathlib import Path
from copy import deepcopy
from datetime import datetime,timezone
from concurrent.futures import Future,ThreadPoolExecutor,as_completed
from contextlib import nullcontext
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
OUT=ROOT/'outputs';OUT.mkdir(exist_ok=True)
WRITE=threading.Lock()


def save(name,value):
    p=OUT/name;t=p.with_name(p.name+'.'+str(threading.get_ident())+'.tmp')
    t.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    with WRITE:t.replace(p)


def grammar_actor(connection,tokenizer_path):
    """CPU-only actor: the identical LM Format Enforcer function, without GIL sharing."""
    from transformers import AutoTokenizer
    from src.common.runtime.json_output_constraints import prefix_for_schema
    runtime=SimpleNamespace(tok=AutoTokenizer.from_pretrained(tokenizer_path,local_files_only=True))
    while True:
        message=connection.recv()
        if message[0]=='stop':return
        if message[0]=='schema':
            callback=prefix_for_schema(runtime,message[1]);connection.send('ready')
        elif message[0]=='tokens':
            try:connection.send(callback.token_enforcer.get_allowed_tokens(message[1]).allowed_tokens)
            except Exception as e:connection.send(dict(error=str(e)))


def main():
    import torch
    from transformers import AutoTokenizer,AutoModelForCausalLM
    from peft import PeftModel
    from src.item4.analysis import exploitation_prerequisites as V2
    from src.item4.analysis import asset_operating_question_generation as V3
    from src.common.runtime.json_output_constraints import prefix_for_schema
    from src.item4.models.json_inference_client import parse_json
    inputs=json.loads((ROOT/'inputs.json').read_text())
    parent=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
    base=parent/'base_model';adapter=parent/'operator-vep-real-v2-20261119-r1/trained/vep_extraction';tokpath=ROOT/'tokenizer'
    save('status.json',dict(state='loading',stage='verify_hashes'))
    actual={}
    for group,path in [('base',base),('adapter',adapter),('tokenizer',tokpath)]:
        actual[group]={}
        for name,expected in inputs['hashes'][group].items():
            h=hashlib.sha256()
            with (path/name).open('rb') as f:
                for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
            actual[group][name]=h.hexdigest()
            if h.hexdigest()!=expected:raise ValueError('Pinned file mismatch: '+group+'/'+name)
    device=torch.cuda.get_device_name(0)
    if 'H200' not in device:raise ValueError('H200 required')
    free,total=torch.cuda.mem_get_info();cap=17*1024**3
    if free<cap:raise RuntimeError('Less than 17 GiB free; existing services retained')
    torch.cuda.set_per_process_memory_fraction(cap/total);torch.set_num_threads(4)
    # Prepare CPU grammar actors before CUDA initialization in their processes.
    context=multiprocessing.get_context('spawn');grammar=[]
    for _ in range(4):
        parent_pipe,child_pipe=context.Pipe()
        process=context.Process(target=grammar_actor,args=(child_pipe,str(tokpath)),daemon=True);process.start()
        grammar.append((parent_pipe,process))
    tok=AutoTokenizer.from_pretrained(str(tokpath),local_files_only=True);tok.padding_side='left'
    if tok.pad_token_id is None:tok.pad_token=tok.eos_token
    model=AutoModelForCausalLM.from_pretrained(str(base),local_files_only=True,device_map={'':0},dtype=torch.bfloat16,attn_implementation='sdpa')
    model=PeftModel.from_pretrained(model,str(adapter),adapter_name='vep_extraction').eval()
    runtime=SimpleNamespace(tok=tok,model=model)
    identity=dict(model='Qwen2.5-Coder-14B-Instruct',device=device,hashes=actual,adapter_sha256=actual['adapter']['adapter_model.safetensors'],
        memory_cap_gib=17,torch=torch.__version__,attention='linux_sdpa',microbatch_size=4,
        decoding=dict(do_sample=False,max_new_tokens=4096,max_time=90),parallel_grammar_actors=4,
        batching_limit='Batched greedy numerics may differ from prior singleton runs; report separately.')
    expected_v2=sum(3 if c['robustness_selected'] else 1 for c in inputs['cases']);expected_v3=2*len(inputs['v3'])
    save('manifest.json',dict(created_at=datetime.now(timezone.utc).isoformat(),identity=identity,policy=V2.OP.POLICY,
        prompts=dict(v2=V2.digest(V2.SYSTEM),v3=V3.digest(V3.SYSTEM)),expected_v2_runs=expected_v2,expected_v3_runs=expected_v3,
        gold_used=False,inputs_sha256=hashlib.sha256((ROOT/'inputs.json').read_bytes()).hexdigest()))
    tasks=queue.Queue();shutdown=object()
    def infer_batch(batch):
        role=batch[0][2]
        if any(b[2]!=role for b in batch):raise ValueError('Mixed adapter roles in batch')
        prompts=[tok.apply_chat_template([dict(role='system',content=s),dict(role='user',content=json.dumps(p,ensure_ascii=False))],tokenize=False,add_generation_prompt=True,enable_thinking=False) for s,p,_,_ in batch]
        encoded=tok(prompts,return_tensors='pt',padding=True).to('cuda');width=encoded['input_ids'].shape[1]
        if width>6144:raise ValueError('Context exceeds bound; no truncation')
        for i,(_,p,_,_) in enumerate(batch):grammar[i][0].send(('schema',p['schema']))
        for i in range(len(batch)):
            if grammar[i][0].recv()!='ready':raise ValueError('Grammar actor failed to initialize')
        class GrammarProcessor:
            def __call__(self,input_ids,scores):
                sequences=input_ids.tolist()
                for i,sequence in enumerate(sequences):grammar[i][0].send(('tokens',sequence))
                allowed=[grammar[i][0].recv() for i in range(len(sequences))]
                mask=torch.full_like(scores,float('-inf'))
                for i,values in enumerate(allowed):
                    if isinstance(values,dict):raise ValueError(values['error'])
                    mask[i,values]=0
                return scores+mask
        start=time.monotonic()
        with model.disable_adapter() if role=='item4-questions' else nullcontext():
            with torch.inference_mode():
                    output=model.generate(**encoded,max_new_tokens=4096,max_time=90,do_sample=False,pad_token_id=tok.pad_token_id,use_cache=True,logits_to_keep=1,logits_processor=[GrammarProcessor()])
        elapsed=time.monotonic()-start
        for i,(_,packet,_,future) in enumerate(batch):
            raw=tok.decode(output[i,width:],skip_special_tokens=True)
            try:
                result=dict(prediction=parse_json(raw),raw=raw,llm_used=True,
                    model=dict(provider='h200_microbatched_deployed_weights',model=identity['model'],device=device,
                        adapter=identity['adapter_sha256'] if role!='item4-questions' else None),
                    generation=dict(input_tokens=int(encoded['attention_mask'][i].sum()),output_tokens=int((output[i,width:]!=tok.pad_token_id).sum()),
                        elapsed_seconds=elapsed,microbatch_size=len(batch),constrained_json=True))
                future.set_result(result)
            except Exception as exc:
                exc.raw_output=raw;future.set_exception(exc)
    def serving():
        while True:
            first=tasks.get()
            if first is shutdown:return
            batch=[first];deadline=time.monotonic()+.15
            while len(batch)<4:
                try:
                    b=tasks.get(timeout=max(.001,deadline-time.monotonic()))
                    if b is shutdown:tasks.put(shutdown);break
                    batch.append(b)
                except queue.Empty:break
            try:infer_batch(batch)
            except Exception as exc:
                # OOM/context outliers are retried one by one, with provenance.
                torch.cuda.empty_cache()
                for b in batch:
                    if b[3].done():continue
                    try:infer_batch([b])
                    except Exception as single:
                        if not b[3].done():b[3].set_exception(single)
    server=threading.Thread(target=serving,daemon=True);server.start()
    def generate(system,packet,*,role):
        future=Future();tasks.put((system,packet,role,future));return future.result(timeout=900)
    done=0;start_all=time.monotonic()
    def v2_one(item):
        case,kind=item;filename=case['id']+'__'+kind+'.json'
        if (OUT/filename).exists():return filename
        record=deepcopy(case['record'])
        for source in record.get('sources',[]):
            if kind=='double_spaces':source['text']=source['text'].replace(' ','  ')
            if kind=='linebreaks':source['text']=source['text'].replace(' ','\n')
            source['text_sha256']=hashlib.sha256(source['text'].encode()).hexdigest()
        row=dict(cve=case['id'],variant=kind,stratum=case['stratum'],record=record,trace=[])
        start=time.monotonic()
        def runner(system,packet,*,role):
            try:r=generate(system,packet,role=role)
            except Exception as e:row['trace'].append(dict(error=str(e),raw=getattr(e,'raw_output',None)));raise
            row['trace'].append(dict(response=r));return r
        try:
            if not record.get('sources'):row.update(status='source_unavailable',error=record.get('reason','Source unavailable'))
            else:row.update(status='validated',artifact=V2.extract(record,runner=runner))
        except Exception as exc:row.update(status='failed',error=str(exc))
        row['elapsed_seconds']=time.monotonic()-start;save(filename,row);return filename
    v2_items=[(c,k) for c in inputs['cases'] for k in (['original','double_spaces','linebreaks'] if c['robustness_selected'] else ['original'])]
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures=[pool.submit(v2_one,x) for x in v2_items]
        for f in as_completed(futures):
            name=f.result();done+=1
            save('status.json',dict(state='running',stage='V2',completed=done,total=expected_v2+expected_v3,last=name,elapsed_seconds=time.monotonic()-start_all))
            if done%20==0:print('V2',done,name,flush=True)
    def v3_one(item):
        reference,kind=item;filename='v3__'+reference['id']+'__'+kind+'.json'
        if (OUT/filename).exists():return filename
        payload=deepcopy(reference['packet'])
        if kind=='without_context':payload['asset_classification']=dict(status='unresolved',asset_type_id=None)
        row=dict(id=reference['id'],kind=reference['kind'],variant=kind,packet=payload)
        start=time.monotonic()
        try:row.update(status='validated',artifact=V3.generate(payload,generate))
        except Exception as e:row.update(status='failed',error=str(e),raw=getattr(e,'raw_output',None))
        row['elapsed_seconds']=time.monotonic()-start;save(filename,row);return filename
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures=[pool.submit(v3_one,(r,k)) for r in inputs['v3'] for k in ['with_context','without_context']]
        for f in as_completed(futures):
            name=f.result();done+=1
            save('status.json',dict(state='running',stage='V3',completed=done,total=expected_v2+expected_v3,last=name,elapsed_seconds=time.monotonic()-start_all))
            if done%20==0:print('V3',done,name,flush=True)
    tasks.put(shutdown);server.join(timeout=10)
    for pipe,process in grammar:pipe.send(('stop',));process.join(timeout=5)
    save('status.json',dict(state='complete',completed=done,total=expected_v2+expected_v3,elapsed_seconds=time.monotonic()-start_all,
        peak_allocated_gib=torch.cuda.max_memory_allocated()/1024**3,device=device))


if __name__=='__main__':
    try:main()
    except Exception:
        save('status.json',dict(state='failed',error=traceback.format_exc()));raise
