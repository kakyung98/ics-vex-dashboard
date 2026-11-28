"""Isolated, capped H200 evaluation with byte-pinned deployed Qwen weights."""
import sys
import os
import json
import hashlib
import time
import traceback
from copy import deepcopy
from pathlib import Path
from datetime import datetime, timezone
from types import SimpleNamespace
from contextlib import nullcontext

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
OUT=ROOT/'outputs'
OUT.mkdir(exist_ok=True)


def save(name,value):
    p=OUT/name;t=p.with_suffix('.tmp')
    t.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8');t.replace(p)


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
    base=parent/'base_model'
    adapter=parent/'operator-vep-real-v2-20261119-r1/trained/vep_extraction'
    tokenizer=ROOT/'tokenizer'
    actual={}
    save('status.json',dict(state='loading',stage='verify_weights'))
    for group,folder in [('base',base),('adapter',adapter),('tokenizer',tokenizer)]:
        actual[group]={}
        for name,expected in inputs['hashes'][group].items():
            h=hashlib.sha256()
            with (folder/name).open('rb') as f:
                for block in iter(lambda:f.read(8*1024*1024),b''):h.update(block)
            actual[group][name]=h.hexdigest()
            if h.hexdigest()!=expected:raise ValueError('Pinned '+group+' file differs: '+name)
    device=torch.cuda.get_device_name(0)
    if 'H200' not in device:raise ValueError('Expected H200, got '+device)
    free,total=torch.cuda.mem_get_info()
    cap=16*1024**3
    if free<cap:raise RuntimeError('Less than 16 GiB free; existing GPU services retained')
    torch.cuda.set_per_process_memory_fraction(cap/total)
    torch.set_num_threads(4)
    tok=AutoTokenizer.from_pretrained(str(tokenizer),local_files_only=True)
    model=AutoModelForCausalLM.from_pretrained(str(base),local_files_only=True,
        device_map={'':0},dtype=torch.bfloat16,attn_implementation='sdpa')
    model=PeftModel.from_pretrained(model,str(adapter),adapter_name='vep_extraction').eval()
    runtime=SimpleNamespace(tok=tok,model=model)
    identity=dict(model='Qwen2.5-Coder-14B-Instruct',device=device,hashes=actual,
        adapter_sha256=actual['adapter']['adapter_model.safetensors'],
        memory_cap_gib=16,torch=torch.__version__,
        attention_backend='linux_sdpa',decoding=dict(do_sample=False,max_new_tokens=4096,max_time=90),
        tokenizer_path=str(tokenizer),base_path=str(base),adapter_path=str(adapter))
    save('manifest.json',dict(created_at=datetime.now(timezone.utc).isoformat(),identity=identity,
        policy=V2.OP.POLICY,prompts=dict(v2=V2.digest(V2.SYSTEM),v3=V3.digest(V3.SYSTEM)),
        transformations=['original','double_spaces','linebreaks'],expected_v2_runs=54,expected_v3_runs=14,
        source_cases=inputs['cases'],gold_used=False))
    def generate(system,packet,*,role):
        start=time.monotonic()
        prompt=tok.apply_chat_template([dict(role='system',content=system),dict(role='user',content=json.dumps(packet,ensure_ascii=False))],tokenize=False,add_generation_prompt=True,enable_thinking=False)
        encoded=tok(prompt,return_tensors='pt').to('cuda')
        length=int(encoded['input_ids'].shape[1])
        if length>6144:raise ValueError('Context exceeds bound; no truncation')
        constrained=prefix_for_schema(runtime,packet['schema'])
        with model.disable_adapter() if role=='item4-questions' else nullcontext():
            with torch.inference_mode():
                output=model.generate(**encoded,max_new_tokens=4096,max_time=90.0,do_sample=False,
                    pad_token_id=tok.pad_token_id,use_cache=True,logits_to_keep=1,prefix_allowed_tokens_fn=constrained)
        raw=tok.decode(output[0,length:],skip_special_tokens=True)
        count=int(output.shape[1]-length)
        if count>=4096:raise ValueError('Incomplete token-limited output')
        response=dict(prediction=parse_json(raw),raw=raw,llm_used=True,
            model=dict(provider='isolated_h200_deployed_weights',model=identity['model'],device=device,
                adapter=identity['adapter_sha256'] if role!='item4-questions' else None),
            generation=dict(input_tokens=length,output_tokens=count,elapsed_seconds=time.monotonic()-start,
                max_seconds=90,constrained_json=True,attention_backend='linux_sdpa'))
        return response
    completed=0
    for case in inputs['cases']:
        for kind in ['original','double_spaces','linebreaks']:
            filename=case['id']+'__'+kind+'.json'
            if (OUT/filename).exists():completed+=1;continue
            record=deepcopy(case['record'])
            for s in record['sources']:
                if kind=='double_spaces':s['text']=s['text'].replace(' ','  ')
                if kind=='linebreaks':s['text']=s['text'].replace(' ','\n')
                s['text_sha256']=hashlib.sha256(s['text'].encode()).hexdigest()
            traces=[]
            def runner(system,packet,*,role):
                start=time.monotonic()
                try:result=generate(system,packet,role=role)
                except Exception as e:
                    traces.append(dict(error=str(e),elapsed_seconds=time.monotonic()-start));raise
                traces.append(dict(response=result,elapsed_seconds=time.monotonic()-start));return result
            row=dict(cve=case['id'],variant=kind,record=record,device=device)
            start=time.monotonic()
            try:row.update(status='validated',artifact=V2.extract(record,runner=runner))
            except Exception as e:row.update(status='failed',error=str(e))
            row.update(elapsed_seconds=time.monotonic()-start,trace=traces)
            save(filename,row);completed+=1
            save('status.json',dict(state='running',stage='V2',completed=completed,total=68,last=filename))
            print(filename,row['status'],round(row['elapsed_seconds'],2),flush=True)
    for reference in inputs['v3']:
        for kind in ['with_context','without_context']:
            filename='v3__'+reference['id']+'__'+kind+'.json'
            if (OUT/filename).exists():completed+=1;continue
            payload=deepcopy(reference['packet'])
            if kind=='without_context':payload['asset_classification']=dict(status='unresolved',asset_type_id=None)
            row=dict(id=reference['id'],kind=reference['kind'],variant=kind,packet=payload,device=device)
            start=time.monotonic()
            try:row.update(status='validated',artifact=V3.generate(payload,generate))
            except Exception as e:row.update(status='failed',error=str(e))
            row['elapsed_seconds']=time.monotonic()-start
            save(filename,row);completed+=1
            save('status.json',dict(state='running',stage='V3',completed=completed,total=68,last=filename))
            print(filename,row['status'],round(row['elapsed_seconds'],2),flush=True)
    save('status.json',dict(state='complete',completed=completed,total=68,
        peak_allocated_gib=torch.cuda.max_memory_allocated()/1024**3,device=device))


if __name__=='__main__':
    try:main()
    except Exception:
        save('status.json',dict(state='failed',error=traceback.format_exc()));raise
