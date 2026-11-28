"""Supplemental H200 arm with actual human-readable provisional asset labels."""
import sys,json,time,threading,traceback
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
OUT=ROOT/'outputs';LOCK=threading.Lock()


def save(name,value):
    p=OUT/name;t=p.with_name(p.name+'.'+str(threading.get_ident())+'.tmp');t.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    with LOCK:t.replace(p)


def main():
    import requests
    from transformers import AutoTokenizer
    from src.item4.analysis import asset_operating_question_generation as V3
    from src.common.runtime.json_output_constraints import generation_schema
    # The original study finishes first; its status and outputs remain intact.
    while True:
        status=json.loads((OUT/'status.json').read_text()) if (OUT/'status.json').exists() else {}
        if status.get('state')=='complete':break
        if status.get('state')=='failed':raise RuntimeError('Main inference worker failed')
        time.sleep(5)
    rows=json.loads((ROOT/'named_context_inputs.json').read_text());tok=AutoTokenizer.from_pretrained(str(ROOT/'tokenizer'),local_files_only=True);local=threading.local()
    def runner(system,packet,*,role):
        if not hasattr(local,'session'):
            s=requests.Session();s.trust_env=False;s.headers['Authorization']='Bearer '+(ROOT/'server.auth').read_text().strip();local.session=s
        prompt=tok.apply_chat_template([dict(role='system',content=system),dict(role='user',content=json.dumps(packet,ensure_ascii=False))],tokenize=False,add_generation_prompt=True,enable_thinking=False)
        if len(tok.encode(prompt,add_special_tokens=False))>6144:raise ValueError('Input exceeds deployed context bound; no truncation')
        start=time.monotonic();r=local.session.post('http://127.0.0.1:18971/v1/chat/completions',json=dict(model='qwen-base',temperature=0,max_tokens=4096,
            chat_template_kwargs=dict(enable_thinking=False),messages=[dict(role='system',content=system),dict(role='user',content=json.dumps(packet,ensure_ascii=False))],
            response_format=dict(type='json_schema',json_schema=dict(name='named_question',strict=True,schema=generation_schema(packet['schema'])))),timeout=(5,180))
        r.raise_for_status();reply=r.json();choice=reply['choices'][0]
        if choice['finish_reason']!='stop':raise ValueError('Incomplete generation')
        return dict(prediction=json.loads(choice['message']['content']),raw=choice['message']['content'],llm_used=True,
            model=dict(provider='h200_vllm_pinned_qwen_weights',model='Qwen2.5-Coder-14B-Instruct',adapter=None,device='NVIDIA H200'),
            generation=dict(elapsed_seconds=time.monotonic()-start,usage=reply.get('usage')))
    def one(row):
        name='v3__'+row['id']+'__named_context.json'
        if (OUT/name).exists():return
        result=dict(id=row['id'],variant='named_context',kind=row['kind'],packet=row['packet'],named_context_available=row['named_context_available'])
        try:
            if not row['named_context_available']:result.update(status='context_unavailable',reason='Asset type unresolved; use the original unresolved-context run in the effective main analysis.')
            else:result.update(status='validated',artifact=V3.generate(row['packet'],runner))
        except Exception as e:result.update(status='failed',error=str(e),raw=getattr(e,'raw_output',None))
        save(name,result)
    completed=0
    with ThreadPoolExecutor(max_workers=4) as pool:
        for f in as_completed([pool.submit(one,r) for r in rows]):
            f.result();completed+=1;save('named_context_status.json',dict(state='running',completed=completed,total=len(rows)))
    save('named_context_status.json',dict(state='complete',completed=completed,total=len(rows),actual_named_context_cases=sum(r['named_context_available'] for r in rows)))


if __name__=='__main__':
    try:main()
    except Exception:save('named_context_status.json',dict(state='failed',error=traceback.format_exc()));raise
