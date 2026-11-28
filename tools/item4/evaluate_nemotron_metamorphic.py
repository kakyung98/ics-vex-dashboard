"""Evaluate the actual Nemotron native source extractor; no Qwen adapters.

Two DEV prompt/structure candidates are distinct from weight training.
No TEST prediction or labels enter candidate selection.
"""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
import sys,json,time,argparse,hashlib,threading
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.evaluation import metamorphic_synthetic as E
from src.item4.evaluation import nemotron_source_synthetic as N
from tools.item4 import extract_source_conditions_for_question_links as S
from tools.item4.compact_json_grammar import structured_completion
from src.item4.models.nemotron_inference_provider import MODEL,REVISION,SERVED_MODEL

from src.item4.analysis.source_extraction_prompt_variants import CANDIDATES as TUNING


def write(p,value):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
    tmp=p.with_name(p.name+'.'+str(threading.get_ident())+'.tmp');tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2));tmp.replace(p)


class Backend:
    def __init__(self,token):
        self.url='http://127.0.0.1:18128/v1';self.token=token.read_text().strip();self.local=threading.local()
        r=self.session().get(self.url+'/models',timeout=15);r.raise_for_status()
        if SERVED_MODEL not in {m['id'] for m in r.json()['data']}:raise ValueError('Wrong inference model')
    def session(self):
        import requests
        if not hasattr(self.local,'session'):
            self.local.session=requests.Session();self.local.session.trust_env=False;self.local.session.headers['Authorization']='Bearer '+self.token
        return self.local.session


def evaluate(cases,phase,args,backend):
    out=args.output;folder=out/'predictions'/phase;folder.mkdir(parents=True,exist_ok=True)
    S.PROMPT=args.base_prompt+TUNING[phase]
    S.OUT=out/'native_cache'/phase;S.CACHE=S.OUT/'model_cache';S.CASE_CACHE=S.CACHE/'cases'
    S.CASE_CACHE.mkdir(parents=True,exist_ok=True)
    def raw_call(backend,body,schema):
        reply=structured_completion(backend,body,schema)
        write(S.OUT/'raw_calls'/(E.digest(body)+'.json'),dict(request=body,response=reply,model=MODEL,revision=REVISION))
        return reply
    S.source_completion=raw_call
    start=time.monotonic();rows={};lock=threading.Lock();inner=S.source_schema()
    def group_eval(group):
        pending=[]
        for c in group:
            p=folder/(c['id']+'.json')
            if p.exists():
                row=json.loads(p.read_text());rows[c['id']]=row
            else:pending.append(c)
        if not pending:return
        native={str(i):dict(case_id=c['id'],cve=c['record']['cve'],passages={'S'+str(j):s['text'] for j,s in enumerate(c['record']['sources'])},cvss_version='4.0',
            scopes={'S'+str(j):E.digest([s.get('product_keys',[]),s.get('scope_binding')])[:16] for j,s in enumerate(c['record']['sources'])}) for i,c in enumerate(pending)}
        schema=dict(type='object',properties={k:inner for k in native},required=list(native),additionalProperties=False)
        packet=dict(cases=native,metric_definitions=S.DEFINITIONS,schema=schema)
        try:prediction=S.model_call(backend,packet);error=None
        except Exception as exc:
            import requests
            if isinstance(exc,(requests.RequestException,ConnectionError,TimeoutError)):raise RuntimeError('Infrastructure failure; repair before scoring') from exc
            if len(pending)>1:
                half=len(pending)//2;group_eval(pending[:half]);group_eval(pending[half:]);return
            prediction={};error=type(exc).__name__+': '+str(exc)
        for i,c in enumerate(pending):
            row=dict(id=c['id'],phase=phase,arm='native_source_extractor',prediction=prediction.get(str(i)),valid=error is None,error=error,
                oracle=N.VERSION,prompt_sha256=hashlib.sha256(S.PROMPT.encode()).hexdigest(),packet_sha256=E.digest(packet),model=MODEL,revision=REVISION,adapter=None)
            write(folder/(c['id']+'.json'),row)
            with lock:
                rows[c['id']]=row
                write(out/'status.json',dict(state='evaluating',phase=phase,split=c['split'],completed=len(rows),total=len(cases),elapsed_seconds=time.monotonic()-start))
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for f in as_completed([pool.submit(group_eval,cases[i:i+args.batch_size]) for i in range(0,len(cases),args.batch_size)]):f.result()
    report=N.summarize(cases,list(rows.values()),args.synthetic_only);write(out/(phase+'_'+cases[0]['split']+'.json'),report);return report


def main(args):
    args.output.mkdir(parents=True,exist_ok=True);allcases=[c for c in E.dataset() if not args.synthetic_only or c['variant']=='original'];args.base_prompt=S.BASELINE_PROMPT
    manifest=dict(model=MODEL,revision=REVISION,adapter=None,weight_training_performed=False,
        implementation='tools/item4/extract_source_conditions_for_question_links.py:model_call/source_schema',
        source_sha256=hashlib.sha256(Path(S.__file__).read_bytes()).hexdigest(),oracle=N.VERSION,
        oracle_sha256=hashlib.sha256(Path(N.__file__).read_bytes()).hexdigest(),dataset_sha256=E.digest(allcases),
        selection_split='DEV only, all original+related variants grouped',gate='Precision, recall, F1, full logic and complete-case accuracy all strictly >0.90' if args.synthetic_only else 'Every one of condition F1, full logic accuracy, grounded MR strictly >0.90',
        evaluation='synthetic_gt_only' if args.synthetic_only else 'synthetic_and_metamorphic',
        candidates=TUNING,batch_size=args.batch_size,workers=args.workers,
        note='Source extractor and native branch schema, not the historical four-role VEX classifier. Two candidates mean prompt/structure tuning, not two epochs of weight training.')
    write(args.output/'manifest.json',manifest)
    write(args.output/'inputs.json',[{k:v for k,v in c.items() if k!='gold'} for c in allcases]);write(args.output/'gold.json',[dict(id=c['id'],gold=c['gold']) for c in allcases])
    backend=Backend(args.token);dev=[c for c in allcases if c['split']=='dev'];reports={}
    for phase in TUNING:
        report=evaluate(dev,phase,args,backend);reports[phase]=report['scores'][phase+'/native_source_extractor/dev']
    selected=max(reports,key=lambda p:(min([reports[p].get(k) or 0 for k in (('precision','recall','f1','logic_accuracy','case_accuracy') if args.synthetic_only else ('f1','logic_accuracy','grounded_mr_rate'))]),reports[p]['case_accuracy']))
    selection=dict(selected=selected,metrics=reports,above_90=reports[selected]['above_90'],test_used_for_selection=False)
    write(args.output/'selection.json',selection)
    if not selection['above_90']:
        write(args.output/'status.json',dict(state='needs_additional_tuning',selection=selection));return
    test=[c for c in allcases if c['split']=='test']
    final=evaluate(test,selected,args,backend)
    if selected!='baseline':
        baseline=evaluate(test,'baseline',args,backend);final['scores'].update(baseline['scores'])
    final.update(selection=selection,manifest=manifest,production_installed=False)
    write(args.output/'report.json',final);write(args.output/'status.json',dict(state='complete',selected=selected,scores=final['scores']))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--token',type=Path,required=True)
    p.add_argument('--workers',type=int,default=8);p.add_argument('--batch-size',type=int,default=6);p.add_argument('--synthetic-only',action='store_true');a=p.parse_args()
    try:main(a)
    except Exception as exc:write(a.output/'status.json',dict(state='failed',error=type(exc).__name__+': '+str(exc)));raise
