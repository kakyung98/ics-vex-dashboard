"""Select continued LoRA checkpoints on DEV validation; then frozen TEST only."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
from copy import deepcopy
from unittest.mock import patch
import sys,json,time,threading,argparse
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.evaluation import metamorphic_synthetic as E
from src.item4.evaluation import exact_atom_normalization as N
from tools.item4.run_metamorphic_synthetic import TUNING


def write(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    p=path.with_name(path.name+'.'+str(threading.get_ident())+'.tmp');p.write_text(json.dumps(value,ensure_ascii=False,indent=2));p.replace(path)


def evaluate(args,inputs,alias,phase,output):
    import requests
    from src.item4.analysis import exploitation_prerequisites as V
    from src.item4.evaluation import source_guard_candidate as G
    from src.common.runtime.json_output_constraints import generation_schema
    output=Path(output);root=args.output;local=threading.local();start=time.monotonic()
    identities=json.loads(args.identity.read_text());identity=identities['adapters'][alias]
    def canonical(x):
        if isinstance(x,list):return [canonical(v) for v in x]
        if not isinstance(x,dict):return x
        return {k:canonical(v) for k,v in x.items() if k!='uniqueItems' and not(x.get('type')=='array' and x.get('maxItems')==0 and k=='items')}
    def session():
        if not hasattr(local,'session'):
            local.session=requests.Session();local.session.trust_env=False
            local.session.headers['Authorization']='Bearer '+args.token.read_text().strip()
        return local.session
    def one(item):
        path=output/(item['id']+'.json')
        if path.exists():
            previous=json.loads(path.read_text())
            if previous.get('normalization_version')==N.VERSION:return previous
            archive=root/'sft_validation_superseded'/alias/path.name;archive.parent.mkdir(parents=True,exist_ok=True);path.replace(archive)
        row=dict(id=item['id'],arm='D_adapter_pipeline',phase=phase,valid=False,draft=None,trace=[],validation_candidate=G.VERSION,normalization_version=N.VERSION)
        def runner(system,packet,*,role):
            system+=TUNING['adapter_review']
            key=E.digest(dict(system=system,packet=packet,model=alias,identity=identity))
            cached=root/'sft_generation_cache'/(key+'.json')
            if cached.exists():result=json.loads(cached.read_text())
            else:
                begin=time.monotonic()
                decode_schema=packet['schema'] if identity.get('strict_boolean_constants') else generation_schema(packet['schema'])
                body=dict(model=alias,temperature=0,max_tokens=3072,chat_template_kwargs=dict(enable_thinking=False),
                    messages=[dict(role='system',content=system),dict(role='user',content=json.dumps(packet,ensure_ascii=False))],
                    response_format=dict(type='json_schema',json_schema=dict(name='vep',strict=True,schema=canonical(decode_schema))))
                try:
                    response=session().post(args.url+'/v1/chat/completions',json=body,timeout=(10,240));response.raise_for_status()
                except requests.RequestException as exc:
                    row['infrastructure_error']=type(exc).__name__+': '+str(exc);raise FileNotFoundError('Inference transport failed') from exc
                raw=response.json();choice=raw['choices'][0]
                if choice['finish_reason']!='stop':raise ValueError('Incomplete model generation')
                result=dict(prediction=json.loads(choice['message']['content']),llm_used=True,
                    model=dict(provider='h200_vllm_pinned_qwen_synthetic_continuation',model='Qwen2.5-Coder-14B-Instruct',served_model=alias,**identity),
                    generation=dict(elapsed_seconds=time.monotonic()-begin,usage=raw.get('usage')))
                write(cached,result)
            prediction,notes=N.normalize(result['prediction'])
            row['trace'].append(dict(role=role,cache_key=key,response=deepcopy(result),normalizations=notes))
            normalized=deepcopy(result);normalized['prediction']=prediction
            return normalized
        begin=time.monotonic()
        try:
            artifact=V.extract(item['record'],runner=runner)
            row.update(artifact=artifact,draft=artifact['draft'],valid=True)
        except Exception as exc:row['error']=type(exc).__name__+': '+str(exc)
        if row.get('infrastructure_error'):
            write(root/'sft_infrastructure_failures'/phase/path.name,row)
            raise RuntimeError('Repair infrastructure before continuing; no model-error score assigned')
        row['elapsed_seconds']=time.monotonic()-begin;write(path,row);return row
    done=0;rows=[]
    with patch.object(V.OP,'EXPLICIT',G.explicit(V.OP.EXPLICIT)),patch.object(V.OP,'NONREQUIREMENT',G.nonrequirement(V.OP.NONREQUIREMENT)),patch.object(V.OP,'source_polarity',G.polarity(V.OP.source_polarity)):
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for f in as_completed([pool.submit(one,i) for i in inputs]):
                rows.append(f.result());done+=1
                write(root/'status.json',dict(state='sft_evaluation',phase=phase,alias=alias,completed=done,total=len(inputs),elapsed_seconds=time.monotonic()-start))
    return rows


def main(args):
    out=args.output
    if args.action=='validation':
        inputs=json.loads((args.data/'validation_inputs.json').read_text());reports={}
        for alias in args.alias:
            phase='validation_'+alias
            rows=evaluate(args,inputs,alias,phase,out/'sft_validation_predictions'/alias)
            labels={r['id']:r['gold'] for r in json.loads((args.data/'validation_gold.json').read_text())}
            report=E.summarize([dict(i,gold=labels[i['id']]) for i in inputs],rows)
            write(out/('sft_validation_'+alias+'.json'),report)
            reports[alias]=report['scores'][phase+'/D_adapter_pipeline/dev']
        def utility(s):return min(s['f1'] or 0,s['logic_accuracy'],s['grounded_mr_rate'] or 0),s['case_accuracy']
        selected=max(reports,key=lambda a:utility(reports[a]))
        selection=dict(selected=selected,validation_cases=len(inputs),metrics=reports,above_90=reports[selected]['above_90'],
            selection_split='DEV validation worlds only; source worlds disjoint from SFT training.',test_used=False,
            training_manifest=json.loads((args.data/'manifest.json').read_text()),identities=json.loads(args.identity.read_text()))
        write(out/'sft_selection.json',selection)
        write(out/'status.json',dict(state='sft_selected' if selection['above_90'] else 'sft_below_target',selected=selected,metrics=reports[selected]))
    else:
        selection=json.loads((out/'sft_selection.json').read_text())
        if not selection['above_90']:raise ValueError('Select a qualifying checkpoint on DEV before TEST inference')
        alias=selection['selected'];inputs=[r for r in json.loads((out/'inputs.json').read_text()) if r['split']=='test']
        rows=evaluate(args,inputs,alias,'sft_tuned',out/'predictions/sft_tuned/D_adapter_pipeline')
        ids={i['id'] for i in inputs}
        labels={r['id']:r['gold'] for r in json.loads((out/'gold.json').read_text()) if r['id'] in ids}
        report=E.summarize([dict(i,gold=labels[i['id']]) for i in inputs],rows)
        report.update(sft_selection=selection)
        write(out/'sft_test_report.json',report)
        point=report['scores']['sft_tuned/D_adapter_pipeline/test']
        write(out/'status.json',dict(state='sft_test_complete' if point['above_90'] else 'sft_test_below_target',selected=alias,scores=report['scores']))
        if not point['above_90']:
            # Further model selection must use a fresh confirmatory holdout;
            # never silently tune against and re-score this same TEST set.
            raise SystemExit(75)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['validation','test']);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--data',type=Path,required=True);p.add_argument('--identity',type=Path,required=True);p.add_argument('--token',type=Path,required=True)
    p.add_argument('--url',default='http://127.0.0.1:18972');p.add_argument('--alias',action='append',default=[]);p.add_argument('--workers',type=int,default=8)
    main(p.parse_args())
