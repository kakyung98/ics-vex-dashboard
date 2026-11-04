"""Frozen v2 task tests and full item-3 candidate pipeline, with batched GPU calls.

No NVD network calls, retraining, GT-derived candidates, or test-driven tuning.
The local flattened snapshot returns candidate CVEs with unknown applicability.
"""
import argparse
from collections import Counter
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tools'))
import eval_cpe_match_precision as E3
from src.identification_agents import LocalIdentificationAgents
from src.training_io import atomic_json
from src.identification_tasks import valid_output,identity_gold
from evaluation.identification_metrics import score as task_score
from src.candidate_snapshot import SnapshotNVD
from ics_agent_matcher_full.ics_agent_matcher.matcher import extract,make_l4,run,norm


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,obj):
    atomic_json(path,obj)
def key(task,payload,mode):return json.dumps([mode,task,payload],sort_keys=True,ensure_ascii=False)


class FrozenSnapshot(SnapshotNVD):
    def __init__(self,index_path):super().__init__(index_path=index_path);self.memo={}
    def get_all(self,path,params,field):
        k=json.dumps([path,params,field],sort_keys=True)
        if k not in self.memo:self.memo[k]=super().get_all(path,params,field)
        return self.memo[k]


class CachedPipeline:
    SUT_NAME='README L2/L3/L4 frozen v2 + local snapshot (candidate identification; applicability unknown)'
    def __init__(self,outputs):
        self.records={}
        for row in outputs:
            c=row['component'];k=(c['name'],c.get('version') or '',c.get('supplier') or '',tuple(c.get('cpes') or []))
            self.records[k]=row
    def find(self,comp,supplier=None):
        cpes=(comp['cpe'],) if comp.get('cpe') else ()
        return self.records.get((comp['name'],comp.get('version') or '',supplier if supplier is not None else comp.get('supplier') or '',cpes))
    def identify_product(self,comp):
        row=self.find(comp);v=(row or {}).get('validation') or {}
        return (v.get('product'),'agents-v2') if v.get('status')=='validated' else (None,'unresolved')
    def cves_for(self,comp,sbom_vendor='',strict=False):
        row=self.find(comp,sbom_vendor)
        return [{'cve':c['cve_id']} for c in (row or {}).get('cves',[]) if c.get('match_status')!='no_match']


def main():
    p=argparse.ArgumentParser();p.add_argument('--batch',type=int,default=16)
    p.add_argument('--preflight-only',action='store_true')
    p.add_argument('--deadline-utc',default='2026-11-01T12:15:44+00:00')
    a=p.parse_args()
    out=ROOT/'results/item3_identification_v2_run';out.mkdir(parents=True,exist_ok=True)
    started=time.time();deadline=datetime.fromisoformat(a.deadline_utc).timestamp()
    state={'phase':'preflight','pid':__import__('os').getpid(),'deadline_utc':a.deadline_utc,'started_at':datetime.now(timezone.utc).isoformat()}
    def status(phase,**extra):
        state.update(phase=phase,elapsed_seconds=round(time.time()-started,2),updated_at=datetime.now(timezone.utc).isoformat(),**extra);save(out/'status.json',state)
    status('preflight')
    try:
        data=ROOT/'data/identification_agents_v2'
        manifest=json.loads((data/'manifest.json').read_text(encoding='utf-8'))
        for split in ('train','val','test'):assert digest(data/f'{split}.jsonl')==manifest['splits'][split]['sha256']
        weights={t:digest(ROOT/f'models/identification-agents-v2/{t}/adapter_model.safetensors') for t in ('L2','L3','L4')}
        gtfile=ROOT/'data/cpe_match_eval.jsonl'
        old=json.loads((out/'run_config.json').read_text()) if (out/'run_config.json').exists() else None
        index_path=ROOT/'data/cpe_index.json'
        if old and digest(index_path)!=old['fingerprints']['cve_index']:
            # Live corpus refreshes must not alter a resumed evaluation. Recover
            # only a byte-identical original snapshot, never relax hash checks.
            choices=[out/'frozen_cpe_index.json',*sorted((ROOT/'results/corpus_backups').glob('*/cpe_index.json'))]
            original=next((p for p in choices if p.is_file() and digest(p)==old['fingerprints']['cve_index']),None)
            if original is None:raise ValueError('Original evaluation CVE snapshot unavailable')
            index_path=out/'frozen_cpe_index.json'
            if original!=index_path:index_path.write_bytes(original.read_bytes())
        fingerprint={'dataset':digest(data/'test.jsonl'),'gt':digest(gtfile),'adapters':weights,
                     'dictionary':digest(ROOT/'data/cpe_dictionary.jsonl'),'cve_index':digest(index_path)}
        if old and old['fingerprints']!=fingerprint:raise ValueError('Cached run inputs/model changed')
        save(out/'run_config.json',{'fingerprints':fingerprint,'batch_size':a.batch,'deadline_utc':a.deadline_utc,
                                  'frozen_cve_index_path':str(index_path),
                                  'test_used_for_training':False,'pipeline_scope':'full bundled labelled cohort, local candidate lookup, not live-NVD applicability proof'})
        if a.preflight_only:
            _,cases,_,_,_=E3.load_gt(str(gtfile))
            status('ready',item3_cases=len(cases),task_test_examples=3072,models_frozen=True)
            print(json.dumps(state,indent=2));return
        cache={};cachefile=out/'predictions.jsonl'
        if cachefile.exists():
            for l in cachefile.read_text(encoding='utf-8').splitlines():
                r=json.loads(l);cache[r['key']]=r['output']
        agents=LocalIdentificationAgents(adapters=ROOT/'models/identification-agents-v2')
        def infer(task,payloads,mode,phase):
            missing={key(task,x,mode):x for x in payloads if key(task,x,mode) not in cache}
            pairs=list(missing.items())
            for offset in range(0,len(pairs),a.batch):
                if time.time()>deadline:raise TimeoutError('Four-hour target reached; partial predictions retained, no full-run claim')
                chunk=pairs[offset:offset+a.batch]
                outputs=agents.batch(task,[v for _,v in chunk],mode=mode,batch_size=a.batch)
                with cachefile.open('a',encoding='utf-8') as f:
                    for (k,_),v in zip(chunk,outputs):cache[k]=v;f.write(json.dumps({'key':k,'output':v},ensure_ascii=False)+'\n')
                status(phase,task=task,mode=mode,done=min(offset+a.batch,len(pairs)),total=len(pairs),cached_predictions=len(cache))
            return [dict(cache[key(task,x,mode)]) for x in payloads]
        rows=[json.loads(l) for l in (data/'test.jsonl').read_text(encoding='utf-8').splitlines()]
        task_report={'scope':'held-out procedural task test, not real SBOM precision','evaluation_split':'test','fingerprints':fingerprint,'tasks':{}}
        for task in ('L2','L3','L4'):
            subset=[r for r in rows if r['task']==task];assert len(subset)==1024
            task_report['tasks'][task]={}
            for mode in ('base','tuned'):
                outputs=infer(task,[r['input'] for r in subset],mode,'agent_test')
                task_report['tasks'][task][mode]=task_score(task,subset,[o['prediction'] for o in outputs])
            save(out/'task_test.json',task_report)
        # Pipeline inputs come from _sut_input only. Gold products/CVEs are
        # withheld from the agents and read only by the final common scorer.
        _,cases,_,_,_=E3.load_gt(str(gtfile))
        components=[]
        for i,c in enumerate(cases):
            item={'bom-ref':f'item3-{i:05d}','name':c['name'],'version':c['version'] or '', 'supplier':c.get('publisher') or ''}
            if c.get('cpe'):item['cpe']=c['cpe']
            components.append(item)
        sbom={'bomFormat':'CycloneDX','components':components};internal=extract(sbom)
        l2payload=[{'name':c['name'],'supplier':c['supplier']} for c in internal]
        l3payload=[{'raw_version':c['version']} for c in internal]
        infer('L2',l2payload,'tuned','item3_L2')
        infer('L3',l3payload,'tuned','item3_L3')
        l4payload={};nvd=FrozenSnapshot(index_path);empty_guard=0
        def collect(task,payload):
            nonlocal empty_guard
            assert task=='L4'
            k=key(task,payload,'tuned')
            if not payload['candidates']:
                empty_guard+=1
                cache[k]={'prediction':identity_gold(payload),'raw':'','mode':'empty_dictionary_impossibility_guard','task':'L4'}
            else:l4payload[k]=payload
            return {'prediction':identity_gold(payload),'mode':'payload_collection_not_model_evaluation','raw':''}
        collector=make_l4(nvd,collect)
        for i,(c,payload) in enumerate(zip(internal,l2payload)):
            pred=cache[key('L2',payload,'tuned')]['prediction']
            name=norm(pred['normalized']) if valid_output('L2',pred) and pred['status']=='resolved' else None
            if name:collector({'component':c,'l2':{'normalized':name}})
            if i%200==0:status('item3_prepare_L4',done=i,total=len(cases))
        infer('L4',list(l4payload.values()),'tuned','item3_L4')
        def provider(task,payload):return dict(cache[key(task,payload,'tuned')])
        def progress(done,total,stage,name):
            if stage=='component_complete' and done%100==0:status('item3_pipeline',done=done,total=total)
        result=run(sbom,nvd,agents=provider,progress=progress)
        save(out/'pipeline_outputs.json',result)
        adapter=CachedPipeline(result['components'])
        scored=E3.score(str(gtfile),matcher='agents-v2',matcher_module=adapter,
                        progress=lambda d,t,n:status('item3_scoring',done=d,total=t))
        scored.update(ground_truth_sha256=fingerprint['gt'],complete=True,
                      candidate_applicability='unknown: flattened local snapshot does not preserve full platform AND/OR constraints',
                      empty_dictionary_model_short_circuits=empty_guard,
                      shortcut_reason='Without dictionary candidates no model prediction can pass identity validation; not counted as raw L4 model evaluation.',
                      pipeline_errors=sum('error' in r for r in result['components']),
                      version_unconfirmed_components=sum((r.get('validation') or {}).get('version_status')=='unknown' for r in result['components']),
                      unknown_candidate_records=sum(c.get('match_status')=='unknown' for r in result['components'] for c in r.get('cves',[])))
        save(out/'item3_agents_v2_full.json',scored)
        assert weights=={t:digest(ROOT/f'models/identification-agents-v2/{t}/adapter_model.safetensors') for t in ('L2','L3','L4')},'Adapter weights changed during evaluation'
        summary={'complete':True,'task_test':{t:{m:{k:v for k,v in d.items() if k!='cases'} for m,d in variants.items()} for t,variants in task_report['tasks'].items()},
                 'item3':scored,'elapsed_seconds':time.time()-started,'fingerprints':fingerprint,'models_retrained_or_selected_on_test':False}
        save(out/'summary.json',summary)
        lines=['# L2/L3/L4 frozen v2 evaluation','','Task tests are procedural holdouts, not the item-3 metric.','','| Agent | Base exact | Tuned exact | Tuned decision precision | Coverage |','| --- | ---: | ---: | ---: | ---: |']
        for t,vs in summary['task_test'].items():lines.append(f"| {t} | {vs['base']['exact_accuracy']:.4f} | {vs['tuned']['exact_accuracy']:.4f} | {vs['tuned']['decision_precision']} | {vs['tuned']['coverage']:.4f} |")
        lines+=['','## Full item-3 cohort',f"Components: {scored['sut_runs']}; TP: {scored['TP']}; FP: {scored['FP']}; precision: {scored['precision']}; abstained: {scored['sut_abstained']}.",f"Labelled share: {scored['labelled_share_pct']}%; unlabelled: {scored['unlabelled_predictions']}; unadjudicable: {scored['unadjudicable_predictions']}.",'','Local results are candidate identifications, not proven version applicability or VEX. Empty-dictionary fast paths are disclosed. No test-driven retraining occurred.']
        (out/'REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
        status('complete',components=scored['sut_runs'],precision=scored['precision'])
    except BaseException as exc:
        status('failed',error_type=type(exc).__name__,error=str(exc));raise


if __name__=='__main__':main()
