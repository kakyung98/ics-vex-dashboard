"""Full 12418-CVE audit. Source-only machine Gold; never invent impact labels."""
from collections import Counter
from functools import partial
import hashlib,json,sqlite3,sys,time,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.training_io import atomic_json
from tools.item3_precision_pipeline import sha,digest_json,SourceNVD,connection
BASE=ROOT/'benchmark/cve_population_12418_v1'
GOLD=ROOT/'benchmark/cve_population_precision_v1'
OUT=ROOT/'results/cve_population_precision_v1'

def read(p):return json.loads(p.read_text(encoding='utf-8'))

def build():
    if GOLD.exists():raise FileExistsError(GOLD)
    GOLD.mkdir(parents=True);OUT.mkdir(parents=True,exist_ok=True)
    db=connection()
    chosen=dict(db.execute('SELECT cve,min(condition_id) FROM source_coverage GROUP BY cve'))
    needed=set(chosen.values());controls={};labels={}
    for cond,identity,text in db.execute("SELECT condition_id,id,sbom FROM cases WHERE scenario='control' ORDER BY id"):
        if cond in needed:controls.setdefault(cond,dict(source_input_id=identity,sbom=json.loads(text)))
    for fold in ('train','evaluation'):
        for line in (ROOT/'benchmark/item3_gold_v11'/fold/'labels.jsonl').open(encoding='utf-8'):
            r=json.loads(line)
            if r['scenario']=='control' and r['condition_id'] in needed:
                labels.setdefault(r['condition_id'],r)
    target_ids={json.loads(s)['cve'] for s in (BASE/'labels.jsonl').open(encoding='utf-8')}
    missing=target_ids-set(chosen);counts=Counter();sboms={}
    with (GOLD/'inputs.jsonl').open('w',encoding='utf-8') as fi,(GOLD/'labels.jsonl').open('w',encoding='utf-8') as fl:
        for line in (BASE/'inputs.jsonl').open(encoding='utf-8'):
            row=json.loads(line);cid=row['cve'];identity='POP-'+cid
            if cid in chosen:
                cond=chosen[cid];base=labels[cond];sbom=controls[cond]['sbom']
                label=dict(id=identity,cve=cid,expected_cves=base['expected_cves'],
                    unknown_cves=sorted(set(base['unknown_cves'])|missing),
                    own_cve_truth=True if cid in base['expected_cves'] else None if cid in base['unknown_cves'] else False,
                    provenance='Existing audited independent source-CPE oracle; deterministic source condition selection',
                    source_condition_id=cond,origin_fold=base['fold'],source_input_id=controls[cond]['source_input_id'])
            else:
                link=row['advisory_sbom_candidates'][0];path=link['sbom_file']
                if path not in sboms:sboms[path]=read(ROOT/path)
                source=sboms[path];v=next(v for v in source.get('vulnerabilities',[]) if v['id']==cid)
                refs={a['ref'] for a in v.get('affects',[])}
                components=[c for c in source.get('components',[]) if c.get('bom-ref') in refs]
                if not components:components=[dict(type='application',name=row['products'][0]['name'],version='NOASSERTION')]
                component=min(components,key=lambda c:json.dumps(c,sort_keys=True))
                component={k:v for k,v in component.items() if k in {'type','name','version','manufacturer','supplier','cpe','purl'}}
                sbom=dict(bomFormat='CycloneDX',specVersion='1.5',version=1,components=[component])
                label=dict(id=identity,cve=cid,expected_cves=[],unknown_cves=sorted(target_ids),own_cve_truth=None,
                    provenance='Advisory/SBOM candidate; independent exact CPE truth unavailable',origin_fold='unlabelled')
            inp=dict(id=identity,cve=cid,sbom=sbom)
            fi.write(json.dumps(inp,ensure_ascii=False)+'\n');fl.write(json.dumps(label,ensure_ascii=False)+'\n')
            counts['cases']+=1;counts['own_truth_known' if label['own_cve_truth'] is not None else 'own_truth_unknown']+=1
            counts['origin:'+label['origin_fold']]+=1
    db.close();assert counts['cases']==12418
    atomic_json(GOLD/'manifest.json',dict(population=12418,**dict(counts),
        selection='One minimum source condition ID per CVE; first explicit SBOM/product candidate if no CPE source',
        selection_uses_predictions=False,synthetic_inventory=True,real_CVE_identifiers=True,
        evaluation_type='Whole-population audit including training-origin cases; NOT independent held-out generalization',
        base_manifest_sha256=sha(BASE/'manifest.json'),
        artifacts={p.name:sha(p) for p in GOLD.glob('*.jsonl')}))
    # #4: run the existing gate for all real CVEs with genuinely missing asset context.
    from src.operational_assessment import assess
    with (OUT/'item4_readiness_predictions.jsonl').open('w',encoding='utf-8') as f:
        for line in (BASE/'inputs.jsonl').open(encoding='utf-8'):
            r=json.loads(line);packet=dict(binding={'cve':r['cve']},scenarios=r['item4_scenario_drafts'],observations=[])
            decision=assess(packet)
            assert decision['status']=='under_investigation'
            f.write(json.dumps(dict(cve=r['cve'],record_type='source_readiness_not_asset_assessment',
                status=decision['status'],actual_affected=None,missing_evidence=decision['missing_evidence']))+'\n')
    atomic_json(OUT/'item4_precision_report.json',dict(population=12418,source_records_examined=12418,
        independent_impact_gold_cases=0,precision=None,TP=None,FP=None,target_met=None,
        status='not_verifiable_missing_context_and_impact_gold',
        readiness_under_investigation=12418,readiness_is_not_precision_evaluation=True))
    print('Frozen full-population inputs built',dict(counts),flush=True)

def evaluate():
    from src import gpu_lease
    from src.precision_role_runtime import PrecisionRoleRuntime
    from src.identification_batch_flow import PacketCache,resolve_window
    from src.unified_identification import run_unified
    from src.identity_retrieval import get_index
    from tools.item3_v6_metrics import case_score,aggregate
    import os
    OUT.mkdir(parents=True,exist_ok=True)
    manifest=read(GOLD/'manifest.json')
    for name,h in manifest['artifacts'].items():assert sha(GOLD/name)==h
    old=ROOT/'results/item3_precision_v11/trained_evaluation'
    sig=read(old/'run_config.json');release=read(ROOT/'results/precision_evaluation_v1/release.json')
    api=release['integration_only_change_after_frozen_inference']
    for p,h in sig['code'].items():assert sha(ROOT/p)==(api['after_sha256'] if (ROOT/p).resolve()==(ROOT/api['file']).resolve() else h),p
    config=dict(gold_sha256=sha(GOLD/'manifest.json'),adapter=sig['adapter'],cache_signature=digest_json(sig),
        classifier_code=sig['code'],API_integration_sha256=api['after_sha256'],driver_sha256=sha(Path(__file__)),gold_passed_to_inference=False)
    if (OUT/'run_config.json').exists():assert read(OUT/'run_config.json')==config
    atomic_json(OUT/'run_config.json',config)
    path=OUT/'packet_cache.sqlite3'
    if not path.exists():
        original=sqlite3.connect(old/'packet_cache.sqlite3');copy=sqlite3.connect(path);original.backup(copy);copy.close();original.close()
    cache=PacketCache(path,digest_json(sig));initial=cache.statistics()
    db=sqlite3.connect(OUT/'item3_predictions.sqlite3')
    db.execute('CREATE TABLE IF NOT EXISTS predictions(id TEXT PRIMARY KEY,cve TEXT,result TEXT,score TEXT)')
    done={r[0] for r in db.execute('SELECT id FROM predictions')}
    inputs=[json.loads(s) for s in (GOLD/'inputs.jsonl').open(encoding='utf-8')]
    labels={r['id']:r for r in map(json.loads,(GOLD/'labels.jsonl').open(encoding='utf-8'))}
    todo=[r for r in inputs if r['id'] not in done]
    source=connection();nvd=SourceNVD(source);universe=set(nvd.records)|{r['cve'] for r in inputs};index=get_index();runtime=PrecisionRoleRuntime()
    assert sha(runtime.folder/'adapter_model.safetensors')==sig['adapter']
    gpu_lease.assert_inference_available();atomic_json(gpu_lease.FILE,dict(active=True,pid=os.getpid(),stage='full_CVE_population_validation'))
    started=time.perf_counter()
    def infer(task,packets,**kwargs):return runtime.identification_batch(task,packets,batch_size=4,compact_wire=True)
    try:
        for start in range(0,len(todo),64):
            chunk=todo[start:start+64]
            results=resolve_window({r['id']:r['sbom'] for r in chunk},cache,infer,index=index,nvd=nvd,batch_size=16,
                core=partial(run_unified,mapping_scope='identification'))
            with db:
                for r in chunk:
                    result,trace=results[r['id']];score=case_score(result,labels[r['id']],universe)
                    db.execute('INSERT INTO predictions VALUES (?,?,?,?)',(r['id'],r['cve'],json.dumps(dict(result=result,trace=trace)),json.dumps(score)))
                    done.add(r['id'])
            atomic_json(OUT/'status.json',dict(phase='evaluating',completed=len(done),total=12418,elapsed_seconds=time.perf_counter()-started))
            print('Full-population model audit',len(done),'/12418',flush=True)
        report=aggregate(((labels[i]['origin_fold'],'population_audit',json.loads(s)) for i,s in db.execute('SELECT id,score FROM predictions')),12418)
        m=report['all_BOMs_latent_asset_mapping_metrics']
        report.update(population=12418,evaluation_type=manifest['evaluation_type'],own_truth_known=manifest['own_truth_known'],
            own_truth_unknown=manifest['own_truth_unknown'],gold_coverage=manifest['own_truth_known']/12418,
            precision=m['precision_percent']/100 if m['precision_percent'] is not None else None,
            precision_on_judged=m['precision_on_adjudicated_percent']/100 if m['precision_on_adjudicated_percent'] is not None else None,
            precision_lower_bound=m['precision_lower_bound_percent']/100 if m['precision_lower_bound_percent'] is not None else None,
            target_met=None if manifest['own_truth_unknown'] else m['precision_percent'] is not None and m['precision_percent']>80,
            full_population_precision_certified=False if manifest['own_truth_unknown'] else True,
            cache_statistics_before=initial,cache_statistics_after=cache.statistics(),model=sig['mode'],
            limitation='Unlabelled CVEs retained; source-derived simulated inventory, training-origin cases included; not field accuracy')
        atomic_json(OUT/'item3_precision_report.json',report)
        atomic_json(OUT/'status.json',dict(phase='complete',completed=len(done),total=12418))
        print(json.dumps(report),flush=True)
    finally:
        atomic_json(gpu_lease.FILE,dict(active=False,pid=os.getpid()));db.close();cache.close();source.close()

if __name__=='__main__':
    if sys.argv[1]=='build':build()
    elif sys.argv[1]=='evaluate':evaluate()
