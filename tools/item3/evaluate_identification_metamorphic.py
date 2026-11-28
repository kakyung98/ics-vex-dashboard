"""#3 robustness only: source-derived inventories, no synthetic GT accuracy.

Use the production I1/I2/I3 finite-token-choice runtime and CVE matching core.
"""
from pathlib import Path
from copy import deepcopy
from collections import Counter
import argparse,hashlib,json,random,sys,time
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))


def write(p,x):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);t=p.with_suffix('.tmp');t.write_text(json.dumps(x,ensure_ascii=False,indent=2));t.replace(p)


def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True).encode()).hexdigest()


def prepare(out,seed=20261127,exclude=None):
    from src.common.data.sbom_input_normalization import to_analysis_input
    from src.item3.evidence.product_identity_evidence import parse_components
    paths=sorted((ROOT/'benchmark/item3_evaluation/sboms').glob('*.json'));random.Random(seed).shuffle(paths)
    excluded_sources=set();excluded_groups=set()
    if exclude:
        for old in json.loads(Path(exclude).read_text()):
            excluded_sources.add(old['source'])
            for c in parse_components(to_analysis_input(old['sbom'])):
                cpes=[v.split(':')[2:5] for v in c.get('cpes',[]) if v.startswith('cpe:2.3:')]
                excluded_groups.add(json.dumps(cpes or [c.get('manufacturer'),c.get('name')],sort_keys=True))
    selected=[];seen=set();strata=Counter()
    for path in paths:
        if path.relative_to(ROOT).as_posix() in excluded_sources or str(path.relative_to(ROOT)) in excluded_sources:continue
        raw=json.loads(path.read_text(encoding='utf-8'));normalized=to_analysis_input(raw)
        comp=parse_components(normalized)
        if len(comp)!=1:continue
        c=comp[0];cpes=[v.split(':')[2:5] for v in c.get('cpes',[]) if v.startswith('cpe:2.3:')]
        group=json.dumps(cpes or [c.get('manufacturer'),c.get('name')],sort_keys=True)
        if group in seen or group in excluded_groups:continue
        stratum=str((bool(c.get('cpes')),str(c.get('version','')).casefold() not in ('','noassertion','unknown')))
        if strata[stratum]>=32:continue
        seen.add(group);strata[stratum]+=1
        # One component envelope retains source evidence but excludes embedded
        # vulnerability answers. No annotation or gold file is read.
        sbom={k:deepcopy(raw[k]) for k in ('bomFormat','specVersion','version','metadata','properties','components') if k in raw}
        selected.append(dict(id='w'+str(len(selected)),source=str(path.relative_to(ROOT)),source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),stratum=stratum,sbom=sbom))
        if len(selected)==96:break
    if len(selected)<64:raise ValueError('Not enough distinct source product groups')
    rows=[]
    for i,base in enumerate(selected):
        split='dev' if i%3==0 else 'test';original=base['sbom'];variants={'original':deepcopy(original)}
        order=deepcopy(original);order['components']=[dict(reversed(list(c.items()))) for c in order['components']];variants['field_order']=dict(reversed(list(order.items())))
        irrelevant=deepcopy(original)
        for c in irrelevant['components']:c['description']=str(c.get('description',''))+' Inventory reviewed on Tuesday; this sentence supplies no identity or release.'
        variants['irrelevant_text']=irrelevant
        casing=deepcopy(original)
        for c in casing['components']:
            if isinstance(c.get('name'),str):c['name']=c['name'].upper()
        variants['display_case']=casing
        version=deepcopy(original)
        for c in version['components']:
            v=c.get('version')
            if isinstance(v,str) and v[:1].isdigit():c['version']='v'+v
            elif isinstance(v,str) and len(v)>1 and v[0] in 'vV' and v[1].isdigit():c['version']=v[1:]
        variants['version_notation']=version
        for kind,sbom in variants.items():
            rows.append(dict(id=base['id']+'__'+kind,base_id=base['id'],split=split,variant=kind,sbom=sbom,source=base['source'],source_sha256=base['source_sha256'],stratum=base['stratum']))
    write(out/'inputs.json',rows);write(out/'dataset_manifest.json',dict(source_worlds=len(selected),cases=len(rows),strata=dict(strata),input_sha256=digest(rows),gold_loaded=False,
        objective='Metamorphic robustness only, not CVE accuracy.',selection='seed '+str(seed)+', distinct source product groups, fixed before model predictions',
        excluded_prior_inputs=str(exclude) if exclude else None,excluded_source_count=len(excluded_sources),split='Every third source group DEV; others TEST; all variants grouped.'))
    print(json.dumps(dict(worlds=len(selected),cases=len(rows))))


def signature(result):
    rows=[]
    for c in result.get('components',[]):
        v=c.get('validation',{});version=c.get('i2',{})
        rows.append(dict(identity=[v.get(k) for k in ('status','part','vendor','product')],version=version.get('normalized'),range=version.get('declared_range'),
            cves=sorted((r['cve_id'],r['match_status']) for r in c.get('cves',[])),lookup_error=c.get('i3',{}).get('lookup_error')))
    return rows


def prepare_version_stress(out,exclusions):
    """A frozen supplemental cohort fills the sparse version-notation stratum."""
    from src.common.data.sbom_input_normalization import to_analysis_input
    from src.item3.evidence.product_identity_evidence import parse_components
    def group(sbom):
        c=parse_components(to_analysis_input(sbom))[0]
        cpes=[v.split(':')[2:5] for v in c.get('cpes',[]) if v.startswith('cpe:2.3:')]
        return json.dumps(cpes or [c.get('manufacturer'),c.get('name')],sort_keys=True)
    blocked=set();sources=set()
    for path in exclusions:
        for r in json.loads(Path(path).read_text()):blocked.add(group(r['sbom']));sources.add(r['source'])
    paths=sorted((ROOT/'benchmark/item3_evaluation/sboms').glob('*.json'));random.Random(20261129).shuffle(paths)
    rows=[];worlds=0
    for p in paths:
        if str(p.relative_to(ROOT)) in sources or p.relative_to(ROOT).as_posix() in sources:continue
        raw=json.loads(p.read_text(encoding='utf-8'));components=raw.get('components',[])
        if len(components)!=1:continue
        v=components[0].get('version')
        if not isinstance(v,str) or not (v[:1].isdigit() or len(v)>1 and v[0] in 'vV' and v[1].isdigit()):continue
        sbom={k:deepcopy(raw[k]) for k in ('bomFormat','specVersion','version','metadata','properties','components') if k in raw}
        key=group(sbom)
        if key in blocked:continue
        blocked.add(key);base='vs'+str(worlds);changed=deepcopy(sbom);changed['components'][0]['version']=v[1:] if v[0] in 'vV' else 'v'+v
        for kind,value in [('original',sbom),('version_notation',changed)]:
            rows.append(dict(id=base+'__'+kind,base_id=base,split='test',variant=kind,sbom=value,source=str(p.relative_to(ROOT)),source_sha256=hashlib.sha256(p.read_bytes()).hexdigest()))
        worlds+=1
        if worlds==64:break
    if worlds!=64:raise ValueError('Insufficient disjoint explicit-version products')
    write(out/'inputs.json',rows);write(out/'dataset_manifest.json',dict(source_worlds=64,cases=128,gold_loaded=False,seed=20261129,excluded_prior_source_files=len(sources),
        evaluation='Supplemental frozen version-notation MRT, selected by input coverage only, no output-based filtering.',input_sha256=digest(rows)))
    print(json.dumps(dict(worlds=worlds,cases=len(rows))))


def report(inputs,predictions):
    byid={r['id']:r for r in predictions};counts=Counter();groups={};examples=[]
    for c in inputs:
        if c['variant']=='original':continue
        base=next(x for x in inputs if x['id']==c['base_id']+'__original')
        if json.dumps(c['sbom'])==json.dumps(base['sbom']):counts['noops']+=1;continue
        a=byid.get(base['id'],{});b=byid.get(c['id'],{});x=a.get('signature',[]);y=b.get('signature',[])
        valid=not a.get('error') and not b.get('error') and not a.get('agent_failures') and not b.get('agent_failures') and bool(x) and bool(y) and not any(r.get('lookup_error') for r in x+y)
        metrics=dict(identity_preserved=valid and [r['identity'] for r in x]==[r['identity'] for r in y],version_preserved=valid and [(r['version'],r['range']) for r in x]==[(r['version'],r['range']) for r in y],cves_preserved=valid and [r['cves'] for r in x]==[r['cves'] for r in y])
        metrics['all_preserved']=all(metrics.values());counts['pairs']+=1
        for k,v in metrics.items():counts[k]+=v
        group=groups.setdefault(c['variant'],Counter());group.update(total=1,passed=metrics['all_preserved'])
        if not metrics['all_preserved']:examples.append(dict(id=c['id'],relation=metrics,original=x,variant=y,error=b.get('error')))
    ratios={k:counts[k]/counts['pairs'] if counts['pairs'] else None for k in ('identity_preserved','version_preserved','cves_preserved','all_preserved')}
    return dict(cases=len(inputs),source_worlds=len({r['base_id'] for r in inputs}),counts=dict(counts),metrics=ratios,relations={k:dict(v) for k,v in groups.items()},
        above_90=all(x is not None and x>.9 for x in ratios.values()) and all(v['total'] and v['passed']/v['total']>.9 for v in groups.values()),
        gate='Every aggregate measure AND every transformation type must exceed .90.',failures=examples,model_backed_cases=sum(bool(r.get('model_used')) for r in predictions),
        original_confirmed_cases=sum(any(s=='match' for p in r.get('signature',[]) for _,s in p['cves']) for r in predictions if r['id'].endswith('__original')),
        scope='Source-derived controlled inventories; no gold labels loaded. Consistently wrong outputs can pass invariance; this is not CVE accuracy.')


def evaluate(args):
    import torch
    from src.item3.evidence.product_candidate_search import get_index
    from src.item3.evidence.local_vulnerability_lookup import get_source_lookup
    from src.item3.matching.identification_pipeline import run_unified
    from src.common.runtime.shared_adapter_runtime import PrecisionRoleRuntime
    from src.item3.agents.batched_provider import BatchedIdentificationProvider
    out=args.output;inputs=json.loads((out/'inputs.json').read_text());runtime=PrecisionRoleRuntime(args.model)
    free,total=torch.cuda.mem_get_info();cap=int(18.5*1024**3)
    if free<cap:raise RuntimeError('Insufficient free GPU memory; other services preserved')
    torch.cuda.set_per_process_memory_fraction(cap/total)
    write(out/'status.json',dict(state='loading_indexes'));index=get_index();lookup=get_source_lookup()
    provider=BatchedIdentificationProvider(infer=runtime.identification_batch);allrows={};scores={};start=time.monotonic()
    try:
        for split in (('test',) if args.test_only else ('dev','test')):
            cases=[r for r in inputs if r['split']==split];rows=[]
            for n,c in enumerate(cases,1):
                p=out/'predictions'/(c['id']+'.json')
                if p.exists():row=json.loads(p.read_text())
                else:
                    row=dict(id=c['id'],error=None)
                    try:
                        result=run_unified(c['sbom'],lookup,index=index,agents=provider,mode='agents',mapping_scope='identification')
                        failed=[dict(stage=stage,error=agent.get('error'),status=agent.get('status')) for comp in result.get('components',[]) for stage in ('i1','i2','i3') for agent in [comp.get(stage,{}).get('agent') or {}] if agent.get('executed') and not agent.get('guard_accepted')]
                        row.update(signature=signature(result),model_used=result['llm_used'],result=result,agent_failures=failed)
                    except Exception as exc:row['error']=type(exc).__name__+': '+str(exc)
                    write(p,row)
                rows.append(row);allrows[c['id']]=row
                write(out/'status.json',dict(state='evaluating',split=split,completed=n,total=len(cases),elapsed_seconds=time.monotonic()-start))
            scores[split]=report(cases,rows);write(out/(split+'_report.json'),scores[split])
            if split=='dev' and not scores[split]['above_90']:
                write(out/'status.json',dict(state='needs_tuning',scores=scores));return
        write(out/'report.json',dict(scores=scores,production_modified=False,weight_training_performed=False,model='Qwen2.5-Coder-14B-Instruct',adapter_sha256=hashlib.sha256((args.model/'adapter_model.safetensors').read_bytes()).hexdigest()))
        write(out/'status.json',dict(state='complete',metrics=scores['test']['metrics'],above_90=scores['test']['above_90']))
    finally:provider.close()


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=('prepare','prepare-version','evaluate'));p.add_argument('--output',type=Path,required=True);p.add_argument('--model',type=Path);p.add_argument('--seed',type=int,default=20261127);p.add_argument('--exclude-inputs',type=Path);p.add_argument('--extra-exclude-inputs',type=Path);p.add_argument('--test-only',action='store_true');a=p.parse_args()
    if a.action=='prepare':prepare(a.output,a.seed,a.exclude_inputs)
    elif a.action=='prepare-version':prepare_version_stress(a.output,[a.exclude_inputs,a.extra_exclude_inputs])
    else:
        try:evaluate(a)
        except Exception as exc:write(a.output/'status.json',dict(state='failed',error=type(exc).__name__+': '+str(exc)));raise
