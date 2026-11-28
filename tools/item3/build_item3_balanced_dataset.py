"""Generate three actual, matched noise axes per CPE-supported source document."""
from collections import Counter,defaultdict
from pathlib import Path
import argparse
import json
import sys

ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))
from tools.item3.build_item3_advisory_dataset import (
    blind_document,source_gold,partition,perturb,usable,properties,digest,compact,sha,write)

SCHEMA='item3-advisory-balanced/2'
AXES=(('I1','component_noise'),('I2','version_noise'),('I3','CPE_noise'))


def semantic(document):
    return digest(sorted([{k:v for k,v in c.items() if k!='bom-ref'} for c in document['components']],key=compact))


def build(source,output,cve_source,published_source=None):
    source,output,cve_source=Path(source).resolve(),Path(output).resolve(),Path(cve_source).resolve()
    if output.exists():
        raise FileExistsError(output)
    cv={r['id']:r for r in (json.loads(s) for s in cve_source.read_text(encoding='utf-8').splitlines())}
    universe=set(cv);rejected={c for c,r in cv.items() if r.get('vulnStatus')=='Rejected'}
    records=[];names=set();all_cves=set()
    for path in sorted(source.glob('*.json')):
        original=json.loads(path.read_bytes())
        blind=blind_document(original,digest(['source',path.stem])[:24])
        gold=source_gold(original,universe,rejected)
        originals={c['bom-ref']:c for c in original['components']}
        candidates=[c for c in blind['components']
                    if properties(originals[c['bom-ref']]).get('dataset:component-origin')=='NVD-CPE-condition'
                    and all(usable(c.get(f)) for f in ('name','version','cpe')) and c['cpe'].startswith('cpe:2.3:')]
        def preference(c):
            value=c['version']
            kind=0 if value[0].isdigit() else 1 if value.startswith(('<','>')) else 2
            return kind,digest([path.stem,c['bom-ref']])
        selected=min(candidates,key=preference)['bom-ref'] if candidates else None
        records.append(dict(source_id=path.stem,source_file=path.name,source_sha256=sha(path),
            blind=blind,gold=gold,selected_ref=selected,semantic_sha256=semantic(blind),variants=[],
            requires_cpe_test=False))
        names.update(c.get('name','').casefold() for c in original['components'])
        all_cves.update(v['id'] for v in original.get('vulnerabilities',[]))
    for record in records:
        if record['selected_ref']:
            for axis,noise_scenario in AXES:
              for scenario in (noise_scenario.replace('_noise','_mask'),noise_scenario):
                variant,change=perturb(record['blind'],scenario,record['source_id'],names,
                    allowed_refs={record['selected_ref']})
                if not change['applied']:
                    raise ValueError('Balanced axis cannot be a no-op')
                record['variants'].append(dict(axis=axis,scenario=scenario,change=change,semantic_sha256=semantic(variant)))
        hashes=[v['semantic_sha256'] for v in record['variants']]
        record['variant_semantic_sha256']=hashes[0] if hashes else record['semantic_sha256']
        record['additional_semantic_sha256']=hashes[1:]
    folds,split=partition(records)
    eligible_by_fold={f:sorted([r for r in records if r['selected_ref'] and folds[r['source_id']]==f],
                              key=lambda r:digest(['mask-style',r['source_id']])) for f in ('train','test')}
    mask_quota={f:len(rs)//2 for f,rs in eligible_by_fold.items()}
    remaining=sum(map(len,eligible_by_fold.values()))//2-sum(mask_quota.values())
    for f in sorted(eligible_by_fold,key=lambda f:digest(['mask-remainder',f])):
        if remaining and len(eligible_by_fold[f])%2:
            mask_quota[f]+=1;remaining-=1
    masked={r['source_id'] for f,rs in eligible_by_fold.items() for r in rs[:mask_quota[f]]}
    for record in records:
        record['partition_candidate_semantic_sha256']=[v['semantic_sha256'] for v in record['variants']]
        style='_mask' if record['source_id'] in masked else '_noise'
        record['variants']=[v for v in record['variants'] if v['scenario'].endswith(style)]
        hashes=[v['semantic_sha256'] for v in record['variants']]
        record['variant_semantic_sha256']=hashes[0] if hashes else record['semantic_sha256']
        record['additional_semantic_sha256']=hashes[1:]
    output.mkdir(parents=True)
    write(output/'universe.json',dict(scored_cves=sorted(universe),source_population_cves=len(all_cves),
        out_of_scope_cves=sorted(all_cves-universe),cve_source_sha256=sha(cve_source)))
    write(output/'CVE_split.json',split['cves']);write(output/'split_manifest.json',{k:v for k,v in split.items() if k!='cves'})
    counts=Counter();by_fold=defaultdict(Counter);scenario_counts=defaultdict(Counter);ledger=[];handles={}
    for fold in ('train','test'):
        (output/fold/'sboms').mkdir(parents=True);(output/fold/'annotations').mkdir()
        handles[fold]=(output/fold/'gold.jsonl').open('x',encoding='utf-8')
    try:
        for record in records:
            fold=folds[record['source_id']];base='advisory-'+digest(record['source_id'])[:24]
            control_id=base+'-control'
            variants=[dict(axis='control',scenario='control',change=None)]+record['variants']
            ledger.append(dict(source_id=record['source_id'],source_file=record['source_file'],source_sha256=record['source_sha256'],
                semantic_sha256=record['semantic_sha256'],variant_semantic_sha256=record['variant_semantic_sha256'],
                additional_semantic_sha256=record['additional_semantic_sha256'],fold=fold,
                partition_candidate_semantic_sha256=record['partition_candidate_semantic_sha256'],
                noise_eligible=bool(record['selected_ref']),selected_component_ref=record['selected_ref'],
                baseline_only_reason=None if record['selected_ref'] else 'no_common_source_CPE_name_version_fields'))
            for specification in variants:
                scenario=specification['scenario'];axis=specification['axis']
                if scenario=='control':
                    document=record['blind'];change=None;identity=control_id
                else:
                    document,change=perturb(record['blind'],scenario,record['source_id'],names,
                        allowed_refs={record['selected_ref']})
                    identity=base+'-'+axis
                    if change!=specification['change']:
                        raise ValueError('Non-deterministic perturbation')
                path=output/fold/'sboms'/(identity+'.json');write(path,document)
                label=dict(schema=SCHEMA,id=identity,fold=fold,sbom_file='sboms/'+path.name,
                    pair_id=base,condition_id=base,source_id=record['source_id'],source_file=record['source_file'],
                    source_sha256=record['source_sha256'],scenario=scenario,axis=axis,control_sbom_id=control_id,
                    noise_applied=change is not None,perturbation=change,gold=record['gold'],
                    export_format=dict(sbom_file_sha256=sha(path)))
                write(output/fold/'annotations'/(identity+'.json'),label)
                handles[fold].write(compact(label)+'\n')
                counts['cases']+=1;by_fold[fold]['cases']+=1
                if change:
                    counts[axis]+=1;by_fold[fold][axis]+=1
                    scenario_counts[fold][scenario]+=1
            for c in (counts,by_fold[fold]):
                c.update(source_sboms=1,components=len(record['blind']['components']),
                    noise_eligible_documents=bool(record['selected_ref']),baseline_only_documents=not bool(record['selected_ref']))
    finally:
        for h in handles.values():h.close()
    for c in [counts,*by_fold.values()]:
        if not c['I1']==c['I2']==c['I3']:
            raise ValueError('Actual noise axes are not balanced')
    with (output/'source_ledger.jsonl').open('x',encoding='utf-8') as stream:
        for row in ledger:stream.write(compact(row)+'\n')
    if any(sha(source/r['source_file'])!=r['source_sha256'] for r in records):
        raise ValueError('Source changed during generation')
    manifest=dict(schema=SCHEMA,source_directory=str(Path(published_source).resolve() if published_source else source),
        source_dataset_id='icsa-advisory-products-sbom-v3',source_documents=len(records),counts=dict(counts),
        by_fold={k:dict(v) for k,v in by_fold.items()},actual_noise_ratio='1:1:1',no_op_noise_cases=0,
        scenarios_by_fold={f:dict(c) for f,c in scenario_counts.items()},
        noise_policy='One control per source, one actual I1/I2/I3 change each per eligible document on a common NVD component. Original masks and notation operators retained, globally half each per axis and within one per split. Group all possible mask/notation fingerprints before assigning style.',
        gold_policy='Separate CSAF and explicit NVD affected-condition source relations; source conflicts remain unknown.',
        source_ledger_sha256=sha(output/'source_ledger.jsonl'),cve_source_sha256=sha(cve_source),
        builder_sha256=sha(Path(__file__)),new_model_training_performed=False,
        artifacts={f'{f}/gold.jsonl':sha(output/f/'gold.jsonl') for f in ('train','test')})
    write(output/'manifest.json',manifest)
    for fold in ('train','test'):
        write(output/fold/'manifest.json',dict(schema=SCHEMA,fold=fold,parent_manifest_sha256=sha(output/'manifest.json'),
            gold_sha256=sha(output/fold/'gold.jsonl'),universe_sha256=sha(output/'universe.json')))
    return manifest


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    published=ROOT/'benchmark/icsa-cpe-synthetic sbom'
    p.add_argument('--source',type=Path,default=published/'sbom' if (published/'manifest.json').is_file() and json.loads((published/'manifest.json').read_bytes()).get('dataset_id')=='icsa-advisory-products-sbom-v3' else ROOT/'benchmark/icsa-cpe-source-v3-staged/sbom')
    p.add_argument('--output',type=Path,default=ROOT/'benchmark/item3_advisory_inputs_v5')
    p.add_argument('--published-source',type=Path,default=ROOT/'benchmark/icsa-cpe-synthetic sbom/sbom')
    p.add_argument('--cve-source',type=Path,default=ROOT/'data/item3_identification_sources_v11/cves.jsonl')
    a=p.parse_args();print(json.dumps(build(a.source,a.output,a.cve_source,a.published_source),ensure_ascii=False,indent=2))
