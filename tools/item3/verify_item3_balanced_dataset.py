"""Audit actual 1:1:1 transformations, source gold, population and split isolation."""
from collections import Counter,defaultdict
from pathlib import Path
import argparse
import json
import sys

ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from tools.item3.advisory_test_scoring import checked_dataset
from tools.item3.build_item3_advisory_dataset import properties,sha,write
from tools.item3.build_item3_balanced_dataset import semantic
from tools.item3.verify_item3_advisory_dataset import differences


def verify(dataset,source_override=None):
    dataset=Path(dataset).resolve();manifest=json.loads((dataset/'manifest.json').read_bytes())
    source=Path(source_override).resolve() if source_override else Path(manifest['source_directory'])
    index={r['file'].split('/')[-1]:r['sha256'] for r in json.loads((source.parent/'index.json').read_bytes())['advisories']}
    ledger=[json.loads(s) for s in (dataset/'source_ledger.jsonl').read_text(encoding='utf-8').splitlines()]
    if sha(dataset/'source_ledger.jsonl')!=manifest['source_ledger_sha256']:
        raise ValueError('Ledger hash differs')
    if {r['source_file'] for r in ledger}!=set(index):raise ValueError('Source population differs')
    universe=set(json.loads((dataset/'universe.json').read_bytes())['scored_cves'])
    cve_records=[json.loads(s) for s in (ROOT/'data/item3_identification_sources_v11/cves.jsonl').read_text(encoding='utf-8').splitlines()]
    if sha(ROOT/'data/item3_identification_sources_v11/cves.jsonl')!=manifest['cve_source_sha256']:
        raise ValueError('CVE source changed')
    rejected={r['id'] for r in cve_records if r.get('vulnStatus')=='Rejected'}
    counts=Counter();ratios={f:Counter() for f in ('train','test')};scope={f:set() for f in ratios};fingerprints={f:set() for f in ratios}
    grouped={}
    for fold in ('train','test'):
        labels,groups,_,_=checked_dataset(dataset/fold)
        for members in groups.values():
            grouped[members[0]['source_id']]=members
    if len(grouped)!=len(ledger):raise ValueError('Source missing or duplicated across splits')
    for entry in ledger:
        original_path=source/entry['source_file']
        if sha(original_path)!=entry['source_sha256'] or sha(original_path)!=index[entry['source_file']]:
            raise ValueError('Source bytes differ')
        original=json.loads(original_path.read_bytes());members=grouped[entry['source_id']]
        control=next(r for r in members if r['scenario']=='control');variants=[r for r in members if r['scenario']!='control']
        fold=entry['fold']
        if any(r['fold']!=fold for r in members):raise ValueError('Parent group crosses splits')
        if len(variants)!=(3 if entry['noise_eligible'] else 0):raise ValueError('Noise population differs')
        a=json.loads((dataset/fold/control['sbom_file']).read_bytes())
        if len(a['components'])!=len(original['components']):raise ValueError('Component dropped')
        fingerprints[fold].add(semantic(a))
        if semantic(a)!=entry['semantic_sha256']:raise ValueError('Control fingerprint differs')
        for label in members:
            document=json.loads((dataset/fold/label['sbom_file']).read_bytes())
            import re
            if 'vulnerabilities' in document or re.search(r'(?i)CVE-\d{4}-\d+',json.dumps(document)):
                raise ValueError('Answer leakage')
        expected={c['bom-ref']:set() for c in original['components']};negative={k:set() for k in expected}
        for v in original.get('vulnerabilities',[]):
            cid=v['id']
            if cid not in universe:continue
            scope[fold].add(cid);p=properties(v)
            if cid in rejected or p.get('dataset:product-link-status')=='source-conflict-review':continue
            nvd_refs=set(json.loads(p.get('dataset:nvd-cpe-component-refs','[]')))
            for edge in v.get('affects',[]):
                if p.get('dataset:product-link-status')=='source-explicit' or edge['ref'] in nvd_refs:
                    expected[edge['ref']].add(cid)
            not_affected=set(json.loads(p.get('dataset:source-product-status','{}')).get('known_not_affected',[]))
            for c in original['components']:
                if properties(c).get('dataset:source-product-id') in not_affected:negative[c['bom-ref']].add(cid)
        for truth in control['gold']['components']:
            ref=truth['component_ref']
            if set(truth['expected_cves'])!=expected[ref]-negative[ref] or set(truth['negative_cves'])!=negative[ref]-expected[ref]:
                raise ValueError('Gold source relation differs')
        hashes=[]
        for variant in sorted(variants,key=lambda r:r['axis']):
            b=json.loads((dataset/fold/variant['sbom_file']).read_bytes());change=variant['perturbation']
            i=next(i for i,c in enumerate(a['components']) if c['bom-ref']==entry['selected_component_ref'])
            field={'I1':'name','I2':'version','I3':'cpe'}[variant['axis']]
            if not variant['noise_applied'] or change['component_ref']!=entry['selected_component_ref']:
                raise ValueError('No-op or unmatched common component')
            if differences(a,b)!=[('components',i,field)] or a['components'][i][field]!=change['before'] or b['components'][i][field]!=change['after']:
                raise ValueError('Invalid single-field actual change')
            if change['operator']!='mask':
                if field=='version' and not change['after'].endswith(change['before']):raise ValueError('Version changed')
                if field=='cpe' and not change['after'].endswith(change['before'][8:]):raise ValueError('CPE attributes changed')
            h=semantic(b);hashes.append(h);fingerprints[fold].add(h)
            ratios[fold][variant['axis']]+=1
        if hashes and hashes!=[entry['variant_semantic_sha256'],*entry['additional_semantic_sha256']]:
            raise ValueError('Variant fingerprints differ')
        counts.update(source_documents=1,cases=len(members),eligible_documents=bool(variants),baseline_only_documents=not bool(variants))
    if scope['train']&scope['test'] or fingerprints['train']&fingerprints['test']:raise ValueError('Split overlap')
    if scope['train']|scope['test']!=universe:raise ValueError('Target CVE loss')
    for fold,c in ratios.items():
        if not c['I1']==c['I2']==c['I3'] or not c['I3']:raise ValueError('Actual axis ratio or CPE coverage missing: '+fold)
    result=dict(passed=True,**dict(counts),actual_noise_by_fold={f:dict(c) for f,c in ratios.items()},
        actual_noise_ratio='1:1:1',no_op_noise_cases=0,target_cve_overlap=0,derived_input_overlap=0,
        manifest_sha256=sha(dataset/'manifest.json'),source_hashes_verified=True,source_gold_recounted=True,
        scope='Source and transform reproducibility; independent semantic accuracy not established')
    write(dataset/'verification.json',result);return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dataset',type=Path,default=ROOT/'benchmark/item3_advisory_inputs_v5')
    p.add_argument('--source-override',type=Path)
    a=p.parse_args();print(json.dumps(verify(a.dataset,a.source_override),ensure_ascii=False,indent=2))
