"""Audit all derived files against the selected original corpus, without inference."""
from collections import Counter
from pathlib import Path
import argparse
import hashlib
import json
import re
import sys

ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))
from tools.item3.advisory_test_scoring import checked_dataset


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def props(obj):
    return {p['name']:p['value'] for p in obj.get('properties',[])}


def differences(a,b,path=()):
    if type(a)!=type(b):
        return [path]
    if isinstance(a,dict):
        if set(a)!=set(b):
            return [path]
        return [p for k in a for p in differences(a[k],b[k],path+(k,))]
    if isinstance(a,list):
        if len(a)!=len(b):
            return [path]
        return [p for i,(x,y) in enumerate(zip(a,b)) for p in differences(x,y,path+(i,))]
    return [] if a==b else [path]


def verify(dataset):
    dataset=Path(dataset).resolve()
    manifest=json.loads((dataset/'manifest.json').read_bytes())
    source=Path(manifest['source_directory'])
    ledger=[json.loads(s) for s in (dataset/'source_ledger.jsonl').read_text(encoding='utf-8').splitlines()]
    if sha(dataset/'source_ledger.jsonl')!=manifest['source_ledger_sha256']:
        raise ValueError('Source ledger hash differs')
    if {p.name for p in source.glob('*.json')}!={r['source_file'] for r in ledger}:
        raise ValueError('Original population differs')
    original_index=json.loads((source.parent/'index.json').read_bytes())
    expected={Path(r['file']).name:r['sha256'] for r in original_index['advisories']}
    universe=set(json.loads((dataset/'universe.json').read_bytes())['scored_cves'])
    cve_records=[json.loads(s) for s in (ROOT/'data/item3_identification_sources_v11/cves.jsonl').read_text(encoding='utf-8').splitlines()]
    if sha(ROOT/'data/item3_identification_sources_v11/cves.jsonl')!=manifest['cve_source_sha256']:
        raise ValueError('CPE CVE scope changed')
    rejected={r['id'] for r in cve_records if r.get('vulnStatus')=='Rejected'}
    labels={};counts=Counter();scope={'train':set(),'test':set()};semantics={'train':set(),'test':set()};coverage=[]
    for fold in ('train','test'):
        loaded,pairs,_,actual=checked_dataset(dataset/fold)
        if actual!=fold:
            raise ValueError('Wrong split')
        labels.update(loaded)
        counts[fold+'_pairs']=len(pairs)
    for item in ledger:
        path=source/item['source_file']
        if sha(path)!=item['source_sha256'] or sha(path)!=expected[path.name]:
            raise ValueError('Original source/index bytes differ: '+path.name)
        original=json.loads(path.read_bytes())
        members=[r for r in labels.values() if r['source_id']==item['source_id']]
        if len(members)!=2 or any(r['fold']!=item['fold'] for r in members):
            raise ValueError('Source not preserved as exactly one pair')
        control=next(r for r in members if r['scenario']=='control')
        variant=next(r for r in members if r['scenario']!='control')
        a=json.loads((dataset/item['fold']/control['sbom_file']).read_bytes())
        b=json.loads((dataset/item['fold']/variant['sbom_file']).read_bytes())
        if len(a['components'])!=len(original.get('components',[])):
            raise ValueError('Source component dropped')
        for before,after in zip(original.get('components',[]),a['components']):
            for field in ('name','version','cpe','purl','bom-ref','type','manufacturer'):
                original_value=before.get(field)
                if isinstance(original_value,str):
                    original_value=re.sub(r'(?i)CVE-\d{4}-\d+','[redacted-cve]',original_value)
                if original_value!=after.get(field):
                    raise ValueError('Source product field changed without blinding justification')
        for doc,key in ((a,'semantic_sha256'),(b,'variant_semantic_sha256')):
            if 'vulnerabilities' in doc or re.search(r'(?i)CVE-\d{4}-\d+',json.dumps(doc)):
                raise ValueError('Answer leakage')
            if any('description' in c or 'properties' in c or 'externalReferences' in c for c in doc['components']):
                raise ValueError('Unblinded duplicate source hints')
            facts=[{k:v for k,v in c.items() if k!='bom-ref'} for c in doc['components']]
            serialize=lambda value:json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))
            actual_hash=hashlib.sha256(serialize(sorted(facts,key=serialize)).encode()).hexdigest()
            if actual_hash!=item[key]:
                raise ValueError('Derived semantic fingerprint differs')
            semantics[item['fold']].add(actual_hash)
        change=variant['perturbation']
        delta=differences(a,b)
        if change['applied']:
            index=next(i for i,c in enumerate(a['components']) if c['bom-ref']==change['component_ref'])
            field=change['field']
            if delta!=[('components',index,field)] or a['components'][index][field]!=change['before'] or b['components'][index][field]!=change['after']:
                raise ValueError('Not a single recorded field mutation')
        elif delta:
            raise ValueError('Unavailable perturbation changed input')
        if change['applied'] and change['field']=='cpe' and change['operator']!='mask':
            suffix=change['before'][8:]
            if not change['after'].endswith(suffix):
                raise ValueError('CPE attributes changed')
        if change['applied'] and change['field']=='version' and change['operator']!='mask':
            if not change['after'].endswith(change['before']):
                raise ValueError('Original version expression changed')
        # Recount positive and negative source edges directly from original JSON.
        source_positive={c['bom-ref']:set() for c in original.get('components',[])}
        source_negative={c['bom-ref']:set() for c in original.get('components',[])}
        for v in original.get('vulnerabilities',[]):
            cid=v['id']
            if cid not in universe:
                continue
            scope[item['fold']].add(cid)
            p=props(v)
            if cid in rejected or p.get('dataset:product-link-status')=='source-conflict-review':
                continue
            if p.get('dataset:product-link-status')=='source-explicit':
                for edge in v.get('affects',[]):
                    source_positive[edge['ref']].add(cid)
            negatives=set(json.loads(p.get('dataset:source-product-status','{}')).get('known_not_affected',[]))
            for c in original.get('components',[]):
                if props(c).get('dataset:source-product-id') in negatives:
                    source_negative[c['bom-ref']].add(cid)
        for truth in control['gold']['components']:
            ref=truth['component_ref'];positive=source_positive[ref];negative=source_negative[ref]
            if set(truth['expected_cves'])!=positive-negative or set(truth['negative_cves'])!=negative-positive:
                raise ValueError('Gold does not preserve explicit source relations')
        judged_cpe_refs={c['bom-ref'] for c in original.get('components',[])
                        if isinstance(c.get('cpe'),str) and c['cpe'].startswith('cpe:2.3:')
                        and (source_positive[c['bom-ref']]-source_negative[c['bom-ref']] or
                             source_negative[c['bom-ref']]-source_positive[c['bom-ref']])}
        if judged_cpe_refs:
            if (item['fold']!='test' or not change['applied'] or change['field']!='cpe'
                    or change['component_ref'] not in judged_cpe_refs or variant['scenario']!='CPE_noise'):
                raise ValueError('Required in-scope CPE test coverage missing')
            coverage.append(dict(source_id=item['source_id'],fold=item['fold'],control_id=control['id'],
                variant_id=variant['id'],component_ref=change['component_ref'],scenario=variant['scenario'],
                operator=change['operator'],before=change['before'],after=change['after'],
                source_supported_CVE_count=len(source_positive[change['component_ref']]-source_negative[change['component_ref']])))
        counts.update(source_documents=1,components=len(a['components']),cases=2,
                      applied_variants=bool(change['applied']),unavailable_variants=not change['applied'])
    if scope['train']&scope['test'] or semantics['train']&semantics['test']:
        raise ValueError('Split leakage')
    if scope['train']|scope['test']!=universe:
        raise ValueError('Target CVE population lost')
    required=set(manifest.get('required_CPE_test_sources',[]))
    if required!={r['source_id'] for r in coverage}:
        raise ValueError('CPE coverage ledger differs')
    (dataset/'CPE_test_coverage.json').write_text(json.dumps(coverage,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    result=dict(passed=True,**dict(counts),target_cves=len(universe),target_cve_overlap=0,semantic_input_overlap=0,
                actual_CPE_test_pairs=len(coverage),CPE_test_coverage=coverage,
                original_source_hashes_match_index=True,source_fields_preserved_except_answer_token_redactions=True,
                all_inputs_answer_blinded=True,single_field_mutations_verified=True,
                positive_and_negative_source_edges_recounted=True,
                scope='Source/transform reproducibility, not independent semantic label accuracy',
                manifest_sha256=sha(dataset/'manifest.json'))
    (dataset/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset',type=Path,default=ROOT/'benchmark/item3_advisory_inputs_v3')
    args=parser.parse_args()
    print(json.dumps(verify(args.dataset),ensure_ascii=False,indent=2))
