"""Check all target identities and explicit CVE declarations in linked SBOMs."""
from collections import Counter
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.build_full_cve_population import OUT,sha
from src.training_io import atomic_json

def audit():
    manifest=json.loads((OUT/'manifest.json').read_text(encoding='utf-8'))
    for name,digest in manifest['artifacts'].items():assert sha(OUT/name)==digest,name
    identities={};cache={};counts=Counter();train=set();evaluation=set()
    for name in ('inputs','labels','reverse_links'):
        ids=[]
        for line in (OUT/(name+'.jsonl')).open(encoding='utf-8'):
            r=json.loads(line);cid=r['cve'];ids.append(cid)
            assert not cid.startswith('CVE-2099-'),cid
            if name=='labels':
                assert r['item4']['actual_affected'] is None
                folds=r['item3']['existing_benchmark_positive_input_ids']
                if folds.get('train'):train.add(cid)
                if folds.get('evaluation'):evaluation.add(cid)
            if name=='reverse_links':
                assert r['sbom_links'],cid
                for link in r['sbom_links']:
                    path=ROOT/link['sbom_file'];assert path.is_file(),str(path)
                    if str(path) not in cache:
                        raw=json.loads(path.read_text(encoding='utf-8'))
                        cache[str(path)]={v['id'] for v in raw.get('vulnerabilities',[])}
                    assert cid in cache[str(path)],(cid,str(path))
                    counts['explicit_SBOM_CVE_edges']+=1
        assert len(ids)==len(set(ids))==12418,name
        identities[name]=set(ids)
    assert identities['inputs']==identities['labels']==identities['reverse_links']
    report=dict(passed=True,unique_target_CVEs=12418,all_three_files_have_identical_CVEs=True,
        all_reverse_links_have_explicit_CVE_in_existing_SBOM=True,linked_SBOM_files=len(cache),
        **dict(counts),existing_item3_positive_CVEs_train_test_overlap=len(train&evaluation),
        reverse_link_is_candidate_source_not_independent_gold=True,
        item4_independent_operational_impact_labels=0,
        limitations='SBOMs are advisory-derived inventories; explicit linkage is not proof of real installed assets or contextual impact.')
    atomic_json(OUT/'integrity_audit.json',report)
    print(json.dumps(report))

if __name__=='__main__':audit()
