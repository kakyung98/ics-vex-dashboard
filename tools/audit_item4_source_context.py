"""Audit real-CVE coverage, source spans, independent oracle and model boundary."""
from collections import Counter,defaultdict
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.item4_source_simulation import DATA,gate,source_spec,model_packet,messages
from src.training_io import atomic_json
from tools.item3_precision_pipeline import sha

def audit():
    manifest=json.loads((DATA/'manifest.json').read_text(encoding='utf-8'))
    for p,h in manifest['artifacts'].items():assert sha(DATA/p)==h,p
    records={r['cve']:r for r in map(json.loads,(DATA/'cve_source_records.jsonl').open(encoding='utf-8'))}
    target={r['cve'] for r in map(json.loads,(ROOT/'benchmark/cve_population_12418_v1/labels.jsonl').open(encoding='utf-8'))}
    assert len(records)==12418 and records.keys()==target
    ids=set();folds={};counts=Counter();source_hashes=defaultdict(set);seen_specs=set()
    from transformers import AutoTokenizer
    marker=json.loads((ROOT/'models/precision_roles_qwen25_14b_v1/training_complete.json').read_text(encoding='utf-8'))
    tok=AutoTokenizer.from_pretrained(marker['base'],local_files_only=True)
    for fold in ('train','evaluation'):
        labels={r['id']:r for r in map(json.loads,(DATA/fold/'labels.jsonl').open(encoding='utf-8'))};folds[fold]=set()
        for row in map(json.loads,(DATA/fold/'inputs.jsonl').open(encoding='utf-8')):
            identity=row['id'];p=row['packet'];label=labels[identity]
            assert identity not in ids;ids.add(identity);folds[fold].add(p['cve'])
            assert label['cve']==p['cve'] and label['fold']==fold
            assert 'actual_affected' not in json.dumps(p) and 'latent_state' not in json.dumps(p)
            assert len(identity)==36 and identity.startswith('CTX-')
            spec=p.get('spec')
            if spec:
                signature=(p['cve'],spec['scenario_id'])
                if signature not in seen_specs:
                    r=records[p['cve']];s=next(s for s in r['scenarios'] if s['id']==spec['scenario_id'])
                    assert source_spec(r,s)==spec
                    seen_specs.add(signature)
                source_hashes[fold].add(hashlib.sha256(spec['source']['clause']['quote'].encode()).hexdigest())
                assert spec['source_semantic_review']=='pending'
                assert spec['simulation_assumptions']['assumptions_verified_for_real_CVE'] is False
            decision=gate(p);code='A' if decision['simulation_status']=='affected' else 'U'
            assert code==label['expected_code'],identity
            assert not decision['is_production_VEX'] and not decision['export_allowed']
            assert code!='A' or label['actual_affected'] is True,identity
            prompt=tok.apply_chat_template(messages(p),tokenize=False,add_generation_prompt=True)
            n=len(tok(prompt,add_special_tokens=False)['input_ids'])
            counts['max_prompt_tokens']=max(counts['max_prompt_tokens'],n)
            assert n<=6144,(identity,n)
            counts[fold+':cases']+=1
        assert counts[fold+':cases']==len(labels)
    assert not folds['train']&folds['evaluation'] and folds['train']|folds['evaluation']==target
    report=dict(passed=True,population=12418,cases=len(ids),fold_CVE_counts={k:len(v) for k,v in folds.items()},
        checks=['Frozen artifacts','Exact original CVE population','Source hash/span/product/path reconstruction',
            'No fabricated human semantic approval','Gate vs independent DNF possible-world oracle',
            'All A labels consistent with latent world','No label keys in model inputs','Disjoint CVE folds','Complete prompt fits model context'],
        max_prompt_tokens=counts['max_prompt_tokens'],exact_clause_hash_overlap_between_folds=len(source_hashes['train']&source_hashes['evaluation']),
        gold_manifest_sha256=sha(DATA/'manifest.json'),real_asset_accuracy_verified=False)
    atomic_json(DATA/'integrity_audit.json',report);print(json.dumps(report),flush=True)

if __name__=='__main__':audit()
