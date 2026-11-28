"""Audit real-CVE coverage, source spans, independent oracle and model boundary."""
from collections import Counter,defaultdict
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.evaluation.source_context_simulation import DATA; from src.item4.evaluation.source_context_simulation import gate; from src.item4.evaluation.source_context_simulation import source_spec; from src.item4.evaluation.source_context_simulation import model_packet; from src.item4.evaluation.source_context_simulation import messages
from src.common.runtime.training_progress_io import atomic_json
from tools.item3.item3_precision_pipeline import sha
from tools.item4.build_item4_source_context_gold import VARIATIONS
from src.item4.evaluation.ground_truth_evidence import GroundingIndex

def audit(data=None):
    global DATA
    if data is not None:DATA=Path(data)
    manifest=json.loads((DATA/'manifest.json').read_text(encoding='utf-8'))
    assert manifest['variations']==list(VARIATIONS)
    for p,h in manifest['artifacts'].items():assert sha(DATA/p.replace('\\','/'))==h,p
    records={r['cve']:r for r in map(json.loads,(DATA/'cve_source_records.jsonl').open(encoding='utf-8'))}
    target={r['cve'] for r in map(json.loads,(ROOT/'results/item4_condition_clusters_v1/cve_assignments.jsonl').open(encoding='utf-8'))}
    assert len(records)==12418 and records.keys()==target
    grounding_counts=Counter()
    if manifest.get('grounding_version'):
        from src.item4.decision.scoped_vex_review import DATA as ORIGINALS
        original={}
        for path in sorted(ORIGINALS.glob('records_*.json')):
            original.update(json.loads(path.read_text(encoding='utf-8')))
        grounder=GroundingIndex(ROOT)
        if grounder.vendor:
            from tools.item4.collect_item4_grounding_sources import Text
            import re
            vendor=grounder.vendor
            assert hashlib.sha256(vendor['raw_html'].encode()).hexdigest()==vendor['document_sha256']
            html=Text();html.feed(vendor['raw_html'])
            assert re.sub(r'\s+',' ',' '.join(html.parts))==vendor['text']
        for cid,record in records.items():
            assert record==grounder.prepare(original[cid]),('Original product/source/role reconstruction failed',cid)
            for product in record['products']:
                grounding_counts['asset_role:'+product['asset_type']['status']]+=1
        # Concrete independent expectation for the previously wrong example.
        cp=records['CVE-2015-8214']
        general=next(s for s in cp['sources'] if s['id']=='icsa-15-335-03:v0:n0')
        specific=next(s for s in cp['sources'] if s['id']=='icsa-15-335-03:v0:n1')
        assert 'icsa-15-335-03:CSAFPID-0001' not in general['product_keys']
        assert 'icsa-15-335-03:CSAFPID-0001' in specific['product_keys']
    ids=set();folds={};counts=Counter();source_hashes=defaultdict(set);seen_specs=set();variations_by_cve=defaultdict(set)
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
                assert label['variation'] in VARIATIONS,identity
                assert label['variation'] not in variations_by_cve[p['cve']],identity
                variations_by_cve[p['cve']].add(label['variation'])
                signature=(p['cve'],spec['scenario_id'])
                if signature not in seen_specs:
                    r=records[p['cve']];s=next(s for s in r['scenarios'] if s['id']==spec['scenario_id'])
                    assert source_spec(r,s)==spec
                    seen_specs.add(signature)
                source_hashes[fold].add(hashlib.sha256(spec['source']['clause']['quote'].encode()).hexdigest())
                assert spec['source_semantic_review']=='pending'
                assert spec['simulation_assumptions']['assumptions_verified_for_real_CVE'] is False
                if manifest.get('grounding_version'):
                    assert spec['asset_type']['status']=='source_supported'
                    assert not spec['simulation_assumptions']['unobserved_requirements_satisfied']
                    assert spec['question_formula_validation']['status']=='source_supported'
                    for condition in spec['conditions']:
                        assert condition['operator_observable']
                        assert condition['question_contract']['answers']==dict(yes='true',no='false',unknown='unknown')
                        assert condition['question']==condition['question_contract']['question']
            else:
                assert label['actual_affected'] is None and label['expected_code']=='U',identity
                originals={s['id']:s for s in records[p['cve']]['sources']}
                for evidence in p.get('source_evidence',[]):
                    original=originals[evidence['source_id']]
                    assert evidence['text']==original['text'],identity
                    assert hashlib.sha256(evidence['text'].encode()).hexdigest()==evidence['text_sha256'],identity
                    assert evidence['text_sha256']==original['text_sha256'],identity
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
    assert all(v==set(VARIATIONS) for v in variations_by_cve.values())
    assert len(ids)==len(variations_by_cve)*len(VARIATIONS)+(len(target)-len(variations_by_cve))
    report=dict(passed=True,population=12418,cases=len(ids),fold_CVE_counts={k:len(v) for k,v in folds.items()},
        grounding_counts=dict(grounding_counts),independent_human_semantic_validation=False,
        checks=['Exactly four operator-context variants per source-supported CVE','Frozen artifacts','Exact original CVE population','Source hash/span/product/path reconstruction',
            'No fabricated human semantic approval','Gate vs independent DNF possible-world oracle',
            'All A labels consistent with latent world','No label keys in model inputs','Disjoint CVE folds','Complete prompt fits model context'],
        max_prompt_tokens=counts['max_prompt_tokens'],exact_clause_hash_overlap_between_folds=len(source_hashes['train']&source_hashes['evaluation']),
        gold_manifest_sha256=sha(DATA/'manifest.json'),real_asset_accuracy_verified=False)
    atomic_json(DATA/'integrity_audit.json',report);print(json.dumps(report),flush=True)

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data',type=Path,default=DATA)
    audit(parser.parse_args().data)
