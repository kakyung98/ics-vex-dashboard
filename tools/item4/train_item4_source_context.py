"""Dedicated operational QLoRA, real-CVE TRAIN synthetic worlds only."""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.evaluation.source_context_simulation import DATA; from src.item4.evaluation.source_context_simulation import MODEL; from src.item4.evaluation.source_context_simulation import messages
from src.common.runtime.training_progress_io import atomic_json
from tools.item3.item3_precision_pipeline import sha
SFT=ROOT/'benchmark/item4_source_context_sft_v1'

def prepare(per_class=128):
    audit=json.loads((DATA/'integrity_audit.json').read_text(encoding='utf-8'));assert audit['passed']
    if SFT.exists():raise FileExistsError(SFT)
    SFT.mkdir(parents=True)
    # Input-only grouping safeguard, never held-out labels or predictions.
    test_hashes={hashlib.sha256(r['packet']['spec']['source']['clause']['quote'].encode()).hexdigest()
        for r in map(json.loads,(DATA/'evaluation/inputs.jsonl').open(encoding='utf-8')) if r['packet'].get('spec')}
    labels={r['id']:r for r in map(json.loads,(DATA/'train/labels.jsonl').open(encoding='utf-8'))}
    candidates=[];excluded=0
    for row in map(json.loads,(DATA/'train/inputs.jsonl').open(encoding='utf-8')):
        spec=row['packet'].get('spec')
        if not spec:continue
        if hashlib.sha256(spec['source']['clause']['quote'].encode()).hexdigest() in test_hashes:excluded+=1;continue
        candidates.append(row)
    candidates.sort(key=lambda r:hashlib.sha256(('source-SFT-v1|'+r['id']).encode()).hexdigest())
    selected=[];seen={'A':set(),'U':set()}
    for row in candidates:
        label=labels[row['id']];code=label['expected_code'];cid=label['cve']
        if cid in seen[code] or len(seen[code])>=per_class:continue
        assert label['fold']=='train'
        seen[code].add(cid)
        selected.append(dict(id=row['id'],cve=cid,task='OPERATIONAL_SOURCE_SIMULATION',split='train',
            messages=messages(row['packet'])+[dict(role='assistant',content=code)]))
    assert all(len(v)==per_class for v in seen.values())
    with (SFT/'train.jsonl').open('w',encoding='utf-8') as f:
        for r in selected:f.write(json.dumps(r,ensure_ascii=False)+'\n')
    atomic_json(SFT/'manifest.json',dict(examples=len(selected),train_only=True,heldout_labels_loaded=False,
        selection='Fixed hash order, balanced A/U, distinct CVE per class, TRAIN only; exact evaluation clause text excluded',
        per_class=per_class,source_gold_manifest_sha256=sha(DATA/'manifest.json'),
        excluded_exact_evaluation_clause_train_cases=excluded,train_sha256=sha(SFT/'train.jsonl'),
        conditional_simulation_only=True,real_asset_impact_supervision=False))
    print('Prepared source-conditioned TRAIN examples',len(selected),flush=True)

def train():
    from tools.common import train_precision_roles as trainer
    from src.common import gpu_lease
    marker=json.loads((ROOT/'models/precision_roles_qwen25_14b_v1/training_complete.json').read_text(encoding='utf-8'))
    trainer.OUT=MODEL;trainer.SFT=SFT;trainer.BASE=Path(marker['base'])
    for name,h in marker['base_files_sha256'].items():assert sha(trainer.BASE/name)==h,name
    try:
        trainer.train()
        p=MODEL/'training_complete.json';r=json.loads(p.read_text(encoding='utf-8'))
        r.update(shared_tasks=['OPERATIONAL_SOURCE_SIMULATION'],conditional_simulation_only=True,
            real_asset_impact_supervision=False,source_semantics_verified=False,
            base_files_sha256=marker['base_files_sha256'],source_gold_manifest_sha256=sha(DATA/'manifest.json'),
            source_role_code_sha256=sha(ROOT/'src/item4/evaluation/source_context_simulation.py'))
        atomic_json(p,r)
    finally:
        import os
        atomic_json(gpu_lease.FILE,dict(active=False,pid=os.getpid()))

if __name__=='__main__':
    prepare() if sys.argv[1]=='prepare' else train()
