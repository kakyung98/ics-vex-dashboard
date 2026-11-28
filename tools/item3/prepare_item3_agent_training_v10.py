"""Prepare and audit SFT from v10 TRAIN fault/control pairs only."""
from collections import Counter
from pathlib import Path
import json
import sqlite3
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.common.runtime.training_progress_io import atomic_json; from src.common.runtime.training_progress_io import read_json
from tools.item3.build_item3_cpe_faults_v6 import sha
from src.item3.matching.identification_pipeline import run_unified
from src.item3.evidence.product_candidate_search import get_index
from tools.item3.item3_agent_training_v8 import CapturedPacket, provider, teacher, training_messages

DATA = ROOT/'data/item3_spelling_noise_v10'
SOURCE = ROOT/'benchmark/item3_evaluation/prep/dataset.sqlite3'
OUT = ROOT/'data/item3_agents_sft_v10'


class NoCVELookup:
    def get_all(self, *args, **kwargs):
        return {'vulnerabilities': []}


def main():
    if OUT.exists():
        raise FileExistsError(OUT)
    OUT.mkdir()
    begin = time.perf_counter()
    def status(phase, **extra):
        atomic_json(OUT/'status.json', {'phase': phase, 'heldout_loaded': False,
                    'elapsed_seconds': time.perf_counter()-begin, **extra})
    status('checking_source')
    assert read_json(DATA/'validation_audit.json')['passed']
    manifest = read_json(DATA/'manifest.json')
    for name, digest in manifest['artifacts'].items():
        artifact = SOURCE if name == 'dataset.sqlite3' else DATA/name
        assert sha(artifact) == digest, name
    db = sqlite3.connect(f'file:{SOURCE.as_posix()}?mode=ro', uri=True)
    # Never select evaluation inputs, canonical fields or gold.
    fields = {cid: json.loads(text) for cid, text in db.execute("SELECT id,canonical_fields FROM conditions WHERE fold='train'")}
    rows = db.execute("SELECT c.id,c.condition_id,c.axis,c.sbom,r.id,r.sbom FROM cases c JOIN cases r ON r.condition_id=c.condition_id AND r.scenario='control' WHERE c.fold='train' AND r.fold='train' AND c.scenario!='control' ORDER BY c.axis,c.id").fetchall()
    assert len(rows) == 41556 and Counter(r[2] for r in rows) == {'I1':13852, 'I2':13852, 'I3':13852}
    status('loading_dictionary')
    index = get_index()
    seen = {task: {} for task in ('I1','I2','I3')}
    handles = {}
    coverage = sqlite3.connect(OUT/'coverage.sqlite3')
    coverage.execute('CREATE TABLE coverage(case_id TEXT,task TEXT,example_id TEXT,status TEXT,PRIMARY KEY(case_id,task))')
    counts, targets, blocked = Counter(), Counter(), 0
    for task in seen:
        (OUT/task).mkdir(); handles[task] = (OUT/task/'train.jsonl').open('w', encoding='utf-8')
    try:
        for number, (cid, pid, task, text, control_id, control_text) in enumerate(rows, 1):
            for case, payload in ((cid,text),(control_id,control_text)):
                try:
                    run_unified(json.loads(payload),NoCVELookup(),index=index,agents=provider(fields[pid],capture=task),mode='agents',mapping_scope='identification')
                except CapturedPacket as captured:
                    packet = captured.packet
                    answer = teacher(task,packet,fields[pid])
                    messages = training_messages(task,packet,answer)
                    digest = __import__('hashlib').sha256(json.dumps(messages[:-1],ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
                    eid = task+'-'+digest[:24]
                    previous = seen[task].get(digest)
                    if previous:
                        assert previous == messages[-1]['content'], 'Conflicting observable supervision'
                    else:
                        # Recompute targets from TRAIN-only source facts before writing.
                        assert teacher(task,packet,fields[pid]) == answer
                        handles[task].write(json.dumps({'id':eid,'task':task,'source_profile':pid,'messages':messages,'packet':packet,'gold':answer,'split':'train'},ensure_ascii=False)+'\n')
                        seen[task][digest] = messages[-1]['content']
                        counts[task+':unique_examples'] += 1
                        targets[task+':'+answer['status']] += 1
                    coverage.execute('INSERT INTO coverage VALUES (?,?,?,?)',(case,task,eid,'covered'))
                    counts[task+':covered_BOMs'] += 1
                else:
                    blocked += 1
                    coverage.execute('INSERT INTO coverage VALUES (?,?,?,?)',(case,task,None,'runtime_stage_bypassed'))
            if number % 250 == 0:
                coverage.commit()
                for handle in handles.values(): handle.flush()
                speed = (time.perf_counter()-begin)/number
                status('preparing',problem_BOMs_completed=number,problem_BOMs_total=len(rows),counts=dict(counts),eta_seconds=speed*(len(rows)-number))
                print(f'{number}/{len(rows)} train pairs; ETA {speed*(len(rows)-number)/60:.1f} min',flush=True)
        coverage.commit()
    finally:
        for handle in handles.values(): handle.close()
        coverage.close(); db.close()
    roles = {t:{'examples':counts[t+':unique_examples'],'covered_BOMs':counts[t+':covered_BOMs'],'path':t+'/train.jsonl','sha256':sha(OUT/t/'train.jsonl')} for t in handles}
    code_names = ['tools/item3/prepare_item3_agent_training_v10.py','tools/item3/item3_agent_training_v8.py',
                  'src/item3/agents/agent_contracts.py','src/item3/agents/agent_message_format.py','src/item3/agents/evidence_review_agents.py',
                  'src/item3/evidence/product_identity_evidence.py','src/item3/evidence/product_candidate_search.py','src/common/data/sbom_input_normalization.py']
    spec = {'schema':'ics-vex-three-grounded-agents-SFT/10','source_dataset_manifest_sha256':sha(DATA/'manifest.json'),
            'source_train_BOMs':83112,'source_train_CVEs':7593,'heldout_BOMs':18608,'heldout_CVEs':3254,
            'heldout_loaded_for_training':False,'roles':roles,'label_statuses':dict(targets),'runtime_bypassed_examples':blocked,
            'training_policy':'One fixed epoch per role; final checkpoint only; evaluation is not used for training, tuning or checkpoint selection.',
            'supervision':'Source CPE anchors, exact production packets and contract-valid teacher evidence; no LLM-derived labels.',
            'code':{p:sha(ROOT/p) for p in code_names}}
    atomic_json(OUT/'manifest.json',spec)
    atomic_json(OUT/'supervision_audit.json',{'passed':True,'every_written_target_recomputed':True,'manifest_sha256':sha(OUT/'manifest.json'),'heldout_loaded':False,'roles':roles})
    status('ready',roles=roles)


if __name__ == '__main__':
    main()
