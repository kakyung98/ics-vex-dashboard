"""Fresh #3 70/30 CVE/product-group split, full TRAIN preparation and QLoRA.

Preserves all 12,418 identities, source unknowns, and historical artifacts.
The final checkpoint is fixed at one epoch; no test-driven selection.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import random
import re
import sqlite3
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.common.runtime.training_progress_io import atomic_json
from tools.item3.item3_precision_pipeline import connection, sha, digest_json
from tools.item3.item3_splits import canonical_split_map, split_folder, legacy_source_database

SEED = 20261117


def read(path):
    value = json.loads(Path(path).read_text(encoding='utf-8'))
    return canonical_split_map(value) if Path(path).name == 'CVE_split.json' else value


def rows(path):
    with Path(path).open(encoding='utf-8') as handle:
        for line in handle:
            yield json.loads(line)


def norm(value):
    return re.sub(r'[^a-z0-9]', '', str(value or '').casefold())


def prepare(out):
    db = connection()
    inputs = list(rows(ROOT/'benchmark/cve_population_precision_v1/inputs.jsonl'))
    labels = {r['id']: r for r in rows(ROOT/'benchmark/cve_population_precision_v1/labels.jsonl')}
    target = {r['cve'] for r in inputs}
    assert len(target) == len(inputs) == 12418
    parent = {c: c for c in target}
    def find(c):
        while parent[c] != c:
            parent[c] = parent[parent[c]]
            c = parent[c]
        return c
    def union(a, b):
        a, b = find(a), find(b)
        if a != b:
            parent[max(a, b)] = min(a, b)
    owners = {}
    def bind(key, cve):
        if key in owners:
            union(cve, owners[key])
        else:
            owners[key] = cve
    fields = {c: json.loads(f) for c, f in db.execute('SELECT id,canonical_fields FROM conditions')}
    identity_owner = {}
    for cve, condition in db.execute('SELECT cve,condition_id FROM source_coverage ORDER BY cve,condition_id'):
        if cve in target:
            f = fields[condition]
            key = ('product', norm(f[1]), norm(f[2]))
            bind(key, cve)
            identity_owner[tuple(f[:3])] = cve
    input_hashes = {}
    for row in inputs:
        cve = row['cve']
        h = digest_json(row['sbom'])
        input_hashes[row['id']] = h
        bind(('input', h), cve)
        for comp in row['sbom'].get('components', []):
            vendor = comp.get('manufacturer') or comp.get('supplier') or ''
            if isinstance(vendor, dict):
                vendor = vendor.get('name', '')
            if vendor and comp.get('name'):
                bind(('product', norm(vendor), norm(comp['name'])), cve)
    groups = defaultdict(list)
    for cve in sorted(target):
        groups[find(cve)].append(cve)
    ordered = sorted(groups.values(), key=lambda g: hashlib.sha256((str(SEED)+g[0]).encode()).hexdigest())
    # Exact subset sum of whole groups; never split duplicate/product groups.
    goal = round(len(target)*.3)
    reachable, paths = 1, {}
    mask = (1 << (goal+1))-1
    for i, group in enumerate(ordered):
        shifted = (reachable << len(group)) & mask
        new = shifted & ~reachable
        while new:
            bit = new & -new
            n = bit.bit_length()-1
            paths[n] = (n-len(group), i)
            new ^= bit
        reachable |= shifted
    actual = max(n for n in range(goal+1) if (reachable >> n) & 1)
    test = set()
    while actual:
        previous, i = paths[actual]
        test.update(ordered[i])
        actual = previous
    train = target-test
    folds = {c: 'test' if c in test else 'train' for c in target}
    assert not train & test and train | test == target
    condition_folds = {}
    for condition, f in fields.items():
        owner = identity_owner.get(tuple(f[:3]))
        if owner is None:
            owner = owners.get(('product', norm(f[1]), norm(f[2])))
        if owner is None:
            raise ValueError('Condition lacks source group: '+condition)
        condition_folds[condition] = folds[owner]
    for cve, condition in db.execute('SELECT cve,condition_id FROM source_coverage'):
        if cve in target:
            assert folds[cve] == condition_folds[condition]
    cross_hash = defaultdict(set)
    semantic = defaultdict(set)
    for row in inputs:
        cross_hash[folds[row['cve']]].add(input_hashes[row['id']])
    for condition, h in db.execute('SELECT condition_id,semantic_sha256 FROM cases'):
        semantic[condition_folds[condition]].add(h)
    assert not cross_hash['train'] & cross_hash['test']
    assert not semantic['train'] & semantic['test']
    split = dict(train=sorted(train), test=sorted(test))
    atomic_json(out/'CVE_split.json', split)
    atomic_json(out/'condition_folds.json', condition_folds)
    counts = Counter()
    handles = {}
    for fold in split:
        folder = out/fold
        folder.mkdir()
        for kind in ('inputs', 'labels'):
            handles[fold, kind] = (folder/(kind+'.jsonl')).open('w', encoding='utf-8')
    try:
        for row in inputs:
            fold = folds[row['cve']]
            gold = dict(labels[row['id']], split=fold)
            for kind, payload in [('inputs', row), ('labels', gold)]:
                handles[fold, kind].write(json.dumps(payload, ensure_ascii=False)+'\n')
            counts[fold+':CVEs'] += 1
            counts[fold+':unknown_own_truth'] += gold['own_cve_truth'] is None
    finally:
        for f in handles.values():
            f.close()
    manifest = dict(population=12418, seed=SEED, split_unit='connected CVE/product groups and identical input hashes',
        requested_train_fraction=.7, actual_train_fraction=len(train)/12418, CVE_counts={k:len(v) for k,v in split.items()},
        product_groups=len(groups), largest_group=max(map(len, groups.values())), counts=dict(counts),
        duplicate_input_overlap=0, semantic_case_overlap=0, source_product_overlap=0,
        source_dataset_sha256=sha(legacy_source_database(ROOT)),
        source_population_gold_sha256=sha(ROOT/'benchmark/cve_population_precision_v1/manifest.json'),
        split_uses_predictions=False, prior_adapter_reused=False, all_original_CVEs_retained=True,
        training_policy='All 8693 TRAIN population records examined for each role; identical task prompts deduplicated; bypasses and missing source supervision recorded; no example cap; no extra perturbation dataset',
        epochs=1, checkpoint_selection='final epoch only', real_asset_precision=None)
    atomic_json(out/'split_manifest.json', manifest)
    print('SPLIT', json.dumps(manifest), flush=True)
    # Only TRAIN fields/cases are accessed from here onwards.
    from src.item3.matching.identification_pipeline import run_unified
    from src.item3.evidence.product_candidate_search import get_index
    from tools.item3.item3_agent_training_v8 import CapturedPacket, provider, teacher, training_messages
    from src.item3.agents.agent_message_format import encode
    index = get_index()
    class NoCVEs:
        def get_all(self, *args, **kwargs):
            return {'vulnerabilities': []}
    training_rows = [(r, labels[r['id']].get('source_condition_id')) for r in inputs if folds[r['cve']]=='train']
    train_fields = {c:f for c,f in fields.items() if condition_folds[c]=='train'}
    del fields, inputs, labels
    seen, stats = {}, Counter()
    start = time.time()
    with (out/'train.jsonl').open('w', encoding='utf-8') as handle, sqlite3.connect(out/'training_coverage.sqlite3') as audit:
        audit.execute('CREATE TABLE coverage(case_id TEXT,task TEXT,example_id TEXT,status TEXT,PRIMARY KEY(case_id,task))')
        for number, (row, condition) in enumerate(training_rows, 1):
            for task in ('I1','I2','I3'):
                case_id = row['id']
                eid, status = None, 'runtime_stage_bypassed'
                if condition is None:
                    stats[task+':missing_source_supervision'] += 1
                    audit.execute('INSERT INTO coverage VALUES (?,?,?,?)', (case_id,task,None,'missing_source_supervision'))
                    continue
                assert condition_folds[condition]=='train'
                try:
                    run_unified(row['sbom'], NoCVEs(), index=index, mode='agents', agents=provider(train_fields[condition], capture=task), mapping_scope='identification')
                except CapturedPacket as captured:
                    answer = teacher(task, captured.packet, train_fields[condition])
                    messages = training_messages(task, captured.packet, answer)
                    wire, system, _, _ = encode(task, captured.packet, tabular=True)
                    messages[0]['content'] = system
                    messages[1]['content'] = json.dumps(wire, ensure_ascii=False, separators=(',', ':'))
                    key = digest_json([task, messages[:-1]])
                    eid, status = task+'-'+key, 'covered'
                    if key in seen:
                        assert seen[key] == messages[-1]['content'], 'Conflicting source supervision'
                    else:
                        seen[key] = messages[-1]['content']
                        handle.write(json.dumps(dict(id=eid, task=task, source_case=case_id, source_condition=condition, split='train', messages=messages), ensure_ascii=False)+'\n')
                        stats[task+':examples'] += 1
                stats[task+':'+status] += 1
                audit.execute('INSERT INTO coverage VALUES (?,?,?,?)', (case_id, task, eid, status))
            if number % 100 == 0 or number == len(training_rows):
                audit.commit();handle.flush()
                atomic_json(out/'prepare_status.json', dict(phase='preparing', records=number,total_records=len(training_rows),seconds=time.time()-start,stats=dict(stats)))
                print('PREPARE', number, '/', len(training_rows), dict(stats), flush=True)
    manifest.update(training_stats=dict(stats), train_population_records_examined=len(training_rows), training_examples=sum(v for k,v in stats.items() if k.endswith(':examples')),
        train_sha256=sha(out/'train.jsonl'), heldout_loaded_for_training=False)
    atomic_json(out/'training_manifest.json', manifest)
    db.close()


def train(out):
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM, set_seed
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from src.research.training_memory import cast_frozen_io
    set_seed(SEED);torch.set_num_threads(4)
    manifest = read(out/'training_manifest.json')
    assert sha(out/'train.jsonl') == manifest['train_sha256']
    base = read(ROOT/'models/precision_roles_qwen25_14b_v1/training_complete.json')['base']
    tok = AutoTokenizer.from_pretrained(base, local_files_only=True)
    if tok.pad_token_id is None:
        tok.pad_token = tok.eos_token
    encoded = []
    for row in rows(out/'train.jsonl'):
        assert row['split'] == 'train'
        prompt = tok.apply_chat_template(row['messages'][:-1], tokenize=False, add_generation_prompt=True)
        ids = tok(prompt+row['messages'][-1]['content']+tok.eos_token, add_special_tokens=False)['input_ids']
        prefix = len(tok(prompt, add_special_tokens=False)['input_ids'])
        if len(ids) > 6144:
            raise ValueError('Context overflow; no silent sample omission')
        encoded.append((ids, [-100]*prefix+ids[prefix:]))
    assert encoded
    random.Random(SEED).shuffle(encoded)
    model = AutoModelForCausalLM.from_pretrained(base, local_files_only=True, device_map={'':0}, dtype=torch.bfloat16, attn_implementation='sdpa')
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True, gradient_checkpointing_kwargs={'use_reentrant':True})
    model = get_peft_model(model, LoraConfig(r=4,lora_alpha=8,lora_dropout=.05,bias='none',task_type='CAUSAL_LM',target_modules=['q_proj','v_proj']))
    cast_frozen_io(model, torch.bfloat16)
    model.config.use_cache=False
    model.train()
    params = [p for p in model.parameters() if p.requires_grad]
    def weights():
        h=hashlib.sha256()
        for name,p in model.named_parameters():
            if p.requires_grad:
                h.update(name.encode());h.update(p.detach().cpu().float().numpy().tobytes())
        return h.hexdigest()
    initial = weights()
    optimizer = torch.optim.AdamW(params, lr=1e-4)
    optimizer.zero_grad(set_to_none=True)
    start, losses, updates = time.time(), [], 0
    for i,(ids,labels) in enumerate(encoded):
        x=torch.tensor([ids],device='cuda');y=torch.tensor([labels],device='cuda')
        with torch.autocast('cuda',dtype=torch.bfloat16):
            core=model.get_base_model()
            output=core.model(input_ids=x,attention_mask=torch.ones_like(x),use_cache=False)
            mask=y[:,1:]!=-100
            logits=core.lm_head(output.last_hidden_state[:,:-1,:][mask])
            loss=torch.nn.functional.cross_entropy(logits.float(),y[:,1:][mask])
        if not bool(torch.isfinite(loss)):
            raise RuntimeError('Non-finite training loss')
        losses.append(float(loss.detach()))
        # Normalize the final accumulation group by its actual size.
        accumulation=min(4,len(encoded)-(i//4)*4)
        (loss/accumulation).backward()
        del output,loss,x,y,mask,logits
        if (i+1)%4==0 or i+1==len(encoded):
            gradient=torch.nn.utils.clip_grad_norm_(params,1.)
            if not bool(torch.isfinite(gradient)):
                raise RuntimeError('Non-finite gradient')
            optimizer.step();optimizer.zero_grad(set_to_none=True);updates+=1
            elapsed=time.time()-start
            atomic_json(out/'training_status.json',dict(phase='training',completed_examples=i+1,total_examples=len(encoded),optimizer_updates=updates,
                seconds=elapsed,eta_seconds=elapsed/(i+1)*(len(encoded)-i-1),loss=losses[-1],mean_loss=sum(losses)/len(losses)))
            if updates%10==0:
                print('TRAIN',i+1,'/',len(encoded),'updates',updates,'elapsed',round(elapsed),'eta',round(elapsed/(i+1)*(len(encoded)-i-1)),flush=True)
    final=weights()
    assert final!=initial and updates
    folder=out/'adapter';model.save_pretrained(folder);tok.save_pretrained(folder)
    atomic_json(folder/'training_complete.json',dict(model='Qwen2.5-Coder-14B-Instruct',base=base,heldout_loaded=False,
        shared_tasks=['I1','I2','I3'],examples=len(encoded),epochs=1,optimizer_updates=updates,rank=4,target_modules=['q_proj','v_proj'],
        adapter_sha256=sha(folder/'adapter_model.safetensors'),initial_trainable_sha256=initial,final_trainable_sha256=final,
        train_manifest_sha256=sha(out/'training_manifest.json'),prior_adapter_reused=False,checkpoint_selection='final epoch only',
        seconds=time.time()-start,mean_training_loss=sum(losses)/len(losses)))


def evaluate(out):
    from functools import partial
    from src.common.runtime.shared_adapter_runtime import PrecisionRoleRuntime
    from src.research.identification_batch_flow import PacketCache, resolve_window
    from src.item3.matching.identification_pipeline import run_unified
    from src.item3.evidence.product_candidate_search import get_index
    from tools.item3.item3_precision_pipeline import SourceNVD
    from tools.item3.item3_v6_metrics import case_score, aggregate
    testdir=split_folder(out,'test')
    inputs=list(rows(testdir/'inputs.jsonl'))
    labels={r['id']:r for r in rows(testdir/'labels.jsonl')}
    runtime=PrecisionRoleRuntime(folder=out/'adapter')
    signature=dict(adapter=sha(out/'adapter/adapter_model.safetensors'),split=sha(out/'CVE_split.json'),driver=sha(Path(__file__)),historical_cache_imported=False)
    atomic_json(testdir/'run_config.json',signature)
    cache=PacketCache(testdir/'packet_cache.sqlite3',digest_json(signature))
    assert cache.statistics()['cached_packets']==0
    source=connection();nvd=SourceNVD(source);index=get_index()
    universe=set(nvd.records)|set(read(out/'CVE_split.json')['train'])|set(read(out/'CVE_split.json')['test'])
    scores, unique, hashes=[],{},{}
    with sqlite3.connect(testdir/'predictions.sqlite3') as db:
        db.execute('CREATE TABLE predictions(id TEXT PRIMARY KEY,cve TEXT,result TEXT,score TEXT)')
        def infer(task,packets,**kwargs):
            return runtime.identification_batch(task,packets)
        for start in range(0,len(inputs),64):
            chunk=inputs[start:start+64]
            result=resolve_window({r['id']:r['sbom'] for r in chunk},cache,infer,index=index,nvd=nvd,batch_size=16,core=partial(run_unified,mapping_scope='identification'))
            for row in chunk:
                prediction,trace=result[row['id']]
                score=case_score(prediction,labels[row['id']],universe)
                db.execute('INSERT INTO predictions VALUES (?,?,?,?)',(row['id'],row['cve'],json.dumps(dict(result=prediction,trace=trace)),json.dumps(score)))
                scores.append(('holdout','test',score))
                h=digest_json(row['sbom'])
                if h in unique:
                    assert unique[h]==score
                unique[h]=score
            db.commit()
            atomic_json(testdir/'status.json',dict(phase='evaluating',completed=min(start+64,len(inputs)),total=len(inputs)))
            print('EVALUATE',min(start+64,len(inputs)),'/',len(inputs),flush=True)
    report=aggregate(scores,len(inputs))
    report.update(deduplicated=aggregate([('holdout','test',s) for s in unique.values()],len(unique)),
        split=read(out/'split_manifest.json'),training=read(out/'adapter/training_complete.json'),
        actual_model_requests=cache.statistics(),gold_passed_to_inference=False,historical_predictions_reused=False,
        scope='Public-source-derived synthetic inventory; fresh grouped 70/30 split, final one-epoch TRAIN checkpoint. Real-asset precision unmeasured.')
    atomic_json(testdir/'precision_report.json',report)
    cache.close();source.close()
    print('RESULT',json.dumps(report),flush=True)


def queue(out):
    from src.common import gpu_lease
    gpu_lease.assert_inference_available()
    out.mkdir(parents=True,exist_ok=False)
    assert 'H200' in subprocess.check_output(['nvidia-smi','--query-gpu=name','--format=csv,noheader'],text=True)
    state=dict(phase='starting',pid=os.getpid(),started_unix=time.time())
    atomic_json(out/'status.json',state)
    atomic_json(out/'driver_protocol.json',dict(driver_sha256=sha(Path(__file__)),seed=SEED,epochs=1,
        final_checkpoint_only=True,no_test_tuning=True,new_adapter_from_base=True))
    try:
        for stage in ('prepare','train','evaluate'):
            state.update(phase=stage);atomic_json(out/'status.json',state)
            env=dict(os.environ,HF_HUB_OFFLINE='1',TOKENIZERS_PARALLELISM='false',OMP_NUM_THREADS='4',MKL_NUM_THREADS='4',OPENBLAS_NUM_THREADS='4')
            with (out/(stage+'.log')).open('wb') as log:
                child=subprocess.Popen([sys.executable,str(Path(__file__)),stage,'--output',str(out)],cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
                atomic_json(gpu_lease.FILE,dict(active=True,pid=os.getpid(),child_pid=child.pid,stage='item3_holdout_7030_'+stage))
                state['child_pid']=child.pid;atomic_json(out/'status.json',state)
                code=child.wait()
            if code:
                raise RuntimeError(stage+' failed; inspect '+str(out/(stage+'.log')))
        state.update(phase='complete',finished_unix=time.time());atomic_json(out/'status.json',state)
    except BaseException as exc:
        state.update(phase='failed',error=str(exc),finished_unix=time.time());atomic_json(out/'status.json',state)
        traceback.print_exc();raise
    finally:
        lease=read(gpu_lease.FILE) if gpu_lease.FILE.exists() else {}
        if lease.get('pid')==os.getpid():
            atomic_json(gpu_lease.FILE,dict(active=False,pid=os.getpid()))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('stage',choices=['queue','prepare','train','evaluate']);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();globals()[args.stage](args.output)
