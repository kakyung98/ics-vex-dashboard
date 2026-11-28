"""Full v2 inference with shared-prefix KV reuse, without label-based decisions."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import time

from src.common.runtime.training_progress_io import atomic_json
from tools.item4.run_item4_v2_unsupervised import CHOICES,SYSTEM,sha,jsonl,load_model,evaluation_payload


def common_prefix(rows):
    shortest=min(map(len,rows));n=0
    while n<shortest and all(r[n]==rows[0][n] for r in rows[1:]):n+=1
    if n==shortest:raise ValueError('Identical/incomplete prompts cannot have an empty suffix')
    return rows[0][:n],[r[n:] for r in rows]


def padded(seqs,pad_id,device,left=False):
    import torch
    width=max(map(len,seqs));x=torch.full((len(seqs),width),pad_id,dtype=torch.long,device=device)
    mask=torch.zeros_like(x)
    for i,row in enumerate(seqs):
        start=width-len(row) if left else 0
        x[i,start:start+len(row)]=torch.tensor(row,device=device);mask[i,start:start+len(row)]=1
    return x,mask


def full_logits(base,seqs,head_weight,pad_id,device):
    import torch
    x,mask=padded(seqs,pad_id,device)
    position=(mask.cumsum(-1)-1).clamp_min(0)
    output=base.model(input_ids=x,attention_mask=mask,position_ids=position,use_cache=False).last_hidden_state
    last=output[torch.arange(len(seqs),device=device),mask.sum(-1)-1]
    return torch.nn.functional.linear(last,head_weight).float()


def prefix_logits(base,groups,head_weight,pad_id,device):
    """Return [CVE][variant][choice] scores; every suffix executes on the model."""
    import torch
    from transformers.cache_utils import DynamicCache
    parts=[common_prefix(g) for g in groups]
    x,mask=padded([p[0] for p in parts],pad_id,device,left=True)
    position=(mask.cumsum(-1)-1).clamp_min(0)
    prefix=base.model(input_ids=x,attention_mask=mask,position_ids=position,use_cache=True).past_key_values
    result=[[] for _ in groups]
    for v in range(len(groups[0])):
        suffixes=[p[1][v] for p in parts]
        suffix,suffix_mask=padded(suffixes,pad_id,device)
        attention=torch.cat([mask,suffix_mask],-1)
        position=(attention.cumsum(-1)-1).clamp_min(0)[:,-suffix.shape[1]:]
        cache=DynamicCache([(layer.keys.clone(),layer.values.clone()) for layer in prefix.layers],config=base.config)
        out=base.model(input_ids=suffix,attention_mask=attention,position_ids=position,
            past_key_values=cache,use_cache=True)
        last=out.last_hidden_state[torch.arange(len(groups),device=device),suffix_mask.sum(-1)-1]
        scores=torch.nn.functional.linear(last,head_weight).float().cpu().tolist()
        for owner,row in enumerate(scores):result[owner].append(row)
        del out,cache,suffix,suffix_mask,attention,position,last
    return result,dict(prefix_tokens=sum(len(p[0]) for p in parts),
        total_full_tokens=sum(len(row) for g in groups for row in g),
        total_suffix_tokens=sum(len(row) for p in parts for row in p[1]))


def vectorized_prefix_logits(base,groups,head_weight,pad_id,device):
    """Process all seven suffixes in one model call, with repeated prefix KV."""
    import torch
    parts=[common_prefix(g) for g in groups];variants=len(groups[0])
    x,mask=padded([p[0] for p in parts],pad_id,device,left=True)
    position=(mask.cumsum(-1)-1).clamp_min(0)
    cache=base.model(input_ids=x,attention_mask=mask,position_ids=position,use_cache=True).past_key_values
    cache.batch_repeat_interleave(variants)
    suffixes=[row for p in parts for row in p[1]]
    suffix,suffix_mask=padded(suffixes,pad_id,device)
    attention=torch.cat([mask.repeat_interleave(variants,dim=0),suffix_mask],-1)
    position=(attention.cumsum(-1)-1).clamp_min(0)[:,-suffix.shape[1]:]
    out=base.model(input_ids=suffix,attention_mask=attention,position_ids=position,
        past_key_values=cache,use_cache=True)
    last=out.last_hidden_state[torch.arange(len(suffixes),device=device),suffix_mask.sum(-1)-1]
    scores=torch.nn.functional.linear(last,head_weight).float().cpu().tolist()
    result=[scores[i*variants:(i+1)*variants] for i in range(len(groups))]
    return result,dict(prefix_tokens=sum(len(p[0]) for p in parts),
        total_full_tokens=sum(len(row) for g in groups for row in g),
        total_suffix_tokens=sum(len(row) for p in parts for row in p[1]))


def payload(row,path):
    original=evaluation_payload(row,path)
    # Change field order only; all original evidence, assumptions and scope stay.
    return {k:original[k] for k in ['cve','target','source_selected_path','assumptions','inventory_role','documents']}


def group_length_key(group,paths):
    """Input-only proxy for shared context length; never reads reference labels."""
    first=group[0]
    return (len(json.dumps(paths[first['cve']],ensure_ascii=False)),
            len(json.dumps(first['target'],ensure_ascii=False)),first['cve'])


def evaluate_prefix(args):
    import torch
    from src.item4.evaluation.synthetic_vex_benchmark import affected_precision
    begin=time.time();out=args.run/'evaluation';out.mkdir(parents=True,exist_ok=True)
    protocol=json.loads((args.run/'evaluation_protocol.json').read_text())
    for name,h in protocol['code_sha256'].items():
        if sha(args.run/name)!=h:raise ValueError('Frozen inference code changed: '+name)
    manifest=json.loads((args.run/'run_manifest.json').read_text())
    for name in ['inputs.jsonl','sources/cve_evidence.jsonl']:
        if sha(args.data/name)!=manifest['data_sha256'][name]:raise ValueError('Evaluation input changed')
    state=dict(status='running',stage='loading_trained_model',started_at=begin,total_cases=86926,total_cves=12418)
    def update(**kw):state.update(kw);atomic_json(out/'status.json',state)
    update();model,tok,base_info=load_model(args,False)
    paths={r['cve']:r.get('selected_path') for r in jsonl(args.data/'sources/cve_evidence.jsonl')}
    digits=[tok(str(i),add_special_tokens=False)['input_ids'] for i in range(7)]
    if any(len(x)!=1 for x in digits):raise ValueError('Digits are not single tokens')
    base=model.get_base_model();head_weight=base.lm_head.weight.index_select(0,torch.tensor([x[0] for x in digits],device='cuda'))
    config=dict(method='Trained 14B seven-way bounded next-token classification; all cases executed; common-prefix KV reuse',
        protocol=protocol,protocol_sha256=sha(args.run/'evaluation_protocol.json'),production_agent_mulval_pipeline=False,
        adapter_sha256=sha(args.run/'adapter/adapter_model.safetensors'),base=base_info,
        system_sha256=hashlib.sha256(SYSTEM.encode()).hexdigest(),choice_map=CHOICES,
        prefix_batch_cves=8,gold_access='Only after predictions close',test_used_for_selection=False,
        previous_execution_segments=protocol.get('previous_execution_segments',[]))
    atomic_json(out/'run_config.json',config)
    pred_path=out/'predictions.jsonl';completed={};cves=set();stats=Counter();parity=None
    if pred_path.exists():
        with pred_path.open('rb+') as handle:
            last=0
            while True:
                data=handle.readline()
                if not data:break
                try:r=json.loads(data)
                except ValueError:
                    handle.truncate(last);break
                if r['id'] in completed:raise ValueError('Duplicate prediction')
                completed[r['id']]=r;cves.add(r['cve']);last=handle.tell()
    strategy='sequential';batch_cves=8
    def sequences_for(groups):
        return [[tok(tok.apply_chat_template([dict(role='system',content=SYSTEM),
            dict(role='user',content=json.dumps(payload(row,paths[row['cve']]),ensure_ascii=False,
                separators=(',',':')))],tokenize=False,add_generation_prompt=True),
            add_special_tokens=False)['input_ids'] for row in group] for group in groups]
    if protocol.get('resource_autotune'):
        update(stage='benchmarking_resource_batches',completed_cases=len(completed),completed_cves=len(cves))
        probe=[];group=[];current=None
        for row in jsonl(args.data/'inputs.jsonl'):
            if current is not None and row['cve']!=current:
                if len(group)==7 and all(r['id'] in completed for r in group):probe.append(group)
                group=[]
                if len(probe)>=32:break
            current=row['cve'];group.append(row)
        if protocol.get('length_bucketing'):
            probe.sort(key=lambda g:group_length_key(g,paths))
        encoded_probe=sequences_for(probe);trials=[]
        for mode,n in [('sequential',8),('vectorized',8),('vectorized',16),('vectorized',32),('sequential',16),('sequential',32)]:
            if len(probe)<n:continue
            trial=dict(mode=mode,batch_cves=n)
            try:
                torch.cuda.synchronize();start=time.perf_counter()
                with torch.inference_mode(),torch.autocast('cuda',dtype=torch.bfloat16):
                    function=vectorized_prefix_logits if mode=='vectorized' else prefix_logits
                    values=[]
                    # All trials execute exactly the same probe cases; only
                    # physical batching changes, so throughput is comparable.
                    for start_index in range(0,len(encoded_probe),n):
                        part,_=function(base,encoded_probe[start_index:start_index+n],head_weight,tok.pad_token_id,'cuda')
                        values.extend(part)
                torch.cuda.synchronize();trial['seconds']=time.perf_counter()-start
                mismatches=0;maxdiff=0.
                for rows,logits_by_case in zip(probe,values):
                    for row,logits in zip(rows,logits_by_case):
                        old=completed[row['id']]
                        mismatches+=str(max(range(7),key=lambda i:logits[i]))!=old['raw_digit']
                        maxdiff=max(maxdiff,max(abs(a-b) for a,b in zip(logits,old['choice_logits'])))
                trial.update(choice_mismatches=mismatches,max_absolute_logit_difference=maxdiff,
                    cases_per_second=len(probe)*7/trial['seconds'],probe_cases=len(probe)*7,eligible=mismatches==0)
                del values
            except torch.cuda.OutOfMemoryError:
                trial.update(eligible=False,error='GPU_OOM')
            import gc;gc.collect();torch.cuda.empty_cache()
            trials.append(trial);atomic_json(out/'resource_tuning.json',dict(trials=trials,candidate_labels_opened=False))
            print(json.dumps(dict(resource_trial=trial)),flush=True)
        eligible=[t for t in trials if t.get('eligible')]
        if not eligible:raise ValueError('No resource batch preserves recorded model choices')
        best=max(eligible,key=lambda t:t['cases_per_second'])
        strategy=best['mode'];batch_cves=best['batch_cves']
        config.update(prefix_batch_cves=batch_cves,suffix_execution=strategy,
            resource_tuning=trials,resource_choice_basis='Throughput only, with zero choice mismatches versus saved model outputs; no candidate labels')
        config['length_bucketing']=bool(protocol.get('length_bucketing'))
        atomic_json(out/'run_config.json',config)
    def infer(groups,handle):
        nonlocal parity
        if not groups:return
        sequences=sequences_for(groups)
        try:
            with torch.inference_mode(),torch.autocast('cuda',dtype=torch.bfloat16):
                function=vectorized_prefix_logits if strategy=='vectorized' else prefix_logits
                scores,token_stats=function(base,sequences,head_weight,tok.pad_token_id,'cuda')
                if parity is None:
                    check=full_logits(base,sequences[0],head_weight,tok.pad_token_id,'cuda')
                    cached=torch.tensor(scores[0],device='cuda')
                    parity=dict(cases=7,max_absolute_logit_difference=float((check-cached).abs().max()),
                        choice_mismatches=int((check.argmax(-1)!=cached.argmax(-1)).sum()),
                        mathematical_operation='Equivalent causal next-token attention; kernel rounding can differ',
                        candidate_labels_opened=False)
                    if not torch.allclose(check,cached,rtol=.02,atol=.15):raise ValueError('Prefix-cache numerical parity failed: '+str(parity))
                    atomic_json(out/'prefix_parity.json',parity)
            for group,case_scores in zip(groups,scores):
                for row,logits in zip(group,case_scores):
                    if row['id'] in completed:continue
                    if not all(math_finite(x) for x in logits):raise ValueError('Nonfinite model score')
                    choice=max(range(7),key=lambda i:logits[i]);status,just=CHOICES[choice]
                    record=dict(id=row['id'],cve=row['cve'],status=status,justification=just,
                        raw_digit=str(choice),choice_logits=logits,model_inference=True,
                        execution_segment=protocol.get('execution_segment',1 if protocol.get('resource_autotune') else 0),
                        input_sha256=hashlib.sha256(json.dumps(payload(row,paths[row['cve']]),sort_keys=True,
                            ensure_ascii=False).encode()).hexdigest())
                    handle.write(json.dumps(record,separators=(',',':'))+'\n');completed[row['id']]=record;cves.add(row['cve'])
            handle.flush();os.fsync(handle.fileno());stats.update(token_stats)
            update(stage='inference',completed_cases=len(completed),completed_cves=len(cves),
                elapsed_seconds=time.time()-begin,token_computation=dict(stats),prefix_parity=parity)
            if len(cves)%128<len(groups):print(json.dumps(state),flush=True)
        except torch.cuda.OutOfMemoryError:
            torch.cuda.empty_cache()
            if len(groups)==1:raise
            middle=len(groups)//2;infer(groups[:middle],handle);infer(groups[middle:],handle)
    with pred_path.open('a',encoding='utf-8',newline='\n') as handle:
        batch=[];group=[];current=None;buffer=[]
        def flush_buffer():
            nonlocal buffer,batch
            if protocol.get('length_bucketing'):buffer.sort(key=lambda g:group_length_key(g,paths))
            for pending_group in buffer:
                batch.append(pending_group)
                if len(batch)>=batch_cves:infer(batch,handle);batch=[]
            buffer=[]
        for row in jsonl(args.data/'inputs.jsonl'):
            if current is not None and row['cve']!=current:
                if len(group)!=7:raise ValueError('CVE does not have exactly seven cases')
                if not all(r['id'] in completed for r in group):buffer.append(group)
                group=[]
                if len(buffer)>=(1024 if protocol.get('length_bucketing') else batch_cves):flush_buffer()
            current=row['cve'];group.append(row)
        if group:
            if len(group)!=7:raise ValueError('Last CVE incomplete')
            if not all(r['id'] in completed for r in group):buffer.append(group)
        flush_buffer()
        infer(batch,handle)
    if len(completed)!=86926 or len(cves)!=12418:raise ValueError('Full population not completed')
    labels=args.data/'candidate_labels.jsonl'
    if sha(labels)!=manifest['data_sha256']['candidate_labels.jsonl']:raise ValueError('Candidate reference changed')
    gold={r['id']:dict(r,actual_affected=r['candidate_actual_affected']) for r in jsonl(labels)}
    metric=affected_precision(completed,gold)
    per_variant={v:affected_precision({k:completed[k] for k,g in gold.items() if g['variant']==v},
        {k:g for k,g in gold.items() if g['variant']==v}) for v in sorted({g['variant'] for g in gold.values()})}
    report=dict(status='complete',population_cves=12418,cases=86926,all_cases=metric,per_variant=per_variant,
        reference='conditional_synthetic_candidate_labels_NOT_expert_gold',expert_review_complete=False,
        training=json.loads((args.run/'adapter/training_complete.json').read_text()),inference=config,
        prefix_parity=parity,token_computation=dict(stats),predictions_sha256=sha(pred_path),
        candidate_labels_sha256=sha(labels),elapsed_seconds=time.time()-begin)
    atomic_json(out/'report.json',report)
    update(status='complete',stage='scored',finished_at=time.time(),all_cases=metric)


def math_finite(value):
    import math
    return math.isfinite(value)
