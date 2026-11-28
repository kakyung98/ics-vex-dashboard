"""Resumable, separate QLoRA optimization over every TRAIN example of both roles.

Reads TRAIN labels only. Fixed one-epoch budget; no held-out model selection.
Optional cooperative H200 sharing has a strict allocator cap and checkpoints
before yielding when the incumbent source-repair job changes its phase.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter
from array import array
from pathlib import Path
import argparse,hashlib,json,math,os,random,sys,time,traceback

ROLES={'exploitation-prerequisites':'vep_extraction','operating-record-review':'operating_record_review'}


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(8*1024*1024),b''):h.update(block)
    return h.hexdigest()
def dump(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);tmp=path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8');tmp.replace(path)
def read_lines(path):
    with Path(path).open(encoding='utf-8') as stream:return [json.loads(s) for s in stream]


class YieldGPU(Exception):pass


def train(args):
    import torch
    from transformers import AutoTokenizer,AutoModelForCausalLM,set_seed
    from peft import LoraConfig,get_peft_model,prepare_model_for_kbit_training,get_peft_model_state_dict,set_peft_model_state_dict
    work=args.output;work.mkdir(parents=True,exist_ok=True)
    status_path=work/'status.json';started=time.time()
    status=dict(state='running',stage='validate_inputs',started_at=started,nli_used=False,
        independent_semantic_accuracy_verified=False,heldout_labels_loaded=False,
        dataset_population=12418,training_scope='Only grouped TRAIN partition; all TRAIN cases used')
    def status_update(**values):status.update(values);dump(status_path,status)
    status_update()
    if args.cooperative_status and args.cooperative_status.exists():
        incumbent=json.loads(args.cooperative_status.read_text())
        if incumbent.get('state')=='running' and incumbent.get('stage')!='source_label_repair':
            status_update(state='waiting_for_exclusive_gpu',stage='cooperative_yield');return 75
    manifest=json.loads((args.data/'manifest.json').read_text(encoding='utf-8'))
    if manifest['population_count']!=12418 or not manifest['all_cves_have_actual_examples_in_both_roles']:
        raise ValueError('Confirmed full population is required')
    if not json.loads((args.data/'integrity_audit.json').read_text())['passed']:raise ValueError('Dataset audit failed')
    pins=json.loads(args.base_pin.read_text(encoding='utf-8'))
    for name,expected in pins.items():
        if sha(args.base/name)!=expected:raise ValueError('Pinned shared base changed: '+name)
    set_seed(20261119);torch.set_num_threads(4)
    if not torch.cuda.is_available():raise RuntimeError('CUDA GPU is required')
    total=torch.cuda.get_device_properties(0).total_memory
    if args.memory_gib:torch.cuda.set_per_process_memory_fraction(min(.95,args.memory_gib*1024**3/total),0)
    status_update(stage='tokenization',device=torch.cuda.get_device_name(0),allocator_limit_gib=args.memory_gib)
    tok=AutoTokenizer.from_pretrained(str(args.base),local_files_only=True)
    if tok.pad_token_id is None:tok.pad_token=tok.eos_token
    encoded={};provenance={}
    for role in ROLES:
        ip=args.data/role/'train/inputs.jsonl';lp=args.data/role/'train/labels.jsonl'
        for path in (ip,lp):
            name=str(path.relative_to(args.data)).replace('\\','/')
            if sha(path)!=manifest['sha256'][name]:raise ValueError('Frozen training input changed')
        inputs=read_lines(ip);labels={r['id']:r for r in read_lines(lp)}
        if len(inputs)!=len(labels):raise ValueError('Training input/label mismatch')
        def reference_class(label):
            if role=='operating-record-review':return label['authority']['answer']
            scenarios=label['target']['scenarios']
            return 'source_bound' if any(s['product_keys'] for s in scenarios) else 'source_only' if scenarios else 'unresolved'
        classes=Counter(reference_class(r) for r in labels.values())
        rng=random.Random('20261119/'+role);rng.shuffle(inputs);items=[]
        for i,row in enumerate(inputs):
            if row['split']!='train' or labels[row['id']]['split']!='train':raise ValueError('Non-TRAIN data reached optimizer')
            messages=[dict(role='system',content=row['system']),dict(role='user',content=json.dumps(row['packet'],ensure_ascii=False,separators=(',',':')))]
            prefix=tok.apply_chat_template(messages,tokenize=False,add_generation_prompt=True)
            completion=json.dumps(labels[row['id']]['target'],ensure_ascii=False,separators=(',',':'))
            prefix_ids=tok(prefix,add_special_tokens=False)['input_ids']
            ids=prefix_ids+tok(completion+tok.eos_token,add_special_tokens=False)['input_ids']
            n=len(prefix_ids)
            if len(ids)>args.context_limit:
                raise ValueError('Context overflow; no case was dropped or truncated: '+row['cve']+' '+str(len(ids)))
            weight=min(16.,math.sqrt(len(inputs)/classes[reference_class(labels[row['id']])]))
            # Compact integer arrays keep the full corpus within the pod's RAM
            # limit; no token or example is truncated to obtain this reduction.
            items.append(dict(id=row['id'],cve=row['cve'],ids=array('i',ids),labels=array('i',[-100]*n+ids[n:]),weight=weight))
            if (i+1)%1000==0:status_update(tokenized_role=role,tokenized=i+1)
        if {r['cve'] for r in items}!={r['cve'] for r in inputs}:raise ValueError('A TRAIN CVE was omitted')
        encoded[role]=items
        provenance[role]=dict(role=role,train_examples=len(items),train_cves=len({r['cve'] for r in items}),
            train_inputs_sha256=sha(ip),train_labels_sha256=sha(lp),dataset_manifest_sha256=sha(args.data/'manifest.json'),
            ordered_case_ids_sha256=hashlib.sha256(json.dumps([r['id'] for r in items]).encode()).hexdigest(),
            dataset_population=manifest['population_count'],split_counts=manifest['split_counts'],
            heldout_loaded=False,expert_gold=False,synthetic_operating_records=True,source_supervision='automatic weak reference')
        provenance[role].update(reference_classes=dict(classes),loss_weighting='sqrt inverse TRAIN class frequency, capped at 16; no examples excluded')
        dump(work/ROLES[role]/'train_manifest.json',provenance[role])
    status_update(stage='loading_model',role_examples={r:len(v) for r,v in encoded.items()},
                  max_tokens={r:max(len(x['ids']) for x in v) for r,v in encoded.items()})
    model=AutoModelForCausalLM.from_pretrained(str(args.base),local_files_only=True,
        device_map={'':0},dtype=torch.bfloat16,attn_implementation='sdpa')
    model=prepare_model_for_kbit_training(model,use_gradient_checkpointing=True,gradient_checkpointing_kwargs={'use_reentrant':True})
    config=lambda:LoraConfig(r=4,lora_alpha=8,lora_dropout=.05,bias='none',task_type='CAUSAL_LM',target_modules=['q_proj','v_proj'])
    model=get_peft_model(model,config(),adapter_name=ROLES['exploitation-prerequisites'])
    set_seed(20261120);model.add_adapter(ROLES['operating-record-review'],config())
    for module in [model.get_input_embeddings(),model.get_output_embeddings()]:
        for parameter in module.parameters():
            if not parameter.requires_grad:parameter.data=parameter.data.to(torch.bfloat16)
    representation='pinned_4bit_base'
    if args.dequantize_frozen_base:
        # Exclusive H200 memory permits materializing the SAME pinned quantized
        # weights once, rather than dequantizing them on every training matmul.
        # Adapter serialization and final evaluation still use the pinned base.
        import bitsandbytes as bnb
        model.eval()
        probe=torch.tensor([encoded['exploitation-prerequisites'][0]['ids'][:128]],device='cuda')
        with torch.inference_mode(),torch.autocast('cuda',dtype=torch.bfloat16):
            before=model(input_ids=probe,use_cache=False,logits_to_keep=1).logits.float()
        replaced=0
        for name,module in list(model.named_modules()):
            if not isinstance(module,bnb.nn.Linear4bit):continue
            if module.weight.requires_grad:raise ValueError('Only frozen base weights may be materialized')
            weight=bnb.functional.dequantize_4bit(module.weight.data,module.weight.quant_state).to(torch.bfloat16)
            dense=torch.nn.Linear(module.in_features,module.out_features,bias=module.bias is not None,device='meta',dtype=torch.bfloat16)
            dense.weight=torch.nn.Parameter(weight,requires_grad=False)
            if module.bias is not None:dense.bias=torch.nn.Parameter(module.bias.detach().to(torch.bfloat16),requires_grad=False)
            parent,_,leaf=name.rpartition('.');setattr(model.get_submodule(parent),leaf,dense);replaced+=1
        if not replaced:raise RuntimeError('No pinned quantized linear weights found')
        with torch.inference_mode(),torch.autocast('cuda',dtype=torch.bfloat16):
            after=model(input_ids=probe,use_cache=False,logits_to_keep=1).logits.float()
        delta=float((before-after).abs().max())
        if not bool(torch.isfinite(after).all()) or not torch.allclose(before,after,rtol=.05,atol=.1):
            raise ValueError('Materialized-base numerical parity check failed: '+str(delta))
        representation='bfloat16_materialization_of_pinned_4bit_weights'
        dump(work/'base_representation.json',dict(representation=representation,replaced_linears=replaced,
            train_prefix_probe_tokens=128,max_absolute_logit_difference=delta,
            evaluation_base='original pinned quantized base',base_files_sha256=pins))
        del probe,before,after,weight,module,dense
        torch.cuda.empty_cache()
    if args.cpu_embedding:model.get_input_embeddings().to('cpu')
    model.config.use_cache=False
    params={r:[p for name,p in model.named_parameters() if '.'+alias+'.' in name] for r,alias in ROLES.items()}
    if any(not p for p in params.values()):raise RuntimeError('Role adapter has no trainable matrices')
    optimizers={r:torch.optim.AdamW(p,lr=1e-4) for r,p in params.items()}
    cursors={r:0 for r in ROLES};updates={r:0 for r in ROLES};loss_sums={r:0. for r in ROLES};batch_size=args.batch_size
    def weight_hash(role):
        h=hashlib.sha256()
        for key,value in sorted(get_peft_model_state_dict(model,adapter_name=ROLES[role]).items()):
            h.update(key.encode());h.update(value.detach().cpu().float().numpy().tobytes())
        return h.hexdigest()
    initial={r:weight_hash(r) for r in ROLES}
    checkpoint=work/'checkpoint.pt'
    if checkpoint.exists():
        saved=torch.load(checkpoint,map_location='cpu',weights_only=False)
        if saved['dataset_manifest_sha256']!=sha(args.data/'manifest.json'):raise ValueError('Resume dataset differs')
        for role,alias in ROLES.items():
            set_peft_model_state_dict(model,saved['adapters'][role],adapter_name=alias)
            optimizers[role].load_state_dict(saved['optimizers'][role])
            for state in optimizers[role].state.values():
                for key,value in state.items():
                    if isinstance(value,torch.Tensor):state[key]=value.to('cuda')
        cursors=saved['cursors'];updates=saved['updates'];initial=saved['initial'];loss_sums=saved['loss_sums'];batch_size=saved['batch_size']
        if args.resume_batch_size:batch_size=args.resume_batch_size
        torch.set_rng_state(saved['torch_rng']);torch.cuda.set_rng_state_all(saved['cuda_rng'])
    def save():
        payload=dict(dataset_manifest_sha256=sha(args.data/'manifest.json'),cursors=cursors,updates=updates,
            initial=initial,loss_sums=loss_sums,batch_size=batch_size,
            adapters={r:{k:v.detach().cpu() for k,v in get_peft_model_state_dict(model,adapter_name=a).items()} for r,a in ROLES.items()},
            optimizers={r:o.state_dict() for r,o in optimizers.items()},torch_rng=torch.get_rng_state(),cuda_rng=torch.cuda.get_rng_state_all())
        tmp=checkpoint.with_suffix('.tmp');torch.save(payload,tmp);tmp.replace(checkpoint)
    def cooperative_check():
        if args.cooperative_status and args.cooperative_status.exists():
            incumbent=json.loads(args.cooperative_status.read_text())
            if incumbent.get('state')=='running' and incumbent.get('stage')!='source_label_repair':
                raise YieldGPU('Incumbent GPU task moved beyond its steady-memory source-label phase')
    try:
        model.train();status_update(stage='training',completed=cursors,optimizer_updates=updates)
        while any(cursors[r]<len(encoded[r]) for r in ROLES):
            for role,alias in ROLES.items():
                if cursors[role]>=len(encoded[role]):continue
                cooperative_check();model.set_adapter(alias)
                start=cursors[role];rows=encoded[role][start:start+batch_size]
                while len(rows)>1 and len(rows)*max(len(r['ids']) for r in rows)>args.batch_token_limit:rows=rows[:-1]
                n=len(rows);width=max(len(r['ids']) for r in rows)
                x=torch.full((n,width),tok.pad_token_id,dtype=torch.long,device='cuda')
                y=torch.full_like(x,-100);attention=torch.zeros_like(x)
                for i,row in enumerate(rows):
                    size=len(row['ids']);x[i,:size]=torch.tensor(row['ids'],device='cuda');y[i,:size]=torch.tensor(row['labels'],device='cuda');attention[i,:size]=1
                optimizer=optimizers[role];optimizer.zero_grad(set_to_none=True)
                # Express the fixed warmup/cosine schedule in examples so a
                # resource-driven batch resize does not consume the budget early.
                progress=(start+n)/len(encoded[role])
                factor=progress/.03 if progress<.03 else .5*(1+math.cos(math.pi*min(1.,(progress-.03)/.97)))
                for group in optimizer.param_groups:group['lr']=1e-4*factor
                try:
                    with torch.autocast('cuda',dtype=torch.bfloat16):
                        base=model.get_base_model();embedding=base.get_input_embeddings()
                        embedded=embedding(x.to(embedding.weight.device)).to('cuda')
                        out=base.model(inputs_embeds=embedded,attention_mask=attention,use_cache=False)
                        mask=y[:,1:]!=-100;hidden=out.last_hidden_state[:,:-1,:][mask]
                        logits=base.lm_head(hidden)
                        per_token=torch.nn.functional.cross_entropy(logits.float(),y[:,1:][mask],reduction='none')
                        row_weights=torch.tensor([r['weight'] for r in rows],device='cuda')
                        weights=row_weights[:,None].expand(n,width-1)[mask]
                        loss=(per_token*weights).sum()/weights.sum()
                    if not bool(torch.isfinite(loss)):raise RuntimeError('Nonfinite role loss')
                    scalar=float(loss.detach());loss.backward()
                    norm=torch.nn.utils.clip_grad_norm_(params[role],1.)
                    if not bool(torch.isfinite(norm)):raise RuntimeError('Nonfinite role gradient')
                    optimizer.step();optimizer.zero_grad(set_to_none=True)
                    cursors[role]+=n;updates[role]+=1;loss_sums[role]+=scalar
                    del embedded,out,mask,hidden,logits,loss,per_token,row_weights,weights,x,y,attention
                except torch.cuda.OutOfMemoryError:
                    optimizer.zero_grad(set_to_none=True)
                    if batch_size==1:raise
                    embedded=out=mask=hidden=logits=loss=per_token=row_weights=weights=x=y=attention=None
                    import gc
                    gc.collect();batch_size=max(1,batch_size//2);torch.cuda.empty_cache()
                    status_update(oom_retry_batch_size=batch_size);continue
                elapsed=time.time()-started;done=sum(cursors.values());total_examples=sum(len(v) for v in encoded.values())
                status_update(stage='training',current_role=role,completed=dict(cursors),optimizer_updates=dict(updates),
                    mean_loss={r:loss_sums[r]/max(1,updates[r]) for r in ROLES},batch_size=batch_size,
                    elapsed_seconds=elapsed,eta_seconds=elapsed/max(1,done)*(total_examples-done),
                    allocated_vram_gib=round(torch.cuda.memory_allocated()/1024**3,2))
                if sum(updates.values())%100==0:
                    save();print(json.dumps(dict(completed=cursors,updates=updates)),flush=True)
        save();model.eval()
        for role,alias in ROLES.items():
            folder=work/alias;folder.mkdir(exist_ok=True)
            export=work/'export';model.save_pretrained(str(export),selected_adapters=[alias])
            import shutil
            for file in (export/alias).iterdir():
                if file.is_file():shutil.copyfile(file,folder/file.name)
            final=weight_hash(role)
            if final==initial[role] or not updates[role] or cursors[role]!=len(encoded[role]):raise RuntimeError('Incomplete role optimization')
            dump(folder/'training_complete.json',dict(role=role,base=str(args.base),model='Qwen2.5-Coder-14B-Instruct',
                adapter_sha256=sha(folder/'adapter_model.safetensors'),train_manifest_sha256=sha(folder/'train_manifest.json'),
                initial_trainable_sha256=initial[role],final_trainable_sha256=final,optimizer_updates=updates[role],
                examples=cursors[role],trained_cves=provenance[role]['train_cves'],dataset_population=12418,
                epochs=1,rank=4,target_modules=['q_proj','v_proj'],heldout_loaded=False,nli_used=False,
                batch_size=batch_size,context_limit=args.context_limit,training_device=torch.cuda.get_device_name(0),
                allocator_limit_gib=args.memory_gib,batch_token_limit=args.batch_token_limit,
                training_base_representation=representation,evaluation_base_representation='original_pinned_4bit_base',
                weak_source_supervision=True,synthetic_operating_training=True,independent_semantic_accuracy_verified=False,
                base_files_sha256=pins,mean_training_loss=loss_sums[role]/updates[role]))
        status_update(state='complete',stage='trained',completed=cursors,optimizer_updates=updates,finished_at=time.time())
    except YieldGPU as exc:
        save();status_update(state='waiting_for_exclusive_gpu',stage='cooperative_yield',reason=str(exc));return 75
    except Exception:
        save();status_update(state='failed',error=traceback.format_exc());raise
    return 0


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data',type=Path,required=True);p.add_argument('--base',type=Path,required=True)
    p.add_argument('--base-pin',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--batch-size',type=int,default=4);p.add_argument('--context-limit',type=int,default=8192)
    p.add_argument('--memory-gib',type=float,default=32);p.add_argument('--cpu-embedding',action='store_true')
    p.add_argument('--cooperative-status',type=Path)
    p.add_argument('--resume-batch-size',type=int,default=0)
    p.add_argument('--batch-token-limit',type=int,default=32000)
    p.add_argument('--dequantize-frozen-base',action='store_true')
    args=p.parse_args()
    try:raise SystemExit(train(args))
    except Exception:
        dump(args.output/'failure.json',dict(error=traceback.format_exc(),training_complete=False));raise
