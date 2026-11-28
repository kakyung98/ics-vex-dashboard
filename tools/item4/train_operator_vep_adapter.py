"""Fixed-budget corrective continuation and synthetic contract evaluation.

Training reads only TRAIN rows. The unchanged parent VEP adapter was trained on
8,692 real-CVE weak references; this continuation uses fictional contrast cases.
"""
from pathlib import Path
from types import SimpleNamespace
from collections import Counter
import argparse,hashlib,json,math,random,sys,time,traceback
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(8*1024*1024),b''):h.update(block)
    return h.hexdigest()

def dump(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n');tmp.replace(path)

def rows(path):return [json.loads(line) for line in Path(path).read_text().splitlines()]

def run(args):
    import torch
    from transformers import AutoModelForCausalLM,AutoTokenizer,set_seed
    from peft import PeftModel,prepare_model_for_kbit_training,get_peft_model_state_dict
    from src.item4.analysis import exploitation_prerequisites as V
    from src.common.data.prerequisite_research_schema import enrich
    from src.common.runtime.json_output_constraints import prefix_for_schema
    status=dict(action=args.action,state='running',started_at=time.time(),policy=V.VERSION)
    def update(**values):status.update(values);dump(args.output/(args.action+'_status.json'),status)
    update(stage='validate_inputs')
    manifest=json.loads((args.data/'manifest.json').read_text())
    pins=json.loads(args.base_pin.read_text())
    for name,expected in pins.items():
        if sha(args.base/name)!=expected:raise ValueError('Pinned base fingerprint differs: '+name)
    split='train' if args.action=='train' else 'test';path=args.data/(split+'.jsonl')
    if sha(path)!=manifest['sha256'][path.name]:raise ValueError('Curriculum fingerprint differs')
    data=rows(path)
    set_seed(20261119);torch.set_num_threads(4)
    torch.cuda.set_per_process_memory_fraction(min(.95,112*1024**3/torch.cuda.get_device_properties(0).total_memory))
    tok=AutoTokenizer.from_pretrained(args.base,local_files_only=True,padding_side='left')
    if tok.pad_token_id is None:tok.pad_token=tok.eos_token
    update(stage='loading_base',examples=len(data))
    base=AutoModelForCausalLM.from_pretrained(args.base,local_files_only=True,device_map={'':0},dtype=torch.bfloat16,attn_implementation='sdpa')
    parent=args.parent if args.action=='train' else args.output/'vep_extraction'
    marker=json.loads((parent/'training_complete.json').read_text())
    if marker['adapter_sha256']!=sha(parent/'adapter_model.safetensors'):raise ValueError('Parent adapter fingerprint differs')
    if args.action=='train':base=prepare_model_for_kbit_training(base,use_gradient_checkpointing=True,gradient_checkpointing_kwargs={'use_reentrant':True})
    model=PeftModel.from_pretrained(base,parent,adapter_name='vep_extraction',is_trainable=args.action=='train')
    if args.action=='train':
        # Materialize the same pinned quantized base once on the exclusive H200.
        import bitsandbytes as bnb
        for module in (model.get_input_embeddings(),model.get_output_embeddings()):
            for parameter in module.parameters():
                if not parameter.requires_grad:parameter.data=parameter.data.to(torch.bfloat16)
        replaced=0
        for name,module in list(model.named_modules()):
            if not isinstance(module,bnb.nn.Linear4bit):continue
            if module.weight.requires_grad:raise ValueError('Only frozen base weights may be materialized')
            weight=bnb.functional.dequantize_4bit(module.weight.data,module.weight.quant_state).to(torch.bfloat16)
            dense=torch.nn.Linear(module.in_features,module.out_features,bias=module.bias is not None,device='meta',dtype=torch.bfloat16)
            dense.weight=torch.nn.Parameter(weight,requires_grad=False)
            if module.bias is not None:dense.bias=torch.nn.Parameter(module.bias.detach().to(torch.bfloat16),requires_grad=False)
            prefix,_,leaf=name.rpartition('.');setattr(model.get_submodule(prefix),leaf,dense);replaced+=1
        if not replaced:raise ValueError('Expected pinned quantized base linears')
        encoded=[]
        for row in data:
            messages=[dict(role='system',content=row['system']),dict(role='user',content=json.dumps(row['packet'],separators=(',',':')))]
            prompt=tok.apply_chat_template(messages,tokenize=False,add_generation_prompt=True)
            text=tok.apply_chat_template(messages+[dict(role='assistant',content=json.dumps(row['target'],separators=(',',':')))],tokenize=False)
            prefix=tok(prompt,add_special_tokens=False).input_ids;tokens=tok(text,add_special_tokens=False).input_ids
            if tokens[:len(prefix)]!=prefix or len(tokens)>8192:raise ValueError('Training context/prefix mismatch; no truncation')
            encoded.append((tokens,[-100]*len(prefix)+tokens[len(prefix):]))
        train_manifest=dict(role='exploitation-prerequisites',policy=V.VERSION,dataset_manifest_sha256=sha(args.data/'manifest.json'),
            train_file_sha256=sha(path),train_examples=len(data),epochs=args.epochs,synthetic=all(r.get('synthetic') for r in data),heldout_loaded=False,
            real_description_examples=sum(not r.get('synthetic') for r in data),
            parent_adapter_sha256=marker['adapter_sha256'],parent_training_manifest_sha256=marker['train_manifest_sha256'],
            parent_trained_cves=marker.get('trained_cves'),supervision=manifest.get('annotation_method','Synthetic contrast curriculum')+'; not independent expert Gold')
        folder=args.output/'vep_extraction';dump(folder/'train_manifest.json',train_manifest)
        parameters=[p for p in model.parameters() if p.requires_grad]
        def weight_digest():
            h=hashlib.sha256()
            for k,v in sorted(get_peft_model_state_dict(model,adapter_name='vep_extraction').items()):h.update(k.encode());h.update(v.detach().float().cpu().numpy().tobytes())
            return h.hexdigest()
        initial=weight_digest();optimizer=torch.optim.AdamW(parameters,lr=5e-5)
        work=encoded*args.epochs;random.Random(20261119).shuffle(work);model.train();model.config.use_cache=False
        losses=[];batch_size=8;cursor=0;updates=0
        while cursor<len(work):
            batch=work[cursor:cursor+batch_size];width=max(len(x[0]) for x in batch)
            x=torch.full((len(batch),width),tok.pad_token_id,dtype=torch.long,device='cuda');y=torch.full_like(x,-100);attention=torch.zeros_like(x)
            for i,(ids,labels) in enumerate(batch):
                x[i,:len(ids)]=torch.tensor(ids,device='cuda');y[i,:len(ids)]=torch.tensor(labels,device='cuda');attention[i,:len(ids)]=1
            optimizer.zero_grad(set_to_none=True)
            progress=(cursor+len(batch))/len(work)
            for g in optimizer.param_groups:g['lr']=5e-5*min(1.,progress/.05)*.5*(1+math.cos(math.pi*progress))
            try:
                with torch.autocast('cuda',dtype=torch.bfloat16):
                    base=model.get_base_model();out=base.model(input_ids=x,attention_mask=attention,use_cache=False)
                    mask=y[:,1:]!=-100;logits=base.lm_head(out.last_hidden_state[:,:-1,:][mask])
                    loss=torch.nn.functional.cross_entropy(logits.float(),y[:,1:][mask])
                if not torch.isfinite(loss):raise ValueError('Nonfinite loss')
                losses.append(float(loss.detach()));loss.backward()
                norm=torch.nn.utils.clip_grad_norm_(parameters,1.)
                if not torch.isfinite(norm):raise ValueError('Nonfinite gradient')
                optimizer.step();cursor+=len(batch);updates+=1
                del x,y,attention,out,mask,logits,loss
            except torch.cuda.OutOfMemoryError:
                optimizer.zero_grad(set_to_none=True)
                x=y=attention=out=mask=logits=loss=None
                import gc;gc.collect();torch.cuda.empty_cache()
                if batch_size==1:raise
                batch_size=max(1,batch_size//2);continue
            update(stage='training',completed=cursor,total=len(work),optimizer_updates=updates,batch_size=batch_size,mean_loss=sum(losses)/len(losses),elapsed_seconds=time.time()-status['started_at'])
        final=weight_digest()
        if final==initial:raise ValueError('Adapter did not change')
        model.save_pretrained(args.output/'export',selected_adapters=['vep_extraction'])
        import shutil
        for file in (args.output/'export/vep_extraction').iterdir():
            if file.is_file():shutil.copyfile(file,folder/file.name)
        dump(folder/'training_complete.json',dict(role='exploitation-prerequisites',base=str(args.base),model='Qwen2.5-Coder-14B-Instruct',
            adapter_sha256=sha(folder/'adapter_model.safetensors'),train_manifest_sha256=sha(folder/'train_manifest.json'),
            optimizer_updates=updates,examples=len(data),epochs=args.epochs,heldout_loaded=False,
            real_description_examples=sum(not r.get('synthetic') for r in data),synthetic_boundary_examples=sum(bool(r.get('synthetic')) for r in data),
            initial_trainable_sha256=initial,final_trainable_sha256=final,base_files_sha256=pins,extraction_policy=V.VERSION,
            parent_adapter_sha256=marker['adapter_sha256'],parent_trained_cves=marker.get('trained_cves'),
            independent_semantic_accuracy_verified=False,training_device=torch.cuda.get_device_name(0)))
        update(state='complete',stage='trained',optimizer_updates=updates);return
    model.eval();model.config.use_cache=True
    # cuDNN SDPA plan selection stalled on an H200 evaluation prefill shape.
    # Keep the same pinned weights, dtype and math; permit Flash/Efficient/Math.
    if hasattr(torch.backends.cuda,'enable_cudnn_sdp'):torch.backends.cuda.enable_cudnn_sdp(False)
    if args.diagnostic_trace:
        original_sdpa=torch.nn.functional.scaled_dot_product_attention
        observed=[False]
        def checked_sdpa(query,key,value,**kwargs):
            if not observed[0]:
                print('SDPA_DIAGNOSTIC',query.device,query.dtype,tuple(query.shape),tuple(key.shape),'cudnn_disabled',flush=True);observed[0]=True
            return original_sdpa(query,key,value,**kwargs)
        torch.nn.functional.scaled_dot_product_attention=checked_sdpa
    runtime=SimpleNamespace(tok=tok);predictions=[];started=time.time();batch_size=8
    checkpoint=args.output/'evaluation_checkpoint.json'
    fingerprint=dict(adapter_sha256=marker['adapter_sha256'],dataset_manifest_sha256=sha(args.data/'manifest.json'),generation_constraint_sha256=sha(Path(__file__).resolve().parents[2]/'src/common/runtime/json_output_constraints.py'))
    if args.resume_evaluation:
        prior=json.loads(checkpoint.read_text())
        if prior['fingerprint']!=fingerprint or prior['predictions_sha256']!=sha(args.output/'predictions.json'):raise ValueError('Evaluation resume fingerprint differs')
        predictions=json.loads((args.output/'predictions.json').read_text())
        if [r['id'] for r in predictions]!=[r['id'] for r in data[:len(predictions)]]:raise ValueError('Evaluation resume IDs differ')
    if args.diagnostic_trace:
        import faulthandler
        faulthandler.dump_traceback_later(45,repeat=True)
    for offset in range(len(predictions),len(data),batch_size):
        update(stage='heldout_generation',completed=len(predictions),total=len(data),active_batch_start=offset)
        batch=data[offset:offset+batch_size]
        prompts=[tok.apply_chat_template([dict(role='system',content=r['system']),dict(role='user',content=json.dumps(r['packet'],separators=(',',':')))],tokenize=False,add_generation_prompt=True) for r in batch]
        encoded=tok(prompts,return_tensors='pt',padding=True,add_special_tokens=False).to('cuda')
        constraints=[prefix_for_schema(runtime,r['packet']['schema']) for r in batch]
        heartbeat=[-1]
        def allowed_tokens(bi,ids):
            produced=len(ids)-encoded.input_ids.shape[1]
            if bi==0 and produced//100>heartbeat[0]:
                heartbeat[0]=produced//100
                update(stage='heldout_generation',completed=len(predictions),total=len(data),active_batch_start=offset,generated_tokens=produced)
            return constraints[bi](bi,ids)
        with torch.inference_mode():
            generated=model.generate(**encoded,do_sample=False,max_new_tokens=1800,pad_token_id=tok.pad_token_id,prefix_allowed_tokens_fn=allowed_tokens,logits_to_keep=1,use_cache=True)
        for i,row in enumerate(batch):predictions.append(dict(id=row['id'],text=tok.decode(generated[i,encoded.input_ids.shape[1]:],skip_special_tokens=True)))
        dump(args.output/'predictions.json',predictions)
        dump(checkpoint,dict(fingerprint=fingerprint,predictions_sha256=sha(args.output/'predictions.json'),completed=len(predictions)))
        update(stage='heldout_generation',completed=len(predictions),total=len(data),elapsed_seconds=time.time()-started)
    counts=Counter()
    for row,pred in zip(data,predictions):
        expected=row['target'];valid=False;actual=None
        try:
            actual=enrich(json.loads(pred['text']));record={k:row['packet'][k] for k in ('cve','sources','products')}
            V.validate(V.resolve_references(actual,row['packet']),record);valid=True
        except Exception as e:pred['validation_error']=str(e)
        counts['total']+=1;counts['valid']+=valid
        if expected['prerequisites']:
            counts['positive_cases']+=1;counts['positive_cases_recovered']+=valid and bool(actual['prerequisites'])
        if row['family']=='defect_only':
            counts['defect_cases']+=1;counts['admitted_defect_cases']+=valid and bool(actual['prerequisites'])
        if row['family'] in ('negative','and_not'):
            counts['negative_cases']+=1;counts['valid_negative_cases']+=valid and bool(actual['scenarios'])
    report=dict(state='complete',policy=V.VERSION,counts=dict(counts),adapter_sha256=marker['adapter_sha256'],
        dataset_manifest_sha256=sha(args.data/'manifest.json'),synthetic=all(r.get('synthetic') for r in data),expert_gold=False,
        real_description_cases=sum(not r.get('synthetic') for r in data),synthetic_boundary_cases=sum(bool(r.get('synthetic')) for r in data),
        evaluation_attention_backend='SDPA with cuDNN disabled after H200 plan-selection stall',
        independent_real_asset_accuracy_verified=False,thresholds=dict(valid_rate=.9,positive_case_recovery=.8,admitted_defects=0,valid_negative_rate=1.))
    report['passed']=(counts['valid']/counts['total']>=.9 and counts['positive_cases_recovered']/counts['positive_cases']>=.8 and counts['admitted_defect_cases']==0 and counts['valid_negative_cases']==counts['negative_cases'])
    dump(args.output/'evaluation.json',report);dump(args.output/'predictions.json',predictions)
    update(state='complete',stage='evaluated',passed=report['passed'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['train','evaluate'])
    p.add_argument('--epochs',type=int,default=2);p.add_argument('--resume-evaluation',action='store_true');p.add_argument('--diagnostic-trace',action='store_true')
    for name in ('data','base','base-pin','parent','output'):p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args()
    try:run(args)
    except Exception:
        dump(args.output/(args.action+'_status.json'),dict(state='failed',error=traceback.format_exc()));raise
