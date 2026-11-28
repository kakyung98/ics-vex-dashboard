"""Greedy rolling batches using HF's prefill, processors and DynamicCache.

Finished requests leave immediately; waiting prompts refill vacated slots.
Masks and RoPE positions retain each request's own history. Output limits are
per request. Source-specific semantic validation remains outside this scheduler.
"""


def capture_prefill(model,input_ids,logits_processor,stopping_criteria,generation_config,
                    synced_gpus=False,streamer=None,**model_kwargs):
    import torch
    outputs=model._prefill(input_ids,generation_config,model_kwargs,is_first_iteration=True)
    model_kwargs=model._update_model_kwargs_for_generation(outputs,model_kwargs,is_encoder_decoder=False)
    scores=logits_processor(input_ids,outputs.logits[:,-1].to(copy=True,dtype=torch.float32))
    tokens=scores.argmax(-1)
    ids=torch.cat([input_ids,tokens[:,None]],dim=-1)
    return dict(ids=ids,kwargs=model_kwargs,processors=logits_processor)


def merge_states(ids,kwargs,processors,new,pad):
    import torch
    import torch.nn.functional as F
    other_ids=new['ids'];other_kwargs=new['kwargs']
    width=max(ids.shape[1],other_ids.shape[1])
    merged_ids=torch.cat([F.pad(ids,(width-ids.shape[1],0),value=pad),
                          F.pad(other_ids,(width-other_ids.shape[1],0),value=pad)],dim=0)
    if kwargs.get('inputs_embeds') is not None or other_kwargs.get('inputs_embeds') is not None:
        raise ValueError('Rolling cache requires text-only inputs')
    a=kwargs['past_key_values'];b=other_kwargs['past_key_values']
    if len(a.layers)!=len(b.layers):raise ValueError('Mismatched rolling cache layers')
    past=width-1
    for left,right in zip(a.layers,b.layers):
        if left.is_sliding or right.is_sliding:raise ValueError('Sliding-window cache is not supported')
        for name in ('keys','values'):
            x=getattr(left,name);y=getattr(right,name)
            setattr(left,name,torch.cat([F.pad(x,(0,0,past-x.shape[-2],0)),
                                         F.pad(y,(0,0,past-y.shape[-2],0))],dim=0))
    for key in ('attention_mask','position_ids','token_type_ids'):
        x=kwargs.get(key);y=other_kwargs.get(key)
        if x is None and y is None:continue
        if x is None or y is None or x.ndim!=2 or y.ndim!=2:
            raise ValueError('Mismatched rolling sequence field: '+key)
        kwargs[key]=torch.cat([F.pad(x,(width-x.shape[1],0),value=1 if key=='position_ids' else 0),
                              F.pad(y,(width-y.shape[1],0),value=1 if key=='position_ids' else 0)],dim=0)
    if len(processors)!=len(new['processors']):raise ValueError('Mismatched rolling logits processors')
    for p,q in zip(processors,new['processors']):
        if type(p)!=type(q):raise ValueError('Mismatched rolling logits processor types')
        if hasattr(p,'matchers') and hasattr(p,'token_bitmask'):
            p.matchers.extend(q.matchers);p.compiled_grammars.extend(q.compiled_grammars)
            p.token_bitmask=torch.cat([p.token_bitmask,q.token_bitmask],dim=0)
            p.batch_size=len(p.matchers)
        elif type(p).__name__!='RepetitionPenaltyLogitsProcessor':
            raise TypeError('Unreviewed rolling processor: '+type(p).__name__)
        elif p.penalty!=q.penalty or getattr(p,'prompt_ignore_length',0):
            raise ValueError('Rolling repetition penalty configuration differs')
    return merged_ids,kwargs


def rolling_sample(model,input_ids,logits_processor,stopping_criteria,generation_config,
                   synced_gpus=False,streamer=None,on_generated=None,refill=None,
                   capacity=64,**model_kwargs):
    import torch
    from tools.item4.item4_compact_decode import select_processor_rows
    if generation_config.do_sample or synced_gpus or streamer is not None or model.config.is_encoder_decoder:
        raise ValueError('Rolling decode requires single-GPU decoder-only greedy inference')
    initial=input_ids.clone();batch=input_ids.shape[0]
    owners=torch.arange(batch,device=input_ids.device)
    counts=torch.zeros(batch,dtype=torch.long,device=input_ids.device)
    first_outputs=[None]*batch
    pad=int(generation_config._pad_token_tensor)
    budget=generation_config.max_new_tokens
    if not budget:raise ValueError('Explicit per-request output budget is required')
    outputs=model._prefill(input_ids,generation_config,model_kwargs,is_first_iteration=True)
    prefilled=False;steps=0
    with model._optimize_model_for_decode():
        while len(owners):
            if prefilled:
                prepared=model.prepare_inputs_for_generation(input_ids,next_sequence_length=1,**model_kwargs)
                outputs=model(**prepared,return_dict=True)
            prefilled=True
            model_kwargs=model._update_model_kwargs_for_generation(outputs,model_kwargs,is_encoder_decoder=False)
            scores=logits_processor(input_ids,outputs.logits[:,-1].to(copy=True,dtype=torch.float32))
            tokens=scores.argmax(-1);del outputs,scores
            input_ids=torch.cat([input_ids,tokens[:,None]],dim=-1);counts+=1;steps+=1
            done=counts>=budget
            for criterion in stopping_criteria:
                if type(criterion).__name__!='MaxLengthCriteria':done|=criterion(input_ids,None)
            if bool(done.any()):
                for row in done.nonzero(as_tuple=False).flatten().tolist():
                    owner=int(owners[row]);generated=input_ids[row,-int(counts[row]):].detach().clone()
                    if owner<batch:first_outputs[owner]=generated
                    if on_generated is not None:on_generated(owner,generated)
                keep=(~done).nonzero(as_tuple=False).flatten()
                if not len(keep):break
                model_kwargs['past_key_values'].batch_select_indices(keep)
                for key in ('attention_mask','position_ids','token_type_ids'):
                    if model_kwargs.get(key) is not None:model_kwargs[key]=model_kwargs[key].index_select(0,keep)
                select_processor_rows(logits_processor,keep)
                input_ids=input_ids.index_select(0,keep);owners=owners.index_select(0,keep);counts=counts.index_select(0,keep)
                # Remove padding common to every remaining request. This bounds
                # cache width by actual live context, independent of job duration.
                mask=model_kwargs['attention_mask']
                trim=int((mask==0).long().cumprod(-1).sum(-1).min())
                if trim:
                    input_ids=input_ids[:,trim:]
                    for key in ('attention_mask','position_ids','token_type_ids'):
                        if model_kwargs.get(key) is not None:model_kwargs[key]=model_kwargs[key][:,trim:]
                    for layer in model_kwargs['past_key_values'].layers:
                        layer.keys=layer.keys[...,trim:,:];layer.values=layer.values[...,trim:,:]
            if refill is not None and steps%8==0 and len(owners)<=capacity-8:
                incoming=refill(min(8,capacity-len(owners)))
                if incoming is not None:
                    new=model.generate(**incoming['encoded'],generation_config=generation_config,max_new_tokens=budget,do_sample=False,
                        pad_token_id=pad,use_cache=True,logits_to_keep=1,
                        logits_processor=incoming['processors'],custom_generate=capture_prefill)
                    input_ids,model_kwargs=merge_states(input_ids,model_kwargs,logits_processor,new,pad)
                    owners=torch.cat([owners,owners.new_tensor(incoming['owners'])])
                    counts=torch.cat([counts,counts.new_ones(len(incoming['owners']))])
    if not all(row is not None for row in first_outputs):raise RuntimeError('Original rolling requests did not finish')
    length=max(len(r) for r in first_outputs)
    result=initial.new_full((batch,initial.shape[1]+length),pad);result[:,:initial.shape[1]]=initial
    for owner,row in enumerate(first_outputs):result[owner,initial.shape[1]:initial.shape[1]+len(row)]=row
    return result
