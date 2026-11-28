"""DEV-only supervised continuation; no TEST source, labels or predictions loaded."""
from pathlib import Path
from copy import deepcopy
import sys,json,hashlib,argparse,random,time,re
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.evaluation import metamorphic_synthetic as E


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    p=path.with_suffix('.tmp');p.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8');p.replace(path)


def response_tokens(tokenizer,value):
    text=json.dumps(value,ensure_ascii=False)
    encoded=tokenizer(text,add_special_tokens=False,return_offsets_mapping=True)
    labels=list(encoded['input_ids'])
    spans=[m.span(1) for m in re.finditer(r'"extraction_confidence"\s*:\s*([0-9]+(?:\.[0-9]+)?)',text)]
    for i,(a,b) in enumerate(encoded['offset_mapping']):
        if any(a<end and b>start for start,end in spans):labels[i]=-100
    return encoded['input_ids']+[tokenizer.eos_token_id],labels+[tokenizer.eos_token_id]


def wire_order(value,schema,root=None):
    """Match schema-constrained decoding order without changing any labels."""
    root=schema if root is None else root
    if '$ref' in schema:
        resolved=root
        for part in schema['$ref'].removeprefix('#/').split('/'):resolved=resolved[part.replace('~1','/').replace('~0','~')]
        return wire_order(value,resolved,root)
    if 'oneOf' in schema and isinstance(value,dict):
        for branch in schema['oneOf']:
            props=branch.get('properties',{})
            if not set(branch.get('required',[]))<=set(value) or not set(value)<=set(props):continue
            if any(('const' in p and value[k]!=p['const']) or ('enum' in p and value[k] not in p['enum']) for k,p in props.items() if k in value):continue
            return wire_order(value,branch,root)
    if isinstance(value,dict):
        props=schema.get('properties',{})
        return {k:wire_order(value[k],props.get(k,{}),root) for k in list(props)+[k for k in value if k not in props] if k in value}
    if isinstance(value,list):return [wire_order(v,schema.get('items',{}),root) for v in value]
    return value


def response_weights(tokenizer,value,focused=False):
    text=json.dumps(value,ensure_ascii=False);encoded=tokenizer(text,add_special_tokens=False,return_offsets_mapping=True)
    weights=[1.0]*len(encoded['input_ids'])
    if focused:
        decoder=json.JSONDecoder()
        rules=[('observation',.25),('kind',2.),('record_type',2.),('condition_type',4.),('target',3.),('value',3.),('statement',3.),('expression',6.),('nonrequirements',4.),('unknowns',3.)]
        for field,weight in rules:
            for match in re.finditer(r'(?<!\\)"'+field+r'"\s*:\s*',text):
                a=match.end();_,b=decoder.raw_decode(text,a)
                for i,(start,end) in enumerate(encoded['offset_mapping']):
                    if start<b and end>a:weights[i]=weight
    return weights+[1.0]


def target(case,packet):
    from src.item4.analysis import exploitation_prerequisites as V
    source=case['record']['sources'][0]
    atoms=[]
    for key,g in case['gold']['atoms'].items():
        quote=case['gold']['evidence_quotes'][0]
        parent=next(e for e in packet['evidence'] if e['source_id']==source['id'] and e['quote']==quote)
        evidence=next(e for e in packet['operational_evidence'] if e['evidence_id']==parent['evidence_id'] and e['quote']==quote)
        cat=g['category'];predicate=g['predicates'][0];name=g['target']
        kinds={'C1':('configuration','configuration_export','enabled'),'C2':('service_inventory','service_inventory','available'),
            'C3':('network_access','firewall_acl','reachable'),'C4':('access_policy','access_control_record','required'),
            'C5':('access_policy','access_control_record','permission'),'C6':('operating_workflow','operating_event_log','opened'),
            'C7':('operating_mode','configuration_export','active')}
        kind,record,value=kinds[cat]
        check='Inspect current '+record.replace('_',' ')+' records to establish whether '+g['positive']+'. Leave Unknown if the specified state, actor or scope cannot be established.'
        if cat=='C3':check+=' An ACL alone does not prove end-to-end reachability from the assessed origin.'
        atoms.append(dict(id=key,condition_type=cat+':'+predicate,target=name,value=value,statement=g['positive']+'.',
            operator_observable=True,observation=dict(kind=kind,record_type=record,check=check),
            operational_evidence_id=evidence['id'],source_refs=[dict(evidence_id=parent['evidence_id'])],
            operator='eq',expected=True,extraction_confidence=1.0,necessity='required',evidence_directness='direct_evidence',review_status='pending'))
    scenarios=[]
    if case['gold']['expression']:
        quote=case['gold']['evidence_quotes'][0];eid=next(e['evidence_id'] for e in packet['evidence'] if e['quote']==quote)
        scenarios=[dict(id='path1',product_keys=[],product_binding='unresolved',expression=case['gold']['expression'],source_refs=[dict(evidence_id=eid)])]
    nonrequirements=[]
    for topic in case['gold']['nonrequirements']:
        evidence=next(e for e in packet['evidence'] if 'Authentication is not required' in e['quote'])
        nonrequirements.append(dict(statement='Authentication is not required.',source_refs=[dict(evidence_id=evidence['evidence_id'])]))
    return dict(format=V.VERSION,cve=case['record']['cve'],prerequisites=atoms,scenarios=scenarios,
        nonrequirements=nonrequirements,excluded_facts=[],unknowns=['Operating prerequisites are not stated.'] if not atoms else [],
        uncertainty_details=[],applicability_claims=[])


def prepare(folder,aligned=False):
    from src.item4.analysis import exploitation_prerequisites as V
    from src.item4.analysis import prerequisite_automation as A
    from src.item4.analysis import operational_evidence_catalogue as O
    from tools.item4.run_metamorphic_synthetic import TUNING
    from src.item4.evaluation import source_guard_candidate as GUARD
    folder=Path(folder);train=[];validation=[];labels=[]
    # Only DEV worlds are constructed here; no TEST files are read.
    for family in range(12):
        for index in range(8):
            subset='train' if index<4 else 'validation'
            variants=('original',)+E.VARIANTS if index in (0,4) else ('original',)
            for variant in variants:
                case=E.make_case(family,index,variant)
                packet=V.TAXONOMY.bind_type_schema(O.bind(V.extraction_packet(case['record'])))
                answer=target(case,packet)
                from jsonschema import Draft202012Validator
                Draft202012Validator(packet['schema']).validate(answer)
                if aligned:
                    ordered=wire_order(answer,packet['schema']);assert ordered==answer;answer=ordered
                with patch.object(V.OP,'EXPLICIT',GUARD.explicit(V.OP.EXPLICIT)),patch.object(V.OP,'NONREQUIREMENT',GUARD.nonrequirement(V.OP.NONREQUIREMENT)),patch.object(V.OP,'source_polarity',GUARD.polarity(V.OP.source_polarity)):
                    native=V.validate(V.enrich(V.resolve_references(deepcopy(answer),packet)),case['record'])
                if not E.judge(case,native)['case_correct']:raise ValueError('Generated teacher violates the frozen oracle: '+case['id'])
                if subset=='train':
                    for role,system in [('exploitation-prerequisites',V.SYSTEM),(V.COVERAGE.ROLE,V.COVERAGE.SYSTEM)]:
                        req=A.repair_request(packet,system,role,None,None)
                        train.append(dict(id=case['id']+'__'+role,base_id=case['base_id'],role=role,
                            system=req['system']+TUNING['adapter_review'],packet=req['payload'],target=answer))
                else:
                    validation.append({k:deepcopy(case[k]) for k in ('id','base_id','family','split','variant','synthetic','record')})
                    labels.append(dict(id=case['id'],gold=case['gold']))
    train_ids={r['base_id'] for r in train};val_ids={r['base_id'] for r in validation}
    assert not train_ids&val_ids
    write(folder/'train.json',train);write(folder/'validation_inputs.json',validation);write(folder/'validation_gold.json',labels)
    manifest=dict(train_examples=len(train),train_worlds=len(train_ids),validation_cases=len(validation),validation_worlds=len(val_ids),
        teacher='Deterministic source-world AST, passed production schema/quote/scope validation with the explicitly versioned experimental guards, and the frozen matcher.',
        validation_guard=GUARD.VERSION,
        wire_order_aligned=aligned,loss_weighting='structured-fields-v1' if aligned else 'uniform',
        train_sha256=sha(folder/'train.json'),validation_inputs_sha256=sha(folder/'validation_inputs.json'),
        validation_gold_sha256=sha(folder/'validation_gold.json'),test_loaded=False,split='DEV indices 0-3 train; 4-7 validation; related variants grouped.',
        confidence_targets='Numeric confidence values are masked out of the training loss; teacher marker is used only for structural validation. No confidence-threshold optimization.')
    write(folder/'manifest.json',manifest);return manifest


def train(args):
    import torch
    from transformers import AutoTokenizer,AutoModelForCausalLM
    from peft import PeftModel,prepare_model_for_kbit_training
    folder=args.output;folder.mkdir(parents=True,exist_ok=True)
    metadata=json.loads((args.data/'manifest.json').read_text());assert sha(args.data/'train.json')==metadata['train_sha256']
    rows=json.loads((args.data/'train.json').read_text());random.Random(20261127).shuffle(rows)
    torch.manual_seed(20261127);torch.cuda.manual_seed_all(20261127);torch.set_num_threads(4)
    free,total=torch.cuda.mem_get_info();cap=int(args.memory_gib*1024**3)
    if free<cap:raise RuntimeError('Not enough free GPU memory; existing services are retained')
    torch.cuda.set_per_process_memory_fraction(cap/total)
    tok=AutoTokenizer.from_pretrained(str(args.tokenizer),local_files_only=True)
    if tok.pad_token_id is None:tok.pad_token=tok.eos_token
    model=AutoModelForCausalLM.from_pretrained(str(args.base),local_files_only=True,device_map={'':0},dtype=torch.bfloat16,attn_implementation='sdpa')
    model=prepare_model_for_kbit_training(model,use_gradient_checkpointing=True)
    # Keep the same BF16 embedding/head representation used during inference;
    # only LoRA matrices are trainable and exported.
    for parameter in model.parameters():
        if parameter.is_floating_point():parameter.data=parameter.data.to(torch.bfloat16)
    model=PeftModel.from_pretrained(model,str(args.adapter),adapter_name='vep_synthetic',is_trainable=True)
    model.config.use_cache=False;model.train()
    trainable=[(n,p) for n,p in model.named_parameters() if p.requires_grad]
    if not trainable or any('lora_' not in n for n,_ in trainable):raise ValueError('Only LoRA matrices may be trainable')
    params=[p for _,p in trainable]
    def trainable_hash():
        h=hashlib.sha256()
        for name,p in sorted(trainable):h.update(name.encode());h.update(p.detach().cpu().float().numpy().tobytes())
        return h.hexdigest()
    initial_trainable_sha256=trainable_hash()
    optimizer=torch.optim.AdamW(params,lr=args.learning_rate);encoded=[]
    for r in rows:
        messages=[dict(role='system',content=r['system']),dict(role='user',content=json.dumps(r['packet'],ensure_ascii=False))]
        prompt=tok.apply_chat_template(messages,tokenize=False,add_generation_prompt=True,enable_thinking=False)
        prefix=tok.encode(prompt,add_special_tokens=False)
        suffix,suffix_labels=response_tokens(tok,r['target'])
        suffix_weights=response_weights(tok,r['target'],metadata.get('loss_weighting')=='structured-fields-v1')
        if len(prefix)+len(suffix)>8192:raise ValueError('Training context too long; no truncation')
        encoded.append((prefix+suffix,[-100]*len(prefix)+suffix_labels,[0.]*len(prefix)+suffix_weights,r['id']))
    start=time.monotonic();history=[]
    torch.cuda.empty_cache()
    for epoch in range(args.epochs):
        random.Random(20261127+epoch).shuffle(encoded)
        for step,(ids,labels,weights,identity) in enumerate(encoded):
            x=torch.tensor([ids],device='cuda');y=torch.tensor([labels],device='cuda')
            optimizer.zero_grad(set_to_none=True)
            core=model.get_base_model()
            from torch.nn.attention import sdpa_kernel,SDPBackend
            with torch.autocast('cuda',dtype=torch.bfloat16),sdpa_kernel([SDPBackend.FLASH_ATTENTION,SDPBackend.EFFICIENT_ATTENTION]):
                embedded=core.get_input_embeddings()(x).requires_grad_(True)
                hidden=core.model(inputs_embeds=embedded,use_cache=False,return_dict=True).last_hidden_state[:,:-1]
                mask=y[:,1:]!=-100
                logits=core.lm_head(hidden[mask]);per_token=torch.nn.functional.cross_entropy(logits.float(),y[:,1:][mask],reduction='none')
                selected_weights=torch.tensor([weights],device='cuda')[:,1:][mask]
                loss=(per_token*selected_weights).sum()/selected_weights.sum()
            if not torch.isfinite(loss):raise ValueError('Nonfinite loss')
            scalar=float(loss.detach());loss.backward();norm=torch.nn.utils.clip_grad_norm_(params,1.0)
            if not torch.isfinite(norm):raise ValueError('Nonfinite adapter gradient')
            optimizer.step()
            history.append(dict(epoch=epoch+1,step=step+1,id=identity,loss=scalar))
            del x,y,embedded,hidden,mask,logits,loss,per_token,selected_weights
            write(folder/'status.json',dict(state='training',epoch=epoch+1,step=step+1,total=len(encoded),loss=scalar,
                elapsed_seconds=time.monotonic()-start,allocated_gib=torch.cuda.memory_allocated()/1024**3))
        checkpoint=folder/('epoch-'+str(epoch+1));model.save_pretrained(str(checkpoint),selected_adapters=['vep_synthetic'])
        final_trainable_sha256=trainable_hash()
        if final_trainable_sha256==initial_trainable_sha256:raise ValueError('Adapter parameters did not change')
        actual=checkpoint/'vep_synthetic';write(actual/'train_manifest.json',metadata)
        write(actual/'training_complete.json',dict(model='Qwen2.5-Coder-14B-Instruct',base=str(args.base),
            initial_adapter_sha256=sha(args.adapter/'adapter_model.safetensors'),adapter_sha256=sha(actual/'adapter_model.safetensors'),
            train_manifest_sha256=sha(actual/'train_manifest.json'),heldout_loaded=False,synthetic=True,
            epochs=epoch+1,optimizer_updates=len(history),rank=4,only_lora_trained=True,production_installed=False,
            learning_rate=args.learning_rate,wire_order_aligned=metadata.get('wire_order_aligned',False),loss_weighting=metadata.get('loss_weighting','uniform')))
        marker=json.loads((actual/'training_complete.json').read_text());marker.update(initial_trainable_sha256=initial_trainable_sha256,final_trainable_sha256=final_trainable_sha256)
        write(actual/'training_complete.json',marker)
    write(folder/'history.json',history);write(folder/'status.json',dict(state='complete',epochs=args.epochs,updates=len(history),elapsed_seconds=time.monotonic()-start))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['prepare','train']);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--data',type=Path);p.add_argument('--base',type=Path);p.add_argument('--adapter',type=Path);p.add_argument('--tokenizer',type=Path)
    p.add_argument('--epochs',type=int,default=2);p.add_argument('--memory-gib',type=float,default=18.5)
    p.add_argument('--learning-rate',type=float,default=1e-4);p.add_argument('--wire-order',action='store_true');a=p.parse_args()
    if a.action=='prepare':print(json.dumps(prepare(a.output,a.wire_order)))
    else:train(a)
