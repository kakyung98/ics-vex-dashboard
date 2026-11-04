"""Train a grounded role independently; never train/select on held-out test rows."""
import argparse
from datetime import datetime,timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.grounded_role_tasks import evaluate,check_conditions,check_writer
from src.training_io import atomic_json


def save(path,obj):
    atomic_json(path,obj)


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--role',choices=['l2-candidates','vex-writer','operation-questions','operation-assessment','item4-questions'],required=True)
    p.add_argument('--base',default=r'C:\Users\user\Desktop\ICS-VEXForge\models\Qwen3-8B')
    p.add_argument('--epochs',type=float,default=3)
    p.add_argument('--preflight-only',action='store_true')
    p.add_argument('--resume',action='store_true')
    p.add_argument('--experimental-curriculum',action='store_true')
    p.add_argument('--item4-curriculum',action='store_true')
    p.add_argument('--eval-heldout-after-training',action='store_true')
    p.add_argument('--generation-batch-size',type=int,default=1)
    p.add_argument('--max-length',type=int,default=1536)
    a=p.parse_args()
    # Retain old CLI spelling while using the maintained v3 role and contract.
    if a.role=='operation-questions':a.role='item4-questions'
    if a.role in {'item4-questions','operation-assessment'}:a.item4_curriculum=True
    operational=a.role.startswith('operation-') or a.role=='item4-questions'
    if a.item4_curriculum and a.role not in {'item4-questions','operation-assessment'}:p.error('New #4 curriculum supports only its question and assessment roles.')
    if a.role=='item4-questions' and not a.item4_curriculum:p.error('item4-questions requires --item4-curriculum.')
    if not 1<=a.generation_batch_size<=4:p.error('Generation batch size must be 1 to 4.')
    if operational and not a.experimental_curriculum:p.error('New operational roles currently support explicitly experimental curriculum only; real CVE annotations are pending.')
    if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
    os.environ.setdefault('HF_HUB_OFFLINE','1');os.environ.setdefault('TOKENIZERS_PARALLELISM','false')
    data=ROOT/'data/grounded_role_sft_v1';out=ROOT/'models'/f'{a.role}-qwen3-8b-v1'
    reports=ROOT/'results/grounded_role_finetune_v1'/a.role
    if a.role=='l2-candidates':
        data=ROOT/'data/l2_candidate_ranking_v1'
        reports=ROOT/'results/l2_candidate_finetune_v1'
    if a.item4_curriculum:
        data=ROOT/'data/operational_curriculum_v3';out=ROOT/'models'/f'{a.role}-qwen3-8b-item4-v3'
        reports=ROOT/'results/operational_role_finetune_v3'/a.role
    def check_target(packet,gold):
        if a.role=='l2-candidates':
            from src.l2_candidates import valid_prediction
            return {'grounded_candidate_ids':valid_prediction(packet,gold)}
        if a.item4_curriculum:
            from src.item4_role_tasks import check
            return check(a.role,packet,gold)
        if operational:
            from src.operational_role_tasks import check
            return check(a.role,packet,gold)
        return check_conditions(packet,gold) if a.role=='cve-conditions' else check_writer(packet,gold)
    def score(rows,texts):
        if a.role=='l2-candidates':
            from src.l2_candidates import evaluate as l2_evaluate
            return l2_evaluate(rows,texts)
        if a.item4_curriculum:
            from src.item4_role_tasks import evaluate as item4_evaluate
            return item4_evaluate(a.role,rows,texts)
        if operational:
            from src.operational_role_tasks import evaluate as operational_evaluate
            return operational_evaluate(a.role,rows,texts)
        return evaluate(a.role,rows,texts)
    started=time.time();state={'role':a.role,'pid':os.getpid(),'base':a.base,'adapter':str(out),'test_loaded':False,
        'expert_gold':False,'experimental_curriculum':operational or a.role=='l2-candidates','deployment_approved':False if operational or a.role=='l2-candidates' else None,
        'started_at':datetime.now(timezone.utc).isoformat()}
    def status(phase,**extra):
        state.update(phase=phase,updated_at=datetime.now(timezone.utc).isoformat(),elapsed_seconds=round(time.time()-started,2),**extra)
        save(reports/'status.json',state)
    status('preflight')
    try:
        import torch
        from datasets import Dataset
        from peft import LoraConfig,prepare_model_for_kbit_training
        from transformers import AutoModelForCausalLM,AutoTokenizer,BitsAndBytesConfig,EarlyStoppingCallback,TrainerCallback,set_seed
        from trl import SFTConfig,SFTTrainer
        os.environ.setdefault('HF_ENABLE_PARALLEL_LOADING','false')
        torch.set_num_threads(2);set_seed(20261101)
        manifest=json.loads((data/'manifest.json').read_text(encoding='utf-8'))
        spec=manifest['roles'][a.role];rows={};hashes={}
        if operational:
            assert manifest['experimental'] is True and manifest['human_gold'] is False
            assert manifest.get('test_loaded_for_training',manifest.get('test_created_or_loaded')) is False
        for split in ('train','validation'):
            file=data/a.role/f'{split}.jsonl';hashes[split]=hashlib.sha256(file.read_bytes()).hexdigest()
            assert hashes[split]==spec['splits'][split]['sha256'],'Dataset changed after manifest creation'
            rows[split]=[json.loads(l) for l in file.read_text(encoding='utf-8').splitlines()]
            assert len(rows[split])==spec['splits'][split]['examples']
            for r in rows[split]:
                assert r['split']==split
                gold=json.loads(r['messages'][-1]['content'])
                if operational:assert r['simulation'] is True and r['packet']['cve'].startswith('SIM-')
                checked=check_target(r['packet'],gold)
                assert all(checked.values()),r['id']
        assert not {r['group_id'] for r in rows['train']}&{r['group_id'] for r in rows['validation']}
        identity=lambda r:r['packet'].get('vulnerability',r['packet'].get('cve'))
        if a.role!='l2-candidates':assert not {identity(r) for r in rows['train']}&{identity(r) for r in rows['validation'] if identity(r)!='synthetic-example'}
        tok=AutoTokenizer.from_pretrained(a.base,local_files_only=True)
        if tok.pad_token_id is None:tok.pad_token=tok.eos_token
        def prompt(r):return tok.apply_chat_template(r['messages'][:-1],tokenize=False,add_generation_prompt=True,enable_thinking=False)
        lengths={};max_answer=0
        def dataset(split):
            nonlocal max_answer
            items=[];sizes=[]
            for r in rows[split]:
                prefix=prompt(r);completion=r['messages'][-1]['content']+tok.eos_token
                size=len(tok(prefix+completion,add_special_tokens=False)['input_ids'])
                assert size<=a.max_length,(r['id'],'Do not truncate labels')
                max_answer=max(max_answer,len(tok(completion,add_special_tokens=False)['input_ids']))
                sizes.append(size);items.append({'prompt':prefix,'completion':completion})
            lengths[split]={'min':min(sizes),'max':max(sizes),'mean':sum(sizes)/len(sizes)}
            return Dataset.from_list(items)
        train,val=dataset('train'),dataset('validation')
        config={'role':a.role,'base':a.base,'dataset_hashes':hashes,'counts':{s:len(r) for s,r in rows.items()},'lengths':lengths,
                'seed':20261101,'epochs_max':a.epochs,'rank':8,'batch':1,'accumulation':8,'max_length':a.max_length,
                'experimental_curriculum':operational or a.role=='l2-candidates','deployment_approved':False if operational or a.role=='l2-candidates' else None,
                'learning_rate':5e-5 if a.item4_curriculum else 1e-4,'generation_batch_size':a.generation_batch_size,'item4_contract':a.item4_curriculum,'test_loaded':False,'expert_gold':False,'references':spec['references'],
                'metric_interpretation':'Weak-reference/synthetic agreement and structural consistency, not expert semantic accuracy.',
                'versions':{k:importlib.metadata.version(k) for k in ['torch','transformers','peft','trl','bitsandbytes']}}
        save(reports/'run_config.json',config)
        if a.preflight_only:
            status('ready',train_examples=len(train),validation_examples=len(val),sequence_lengths=lengths)
            print(json.dumps(config,indent=2),flush=True);return
        from transformers.trainer_utils import get_last_checkpoint
        checkpoint=get_last_checkpoint(str(out)) if a.resume and out.exists() else None
        if out.exists() and any(out.iterdir()) and not a.resume:raise FileExistsError(f'Existing adapter/checkpoints: {out}')
        assert torch.cuda.is_available()
        interval=max(10,min(50,(len(train)+7)//8))
        warmup=max(1,round(((len(train)+7)//8)*a.epochs*.05))
        # Validate installed trainer configuration before allocating model memory.
        cfg=SFTConfig(output_dir=str(out),num_train_epochs=a.epochs,per_device_train_batch_size=1,per_device_eval_batch_size=1,
            gradient_accumulation_steps=8,learning_rate=5e-5 if a.item4_curriculum else 1e-4,lr_scheduler_type='cosine',warmup_steps=warmup,
            logging_steps=5,logging_first_step=True,eval_strategy='steps',eval_steps=interval,save_strategy='steps',save_steps=interval,
            save_total_limit=2,load_best_model_at_end=True,metric_for_best_model='eval_loss',greater_is_better=False,
            bf16=True,optim='paged_adamw_8bit',gradient_checkpointing=True,gradient_checkpointing_kwargs={'use_reentrant':False},
            max_length=a.max_length,packing=False,completion_only_loss=True,max_grad_norm=1,seed=20261101,report_to=[],dataloader_num_workers=0,disable_tqdm=True)
        status('loading_model',train_examples=len(train),validation_examples=len(val),gpu=torch.cuda.get_device_name(0))
        print(f'{a.role}: loading base; train={len(train)}, validation={len(val)}, test withheld',flush=True)
        quant=BitsAndBytesConfig(load_in_4bit=True,bnb_4bit_quant_type='nf4',bnb_4bit_use_double_quant=True,bnb_4bit_compute_dtype=torch.bfloat16)
        model=AutoModelForCausalLM.from_pretrained(a.base,quantization_config=quant,dtype=torch.bfloat16,device_map={'':0},attn_implementation='sdpa',local_files_only=True)
        model=prepare_model_for_kbit_training(model,use_gradient_checkpointing=True,gradient_checkpointing_kwargs={'use_reentrant':False});model.config.use_cache=False
        class Progress(TrainerCallback):
            def on_train_begin(self,args,s,control,**kwargs):status('training',global_step=s.global_step,max_steps=s.max_steps)
            def on_step_end(self,args,s,control,**kwargs):status('training',global_step=s.global_step,max_steps=s.max_steps,epoch=s.epoch)
            def on_log(self,args,s,control,logs=None,**kwargs):
                status(state['phase'],last_metrics=logs or {},global_step=s.global_step)
                print(json.dumps({'step':s.global_step,**(logs or {})}),flush=True)
        trainer=SFTTrainer(model=model,args=cfg,train_dataset=train,eval_dataset=val,processing_class=tok,
            peft_config=LoraConfig(r=8,lora_alpha=16,lora_dropout=.05,bias='none',task_type='CAUSAL_LM',target_modules=['q_proj','k_proj','v_proj','o_proj','gate_proj','up_proj','down_proj']),
            callbacks=[Progress(),EarlyStoppingCallback(early_stopping_patience=2)])
        batch=trainer.data_collator([trainer.train_dataset[0]])
        n=int((batch['labels'][0]!=-100).sum());total=int(batch['attention_mask'][0].sum())
        assert 0<n<total,'Prompt masking failed'
        config.update(prompt_mask_verified=True,supervised_tokens=n,example_tokens=total,eval_save_interval=interval,warmup_steps=warmup)
        save(reports/'run_config.json',config)
        trained=trainer.train(resume_from_checkpoint=checkpoint);trainer.save_model(str(out));tok.save_pretrained(str(out))
        model=trainer.model;model.eval();model.gradient_checkpointing_disable();model.config.use_cache=True
        max_new=min(1024,max(256,max_answer+64));tok.padding_side='left'
        def generate(label,split='validation'):
            output=[]
            for start in range(0,len(rows[split]),a.generation_batch_size):
                selected=rows[split][start:start+a.generation_batch_size]
                enc=tok([prompt(r) for r in selected],padding=True,return_tensors='pt').to('cuda')
                with torch.inference_mode():gen=model.generate(**enc,max_new_tokens=max_new,do_sample=False,pad_token_id=tok.pad_token_id,use_cache=True)
                output.extend(tok.batch_decode(gen[:,enc['input_ids'].shape[1]:],skip_special_tokens=True))
                status('validation_generation' if split=='validation' else 'heldout_generation',evaluation=label,evaluation_split=split,evaluated=len(output),global_step=trainer.state.global_step)
            return output
        with model.disable_adapter():base=generate('base')
        tuned=generate('tuned')
        bm,bp=score(rows['validation'],base);tm,tp=score(rows['validation'],tuned)
        strata={}
        for basis in sorted({r['annotation_basis'] for r in rows['validation']}):
            ids=[i for i,r in enumerate(rows['validation']) if r['annotation_basis']==basis]
            picked=[rows['validation'][i] for i in ids]
            strata[basis]={'base':score(picked,[base[i] for i in ids])[0],'tuned':score(picked,[tuned[i] for i in ids])[0]}
        report={'config':config,'training':trained.metrics,'evaluation_split':'validation','test_evaluated':False,
                'best_checkpoint':trainer.state.best_model_checkpoint,'baseline':bm,'tuned':tm,'strata':strata,
                'baseline_predictions':bp,'tuned_predictions':tp,'expert_semantic_evaluation_complete':False}
        save(reports/'validation_report.json',report);save(out/'training_complete.json',{'role':a.role,'report':str(reports/'validation_report.json')})
        if a.eval_heldout_after_training:
            if not a.item4_curriculum and a.role!='l2-candidates':raise ValueError('Held-out evaluation requires a supported split manifest.')
            testfile=data/a.role/'test.jsonl'
            assert hashlib.sha256(testfile.read_bytes()).hexdigest()==spec['splits']['test']['sha256']
            rows['test']=[json.loads(line) for line in testfile.read_text(encoding='utf-8').splitlines()]
            state.update(test_loaded=True,test_used_for_training_or_checkpoint_selection=False)
            assert len(rows['test'])==spec['splits']['test']['examples']
            assert not {r['group_id'] for r in rows['test']}&{r['group_id'] for r in rows['train']+rows['validation']}
            for r in rows['test']:
                assert r['split']=='test' and all(check_target(r['packet'],r['target']).values())
            weight_hash=hashlib.sha256((out/'adapter_model.safetensors').read_bytes()).hexdigest()
            with model.disable_adapter():testbase=generate('base','test')
            testtuned=generate('tuned','test')
            tb,tbp=score(rows['test'],testbase);tt,ttp=score(rows['test'],testtuned)
            assert hashlib.sha256((out/'adapter_model.safetensors').read_bytes()).hexdigest()==weight_hash
            save(reports/'heldout_report.json',{'evaluation_split':'test','synthetic_curriculum_only':True,
                'expert_semantic_accuracy_evaluated':False,'checkpoint_selected_before_test':True,
                'adapter_sha256':weight_hash,'test_sha256':spec['splits']['test']['sha256'],
                'baseline':tb,'tuned':tt,'baseline_predictions':tbp,'tuned_predictions':ttp,
                'deployment_approved':False,'test_used_for_training_or_checkpoint_selection':False})
        status('complete',baseline=bm,tuned=tm)
        print(f'{a.role}: training/validation complete; held-out curriculum evaluated={a.eval_heldout_after_training}',flush=True)
    except BaseException as exc:
        status('failed',error_type=type(exc).__name__,error=str(exc));raise


if __name__=='__main__':main()
