"""QLoRA SFT for application source facts; test100 is never loaded or scored.

This is not CVE-condition extraction or final VEX generation training.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
FIELDS=('dependency_linked','api','api_reachable_from_main','additional_api_guard_present')


def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value,indent=2,ensure_ascii=False),encoding='utf-8')
    tmp.replace(path)


def score(rows,outputs):
    if len(rows)!=len(outputs):raise ValueError('Prediction count does not match evaluation rows')
    correct={k:0 for k in FIELDS}; valid=exact=0; predictions=[]
    for row,text in zip(rows,outputs):
        gold=json.loads(row['messages'][-1]['content'])
        try:
            start=text.find('{');end=text.rfind('}')
            pred=json.loads(text[start:end+1])
            ok=isinstance(pred,dict) and set(pred)==set(FIELDS) and isinstance(pred['api'],str) and all(type(pred[k]) is bool for k in FIELDS if k!='api')
        except (ValueError,TypeError):pred=None;ok=False
        valid+=int(ok)
        matches={k:bool(ok and type(pred[k]) is type(gold[k]) and pred[k]==gold[k]) for k in FIELDS}
        for k,v in matches.items():correct[k]+=int(v)
        exact+=int(all(matches.values()))
        predictions.append({'id':row['id'],'gold':gold,'prediction':pred,'valid':ok,'raw':text})
    n=len(rows)
    return {'examples':n,'schema_valid_rate':valid/n if n else None,'exact_accuracy':exact/n if n else None,
            'field_accuracy':{k:v/n if n else None for k,v in correct.items()}},predictions


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--base',default=r'C:\Users\user\Desktop\ICS-VEXForge\models\Qwen3-8B')
    p.add_argument('--data',type=Path,default=ROOT/'data/source_training_sw')
    p.add_argument('--out',type=Path,required=True,help='Explicit research output directory; no deployed source-evidence adapter is configured.')
    p.add_argument('--reports',type=Path,default=ROOT/'results/source_evidence_finetune_v1')
    p.add_argument('--epochs',type=float,default=3)
    p.add_argument('--max-length',type=int,default=1280)
    p.add_argument('--accum',type=int,default=8)
    p.add_argument('--rank',type=int,default=8)
    p.add_argument('--seed',type=int,default=20261101)
    a=p.parse_args()
    if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
    os.environ.setdefault('HF_HUB_OFFLINE','1')
    os.environ.setdefault('TOKENIZERS_PARALLELISM','false')
    if a.out.exists() and any(a.out.iterdir()):raise FileExistsError(f'Output already contains files: {a.out}')
    a.reports.mkdir(parents=True,exist_ok=True)
    started=time.time()
    state={'phase':'preflight','pid':os.getpid(),'started_at':datetime.now(timezone.utc).isoformat(),
           'task':'application_source_evidence','base':a.base,'adapter':str(a.out),
           'train_examples':800,'validation_examples':100,'test_examples_loaded':0,
           'scope':'Synthetic application linkage, public-API reachability and additional guard classification. Not CVE exploitability or final VEX generation.'}
    def status(phase,**extra):
        state.update(phase=phase,updated_at=datetime.now(timezone.utc).isoformat(),elapsed_seconds=round(time.time()-started,2),**extra)
        save(a.reports/'status.json',state)
    status('preflight')
    try:
        import torch
        from datasets import Dataset
        from peft import LoraConfig,prepare_model_for_kbit_training
        from transformers import AutoModelForCausalLM,AutoTokenizer,BitsAndBytesConfig,EarlyStoppingCallback,TrainerCallback,set_seed
        from trl import SFTConfig,SFTTrainer
        if not torch.cuda.is_available():raise RuntimeError('CUDA GPU required')
        torch.set_num_threads(4);set_seed(a.seed)
        audit=json.loads((ROOT/'results/source_training_sw/split_audit.json').read_text())
        built=json.loads((a.data/'manifest.json').read_text())
        if not audit['test100_unchanged'] or audit['counts']!={'train':800,'validation':100,'test':100} or not built['build_verified']:
            raise ValueError('Dataset build/split audits are incomplete')
        rows={};hashes={}
        for split,count in [('train',800),('validation',100)]:
            path=a.data/'sft'/f'{split}.jsonl';hashes[split]=hashlib.sha256(path.read_bytes()).hexdigest()
            rows[split]=[json.loads(l) for l in path.read_text(encoding='utf-8').splitlines()]
            if len(rows[split])!=count:raise ValueError('Unexpected split size')
            for r in rows[split]:
                if not r['id'].startswith('TR' if split=='train' else 'VA') or [m['role'] for m in r['messages']]!=['system','user','assistant']:
                    raise ValueError('Unexpected training message/split')
                gold=json.loads(r['messages'][-1]['content'])
                if set(gold)!=set(FIELDS):raise ValueError('Unexpected label schema')
                if 'evaluation/virtual_sw_100' in r['messages'][1]['content']:raise ValueError('Test content in model input')
        if {r['group_id'] for r in rows['train']}&{r['group_id'] for r in rows['validation']}:raise ValueError('Group overlap')
        tok=AutoTokenizer.from_pretrained(a.base,local_files_only=True)
        if tok.pad_token_id is None:tok.pad_token=tok.eos_token
        def prompt(r):return tok.apply_chat_template(r['messages'][:-1],tokenize=False,add_generation_prompt=True,enable_thinking=False)
        lengths={}
        def dataset(split):
            items=[];sizes=[]
            for r in rows[split]:
                prefix=prompt(r);completion=r['messages'][-1]['content']+tok.eos_token
                size=len(tok(prefix+completion,add_special_tokens=False)['input_ids'])
                if size>a.max_length:raise ValueError(f'{r["id"]} exceeds sequence limit; no truncation allowed')
                sizes.append(size);items.append({'prompt':prefix,'completion':completion})
            lengths[split]={'min':min(sizes),'max':max(sizes),'mean':sum(sizes)/len(sizes)}
            return Dataset.from_list(items)
        train,val=dataset('train'),dataset('validation')
        warmup_steps=max(1,round(((len(train)+a.accum-1)//a.accum)*a.epochs*.05))
        config={'base':a.base,'adapter':str(a.out),'dataset_hashes':hashes,'sequence_lengths':lengths,
                'seed':a.seed,'epochs_max':a.epochs,'batch_size':1,'gradient_accumulation':a.accum,'rank':a.rank,
                'max_length':a.max_length,'learning_rate':1e-4,'warmup_steps':warmup_steps,'early_stopping_validation_checks':2,
                'checkpoint_selection':'minimum validation loss; validation only','test_loaded':False,
                'versions':{k:importlib.metadata.version(k) for k in ['torch','transformers','peft','trl','bitsandbytes']}}
        save(a.reports/'run_config.json',config)
        status('loading_model',gpu=torch.cuda.get_device_name(0),sequence_lengths=lengths)
        print('Loading Qwen3-8B 4-bit; 800 train / 100 validation; test withheld.',flush=True)
        quant=BitsAndBytesConfig(load_in_4bit=True,bnb_4bit_quant_type='nf4',bnb_4bit_use_double_quant=True,bnb_4bit_compute_dtype=torch.bfloat16)
        model=AutoModelForCausalLM.from_pretrained(a.base,quantization_config=quant,dtype=torch.bfloat16,device_map={'':0},attn_implementation='sdpa',local_files_only=True)
        model=prepare_model_for_kbit_training(model,use_gradient_checkpointing=True,gradient_checkpointing_kwargs={'use_reentrant':False})
        model.config.use_cache=False
        class Progress(TrainerCallback):
            def on_train_begin(self,args,s,control,**kwargs):status('training',global_step=s.global_step,max_steps=s.max_steps)
            def on_step_end(self,args,s,control,**kwargs):
                status('training',global_step=s.global_step,max_steps=s.max_steps,epoch=s.epoch,gpu_allocated_mb=round(torch.cuda.memory_allocated()/1024**2))
            def on_log(self,args,s,control,logs=None,**kwargs):
                status(state['phase'],global_step=s.global_step,last_metrics=logs or {})
                print(json.dumps({'step':s.global_step,**(logs or {})}),flush=True)
            def on_evaluate(self,args,s,control,metrics=None,**kwargs):status('training',validation_metrics=metrics or {},global_step=s.global_step)
        cfg=SFTConfig(output_dir=str(a.out),num_train_epochs=a.epochs,per_device_train_batch_size=1,
            per_device_eval_batch_size=1,gradient_accumulation_steps=a.accum,learning_rate=1e-4,
            lr_scheduler_type='cosine',warmup_steps=warmup_steps,logging_steps=5,logging_first_step=True,
            eval_strategy='steps',eval_steps=50,save_strategy='steps',save_steps=50,save_total_limit=2,
            load_best_model_at_end=True,metric_for_best_model='eval_loss',greater_is_better=False,
            bf16=True,optim='paged_adamw_8bit',gradient_checkpointing=True,
            gradient_checkpointing_kwargs={'use_reentrant':False},max_length=a.max_length,packing=False,
            completion_only_loss=True,max_grad_norm=1,seed=a.seed,report_to=[],dataloader_num_workers=0,disable_tqdm=True)
        trainer=SFTTrainer(model=model,args=cfg,train_dataset=train,eval_dataset=val,processing_class=tok,
            peft_config=LoraConfig(r=a.rank,lora_alpha=a.rank*2,lora_dropout=.05,bias='none',task_type='CAUSAL_LM',
                target_modules=['q_proj','k_proj','v_proj','o_proj','gate_proj','up_proj','down_proj']),
            callbacks=[Progress(),EarlyStoppingCallback(early_stopping_patience=2)])
        batch=trainer.data_collator([trainer.train_dataset[0]])
        answer_tokens=int((batch['labels'][0]!=-100).sum());all_tokens=int(batch['attention_mask'][0].sum())
        if not 0<answer_tokens<all_tokens:raise RuntimeError('Completion-only masking check failed')
        config.update(completion_only_mask_verified=True,supervised_example_tokens=answer_tokens,
                      total_example_tokens=all_tokens,trainable_parameters=model.get_nb_trainable_parameters() if hasattr(model,'get_nb_trainable_parameters') else None)
        save(a.reports/'run_config.json',config)
        print(f'Answer masking checked: {answer_tokens}/{all_tokens} supervised tokens.',flush=True)
        trained=trainer.train()
        trainer.save_model(str(a.out));tok.save_pretrained(str(a.out))
        status('validation_generation',global_step=trainer.state.global_step,best_checkpoint=trainer.state.best_model_checkpoint)
        model=trainer.model;model.eval();model.gradient_checkpointing_disable();model.config.use_cache=True
        tok.padding_side='left'
        def generate(label):
            output=[]
            for i in range(0,len(rows['validation']),2):
                chunk=rows['validation'][i:i+2]
                enc=tok([prompt(r) for r in chunk],return_tensors='pt',padding=True).to('cuda')
                with torch.inference_mode():
                    gen=model.generate(**enc,max_new_tokens=112,do_sample=False,pad_token_id=tok.pad_token_id,use_cache=True)
                output.extend(tok.batch_decode(gen[:,enc['input_ids'].shape[1]:],skip_special_tokens=True))
                status('validation_generation',evaluation=label,evaluated=len(output))
            return output
        with model.disable_adapter():baseline=generate('base')
        tuned=generate('tuned')
        base_metrics,base_predictions=score(rows['validation'],baseline)
        tuned_metrics,tuned_predictions=score(rows['validation'],tuned)
        report={'config':config,'scope':state['scope'],'evaluation_split':'validation','test_evaluated':False,
                'steps':trainer.state.global_step,'best_checkpoint':trainer.state.best_model_checkpoint,
                'training':trained.metrics,'baseline':base_metrics,'tuned':tuned_metrics,
                'baseline_predictions':base_predictions,'tuned_predictions':tuned_predictions}
        save(a.reports/'validation_report.json',report)
        save(a.out/'training_complete.json',{'report':str(a.reports/'validation_report.json'),'task':state['task']})
        status('complete',validation_baseline=base_metrics,validation_tuned=tuned_metrics)
        print('Training and validation complete; test100 remains withheld.',flush=True)
    except BaseException as exc:
        status('failed',error_type=type(exc).__name__,error=str(exc))
        raise


if __name__=='__main__':main()
