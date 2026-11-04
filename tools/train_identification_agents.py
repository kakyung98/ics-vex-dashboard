"""Train independent Qwen QLoRA adapters for README L2/L3/L4 and evaluate each.

No SecureBERT. Each task runs in a fresh process so GPU memory is released.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.identification_tasks import messages, parse_output, SYSTEM, INSTRUCTIONS
from evaluation.identification_metrics import score


def read_rows(data, split, task):
    rows = [json.loads(line) for line in (data/f'{split}.jsonl').read_text(encoding='utf-8').splitlines()]
    return [r for r in rows if r['task'] == task]


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--task', choices=['all', 'L2', 'L3', 'L4'], default='all')
    p.add_argument('--base', default=os.environ.get('ICSVEX_AGENT_BASE', r'C:\Users\user\Desktop\ICS-VEXForge\models\Qwen3-8B'))
    p.add_argument('--data', type=Path, default=ROOT/'data/identification_agents')
    p.add_argument('--out', type=Path, default=ROOT/'models/identification-agents-v1')
    p.add_argument('--epochs', type=float, default=1.0)
    p.add_argument('--batch', type=int, default=2)
    p.add_argument('--accum', type=int, default=4)
    p.add_argument('--rank', type=int, default=8)
    p.add_argument('--max-length', type=int, default=512)
    p.add_argument('--seed', type=int, default=20261101)
    p.add_argument('--resume', action='store_true')
    p.add_argument('--reports',type=Path,default=ROOT/'results/identification_agents')
    p.add_argument('--train-limit',type=int,default=0,help='Nested training prefix for validation-only learning curves')
    p.add_argument('--validation-only',action='store_true',help='Compare candidates without inspecting test outputs')
    p.add_argument('--eval-batch',type=int,default=4)
    a = p.parse_args()
    if a.task == 'all':
        for task in ['L2', 'L3', 'L4']:
            command = [sys.executable, '-u', __file__, '--task', task, '--base', a.base,
                       '--data', str(a.data), '--out', str(a.out), '--epochs', str(a.epochs),
                       '--batch', str(a.batch), '--accum', str(a.accum), '--rank', str(a.rank),
                       '--max-length', str(a.max_length), '--seed', str(a.seed),
                       '--reports',str(a.reports),'--train-limit',str(a.train_limit),'--eval-batch',str(a.eval_batch)]
            if a.resume: command.append('--resume')
            if a.validation_only:command.append('--validation-only')
            subprocess.run(command, check=True)
        print('All three adapters trained and evaluated.', flush=True)
        return
    if hasattr(sys.stdout, 'reconfigure'): sys.stdout.reconfigure(encoding='utf-8')
    os.environ.setdefault('HF_HUB_OFFLINE', '1')
    import torch
    from datasets import Dataset
    from peft import LoraConfig, prepare_model_for_kbit_training
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, set_seed
    from trl import SFTConfig, SFTTrainer
    set_seed(a.seed); torch.set_num_threads(4)
    if not torch.cuda.is_available(): raise RuntimeError('CUDA is required')
    started = time.time()
    train = read_rows(a.data, 'train', a.task)
    val = read_rows(a.data, 'val', a.task)
    test = read_rows(a.data, 'test', a.task)
    if a.train_limit:
        if not a.validation_only:raise ValueError('Learning-curve candidates must use --validation-only')
        if a.train_limit>len(train):raise ValueError('Training limit exceeds available data')
        train=train[:a.train_limit]
    manifest=json.loads((a.data/'manifest.json').read_text(encoding='utf-8'))
    for split in ('train','val','test'):
        actual=hashlib.sha256((a.data/f'{split}.jsonl').read_bytes()).hexdigest()
        if actual!=manifest['splits'][split]['sha256']:raise ValueError('Dataset changed after manifest creation')
    groups = [{json.dumps(r['group'], sort_keys=True) for r in split} for split in (train,val,test)]
    if groups[0]&groups[1] or groups[0]&groups[2] or groups[1]&groups[2]:
        raise ValueError('Group leakage')
    output = a.out/a.task
    if (output/'adapter_model.safetensors').exists() and not a.resume:
        raise FileExistsError(f'{output} already exists; choose a new --out')
    tok = AutoTokenizer.from_pretrained(a.base, local_files_only=True)
    if tok.pad_token_id is None: tok.pad_token = tok.eos_token
    def prompt(row):
        return tok.apply_chat_template(messages(a.task,row['input']), tokenize=False,
                                       add_generation_prompt=True, enable_thinking=False)
    def dataset(rows):
        items = []
        for row in rows:
            rendered = prompt(row)
            completion = json.dumps(row['gold'], separators=(',',':')) + tok.eos_token
            if len(tok(rendered+completion)['input_ids']) > a.max_length:
                raise ValueError('Example exceeds max length; increase --max-length, do not truncate labels')
            items.append({'prompt': rendered, 'completion': completion})
        return Dataset.from_list(items)
    train_ds, val_ds = dataset(train), dataset(val)
    quant = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type='nf4',
                              bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.bfloat16)
    print(f'{a.task}: loading Qwen3-8B, train={len(train)} val={len(val)} test={len(test)}', flush=True)
    model = AutoModelForCausalLM.from_pretrained(a.base, quantization_config=quant,
            dtype=torch.bfloat16, device_map={'':0}, attn_implementation='sdpa', local_files_only=True)
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True,
                                           gradient_checkpointing_kwargs={'use_reentrant':False})
    model.config.use_cache=False
    cfg = SFTConfig(output_dir=str(output), num_train_epochs=a.epochs,
        per_device_train_batch_size=a.batch, gradient_accumulation_steps=a.accum,
        per_device_eval_batch_size=a.batch, learning_rate=1e-4, lr_scheduler_type='cosine',
        warmup_steps=2, logging_steps=8, eval_strategy='epoch', save_strategy='epoch',
        save_total_limit=1, bf16=True, optim='paged_adamw_8bit',
        gradient_checkpointing=True, gradient_checkpointing_kwargs={'use_reentrant':False},
        max_length=a.max_length, packing=False, completion_only_loss=True,
        max_grad_norm=1.0, seed=a.seed, report_to=[], dataloader_num_workers=0, disable_tqdm=True)
    trainer = SFTTrainer(model=model, args=cfg, train_dataset=train_ds, eval_dataset=val_ds,
        processing_class=tok, peft_config=LoraConfig(r=a.rank, lora_alpha=a.rank*2,
        lora_dropout=0.05, bias='none', task_type='CAUSAL_LM',
        target_modules=['q_proj','k_proj','v_proj','o_proj','gate_proj','up_proj','down_proj']))
    batch = trainer.data_collator([trainer.train_dataset[0]])
    labels = batch['labels'][0]
    supervised = int((labels!=-100).sum())
    if not 0 < supervised < int(batch['attention_mask'][0].sum()):
        raise RuntimeError('Completion-only masking check failed')
    print(f'{a.task}: supervised answer tokens={supervised}; prompt masked', flush=True)
    result = trainer.train(resume_from_checkpoint=True if a.resume else None)
    trainer.save_model(str(output)); tok.save_pretrained(str(output))
    model = trainer.model; model.eval(); model.gradient_checkpointing_disable(); model.config.use_cache=True
    tok.padding_side='left'
    def generate(rows):
        predictions=[]; raw=[]
        for offset in range(0,len(rows),a.eval_batch):
            chunk=rows[offset:offset+a.eval_batch]
            encoded=tok([prompt(r) for r in chunk], return_tensors='pt', padding=True).to('cuda')
            with torch.inference_mode():
                generated=model.generate(**encoded, max_new_tokens=112, do_sample=False,
                                          pad_token_id=tok.pad_token_id, use_cache=True)
            texts=tok.batch_decode(generated[:,encoded['input_ids'].shape[1]:],skip_special_tokens=True)
            raw.extend(texts); predictions.extend(parse_output(t) for t in texts)
            print(f'{a.task}: eval {min(offset+a.eval_batch,len(rows))}/{len(rows)}', flush=True)
        return predictions, raw
    # Baseline and adapter see identical held-out test inputs, after training is frozen.
    evaluated=val if a.validation_only else test
    with model.disable_adapter(): baseline, base_raw = generate(evaluated)
    tuned, tuned_raw = generate(evaluated)
    report = {'task': a.task, 'base': a.base, 'adapter': str(output), 'seed': a.seed,
        'system_prompt':SYSTEM, 'task_instruction':INSTRUCTIONS[a.task], 'enable_thinking':False,
        'scope': 'NVD-derived procedural pilot; not real-world CVE precision',
        'split_manifest': json.loads((a.data/'manifest.json').read_text(encoding='utf-8')),
        'train_examples':len(train), 'val_examples':len(val), 'test_examples':len(test),
        'evaluation_split':'val' if a.validation_only else 'test', 'evaluation_examples':len(evaluated),
        'training_rows_sha256':hashlib.sha256(json.dumps(train,sort_keys=True).encode()).hexdigest(),
        'epochs': a.epochs, 'rank':a.rank, 'steps':trainer.state.global_step,
        'completion_only_mask_verified':True, 'training':result.metrics,
        'baseline':score(a.task,evaluated,baseline), 'tuned':score(a.task,evaluated,tuned),
        'elapsed_seconds':time.time()-started, 'gpu':torch.cuda.get_device_name(0),
        'raw_predictions':[{'id':r['id'],'base':b,'tuned':t} for r,b,t in zip(evaluated,base_raw,tuned_raw)]}
    reports = a.reports; reports.mkdir(parents=True,exist_ok=True)
    if 'extends' in manifest:
        split='val' if a.validation_only else 'test'
        old_ids={r['id'] for r in read_rows(Path(manifest['extends']['path']),split,a.task)}
        report['evaluation_strata']={}
        for label,indices in [('previous_v1',[i for i,r in enumerate(evaluated) if r['id'] in old_ids]),
                              ('new_v2',[i for i,r in enumerate(evaluated) if r['id'] not in old_ids])]:
            selected=[evaluated[i] for i in indices]
            report['evaluation_strata'][label]={'baseline':score(a.task,selected,[baseline[i] for i in indices]),
                                               'tuned':score(a.task,selected,[tuned[i] for i in indices])}
    (reports/f'{a.task}.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    (output/'training_complete.json').write_text(json.dumps({'task':a.task,'report':str(reports/f'{a.task}.json')},indent=2),encoding='utf-8')
    print(f'{a.task}: complete; baseline={report["baseline"]["exact_accuracy"]:.3f} tuned={report["tuned"]["exact_accuracy"]:.3f}',flush=True)


if __name__=='__main__': main()
