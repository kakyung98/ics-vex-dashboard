"""Frozen all-TEST evaluation; automatic reference agreement is not expert accuracy.

Generation reads inputs only. References are loaded after every prediction has
been persisted. Invalid outputs remain in all denominators and are never dropped.
"""
from pathlib import Path
from collections import Counter
from types import SimpleNamespace
import argparse,hashlib,json,time,traceback,sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))

ROLES={'exploitation-prerequisites':'vep_extraction','operating-record-review':'operating_record_review'}

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(8*1024*1024),b''):h.update(block)
    return h.hexdigest()

def dump(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8');tmp.replace(path)

def rows(path):
    with Path(path).open(encoding='utf-8') as stream:return [json.loads(line) for line in stream]

def parse(text):
    text=text.strip()
    if text.startswith('```'):
        lines=text.splitlines();text='\n'.join(lines[1:-1])
    value=json.loads(text)
    if not isinstance(value,dict):raise ValueError('Expected JSON object')
    return value

SIGNATURE_FIELDS=('predicate','target','value','vep_category','operator','expected','necessity',
                  'evidence_directness','operator_observable','review_status')
def atom(item):
    return tuple(json.dumps(item.get(k),ensure_ascii=False,sort_keys=True) for k in SIGNATURE_FIELDS)

def condition_set(prediction):return {atom(p) for p in prediction.get('prerequisites',[])}

def cited_set(prediction):
    return {(atom(p),tuple(sorted(json.dumps(r,sort_keys=True) for r in p['source_refs'])))
            for p in prediction['prerequisites']}

def nonrequirement_set(prediction):
    return {(p.get('vep_category'),p['statement'],tuple(sorted(json.dumps(r,sort_keys=True) for r in p['source_refs'])))
            for p in prediction['nonrequirements']}

def prf(tp,fp,fn):
    return dict(precision=tp/(tp+fp) if tp+fp else None,recall=tp/(tp+fn) if tp+fn else None,
                f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None)

def relation_set(prediction):
    by_id={p['id']:atom(p) for p in prediction['prerequisites']}
    def walk(expr):
        if 'condition' in expr:return ('condition',by_id[expr['condition']])
        return (expr['op'],tuple(sorted((walk(a) for a in expr['args']),key=repr)))
    return {(tuple(sorted(s['product_keys'])),walk(s['expression'])) for s in prediction['scenarios']}

def record_value(prediction,packet):
    """Policy result as well as raw label; unknown is retained, never scored positive."""
    got=prediction['records'];expected={r['id'] for r in packet['records']}
    if len(got)!=len(expected) or {r['evidence_id'] for r in got}!=expected:raise ValueError('Missing/extra record')
    values=set()
    for row in got:
        if row['quote_evidence_id'] not in ('',row['evidence_id']):raise ValueError('Invalid citation')
        value=row['value']
        if value!='unknown' and not row['quote_evidence_id']:raise ValueError('Uncited resolved state')
        if not row['scope_matches'] or not row['current_applied_state']:value='unknown'
        values.add(value)
    return next(iter(values)) if len(values)==1 else 'unknown'

def score(role,inputs,predictions,labels):
    from jsonschema import Draft202012Validator
    counts=Counter();confusion=Counter();subgroups={};n=len(inputs)
    by_id={p['id']:p for p in predictions};gold={p['id']:p for p in labels}
    if len(by_id)!=n or set(by_id)!={r['id'] for r in inputs}:raise ValueError('Incomplete TEST predictions')
    for row in inputs:
        result=by_id[row['id']];target=gold[row['id']]['target'];counts['total']+=1
        prediction=None;valid=False
        try:
            if result.get('error'):raise ValueError(result['error'])
            prediction=parse(result['text'])
            Draft202012Validator(row['packet']['schema']).validate(prediction)
            counts['json_schema_valid']+=1
            if role=='exploitation-prerequisites':
                # The production validator also checks source identity and exact references.
                from src.item4.analysis import exploitation_prerequisites as V
                record={k:row['packet'][k] for k in ('cve','sources','products')}
                V.validate(V.resolve_references(prediction,row['packet']),record)
            valid=True;counts['valid']+=1
        except Exception:counts['invalid']+=1
        if role=='operating-record-review':
            expected=target['records'][0]['value'];actual='invalid';raw='invalid'
            if valid:
                try:
                    actual=record_value(prediction,row['packet']);raw=prediction['records'][0]['value']
                except Exception:actual='invalid';counts['policy_invalid']+=1
            confusion[expected,actual]+=1
            variant=gold[row['id']]['authority']['variant']
            subgroup=subgroups.setdefault(str(variant),Counter())
            subgroup['total']+=1;subgroup['correct']+=actual==expected
            subgroup['unknown_predictions']+=actual=='unknown';subgroup['invalid_predictions']+=actual=='invalid'
            counts['raw_correct']+=raw==expected;counts['correct']+=actual==expected
        else:
            expected=condition_set(target);actual=set()
            if valid:
                actual=condition_set(prediction)
                counts['condition_set_exact']+=actual==expected
                counts['condition_nonempty_exact']+=bool(expected) and actual==expected
                counts['relation_set_exact']+=relation_set(prediction)==relation_set(target)
                counts['relation_nonempty_exact']+=bool(target['scenarios']) and relation_set(prediction)==relation_set(target)
                counts['V1_claims_exact']+=prediction.get('applicability_claims',[])==target.get('applicability_claims',[])
                counts['unknowns_present_match']+=bool(prediction['unknowns'])==bool(target['unknowns'])
                counts['abstained_without_conditions']+=not bool(actual)
            counts['condition_tp']+=len(expected & actual)
            counts['condition_fp']+=len(actual-expected);counts['condition_fn']+=len(expected-actual)
            counts['reference_nonempty']+=bool(expected)
            counts['reference_scenario_cases']+=bool(target['scenarios'])
            for prefix,reference,predicted in (
                ('condition_and_citation',cited_set(target),cited_set(prediction) if valid else set()),
                ('nonrequirement',nonrequirement_set(target),nonrequirement_set(prediction) if valid else set())):
                counts[prefix+'_tp']+=len(reference & predicted)
                counts[prefix+'_fp']+=len(predicted-reference);counts[prefix+'_fn']+=len(reference-predicted)
                counts[prefix+'_reference_nonempty']+=bool(reference)
                counts[prefix+'_nonempty_exact']+=valid and bool(reference) and predicted==reference
            counts['reference_bound_scenarios']+=sum(bool(s['product_keys']) for s in target['scenarios'])
            counts['predicted_bound_scenarios']+=sum(bool(s['product_keys']) for s in prediction['scenarios']) if valid else 0
    metrics=dict(role=role,test_cases=n,counts=dict(counts),all_cases_in_denominator=True,
        schema_valid_rate=counts['json_schema_valid']/n,
        validated_output_rate=(counts['valid']-counts['policy_invalid'])/n,
        invalid_output_rate=(counts['invalid']+counts['policy_invalid'])/n,
        expert_gold=False,independent_real_asset_accuracy_verified=False)
    if role=='operating-record-review':
        classes=('true','false','unknown');per_class={}
        for c in classes:
            tp=confusion[c,c];fp=sum(v for (a,b),v in confusion.items() if b==c and a!=c)
            fn=sum(v for (a,b),v in confusion.items() if a==c and b!=c)
            precision=tp/(tp+fp) if tp+fp else None;recall=tp/(tp+fn) if tp+fn else None
            per_class[c]=dict(precision=precision,recall=recall,f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,support=tp+fn)
        metrics.update(accuracy=counts['correct']/n,raw_accuracy=counts['raw_correct']/n,
            confusion={a:{b:confusion[a,b] for b in (*classes,'invalid')} for a in classes},per_class=per_class,
            macro_f1=sum(v['f1'] or 0 for v in per_class.values())/3,
            synthetic_variant_metrics={k:dict(v,accuracy=v['correct']/v['total']) for k,v in subgroups.items()},
            variant_definitions={'0':'current positive','1':'current positive paraphrase','2':'current positive verified','3':'explicit complete negative','4':'complete negative paraphrase','5':'all scoped instances negative','6':'historical','7':'planned unapplied','8':'wrong asset','9':'wrong build','10':'missing evidence','11':'conflicting current records'},
            interpretation='Synthetic conditional record comprehension, not real CVE exploitability precision')
    else:
        tp=counts['condition_tp'];fp=counts['condition_fp'];fn=counts['condition_fn']
        metrics.update(condition_micro_precision=tp/(tp+fp) if tp+fp else None,
            condition_micro_recall=tp/(tp+fn) if tp+fn else None,
            condition_micro_f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,
            condition_set_exact_rate=counts['condition_set_exact']/n,
            condition_nonempty_exact_rate=counts['condition_nonempty_exact']/counts['reference_nonempty'] if counts['reference_nonempty'] else None,
            V1_claims_exact_rate=counts['V1_claims_exact']/n,
            relation_set_exact_rate=counts['relation_set_exact']/n,
            relation_nonempty_exact_rate=counts['relation_nonempty_exact']/counts['reference_scenario_cases'] if counts['reference_scenario_cases'] else None,
            condition_signature_fields=list(SIGNATURE_FIELDS),
            condition_and_citation=prf(counts['condition_and_citation_tp'],counts['condition_and_citation_fp'],counts['condition_and_citation_fn']),
            nonrequirements=prf(counts['nonrequirement_tp'],counts['nonrequirement_fp'],counts['nonrequirement_fn']),
            interpretation='Agreement with automatic weak source annotations; no independent semantic Gold')
    return metrics

def main(args):
    import torch
    from transformers import AutoModelForCausalLM,AutoTokenizer
    from peft import PeftModel
    args.output.mkdir(parents=True,exist_ok=True);started=time.time()
    status_path=args.output/'status.json'
    def status(**kw):dump(status_path,dict(updated_at=time.time(),**kw))
    pins=json.loads(args.base_pin.read_text(encoding='utf-8'))
    for name,expected in pins.items():
        if sha(args.base/name)!=expected:raise ValueError('Pinned base changed')
    manifest=json.loads((args.data/'manifest.json').read_text(encoding='utf-8'))
    torch.set_num_threads(4)
    torch.cuda.set_per_process_memory_fraction(min(.95,args.memory_gib*1024**3/torch.cuda.get_device_properties(0).total_memory),0)
    tok=AutoTokenizer.from_pretrained(str(args.base),local_files_only=True,padding_side='left')
    from src.common.runtime.json_output_constraints import prefix_for_schema
    runtime=SimpleNamespace(tok=tok)
    if tok.pad_token_id is None:tok.pad_token=tok.eos_token
    status(state='running',stage='loading_model')
    base=AutoModelForCausalLM.from_pretrained(str(args.base),local_files_only=True,device_map={'':0},dtype=torch.bfloat16,attn_implementation='sdpa')
    model=None;reports={};batch_size=args.batch_size
    for role,alias in ROLES.items():
        folder=args.adapters/alias;marker=json.loads((folder/'training_complete.json').read_text(encoding='utf-8'))
        if marker['role']!=role or marker['adapter_sha256']!=sha(folder/'adapter_model.safetensors'):raise ValueError('Adapter role/hash mismatch')
        if marker['heldout_loaded'] or marker['examples']!=manifest['split_counts']['train']:raise ValueError('Invalid training provenance')
        model=PeftModel.from_pretrained(base,str(folder),adapter_name=alias,is_trainable=False) if model is None else model
        if alias not in model.peft_config:model.load_adapter(str(folder),adapter_name=alias,is_trainable=False)
        model.set_adapter(alias);model.eval();model.config.use_cache=True
        ip=args.data/role/'test/inputs.jsonl';lp=args.data/role/'test/labels.jsonl'
        for path in (ip,lp):
            if sha(path)!=manifest['sha256'][str(path.relative_to(args.data)).replace('\\','/')]:raise ValueError('Frozen TEST file changed')
        inputs=rows(ip);out=args.output/(alias+'.predictions.jsonl')
        existing=rows(out) if out.exists() else [];done={p['id'] for p in existing}
        if any(p.get('adapter_sha256')!=marker['adapter_sha256'] for p in existing):raise ValueError('Resume adapter changed')
        pending=[r for r in inputs if r['id'] not in done]
        with out.open('a',encoding='utf-8') as stream:
            cursor=0
            while cursor<len(pending):
                batch=pending[cursor:cursor+batch_size]
                prompts=[tok.apply_chat_template([dict(role='system',content=r['system']),dict(role='user',content=json.dumps(r['packet'],ensure_ascii=False,separators=(',',':')))],tokenize=False,add_generation_prompt=True) for r in batch]
                encoded=tok(prompts,return_tensors='pt',padding=True,add_special_tokens=False).to('cuda')
                constraints=[prefix_for_schema(runtime,r['packet']['schema']) for r in batch]
                def allowed(batch_id,ids):return constraints[batch_id](batch_id,ids)
                try:
                    with torch.inference_mode():
                        generated=model.generate(**encoded,do_sample=False,max_new_tokens=args.max_new_tokens,pad_token_id=tok.pad_token_id,eos_token_id=tok.eos_token_id,prefix_allowed_tokens_fn=allowed,logits_to_keep=1)
                    width=encoded.input_ids.shape[1]
                    outputs=[dict(id=r['id'],cve=r['cve'],text=tok.decode(generated[i,width:],skip_special_tokens=True),generated_tokens=int((generated[i,width:]!=tok.pad_token_id).sum()),adapter_sha256=marker['adapter_sha256']) for i,r in enumerate(batch)]
                    del generated,encoded
                except torch.cuda.OutOfMemoryError:
                    encoded=None
                    import gc;gc.collect();torch.cuda.empty_cache()
                    if batch_size>1:batch_size=max(1,batch_size//2);continue
                    outputs=[dict(id=batch[0]['id'],cve=batch[0]['cve'],text='',error='CUDA OOM at batch size 1',adapter_sha256=marker['adapter_sha256'])]
                for value in outputs:
                    if value.get('generated_tokens',0)>=args.max_new_tokens:value['error']='Generation reached the production output token limit'
                    stream.write(json.dumps(value,ensure_ascii=False)+'\n')
                stream.flush();cursor+=len(batch)
                status(state='running',stage='generation',role=role,completed=len(done)+cursor,total=len(inputs),elapsed_seconds=time.time()-started,batch_size=batch_size)
        # First point at which held-out labels enter the evaluator process.
        reports[role]=score(role,inputs,rows(out),rows(lp))
        reports[role].update(adapter_sha256=marker['adapter_sha256'],predictions_sha256=sha(out),test_inputs_sha256=sha(ip),test_labels_sha256=sha(lp))
        dump(args.output/(alias+'.metrics.json'),reports[role])
    report=dict(state='complete',population=12418,test_cves=manifest['split_counts']['test'],roles=reports,
        dataset_manifest_sha256=sha(args.data/'manifest.json'),evaluator_sha256=sha(Path(__file__)),max_new_tokens=args.max_new_tokens,
        decoding='greedy with production JSON schema constraints',fixed_checkpoint_no_test_model_selection=True,nli_used=False,
        pipeline_scope='Single model pass; production relation retry and default-field enrichment are not applied; no operating-record lexical prefilter',
        real_asset_gold_available=False,production_accuracy_claim=False,elapsed_seconds=time.time()-started)
    dump(args.output/'report.json',report);status(state='complete',stage='evaluated',report_sha256=sha(args.output/'report.json'))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('data','base','base-pin','adapters','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--batch-size',type=int,default=2);parser.add_argument('--max-new-tokens',type=int,default=4096)
    parser.add_argument('--memory-gib',type=float,default=32)
    args=parser.parse_args()
    try:main(args)
    except Exception:
        dump(args.output/'failure.json',dict(state='failed',error=traceback.format_exc()));raise
