"""Run current #4 extraction, classification, keys and MulVAL on frozen worlds.

Only inference scheduling and the physical remote MulVAL transport are adapted.
The same model bytes, prompts, schemas, validation/retry logic and final #4
decision implementation are used. Gold is opened only after predictions close.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import queue
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'benchmark/item4_evaluation'
OUT = ROOT / 'results/item4_full_actual_20261120'
TOOL_SLOTS = threading.Semaphore(4)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


class BatchedProductionModel:
    """Same greedy constrained generation, batched without prompt alteration."""
    def __init__(self, size=16, grammar_backend='lmformatenforcer', compact=False, cached=False, rolling=False):
        import torch
        # cuDNN SDPA recompiles variable-length decode plans on this H200.
        # Keep the standard SDPA equation/dtypes and use its efficient/flash
        # backend, as in the existing H200 role-adapter evaluation setup.
        torch.backends.cuda.enable_cudnn_sdp(False)
        from src.common.runtime.shared_adapter_runtime import PrecisionRoleRuntime
        self.runtime = PrecisionRoleRuntime()
        self.runtime._load()
        self.runtime.tok.padding_side = 'left'
        if self.runtime.tok.pad_token_id is None:
            self.runtime.tok.pad_token_id = self.runtime.tok.eos_token_id
        self.grammar_backend=grammar_backend
        self.compact=compact
        self.cached=cached
        self.rolling=rolling
        self.tokenizer_lock=threading.Lock()
        if grammar_backend=='xgrammar':
            import xgrammar as xgr
            info=xgr.TokenizerInfo.from_huggingface(self.runtime.tok,
                vocab_size=self.runtime.model.config.vocab_size,
                stop_token_ids=self.runtime.model.generation_config.eos_token_id)
            self.grammar_compiler=xgr.GrammarCompiler(info,max_threads=5,cache_enabled=rolling)
        if cached:
            from tools.item4.research.probe_item4_optimized import run as probe
            probe(self.runtime,self.grammar_compiler,ROOT,OUT/'optimization_probe.json',rolling=rolling)
        self.size = size
        self.queue = queue.Queue()
        self.count = max((int(p.stem) for p in (OUT/'raw').glob('*.json')), default=0)
        self.request_count = max((int(p.stem) for p in (OUT/'requests').glob('*.json')), default=0)
        self.request_lock = threading.Lock()
        self.fatal_error = None
        self.worker = threading.Thread(target=self.loop, daemon=True)
        self.worker.start()

    def generate(self, system, packet, *, role):
        if self.fatal_error:
            raise RuntimeError(self.fatal_error)
        future = Future()
        with self.request_lock:
            self.request_count += 1
            future.request_id = self.request_count
            future.cve = packet.get('cve')
            future.input_sha256 = hashlib.sha256(json.dumps(packet,ensure_ascii=False,sort_keys=True).encode()).hexdigest()
            write(OUT/'requests'/(str(self.request_count).zfill(7)+'.json'),dict(
                request_id=future.request_id,cve=future.cve,role=role,input_sha256=future.input_sha256,
                system_sha256=hashlib.sha256(system.encode()).hexdigest()))
        if self.rolling:
            try:self.queue.put(self.prepare(future,system,packet,role))
            except Exception as exc:future.set_exception(exc)
        else:self.queue.put((future, system, packet, role))
        return future.result()

    def prepare(self,future,system,packet,role):
        from src.common.runtime.json_output_constraints import generation_schema; from src.common.runtime.json_output_constraints import prefix_for_schema
        with self.tokenizer_lock:
            prompt=self.runtime.tok.apply_chat_template([dict(role='system',content=system),
                dict(role='user',content=json.dumps(packet,ensure_ascii=False))],
                tokenize=False,add_generation_prompt=True,enable_thinking=False)
            token_ids=self.runtime.tok(prompt,add_special_tokens=False)['input_ids']
            if self.runtime.tok(prompt)['input_ids']!=token_ids:
                raise ValueError('Batched tokenization differs from the production tokenizer')
        length=len(token_ids)
        if length>6144:raise ValueError('Prerequisite input exceeds the bounded model context; no truncation is allowed')
        schema=packet.get('schema',dict(type='object'))
        schema=generation_schema(schema)
        prefix=(self.grammar_compiler.compile_json_schema(schema,strict_mode=False)
                if self.grammar_backend=='xgrammar' else prefix_for_schema(self.runtime,schema))
        return future,prompt,prefix,length,role

    def loop(self):
        import torch
        from src.common.runtime.json_output_constraints import prefix_for_schema; from src.common.runtime.json_output_constraints import generation_schema
        from src.item4.models.review_adapter_config import inference_context
        from src.item4.models.json_inference_client import parse_json
        while True:
            first = self.queue.get()
            if first is None:
                return
            chunk = [first]
            deadline = time.monotonic() + .2
            while len(chunk) < self.size:
                try:
                    chunk.append(self.queue.get(timeout=max(.001, deadline-time.monotonic())))
                except queue.Empty:
                    break
            ready = []
            for entry in chunk:
                try:
                    ready.append(entry if self.rolling else self.prepare(*entry))
                except Exception as exc:
                    entry[0].set_exception(exc)
            if not ready:
                continue
            try:
                with self.tokenizer_lock:
                    encoded = self.runtime.tok([r[1] for r in ready], padding=True, return_tensors='pt',
                                               add_special_tokens=False).to('cuda')
                def allowed(batch_id, sent):
                    return ready[batch_id][2](0, sent)
                from transformers import StoppingCriteria, StoppingCriteriaList
                started=time.monotonic()
                initial_length=encoded['input_ids'].shape[1]
                class Heartbeat(StoppingCriteria):
                    def __call__(self,input_ids,scores,**kwargs):
                        step=input_ids.shape[1]-initial_length
                        if step%32==0:
                            rss=next(int(line.split()[1])*1024 for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('VmRSS:'))
                            if rss>7*1024**3:
                                raise MemoryError('Host RAM admission guard reached; retry a smaller batch before the container OOM limit')
                        if step%128==0:
                            write(OUT/'generation_progress.json',dict(step=step,batch_size=len(ready),
                                batch_seconds=time.monotonic()-started,requests_completed=self_owner.count,
                                active_cves=[r[0].cve for r in ready],updated_at=time.time()))
                        return torch.zeros(input_ids.shape[0],dtype=torch.bool,device=input_ids.device)
                self_owner=self
                def complete(row, entry):
                    future, _, _, length, role = entry
                    if future.done():
                        return
                    raw = self.runtime.tok.decode(row, skip_special_tokens=True)
                    tokens = int((row != self.runtime.tok.pad_token_id).sum())
                    response = dict(raw=raw, role=role, llm_used=True,request_id=future.request_id,
                        cve=future.cve,input_sha256=future.input_sha256,
                        generation=dict(input_tokens=length, output_tokens=tokens, constrained_json=True,
                                        do_sample=False, batch_size=self.size if self.rolling else len(ready),
                                        batch_size_is_capacity=self.rolling,max_new_tokens=4096,
                                        grammar_backend=self.grammar_backend,
                                        completed_rows_removed=self.compact),
                        model=dict(provider='local_shared_role_adapter' if adapter else 'local_shared_base',
                                   model=self.runtime.model_name, adapter=adapter, nli_used=False))
                    self.count += 1
                    write(OUT/'raw'/(str(self.count).zfill(7)+'.json'), response)
                    try:
                        if tokens >= 4096:
                            raise ValueError('Incomplete prerequisite output at the 4096 token limit')
                        response['prediction'] = parse_json(raw)
                        future.set_result(response)
                    except Exception as exc:
                        exc.raw_output = raw
                        future.set_exception(exc)
                if self.grammar_backend=='xgrammar':
                    from xgrammar.contrib.hf import LogitsProcessor
                    grammar_options=dict(logits_processor=[LogitsProcessor([r[2] for r in ready])])
                else:
                    grammar_options=dict(prefix_allowed_tokens_fn=allowed)
                if self.rolling:
                    from tools.item4.item4_rolling_decode import rolling_sample
                    def refill(count):
                        entries=[];owners=[]
                        for _ in range(count):
                            try:entry=self.queue.get_nowait()
                            except queue.Empty:break
                            owners.append(len(ready));ready.append(entry);entries.append(entry)
                        if not entries:return None
                        with self.tokenizer_lock:
                            inputs=self.runtime.tok([r[1] for r in entries],padding=True,return_tensors='pt',add_special_tokens=False).to('cuda')
                        return dict(owners=owners,encoded=inputs,processors=[LogitsProcessor([r[2] for r in entries])])
                    grammar_options.update(custom_generate=rolling_sample,capacity=self.size,
                        on_generated=lambda owner,row:complete(row,ready[owner]),refill=refill)
                elif self.compact:
                    from tools.item4.item4_compact_decode import compact_sample
                    grammar_options.update(custom_generate=compact_sample,
                        on_complete=lambda owner,sequence:complete(sequence[initial_length:],ready[owner]))
                with inference_context(self.runtime, ready[0][4]) as adapter, torch.inference_mode():
                    if not (OUT/'runtime_metadata.json').exists():
                        from importlib.metadata import version
                        alias=(adapter or {}).get('alias')
                        dtypes=sorted({str(p.dtype) for name,p in self.runtime.model.named_parameters()
                            if alias and '.lora_' in name and ('.'+alias+'.') in name})
                        if adapter and dtypes!=['torch.float32']:
                            raise RuntimeError('The production FP32 role-adapter computation was not preserved: '+str(dtypes))
                        write(OUT/'runtime_metadata.json',dict(
                            model_backend='Production Transformers/Peft/bitsandbytes with cached NF4 values' if self.cached else 'Unmodified production Transformers/Peft/bitsandbytes runtime',
                            grammar_backend=self.grammar_backend,
                            completed_rows_removed_from_decode=self.compact,
                            cached_dequantized_NF4_values=self.cached,
                            rolling_refill=self.rolling,
                            grammar_value_membership='source-specific token mask and unchanged source-specific postvalidation/repair',
                            versions={p:version(p) for p in ['torch','transformers','peft','bitsandbytes']+(['xgrammar'] if self.grammar_backend=='xgrammar' else ['lm-format-enforcer'])},
                            role_adapter=adapter,role_adapter_parameter_dtypes=dtypes,
                            eos_token_ids=self.runtime.model.generation_config.eos_token_id,
                            repetition_penalty=self.runtime.model.generation_config.repetition_penalty,
                            model_weights_and_arithmetic_dtypes_unchanged=True,checkpoint_or_quantization_changed=False,
                            attention_backend=dict(api='torch SDPA',cudnn_enabled=torch.backends.cuda.cudnn_sdp_enabled(),
                                efficient_enabled=torch.backends.cuda.mem_efficient_sdp_enabled(),
                                flash_enabled=torch.backends.cuda.flash_sdp_enabled()),
                            runtime_bitwise_equivalence_asserted=False,
                            decoder_bitwise_equivalence_asserted=False,
                            decoder_scope='Same source JSON schema and postvalidation; native grammar masking replaces Python grammar masking only'))
                    output = self.runtime.model.generate(**encoded, max_new_tokens=4096,
                        do_sample=False, pad_token_id=self.runtime.tok.pad_token_id,
                        use_cache=True, logits_to_keep=1, **grammar_options,
                        stopping_criteria=StoppingCriteriaList([Heartbeat()]))
                generated = output[:, encoded['input_ids'].shape[1]:]
                for row, entry in zip(generated, ready):
                    complete(row, entry)
            except BaseException as exc:
                resource_failure=isinstance(exc,MemoryError) or 'out of memory' in str(exc).casefold()
                if resource_failure and len(ready)>1:
                    import gc
                    self.size=max(1,self.size//2)
                    write(OUT/'batch_resource_retry.json',dict(batch_size=self.size,error=str(exc),
                        source_gold_and_model_unchanged=True,time=time.time()))
                    for entry in (ready if self.rolling else chunk):
                        if not entry[0].done():self.queue.put(entry)
                    ready.clear()
                    if 'encoded' in locals():del encoded
                    if 'output' in locals():del output
                    gc.collect();torch.cuda.empty_cache()
                    continue
                if resource_failure:
                    self.fatal_error='A single model request exceeded host/GPU memory; evaluation is incomplete: '+str(exc)
                elif self.rolling:
                    self.fatal_error='Rolling model generation failed; evaluation is incomplete: '+str(exc)
                for future, *_ in ready:
                    if not future.done():
                        future.set_exception(exc)
                if 'out of memory' in str(exc).casefold():
                    torch.cuda.empty_cache()


def install_remote_mulval():
    """Use the real existing PRoot MulVAL backend without nested Kubernetes exec."""
    from src.item4.decision import mulval_attack_graphs as M
    migration = Path(os.environ['ICSVEX_MIGRATION_ROOT'])
    def execute(program):
        import importlib.util
        import tempfile
        spec = importlib.util.spec_from_file_location('actual_mulval_backend', ROOT / 'tools/item4/ncp_operational_runtime.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        parent = OUT / 'mulval_runs'; parent.mkdir(exist_ok=True)
        folder = Path(tempfile.mkdtemp(prefix=program['sha256'][:20]+'-', dir=parent))
        (folder / 'input.P').write_text(program['input_P'])
        (folder / 'rules.P').write_text(program['rules_P'])
        tool = program.get('execution_tool_root', '/opt/mulval-population')
        with TOOL_SLOTS:
            result = module.run(['env', 'MULVALROOT='+tool, 'graph_gen.sh', '-r', '/work/rules.P',
                                 '/work/input.P', '-l', '-t', program.get('trace_mode', 'completeTrace2')], folder, 'generation')
        names = ['VERTICES.CSV','ARCS.CSV','AttackGraph.txt','trace_output.P','xsb_log.txt']
        files = {n:(folder/n).read_text(errors='replace') for n in names if (folder/n).exists()}
        pins = {}
        for n in ['utils/graph_gen.sh','bin/attack_graph','lib/libmulval.P','src/analyzer/translate.P','src/analyzer/attack_trace.P']:
            p = migration / 'operational_rootfs' / tool.lstrip('/') / n
            if p.exists():
                pins[n] = hashlib.sha256(p.read_bytes()).hexdigest()
        return dict(returncode=result.returncode, files=files, stdout=result.stdout, stderr=result.stderr,
                    tool_sha256=pins, backend='ncp-isolated-proot', remote_directory=str(folder),
                    trace_mode=program.get('trace_mode','completeTrace2'))
    M._remote_run = execute
    os.environ['ICSVEX_MULVAL_BACKEND'] = 'ncp'


def normalized(value):
    return ' '.join(str(value).casefold().split())


def operator_answer(question, records):
    """Strict source-local record transfer; never consult variant or gold.

    Ambiguous/multiple source conditions or positive-polarity interpretation
    cannot be resolved by an all-yes/all-no shortcut.
    """
    values = set()
    for record in records:
        ref = record['source_ref']
        if not any(r['source_id'] == ref['source_id'] for r in question['source_refs']):
            continue
        if normalized(question['operational_quote']) != normalized(ref['quote']):
            continue
        statement = normalized(record['statement'])
        # Negative wording needs a dedicated semantic review; do not guess it.
        if any(word in statement.split() for word in ('disabled','without','unless','not')):
            continue
        values.add(record['value'])
    return 'mixed' if len(values) > 1 else ('o' if next(iter(values)) else 'x') if values else 'unknown'


def run_cve(item, model):
    from src.item4.workflow import source_analysis_jobs as Q; from src.item4.assets import asset_observations as I; from src.item4.decision import asset_vex_assessment as E
    from src.item4.analysis import product_advisory_evidence as C
    cve = item['cve']
    location = OUT / 'cves' / (cve + '.json')
    if location.exists():
        return json.loads(location.read_bytes())
    bom = item['bom']; components, declared = Q.inventory(bom)
    selected = next(c for c in components if c['ref'] == item['cases'][0]['component_ref'])
    identities = [dict(C.component_identity(c), type=c['value'].get('type')) for c in components]
    begin = time.monotonic(); error = None
    try:
        extraction = Q.extract_declared(cve, components)
    except Exception as exc:
        extraction = dict(cve=cve, status='unresolved', reason=type(exc).__name__+': '+str(exc))
    if model.fatal_error:
        raise RuntimeError(model.fatal_error)
    try:
        classification = Q.classify(bom, selected)
    except Exception as exc:
        classification = dict(status='unresolved', reason=type(exc).__name__+': '+str(exc), component_classifications=[])
    job = dict(id='benchmark-'+cve, status='completed', revision=1, bom_sha256=Q.digest(bom),
        input_bom=bom, components=identities, representative=dict(ref=selected['ref'], name=selected['name'], pointer=selected['pointer']),
        declared_cves=declared, conditions=[extraction], asset_classification=classification,
        answers={}, context_answers={})
    I.prepare(job, Q.digest)
    predicted = []
    for case in item['cases']:
        work = deepcopy(job)
        work['answers'] = {q['id']: operator_answer(q, case['operating_records']) for q in work['questions']}
        work['context_answers'] = {k:v for k,v in case['context'].items() if k in ('scope','mode','origin')}
        for assessed in work['assessment_cases']:
            for k in ('deployment','runtime'):
                work['context_answers'][assessed['prefix']+k] = case['context'][k]
        try:
            report = E.evaluate(work)
            row = report['decisions'][0]
            predicted.append(dict(id=case['id'], cve=cve, status=row['status'], reason=row['reason'],
                product_applicability=row['product_applicability'], prerequisite_status=row['prerequisite_status'],
                deployment_exploitability=row['deployment_exploitability'],
                graph_generation_status=row['attack_graph'].get('generation_status'),
                graph_sha256=row['attack_graph'].get('sha256'),
                answers=work['answers'], source_extraction_sha256=(extraction.get('prerequisite') or {}).get('sha256')))
        except Exception as exc:
            predicted.append(dict(id=case['id'], cve=cve, status='under_investigation',
                                  error=type(exc).__name__+': '+str(exc), traceback=traceback.format_exc()))
    result = dict(cve=cve, extraction=extraction, classification=classification, predictions=predicted,
                  seconds=time.monotonic()-begin)
    write(location, result)
    return result


def summarize():
    from math import sqrt
    predictions = []
    for path in sorted((OUT / 'cves').glob('CVE-*.json')):
        predictions += json.loads(path.read_bytes())['predictions']
    # Close the prediction export before opening frozen reference labels.
    with (OUT / 'predictions.jsonl').open('w', encoding='utf-8') as f:
        for row in predictions:
            f.write(json.dumps(row, ensure_ascii=False)+'\n')
    gold = {r['id']:r for r in map(json.loads, (DATA/'full_population_gold.jsonl').open(encoding='utf-8'))}
    assert len(predictions) == len({r['id'] for r in predictions}) == len(gold) == 62090
    assert {r['id'] for r in predictions} == set(gold)
    def metrics(rows):
        tp=fp=unjudged=fn=abstentions=known=positive=0
        for p in rows:
            actual = gold[p['id']]['actual_affected']; affected=p['status']=='affected'
            tp += affected and actual is True; fp += affected and actual is False
            unjudged += affected and actual is None; fn += not affected and actual is True
            known += actual is not None; positive += actual is True
            abstentions += p['status']=='under_investigation'
        precision=100*tp/(tp+fp) if tp+fp and not unjudged else None
        return dict(cases=len(rows), TP=tp, FP=fp, unjudged_predicted_affected=unjudged,
                    FN_including_abstentions=fn, precision_percent=precision,
                    precision_on_judged_predictions_percent=100*tp/(tp+fp) if tp+fp else None,
                    conservative_precision_lower_bound_percent=100*tp/(tp+fp+unjudged) if tp+fp+unjudged else None,
                    recall_percent=100*tp/positive if positive else None,
                    abstention_percent=100*abstentions/len(rows), known_labels=known,
                    unknown_labels=len(rows)-known, status_counts=dict(Counter(p['status'] for p in rows)),
                    target_met=precision>85 if precision is not None else None)
    by_cve=defaultdict(list); by_variant=defaultdict(list)
    for p in predictions:
        by_cve[p['cve']].append(p); by_variant[gold[p['id']]['variant']].append(p)
    report=dict(status='complete', population_cves=len(by_cve), llm_requests=len(list((OUT/'raw').glob('*.json'))),
        all_cases=metrics(predictions), per_variant={k:metrics(v) for k,v in by_variant.items()},
        CVEs_with_positive_reference=len({r['cve'] for r in gold.values() if r['actual_affected'] is True}),
        CVEs_with_unknown_context_reference=len({r['cve'] for r in gold.values() if r['actual_affected'] is None}),
        model_config=json.loads((OUT/'run_config.json').read_bytes()),
        metric_scope='Current #4 pipeline on full-population source-conditioned hypothetical worlds; not real asset accuracy',
        sources_without_supported_positive_reference_retained=True,
        independent_semantic_accuracy_verified=False, test_predictions_used_to_select_checkpoint=False,
        no_failed_or_unjudged_CVEs_excluded=True,
        per_cve={k:metrics(v) for k,v in by_cve.items()})
    if (OUT/'runtime_metadata.json').exists():
        report['inference_runtime']=json.loads((OUT/'runtime_metadata.json').read_bytes())
    write(OUT/'report.json',report)
    return report


def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--limit',type=int)
    parser.add_argument('--batch-size',type=int,default=4)
    parser.add_argument('--threads',type=int,default=8)
    parser.add_argument('--engine',choices=['hf','hf_xgrammar','hf_xgrammar_compact','hf_xgrammar_compact_cached','hf_xgrammar_compact_cached_rolling'],default='hf')
    args=parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    state=dict(status='running',stage='initializing',started_at=time.time(),population_cves=12418)
    write(OUT/'status.json',state)
    try:
        manifest=json.loads((DATA/'full_population_manifest.json').read_bytes())
        for name, expected in manifest['artifacts'].items():
            assert hashlib.sha256((DATA/name).read_bytes()).hexdigest()==expected
        from src.item4.analysis import exploitation_prerequisites as V
        from src.item4.models.review_adapter_config import active_roles
        from src.item4.models.json_inference_client import identity
        config=dict(model=identity('exploitation-prerequisites'), roles=active_roles(),
                    frozen_manifest_sha256=hashlib.sha256((DATA/'full_population_manifest.json').read_bytes()).hexdigest(),
                    code_sha256={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in (ROOT/'src').rglob('*.py')},
                    prompts_sha256=hashlib.sha256(V.SYSTEM.encode()).hexdigest(),
                    inference_engine=args.engine,
                    attention_backend_policy='Standard SDPA with cuDNN SDP disabled on H200; no weight or dtype change',
                    evaluation_code_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in
                        [ROOT/'tools/item4/run_item4_full_actual.py',ROOT/'tools/item4/item4_compact_decode.py',
                         ROOT/'tools/item4/research/probe_item4_optimized.py',ROOT/'tools/item4/item4_rolling_decode.py'] if p.exists()},
                    batching='Same greedy NF4 model, FP32 LoRA, production tokenizer, JSON schema, validation and 6144/4096 token limits; grammar engine recorded separately',
                    weights_retrained=False, graph_backend='actual isolated PRoot MulVAL/XSB')
        if (OUT/'run_config.json').exists():
            previous=json.loads((OUT/'run_config.json').read_bytes())
            assert previous==config,'Run configuration changed; use a new run directory'
        write(OUT/'run_config.json',config)
        # The H200 has ample VRAM but this container has only ~10.5 GiB host RAM.
        # Never co-load another inference runtime beside the existing Item 3 job.
        import subprocess
        while True:
            gpu_processes=subprocess.run(['nvidia-smi','--query-compute-apps=pid','--format=csv,noheader,nounits'],
                                         capture_output=True,text=True,check=True).stdout.splitlines()
            other=[int(p.strip()) for p in gpu_processes if p.strip().isdigit() and int(p.strip())!=os.getpid()]
            known=Path(os.environ['ICSVEX_MIGRATION_ROOT'])/'item3-benchmark-runs/20261119_parser_cisa_v1/worker.pid'
            if known.exists():
                pid=int(known.read_text())
                command=Path('/proc')/str(pid)/'cmdline'
                if command.exists() and b'h200_worker.py' in command.read_bytes() and pid not in other:
                    other.append(pid)
            if not other:break
            state.update(stage='waiting_for_existing_GPU_job',other_gpu_pids=other,updated_at=time.time())
            write(OUT/'status.json',state)
            time.sleep(10)
        state['stage']='loading_frozen_production_model';state.pop('other_gpu_pids',None);write(OUT/'status.json',state)
        model=BatchedProductionModel(args.batch_size,
            grammar_backend='xgrammar' if args.engine.startswith('hf_xgrammar') else 'lmformatenforcer',
            compact=args.engine.startswith('hf_xgrammar_compact'),
            cached=args.engine.startswith('hf_xgrammar_compact_cached'),
            rolling=args.engine.endswith('_rolling'))
        # Cache transport is removed for isolation; validation and repair are
        # exactly production V.extract, invoked by production Q.extract_declared.
        V.resolve=lambda record:V.extract(record,runner=model.generate)
        install_remote_mulval()
        items=[json.loads(s) for s in (DATA/'full_population_inputs.jsonl').open(encoding='utf-8')]
        if args.limit:
            items=items[:args.limit]
        pending=[r for r in items if not (OUT/'cves'/(r['cve']+'.json')).exists()]
        done=len(items)-len(pending);state.update(stage='actual_model_and_mulval',completed_cves=done,total_cves=len(items))
        write(OUT/'status.json',state)
        pool=ThreadPoolExecutor(max_workers=args.threads)
        try:
            futures={pool.submit(run_cve,item,model):item['cve'] for item in pending}
            for future in as_completed(futures):
                future.result();done+=1
                state.update(completed_cves=done,llm_requests=model.count,last_cve=futures[future],updated_at=time.time())
                write(OUT/'status.json',state)
                if done%25==0:print(json.dumps(state),flush=True)
        finally:
            pool.shutdown(wait=True,cancel_futures=True)
        if not args.limit and not model.count:
            raise RuntimeError('No actual model completions were produced; evaluation is incomplete')
        if not args.limit:
            summarize()
        state.update(status='complete',stage='complete',finished_at=time.time())
        write(OUT/'status.json',state)
    except BaseException:
        state.update(status='failed',error=traceback.format_exc(),finished_at=time.time())
        write(OUT/'status.json',state)
        raise
    finally:
        if 'model' in locals() and hasattr(model,'close'):
            model.close()


if __name__=='__main__':
    main()
