"""Frozen synthetic/MR evaluation with base/adapter and raw/pipeline ablations.

Gold is never passed to inference. Tuning selection reads DEV only. TEST is
scored after the selected candidate and baseline predictions are persisted.
"""
import sys,json,time,hashlib,threading,traceback,argparse
from pathlib import Path
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor,as_completed
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.evaluation import metamorphic_synthetic as E

ARMS=('A_base_raw','B_base_pipeline','C_adapter_raw','D_adapter_pipeline')
TUNING={
 'baseline':'',
 'faithful_atoms':'''\nAdditional extraction discipline: first identify the exact operating facts in the source, then represent each as a positive variable. Do not replace a named mode or setting with a guessed interface. Preserve every named target literally. Record a required absence with NOT over the positive atom, never with a negative atom. For a choice between two states, retain both variables and OR. Conditions in a necessary expression describe this path's requirements, not proof that exploitation succeeds. Keep implementation defects and update advice outside prerequisites. If the only operational requirement evidence was removed, return no prerequisites and explain the uncertainty. These are general reading rules, not facts about the supplied source.''',
 'logical_reading':'''\nBefore returning JSON, check that every source-required operating variable has its own short affirmative statement and its exact named target. Preserve source AND, inclusive OR, parentheses and negation in expression, without introducing extra states. A named operating mode is configuration_required in C7; a feature enabled state is feature_enabled in C1; an available input is interface_available in C2. Distinguish a source's prerequisite from the current deployed answer. Empty or defect-only passages require empty prerequisites and scenarios with an explicit unknown. Read the original evidence, not these instructions, to decide which facts exist.'''
}
for _candidate in ('faithful_atoms','logical_reading'):
    TUNING[_candidate]+='\nAn empty products list does not erase a described source path. If the source states a requirement and its relation, create its source-only scenario with product_keys=[] and product_binding="unresolved", and the complete expression over the extracted IDs. Do not put a parser/validation error in unknowns to avoid representing an explicit relation. For a single required atom the expression is {"condition":"its_actual_id"}. This source expression is separate from deployed-product applicability.'
TUNING['adapter_review']=TUNING['logical_reading']
TUNING['adapter_review_normalized']=TUNING['adapter_review']


def write(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.'+str(threading.get_ident())+'.tmp')
    temp.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8');temp.replace(path)


def prepare(folder):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=True)
    cases=E.dataset()
    inputs=[{k:deepcopy(c[k]) for k in ('id','base_id','family','split','variant','synthetic','record')} for c in cases]
    labels=[dict(id=c['id'],gold=c['gold']) for c in cases]
    write(folder/'inputs.json',inputs);write(folder/'gold.json',labels)
    manifest=dict(version=E.VERSION,base_worlds=384,cases=len(cases),dev_cases=sum(c['split']=='dev' for c in cases),
        test_cases=sum(c['split']=='test' for c in cases),families=12,variants=list(E.VARIANTS),seed='deterministic-enumeration',
        input_sha256=E.digest(inputs),gold_sha256=E.digest(labels),synthetic=True,independent_human_gold=False,
        split_policy='Related variants stay with their source world; DEV and TEST renderers are disjoint. Named-target lexical combinations are disjoint, semantic families are shared.',
        threshold=dict(comparison='>',percent=90,metrics=['condition_f1','logic_accuracy','grounded_mr_rate']),
        scope_limits=['Controlled short English requirements, not representative full real-CVE distribution.',
            'No multiple-product or cross-CVE source extraction cases in this version.',
            'No weight fine-tuning or production deployment is performed by this benchmark.'],
        matcher='Frozen predicate/category + full fictional named-target matching in target/statement; duplicates and negative atoms penalized.',
        decoding_parity='Pinned production weights; isolated vLLM backend, not exact deployed Transformers parity.')
    write(folder/'dataset_manifest.json',manifest);return manifest


def run(folder,url,token_file,identity_file,workers=4,baseline_test_only=False):
    import requests
    from src.item4.analysis import exploitation_prerequisites as V
    from src.item4.analysis import prerequisite_automation as A
    from src.item4.analysis import operational_evidence_catalogue as O
    from src.item4.analysis import condition_normalization as N
    from src.common.runtime.json_output_constraints import generation_schema
    from src.item4.evaluation import source_guard_candidate as GUARD
    from src.item4.evaluation import exact_atom_normalization as EXACT
    original_explicit=V.OP.EXPLICIT;original_nonrequirement=V.OP.NONREQUIREMENT
    original_polarity=V.OP.source_polarity
    out=Path(folder);inputs=json.loads((out/'inputs.json').read_text(encoding='utf-8'))
    # Labels are not loaded until DEV inference has finished.
    manifest=json.loads((out/'dataset_manifest.json').read_text());assert E.digest(inputs)==manifest['input_sha256']
    identity=json.loads(Path(identity_file).read_text());local=threading.local();cache_lock=threading.Lock();locks={}
    start=time.monotonic();stats=dict(generations=0,cache_hits=0);statslock=threading.Lock();transport_failed=threading.Event()
    def session():
        if not hasattr(local,'session'):
            local.session=requests.Session();local.session.trust_env=False
            local.session.headers['Authorization']='Bearer '+Path(token_file).read_text().strip()
        return local.session
    def canonical(n):
        if isinstance(n,list):return [canonical(x) for x in n]
        if not isinstance(n,dict):return n
        return {k:canonical(v) for k,v in n.items() if k!='uniqueItems' and not(n.get('type')=='array' and n.get('maxItems')==0 and k=='items')}
    def generate(system,packet,*,role,arm,phase,trace):
        if transport_failed.is_set():raise FileNotFoundError('Inference transport failed; stop and repair the service before resuming')
        adapter_role=role=='exploitation-prerequisites' or (phase in ('adapter_review','adapter_review_normalized') and role=='exploitation-coverage-review')
        model='vep-extraction' if 'adapter' in arm and adapter_role else 'qwen-base'
        system+=TUNING[phase]
        fingerprint=dict(system=system,packet=packet,model=model,identity=identity)
        if phase=='adapter_review_normalized':fingerprint['strict_boolean_constants']=True
        key=E.digest(fingerprint)
        path=out/'generation_cache'/(key+'.json')
        with cache_lock:lock=locks.setdefault(key,threading.Lock())
        with lock:
            if path.exists():
                result=json.loads(path.read_text());
                with statslock:stats['cache_hits']+=1
            else:
                begin=time.monotonic()
                decode_schema=packet['schema'] if phase=='adapter_review_normalized' else generation_schema(packet['schema'])
                body=dict(model=model,temperature=0,max_tokens=3072,chat_template_kwargs={'enable_thinking':False},
                    messages=[dict(role='system',content=system),dict(role='user',content=json.dumps(packet,ensure_ascii=False))],
                    response_format=dict(type='json_schema',json_schema=dict(name='vep',strict=True,schema=canonical(decode_schema))))
                try:
                    response=session().post(url+'/v1/chat/completions',json=body,timeout=(10,240));response.raise_for_status()
                except requests.RequestException as exc:
                    transport_failed.set();trace.append(dict(role=role,infrastructure_error=type(exc).__name__+': '+str(exc)))
                    raise
                raw=response.json();choice=raw['choices'][0]
                if choice['finish_reason']!='stop':raise ValueError('Incomplete generation: '+str(choice['finish_reason']))
                result=dict(prediction=json.loads(choice['message']['content']),raw=choice['message']['content'],llm_used=True,
                    model=dict(identity,served_model=model),generation=dict(usage=raw.get('usage'),elapsed_seconds=time.monotonic()-begin))
                write(path,result)
                with statslock:stats['generations']+=1
            if phase=='adapter_review_normalized':
                prediction,notes=EXACT.normalize(result['prediction'])
                trace.append(dict(role=role,cache_key=key,response=deepcopy(result),normalizations=notes))
                normalized=deepcopy(result);normalized['prediction']=prediction;return normalized
            trace.append(dict(role=role,cache_key=key,response=deepcopy(result)))
            return deepcopy(result)
    def one(item,arm,phase):
        path=out/'predictions'/phase/arm/(item['id']+'.json')
        if path.exists():
            old=json.loads(path.read_text())
            if phase=='baseline' or old.get('validation_candidate')==GUARD.VERSION:return old
            archive=out/'superseded_guard_predictions'/phase/arm/path.name;archive.parent.mkdir(parents=True,exist_ok=True)
            path.replace(archive)
        record=item['record'];row=dict(id=item['id'],arm=arm,phase=phase,valid=False,draft=None,trace=[],
            validation_candidate=GUARD.VERSION if phase!='baseline' else None)
        begin=time.monotonic()
        def runner(system,packet,*,role):return generate(system,packet,role=role,arm=arm,phase=phase,trace=row['trace'])
        try:
            if arm.endswith('_raw'):
                packet=V.TAXONOMY.bind_type_schema(O.bind(V.extraction_packet(record)))
                request=A.repair_request(packet,V.SYSTEM,'exploitation-prerequisites',None,None)
                response=runner(request['system'],request['payload'],role=request['role'])
                row['wire_prediction']=response['prediction']
                native=V.resolve_references(deepcopy(response['prediction']),packet)
                # Raw arm has no production normalization or repair. Validation is common scoring instrumentation.
                row['draft']=V.enrich(native);V.validate(row['draft'],record);row['valid']=True
            else:
                artifact=V.extract(record,runner=runner)
                row.update(draft=artifact['draft'],artifact=artifact,valid=True)
        except Exception as exc:row.update(error=type(exc).__name__+': '+str(exc),failure=getattr(exc,'failure',None))
        if any('infrastructure_error' in t for t in row['trace']) or row.get('error','').startswith('FileNotFoundError: Inference transport'):
            write(out/'infrastructure_failures'/phase/arm/(item['id']+'.json'),row)
            raise RuntimeError('Inference infrastructure failed; this case was not counted as a model error. Resume after service repair.')
        row['elapsed_seconds']=time.monotonic()-begin;write(path,row);return row
    def batch(items,phase,arms):
        # Phases execute sequentially; workers in a phase share one policy.
        # Baseline retains the exact original policy throughout its evaluation.
        V.OP.EXPLICIT=original_explicit if phase=='baseline' else GUARD.explicit(original_explicit)
        V.OP.NONREQUIREMENT=original_nonrequirement if phase=='baseline' else GUARD.nonrequirement(original_nonrequirement)
        V.OP.source_polarity=original_polarity if phase=='baseline' else GUARD.polarity(original_polarity)
        total=len(items)*len(arms);done=0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            pending=[pool.submit(one,i,a,phase) for a in arms for i in items]
            for f in as_completed(pending):
                f.result();done+=1
                write(out/'status.json',dict(state='running',phase=phase,split=items[0]['split'],completed=done,total=total,
                    elapsed_seconds=time.monotonic()-start,**stats))
    dev=[i for i in inputs if i['split']=='dev'];test=[i for i in inputs if i['split']=='test']
    if baseline_test_only:
        batch(test,'baseline',ARMS)
        batch(test,'adapter_review_normalized',('D_adapter_pipeline',))
        labels={x['id']:x['gold'] for x in json.loads((out/'gold.json').read_text())}
        cases=[dict(i,gold=labels[i['id']]) for i in inputs]
        rows=[]
        for phase,arms in [('baseline',ARMS),('adapter_review_normalized',('D_adapter_pipeline',))]:
            for item in inputs:
                for arm in arms:
                    p=out/'predictions'/phase/arm/(item['id']+'.json')
                    if p.exists():rows.append(json.loads(p.read_text()))
        report=E.summarize(cases,[r for r in rows if r['phase']=='baseline'])
        matched=E.summarize([c for c in cases if c['split']=='test'],[r for r in rows if r['phase']=='adapter_review_normalized'])
        report['scores'].update(matched['scores'])
        report.update(identity=identity,dataset_manifest=manifest,selection_split='DEV only; selected SFT checkpoint fixed before this TEST run.')
        write(out/'baseline_test_report.json',report)
        write(out/'status.json',dict(state='baseline_test_complete',elapsed_seconds=time.monotonic()-start,**stats))
        return
    batch(dev,'baseline',ARMS)
    labels={x['id']:x['gold'] for x in json.loads((out/'gold.json').read_text())}
    assert E.digest([dict(id=i['id'],gold=labels[i['id']]) for i in inputs])==manifest['gold_sha256']
    cases=[dict(i,gold=labels[i['id']]) for i in inputs]
    def results(phase,arms,items):
        return [json.loads((out/'predictions'/phase/arm/(i['id']+'.json')).read_text()) for i in items for arm in arms]
    dev_cases=[c for c in cases if c['split']=='dev']
    base_report=E.summarize(dev_cases,results('baseline',ARMS,dev));write(out/'development_baseline.json',base_report)
    baseline=base_report['scores']['baseline/D_adapter_pipeline/dev'];selection='baseline'
    candidates=[]
    if not baseline['above_90']:
        for phase in ('adapter_review','logical_reading','faithful_atoms'):
            batch(dev,phase,('D_adapter_pipeline',))
            report=E.summarize(dev_cases,results(phase,('D_adapter_pipeline',),dev));write(out/('development_'+phase+'.json'),report)
            candidates.append((phase,report['scores'][phase+'/D_adapter_pipeline/dev']))
            if candidates[-1][1]['above_90']:break
        def utility(s):return min(s['f1'] or 0,s['logic_accuracy'],s['grounded_mr_rate'] or 0),s['case_accuracy']
        selection=max([('baseline',baseline)]+candidates,key=lambda x:utility(x[1]))[0]
    write(out/'selection.json',dict(selected=selection,selection_split='dev',test_labels_used=False,
        criterion='Maximize minimum of condition F1, logic accuracy and grounded MR rate; tie-break case accuracy.',
        production_modified=False,weight_training=False,threshold=manifest['threshold'],
        candidate_guard=GUARD.VERSION,guard_basis='Independent contract tests for passive required/necessary wording and authentication nonrequirements; defined before TEST inference.'))
    chosen=baseline if selection=='baseline' else dict(candidates)[selection]
    if not chosen['above_90']:
        write(out/'development_comparison.json',E.summarize(dev_cases,
            results('baseline',ARMS,dev)+[p for phase,_ in candidates for p in results(phase,('D_adapter_pipeline',),dev)]))
        write(out/'status.json',dict(state='needs_weight_tuning',selected=selection,dev_metrics=chosen,
            test_started=False,reason='Prompt/structure candidates did not exceed all three 90% DEV thresholds.'))
        return
    # Freeze tuning selection before any TEST prediction is evaluated.
    batch(test,'baseline',ARMS)
    if selection!='baseline':batch(test,selection,('D_adapter_pipeline',))
    predictions=results('baseline',ARMS,inputs)
    for phase,_ in candidates:
        predictions+=results(phase,('D_adapter_pipeline',),dev)
        if phase==selection:predictions+=results(phase,('D_adapter_pipeline',),test)
    report=E.summarize(cases,predictions)
    report.update(selection=selection,identity=identity,dataset_manifest=manifest,generation_stats=stats,elapsed_seconds=time.monotonic()-start,
        tuning_completed=True,test_tuning_forbidden=True)
    write(out/'report.json',report);write(out/'status.json',dict(state='complete',selected=selection,elapsed_seconds=time.monotonic()-start,**stats))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['prepare','run']);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--url',default='http://127.0.0.1:18972');p.add_argument('--token-file');p.add_argument('--identity-file');p.add_argument('--workers',type=int,default=4)
    p.add_argument('--baseline-test-only',action='store_true')
    a=p.parse_args()
    if a.action=='prepare':print(json.dumps(prepare(a.output)))
    else:
        try:run(a.output,a.url,a.token_file,a.identity_file,a.workers,a.baseline_test_only)
        except Exception:
            write(a.output/'status.json',dict(state='failed',error=traceback.format_exc()));raise
