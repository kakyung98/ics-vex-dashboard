"""Queue local LLM proposals after training; never write expert labels or deploy."""
from pathlib import Path
import argparse,hashlib,json,os,sys,time,gzip
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.training_io import read_json,atomic_json
from src.gpu_lease import FILE,alive


def main():
    raise RuntimeError("This analysis-model queue is retired; LLM is reserved for final VEX writing.")
    p=argparse.ArgumentParser();p.add_argument('--limit',type=int,default=24);p.add_argument('--source-limit',type=int,default=16)
    p.add_argument('--output',default='results/item4_research_v1');p.add_argument('--source-only',action='store_true');a=p.parse_args()
    out=ROOT/a.output;out.mkdir(parents=True,exist_ok=True)
    state={'pid':os.getpid(),'phase':'waiting_for_training','expert_gold':False,'independent_review':False,
           'external_model_api_calls':0,'train_ready_labels_created':0,'deployment_approved':False}
    def status(phase,**extra):
        state.update(phase=phase,updated_at=__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),**extra)
        atomic_json(out/'status.json',state)
    status('waiting_for_training')
    while True:
        queue=read_json(ROOT/'results/operational_role_finetune_v3/queue_status.json')
        if queue.get('phase')=='failed':raise RuntimeError('Training failed; research inference did not start.')
        lease=read_json(FILE)
        if queue.get('phase')=='complete' and not alive(queue.get('pid')) and not (lease.get('active') and (alive(lease.get('pid')) or alive(lease.get('child_pid')))):break
        time.sleep(5)
    atomic_json(FILE,{'pid':os.getpid(),'active':True,'purpose':'Same-base research proposal generation; not independent gold'})
    try:
        # The web service releases its shared model under its inference lock.
        import requests
        response=requests.post('http://127.0.0.1:8100/api/cve-match/models/unload',timeout=600)
        response.raise_for_status()
        from src import vex_roles as VR
        from src.cve_source_evidence import catalog,resolve_selection
        from src.item4_questions import topics,validate as validate_questions
        from src.operational_questions import _validate_questions
        from src.operational_guardrails import assessment_gate
        from src.item4_role_tasks import check as check_role_output
        from src.research_review import validate as validate_review
        rows=[json.loads(l) for l in (ROOT/'data/operational_expansion_v1/train.inputs.jsonl').read_text(encoding='utf-8').splitlines()]
        buckets={}
        for row in rows:
            rule=next((d['rule_id'] for d in row['analysis_route_prediction']['decisions'] if d['requirement']=='operational_review'),'unknown')
            buckets.setdefault(rule,[]).append(row)
        selected=[];groups=set()
        while not a.source_only and len(selected)<a.limit:
            before=len(selected)
            for rule,pool in sorted(buckets.items()):
                while pool and pool[0]['group_id'] in groups:pool.pop(0)
                if pool and len(selected)<a.limit:
                    row=pool.pop(0);selected.append(row);groups.add(row['group_id'])
            if before==len(selected):break
        atomic_json(out/'manifest.json',{'selected_cves':[r['cve'] for r in selected],'split':'train',
            'selection':'round robin routing rule, distinct global groups','same_base_critic':True,
            'labels_are_proposals_not_gold':True,'training_data_modified':False})
        for i,row in enumerate(selected):
            dest=out/(row['cve']+'.json')
            if dest.exists():continue
            status('operational_curation',processed=i,total=len(selected),cve=row['cve'])
            sources=[s for s in catalog(row['cve'],row['description']) if s['source_kind'] in {'description','summary','cvss'}][:8]
            packet={'vulnerability':row['cve'],'sources':[{k:s[k] for k in ['id','text','source_kind','condition_eligible']} for s in sources]}
            condition=VR.infer('condition-evidence',packet)
            resolved,condition_errors=resolve_selection(sources,condition.get('prediction'))
            case={**row,'analysis_route':row['analysis_route_prediction']}
            qpacket={'cve':row['cve'],'description':row['description'],'cwe':row['cwe'],
                'sources':packet['sources'],'common_topics':topics(case),'pillar_ids':case['analysis_route']['pillars'],
                'extraction':{'status':'source_id_resolved' if resolved else 'unresolved','usable':bool(resolved),
                    'condition_evidence_ids':sorted({sid for claim in (condition.get('prediction') or {}).get('conditions',[]) for sid in claim.get('evidence_ids',[])}) if resolved else [],
                    'function_candidates':[f['name'] for f in (resolved or {}).get('prediction',{}).get('function_candidates',[])],
                    'completeness':'not_established','can_refute':False},
                'component':'unspecified actual asset','version':None}
            condition_claims=[{'id':row['cve']+':condition:'+str(j),'kind':claim['kind'],
                'source_ids':[s['id'] for s in sources if s['text']==claim['evidence']]}
                for j,claim in enumerate((resolved or {}).get('prediction',{}).get('conditions',[]))]
            attempts=[];critic=None;safety=[];quality=False
            for attempt in range(2):
                questions=VR.infer('item4-questions',qpacket)
                valid,qs,errors,normalizations=validate_questions(questions,sources,case,_validate_questions)
                qs=[{'id':row['cve']+':research-q:'+str(j),'origin':'llm',**q} for j,q in enumerate(qs)] if valid else []
                critic=None;quality=False
                if qs:
                    critic_packet={'cve':row['cve'],'description':row['description'],'sources':packet['sources'],
                                   'questions':qs,'conditions':condition_claims}
                    critic=VR.infer('research-question-review',critic_packet)
                    cv,ce=validate_review('research-question-review',critic_packet,critic.get('prediction'))
                    critic.update(contract_valid=cv,validation_errors=ce,independent_review=False)
                    quality=bool(cv and all(r['support']=='supported' and r['answerability']=='operator_answerable'
                                           for r in critic['prediction']['question_reviews']))
                attempts.append({'generation':questions,'validation_errors':errors,'normalizations':normalizations,
                                 'same_base_critic':critic,'same_base_question_review_passed':quality})
                if quality or questions.get('error')=='input_too_long':break
                qpacket={**qpacket,'correction':{'errors':errors,'same_base_review':critic.get('prediction') if critic else None,
                    'instruction':'Generate exactly two short questions, one common and one specific. Remove unsupported feature/protocol assumptions and developer-only tasks. Use supplied source IDs only in the structured field. Treat uncertain conditions as uncertain; do not invent facts.'}}
            if qs:
                for variant in ['all_unknown','yes_without_records','installed_version_unknown']:
                    qa=[{**q,'answer':{'value':'unknown' if variant=='all_unknown' else 'yes',
                        'evidence':'SIMULATED operating record; not an observed asset fact.' if variant=='installed_version_unknown' else ''}}
                        for q in qs]
                    apacket={'cve':row['cve'],'description':row['description'],'questions_and_answers':qa,
                        'question_generation_valid':quality,'version_decided':variant!='installed_version_unknown',
                        'version_evaluation':{'version_decided':variant!='installed_version_unknown','components':[],
                            'counterfactual_assumption_not_actual_asset_evidence':True},'simulation':True}
                    prediction=VR.infer('operation-assessment',apacket)
                    pred=prediction.get('prediction');raw_checks=check_role_output('operation-assessment',apacket,pred)
                    structural=bool(raw_checks['schema_valid'] and raw_checks['answer_refs_valid'] and raw_checks['concise_explanation'])
                    gate=assessment_gate(pred,qa,valid=structural,generation_valid=quality,version_decided=apacket['version_decided'])
                    safety.append({'variant':variant,'synthetic':True,'raw_output':prediction,'raw_checks':raw_checks,'gate':gate,
                                   'policy_expected_advisory':'likely_cannot_determine','semantic_gold':False})
            atomic_json(dest,{'cve':row['cve'],'group_id':row['group_id'],'source_case':row['id'],'split':'train',
                'source_catalog':sources,'condition_output':condition,'resolved_condition':resolved,'condition_errors':condition_errors,
                'question_output':questions,'question_contract_valid':valid,'question_errors':errors,
                'question_attempts':attempts,'same_base_question_review_passed':quality,'condition_claims':condition_claims,
                'presentation_normalizations':normalizations,'questions':qs,'same_base_critic':critic,
                'counterfactual_safety_probes':safety,'human_gold':False,'train_ready':False,'standard_vex_authority':False})
        # Compiler-backed function proposals use only real project function IDs.
        campaign=ROOT/read_json(ROOT/'results/current_source_campaign.json').get('path','results/source_clang_batch_v3')
        summary=read_json(campaign/'summary.json')
        candidates=[r for r in summary.get('results',[]) if r.get('compiled_project_functions')]
        nvd=read_json(ROOT/'data/nvd_cache.json')
        for i,row in enumerate(candidates[:a.source_limit]):
            status('source_mapping_curation',processed=i,total=min(len(candidates),a.source_limit),cve=row['cve'])
            root=ROOT/row['source'];dest=out/(row['cve']+'.source.json')
            if dest.exists():continue
            with gzip.open(campaign/row['graph_file'],'rt',encoding='utf-8') as f:graph=json.load(f)
            description=nvd.get(row['cve'],{}).get('description','');all_functions=[graph['functions'][k] for k in row['project_function_ids']]
            all_functions.sort(key=lambda f:(f['name'] not in row['targets'],f['name'] not in description,f['file'] or '',f['line'] or 0))
            functions=[];facts=[];text_cache={};path_cache={};seen_definitions=set()
            for f in all_functions:
                filename=(f.get('file') or '').replace('\\','/')
                if filename not in path_cache:
                    direct=(root/filename).resolve()
                    paths=([direct] if direct.is_relative_to(root.resolve()) and direct.is_file() and not direct.is_symlink() else
                           [p for p in root.rglob(Path(filename).name) if p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(root.resolve()) and (p.relative_to(root).as_posix()==filename or p.relative_to(root).as_posix().endswith('/'+filename))])
                    path_cache[filename]=paths
                paths=path_cache[filename]
                if len(paths)!=1:continue
                path=paths[0];line=max(0,(f.get('line') or 1)-1)
                definition=(str(path),line,f['symbol'])
                if definition in seen_definitions:continue
                seen_definitions.add(definition)
                if path not in text_cache:
                    data=path.read_bytes();text_cache[path]=(data.decode('utf-8','replace').splitlines(),hashlib.sha256(data).hexdigest())
                lines,sha=text_cache[path]
                fid='F-'+hashlib.sha256(f['id'].encode()).hexdigest()[:12]
                functions.append({'id':fid,'name':f['name'],'symbol':f['symbol'],'translation_unit':f['translation_unit'],
                                  'file':path.relative_to(root).as_posix(),'line':line+1,
                                  'source_sha256':sha,'code_excerpt':'\n'.join(lines[max(0,line-8):line+22])[:1200]})
            source=catalog(row['cve'],description)[:5]
            for patch in row.get('patch_evidence',{}).get('patches',[])[:3]:
                for h in patch.get('hunks',[])[:2]:
                    source.append({'id':'P-'+hashlib.sha256((patch['sha256']+str(h)).encode()).hexdigest()[:12],
                        'text':h['hunk'],'hunk_header':h['hunk'],'file':h['patch_file'],'source_kind':'patch'})
            search_packet={'cve':row['cve'],'sources':source}
            query_output=VR.infer('research-source-search',search_packet) if source else {'prediction':None,'error':'no_sources'}
            qv,qe=validate_review('research-source-search',search_packet,query_output.get('prediction'))
            query_terms=query_output['prediction']['queries'] if qv and not query_output.get('error') else []
            from src.source_function_retrieval import rank
            total_definitions=len(functions)
            functions=rank(functions,description+' '+' '.join(query_terms),row['targets'],
                           [s['file'] for s in source if s.get('source_kind')=='patch'],limit=12)
            for f in functions:f['code_excerpt']=f['code_excerpt'][:500]
            facts=[{'id':f['id'],'source_kind':'code','text':f['code_excerpt']} for f in functions]
            packet={'cve':row['cve'],'description':description,'functions':functions,'sources':source,
                    'candidate_pool_truncated':total_definitions>len(functions),'mapping_exhaustiveness_established':False,
                    'retrieval_method':'LLM query hints + BM25 over source definitions; scores are not confidence'}
            if not functions:continue
            output=VR.infer('research-source-map',packet);valid,errors=validate_review('research-source-map',packet,output.get('prediction'))
            mapping_attempts=[{'output':output,'contract_valid':valid,'errors':errors}]
            if not valid and not output.get('error'):
                correction={**packet,'correction':{'errors':errors,'instruction':'Use explicit_function_mention only for a literal function identifier in Description/summary. Use patch_context only when the exact function name occurs in hunk_header and its source file matches the patch file. Otherwise use uncertain or abstain. Do not invent evidence.'}}
                output=VR.infer('research-source-map',correction);valid,errors=validate_review('research-source-map',packet,output.get('prediction'))
                mapping_attempts.append({'output':output,'contract_valid':valid,'errors':errors})
            control_packet={'cve':row['cve'],'functions':functions,'sources':facts,'actual_asset_input_boundaries':None,
                            'deployed_binary_identity_verified':False,'negative_proof_enabled':False}
            control=VR.infer('research-control',control_packet);cv,ce=validate_review('research-control',control_packet,control.get('prediction'))
            atomic_json(dest,{'cve':row['cve'],'function_packet':packet,'mapping_output':output,'mapping_contract_valid':valid,
                'query_expansion_output':query_output,'query_validation_errors':qe,'total_source_definitions':total_definitions,
                'mapping_attempts':mapping_attempts,
                'mapping_errors':errors,'control_packet':control_packet,'control_output':control,'control_contract_valid':cv,
                'control_errors':ce,'human_gold':False,'CVE_causality_independently_verified':False,
                'mapping_exhaustiveness_established':False,'attacker_control':'unknown','standard_vex_authority':False})
        status('complete',operational_cases=len(list(out.glob('CVE-*.json')))-len(list(out.glob('*.source.json'))),
               source_cases=len(list(out.glob('*.source.json'))))
    except BaseException as e:
        status('failed',error=str(e));raise
    finally:atomic_json(FILE,{'pid':os.getpid(),'active':False,'phase':state['phase']})


if __name__=='__main__':main()
