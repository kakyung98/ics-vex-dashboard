"""Bounded local job queue and lightweight metadata for the candidate matcher UI."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
import json
import threading
import time
import uuid

from src.candidate_match import match_candidates
from src.identification_agents import ADAPTERS,ROOT
from ics_agent_matcher_full.ics_agent_matcher.matcher import extract
from src import review_store as STORE

_executor=ThreadPoolExecutor(max_workers=1,thread_name_prefix='cve-match')
_lock=threading.Lock()
_jobs={}


def model_status():
    from src.identification_agent_flow import configured_mode
    from src.unified_identification import ARCHITECTURE,RULE_ARCHITECTURE
    available=(ROOT/'data/cpe_dictionary.jsonl').is_file()
    mode=configured_mode();base_ready=False
    try:
        adapter=json.loads((ROOT/'models/vex-writer-qwen3-8b-v1/adapter_config.json').read_text(encoding='utf-8'))
        base=Path(adapter['base_model_name_or_path'])
        shards=base/'model.safetensors.index.json'
        needed=set(json.loads(shards.read_text(encoding='utf-8'))['weight_map'].values()) if shards.is_file() else {'model.safetensors'}
        base_ready=(base/'config.json').is_file() and all((base/name).is_file() for name in needed)
    except (OSError,KeyError,ValueError):pass
    ready=available and (base_ready or mode=='rules')
    tasks=[{'task':t,'ready':ready,'method':'grounded_local_llm' if mode=='agents' else 'deterministic_rules',
            'llm_enabled':mode=='agents','active_in_unified':mode=='agents','fine_tuned_for_contract':False}
           for t in ['L2','L3','L4']]
    return {'model':'Qwen3-8B base' if mode=='agents' else None,
            'version':ARCHITECTURE if mode=='agents' else RULE_ARCHITECTURE,
            'identification_mode':mode,'ready':ready,'tasks':tasks,
            'scope':'Conditional P2/P3/P4 routing with original-evidence guards; question/writer adapters stay separate.',
            'routing_policy':'item3-conditional-routing-v1','routing_engine':'langgraph.StateGraph',
            'base_weights_available':base_ready,'legacy_identification_adapters_used':False,
            'local_snapshot_available':available and (ROOT/'data/cpe_index.json').is_file(),
            'unified':{'default_method':'unified','trained_roles':[],'runtime_roles':['L2','L3','L4'] if mode=='agents' else [],
                       'dictionary_available':available,'independent_accuracy_evaluated':False},
            'evidence_v3':{'available':available,'llm_review':mode},'llm_policy':'grounded_identification_questions_and_locked_vex_writer'}


def submit(sbom,agent_mode='unified',lookup_mode='local'):
    components=extract(sbom)
    if not 1<=len(components)<=100:raise ValueError('Provide CycloneDX or SPDX JSON with 1 to 100 components.')
    if agent_mode not in {'unified','rules','base','tuned','evidence','evidence_llm'}:raise ValueError('Unsupported identification method.')
    if lookup_mode not in {'live','local','none'}:raise ValueError('Unsupported lookup method.')
    if agent_mode=='unified' and not (ROOT/'data/cpe_dictionary.jsonl').is_file():raise RuntimeError('Unified identification requires the local CPE dictionary snapshot.')
    job_id=uuid.uuid4().hex
    with _lock:
        if sum(j['status'] in {'queued','running'} for j in _jobs.values())>=3:
            raise OverflowError('The task queue is full. Try again after a task completes.')
        while len(_jobs)>=20:
            done=next((k for k,j in _jobs.items() if j['status'] in {'completed','failed'}),None)
            if done is None:break
            del _jobs[done]
        _jobs[job_id]={'id':job_id,'status':'queued','created':time.time(),
            'input_sbom':deepcopy(sbom),
            'progress':{'done':0,'total':len(components),'stage':'queued','component':''},
            'agent_mode':agent_mode,'lookup_mode':lookup_mode,'model_version':model_status()['version']}
        STORE.put('job',job_id,_jobs[job_id],7*86400)
    def work():
        with _lock:_jobs[job_id].update(status='running',started=time.time())
        def progress(done,total,stage,component):
            with _lock:_jobs[job_id]['progress']={'done':done,'total':total,'stage':stage,'component':component}
        try:
            result=match_candidates(sbom,agent_mode=agent_mode,lookup_mode=lookup_mode,progress=progress)
            result['model_version']=result['architecture']
            with _lock:_jobs[job_id].update(status='completed',result=result,finished=time.time())
            with _lock:STORE.put('job',job_id,_jobs[job_id],7*86400)
        except Exception as exc:
            with _lock:_jobs[job_id].update(status='failed',error=str(exc),finished=time.time())
            with _lock:STORE.put('job',job_id,_jobs[job_id],7*86400)
    _executor.submit(work)
    return {'id':job_id,'status':'queued'}


def get_job(job_id):
    with _lock:
        job=_jobs.get(job_id)
        if job:return deepcopy(job)
    job=STORE.get('job',job_id)
    if job and job['status'] in {'queued','running'}:
        job.update(status='failed',error='Server restarted before this task completed; rerun identification.')
    return job
