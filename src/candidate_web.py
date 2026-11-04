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
    available=(ROOT/'data/cpe_dictionary.jsonl').is_file()
    tasks=[{'task':t,'ready':available,'method':'deterministic_rules','llm_used':False,'active_in_unified':False} for t in ['L2','L3','L4']]
    return {'model':None,'version':'deterministic-v1','ready':available,'tasks':tasks,
            'scope':'Rule-based identification; LLM is used only for final VEX writing.',
            'local_snapshot_available':available and (ROOT/'data/cpe_index.json').is_file(),
            'unified':{'default_method':'unified','trained_roles':[],'dictionary_available':available,'independent_accuracy_evaluated':False},
            'evidence_v3':{'available':available,'llm_review':'disabled'},'llm_policy':'final_vex_writer_only'}


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
            'agent_mode':agent_mode,'lookup_mode':lookup_mode,'model_version':'deterministic-v1'}
        STORE.put('job',job_id,_jobs[job_id],7*86400)
    def work():
        with _lock:_jobs[job_id].update(status='running',started=time.time())
        def progress(done,total,stage,component):
            with _lock:_jobs[job_id]['progress']={'done':done,'total':total,'stage':stage,'component':component}
        try:
            result=match_candidates(sbom,agent_mode=agent_mode,lookup_mode=lookup_mode,progress=progress)
            result['model_version']='deterministic-v1'
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
