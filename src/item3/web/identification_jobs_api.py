"""Bounded local job queue and lightweight metadata for the candidate matcher UI."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
import json
import threading
import time
import uuid

from src.item3.matching.sbom_candidate_service import match_candidates
from src.item3.agents.identification_model_runtime import ADAPTERS; from src.item3.agents.identification_model_runtime import ROOT
from src.item3.matching.sbom_matching_engine import extract
from src.common.data import analysis_job_store as STORE

_executor=ThreadPoolExecutor(max_workers=1,thread_name_prefix='cve-match')
_lock=threading.Lock()
_jobs={}


def require_reference_data(lookup_mode):
    required=[ROOT/'data/cpe_dictionary.jsonl']
    if lookup_mode=='local':
        required += [ROOT/'data/item3_identification_sources_v11/manifest.json',
                     ROOT/'data/item3_identification_sources_v11/cves.jsonl',
                     ROOT/'data/cisa_advisories.json',ROOT/'data/cisa_reference_manifest.json']
    if any(not path.is_file() for path in required):
        raise RuntimeError('The server identification reference data is unavailable. '
                           'SBOMs without CPE identifiers are supported; this is a server configuration problem.')


def model_status():
    from src.item3.agents.evidence_review_agents import configured_mode
    from src.item3.matching.identification_pipeline import ARCHITECTURE; from src.item3.matching.identification_pipeline import RULE_ARCHITECTURE
    available=(ROOT/'data/cpe_dictionary.jsonl').is_file()
    source_available=all((ROOT/'data/item3_identification_sources_v11'/name).is_file()
                         for name in ('manifest.json','cves.jsonl'))
    settings=ROOT/'data/identification_runtime.json'
    config=json.loads(settings.read_text(encoding='utf-8')) if settings.is_file() else {}
    if config.get('runtime')=='precision_shared_14b_v1':
        marker=ROOT/'models/precision_roles_qwen25_14b_v1/training_complete.json'
        trained=json.loads(marker.read_text(encoding='utf-8')) if marker.is_file() else {}
        ready=bool(available and source_available and trained.get('optimizer_updates'))
        return dict(model='Qwen2.5-Coder-14B-Instruct QLoRA',version=ARCHITECTURE,
            identification_mode='agents',ready=ready,base_weights_available=bool(trained),
            local_snapshot_available=source_available,
            tasks=[dict(task=t,ready=ready,method='grounded_trained_local_llm',llm_enabled=True,
                active_in_unified=True,fine_tuned_for_contract=True) for t in ('I1','I2','I3')],
            routing_policy='item3-conditional-routing-v1',routing_engine='langgraph.StateGraph',
            legacy_identification_adapters_used=False,
            unified=dict(default_method='unified',trained_roles=['I1','I2','I3'],runtime_roles=['I1','I2','I3'],
                dictionary_available=available,independent_accuracy_evaluated=False),
            evidence_v3=dict(available=available,llm_review='agents'),
            scope='Synthetic-benchmark-trained shared adapter; independent real-asset accuracy unmeasured')
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
           for t in ['I1','I2','I3']]
    return {'model':'Qwen3-8B base' if mode=='agents' else None,
            'version':ARCHITECTURE if mode=='agents' else RULE_ARCHITECTURE,
            'identification_mode':mode,'ready':ready,'tasks':tasks,
            'scope':'Conditional I1/I2/I3 routing with original-evidence guards; question/writer adapters stay separate.',
            'routing_policy':'item3-conditional-routing-v1','routing_engine':'langgraph.StateGraph',
            'base_weights_available':base_ready,'legacy_identification_adapters_used':False,
            'local_snapshot_available':available and (ROOT/'data/cpe_index.json').is_file(),
            'unified':{'default_method':'unified','trained_roles':[],'runtime_roles':['I1','I2','I3'] if mode=='agents' else [],
                       'dictionary_available':available,'independent_accuracy_evaluated':False},
            'evidence_v3':{'available':available,'llm_review':mode},'llm_policy':'grounded_identification_questions_and_locked_vex_writer'}


def submit(sbom,agent_mode='unified',lookup_mode='local'):
    components=extract(sbom)
    if not 1<=len(components)<=100:raise ValueError('Provide CycloneDX or SPDX JSON with 1 to 100 components.')
    if agent_mode not in {'unified','rules','base','tuned','evidence','evidence_llm'}:raise ValueError('Unsupported identification method.')
    if lookup_mode not in {'live','local','none'}:raise ValueError('Unsupported lookup method.')
    require_reference_data(lookup_mode)
    from src.item3.agents.evidence_review_agents import configured_mode
    if agent_mode!='rules' and configured_mode()=='agents':
        from src.common.gpu_lease import assert_inference_available
        assert_inference_available()
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
    from src.item3.agents.agent_role_labels import canonical_roles
    with _lock:
        job=_jobs.get(job_id)
        if job:return canonical_roles(deepcopy(job))
    job=STORE.get('job',job_id)
    if job and job['status'] in {'queued','running'}:
        job.update(status='failed',error='Server restarted before this task completed; rerun identification.')
    return canonical_roles(job)
