"""Live, source-bound batch identification on multiple CPU processes.

The original matcher runs in every worker. Only model packets cross the local
model queue; labels and historical predictions are never loaded by this pool.
"""
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
import multiprocessing
from queue import Empty
from threading import Thread
import time

_SESSION=None
_PROVIDER=None


class _RemoteProvider:
    def __init__(self,worker,requests,replies):
        self.worker=worker;self.requests=requests;self.replies=replies

    def __call__(self,task,packet):
        if not self.require_identity_review and task=='I2':
            from src.item3.agents.candidate_choice_scoring import forced_version_classification
            forced=forced_version_classification(packet)
            if forced is not None:
                return dict(prediction=forced,raw=json.dumps(forced),llm_used=False,
                            model_mode='structured_contract',generation=dict(
                                method='forced_source_observation_classification',generated_tokens=0))
        self.requests.put((self.worker,task,packet))
        ok,response=self.replies.get()
        if not ok:raise RuntimeError(response)
        return response


def _initialize(worker,requests,replies,model_review):
    global _SESSION,_PROVIDER
    from src.item3.matching.identification_session import IdentificationSession
    from src.item3.evidence.product_candidate_search import get_index
    from src.item3.evidence.local_vulnerability_lookup import get_source_lookup
    from src.item3.evidence.cisa_advisory_lookup import family_index
    _SESSION=IdentificationSession(compact=True)
    _PROVIDER=_RemoteProvider(worker,requests,replies)
    _PROVIDER.require_identity_review=model_review
    get_index();get_source_lookup();family_index()


def _match(sbom,options):
    from src.item3.matching.sbom_candidate_service import match_candidates
    result=match_candidates(sbom,**options,component_cache=_SESSION,
                            identification_agents=None if options.get('agent_mode')=='rules' else _PROVIDER)
    result['batch_worker_session']=_SESSION.statistics()
    return result


class ParallelIdentificationPool:
    def __init__(self,workers=8,*,model_review=True):
        self.manager=multiprocessing.Manager()
        self.requests=self.manager.Queue()
        self.replies=[self.manager.Queue() for _ in range(workers)]
        self.workers=workers;self.model_packets=0;self.model_batches=0
        self.pools=[ProcessPoolExecutor(max_workers=1,initializer=_initialize,
                    initargs=(i,self.requests,self.replies[i],model_review)) for i in range(workers)]
        self.thread=Thread(target=self._model_loop,daemon=True);self.thread.start()

    def _model_loop(self):
        infer=None
        while True:
            first=self.requests.get()
            if first is None:return
            pending=[first];until=time.monotonic()+.015
            while len(pending)<64 and time.monotonic()<until:
                try:pending.append(self.requests.get(timeout=max(.001,until-time.monotonic())))
                except Empty:break
            for task in sorted({r[1] for r in pending}):
                group=[r for r in pending if r[1]==task]
                try:
                    if infer is None:
                        from src.item3.agents.batched_provider import BatchedIdentificationProvider
                        infer=BatchedIdentificationProvider._configured_inference()
                    results=infer(task,[r[2] for r in group])
                    if len(results)!=len(group):raise RuntimeError('Model response batch length differs')
                    self.model_packets+=len(group);self.model_batches+=1
                    for request,result in zip(group,results):self.replies[request[0]].put((True,result))
                except BaseException as exc:
                    for request in group:self.replies[request[0]].put((False,type(exc).__name__+': '+str(exc)))

    def __call__(self,sbom,**options):
        asset=(sbom.get('metadata') or {}).get('component') or {}
        identity=asset.get('bom-ref') or json.dumps(sbom.get('metadata') or {},sort_keys=True)
        worker=int.from_bytes(hashlib.sha256(identity.encode()).digest()[:8],'big')%self.workers
        return self.pools[worker].submit(_match,sbom,options).result()

    def close(self):
        for pool in self.pools:pool.shutdown(wait=True)
        self.requests.put(None);self.thread.join();self.manager.shutdown()

    def statistics(self):
        return dict(cpu_processes=self.workers,model_source_packets=self.model_packets,
                    model_provider_batches=self.model_batches,stored_predictions_loaded=False,
                    source='live original match_candidates entry point in each worker')
