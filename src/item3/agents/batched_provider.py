"""Batch live model requests from concurrent documents without reading labels."""
from concurrent.futures import Future
import hashlib
import json
from queue import Queue,Empty
from threading import Lock,Thread
import time


class BatchedIdentificationProvider:
    require_identity_review = True
    def __init__(self,infer=None):
        self.queue=Queue();self.lock=Lock();self.responses={};self.batches=0;self.reused=0
        self.infer=infer or self._configured_inference()
        self.thread=Thread(target=self._run,daemon=True);self.thread.start()

    def __call__(self,task,packet):
        if not self.require_identity_review and task=='I2' and 'observations' in packet:
            from src.item3.agents.candidate_choice_scoring import forced_version_classification
            forced=forced_version_classification(packet)
            if forced is not None:
                return dict(prediction=forced,raw=json.dumps(forced),llm_used=False,
                            model_mode='structured_contract',generation=dict(
                                method='forced_source_observation_classification',generated_tokens=0))
        key=task+':'+hashlib.sha256(json.dumps(packet,sort_keys=True).encode()).hexdigest()
        with self.lock:
            future=self.responses.get(key)
            if future is None:
                future=Future();self.responses[key]=future;self.queue.put((task,packet,future))
            else:self.reused+=1
        return future.result()

    @staticmethod
    def _configured_inference():
        from pathlib import Path
        root=Path(__file__).resolve().parents[3]
        settings=json.loads((root/'data/identification_runtime.json').read_text(encoding='utf-8'))
        if settings.get('runtime')=='precision_shared_14b_v1':
            from src.common.runtime.shared_adapter_runtime import get_precision_runtime
            runtime=get_precision_runtime()
            return lambda task,packets:runtime.identification_batch(task,packets)
        else:
            from src.item3.matching.identification_pipeline import infer_agent
            return lambda task,packets:[infer_agent(task,p) for p in packets]

    def _run(self):
        while True:
            first=self.queue.get()
            if first is None:return
            pending=[first];until=time.monotonic()+.015
            while len(pending)<64 and time.monotonic()<until:
                try:pending.append(self.queue.get(timeout=max(.001,until-time.monotonic())))
                except Empty:break
            for task in sorted({r[0] for r in pending}):
                group=[r for r in pending if r[0]==task]
                try:
                    results=self.infer(task,[r[1] for r in group]);self.batches+=1
                    if len(results)!=len(group):raise RuntimeError('Model response batch length differs')
                    for request,result in zip(group,results):request[2].set_result(result)
                except BaseException as exc:
                    for request in group:request[2].set_exception(exc)

    def close(self):
        self.queue.put(None);self.thread.join()

    def statistics(self):
        return dict(unique_source_packets=len(self.responses),reused_source_packets=self.reused,
                    model_provider_batches=self.batches,cache_scope='this live run only')
