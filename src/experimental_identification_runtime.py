"""Isolated evaluation runtime with one explicitly trained adapter per identity role."""
from contextlib import contextmanager
from pathlib import Path
import hashlib,json
from src.identification_agents import LocalIdentificationAgents

class TrainedIdentificationRuntime(LocalIdentificationAgents):
    def __init__(self,root):
        super().__init__();self.role_root=Path(root);self.identification_adapter_metadata={}

    def _load(self,role='vex-writer',*,streaming_weights=True):
        for task in ('L2','L3','L4'):
            folder=self.role_root/task;marker=folder/'training_complete.json'
            if not marker.is_file():raise RuntimeError('Role training incomplete: '+task)
            spec=json.loads(marker.read_text(encoding='utf-8'));weights=folder/'adapter_model.safetensors'
            if hashlib.sha256(weights.read_bytes()).hexdigest()!=spec['adapter_sha256']:raise RuntimeError('Role adapter changed: '+task)
            self.identification_adapter_metadata[task]={'path':str(folder),'sha256':spec['adapter_sha256'],'role':task}
        super()._load(role,streaming_weights=streaming_weights)
        for task in ('L2','L3','L4'):self.model.load_adapter(str(self.role_root/task),adapter_name='identity_'+task,is_trainable=False)
        self.model.eval()

    @contextmanager
    def identification_context(self,task):
        if task not in self.identification_adapter_metadata:raise RuntimeError('Missing trained role; base fallback is forbidden: '+task)
        previous=self.model.active_adapter;self.model.set_adapter('identity_'+task)
        try:yield
        finally:self.model.set_adapter(previous)

    def identification_agent(self,task,packet):
        return self.identification_batch(task,[packet],batch_size=1,max_padded_tokens=32768,compact_wire=True)[0]
