"""Shared quantized runtime for grounded identity agents, questions and VEX writing."""
import json,threading,os
from pathlib import Path
from src.common.runtime.inference_role_policy import require_inference_role
ROOT=Path(__file__).resolve().parents[3]
ADAPTERS=ROOT/'models/identification-agents-v2'  # Historical metadata only.

class LocalIdentificationAgents:
    def __init__(self,mode='tuned',adapters=ADAPTERS):
        self.mode=mode;self.adapters=adapters;self.model=None;self.lock=threading.Lock()
    def _load(self,role='vex-writer',*,streaming_weights=False):
        from src.common.runtime.gpu_lease import assert_inference_available
        assert_inference_available()
        os.environ.setdefault('HF_ENABLE_PARALLEL_LOADING','false')
        import torch
        from transformers import AutoTokenizer,AutoModelForCausalLM,BitsAndBytesConfig
        from peft import PeftModel
        torch.set_num_threads(2)
        folder=self._folder(role)
        if not (folder/'training_complete.json').is_file():raise RuntimeError('Adapter weights are unavailable: '+role)
        config=json.loads((folder/'adapter_config.json').read_text(encoding='utf-8'))
        base=config['base_model_name_or_path']
        self.tok=AutoTokenizer.from_pretrained(str(folder),local_files_only=True)
        if self.tok.pad_token_id is None:self.tok.pad_token=self.tok.eos_token
        # Windows mmap-backed storage slicing can fault inside torch_cpu.dll while
        # loading these safetensors. The supported eager-read path keeps the same weights.
        from src.common.runtime.safetensors_loading import pread_weights
        streaming=streaming_weights and os.name=='nt'
        with pread_weights(streaming):
            model=AutoModelForCausalLM.from_pretrained(base,local_files_only=True,disable_mmap=os.name=='nt' and not streaming,device_map={'':0},dtype=torch.bfloat16,
                attn_implementation='sdpa',quantization_config=BitsAndBytesConfig(load_in_4bit=True,bnb_4bit_quant_type='nf4',
                bnb_4bit_use_double_quant=True,bnb_4bit_compute_dtype=torch.bfloat16))
        self.model=PeftModel.from_pretrained(model,str(folder),adapter_name=role.replace('-','_')).eval()
        runtime_file=ROOT/'data/identification_runtime.json'
        runtime_config=json.loads(runtime_file.read_text(encoding='utf-8')) if runtime_file.is_file() else {}
        if runtime_config.get('attention_backend')=='icsvex_efficient_sdpa':
            from src.common.runtime.attention_backend import install
            install(self.model)
    def _folder(self,role):
        if role=='item4-questions':
            from src.item4.models.review_model_config import configured; from src.item4.models.review_model_config import verify_weights
            spec=configured(role)
            if spec is None:raise RuntimeError('Tuned question adapter is not enabled.')
            verify_weights(spec)
            return spec['folder']
        return ROOT/'models/vex-writer-qwen3-8b-v1'
    def __call__(self,task,payload,mode=None):
        return self.identification_agent(task,payload)
    def batch(self,task,payloads,mode=None,batch_size=16,progress=None):
        results=[]
        for i,payload in enumerate(payloads):
            results.append(self.identification_agent(task,payload))
            if progress:progress(i+1,len(payloads))
        return results
    def identification_batch(self,task,payloads,batch_size=4,**options):
        from src.item3.agents.batch_inference import generate_batch
        return generate_batch(self,task,payloads,batch_size,**options)
    def identification_agent(self,task,packet):
        runtime_file=ROOT/'data/identification_runtime.json'
        config=json.loads(runtime_file.read_text(encoding='utf-8')) if runtime_file.is_file() else {}
        if config.get('compact_identifier_transport'):
            return self.identification_batch(task,[packet],batch_size=1,compact_wire=True)[0]
        from src.item3.agents.agent_contracts import SYSTEMS; from src.item3.agents.agent_contracts import VERSION
        if task not in SYSTEMS:raise ValueError('Unsupported identification role: '+str(task))
        role='identity-'+task
        require_inference_role(role)
        from src.common.runtime.gpu_lease import assert_inference_available
        assert_inference_available()
        from src.common.runtime.grounded_role_tasks import parse
        from src.common.runtime.json_output_constraints import prefix_function
        import torch
        with self.lock:
            # All roles share the same local base. Existing question/writer adapters
            # remain available; no legacy identification adapter is silently reused.
            if self.model is None:self._load('vex-writer')
            prompt=self.tok.apply_chat_template([
                {'role':'system','content':SYSTEMS[task]},
                {'role':'user','content':json.dumps(packet,ensure_ascii=False)}],
                tokenize=False,add_generation_prompt=True,enable_thinking=False)
            encoded=self.tok(prompt,return_tensors='pt').to('cuda')
            input_tokens=int(encoded['input_ids'].shape[1])
            if input_tokens>6144:return {'prediction':None,'raw':'','error':'input_too_long','llm_used':False,'model_mode':'base','role':role}
            constrained=prefix_function(self,role,packet)
            args={'prefix_allowed_tokens_fn':constrained} if constrained is not None else {}
            with self.model.disable_adapter(),torch.inference_mode():
                output=self.model.generate(**encoded,max_new_tokens=768,do_sample=False,
                    pad_token_id=self.tok.pad_token_id,use_cache=True,**args)
            raw=self.tok.decode(output[0,input_tokens:],skip_special_tokens=True)
            pred=parse(raw);count=int(output.shape[1]-input_tokens)
            return {'prediction':pred,'raw':raw,'role':role,'llm_used':True,
                    'model':'Qwen3-8B','model_mode':'base','adapter':None,'contract':VERSION,
                    'legacy_identification_adapters_used':False,
                    'error':('output_token_limit' if count>=768 else 'invalid_json_output') if pred is None else None,
                    'generation':{'input_tokens':input_tokens,'generated_tokens':count,'max_new_tokens':768,
                                  'do_sample':False,'constrained_json_schema':constrained is not None}}
    def prerequisite_json(self, system, packet, *, role):
        """Use the configured task adapter on the shared generative base; no NLI."""
        require_inference_role(role)
        if role not in {'exploitation-prerequisites', 'exploitation-coverage-review', 'operating-record-review', 'item4-questions'}:
            raise ValueError('Unsupported prerequisite role')
        from src.common.runtime.gpu_lease import assert_inference_available
        assert_inference_available()
        import torch
        with self.lock:
            if self.model is None:
                self._load('vex-writer')
            prompt = self.tok.apply_chat_template([
                dict(role='system', content=system),
                dict(role='user', content=json.dumps(packet, ensure_ascii=False))],
                tokenize=False, add_generation_prompt=True, enable_thinking=False)
            encoded = self.tok(prompt, return_tensors='pt').to('cuda')
            length = int(encoded['input_ids'].shape[1])
            if length > 6144:
                raise ValueError('Prerequisite input exceeds the bounded model context; no truncation is allowed')
            from src.common.runtime.json_output_constraints import prefix_for_schema
            constrained=prefix_for_schema(self,packet.get('schema',dict(type='object')))
            from src.item4.models.review_adapter_config import inference_context
            from src.common.runtime.attention_backend import operating_inference_context
            import time
            started=time.monotonic()
            with inference_context(self,role) as adapter, operating_inference_context(self.model) as attention_backend, torch.inference_mode():
                output = self.model.generate(**encoded, max_new_tokens=4096,
                    max_time=90.0,
                    do_sample=False, pad_token_id=self.tok.pad_token_id, use_cache=True, logits_to_keep=1,
                    prefix_allowed_tokens_fn=constrained)
            raw = self.tok.decode(output[0, length:], skip_special_tokens=True)
            if output.shape[1] - length >= 4096:
                error=ValueError('Incomplete prerequisite output at the 4096 token limit')
                error.raw_output=raw
                raise error
            from src.item4.models.json_inference_client import parse_json
            try:
                prediction = parse_json(raw)
            except ValueError as exc:
                if time.monotonic()-started>=90:
                    error=ValueError('Prerequisite generation reached the 90-second limit without a complete JSON response')
                    error.raw_output=raw
                    raise error from exc
                exc.raw_output=raw
                raise
            if not isinstance(prediction, dict):
                raise ValueError('Expected a prerequisite JSON object')
            return dict(prediction=prediction, llm_used=True, raw=raw,
                        generation=dict(input_tokens=length,output_tokens=int(output.shape[1]-length),constrained_json=True,attention_backend=attention_backend,elapsed_seconds=time.monotonic()-started,max_seconds=90),
                        model=dict(provider='local_shared_role_adapter' if adapter else 'local_shared_base', model=getattr(self,'model_name','Qwen3-8B'), adapter=adapter,
                                   nli_used=False))

    def grounded_role(self,role,packet,*,force_base=False):
        require_inference_role(role)
        if role.startswith('identity-'):raise ValueError('Use identification_agent for identification contracts.')
        if role=='item4-questions' and not packet.get('sources'):
            raise ValueError('Question generation requires retrieved evidence.')
        if force_base:raise ValueError('Base fallback is disabled for these roles.')
        import hashlib,torch
        from src.common.runtime.grounded_role_tasks import WRITER_SYSTEM,parse
        from src.common.runtime.json_output_constraints import prefix_function
        folder=self._folder(role)
        if not (folder/'training_complete.json').is_file():raise RuntimeError('Grounded adapter is not complete: '+role)
        with self.lock:
            if self.model is None:self._load(role)
            alias=role.replace('-','_')
            if alias not in self.model.peft_config:
                conf=json.loads((folder/'adapter_config.json').read_text(encoding='utf-8'))
                existing=next(iter(self.model.peft_config.values())).base_model_name_or_path
                if Path(conf['base_model_name_or_path']).resolve()!=Path(existing).resolve():raise RuntimeError('Grounded adapter base mismatch')
                self.model.load_adapter(str(folder),adapter_name=alias)
            self.model.set_adapter(alias)
            if role=='item4-questions':
                from src.item4.analysis.asset_question_contracts import SYSTEM
                system=SYSTEM
            else:system=WRITER_SYSTEM
            prompt=self.tok.apply_chat_template([{'role':'system','content':system},{'role':'user','content':json.dumps(packet,ensure_ascii=False)}],tokenize=False,add_generation_prompt=True,enable_thinking=False)
            encoded=self.tok(prompt,return_tensors='pt').to('cuda')
            input_limit=6144 if role=='vex-writer' else 4096
            output_limit=1536 if role=='vex-writer' else 1024
            if encoded['input_ids'].shape[1]>input_limit:
                return {'prediction':None,'raw':'','error':'input_too_long','role':role}
            constrained=prefix_function(self,role,packet)
            generation_args={'prefix_allowed_tokens_fn':constrained} if constrained is not None else {}
            penalty=(1.2 if packet.get('generation_feedback') else 1.1) if role=='vex-writer' else 1.0
            with torch.inference_mode():
                output=self.model.generate(**encoded,max_new_tokens=output_limit,do_sample=False,repetition_penalty=penalty,
                    pad_token_id=self.tok.pad_token_id,use_cache=True,**generation_args)
            raw=self.tok.decode(output[0,encoded['input_ids'].shape[1]:],skip_special_tokens=True)
            prediction=parse(raw);count=int(output.shape[1]-encoded['input_ids'].shape[1])
            return {'prediction':prediction,'raw':raw,'role':role,'model':'Qwen3-8B','constrained_json_schema':constrained is not None,
                    'error':('output_token_limit' if count>=output_limit else 'invalid_json_output') if prediction is None else None,
                    'adapter':folder.name,'adapter_sha256':hashlib.sha256((folder/'adapter_model.safetensors').read_bytes()).hexdigest(),
                    'generation':{'max_input_tokens':input_limit,'max_new_tokens':output_limit,'generated_tokens':count,'repetition_penalty':penalty,'do_sample':False}}


_instances={}
_instances_lock=threading.Lock()


def get_runtime():
    from src.common.runtime.gpu_lease import assert_inference_available
    assert_inference_available()
    with _instances_lock:
        if 'shared' not in _instances:_instances['shared']=LocalIdentificationAgents()
        return _instances['shared']


def release_runtime():
    """Serialize release with inference so the next GPU job can claim memory."""
    with _instances_lock:
        runtime=_instances.get('shared')
        if runtime is None:return {'released':False,'reason':'model_not_loaded'}
        with runtime.lock:
            if runtime.model is None:return {'released':False,'reason':'model_not_loaded'}
            runtime.model=None
            import gc,torch
            gc.collect();torch.cuda.empty_cache()
            return {'released':True}


def get_agents(mode):
    if mode not in {'agents','unified','base','tuned'}:raise ValueError('Unsupported agent runtime mode')
    return get_runtime()
