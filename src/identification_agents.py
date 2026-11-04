"""Single quantized runtime restricted to final VEX explanation writing."""
import json,threading,os
from pathlib import Path
from src.inference_policy import require_writer
ROOT=Path(__file__).resolve().parents[1]
ADAPTERS=ROOT/'models/identification-agents-v2'  # Historical metadata only.

class LocalIdentificationAgents:
    def __init__(self,mode='tuned',adapters=ADAPTERS):
        self.mode=mode;self.adapters=adapters;self.model=None;self.lock=threading.Lock()
    def _load(self):
        from src.gpu_lease import assert_inference_available
        assert_inference_available()
        os.environ.setdefault('HF_ENABLE_PARALLEL_LOADING','false')
        import torch
        from transformers import AutoTokenizer,AutoModelForCausalLM,BitsAndBytesConfig
        from peft import PeftModel
        torch.set_num_threads(2)
        folder=ROOT/'models/vex-writer-qwen3-8b-v1'
        if not (folder/'training_complete.json').is_file():raise RuntimeError('VEX writer weights are unavailable.')
        config=json.loads((folder/'adapter_config.json').read_text(encoding='utf-8'))
        base=config['base_model_name_or_path']
        self.tok=AutoTokenizer.from_pretrained(str(folder),local_files_only=True)
        if self.tok.pad_token_id is None:self.tok.pad_token=self.tok.eos_token
        model=AutoModelForCausalLM.from_pretrained(base,local_files_only=True,device_map={'':0},dtype=torch.bfloat16,
            attn_implementation='sdpa',quantization_config=BitsAndBytesConfig(load_in_4bit=True,bnb_4bit_quant_type='nf4',
            bnb_4bit_use_double_quant=True,bnb_4bit_compute_dtype=torch.bfloat16))
        self.model=PeftModel.from_pretrained(model,str(folder),adapter_name='vex_writer').eval()
    def __call__(self,task,payload,mode=None):
        raise ValueError('LLM identification is disabled.')
    def batch(self,task,payloads,mode=None,batch_size=16,progress=None):
        raise ValueError('LLM identification is disabled.')
    def grounded_role(self,role,packet,*,force_base=False):
        require_writer(role)
        import hashlib,torch
        from src.grounded_role_tasks import WRITER_SYSTEM,parse
        from src.llm_output_schema import prefix_function
        folder=ROOT/'models'/(role+'-qwen3-8b-v1')
        if not (folder/'training_complete.json').is_file():raise RuntimeError('Grounded adapter is not complete: '+role)
        with self.lock:
            if self.model is None:self._load()
            alias=role.replace('-','_')
            if alias not in self.model.peft_config:
                conf=json.loads((folder/'adapter_config.json').read_text(encoding='utf-8'))
                existing=self.model.peft_config['vex_writer'].base_model_name_or_path
                if Path(conf['base_model_name_or_path']).resolve()!=Path(existing).resolve():raise RuntimeError('Grounded adapter base mismatch')
                self.model.load_adapter(str(folder),adapter_name=alias)
            self.model.set_adapter(alias)
            system=WRITER_SYSTEM
            prompt=self.tok.apply_chat_template([{'role':'system','content':system},{'role':'user','content':json.dumps(packet,ensure_ascii=False)}],tokenize=False,add_generation_prompt=True,enable_thinking=False)
            encoded=self.tok(prompt,return_tensors='pt').to('cuda')
            input_limit=6144 if role=='vex-writer' else 3072
            output_limit=1536 if role=='vex-writer' else 768
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
    from src.gpu_lease import assert_inference_available
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
    raise ValueError('Identification adapters are disabled; use deterministic identification.')
