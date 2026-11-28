"""Schema-constrained Nemotron inference for the existing four evidence-review roles."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import threading

import requests

from src.item4.models.remote_gpu_expert_client import token_path


MODEL = 'nvidia/NVIDIA-Nemotron-3.5-Super-VL-120B-A12B-NVFP4'
REVISION = 'ae1368329b1fc76b71534c5d04b87b35d9cc6e15'
SERVED_MODEL = 'icsvex-nemotron-3.5-super-vl'


class NemotronBatch:
    def __init__(self, port, manifest, *, concurrency=8):
        self.url=f'http://127.0.0.1:{int(port)}/v1'
        self.identity=json.loads(Path(manifest).read_bytes())
        if (self.identity.get('model')!=MODEL or self.identity.get('revision')!=REVISION
                or not self.identity.get('base_files_sha256') or not self.identity.get('tokenizer_sha256')
                or self.identity.get('served_model')!=SERVED_MODEL or self.identity.get('role_adapter') is not None
                or self.identity.get('decoding')!={'temperature':0,'enable_thinking':False,'max_tokens':1024}):
            raise ValueError('Expected the verified official Nemotron NVFP4 snapshot.')
        if not 1 <= concurrency <= 16:
            raise ValueError('Nemotron request concurrency must be between 1 and 16.')
        self.identity['request_concurrency']=concurrency
        self._local=threading.local()
        self._authorization='Bearer '+token_path().read_text().strip()
        available=self.session().get(self.url+'/models',timeout=(10,30))
        available.raise_for_status()
        if SERVED_MODEL not in {row['id'] for row in available.json()['data']}:
            raise ValueError('The served model differs from the pinned Nemotron snapshot.')
        self._pool=ThreadPoolExecutor(max_workers=concurrency)

    def session(self):
        if not hasattr(self._local,'session'):
            self._local.session=requests.Session()
            self._local.session.trust_env=False
            self._local.session.headers['Authorization']=self._authorization
        return self._local.session

    def _one(self, request):
        from src.item4.models.json_inference_client import parse_json
        schema=request['packet']['schema']
        body=dict(model=SERVED_MODEL,temperature=0,max_tokens=1024,
                  messages=[dict(role='system',content=request['system']),
                            dict(role='user',content=json.dumps(request['packet'],ensure_ascii=False))],
                  chat_template_kwargs={'enable_thinking':False},
                  response_format={'type':'json_schema','json_schema':{
                      'name':'evidence_review','strict':True,'schema':schema}})
        for attempt in range(3):
            try:
                response=self.session().post(self.url+'/chat/completions',json=body,timeout=(10,900))
                response.raise_for_status()
                result=response.json()
                if result.get('model')!=SERVED_MODEL:
                    raise ValueError('The inference server returned a different model.')
                choice=result['choices'][0]
                if choice.get('finish_reason')!='stop':
                    raise ValueError('Nemotron did not finish its evidence review.')
                prediction=parse_json(choice['message']['content'])
                import jsonschema
                jsonschema.validate(prediction,schema)
                return dict(prediction=prediction,llm_used=True,
                            model=dict(provider='nemotron_vllm_nvfp4_h200',model=MODEL,revision=REVISION),
                            generation=dict(usage=result.get('usage'),temperature=0,enable_thinking=False))
            except (requests.ConnectionError,requests.Timeout):
                if attempt==2:
                    raise

    def __call__(self, requests_batch):
        def safe(request):
            try:
                return self._one(request)
            except Exception as exc:
                return exc
        return list(self._pool.map(safe,requests_batch))
