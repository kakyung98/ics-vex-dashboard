"""Client for the loopback-only v2 expert worker on the existing project GPU."""
import hashlib
import json
import os
from pathlib import Path
import time

import requests


ROOT = Path(__file__).resolve().parents[3]
TOKENIZER_FILES = ('tokenizer.json', 'tokenizer_config.json', 'chat_template.jinja')
RUNTIME_FILES = ('src/item4/models/scenario_review_experts.py', 'src/item4/models/expert_batch_inference.py', 'src/common/runtime/shared_adapter_runtime.py',
                 'src/common/runtime/json_output_constraints.py', 'src/item3/agents/identification_model_runtime.py', 'src/item4/models/review_adapter_config.py',
                 'src/item4/models/remote_gpu_expert_client.py', 'tools/item4/serve_item4_moe_h200.py')


def hashes(root, paths):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in paths}


def token_path():
    if os.environ.get('ICSVEX_MOE_H200_TOKEN_FILE'):
        return Path(os.environ['ICSVEX_MOE_H200_TOKEN_FILE'])
    return Path(os.environ['LOCALAPPDATA']) / 'ICS-VEX/runtime/item4_moe_h200.auth'


class H200Batch:
    def __init__(self, port):
        self.url = f'http://127.0.0.1:{int(port)}'
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers['Authorization'] = 'Bearer ' + token_path().read_text().strip()
        response = self.session.get(self.url + '/identity', timeout=(5, 20))
        response.raise_for_status()
        self.identity = response.json()
        model = ROOT / 'models/precision_roles_qwen25_14b_v1'
        marker = json.loads((model / 'training_complete.json').read_bytes())
        if (self.identity['base_files_sha256'] != marker['base_files_sha256']
                or self.identity['tokenizer_sha256'] != hashes(model, TOKENIZER_FILES)
                or self.identity['runtime_sha256'] != hashes(ROOT, RUNTIME_FILES)
                or self.identity['role_adapter'] is not None or self.identity['moe_version'] != 'item4-scenario-moe/2'):
            raise ValueError('The GPU worker differs from the pinned v2 model, tokenizer, or runtime.')

    def __call__(self, requests_batch):
        body = {'runtime_sha256': self.identity['runtime_sha256'], 'requests': requests_batch}
        for attempt in range(3):
            try:
                response = self.session.post(self.url + '/batch', json=body, timeout=(10, 240))
                response.raise_for_status()
                reply = response.json()
                if reply['runtime_sha256'] != self.identity['runtime_sha256']:
                    raise ValueError('Worker identity changed mid-run.')
                result = reply['outputs']
                if len(result) != len(requests_batch):
                    raise ValueError('Incomplete model response batch.')
                return [ValueError(r['error']) if 'error' in r else r for r in result]
            except (requests.ConnectionError, requests.Timeout):
                if attempt == 2:
                    raise
                time.sleep(2 ** attempt)
