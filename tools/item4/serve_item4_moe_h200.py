"""Serve only the frozen #4 MoE v2 expert prompts on the project GPU loopback."""
import argparse
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import metadata
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.models import scenario_review_experts as moe
from src.item4.models.remote_gpu_expert_client import hashes; from src.item4.models.remote_gpu_expert_client import TOKENIZER_FILES; from src.item4.models.remote_gpu_expert_client import RUNTIME_FILES


def permitted_prompts():
    prompts = set()
    def capture(system, packet, *, role):
        prompts.add((system, packet['expert']))
        return {}
    for name in moe.PROMPTS:
        moe._expert(name, [], capture, None)
    moe._expert('supplier', [('a', {'status': 'known_affected', 'version_membership': 'true'}),
                             ('b', {'status': 'fixed', 'version_membership': 'true'})], capture, None)
    return prompts


def serve(port, token_file):
    import torch
    from src.item4.models import expert_batch_inference as item4_moe_batch; from src.item4.models import json_inference_client as prerequisite_llm
    from src.common.runtime.shared_adapter_runtime import get_precision_runtime
    device = torch.cuda.get_device_name(0)
    if 'H200' not in device or moe.VERSION != 'item4-scenario-moe/2':
        raise ValueError('Expected the dedicated H200 and frozen MoE v2.')
    rt = get_precision_runtime()
    rt._load()
    spec = prerequisite_llm.identity('operating-record-review')
    if spec.get('adapter') is not None or spec['provider'] != 'local_shared_base':
        raise ValueError('The operating review must use the same v2 base without an active role adapter.')
    identity = dict(backend='hf_v2_constrained_greedy', device=device, moe_version=moe.VERSION,
                    model=spec['model'], role_adapter=spec['adapter'], base_files_sha256=spec['base_files_sha256'],
                    tokenizer_sha256=hashes(rt.folder, TOKENIZER_FILES), runtime_sha256=hashes(ROOT, RUNTIME_FILES),
                    packages={n: metadata.version(n) for n in ('torch', 'transformers', 'bitsandbytes', 'peft', 'lm-format-enforcer')})
    token = 'Bearer ' + token_file.read_text().strip()
    allowed = permitted_prompts()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            pass

        def reply(self, status, value):
            raw = json.dumps(value, separators=(',', ':')).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def authorized(self):
            if hmac.compare_digest(self.headers.get('Authorization', ''), token):
                return True
            self.reply(403, {})
            return False

        def do_GET(self):
            if self.authorized():
                self.reply(200, identity) if self.path == '/identity' else self.reply(404, {})

        def do_POST(self):
            if not self.authorized():
                return
            if self.path not in {'/batch', '/serial'}:
                return self.reply(404, {})
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 8 * 1024 * 1024:
                    raise ValueError('Request size is invalid.')
                body = json.loads(self.rfile.read(size))
                batch = body['requests']
                if body['runtime_sha256'] != identity['runtime_sha256'] or not 0 < len(batch) <= 256:
                    raise ValueError('Batch exceeds the declared runtime or size.')
                if any((r['system'], r['packet']['expert']) not in allowed for r in batch):
                    raise ValueError('Only the v2 expert tasks are accepted.')
            except (ValueError, KeyError, TypeError) as exc:
                return self.reply(400, {'error': str(exc)})
            if self.path == '/serial':
                outputs = [prerequisite_llm.generate(r['system'], r['packet'], role=moe.INFERENCE_ROLE) for r in batch]
            else:
                outputs = item4_moe_batch.generate_model_batch(batch)
            result = [{'error': type(r).__name__ + ': ' + str(r)[:160]} if isinstance(r, Exception)
                      else {k: r[k] for k in ('prediction', 'model', 'llm_used')} for r in outputs]
            self.reply(200, {'runtime_sha256': identity['runtime_sha256'], 'outputs': result})

    print(json.dumps(identity), flush=True)
    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port', type=int, default=18128)
    p.add_argument('--token-file', type=Path, required=True)
    args = p.parse_args()
    serve(args.port, args.token_file)
