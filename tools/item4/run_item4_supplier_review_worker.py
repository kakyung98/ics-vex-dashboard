"""Run a frozen supplier-review request bundle once with the parent H200 serial runtime."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


CONTRACT = 'item4-supplier-review/1'
ROLE = 'operating-record-review'
PACKAGES = ('torch', 'transformers', 'bitsandbytes', 'peft', 'lm-format-enforcer')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_pinned(path, expected):
    raw = path.read_bytes()
    if sha(raw) != expected:
        raise ValueError(f'File fingerprint changed: {path.name}')
    return json.loads(raw)


def save(path, obj):
    data = (json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()
    if path.exists():
        raise FileExistsError(f'Choose a new output file: {path}')
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
        name = Path(tmp.name)
        try:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
        except BaseException:
            tmp.close()
            name.unlink(missing_ok=True)
            raise
    try:
        # An existing receipt stays immutable if two workers finish concurrently.
        os.link(name, path)
    finally:
        name.unlink(missing_ok=True)
    return sha(data)


def parent_pins(report_file):
    raw = report_file.read_bytes()
    parent = json.loads(raw)
    ledger = parent['ledger']
    identity = parent['backend_identity']
    identity_sha = sha(json.dumps(identity, sort_keys=True).encode())
    if (identity_sha != ledger['code_hashes']['GPU runtime identity']
            or parent['candidates_sha256'] != ledger['result']['candidates_sha256']
            or parent['unique_scenario_count'] != ledger['total']
            or parent['synthetic'] is not True
            or ledger['generation_method'] != 'scenario_moe_h200_llm'
            or identity['moe_version'] != 'item4-scenario-moe/2'
            or identity['role_adapter'] is not None):
        raise ValueError('The parent must be the sealed full-population v2 H200 evaluation.')
    for name, value in {**identity['base_files_sha256'], **identity['tokenizer_sha256']}.items():
        if ledger['model_hashes'].get(name) != value:
            raise ValueError(f'Parent model pin does not match: {name}')
    if not all(ledger['code_hashes'].get(k) == v for k, v in identity['runtime_sha256'].items()):
        raise ValueError('Parent runtime pins do not match its identity.')
    # These paths are imported by the original serial path in addition to the worker identity files.
    dependencies = {f'src/{name}': ledger['code_hashes'][name]
                    for name in ('prerequisite_llm.py', 'model_paths.py')}
    return dict(parent_run_id=ledger['run_id'], parent_report_sha256=sha(raw),
                parent_candidates_sha256=parent['candidates_sha256'],
                model_identity=identity, serial_dependency_sha256=dependencies)


def validate_bundle(bundle, pins):
    if bundle['contract_version'] != CONTRACT or bundle['parent_run_id'] != pins['parent_run_id']:
        raise ValueError('This worker requires the declared supplier contract and parent.')
    seen = set()
    requests = bundle['requests']
    if not isinstance(requests, list) or not requests:
        raise ValueError('Expected a nonempty supplier request list.')
    for row in requests:
        system, packet = row['system'], row['packet']
        if not isinstance(system, str) or not system or packet.get('expert') != 'supplier':
            raise ValueError('Unexpected supplier task.')
        if set(packet) - {'expert', 'evidence', 'schema', 'citation_groups'}:
            raise ValueError('The supplier packet contains unrelated fields.')
        evidence = packet['evidence']
        if not isinstance(evidence, dict) or list(evidence) != [f'e{i}' for i in range(len(evidence))]:
            raise ValueError('Supplier evidence must use the declared ordered row aliases.')
        fields = {'product_key', 'source_version', 'status', 'version_membership'}
        if any(not isinstance(source, dict) or set(source) != fields
               or not all(isinstance(v, str) for v in source.values()) for source in evidence.values()):
            raise ValueError('Only verified supplier product, version, status and membership observations are allowed.')
        schema = packet['schema']
        props = schema['properties']
        if (schema['type'] != 'object' or len(props) != 1 or schema['required'] != list(props)
                or schema.get('additionalProperties') is not False):
            raise ValueError('Expected one required finite supplier-choice field.')
        choice = next(iter(props.values()))
        allowed = choice.get('enum')
        if (choice.get('type') != 'string' or not isinstance(allowed, list) or not allowed
                or not all(isinstance(a, str) for a in allowed) or len(allowed) != len(set(allowed))):
            raise ValueError('Invalid supplier-choice enumeration.')
        # This must preserve packet key insertion order exactly as delivered to the tokenizer.
        wire = json.dumps([system, json.dumps(packet, ensure_ascii=False)],
                          ensure_ascii=False, separators=(',', ':')).encode()
        if row['wire_sha256'] != sha(wire) or row['wire_sha256'] in seen:
            raise ValueError('Mismatched or repeated supplier input fingerprint.')
        seen.add(row['wire_sha256'])
    return requests


def load_runtime(root, pins):
    expected = pins['model_identity']
    for name, value in {**expected['runtime_sha256'], **pins['serial_dependency_sha256']}.items():
        if sha((root / name).read_bytes()) != value:
            raise ValueError(f'Frozen runtime source differs: {name}')
    packages = {name: metadata.version(name) for name in PACKAGES}
    if packages != expected['packages']:
        raise ValueError('GPU package versions differ from the parent.')
    if os.environ.get('ICS_PREREQUISITE_LLM_URL') or os.environ.get('ICS_PREREQUISITE_LLM_MODEL'):
        raise ValueError('This offline evaluation requires the frozen on-device model.')
    jobs = subprocess.check_output(
        ['nvidia-smi', '--query-compute-apps=pid', '--format=csv,noheader,nounits'], text=True)
    if jobs.strip():
        raise RuntimeError('The dedicated GPU is occupied.')
    sys.path.insert(0, str(root))
    import torch
    from src.item4.models import scenario_review_experts as item4_scenario_moe; from src.item4.models import json_inference_client as prerequisite_llm
    from src.item4.models.remote_gpu_expert_client import hashes; from src.item4.models.remote_gpu_expert_client import RUNTIME_FILES; from src.item4.models.remote_gpu_expert_client import TOKENIZER_FILES
    from src.common.runtime.shared_adapter_runtime import get_precision_runtime

    runtime = get_precision_runtime()
    if Path(prerequisite_llm.__file__).resolve() != root / 'src/item4/models/json_inference_client.py':
        raise ValueError('Serial model import differs from the frozen source.')
    spec = prerequisite_llm.identity(ROLE)
    actual = dict(backend='hf_v2_constrained_greedy', device=torch.cuda.get_device_name(0),
                  moe_version=item4_scenario_moe.VERSION, model=spec['model'], role_adapter=spec['adapter'],
                  base_files_sha256=spec['base_files_sha256'], tokenizer_sha256=hashes(runtime.folder, TOKENIZER_FILES),
                  runtime_sha256=hashes(root, RUNTIME_FILES), packages=packages)
    if (actual != expected or spec['provider'] != 'local_shared_base'
            or actual['role_adapter'] is not None or 'H200' not in actual['device']):
        raise ValueError('Loaded model configuration differs from the parent.')
    runtime._load()  # Hashes and verifies the actual base shards and shared adapter before load.
    return prerequisite_llm, actual


def run(args):
    pins = read_pinned(args.pins, args.pins_sha256)
    bundle = read_pinned(args.requests, args.requests_sha256)
    requests = validate_bundle(bundle, pins)
    if args.output.exists():
        raise FileExistsError(args.output)
    started = datetime.now(timezone.utc).isoformat()
    module, actual = load_runtime(args.frozen_root.resolve(strict=True), pins)
    outputs = {}
    for i, row in enumerate(requests, 1):
        output = module.generate(row['system'], row['packet'], role=ROLE)
        if (output.get('llm_used') is not True or output['model']['provider'] != 'local_shared_base'
                or output['model']['model'] != actual['model'] or output['model']['adapter'] is not None
                or output['generation']['constrained_json'] is not True or output['generation']['output_tokens'] < 1):
            raise ValueError('Missing genuine serial inference receipt.')
        outputs[row['wire_sha256']] = {k: output[k] for k in ('prediction', 'model', 'llm_used', 'raw', 'generation')}
        print(f'{i}/{len(requests)} completed', flush=True)
    result = dict(contract_version=CONTRACT, parent_run_id=pins['parent_run_id'],
                  parent_report_sha256=pins['parent_report_sha256'], parent_candidates_sha256=pins['parent_candidates_sha256'],
                  requests_sha256=args.requests_sha256, pins_sha256=args.pins_sha256,
                  worker_sha256=sha(Path(__file__).read_bytes()), model_identity=actual,
                  serial_dependency_sha256=pins['serial_dependency_sha256'], inference_role=ROLE,
                  inference_method='frozen_v2_serial_constrained_greedy', actual_model_calls=len(outputs),
                  started_at=started, completed_at=datetime.now(timezone.utc).isoformat(), responses=outputs)
    print('responses_sha256', save(args.output, result), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    freeze = modes.add_parser('pins', help='Export the model pins from the verified parent report.')
    freeze.add_argument('parent_report', type=Path)
    freeze.add_argument('output', type=Path)
    evaluate = modes.add_parser('run', help='Run the sealed requests on the existing project H200.')
    evaluate.add_argument('--frozen-root', type=Path, required=True)
    evaluate.add_argument('--pins', type=Path, required=True)
    evaluate.add_argument('--pins-sha256', required=True)
    evaluate.add_argument('--requests', type=Path, required=True)
    evaluate.add_argument('--requests-sha256', required=True)
    evaluate.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.mode == 'pins':
        print(save(args.output, parent_pins(args.parent_report)))
    else:
        run(args)
