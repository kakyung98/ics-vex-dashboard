"""Generative JSON inference shared by VEP extraction and operating records.

No entailment classifier or NLI runtime is imported by this module.
"""
import json
import os
import re
from pathlib import Path


def parse_json(raw):
    raw=raw.strip()
    fenced=re.fullmatch(r'```(?:json)?\s*\n([\s\S]*?)\n```',raw)
    if fenced:raw=fenced[1]
    result=json.loads(raw)
    if not isinstance(result,dict):raise ValueError('Expected a JSON object')
    return result


def identity(role=None):
    from src.item4.models import constrained_choice_provider as jev
    if jev.enabled(role):
        return jev.identity()
    url = os.getenv('ICS_PREREQUISITE_LLM_URL')
    model = os.getenv('ICS_PREREQUISITE_LLM_MODEL')
    if bool(url) != bool(model):
        raise ValueError('Configure both ICS_PREREQUISITE_LLM_URL and ICS_PREREQUISITE_LLM_MODEL')
    if url:
        from src.item4.models.review_adapter_config import active_roles
        if any(active_roles().values()):raise ValueError('Local role adapters require the local shared runtime')
        return dict(provider='configured_chat_completion', model=model, endpoint=url, nli_used=False)
    root=Path(__file__).resolve().parents[3]
    settings=root/'data/identification_runtime.json'
    config=json.loads(settings.read_text(encoding='utf-8')) if settings.is_file() else {}
    shared=config.get('runtime')=='precision_shared_14b_v1'
    marker=root/('models/precision_roles_qwen25_14b_v1/training_complete.json' if shared else 'models/vex-writer-qwen3-8b-v1/training_complete.json')
    pin=json.loads(marker.read_text(encoding='utf-8')) if marker.is_file() else {}
    base=pin.get('base')
    if base:
        from src.common.runtime.model_paths import pinned_base
        base=str(pinned_base(pin))
    spec=dict(provider='local_shared_base', model='Qwen2.5-Coder-14B-Instruct' if shared else 'Qwen3-8B',
                runtime=config.get('runtime'), adapter=None, base=base, recorded_base=pin.get('base'),
                base_files_sha256=pin.get('base_files_sha256'), weights_available=marker.is_file(), nli_used=False)
    from src.item4.models.review_adapter_config import active_roles
    roles=active_roles()
    if any(roles.values()):spec['role_adapters']=roles
    if role and roles.get(role):
        spec.update(provider='local_shared_role_adapter',adapter=roles[role])
    return spec


def generate(system, packet, *, role):
    from src.common.runtime.inference_role_policy import require_inference_role
    require_inference_role(role)
    spec = identity(role)
    if spec['provider'] == 'typesafe_jev':
        from src.item4.models.constrained_choice_provider import generate as jev_generate
        return jev_generate(system, packet, role=role)
    if spec['provider'].startswith('local_shared'):
        if spec.get('runtime')=='precision_shared_14b_v1':
            from src.common.runtime.shared_adapter_runtime import get_precision_runtime
            runtime=get_precision_runtime()
        else:
            from src.item3.agents.identification_model_runtime import get_runtime
            runtime=get_runtime()
        return runtime.prerequisite_json(system, packet, role=role)
    import requests
    headers = {'Content-Type': 'application/json'}
    if os.getenv('ICS_PREREQUISITE_LLM_KEY'):
        headers['Authorization'] = 'Bearer ' + os.environ['ICS_PREREQUISITE_LLM_KEY']
    response = requests.post(spec['endpoint'], headers=headers, json=dict(
        model=spec['model'], temperature=0, max_tokens=4096,
        messages=[dict(role='system', content=system),
                  dict(role='user', content=json.dumps(packet, ensure_ascii=False))],
        response_format=dict(type='json_object')), timeout=(10, 120))
    response.raise_for_status()
    result = response.json()
    choice = result['choices'][0]
    if choice.get('finish_reason') != 'stop':
        raise ValueError('Generative response is incomplete')
    prediction = parse_json(choice['message']['content'])
    if not isinstance(prediction, dict):
        raise ValueError('Expected a JSON object')
    return dict(prediction=prediction, model=spec, llm_used=True)
