from copy import deepcopy

import pytest
from src.item4.models import expert_batch_inference as batch; from src.item4.models import scenario_review_experts as moe


def fixture(cve, evidence_id):
    scenario = dict(id=cve, cve=cve, synthetic=True, context=dict(scope='current_single',
                    deployment='running', runtime='bom', mode='normal', origin='same_zone'), answers={})
    product = dict(cve=cve, component_ref='stable-bom-id', version='1.2.3', state='fixed', reasons=[],
                   evidence=[dict(evidence_id=evidence_id, product_key='supplied:key',
                             source_version='1.2.3', version_membership='true', status='fixed')])
    return scenario, product, None


def response(packet):
    findings = dict(supplier='fixed', inventory='installed_exact', crosscheck='corroborated')
    return dict(prediction=dict(finding=findings[packet['expert']], cite='e0'),
                model={'model': 'test-fixture'}, llm_used=True)


def test_original_v2_wire_deduplicates_and_rebinds_each_case(monkeypatch):
    items = [fixture('CVE-2099-7011', 'original-document'), fixture('CVE-2099-7012', 'different-document')]
    serial = []
    serial_wire = []
    def single(system, packet, *, role):
        assert role == 'operating-record-review'
        serial_wire.append(dict(system=system, packet=deepcopy(packet)))
        return response(packet)
    monkeypatch.setattr(moe.L, 'generate', single)
    for scenario, product, rule in items:
        serial.append(moe.generate_candidate(scenario, product, condition_rule=rule))
    grouped_wire = []
    def provider(requests):
        grouped_wire.extend(deepcopy(requests))
        return [response(req['packet']) for req in requests]
    cache = {}
    out = batch.generate_candidates(items, cache=cache, provider=provider, batch_size=4)
    assert grouped_wire == serial_wire[:3] == serial_wire[3:]
    assert len(cache) == 3
    for i, candidate in enumerate(out):
        expected = serial[i]
        assert candidate['candidate_status'] == expected['candidate_status'] == 'fixed'
        assert candidate['evidence_ids'] == expected['evidence_ids']
        assert candidate['cited_evidence'] == expected['cited_evidence']
        assert [r['input_sha256'] for r in candidate['experts']] == [r['input_sha256'] for r in expected['experts']]
        assert all(r['model_called'] == (i == 0) for r in candidate['experts'])
    again = batch.generate_candidates(items[::-1], cache=cache, provider=lambda _: pytest.fail('unexpected model call'))
    assert all(expert['execution'] == 'cached' for candidate in again for expert in candidate['experts'])


def test_different_versions_are_separate_model_inputs():
    first = fixture('CVE-2099-7011', 'evidence-1')
    second = fixture('CVE-2099-7012', 'evidence-2')
    second[1]['version'] = '1.2.4'
    second[1]['evidence'][0]['source_version'] = '1.2.4'
    shapes = []
    def provider(requests):
        shapes.append(len(requests))
        return [response(r['packet']) for r in requests]
    out = batch.generate_candidates([first, second], cache={}, provider=provider)
    assert shapes == [2, 2, 2]
    assert all(e['model_called'] for r in out for e in r['experts'])


def test_batch_transport_failure_propagates_to_wave_for_safe_retry():
    def offline(requests):
        raise TimeoutError('temporary transport failure')
    with pytest.raises(TimeoutError):
        batch.generate_candidates([fixture('CVE-2099-7011', 'e1')], cache={}, provider=offline)


def test_decoder_retains_each_rows_prompt_constraint_and_output_length(monkeypatch):
    import json
    from types import SimpleNamespace
    from src.common.runtime import json_output_constraints as llm_output_schema

    torch = pytest.importorskip('torch')
    requests = [dict(system=name, packet=dict(schema={'title': name})) for name in ('short', 'long')]
    originals = dict(short=[1, 2], long=[3, 4, 5, 6])
    seen = {}

    class Tokenizer:
        pad_token_id = 0
        eos_token_id = 9

        def apply_chat_template(self, messages, **kwargs):
            name = messages[0]['content']
            assert messages == [{'role': 'system', 'content': name},
                                {'role': 'user', 'content': json.dumps({'schema': {'title': name}})}]
            assert kwargs == dict(tokenize=False, add_generation_prompt=True, enable_thinking=False)
            return name

        def __call__(self, prompts, **kwargs):
            assert kwargs == dict(padding=False, truncation=False)
            return {'input_ids': [originals[name] for name in prompts]}

        def decode(self, tokens, *, skip_special_tokens):
            assert skip_special_tokens
            return json.dumps({'tokens': [token for token in tokens if token != self.eos_token_id]})

    def constraint(runtime, schema):
        def allowed(index, tokens):
            assert index == 0
            seen.setdefault(schema['title'], []).append(tokens.tolist())
            return [7, 8, 9]
        return allowed

    class Model:
        generation_config = SimpleNamespace(eos_token_id=[9])

        def get_input_embeddings(self):
            return SimpleNamespace(weight=torch.zeros(1))

        def generate(self, input_ids, attention_mask, prefix_allowed_tokens_fn, **kwargs):
            assert kwargs == dict(max_new_tokens=4096, do_sample=False, pad_token_id=0, use_cache=True, logits_to_keep=1)
            assert input_ids.tolist() == [[0, 0, 1, 2], [3, 4, 5, 6]]
            assert attention_mask.tolist() == [[0, 0, 1, 1], [1, 1, 1, 1]]
            for tokens in ((7, 7), (9, 8), (0, 9)):
                for index in (0, 1):
                    choices = prefix_allowed_tokens_fn(index, input_ids[index])
                    if tokens[index] == 0:
                        assert choices == [9]
                    else:
                        assert tokens[index] in choices
                input_ids = torch.cat([input_ids, torch.tensor(tokens).view(-1, 1)], dim=1)
            return input_ids

    monkeypatch.setattr(llm_output_schema, 'prefix_for_schema', constraint)
    result = batch.decode_batch(SimpleNamespace(tok=Tokenizer(), model=Model()), requests, {'model': 'test-fixture'})
    assert seen['short'] == [[1, 2], [1, 2, 7]]
    assert seen['long'] == [[3, 4, 5, 6], [3, 4, 5, 6, 7], [3, 4, 5, 6, 7, 8]]
    assert [(r['prediction']['tokens'], r['generation']['input_tokens'], r['generation']['output_tokens'])
            for r in result] == [([7], 2, 2), ([7, 8], 4, 3)]
