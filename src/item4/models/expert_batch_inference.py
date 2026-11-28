"""Batch the existing v2 expert requests with the original prompts and JSON constraints."""
import json

from src.item4.models import scenario_review_experts as moe


class _Window:
    """Schedule independent expert calls while retaining the original scenario-specific routing."""

    def __init__(self, cache):
        self.cache = cache
        self.pending = {}
        self.answers = {}
        self.saved = set()
        self.owner = None

    def request_model(self, key, system, packet):
        if key in self.answers:
            answer, owner = self.answers[key]
            if isinstance(answer, Exception):
                raise answer
            return answer, owner != self.owner
        if key in self.cache:
            return self.cache[key], True
        self.pending.setdefault(key, (dict(system=system, packet=packet), self.owner))
        raise moe.ExpertInputPending()

    def __setitem__(self, key, value):
        # Only schema- and citation-validated model outputs enter the run cache.
        if key not in self.saved:
            self.cache[key] = value
            self.saved.add(key)


def generate_candidates(items, *, cache, batch_size=8, provider=None):
    """Process (scenario, product, condition_rule) tuples, returning rows in the original order.

    A model output can be reused only for the same serialized v2 request under this run's
    pinned model and settings. Each row resolves the output aliases against its own evidence.
    """
    if batch_size < 1:
        raise ValueError('Batch size must be positive')
    provider = provider or generate_model_batch
    items = list(items)
    window = _Window(cache)
    results = [None] * len(items)
    while True:
        for i, (scenario, product, rule) in enumerate(items):
            if results[i] is not None:
                continue
            window.owner = i
            try:
                results[i] = moe.generate_candidate(scenario, product, condition_rule=rule, cache=window)
            except moe.ExpertInputPending:
                pass
        if not window.pending:
            return results
        queue = list(window.pending.items())
        window.pending.clear()
        # Group similar lengths in a generation batch to limit unnecessary prompt padding.
        queue.sort(key=lambda x: len(json.dumps(x[1][0], ensure_ascii=False)))
        for start in range(0, len(queue), batch_size):
            chunk = queue[start:start + batch_size]
            outputs = provider([request for _, (request, _) in chunk])
            if len(outputs) != len(chunk):
                raise ValueError('Model batch response count differs from request count')
            for (key, (_, owner)), output in zip(chunk, outputs):
                window.answers[key] = (output, owner)


def generate_model_batch(requests):
    """Use the existing local runtime and adapter policy. The remote worker can use decode_batch."""
    from src.item4.models import constrained_choice_provider as jev
    if jev.enabled():
        return jev.generate_batch(requests)
    from src.common.gpu_lease import assert_inference_available
    from src.common.runtime.inference_role_policy import require_inference_role
    from src.common.runtime.shared_adapter_runtime import get_precision_runtime
    from src.item4.models.review_adapter_config import inference_context

    require_inference_role(moe.INFERENCE_ROLE)
    assert_inference_available()
    runtime = get_precision_runtime()
    with runtime.lock:
        if runtime.model is None:
            runtime._load('vex-writer')
        with inference_context(runtime, moe.INFERENCE_ROLE) as adapter:
            spec = dict(provider='local_shared_role_adapter' if adapter else 'local_shared_base',
                        model=runtime.model_name, adapter=adapter, nli_used=False)
            return decode_batch(runtime, requests, spec)


def decode_batch(runtime, requests, model_spec):
    """HF batched greedy decoding. Caller owns the model lock and verified adapter context.

    runtime supplies tok and model. The same LM Format Enforcer constraint sees each row's
    original unpadded sequence, even when another row has a longer prompt or generation.
    """
    import torch
    from src.common.runtime.json_output_constraints import prefix_for_schema
    from src.item4.models.json_inference_client import parse_json

    if not requests:
        return []
    tokenizer = runtime.tok
    rendered = [tokenizer.apply_chat_template([
        dict(role='system', content=r['system']),
        dict(role='user', content=json.dumps(r['packet'], ensure_ascii=False))],
        tokenize=False, add_generation_prompt=True, enable_thinking=False) for r in requests]
    sequences = tokenizer(rendered, padding=False, truncation=False)['input_ids']
    width = max(map(len, sequences))
    if width > 6144:
        if len(requests) == 1:
            return [ValueError('Prerequisite input exceeds the bounded model context')]
        return _split(runtime, requests, model_spec)
    lengths = [len(s) for s in sequences]
    device = runtime.model.get_input_embeddings().weight.device
    input_ids = torch.full((len(sequences), width), tokenizer.pad_token_id, device=device, dtype=torch.long)
    attention = torch.zeros_like(input_ids)
    for i, seq in enumerate(sequences):
        input_ids[i, -len(seq):] = torch.tensor(seq, device=device)
        attention[i, -len(seq):] = 1
    constraints = [prefix_for_schema(runtime, r['packet']['schema']) for r in requests]
    end = runtime.model.generation_config.eos_token_id
    eos = set(end if isinstance(end, (tuple, list)) else [end if end is not None else tokenizer.eos_token_id])

    def allowed(index, tokens):
        if len(tokens) > width and int(tokens[-1]) in eos | {tokenizer.pad_token_id}:
            return sorted(eos)
        return constraints[index](0, tokens[width - lengths[index]:])

    try:
        with torch.inference_mode():
            generated = runtime.model.generate(input_ids=input_ids, attention_mask=attention, max_new_tokens=4096,
                do_sample=False, pad_token_id=tokenizer.pad_token_id, use_cache=True, logits_to_keep=1,
                prefix_allowed_tokens_fn=allowed)
        generated = generated[:, width:].tolist()
    except torch.cuda.OutOfMemoryError:
        if len(requests) == 1:
            raise
        generated = None
    if generated is None:
        del input_ids, attention
        torch.cuda.empty_cache()
        return _split(runtime, requests, model_spec)
    result = []
    for length, tokens in zip(lengths, generated):
        stop = next((i + 1 for i, t in enumerate(tokens) if t in eos), len(tokens))
        raw = tokenizer.decode(tokens[:stop], skip_special_tokens=True)
        try:
            if stop >= 4096:
                raise ValueError('Incomplete prerequisite output at the 4096 token limit')
            prediction = parse_json(raw)
        except ValueError as exc:
            result.append(exc)
            continue
        result.append(dict(prediction=prediction, llm_used=True, raw=raw, model=model_spec,
                           generation=dict(input_tokens=length, output_tokens=stop, constrained_json=True,
                                           batch_size=len(requests))))
    return result


def _split(runtime, requests, model_spec):
    mid = len(requests) // 2
    return decode_batch(runtime, requests[:mid], model_spec) + decode_batch(runtime, requests[mid:], model_spec)
