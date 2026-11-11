"""Left-padded GPU inference with an independent evidence grammar per request."""
import json


def generate_batch(runtime, task, packets, batch_size=4, *, max_padded_tokens=8192, prefill_chunk_size=None,compact_wire=False,tabular_wire=False):
    from src.inference_policy import require_inference_role
    from src.gpu_lease import assert_inference_available
    from src.identification_agent_contracts import SYSTEMS, VERSION
    from src.grounded_role_tasks import parse
    from src.llm_output_schema import prefix_function,prefix_for_schema
    import torch
    if task not in SYSTEMS or not 1 <= batch_size <= 32:
        raise ValueError('Unknown role or unsupported batch size')
    if not 6144 <= max_padded_tokens <= 32768 or prefill_chunk_size not in (None, 512, 1024):
        raise ValueError('Unsupported GPU memory budget')
    require_inference_role('identity-' + task); assert_inference_available()
    if batch_size == 1 and not compact_wire:
        return [runtime.identification_agent(task, packet) for packet in packets]
    responses = [None] * len(packets)
    with runtime.lock:
        if runtime.model is None: runtime._load('vex-writer')
        original_padding = runtime.tok.padding_side
        runtime.tok.padding_side = 'left'
        try:
            if compact_wire:
                from src.identification_wire import encode,decode
                transport=[encode(task,p,tabular=tabular_wire) for p in packets]
            else:transport=[(p,SYSTEMS[task],None,{}) for p in packets]
            prompts = [runtime.tok.apply_chat_template([
                {'role': 'system', 'content': system},
                {'role': 'user', 'content': json.dumps(packet, ensure_ascii=False,separators=(',',':')) if compact_wire else json.dumps(packet,ensure_ascii=False)}],
                tokenize=False, add_generation_prompt=True, enable_thinking=False) for packet,system,_,_ in transport]
            lengths = [len(runtime.tok(p)['input_ids']) for p in prompts]
            usable = []
            for i, length in enumerate(lengths):
                if length > 6144:
                    responses[i] = {'prediction': None, 'raw': '', 'error': 'input_too_long',
                                    'llm_used': False, 'model_mode': 'base', 'role': 'identity-' + task}
                else: usable.append(i)
            # Similar lengths reduce padding; output positions retain the caller's order.
            usable.sort(key=lambda i: lengths[i])

            def execute(indices):
                if not indices: return
                try:
                    return generate(indices)
                except torch.cuda.OutOfMemoryError:
                    if len(indices) == 1: raise
                # Leave the exception scope before retrying so its GPU tensors are freed.
                import gc
                gc.collect(); torch.cuda.empty_cache()
                runtime._batch_oom_splits = getattr(runtime, '_batch_oom_splits', 0) + 1
                mid = len(indices) // 2
                execute(indices[:mid]); execute(indices[mid:])

            def generate(indices):
                encoded = runtime.tok([prompts[i] for i in indices], padding=True, return_tensors='pt').to('cuda')
                width = int(encoded['input_ids'].shape[1])
                grammars = [prefix_for_schema(runtime,transport[i][2]) if compact_wire else prefix_function(runtime, 'identity-' + task, packets[i]) for i in indices]
                def allowed(batch_id, sent):
                    return grammars[batch_id](0, sent)
                context=runtime.identification_context(task) if hasattr(runtime,'identification_context') else runtime.model.disable_adapter()
                with context, torch.inference_mode():
                    out = runtime.model.generate(**encoded, max_new_tokens=768, do_sample=False,
                        pad_token_id=runtime.tok.pad_token_id, use_cache=True, logits_to_keep=1,
                        prefix_allowed_tokens_fn=allowed,prefill_chunk_size=prefill_chunk_size)
                eos = runtime.model.generation_config.eos_token_id
                eos = set(eos if isinstance(eos, list) else [eos])
                for j, i in enumerate(indices):
                    ids = out[j, width:].tolist()
                    stop = next((k+1 for k, token in enumerate(ids) if token in eos), len(ids))
                    raw = runtime.tok.decode(ids[:stop], skip_special_tokens=True)
                    pred = parse(raw)
                    wire_prediction=pred
                    if compact_wire:pred=decode(pred,transport[i][3])
                    trained=getattr(runtime,'identification_adapter_metadata',{}).get(task)
                    responses[i] = {'prediction': pred, 'raw': raw, 'role': 'identity-' + task,
                        'llm_used': True, 'model': 'Qwen3-8B', 'model_mode': 'fine_tuned' if trained else 'base', 'adapter':trained,
                        'contract': VERSION, 'legacy_identification_adapters_used': False,
                        'error': ('output_token_limit' if stop >= 768 else 'invalid_json_output') if pred is None else None,
                        'generation': {'input_tokens': lengths[i], 'padded_input_tokens': width,
                            'generated_tokens': stop, 'max_new_tokens': 768, 'do_sample': False,
                            'constrained_json_schema': True, 'batch_size': len(indices),
                            'prefill_chunk_size':prefill_chunk_size,'padded_token_budget':max_padded_tokens}}
                    if compact_wire:responses[i].update(wire_prediction=wire_prediction,identifier_aliases=transport[i][3],transport='compact-table-v1' if tabular_wire else 'compact-wire-v1')
                del out, encoded
            torch.cuda.empty_cache()
            start = 0
            while start < len(usable):
                end = start + 1
                # Bound KV cache and padded prefill on the 16 GiB local GPU.
                while (end < len(usable) and end-start < batch_size
                       and lengths[usable[end]] * (end-start+1) <= max_padded_tokens):
                    end += 1
                execute(usable[start:end]); start = end
                torch.cuda.empty_cache()
        finally:
            runtime.tok.padding_side = original_padding
    return responses
