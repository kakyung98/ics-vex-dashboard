"""Greedy HF decoding with completed rows removed from subsequent forwards.

Uses the logits processors, stopping criteria, prefill, cache and generation
configuration constructed by Transformers.generate. No output budget is reduced.
Supported deliberately narrowly: single-GPU decoder-only greedy inference.
"""


def select_processor_rows(processors, indices):
    """Keep each XGrammar matcher bound to its original request."""
    keep = indices.tolist()
    for processor in processors:
        if hasattr(processor, 'matchers') and hasattr(processor, 'token_bitmask'):
            processor.matchers = [processor.matchers[i] for i in keep]
            processor.compiled_grammars = [processor.compiled_grammars[i] for i in keep]
            processor.token_bitmask = processor.token_bitmask.index_select(
                0, indices.to(processor.token_bitmask.device))
            processor.batch_size = len(keep)
        elif processor.__class__.__name__ not in {
            'RepetitionPenaltyLogitsProcessor', 'MinLengthLogitsProcessor',
            'MinNewTokensLengthLogitsProcessor', 'SuppressTokensLogitsProcessor',
            'SuppressTokensAtBeginLogitsProcessor', 'ForcedEOSTokenLogitsProcessor',
        }:
            raise TypeError('Unreviewed stateful logits processor: ' + type(processor).__name__)


def compact_sample(model, input_ids, logits_processor, stopping_criteria,
                   generation_config, synced_gpus=False, streamer=None,
                   on_complete=None, **model_kwargs):
    import torch
    if synced_gpus or streamer is not None or generation_config.do_sample:
        raise ValueError('Compact decoding requires single-GPU greedy, non-streaming generation')
    if model.config.is_encoder_decoder or generation_config.return_dict_in_generate:
        raise ValueError('Compact decoding supports decoder-only tensor output')
    batch = input_ids.shape[0]
    owners = torch.arange(batch, device=input_ids.device)
    completed = [None] * batch
    outputs = model._prefill(input_ids, generation_config, model_kwargs,
                             is_first_iteration=not generation_config.is_assistant)
    prefilled = False
    with model._optimize_model_for_decode():
        while input_ids.shape[0]:
            if prefilled:
                prepared = model.prepare_inputs_for_generation(
                    input_ids, next_sequence_length=1 if model_kwargs['use_cache'] else None,
                    **model_kwargs)
                outputs = model(**prepared, return_dict=True)
            prefilled = True
            model_kwargs = model._update_model_kwargs_for_generation(
                outputs, model_kwargs, is_encoder_decoder=False)
            logits = outputs.logits[:, -1].to(copy=True, dtype=torch.float32,
                                              device=input_ids.device)
            tokens = logits_processor(input_ids, logits).argmax(dim=-1)
            input_ids = torch.cat([input_ids, tokens[:, None]], dim=-1)
            done = stopping_criteria(input_ids, None)
            del outputs, logits
            if not bool(done.any()):
                continue
            old_batch = input_ids.shape[0]
            for row in done.nonzero(as_tuple=False).flatten().tolist():
                owner = int(owners[row])
                sequence = input_ids[row].detach().clone()
                completed[owner] = sequence
                if on_complete is not None:
                    on_complete(owner, sequence)
            keep = (~done).nonzero(as_tuple=False).flatten()
            if not len(keep):
                break
            cache = model_kwargs.get('past_key_values')
            if cache is not None:
                cache.batch_select_indices(keep)
            for key in ('attention_mask', 'position_ids', 'token_type_ids'):
                value = model_kwargs.get(key)
                if isinstance(value, torch.Tensor) and value.ndim > 1 and value.shape[0] == old_batch:
                    model_kwargs[key] = value.index_select(0, keep)
            select_processor_rows(logits_processor, keep)
            input_ids = input_ids.index_select(0, keep)
            owners = owners.index_select(0, keep)
    assert all(row is not None for row in completed)
    longest = max(row.shape[-1] for row in completed)
    result = input_ids.new_full((batch, longest), int(generation_config._pad_token_tensor))
    for owner, row in enumerate(completed):
        result[owner, :len(row)] = row
    return result
