"""Explicit CUTLASS SDPA for Qwen3 on Windows builds without FlashAttention."""
NAME = 'icsvex_efficient_sdpa'


def efficient_attention(module, query, key, value, attention_mask, dropout=0.0,
                        scaling=None, is_causal=None, position_bias=None, **kwargs):
    import torch
    import torch.nn.functional as F
    from torch.nn.attention import sdpa_kernel, SDPBackend
    from transformers.integrations.sdpa_attention import repeat_kv
    if position_bias is not None: raise ValueError('This Qwen3 backend does not support additive position bias')
    groups = getattr(module, 'num_key_value_groups', 1)
    key = repeat_kv(key, groups);value = repeat_kv(value, groups)
    causal = getattr(module, 'is_causal', True) if is_causal is None else is_causal
    causal = bool(causal and query.shape[2] > 1 and attention_mask is None)
    if attention_mask is not None:
        # CUTLASS requires aligned outer bias strides. Padding the storage, then
        # slicing to the original shape, preserves every causal/padding mask value.
        if attention_mask.dtype == torch.bool:
            attention_mask = torch.zeros_like(attention_mask,dtype=query.dtype).masked_fill_(~attention_mask,float('-inf'))
        else:attention_mask = attention_mask.to(query.dtype)
        width = attention_mask.shape[-1];padding = (-width) % 8
        if padding: attention_mask = F.pad(attention_mask, (0,padding))[..., :width]
    with sdpa_kernel(SDPBackend.EFFICIENT_ATTENTION):
        output = F.scaled_dot_product_attention(query,key,value,attn_mask=attention_mask,
            dropout_p=dropout,scale=scaling,is_causal=causal,enable_gqa=False)
    return output.transpose(1,2).contiguous(),None


def install(model):
    from transformers import AttentionInterface
    from transformers.masking_utils import AttentionMaskInterface, sdpa_mask
    AttentionInterface.register(NAME,efficient_attention)
    AttentionMaskInterface.register(NAME,sdpa_mask)
    base = model.get_base_model() if hasattr(model,'get_base_model') else model
    if getattr(base.config,'model_type',None) != 'qwen3': raise ValueError('Only the tested Qwen3 model is supported')
    base.set_attn_implementation(NAME)
    return NAME
