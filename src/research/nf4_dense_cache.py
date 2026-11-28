"""Optional GPU cache of the existing NF4 weights' dequantized values.

Retains the packed checkpoint and FP32 adapters. Only the base linear kernel
changes to dense GEMM; kernel-level numerical equivalence is not guaranteed.
"""
import types


def enable(model):
    import torch
    import bitsandbytes as bnb
    rows=[]
    for name,module in list(model.named_modules()):
        if not isinstance(module,bnb.nn.Linear4bit):
            continue
        if hasattr(module,'_nf4_dense_cache'):
            continue
        dtype=module.compute_dtype or module.weight.quant_state.dtype
        values=bnb.functional.dequantize_4bit(module.weight.data,module.weight.quant_state).to(dtype)
        module.register_buffer('_nf4_dense_cache',values,persistent=False)
        def forward(self,x):
            if not self.compute_type_is_set:
                self.set_compute_type(x);self.compute_type_is_set=True
            original=x.dtype
            dtype=self.compute_dtype or x.dtype
            x=x.to(dtype)
            bias=self.bias.to(dtype) if self.bias is not None else None
            return torch.nn.functional.linear(x,self._nf4_dense_cache.to(dtype),bias).to(original)
        module.forward=types.MethodType(forward,module)
        rows.append(dict(module=name,dtype=str(values.dtype),bytes=values.numel()*values.element_size()))
    torch.cuda.empty_cache()
    return dict(layers=len(rows),bytes=sum(r['bytes'] for r in rows),
        dtypes=sorted({r['dtype'] for r in rows}),checkpoint_bytes_modified=False,
        adapter_weights_or_dtypes_modified=False,kernel_bitwise_equivalence_asserted=False)
