"""Small random-model scheduling regression; no benchmark labels or checkpoints."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

def main():
    import torch
    from transformers import Qwen2Config,Qwen2ForCausalLM,StoppingCriteria,StoppingCriteriaList,LogitsProcessor
    from tools.item4.item4_rolling_decode import rolling_sample
    torch.set_num_threads(2);torch.manual_seed(491)
    model=Qwen2ForCausalLM(Qwen2Config(vocab_size=64,hidden_size=32,intermediate_size=64,
        num_hidden_layers=2,num_attention_heads=4,num_key_value_heads=2,
        max_position_embeddings=256,pad_token_id=0,eos_token_id=None,bos_token_id=1)).eval()
    from peft import get_peft_model,LoraConfig
    model=get_peft_model(model,LoraConfig(task_type='CAUSAL_LM',r=2,lora_alpha=2,target_modules=['q_proj','v_proj'])).eval()
    with torch.no_grad():
        for name,param in model.named_parameters():
            if '.lora_B.' in name:param.normal_(std=0.01)
    class Stop(StoppingCriteria):
        eos_token_id=63
        def __call__(self,ids,scores,**kwargs):
            marker=ids.gather(1,(ids!=0).long().argmax(-1)[:,None]).flatten()
            return (ids!=0).sum(-1)>=marker
    class Grammar(LogitsProcessor):
        def __init__(self,markers):
            self.matchers=list(markers);self.compiled_grammars=['g']*len(markers)
            self.token_bitmask=torch.zeros((len(markers),1),dtype=torch.int32);self.batch_size=len(markers)
        def __call__(self,ids,scores):
            marker=ids.gather(1,(ids!=0).long().argmax(-1)[:,None]).flatten().tolist()
            assert marker==self.matchers,(marker,self.matchers)
            return scores
    ids=torch.tensor([[5,2,3],[25,2,3],[7,2,3],[43,2,3]])
    common=dict(max_new_tokens=60,do_sample=False,repetition_penalty=1.05,
        stopping_criteria=StoppingCriteriaList([Stop()]),use_cache=True)
    with torch.inference_mode():
        baseline=model.generate(input_ids=ids,attention_mask=torch.ones_like(ids),**common)
        waiting=[2,3];seen={};calls=[]
        def refill(count):
            if not waiting:return None
            chosen=waiting[:count];del waiting[:count];calls.append(chosen);x=ids[chosen]
            return dict(owners=chosen,encoded=dict(input_ids=x,attention_mask=torch.ones_like(x)),
                processors=[Grammar(x[:,0].tolist())])
        model.generate(input_ids=ids[:2],attention_mask=torch.ones_like(ids[:2]),**common,
            custom_generate=rolling_sample,capacity=10,refill=refill,
            on_generated=lambda owner,row:seen.__setitem__(owner,row.clone()),logits_processor=[Grammar([5,25])])
        assert set(seen)=={0,1,2,3},seen.keys()
        for i in seen:
            expected=baseline[i,3:];expected=expected[expected!=0]
            assert torch.equal(seen[i],expected),(i,seen[i],expected)
        assert calls==[[2,3]],calls
    print('Rolling CPU regression passed: refill, KV merge/trim, grammar ownership, limits and repetition penalty')


if __name__=='__main__':main()
