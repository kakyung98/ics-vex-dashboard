import pytest
from tools.item4.run_item4_v2_unsupervised import normalize_training,encode_corpus,evaluation_payload


class Tokenizer:
    eos_token_id=99
    def __call__(self,text,**kw):return {'input_ids':[ord(c) for c in text]}


def test_unlabeled_packing_preserves_every_target_and_document():
    rows=[dict(id='a',text='abcdef',label_supervision=False,source_url='url'),
          dict(id='b',text='xyz',label_supervision=False,source_url='url')]
    blocks,report=encode_corpus(rows,Tokenizer(),4)
    assert report['ids']==['a','b'] and not report['metadata_only_records']
    assert report['token_count']==11
    assert sum(len(b)-1 for b in blocks)==10
    assert blocks[0][-1]==blocks[1][0]
    assert not report['truncation']


def test_missing_source_is_preserved_as_metadata_not_an_invented_description():
    text,missing=normalize_training(dict(id='icsa-x',text=None,source_url='https://source'))
    assert text=='icsa-x\nhttps://source' and missing


def test_generated_targets_cannot_be_treated_as_unlabeled_corpus():
    with pytest.raises(ValueError):
        encode_corpus([dict(id='x',text='test',label_supervision=True)],Tokenizer(),4)


def test_inference_projection_excludes_gold_and_split_metadata():
    row=dict(id='opaque',cve='CVE-2000-1234',target={'name':'x'},documents=[],assumptions=[],
             variant='affected_control',fold='evaluation',actual_affected=True)
    packet=evaluation_payload(row,None)
    assert not {'id','variant','fold','actual_affected'} & packet.keys()
    assert packet['source_selected_path'] is None


def test_prefix_reuse_matches_full_attention_with_variable_lengths():
    import torch
    from transformers import Qwen2Config,Qwen2ForCausalLM
    from tools.item4.evaluate_item4_v2_prefix import prefix_logits,vectorized_prefix_logits,full_logits,payload
    torch.manual_seed(3)
    model=Qwen2ForCausalLM(Qwen2Config(vocab_size=64,hidden_size=32,intermediate_size=64,
        num_hidden_layers=2,num_attention_heads=4,num_key_value_heads=2)).eval()
    groups=[[[2,3,4,10+i,20+i,30] for i in range(7)],
            [[5,6,7,8,9,11+i]+([31,32] if i%2 else [33]) for i in range(7)]]
    weight=model.lm_head.weight[:7]
    with torch.inference_mode():
        scores,stats=prefix_logits(model,groups,weight,0,'cpu')
        vectorized,_=vectorized_prefix_logits(model,groups,weight,0,'cpu')
        for i,g in enumerate(groups):
            expected=full_logits(model,g,weight,0,'cpu')
            torch.testing.assert_close(torch.tensor(scores[i]),expected,rtol=1e-5,atol=1e-6)
            torch.testing.assert_close(torch.tensor(vectorized[i]),expected,rtol=1e-5,atol=1e-6)
    assert stats['prefix_tokens']+stats['total_suffix_tokens']<stats['total_full_tokens']
    row=dict(cve='CVE-2000-1234',target={},documents=[],assumptions=[])
    assert payload(row,None)==evaluation_payload(row,None)
