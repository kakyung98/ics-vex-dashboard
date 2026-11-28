import json
from tools.item4.train_synthetic_vep_adapter import prepare,response_tokens,wire_order,response_weights


def test_supervised_continuation_never_loads_test_worlds_or_splits_variants(tmp_path):
    manifest=prepare(tmp_path)
    train=json.loads((tmp_path/'train.json').read_text())
    valid=json.loads((tmp_path/'validation_inputs.json').read_text())
    assert len(train)==216 and len(valid)==108 and manifest['test_loaded'] is False
    train_worlds={r['base_id'] for r in train};valid_worlds={r['base_id'] for r in valid}
    assert not train_worlds&valid_worlds
    assert all(0<=int(k.split('-')[1])<4 for k in train_worlds)
    assert all(4<=int(k.split('-')[1])<8 for k in valid_worlds)
    assert {r['role'] for r in train}=={'exploitation-prerequisites','exploitation-coverage-review'}
    assert all(r['packet']['products']==[] for r in train)


def test_confidence_numbers_are_not_supervised_to_force_admission():
    class CharacterTokenizer:
        eos_token_id=0
        def __call__(self,text,**kwargs):
            return dict(input_ids=[ord(c) for c in text],offset_mapping=[(i,i+1) for i in range(len(text))])
    value=dict(cve='CVE-2099-12345',extraction_confidence=.95,expected=True)
    ids,labels=response_tokens(CharacterTokenizer(),value)
    masked=''.join(chr(i) for i,label in zip(ids,labels) if label==-100)
    assert masked=='0.95' and labels[-1]==0
    assert ''.join(chr(label) for label in labels[:-1] if label!=-100).find('CVE-2099-12345')>=0


def test_wire_order_preserves_values_and_prioritizes_schema_fields():
    value={'z':[{'op':'not','args':[{'condition':'a'}]}],'a':'x'}
    schema={'properties':{'a':{},'z':{'type':'array','items':{'properties':{'args':{},'op':{}}}}}}
    ordered=wire_order(value,schema)
    assert ordered==value and list(ordered)==['a','z'] and list(ordered['z'][0])==['args','op']
