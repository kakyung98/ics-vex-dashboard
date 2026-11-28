from copy import deepcopy
import os

import pytest

from src.research.item4_stage1_spans import annotation_records, bio, check_splits, decode, evaluate, sha


def record(text='The attack requires diagnostic mode.', identity='x'):
    return dict(id=identity, source_id=identity, source_type='ICSA', text=text,
                text_sha256=sha(text), group_id=identity, cves=[], spans=[],
                annotation_complete=True, annotator='human-1')


def positive(row):
    row = deepcopy(row); a = row['text'].index('requires')
    row['spans'] = [dict(start=a, end=len(row['text']), role='necessary_condition', quote=row['text'][a:])]
    return row


def test_exact_unicode_and_bio_roundtrip():
    row = positive(record('장비 🔧 attack requires diagnostic mode.'))
    assert decode(row, bio(row)) == row['spans']
    row['spans'][0]['quote'] = 'fabricated'
    with pytest.raises(ValueError, match='quote'):
        bio(row)


def test_kappa_alignment_and_degenerate_case():
    gold = positive(record()); predicted = deepcopy(gold); predicted['prediction_complete'] = True
    report = evaluate([gold], [predicted])
    assert report['primary_role_kappa']['kappa'] == 1
    assert report['exact_span']['f1'] == 1
    predicted['text'] += ' '
    predicted['text_sha256'] = sha(predicted['text'])
    with pytest.raises(ValueError, match='alignment'):
        evaluate([gold], [predicted])
    negative = record(); predicted = dict(negative, prediction_complete=True)
    assert evaluate([negative], [predicted])['primary_role_kappa']['kappa'] is None
    with pytest.raises(ValueError, match='match exactly'):
        evaluate([gold], [])


def test_unreviewed_and_incomplete_are_not_negative_gold():
    gold = record(); predicted = dict(gold, prediction_complete=True)
    gold['annotation_complete'] = False
    with pytest.raises(ValueError, match='human annotation'):
        evaluate([gold], [predicted])
    gold['annotation_complete'] = True; predicted['prediction_complete'] = False
    with pytest.raises(ValueError, match='coverage'):
        evaluate([gold], [predicted])


@pytest.mark.parametrize('field,value', [('group_id', 'x'), ('source_id', 'x'), ('cves', ['CVE-2026-12345'])])
def test_cross_split_leakage(field, value):
    a, b = record(), record('Different description.', 'y')
    a[field] = value; b[field] = value
    with pytest.raises(ValueError, match='leakage'):
        check_splits([a], [b], [])


def test_csaf_common_text_not_duplicated_per_cve():
    rows = annotation_records(dict(document=dict(tracking=dict(id='ICSA-test'), notes=[dict(text='Shared advice')]),
        vulnerabilities=[dict(cve='CVE-2026-12345', notes=[dict(text='First path')]),
                         dict(cve='CVE-2026-12346', notes=[dict(text='Second path')])]))
    assert len(rows) == 3
    assert rows[0]['cves'] == ['CVE-2026-12345', 'CVE-2026-12346']
    assert rows[1]['cves'] == ['CVE-2026-12345']
    assert not any(r['annotation_complete'] for r in rows)


def test_nvd_and_cve5_adapters():
    cve = 'CVE-2026-12345'
    nvd = {'vulnerabilities': [{'cve': {'id': cve, 'descriptions': [{'value': 'NVD description'}]}}]}
    assert len(annotation_records(nvd)) == 1
    cve5 = {'cveMetadata': {'cveId': cve}, 'containers': {
        'cna': {'descriptions': [{'value': 'CNA description'}]},
        'adp': [{'descriptions': [{'value': 'ADP description'}]}]}}
    rows = annotation_records(cve5)
    assert len(rows) == 2
    assert len({r['id'] for r in rows}) == 2


def test_real_tiny_bert_train_predict_and_long_document(tmp_path):
    """Offline CPU integration with random tiny BERT; no accuracy claim."""
    pytest.importorskip('torch'); pytest.importorskip('transformers')
    from transformers import BertConfig, BertForTokenClassification, BertTokenizerFast
    from src.research.item4_stage1_bert import BertExtractor, encode, train
    base = tmp_path/'base'; base.mkdir()
    vocab = ['[PAD]', '[UNK]', '[CLS]', '[SEP]', '[MASK]', 'The', 'attack', 'requires',
             'diagnostic', 'mode', '.', 'Other', 'path', 'A', 'local']
    (base/'vocab.txt').write_text('\n'.join(vocab), encoding='utf-8')
    tokenizer = BertTokenizerFast(vocab_file=str(base/'vocab.txt'), do_lower_case=False)
    tokenizer.save_pretrained(base)
    BertForTokenClassification(BertConfig(vocab_size=len(vocab), hidden_size=16, num_hidden_layers=1,
        num_attention_heads=2, intermediate_size=24)).save_pretrained(base)
    long = positive(record('The attack ' * 40 + 'requires diagnostic mode.'))
    features, maps = encode(tokenizer, long, max_length=16, stride=4, supervised=True)
    assert len(features) > 1
    assert sum(sum(v != -100 for v in f['labels']) for f in features) == len(bio(long))
    training = positive(record(identity='train'))
    dev = positive(record('Other path requires diagnostic mode.', 'dev'))
    test = positive(record('A local attack requires diagnostic mode.', 'test'))
    device = os.environ.get('ITEM4_TEST_DEVICE', 'cpu')
    report = train([training], [dev], [test], str(base), tmp_path/'model', epochs=1,
                   batch_size=1, device=device, max_length=16, stride=4, local_files_only=True)
    assert report['test']['documents'] == 1
    assert report['best_epoch'] == 1
    assert report['device'] == device
    if device.startswith('cuda'):
        assert report['gpu_name']
    prediction = BertExtractor(tmp_path/'model', device=device, local_files_only=True).predict(long, 16, 4)
    assert prediction['prediction_complete'] is True
    assert prediction['logic'] is None and prediction['vex_eligible'] is False
    assert prediction['text_sha256'] == long['text_sha256']
