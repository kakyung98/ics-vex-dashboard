import hashlib

import pytest

from tools.item4.item4_review_sample_evidence import condition_exhibits, document_exhibits


def source_bundle():
    cve = 'CVE-2099-1000'
    aid, pid = 'icsa-99-001-01', 'CSAFPID-0001'
    key = aid + ':' + pid
    phrase = 'the optional monitoring setting is enabled'
    note = 'Issue in Test System before 1.6.10 occurs when ' + phrase + '.'
    pointer = '/vulnerabilities/0/notes/0/text'
    tree_ptr = '/product_tree/branches/0/branches/0/product'
    status_ptr = '/vulnerabilities/0/product_status/known_affected/0'
    source = dict(id=aid+':v0:n0', subject_ambiguous=False, text=note, pointer=pointer,
                  text_sha256=hashlib.sha256(note.encode()).hexdigest(), product_keys=[key],
                  scope_binding='CVE_product_set')
    doc = dict(document=dict(title='Test bulletin', publisher={'name':'Publisher'}),
               product_tree={'branches':[dict(category='vendor', name='Example', branches=[
                   dict(category='product_version', name='1.6', product=dict(name='Test System 1.6', product_id=pid))])]},
               vulnerabilities=[dict(cve=cve, product_status={'known_affected':[pid]}, notes=[{'text':note}])])
    origin = dict(file='example/source.json', document_sha256='f'*64)
    materials = {aid:(origin,doc,[source])}
    row = dict(advisory_id=aid, document_sha256='f'*64, status_pointer=status_ptr, product_pointer=tree_ptr,
               status='known_affected', source_product_id=pid, source_version='1.6',
               product_key=key, version_membership='true')
    lo = note.index(phrase)
    ref = dict(source_id=source['id'], span=[lo,lo+len(phrase)], quote=phrase)
    rule = dict(id='rule-1', expression={'condition':'p1'}, product_keys=[key],
                conditions=[dict(id='p1', source_ref=ref, operator_observable=True)])
    detail = dict(cve=cve, record_digest='d'*64, scenarios=[rule])
    question = dict(id='q1', operational_quote=phrase, source_refs=[{'source_id':source['id']}])
    return detail, materials, question, row


def test_product_excerpt_binds_cve_status_and_version_tree():
    detail, materials, _, row = source_bundle()
    _, exhibit = document_exhibits(detail['cve'],materials,[row])
    assert exhibit['facts']['source_status'] == 'known_affected'
    assert exhibit['facts']['product_tree_branches'][-1]['name'] == '1.6'
    with pytest.raises(ValueError,match='version'):
        document_exhibits(detail['cve'],materials,[dict(row,source_version='2.0')])
    with pytest.raises(ValueError,match='scope'):
        document_exhibits('CVE-2099-1111',materials,[row])


def test_operator_quote_must_be_bound_to_primary_document_and_scope():
    detail, materials, question, row = source_bundle()
    rule, = condition_exhibits(detail,materials,[question],[row])
    atom, = rule['facts']['operator_condition_excerpts']
    assert atom['question_id'] == 'q1'
    assert atom['note_version_excerpts'][0]['quote'] == 'Issue in Test System before 1.6.10'
    assert condition_exhibits(detail,materials,[],[row]) == []
    assert condition_exhibits(detail,materials,[question],[dict(row,version_membership='unknown')]) == []
    assert condition_exhibits(detail,materials,[question],[dict(row,product_key='another:product')]) == []
    materials[row['advisory_id']][1]['vulnerabilities'][0]['notes'][0]['text'] = 'Changed text'
    with pytest.raises(ValueError,match='differs'):
        condition_exhibits(detail,materials,[question],[row])
