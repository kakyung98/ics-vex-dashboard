"""Full-population indexing, source evidence and paginated draft boundaries."""
from copy import deepcopy
import hashlib
import json
import sqlite3
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from src import operational_corpus as corpus,operational_corpus_api as api


def fixture_source(folder,count=5):
    folder.mkdir();records=[];extractions=[]
    for i in range(count):
        cve=f'CVE-2026-{10000+i}';text='Successful exploitation requires network access.'
        records.append(dict(cve=cve,identity_ambiguous=False,sources=[dict(id=cve+':s',text=text,text_sha256=hashlib.sha256(text.encode()).hexdigest())]))
        fact=dict(kind='access_position',necessity='explicitly_required',condition='Network access',source_id=cve+':s',source_span=[0,len(text)],source_quote=text,evidence_demands=['network_records'])
        extra=dict(cve=cve,all_packets_read=i!=count-1,facts=[fact] if i!=1 else [],extraction_state='fixture')
        extra['facts']+=([{**fact,'necessity':'not_required','condition':'Authentication'}] if i==0 else [])
        extra['facts']+=([{**fact,'source_quote':'invented quote'}] if i==2 else [])
        extra['packet_path_proposals']=[];extractions.append(extra)
    sources=''.join(corpus.encoded(r)+'\n' for r in records)
    (folder/'full_inputs.jsonl').write_text(sources,encoding='utf-8')
    (folder/'semantic_extractions.jsonl').write_text(''.join(corpus.encoded(r)+'\n' for r in extractions),encoding='utf-8')
    (folder/'input_manifest.json').write_text(json.dumps(dict(inputs_sha256=corpus.sha(folder/'full_inputs.jsonl'))),encoding='utf-8')
    return records


def test_all_rows_retained_unknown_and_invalid_are_distinct(tmp_path):
    source=tmp_path/'source';records=fixture_source(source)
    database=tmp_path/'corpus.db';report=corpus.build(source,database,expected_population=5)
    assert report['population']==5 and report['excluded']==0
    assert report['invalid_candidates']==1 and report['automatic_approvals']==0
    assert corpus.search(database=database)['total']==5
    assert corpus.detail(records[1]['cve'],database)['draft']['state']=='no_explicit_conditions'
    assert corpus.detail(records[2]['cve'],database)['draft']['state']=='source_evidence_error'
    assert corpus.detail(records[-1]['cve'],database)['draft']['state']=='source_reading_pending'
    draft=corpus.detail(records[0]['cve'],database)['draft']
    assert draft['formula'] is None and draft['nonrequirements']
    assert not draft['eligible_for_vex']


def test_population_and_hash_mismatches_fail_without_replacing_previous_snapshot(tmp_path):
    source=tmp_path/'source';fixture_source(source)
    database=tmp_path/'corpus.db';corpus.build(source,database,expected_population=5)
    with pytest.raises(ValueError,match='population'):corpus.build(source,database,expected_population=6)
    (source/'full_inputs.jsonl').write_text('tampered',encoding='utf-8')
    with pytest.raises(ValueError,match='digest'):corpus.build(source,database,expected_population=5)
    assert corpus.search(database=database)['total']==5


def test_api_pagination_search_and_streaming_export(tmp_path,monkeypatch):
    source=tmp_path/'source';records=fixture_source(source,7)
    database=tmp_path/'corpus.db';corpus.build(source,database,expected_population=7)
    monkeypatch.setattr(corpus,'DATABASE',database);monkeypatch.setattr(corpus,'SOURCE',source)
    app=FastAPI();app.include_router(api.router);client=TestClient(app)
    prefix='/api/operational-workflow/corpus'
    assert client.get(prefix+'/summary').json()['indexed_cves']==7
    a=client.get(prefix+'/cves?offset=0&limit=3').json();b=client.get(prefix+'/cves?offset=3&limit=3').json()
    assert {r['cve'] for r in a['rows']}.isdisjoint(r['cve'] for r in b['rows'])
    assert client.get(prefix+'/cves?q=10006').json()['total']==1
    assert client.get(prefix+'/cves?limit=201').status_code==422
    exported=[json.loads(line) for line in client.get(prefix+'/export').text.splitlines()]
    assert {r['cve'] for r in exported}=={r['cve'] for r in records}
    assert client.get(prefix+'/cves/CVE-0000-00000').status_code==404


def test_global_clustering_has_no_500_review_limit_and_never_approves_questions(tmp_path,monkeypatch):
    import numpy as np
    from src import prerequisite_models
    from tools import build_operational_corpus as builder
    source=tmp_path/'source';fixture_source(source,501)
    database=tmp_path/'corpus.db';corpus.build(source,database,expected_population=501)
    monkeypatch.setattr(builder,'STATUS',tmp_path/'status.json')
    def vectors(texts):return np.tile(np.array([[1.,0.]]),(len(texts),1)),'synthetic'
    monkeypatch.setattr(prerequisite_models,'embed_conditions',vectors)
    result=builder.cluster(database,ks=(1,))
    assert result['assigned_cves']==500  # One CVE has no conditions, and remains indexed.
    assert corpus.search(database=database)['total']==501
    assert not result['eligible_for_vex'] and result['automatic_approvals']==0
    assert all(not t['question_reuse_approved'] for c in corpus.clusters(database) for t in c['common_candidates'])


def test_full_corpus_on_disk_has_every_pinned_cve():
    if not corpus.DATABASE.is_file():pytest.skip('Local full-corpus snapshot not built')
    expected={r['cve'] for r in corpus.rows(corpus.SOURCE/'full_inputs.jsonl')}
    with corpus.connect() as db:
        actual={r[0] for r in db.execute('SELECT cve FROM corpus')}
    assert len(actual)==12418 and actual==expected


def test_embedding_cache_only_encodes_new_condition_strings(tmp_path,monkeypatch):
    import numpy as np
    from src import prerequisite_models
    from tools.build_operational_corpus import semantic_vectors
    calls=[]
    def encode(texts):calls.append(texts);return np.ones((len(texts),3),dtype=np.float32),'fixture'
    monkeypatch.setattr(prerequisite_models,'embed_conditions',encode)
    semantic_vectors(['network','file'],tmp_path)
    semantic_vectors(['file','network','physical','file'],tmp_path)
    assert calls==[['network','file'],['physical']]


def test_unbuilt_corpus_returns_explicit_unavailable_state(tmp_path,monkeypatch):
    monkeypatch.setattr(corpus,'DATABASE',tmp_path/'missing.db')
    app=FastAPI();app.include_router(api.router);client=TestClient(app)
    for route in ('summary','cves','clusters','export','cves/CVE-2026-10000'):
        assert client.get('/api/operational-workflow/corpus/'+route).status_code==503


def test_export_iterator_survives_serial_worker_thread_changes(tmp_path,monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    source=tmp_path/'source';fixture_source(source)
    database=tmp_path/'corpus.db';corpus.build(source,database,expected_population=5)
    monkeypatch.setattr(corpus,'DATABASE',database)
    stream=api.export_rows()
    with ThreadPoolExecutor(1) as first,ThreadPoolExecutor(1) as second:
        a=json.loads(first.submit(next,stream).result())
        b=json.loads(second.submit(next,stream).result())
        rest=first.submit(list,stream).result()
    assert a['cve']!=b['cve'] and len(rest)==3
