import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from src.item4.evaluation import scenario_evaluation_runner as runs
from src.item4.web import scenario_evaluation_api as api
from tools.item4 import monitor_item4_population as watch
from tools.item4 import finalize_item4_population_rerun as finish


def test_population_artifacts_require_a_completed_hash_pinned_comparison(tmp_path,monkeypatch):
    folder=tmp_path/'run'
    folder.mkdir()
    name='population-report.ko.html'
    path=folder/name
    path.write_bytes(b'<html lang="ko">verified</html>')
    row=dict(run_id='run',status='running',data_hashes={name:runs.file_sha(path)})
    monkeypatch.setattr(api,'snapshot',lambda _:row)
    monkeypatch.setattr(runs,'OUTPUT',tmp_path)
    app=FastAPI()
    app.include_router(api.router)
    client=TestClient(app)
    url='/api/item4/evaluation-runs/run/population-review/'+name
    assert client.get(url).status_code==404
    row.update(status='completed',population_comparison={})
    assert client.get(url).status_code==404
    row['population_comparison']={'previous_run_id':'old'}
    assert client.get(url).content==path.read_bytes()
    assert client.head(url).status_code==200
    assert client.get(url.replace(name,'arbitrary.txt')).status_code==404
    path.write_bytes(b'changed')
    assert client.get(url).status_code==409


def test_finalizer_refuses_partial_output_before_export_or_ledger_mutation(monkeypatch):
    monkeypatch.setattr(finish.runs.ledger,'get_run',lambda _:dict(status='partial',total=97553,completed=97553,candidate_count=97552))
    with pytest.raises(ValueError,match='finish successfully'):
        finish.finalize('unfinished')


def test_monitor_resumes_with_same_run_and_finalizes_only_completed_result(tmp_path,monkeypatch):
    run='run'
    folder=tmp_path/'results/item4_scenario_moe'/run
    folder.mkdir(parents=True)
    rows=iter([dict(status='partial',completed=8,candidate_count=7,total=97553),
               dict(status='running',completed=8,candidate_count=7,total=97553),
               dict(status='completed',completed=97553,candidate_count=97553,total=97553)])
    calls=[]
    monkeypatch.setattr(watch,'ROOT',tmp_path)
    monkeypatch.setattr(watch.ledger,'get_run',lambda _:next(rows))
    monkeypatch.setattr(watch.time,'sleep',lambda _:None)
    class Child:
        pid=1234
        def poll(self):
            return 0
    monkeypatch.setattr(watch.subprocess,'Popen',lambda args,**kw:calls.append(args) or Child())
    monkeypatch.setattr(watch,'finalize',lambda r:calls.append(r) or dict(status_changed=1,reasons_changed=2))
    watch.monitor(run,18128)
    assert calls[0][calls[0].index('--resume')+1]==run
    assert calls[0][calls[0].index('--h200-port')+1]=='18128'
    assert calls[1]==run and json.loads((folder/'monitor.json').read_bytes())['status']=='completed'


def test_full_comparison_and_idempotent_publish_preserve_baseline(tmp_path,monkeypatch):
    ledger=finish.runs.ledger
    monkeypatch.setattr(ledger,'DB',tmp_path/'runs.sqlite3')
    monkeypatch.setattr(finish.runs,'OUTPUT',tmp_path/'output')
    output=finish.runs.OUTPUT
    old=output/finish.PREVIOUS
    new=output/'fixture-full'
    old.mkdir(parents=True)
    new.mkdir()
    counts=ledger.ProgressCounts()
    with (old/'candidates.jsonl').open('wb') as previous,(new/'candidates.jsonl').open('wb') as current:
        for i in range(97553):
            item=dict(id=str(i),cve=f'CVE-2025-{10000+i%12418}',packet_sha256='a'*64,
                      candidate_status='under_investigation',reasons=['old_reason'],synthetic=True,
                      generation_status='completed',run_id=finish.PREVIOUS)
            previous.write(json.dumps(item).encode()+b'\n')
            item['run_id']='fixture-full'
            if i==0:
                item.update(candidate_status='affected',reasons=[])
            counts.add(item)
            current.write(json.dumps(item).encode()+b'\n')
    baseline=dict(run_id=finish.PREVIOUS,status='completed',result={'candidates_sha256':runs.file_sha(old/'candidates.jsonl')})
    row=dict(run_id='fixture-full',status='completed',total=97553,completed=97553,candidate_count=97553,
             generation_method='scenario_moe_h200_llm',code_hashes={},data_hashes={},
             result=dict(counts.snapshot(),candidates_sha256=runs.file_sha(new/'candidates.jsonl')))
    with ledger._connect() as db,db:
        for item in (baseline,row):
            db.execute('insert into runs values (?,?)',(item['run_id'],json.dumps(item)))
    info=finish.finalize('fixture-full')
    assert info['status_changed']==info['reasons_changed']==info['status_or_reasons_changed']==1
    assert info['candidate_statuses']=={'affected':1,'under_investigation':97552}
    assert len((new/'changes.jsonl').read_bytes().splitlines())==1
    assert json.loads((output/'current_full_population.json').read_bytes())['run_id']=='fixture-full'
    assert ledger.get_run(finish.PREVIOUS)==baseline
    assert finish.finalize('fixture-full')==info
