import json
from pathlib import Path
from src.item4.evaluation import prerequisite_consistency as E
from tools.item4 import run_prerequisite_consistency_population as R
from tools.item4.characterize_prerequisite_population import characterize


def test_full_population_retains_missing_empty_and_labeled_records(tmp_path, monkeypatch):
    monkeypatch.setattr(R, 'ROOT', tmp_path)
    corpus, csaf, output = [tmp_path/x for x in ('corpus','csaf','output')]
    for p in (corpus,csaf,output):
        p.mkdir()
    ids=['CVE-2099-90001','CVE-2099-90002','CVE-2099-90003']
    population=tmp_path/'population.json'
    population.write_text(json.dumps([dict(cve=cve) for cve in ids]))
    for cve, conditions in zip(ids[:2],[[dict(id='c1',statement='No user interaction is required.')],[]]):
        raw=dict(job=dict(conditions=[dict(cve=cve,status='extracted',prerequisite=dict(draft=dict(
            cve=cve,prerequisites=conditions)), sources=[dict(text='CVSS in original extraction input')])]))
        (corpus/(cve+'.json')).write_text(json.dumps(raw))
    vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    (csaf/'a.json').write_text(json.dumps(dict(vulnerabilities=[dict(cve=ids[0],
        cwe=dict(id='CWE-787'),scores=[dict(cvss_v3=dict(vectorString=vector), products=['p1'])])])))
    manifest=R.prepare(output,population,corpus,[csaf])
    assert manifest['population']==3
    assert manifest['counts']['with_assertions']==1
    assert manifest['counts']['without_assertions']==2
    rows=[json.loads(s) for s in (output/'extractions.jsonl').read_text().splitlines()]
    assert rows[-1]['extraction_status']=='checkpoint_missing'
    refs={r['cve']:r for r in json.loads((output/'references.json').read_bytes())}
    assert set(refs)==set(ids)
    (output/'checkpoints').mkdir()
    for row in rows:
        state='mapped' if E.extraction_view(row)['conditions'] else 'no_extracted_assertions'
        result=dict(cve=row['cve'],input_sha256=E.digest(row),state=state,
                    comparison=E.evaluate(row,refs[row['cve']]))
        (output/'checkpoints'/(row['cve']+'.json')).write_text(json.dumps(result))
    report=characterize(output)
    assert report['accounted_records']==3
    assert report['by_reference_cwe']['CWE-787']['records']==1
    assert report['by_reference_cwe']['unknown']['records']==2
    assert report['original_extraction_status_counts']['checkpoint_missing']==1
    assert not report['cluster_purity_measured']


def test_checkpoint_retries_transient_windows_read_lock(tmp_path, monkeypatch):
    original=Path.replace
    calls=[]
    def locked(self,target):
        calls.append(target)
        if len(calls)<3:
            raise PermissionError('temporary Windows sharing lock')
        return original(self,target)
    monkeypatch.setattr(Path,'replace',locked)
    monkeypatch.setattr(R.time,'sleep',lambda _:None)
    R.write(tmp_path/'progress.json',dict(completed=10))
    assert len(calls)==3
    assert json.loads((tmp_path/'progress.json').read_bytes())['completed']==10
