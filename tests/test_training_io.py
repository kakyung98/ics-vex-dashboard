import threading
import time
from src.training_io import atomic_json,read_json


def test_reader_and_atomic_writer_can_coexist(tmp_path):
    p=tmp_path/'status.json';atomic_json(p,{'step':0})
    errors=[]
    def reader():
        for _ in range(100):
            v=read_json(p)
            if 'step' not in v:errors.append(v)
    t=threading.Thread(target=reader);t.start()
    for n in range(20):atomic_json(p,{'step':n})
    t.join();assert not errors and read_json(p)['step']==19


def test_transient_replace_failure_retries(tmp_path,monkeypatch):
    from pathlib import Path
    original=Path.replace;calls=[]
    def flaky(self,target):
        calls.append(1)
        if len(calls)<3:raise PermissionError('transient reader lock')
        return original(self,target)
    monkeypatch.setattr(Path,'replace',flaky)
    p=tmp_path/'status.json';atomic_json(p,{'ok':True})
    assert len(calls)==3 and read_json(p)=={'ok':True}
