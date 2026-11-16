"""Project-scoped kubectl transport; never prints kubeconfig credentials."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


def command(config):
    return ['kubectl','--kubeconfig',str(config),'exec','-i','test-0','--']


def execute(config, script):
    return subprocess.run(command(config)+['python','-'],input=script.encode(),check=True,capture_output=True).stdout.decode()


def upload(config, source, dest):
    source = Path(source)
    total = source.stat().st_size
    offset = int(execute(config, 'from pathlib import Path\np=Path('+repr(dest)+')\nprint(p.stat().st_size if p.exists() else 0)'))
    if offset > total:
        raise ValueError('Remote file larger than local source')
    chunk = 128 * 1024 * 1024
    started = time.monotonic()
    with source.open('rb') as f:
        f.seek(offset)
        while offset < total:
            wire = f.read(chunk)
            sha = hashlib.sha256(wire).hexdigest()
            script = ('import sys,hashlib,os; from pathlib import Path; p=Path('+repr(dest)+'); '
                      'p.parent.mkdir(parents=True,exist_ok=True); b=sys.stdin.buffer.read(); '
                      'assert hashlib.sha256(b).hexdigest()=='+repr(sha)+'; '
                      'f=p.open("r+b" if p.exists() else "w+b"); '
                      'f.seek(0,2); assert f.tell()=='+str(offset)+'; f.write(b); f.flush(); os.fsync(f.fileno()); f.close()')
            # Each chunk is checked before append. A reconnect resumes from persisted bytes.
            subprocess.run(command(config)+['python','-c',script],input=wire,check=True)
            offset += len(wire)
            print(json.dumps(dict(file=source.name, sent=offset, total=total, percent=round(100*offset/total,2), seconds=round(time.monotonic()-started,1))),flush=True)
    expected = hashlib.sha256()
    with source.open('rb') as f:
        for block in iter(lambda:f.read(8*1024*1024),b''):expected.update(block)
    remote = execute(config,'import hashlib\nh=hashlib.sha256()\nwith open('+repr(dest)+',"rb") as f:\n for b in iter(lambda:f.read(8*1024*1024),b""): h.update(b)\nprint(h.hexdigest())').strip()
    assert remote == expected.hexdigest(), 'Archive hash mismatch'
    print(json.dumps(dict(file=source.name,sha256=remote,verified=True)),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',type=Path,required=True)
    sub=parser.add_subparsers(dest='action',required=True)
    x=sub.add_parser('exec');x.add_argument('script',type=Path)
    x=sub.add_parser('upload');x.add_argument('source',type=Path);x.add_argument('destination')
    a=parser.parse_args()
    if a.action=='exec': print(execute(a.config,a.script.read_text(encoding='utf-8')))
    else: upload(a.config,a.source,a.destination)
