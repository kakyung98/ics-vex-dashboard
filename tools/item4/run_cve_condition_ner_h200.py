"""H200 experiment status and verified artifact retrieval; never logs credentials."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse
import base64
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import zlib

ROOT=Path(__file__).resolve().parents[2]
REMOTE='/home/irteam/data-vol1/ics-vex-migration-20261116/cve-ner-runs/cve_ner_20261117_v1'


def connection():
    from kubernetes import client,config
    import yaml
    data=yaml.safe_load((ROOT/'hysage-kubeconfig.yaml').read_text(encoding='utf-8-sig'))
    config.load_kube_config_from_dict(data)
    context=next(x['context'] for x in data['contexts'] if x['name']==data['current-context'])
    return client.CoreV1Api(),context.get('namespace','default')


def open_exec(code):
    from kubernetes.stream import stream
    api,namespace=connection()
    packed=base64.b64encode(zlib.compress(code.encode())).decode()
    wrapper='import base64,zlib;exec(zlib.decompress(base64.b64decode('+repr(packed)+')))'
    return stream(api.connect_get_namespaced_pod_exec,'test-0',namespace,
                  command=['python','-c',wrapper],stderr=True,stdout=True,
                  stdin=False,tty=False,_preload_content=False,_request_timeout=30)


def remote(code):
    ws=open_exec(code)
    try:
        ws.run_forever(timeout=60)
        stdout,stderr=ws.read_stdout(),ws.read_stderr()
        if ws.returncode != 0:
            raise RuntimeError('Remote command failed: '+stderr[-3000:])
        return stdout
    finally:
        ws.close()


def fetch(destination):
    destination=Path(destination).resolve()
    if destination.exists():
        raise FileExistsError(destination)
    script="from pathlib import Path\nimport tarfile,hashlib,json\nw=Path("+repr(REMOTE)+")\nnames=['status.json','worker.py','worker.log','src','dataset','model/checkpoint','model/training_report.json','model/test_predictions.jsonl','model/history.json','model/status.json','inference','evaluation_report.json','validation_report.json','validation_tests.xml','validation_tests.log','tests','training_code_snapshot','validate_h200.py','source_manifest.json','synthetic_controls.json','environment_manifest.json']\na=w/'delivery.tar.gz'\nwith tarfile.open(a,'w:gz') as t:\n for name in names:\n  p=w/name\n  if p.exists():t.add(p,arcname=name)\nh=hashlib.sha256(a.read_bytes()).hexdigest()\nprint(json.dumps(dict(bytes=a.stat().st_size,sha256=h)))"
    meta=json.loads(remote(script))
    archive=Path(tempfile.gettempdir())/'ics-vex-cve-ner-delivery.tar.gz.download'
    code="from pathlib import Path\nimport base64,sys\nwith (Path("+repr(REMOTE)+")/'delivery.tar.gz').open('rb') as f:\n for b in iter(lambda:f.read(49152),b''):\n  sys.stdout.write(base64.b64encode(b).decode()+'\\n');sys.stdout.flush()"
    ws=open_exec(code)
    buffered=''
    received=0
    try:
        with archive.open('wb') as stream:
            while ws.is_open():
                ws.update(timeout=10)
                if ws.peek_stderr():
                    raise RuntimeError(ws.read_stderr()[-3000:])
                if ws.peek_stdout():
                    buffered += ws.read_stdout()
                    while '\n' in buffered:
                        line,buffered=buffered.split('\n',1)
                        if line:
                            raw=base64.b64decode(line,validate=True)
                            stream.write(raw);received+=len(raw)
                if received and received % (49152*256)==0:
                    print(json.dumps(dict(stage='download',received=received,total=meta['bytes'])),flush=True)
            if buffered.strip():
                raw=base64.b64decode(buffered.strip(),validate=True)
                stream.write(raw);received+=len(raw)
        if ws.returncode != 0:
            raise RuntimeError('Artifact transfer failed')
    finally:
        ws.close()
    actual=hashlib.sha256(archive.read_bytes()).hexdigest()
    if received != meta['bytes'] or actual != meta['sha256']:
        raise ValueError('Artifact transfer size/hash mismatch')
    destination.mkdir(parents=True)
    with tarfile.open(archive,'r:gz') as tar:
        for member in tar.getmembers():
            target=(destination/member.name).resolve()
            if not target.is_relative_to(destination) or member.issym() or member.islnk():
                raise ValueError('Unsafe archive member')
        tar.extractall(destination)
    (destination/'delivery_manifest.json').write_text(json.dumps(meta,indent=2),encoding='utf-8')
    archive.unlink()
    return dict(output=str(destination),**meta,hash_verified=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['status','exec','fetch'])
    parser.add_argument('--script');parser.add_argument('--output')
    args=parser.parse_args()
    if args.action=='fetch':
        if not args.output:parser.error('--output required')
        print(json.dumps(fetch(args.output)),flush=True)
    elif args.action=='exec':
        if not args.script:parser.error('--script required')
        print(remote(Path(args.script).read_text(encoding='utf-8')),flush=True)
    else:
        code="from pathlib import Path\nw=Path("+repr(REMOTE)+")\nfor n in ['status.json','model/status.json']:\n p=w/n\n if p.exists():print(n,p.read_text())"
        print(remote(code),flush=True)


if __name__=='__main__':
    main()
