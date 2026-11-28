"""Bounded Kubernetes exec using the current kubeconfig, without kubectl."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse
import base64
import json
from pathlib import Path
import ssl
import urllib.parse

import websocket
import yaml


def pod_status(config):
    """Read container health without starting a process inside the container."""
    import urllib.request
    cfg=yaml.safe_load(Path(config).read_text(encoding='utf-8-sig'))
    ctx=next(x['context'] for x in cfg['contexts'] if x['name']==cfg['current-context'])
    user=next(x['user'] for x in cfg['users'] if x['name']==ctx['user'])
    cluster=next(x['cluster'] for x in cfg['clusters'] if x['name']==ctx['cluster'])
    ca=cluster.get('certificate-authority-data')
    context=ssl.create_default_context(cadata=base64.b64decode(ca).decode()) if ca else ssl.create_default_context()
    if cluster.get('insecure-skip-tls-verify'):context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
    url=cluster['server']+'/api/v1/namespaces/'+ctx.get('namespace','default')+'/pods/test-0'
    request=urllib.request.Request(url,headers={'Authorization':'Bearer '+user['token']})
    with urllib.request.urlopen(request,context=context,timeout=15) as response:value=json.load(response)
    container=next(c for c in value['status']['containerStatuses'] if c['name']=='test')
    return dict(phase=value['status']['phase'],restart_count=container['restartCount'],state=container['state'],last_state=container.get('lastState'))


def upload_file(config,source,destination,timeout=60):
    """Stream a checked file over Kubernetes stdin without a native kubectl.

    Read an exact byte count, so no stdin-close extension is required. The remote
    final file appears only after the complete SHA-256 check succeeds.
    """
    import hashlib
    source=Path(source);size=source.stat().st_size
    h=hashlib.sha256()
    with source.open('rb') as stream:
        for block in iter(lambda:stream.read(8*1024*1024),b''):h.update(block)
    expected=h.hexdigest()
    script=f'''from pathlib import Path
import sys,hashlib,os,json
p=Path({str(destination)!r});p.parent.mkdir(parents=True,exist_ok=True)
t=p.with_name(p.name+'.partial');remaining={size};h=hashlib.sha256()
with t.open('wb') as f:
 while remaining:
  b=sys.stdin.buffer.read(min(1024*1024,remaining))
  if not b:raise EOFError('Incomplete upload')
  f.write(b);h.update(b);remaining-=len(b)
 f.flush();os.fsync(f.fileno())
if h.hexdigest()!={expected!r}:raise ValueError('Upload hash mismatch')
t.replace(p);print(json.dumps(dict(uploaded={size},sha256=h.hexdigest())),flush=True)
'''
    cfg=yaml.safe_load(Path(config).read_text(encoding='utf-8-sig'))
    ctx=next(x['context'] for x in cfg['contexts'] if x['name']==cfg['current-context'])
    user=next(x['user'] for x in cfg['users'] if x['name']==ctx['user'])
    cluster=next(x['cluster'] for x in cfg['clusters'] if x['name']==ctx['cluster'])
    ca=cluster.get('certificate-authority-data')
    context=ssl.create_default_context(cadata=base64.b64decode(ca).decode()) if ca else ssl.create_default_context()
    if cluster.get('insecure-skip-tls-verify'):context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
    params=[('command',x) for x in ['python','-c',script]]
    params += [('stdout','true'),('stderr','true'),('stdin','true'),('tty','false'),('container','test')]
    url=cluster['server'].replace('https:','wss:')+'/api/v1/namespaces/'+ctx.get('namespace','default')+'/pods/test-0/exec?'
    ws=websocket.create_connection(url+urllib.parse.urlencode(params),header={'Authorization':'Bearer '+user['token']},subprotocols=['v4.channel.k8s.io'],sslopt={'context':context},timeout=timeout)
    output=[];errors=[];status=None
    try:
        with source.open('rb') as stream:
            for block in iter(lambda:stream.read(256*1024),b''):ws.send_binary(b'\x00'+block)
        while True:
            packet=ws.recv()
            if not packet:break
            if isinstance(packet,str):packet=packet.encode()
            if packet[0]==1:output.append(packet[1:].decode())
            elif packet[0]==2:errors.append(packet[1:].decode())
            elif packet[0]==3:status=json.loads(packet[1:]);break
    finally:ws.close()
    if not status or status.get('status')!='Success':raise RuntimeError('Upload failed: '+''.join(errors)[-1000:]+str(status))
    receipt=json.loads(''.join(output));print(json.dumps(receipt),flush=True);return receipt


def execute(config, script, timeout=45):
    cfg = yaml.safe_load(Path(config).read_text(encoding='utf-8-sig'))
    ctx = next(x['context'] for x in cfg['contexts'] if x['name'] == cfg['current-context'])
    user = next(x['user'] for x in cfg['users'] if x['name'] == ctx['user'])
    cluster = next(x['cluster'] for x in cfg['clusters'] if x['name'] == ctx['cluster'])
    ca = cluster.get('certificate-authority-data')
    context = ssl.create_default_context(cadata=base64.b64decode(ca).decode()) if ca else ssl.create_default_context()
    if cluster.get('insecure-skip-tls-verify'):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    params = [('command', x) for x in ['python', '-c', script]]
    params += [('stdout', 'true'), ('stderr', 'true'), ('stdin', 'false'), ('tty', 'false'), ('container', 'test')]
    url = cluster['server'].replace('https:', 'wss:') + '/api/v1/namespaces/' + ctx.get('namespace', 'default') + '/pods/test-0/exec?'
    ws = websocket.create_connection(url + urllib.parse.urlencode(params),
        header={'Authorization': 'Bearer ' + user['token']}, subprotocols=['v4.channel.k8s.io'],
        sslopt={'context': context}, timeout=min(timeout,15))
    ws.settimeout(timeout)
    output, errors, status = [], [], None
    try:
        while True:
            packet = ws.recv()
            if not packet:
                break
            if isinstance(packet, str):
                packet = packet.encode()
            if packet[0] == 1:
                output.append(packet[1:].decode())
            elif packet[0] == 2:
                errors.append(packet[1:].decode())
            elif packet[0] == 3:
                status = json.loads(packet[1:])
                break
    finally:
        ws.close()
    if not status or status.get('status') != 'Success':
        raise RuntimeError('Remote exec failed: ' + ''.join(errors)[-3000:] + str(status))
    return ''.join(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('script', type=Path)
    args = parser.parse_args()
    print(execute(args.config, args.script.read_text(encoding='utf-8')))
