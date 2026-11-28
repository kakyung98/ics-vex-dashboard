"""Read-only H200 diagnostics, with an explicit optional loopback tunnel repair.

No credentials are printed. No pod restart, deployment change, permission change,
or certificate-verification weakening is performed. Run from a normal project
terminal when the agent's restricted process cannot open network sockets.
"""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import json
import os
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))


def probe(host,port):
    try:
        with socket.create_connection((host,port),timeout=4):
            return dict(connected=True)
    except OSError as exc:
        return dict(connected=False,errno=exc.errno,winerror=getattr(exc,'winerror',None),error=type(exc).__name__)


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--repair',action='store_true',help='Restore only the existing localhost tunnel after checking the remote model.')
    cli.add_argument('--evaluate',action='store_true',help='Run the new four-track 16-case pilot only after all connection checks succeed.')
    cli.add_argument('--port',type=int,default=18128)
    cli.add_argument('--limit',type=int,default=16)
    args=cli.parse_args()
    if not 1024<=args.port<=65535 or args.limit<1:cli.error('Invalid port or pilot limit')
    import yaml
    import requests
    output=ROOT/'results/item4_rule_evaluation_v1'
    output.mkdir(parents=True,exist_ok=True)
    report=dict(checked_at=datetime.now(timezone.utc).isoformat(),credentials_printed=False,
                pod_mutations=False,permission_changes=False,model_evaluation_started=False)
    def save(status):
        report['status']=status
        (output/'h200_diagnostic.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps(report,ensure_ascii=False,indent=2),flush=True)
    conf=yaml.safe_load((ROOT/'hysage-kubeconfig.yaml').read_text(encoding='utf-8'))
    context=next(x['context'] for x in conf['contexts'] if x['name']==conf['current-context'])
    cluster=next(x['cluster'] for x in conf['clusters'] if x['name']==context['cluster'])
    server=urlparse(cluster['server'])
    report['loopback']=probe('127.0.0.1',args.port)
    report['loopback_control']=probe('127.0.0.1',8100)
    report['kubernetes_socket']=probe(server.hostname,server.port or 443)
    if not report['kubernetes_socket']['connected']:
        report['finding']=('Local socket access denied by the current process environment; server health is unknown.'
            if report['loopback'].get('winerror')==10013 and report['loopback_control'].get('winerror')==10013
            else 'Kubernetes endpoint DNS/transport failed before authentication; server health is unknown.')
        save('blocked_before_server');return 2
    try:
        from kubernetes import client,config
        from tools.item4.item4_h200_link import remote,POD,NAMESPACE
        config.load_kube_config(str(ROOT/'hysage-kubeconfig.yaml'))
        pod=client.CoreV1Api().read_namespaced_pod(POD,NAMESPACE,_request_timeout=(5,20))
        report['pod']=dict(name=POD,namespace=NAMESPACE,phase=pod.status.phase,
            containers=[dict(name=c.name,ready=c.ready,restarts=c.restart_count) for c in (pod.status.container_statuses or [])])
        # Query model metadata from inside the existing pod; no token is sent to any new service.
        code=("import json,urllib.request; "
              f"u='http://127.0.0.1:{args.port}/v1/models'; "
              "r=json.load(urllib.request.urlopen(u,timeout=10)); "
              "print(json.dumps({'served_models':[x['id'] for x in r['data']]}))")
        raw=remote(code)
        report['remote_model']=json.loads(raw.strip())
    except Exception as exc:
        report['server_probe_error']=type(exc).__name__
        # Avoid exception text: transport/exec errors may carry authenticated URLs.
        save('server_probe_failed');return 3
    from src.item4.models.nemotron_inference_provider import SERVED_MODEL
    if SERVED_MODEL not in report['remote_model'].get('served_models',[]):
        save('unexpected_remote_model');return 4
    if not report['loopback']['connected'] and args.repair:
        logs=ROOT/'logs';logs.mkdir(exist_ok=True)
        options=dict(cwd=str(ROOT),stdin=subprocess.DEVNULL,
                     stdout=(logs/'nemotron-h200-repair.out.log').open('ab'),
                     stderr=(logs/'nemotron-h200-repair.err.log').open('ab'))
        if os.name=='nt':options['creationflags']=subprocess.CREATE_NO_WINDOW
        process=subprocess.Popen([sys.executable,'-u',str(ROOT/'tools/item4/item4_h200_link.py'),'--port',str(args.port)],**options)
        report['tunnel_started_pid']=process.pid
        for _ in range(10):
            report['loopback']=probe('127.0.0.1',args.port)
            if report['loopback']['connected'] or process.poll() is not None:break
            time.sleep(.5)
    if not report['loopback']['connected']:
        save('remote_healthy_tunnel_missing');return 5
    try:
        from src.item4.models.remote_gpu_expert_client import token_path
        session=requests.Session();session.trust_env=False
        # LOCALAPPDATA differs under AppContainer; use the established host token location only if needed.
        token=token_path()
        if not token.is_file():token=Path('C:/Users/user/AppData/Local/ICS-VEX/runtime/item4_moe_h200.auth')
        session.headers['Authorization']='Bearer '+token.read_text().strip()
        reply=session.get(f'http://127.0.0.1:{args.port}/v1/models',timeout=(5,20));reply.raise_for_status()
        report['tunneled_models']=[r['id'] for r in reply.json()['data']]
    except Exception as exc:
        report['tunnel_probe_error']=type(exc).__name__;save('tunnel_probe_failed');return 6
    if SERVED_MODEL not in report['tunneled_models']:
        save('unexpected_tunneled_model');return 7
    if args.evaluate:
        previous=json.loads((ROOT/'results/item4_scenario_moe/nemotron-20261122T121210Z-534c666308/setup.json').read_bytes())
        identity=output/'nemotron_pinned_identity.json'
        identity.write_text(json.dumps(previous['backend_identity'],ensure_ascii=False,indent=2),encoding='utf-8')
        report['model_evaluation_started']=True;save('connected_evaluation_starting')
        report['evaluation_exit_code']=subprocess.call([sys.executable,str(ROOT/'tools/item4/evaluate_item4_rules.py'),
            '--run-model','--track','all','--limit',str(args.limit),'--nemotron-manifest',str(identity),'--port',str(args.port)],cwd=str(ROOT))
        save('evaluation_process_finished');return report['evaluation_exit_code']
    save('connected');return 0


if __name__=='__main__':raise SystemExit(main())
