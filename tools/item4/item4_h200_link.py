"""Local-only authenticated connection to the user's existing Kubernetes H200 worker."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse
from pathlib import Path
import select
import socketserver

from kubernetes import client, config
from kubernetes.stream import portforward, stream

CONFIG = Path(__file__).resolve().parents[2]/'hysage-kubeconfig.yaml'
POD = 'test-0'
NAMESPACE = 'p-hysage'


def api():
    config.load_kube_config(str(CONFIG))
    return client.CoreV1Api()


def remote(code):
    return stream(api().connect_get_namespaced_pod_exec,POD,NAMESPACE,command=['python','-c',code],
                  stdin=False,stdout=True,stderr=True,tty=False)


def serve(port):
    v = api()
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            tunnel = portforward(v.connect_get_namespaced_pod_portforward,POD,NAMESPACE,ports=str(port))
            peer = tunnel.socket(port)
            try:
                while True:
                    ready,_,_ = select.select([self.request,peer],[],[],60)
                    if not ready:
                        continue
                    for source in ready:
                        data=source.recv(1024*1024)
                        if not data:
                            return
                        (peer if source is self.request else self.request).sendall(data)
            finally:
                tunnel.close()
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address=True
        daemon_threads=True
    with Server(('127.0.0.1',port),Handler) as server:
        print('H200 loopback link ready',flush=True)
        server.serve_forever()


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port',type=int,default=18128)
    serve(p.parse_args().port)
