"""Task-local DNS fallback; preserve original TLS hostname and CA validation.

The host's configured DNS servers can be unreachable while HTTPS still works.
Resolve only the kubeconfig API hostname through verified HTTPS DNS. Never edit
system settings, kubeconfig credentials, or the model/evaluation snapshot.
"""
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse
import ipaddress,socket
import requests,yaml

@contextmanager
def kube_dns_fallback(config):
    cfg=yaml.safe_load(Path(config).read_text(encoding='utf-8-sig'))
    ctx=next(c['context'] for c in cfg['contexts'] if c['name']==cfg['current-context'])
    cluster=next(c['cluster'] for c in cfg['clusters'] if c['name']==ctx['cluster'])
    host=urlparse(cluster['server']).hostname
    session=requests.Session();session.trust_env=False
    response=session.get('https://8.8.8.8/resolve',params={'name':host,'type':'A'},timeout=15)
    response.raise_for_status();answer=response.json()
    if answer.get('Status')!=0:raise RuntimeError('HTTPS DNS lookup failed')
    addresses=[str(ipaddress.IPv4Address(a['data'])) for a in answer.get('Answer',[]) if a.get('type')==1]
    if not addresses:raise RuntimeError('HTTPS DNS returned no IPv4 address')
    original=socket.getaddrinfo
    def lookup(name,*args,**kwargs):return original(addresses[0] if name==host else name,*args,**kwargs)
    socket.getaddrinfo=lookup
    try:yield dict(hostname=host,address=addresses[0],method='verified HTTPS DNS; original TLS identity retained')
    finally:socket.getaddrinfo=original;session.close()
