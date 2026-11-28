"""Compile the same source JSON schema with bounded formatting, not new facts."""
from copy import deepcopy
import hashlib
import json
import threading
from pathlib import Path

LOCK=threading.Lock()
PLACEHOLDER='__ICS_VEX_CVE_CONST__'


def canonical(schema,cve):
    if isinstance(schema,list):return [canonical(v,cve) for v in schema]
    if not isinstance(schema,dict):return schema
    return {k:(PLACEHOLDER if k=='const' and v==cve else canonical(v,cve))
        for k,v in schema.items()
        if k!='uniqueItems' and not(schema.get('type')=='array' and schema.get('maxItems')==0 and k=='items')}


def compile_grammar(schema,cve,folder):
    normalized=canonical(schema,cve)
    key=hashlib.sha256(json.dumps(normalized,sort_keys=True).encode()).hexdigest()
    path=folder/(key+'.json')
    with LOCK:
        if path.exists():receipt=json.loads(path.read_bytes())
        else:
            # Use the already pinned xgrammar installation next to the H200
            # inference server. This subprocess only compiles grammar on CPU.
            from kubernetes import client,config
            from kubernetes.stream import stream
            import yaml
            root=Path(__file__).resolve().parents[2]
            config.load_kube_config_from_dict(yaml.safe_load((root/'hysage-kubeconfig.yaml').read_text(encoding='utf-8')))
            worker_code=('import xgrammar,json,sys,importlib.metadata;'
                'schema=json.loads(sys.stdin.read());'
                'print(json.dumps(dict(grammar=str(xgrammar.Grammar.from_json_schema('
                'json.dumps(schema),any_whitespace=False,separators=(",",":"))),'
                'xgrammar=importlib.metadata.version("xgrammar"))))')
            code=('import subprocess,os,json;'
                'base="/home1/irteam/data-vol1/ics-vex-migration-20261116/item4-nemotron-20261122";'
                'env=dict(os.environ);'
                'env["LD_LIBRARY_PATH"]=base+"/toolchain/lib:"+base+"/venv/lib/python3.11/site-packages/nvidia/cu13/lib:"+'
                'base+"/venv/lib/python3.11/site-packages/torch/lib:"+env.get("LD_LIBRARY_PATH","");'
                'p=subprocess.run([base+"/venv/bin/python","-c",'+repr(worker_code)+'],'
                'input='+repr(json.dumps(normalized))+',capture_output=True,text=True,env=env);'
                'print(p.stdout if p.returncode==0 else json.dumps(dict(error=p.stderr[-1200:])))')
            raw=stream(client.CoreV1Api().connect_get_namespaced_pod_exec,'test-0','p-hysage',
                command=['python','-c',code],stdin=False,stdout=True,stderr=True,tty=False)
            receipt=json.loads(raw)
            if receipt.get('error'):raise RuntimeError(receipt['error'])
            receipt.update(schema_sha256=key,schema=normalized,
                formatting='any_whitespace=False; separators comma/colon without added whitespace',
                unique_items_enforced='original JSON schema post-validator')
            folder.mkdir(parents=True,exist_ok=True)
            temporary=path.with_suffix('.tmp');temporary.write_text(json.dumps(receipt),encoding='utf-8');temporary.replace(path)
    return receipt['grammar'].replace(PLACEHOLDER,cve),str(path),receipt['xgrammar']
