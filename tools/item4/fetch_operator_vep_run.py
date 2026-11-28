"""Fetch bounded candidate artifacts; never activate remote weights implicitly."""
from pathlib import Path
import argparse,base64,hashlib,io,json,tarfile,sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from tools.common.ncp_api_transport import execute

def fetch(run,output):
    remote_script="""from pathlib import Path
import io,tarfile,base64
p=Path(RUN)
b=io.BytesIO()
with tarfile.open(fileobj=b,mode='w:gz') as t:
 for name in ['trained','dataset/manifest.json','job_status.json','reevaluation_status.json','evaluation_before_boolean_constraint_fix.json','evaluation_before_boolean_constraint_fix']:
  f=p/name
  if f.exists():t.add(f,arcname=name)
print(base64.b64encode(b.getvalue()).decode())
""".replace('RUN',repr(run))
    payload=base64.b64decode(execute(ROOT/'hysage-kubeconfig.yaml',remote_script,timeout=50).strip())
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=True)
    archive=output/'candidate_artifacts.tar.gz';archive.write_bytes(payload)
    with tarfile.open(fileobj=io.BytesIO(payload),mode='r:gz') as t:
        for member in t.getmembers():
            target=(output/member.name).resolve()
            if not target.is_relative_to(output) or not (member.isfile() or member.isdir()):raise ValueError('Unsafe artifact member')
        t.extractall(output)
    receipt=dict(run=run,output=str(output),archive_sha256=hashlib.sha256(payload).hexdigest(),bytes=len(payload))
    (output/'fetch_receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8');print(json.dumps(receipt));return receipt

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();fetch(a.run,a.output)
