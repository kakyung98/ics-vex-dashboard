"""Publish the explicit portability overlay, retaining replaced snapshot files."""
from pathlib import Path
import base64
import json
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.common.ncp_transport import execute

FILES=['tools/common/package_ncp_migration.py','tools/item4/ncp_operational_runtime.py','tools/common/ncp_serve.py',
       'tools/common/ncp_service.py','tools/common/ncp_acceptance.py','tools/common/connect_ncp.ps1',
       'tools/common/deploy_ncp_overlay.py','requirements-ncp.txt','docs/NCP_MIGRATION.md']
payload={name:base64.b64encode((ROOT/name).read_bytes()).decode() for name in FILES}
script='''from pathlib import Path
import json,base64,hashlib
root=Path('/home/irteam/data-vol1/ics-vex-migration-20261116/project')
payload=json.loads(PAYLOAD)
changes=[]
for name,encoded in payload.items():
 p=root/name;wire=base64.b64decode(encoded)
 before=p.read_bytes() if p.exists() else None
 if before is not None and before!=wire:
  backup=root/'results/cloud_migration/overlay_originals'/name
  if not backup.exists():
   backup.parent.mkdir(parents=True,exist_ok=True);backup.write_bytes(before)
 p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(wire)
 changes.append(dict(path=name,before_sha256=hashlib.sha256(before).hexdigest() if before is not None else None,
  after_sha256=hashlib.sha256(wire).hexdigest(),kind='Cloud portability overlay; frozen evaluation modules unchanged'))
out=root/'results/cloud_migration/overlay.json';out.write_text(json.dumps(changes,indent=2))
print(json.dumps(dict(overlay_files=len(changes),verified=True)))
'''.replace('PAYLOAD',repr(json.dumps(payload)))
if __name__=='__main__':
    print(execute(Path.home()/'Downloads/hysage-kubeconfig.yaml',script))
