from pathlib import Path
import subprocess,json
r=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
log=(r/'logs/api.log').open('ab')
p=subprocess.Popen([str(r/'venv/bin/python'),str(r/'project/tools/ncp_serve.py')],cwd=r/'project',stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
(r/'api.pid').write_text(str(p.pid))
print(json.dumps(dict(api_pid=p.pid,bind='127.0.0.1:18100')))
