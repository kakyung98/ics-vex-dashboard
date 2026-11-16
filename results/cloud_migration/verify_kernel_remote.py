from pathlib import Path
import json
import time
import nbformat
from jupyter_client import KernelManager
notebook=Path.home()/'ICS-VEX-H200-20261116.ipynb'
nbformat.validate(nbformat.read(notebook,as_version=4))
manager=KernelManager(kernel_name='ics-vex-h200')
manager.start_kernel(cwd='/home/irteam/data-vol1/ics-vex-migration-20261116/project')
client=manager.client();client.start_channels()
messages=[]
try:
 client.wait_for_ready(timeout=45)
 identity=client.execute("import sys,torch,json; assert torch.cuda.is_available(); print(json.dumps(dict(python=sys.executable,gpu=torch.cuda.get_device_name(0),torch=torch.__version__)))")
 while True:
  message=client.get_iopub_msg(timeout=45)
  if message.get('parent_header',{}).get('msg_id')!=identity:continue
  if message['msg_type']=='error':raise RuntimeError(str(message['content']))
  if message['msg_type']=='stream':messages.append(message['content']['text'])
  if message['msg_type']=='status' and message['content']['execution_state']=='idle':break
finally:
 client.stop_channels();manager.shutdown_kernel(now=True)
result=json.loads(''.join(messages).strip())
assert result['gpu']=='NVIDIA H200' and 'ics-vex-migration-20261116/venv/bin/python' in result['python']
report=Path('/home/irteam/data-vol1/ics-vex-migration-20261116/project/results/cloud_migration/migration_report.json')
data=json.loads(report.read_text());data['jupyter']['actual_kernel_execution']=dict(passed=True,**result)
report.write_text(json.dumps(data,indent=2))
print(json.dumps(data['jupyter']))
