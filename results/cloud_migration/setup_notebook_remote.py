from pathlib import Path
import subprocess
import json
r=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
py=str(r/'venv/bin/python')
subprocess.run([py,'-m','pip','install','ipykernel==6.29.5'],check=True)
subprocess.run([py,'-m','ipykernel','install','--user','--name','ics-vex-h200','--display-name','ICS-VEX (H200)'],check=True)
project=r/'project'
shortcut=Path.home()/'ICS-VEX-NCP-20261116'
if not shortcut.exists():shortcut.symlink_to(project,target_is_directory=True)
path=Path.home()/'ICS-VEX-H200-20261116.ipynb'
if path.exists():raise FileExistsError('Existing notebook preserved: '+str(path))
notebook=dict(nbformat=4,nbformat_minor=5,metadata=dict(kernelspec=dict(display_name='ICS-VEX (H200)',language='python',name='ics-vex-h200'),language_info=dict(name='python',version='3.11.9')),
 cells=[dict(id='overview',cell_type='markdown',metadata={},source=['# ICS-VEX · H200\n','이전된 코드·데이터·모델·평가 결과를 사용합니다. 커널은 **ICS-VEX (H200)** 입니다.\n','프로젝트: `/home/irteam/data-vol1/ics-vex-migration-20261116/project`\n','웹 화면은 PC의 클라우드 연결이 실행 중일 때 http://127.0.0.1:18100/precision.html 에서 열립니다.\n','기존 정밀도는 합성 평가 범위이며, 실제 설비 영향 정밀도는 미측정입니다.']),
 dict(id='environment',cell_type='code',metadata={},execution_count=None,outputs=[],source=[
 'from pathlib import Path\n','import os, sys, json, urllib.request\n','import torch\n',
 'PROJECT = Path("/home/irteam/data-vol1/ics-vex-migration-20261116/project")\n',
 'os.chdir(PROJECT)\n','sys.path.insert(0, str(PROJECT))\n',
 'print("Project:", PROJECT)\n','print("Python:", sys.executable)\n',
 'print("GPU:", torch.cuda.get_device_name(0))\n','print("PyTorch:", torch.__version__)\n']),
 dict(id='health',cell_type='code',metadata={},execution_count=None,outputs=[],source=[
 'with urllib.request.urlopen("http://127.0.0.1:18100/api/health") as response:\n','    print(json.load(response))\n',
 'report = json.loads((PROJECT / "results/cloud_migration/migration_report.json").read_text())\n',
 'print("Migrated:", report["completed"])\n','print("Tests passed:", report["pytest"]["passed"])\n'])])
path.write_text(json.dumps(notebook,ensure_ascii=False,indent=2),encoding='utf-8')
report=project/'results/cloud_migration/migration_report.json'
data=json.loads(report.read_text());data['jupyter']=dict(kernel='ics-vex-h200',display_name='ICS-VEX (H200)',notebook=str(path),project_shortcut=str(shortcut))
report.write_text(json.dumps(data,indent=2))
(r/'environment-lock.txt').write_text(subprocess.check_output([py,'-m','pip','freeze'],text=True))
print(json.dumps(data['jupyter']))
