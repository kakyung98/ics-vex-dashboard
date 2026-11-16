from pathlib import Path
import subprocess
import json
import sys
root = Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
root.mkdir(exist_ok=True)
(root/'incoming').mkdir(exist_ok=True)
(root/'logs').mkdir(exist_ok=True)
venv = root/'venv'
if not venv.exists():
    subprocess.run([sys.executable,'-m','venv',str(venv)],check=True)
requirements = '''fastapi==0.115.7
uvicorn==0.34.0
httpx==0.28.1
numpy==2.2.6
scipy==1.15.3
scikit-learn==1.7.2
packaging==26.3
jsonschema==4.26.0
referencing==0.37.0
langgraph==1.2.19
packageurl-python==0.17.6
transformers==5.15.0
peft==0.20.0
bitsandbytes==0.50.0
lm-format-enforcer==0.11.3
pytest==9.1.1
accelerate==1.14.0
safetensors==0.8.0
tokenizers==0.22.2
'''
(root/'requirements.txt').write_text(requirements)
script = '''import subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parent
py=str(root/'venv/bin/python')
subprocess.run([py,'-m','pip','install','torch==2.11.0','--index-url','https://download.pytorch.org/whl/cu128'],check=True)
subprocess.run([py,'-m','pip','install','-r',str(root/'requirements.txt')],check=True)
(root/'environment_ready').write_text('complete')
'''
(root/'install_environment.py').write_text(script)
log=(root/'logs/environment.log').open('wb')
proc=subprocess.Popen([sys.executable,str(root/'install_environment.py')],stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
(root/'environment.pid').write_text(str(proc.pid))
print(json.dumps(dict(root=str(root),install_pid=proc.pid)))
