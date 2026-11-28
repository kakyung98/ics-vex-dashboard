"""Build a bounded, separately pinned MulVAL population executable on NCP."""
from pathlib import Path
import json,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from tools.common.ncp_api_transport import execute
ROOT=Path(__file__).resolve().parents[2]
SCRIPT='''from pathlib import Path
import difflib,hashlib,json,re,shutil,sys
r=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
sys.path.insert(0,str(r/'project'))
from tools.item4.ncp_operational_runtime import run
source=r/'operational_rootfs/opt/mulval';fork=r/'operational_rootfs/opt/mulval-population'
if not fork.exists():shutil.copytree(source,fork,symlinks=True)
header=fork/'src/attack_graph/attack_graph.h';code=fork/'src/attack_graph/attack_graph.cpp'
old_header=(source/'src/attack_graph/attack_graph.h').read_text()
old_code=(source/'src/attack_graph/attack_graph.cpp').read_text()
new_header=re.sub(r'^#define MAX_RULES [0-9]+$', '#define MAX_RULES 100001',old_header,flags=re.M)
new_code=old_code.replace('rulenum > MAX_RULES','rulenum >= MAX_RULES')
if new_header==old_header or new_code==old_code:raise RuntimeError('Unexpected upstream limit definition; review before modifying')
header.write_text(new_header);code.write_text(new_code)
work=r/'mulval-population-build';work.mkdir(exist_ok=True)
result=run(['make','-C','/opt/mulval-population/src/attack_graph','install'],work,'compile',timeout=120)
patch=''.join(difflib.unified_diff(old_header.splitlines(True),new_header.splitlines(True),fromfile='original/attack_graph.h',tofile='population/attack_graph.h'))
patch+=''.join(difflib.unified_diff(old_code.splitlines(True),new_code.splitlines(True),fromfile='original/attack_graph.cpp',tofile='population/attack_graph.cpp'))
receipt=dict(returncode=result.returncode,original_preserved=True,maximum_rule_number=100000,patch=patch,
 source_sha256={str(p.relative_to(fork)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [header,code]},
 binary_sha256=hashlib.sha256((fork/'bin/attack_graph').read_bytes()).hexdigest(),
 change='rule-array capacity and out-of-bounds guard only; inference rules and semantics unchanged')
(work/'receipt.json').write_text(json.dumps(receipt,indent=2))
print(json.dumps(receipt))
if result.returncode:raise RuntimeError('Population runtime compilation failed')
'''

if __name__=='__main__':
    result=json.loads(execute(ROOT/'hysage-kubeconfig.yaml',SCRIPT,timeout=150))
    out=ROOT/'results/mulval_population_20261118';out.mkdir(parents=True,exist_ok=True)
    (out/'runtime_receipt.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='patch'}))
