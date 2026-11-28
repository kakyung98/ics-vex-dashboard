"""Launch and collect expanded H200 run without replacing the pilot."""
import sys,json,tarfile,hashlib,base64,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from tools.common.ncp_api_transport import execute,upload_file
from tools.item4 import run_goldfree_h200 as transport
OUT=ROOT/'results/item4_goldfree_expanded_20261126'
REMOTE='/home/irteam/data-vol1/ics-vex-migration-20261116/item4-goldfree-expanded-20261126'
CONFIG=ROOT/'hysage-kubeconfig.yaml'


def launch():
    archive=OUT/'source_inputs.tar.gz';tok=ROOT/'models/precision_roles_qwen25_14b_v1'
    with tarfile.open(archive,'w:gz') as t:
        for p in (ROOT/'src').rglob('*'):
            if p.suffix in ('.py','.json'):t.add(p,arcname=p.relative_to(ROOT).as_posix())
        t.add(ROOT/'tools/item4/expanded_h200_worker.py',arcname='tools/item4/expanded_h200_worker.py')
        t.add(OUT/'inputs.json',arcname='inputs.json')
        for n in ['tokenizer.json','tokenizer_config.json','chat_template.jinja','special_tokens_map.json','added_tokens.json','merges.txt','vocab.json']:
            if (tok/n).exists():t.add(tok/n,arcname='tokenizer/'+n)
    upload_file(CONFIG,archive,REMOTE+'.tar.gz')
    code=f'''from pathlib import Path
import tarfile,subprocess,json,os
w=Path({REMOTE!r})
if (w/'worker.pid').exists():raise ValueError('Run exists; inspect instead of overwriting')
w.mkdir(exist_ok=True)
with tarfile.open({(REMOTE+'.tar.gz')!r}) as t:
 for m in t.getmembers():
  if not (w/m.name).resolve().is_relative_to(w.resolve()) or m.issym() or m.islnk():raise ValueError('Unsafe archive')
 t.extractall(w)
log=(w/'worker.log').open('w')
p=subprocess.Popen([str(w.parent/'venv/bin/python'),str(w/'tools/item4/expanded_h200_worker.py')],cwd=w,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,env=dict(os.environ,TOKENIZERS_PARALLELISM='false',HF_HUB_OFFLINE='1'))
(w/'worker.pid').write_text(str(p.pid));print(json.dumps(dict(pid=p.pid,run=str(w))))'''
    receipt=json.loads(execute(CONFIG,code,timeout=30));(OUT/'launch.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8');print(json.dumps(receipt))


if __name__=='__main__':
    if len(sys.argv)!=2 or sys.argv[1] not in ('launch','status','collect'):raise SystemExit('launch|status|collect')
    if sys.argv[1]=='launch':launch()
    else:
        transport.OUT=OUT;transport.REMOTE=REMOTE
        getattr(transport,sys.argv[1])()
