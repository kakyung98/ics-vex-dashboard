"""Fetch scoped #3 MRT and #4 Synthetic GT evidence without credentials."""
from pathlib import Path
import sys,json,hashlib,tarfile,base64
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from tools.common.ncp_api_transport import execute


def main():
    config=ROOT/'hysage-kubeconfig.yaml'
    code='''from pathlib import Path
import json,hashlib,tarfile
w=Path('/home/irteam/data-vol1/ics-vex-migration-20261116/item4-metamorphic-synthetic-20261127');summary={}
for name in ('item3_metamorphic','item3_metamorphic_confirmatory','item3_metamorphic_version_stress','nemotron_evaluation'):
 o=w/name;s=json.loads((o/'status.json').read_text())
 if s.get('state')!='complete':raise ValueError(name+' is incomplete: '+str(s.get('state')))
 summary[name]={p.name:json.loads(p.read_text()) for p in o.glob('*.json') if p.name not in ('inputs.json','gold.json')}
archive=w/'scoped_llm_evaluations.tar.gz'
with tarfile.open(archive,'w:gz') as t:
 for name in summary:t.add(w/name,arcname=name)
 for rel in ('tools/item3/evaluate_identification_metamorphic.py','tools/item4/evaluate_nemotron_metamorphic.py','tools/item4/extract_source_conditions_for_question_links.py','tools/item4/compact_json_grammar.py','src/item4/evaluation/nemotron_source_synthetic.py','src/item4/evaluation/metamorphic_synthetic.py','src/common/runtime/shared_adapter_runtime.py','src/item3/agents/candidate_choice_scoring.py','src/item3/evidence/version_evidence.py','src/item3/matching/product_version_cve_matching.py'):
  t.add(w/rel,arcname='source_snapshot/'+rel)
print(json.dumps(dict(summary=summary,archive=str(archive),bytes=archive.stat().st_size,sha256=hashlib.sha256(archive.read_bytes()).hexdigest())))
'''
    meta=json.loads(execute(config,code,timeout=60));out=ROOT/'results/scoped_llm_evaluations_20261127';out.mkdir(parents=True,exist_ok=True)
    destination=out/'artifacts.tar.gz'
    with destination.open('wb') as stream:
        for offset in range(0,meta['bytes'],524288):
            request='import base64\nwith open('+repr(meta['archive'])+',"rb") as f:\n f.seek('+str(offset)+');print(base64.b64encode(f.read(524288)).decode())'
            stream.write(base64.b64decode(execute(config,request,timeout=30).strip(),validate=True))
    if hashlib.sha256(destination.read_bytes()).hexdigest()!=meta['sha256']:raise ValueError('Archive hash mismatch')
    with tarfile.open(destination) as t:
        for m in t.getmembers():
            if not (out/m.name).resolve().is_relative_to(out.resolve()) or m.issym() or m.islnk():raise ValueError('Unsafe archive member')
        t.extractall(out)
    (out/'delivery.json').write_text(json.dumps({k:v for k,v in meta.items() if k!='summary'},indent=2),encoding='utf-8')
    for name,files in meta['summary'].items():
        for n,value in files.items():(out/name/n).write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(directory=str(out),bytes=meta['bytes'],sha256=meta['sha256'])))


if __name__=='__main__':main()
