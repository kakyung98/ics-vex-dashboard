"""Fresh deployed-adapter inference on meaning-preserving text variants."""
import sys
import json
import hashlib
import time
from copy import deepcopy
from pathlib import Path
from datetime import datetime, timezone
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.analysis import exploitation_prerequisites as V2


def main():
    out = ROOT / 'results/item4_goldfree_20261126'
    out.mkdir(exist_ok=True)
    source = json.loads((ROOT/'results/item4_qwen_reference_20261126/manifest.json').read_text(encoding='utf-8'))
    identity = V2.L.identity('exploitation-prerequisites')
    manifest = dict(created_at=datetime.now(timezone.utc).isoformat(), model=identity,
        policy=V2.OP.POLICY, prompt_sha256=V2.digest(V2.SYSTEM),
        transformations=['original','double_spaces','linebreaks'], source_cases=source['cases'],
        scope='18 purposive real CVE descriptions; formatting robustness, not semantic accuracy.')
    (out/'robustness_manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    for case in source['cases']:
        for kind in manifest['transformations']:
            file = out/(case['id']+'__'+kind+'.json')
            if file.exists():continue
            record = deepcopy(case['record'])
            for s in record['sources']:
                if kind=='double_spaces':s['text']=s['text'].replace(' ','  ')
                if kind=='linebreaks':s['text']=s['text'].replace(' ','\n')
                s['text_sha256']=hashlib.sha256(s['text'].encode()).hexdigest()
            traces=[]
            def runner(system,packet,*,role):
                start=time.monotonic()
                try:
                    response=V2.L.generate(system,packet,role=role)
                except Exception as exc:
                    traces.append(dict(error=str(exc),raw=getattr(exc,'raw_output',None),elapsed_seconds=time.monotonic()-start))
                    raise
                traces.append(dict(response=response,elapsed_seconds=time.monotonic()-start))
                return response
            row=dict(cve=case['id'],variant=kind,record=record)
            start=time.monotonic()
            try:row.update(status='validated',artifact=V2.extract(record,runner=runner))
            except Exception as exc:row.update(status='failed',error=str(exc))
            row.update(elapsed_seconds=time.monotonic()-start,trace=traces)
            file.write_text(json.dumps(row,ensure_ascii=False,indent=2),encoding='utf-8')
            atoms=row.get('artifact',{}).get('draft',{}).get('prerequisites',[])
            print(case['id'],kind,row['status'],len(atoms),round(row['elapsed_seconds'],1),flush=True)


if __name__=='__main__':main()
