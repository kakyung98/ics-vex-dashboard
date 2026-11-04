"""Audit real row/unique counts, input/group leakage and preservation of old holdouts."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


def audit(data, previous=None):
    data=Path(data)
    manifest=json.loads((data/'manifest.json').read_text(encoding='utf-8'))
    rows={s:[json.loads(l) for l in (data/f'{s}.jsonl').read_text(encoding='utf-8').splitlines()]
          for s in ('train','val','test')}
    result={'status':'passed','splits':{},'overlaps':{},'shared_constants':['L2 empty name','L3 NOASSERTION'],
            'rationale_status':manifest.get('size_rationale',{}).get('status')}
    groups={}; inputs={}
    for split,items in rows.items():
        if len({r['id'] for r in items})!=len(items):raise ValueError('Duplicate IDs')
        actual=hashlib.sha256((data/f'{split}.jsonl').read_bytes()).hexdigest()
        if actual!=manifest['splits'][split]['sha256']:raise ValueError('Dataset hash mismatch')
        result['splits'][split]={}; groups[split]={}; inputs[split]={}
        for task in ('L2','L3','L4'):
            selected=[r for r in items if r['task']==task]
            if len(selected)!=manifest['splits'][split]['per_task']:raise ValueError('Size mismatch')
            unique={json.dumps(r['input'],sort_keys=True,ensure_ascii=False) for r in selected}
            labels=Counter(r['gold']['status'] for r in selected)
            group=lambda r: (re.sub('[^a-z0-9]','',r['group'][1].lower()) if task!='L3'
                              else re.sub(r'^[vV](?=\d)','',r['group'].strip()).lower())
            groups[split][task]={group(r) for r in selected}
            if task=='L2':
                inputs[split][task]={re.sub('[^a-z0-9]','',r['input']['name'].lower()) for r in selected if r['input']['name']}
            elif task=='L3':
                inputs[split][task]={r['input']['raw_version'].strip() for r in selected
                                    if r['input']['raw_version'].strip().lower()!='noassertion'}
            else:inputs[split][task]=unique
            result['splits'][split][task]={'rows':len(selected),'unique_inputs':len(unique),
                'unique_groups':len(groups[split][task]),'repeated_input_rows':len(selected)-len(unique),
                'labels':dict(labels)}
    for a,b in (('train','val'),('train','test'),('val','test')):
        for task in ('L2','L3','L4'):
            overlap={'group':len(groups[a][task]&groups[b][task]),
                     'nonconstant_input':len(inputs[a][task]&inputs[b][task])}
            result['overlaps'][f'{a}/{b}/{task}']=overlap
            if any(overlap.values()):raise ValueError(f'Leakage: {a}/{b}/{task}: {overlap}')
    if previous:
        preserved={}
        for split in rows:
            old=[json.loads(l) for l in (Path(previous)/f'{split}.jsonl').read_text(encoding='utf-8').splitlines()]
            current={r['id']:r for r in rows[split]}
            if not all(current.get(r['id'])==r for r in old):raise ValueError('An old row moved or changed')
            preserved[split]=len(old)
        result['preserved_previous_rows']=preserved
    # These are nested example IDs, not independent duplicated data. Validation/test stay fixed.
    grid={}
    for size in manifest.get('size_rationale',{}).get('training_grid',[]):
        if size>manifest['splits']['train']['per_task']:continue
        grid[str(size)]={task:[r['id'] for r in rows['train'] if r['task']==task][:size]
                         for task in ('L2','L3','L4')}
    (data/'learning_curve_subsets.json').write_text(json.dumps(grid,indent=2),encoding='utf-8')
    (data/'audit.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('data',type=Path);p.add_argument('--previous',type=Path)
    a=p.parse_args();print(json.dumps(audit(a.data,a.previous),indent=2))
