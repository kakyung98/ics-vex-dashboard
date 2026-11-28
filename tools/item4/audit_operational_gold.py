"""Verify sealed operational Gold, opaque IDs and complete test populations."""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from src.common.runtime.training_progress_io import atomic_json


def audit():
    folder=ROOT/'benchmark/item4_operational_gold_v2'
    manifest=json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
    groups={};seen=set();n=0
    for fold in ('train','evaluation'):
        inp=folder/fold/'inputs.jsonl';lab=folder/fold/'labels.jsonl'
        for path in (inp,lab):
            assert hashlib.sha256(path.read_bytes()).hexdigest()==manifest['artifacts'][str(path.relative_to(folder))]
        inputs=[json.loads(s) for s in inp.read_text(encoding='utf-8').splitlines()]
        labels=[json.loads(s) for s in lab.read_text(encoding='utf-8').splitlines()]
        assert len(inputs)==len(labels)==manifest['counts'][fold]
        groups[fold]=set()
        for row,gold in zip(inputs,labels):
            assert row['id']==gold['id'] and row['packet']['binding']==gold['binding']
            assert re.fullmatch(r'SYN-[0-9a-f]{32}',row['id']) and row['id'] not in seen
            seen.add(row['id']);groups[fold].add(gold['group']);n+=1
            assert set(row)=={'id','packet'}
            serialized=json.dumps(row)
            for forbidden in ('actual_affected','latent_state','label_method','"fault"'):
                assert forbidden not in serialized
            assert row['packet']['binding']['config_baseline']=='cfg-'+row['id']
    assert not groups['train']&groups['evaluation']
    report=dict(passed=True,cases=n,train_groups=len(groups['train']),evaluation_groups=len(groups['evaluation']),
        gold_manifest_sha256=hashlib.sha256((folder/'manifest.json').read_bytes()).hexdigest(),
        checks=['Artifact SHA256','Exact input/label binding','Unique opaque case/config IDs',
            'No latent-state/actual-impact/fault label keys in model inputs','Disjoint vulnerability/product groups'],
        training_note=manifest['training_compatibility'],semantic_accuracy_validated=False)
    atomic_json(folder/'integrity_audit.json',report)
    print(json.dumps(report))


if __name__=='__main__':audit()
