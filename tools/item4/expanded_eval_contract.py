"""Use the executed snapshot, never a concurrently edited workspace validator."""
import importlib.util,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'results/item4_goldfree_expanded_20261126'
MEMBER='src/item4/analysis/asset_operating_question_generation.py'


def frozen_v3():
    target=OUT/'source_snapshot'/MEMBER
    if not target.exists():
        target.parent.mkdir(parents=True,exist_ok=True)
        with tarfile.open(OUT/'source_inputs.tar.gz','r:gz') as t:target.write_bytes(t.extractfile(MEMBER).read())
    spec=importlib.util.spec_from_file_location('expanded_frozen_v3',target)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def baseline_questions(payload):
    result={}
    asset=(payload.get('asset_classification',{}).get('asset') or {}).get('name') or 'asset'
    for key,atom in payload['atoms'].items():
        row=dict(positive_fact=atom['positive_fact'],question='For this '+asset+', is the following true: '+atom['positive_fact'],check=atom['observation']['check'],record_type=atom['observation']['record_type'])
        properties=payload['schema']['properties']['questions']['properties'][key]['properties']
        if 'confidence' in properties:row['confidence']=0  # unassessed, not a calibrated probability
        result[key]=row
    return result


def content_questions(questions):
    return {key:{k:value[k] for k in ('positive_fact','question','check','record_type') if k in value} for key,value in questions.items()}
