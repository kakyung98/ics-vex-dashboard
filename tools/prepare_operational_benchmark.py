"""Compatibility entry point: verify the retained, frozen v2 real-CVE benchmark."""
from pathlib import Path
import sys,json,hashlib
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.dataset_paths import OPERATIONAL_BENCHMARK

def verify_current():
    folder=OPERATIONAL_BENCHMARK
    manifest=json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
    for name,expected in manifest['files'].items():
        if hashlib.sha256((folder/name).read_bytes()).hexdigest()!=expected:
            raise ValueError('Frozen benchmark fingerprint mismatch: '+name)
    print(json.dumps({'dataset':str(folder),'status':'verified_existing_frozen_dataset','counts':manifest['counts']}))
    return folder

def prepare():return verify_current()
if __name__=='__main__':prepare()
