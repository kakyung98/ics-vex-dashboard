"""Freeze actual public downloads, independently of potentially stale index hashes."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.request import urlopen, Request
import hashlib
import json
import time

ROOT = Path('C:/ICS-VEX')
OUT = ROOT/'results/item4_question_cluster_rebuild_20261125/public_source'
BASE = 'https://kakyung98.github.io/ics-vex-dashboard/'

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    documents = OUT/'documents'; documents.mkdir(exist_ok=True)
    raw = urlopen(BASE+'sbom_index.json', timeout=30).read()
    (OUT/'public_index.json').write_bytes(raw)
    assets = json.loads(raw)['assets']
    assert len({a['file'] for a in assets}) == len(assets)
    def fetch(a):
        name = a['file']
        assert Path(name).name == name and name.endswith('.json')
        path = documents/name
        error = None
        for attempt in range(4):
            try:
                payload = path.read_bytes() if path.exists() else urlopen(
                    Request(BASE+'reverse_sbom/'+name, headers={'User-Agent':'ICS-VEX-dataset-rebuild'}), timeout=35).read()
                bom = json.loads(payload)
                assert bom['bomFormat'] == 'CycloneDX'
                if not path.exists(): path.write_bytes(payload)
                actual = hashlib.sha256(payload).hexdigest()
                return dict(file=name,asset_id=a['asset_id'],url=BASE+'reverse_sbom/'+name,
                    sha256=actual,index_sha256=a.get('sbom_sha256'),
                    index_hash_matches=actual==a.get('sbom_sha256'), bytes=len(payload))
            except Exception as exc:
                error = repr(exc)
                if attempt < 3: time.sleep(attempt+1)
        raise RuntimeError(name+': '+str(error))
    results=[]
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures={pool.submit(fetch,a):a for a in assets}
        for future in as_completed(futures):
            results.append(future.result())
            if len(results)%400 == 0: print('Downloaded',len(results),'/',len(assets),flush=True)
    results.sort(key=lambda r:r['file'])
    manifest=dict(source_url=BASE,public_index_sha256=hashlib.sha256(raw).hexdigest(),
        downloaded=len(results),index_hash_mismatches=sum(not r['index_hash_matches'] for r in results),
        policy='Actual public download bytes are authoritative; stale index metadata is not substituted.',files=results)
    (OUT/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Complete',manifest['downloaded'],'index hash mismatches',manifest['index_hash_mismatches'],flush=True)

if __name__=='__main__': main()
