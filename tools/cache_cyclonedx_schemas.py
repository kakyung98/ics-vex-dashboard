"""Cache official schemas for offline output validation; never sends SBOM data."""
from pathlib import Path
import hashlib,json,requests
ROOT=Path(__file__).resolve().parents[1]
folder=ROOT/'.tools/cyclonedx-schemas';folder.mkdir(parents=True,exist_ok=True)
files=['bom-1.5.schema.json','bom-1.6.schema.json','bom-1.7.schema.json','spdx.schema.json','jsf-0.82.schema.json','cryptography-defs.schema.json']
sources=[]
for name in files:
    path=folder/name;url='https://raw.githubusercontent.com/CycloneDX/specification/master/schema/'+name
    if not path.is_file():
        r=requests.get(url,timeout=45);r.raise_for_status();data=r.json();path.write_text(json.dumps(data),encoding='utf-8')
    sources.append({'file':name,'source':url,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
(folder/'manifest.json').write_text(json.dumps({'sources':sources,'user_data_sent':False},indent=2),encoding='utf-8')
print('Official schemas cached:',len(sources))
