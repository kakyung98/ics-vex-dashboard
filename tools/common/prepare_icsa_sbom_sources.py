"""Cache original HTML for advisories without CSAF, plus CycloneDX 1.7 schemas."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import json, urllib.request, hashlib
ROOT=Path(__file__).resolve().parents[2]
CACHE=ROOT/'data/icsa_sbom_source_html'; CACHE.mkdir(exist_ok=True)
a=json.loads((ROOT/'data/cisa_advisories.json').read_bytes())
def fetch(item):
 aid,r=item
 if (ROOT/'icsa/csaf'/f'{aid}.json').exists(): return None
 p=CACHE/f'{aid}.html'
 try:
  if not p.exists():
   req=urllib.request.Request(r['url'],headers={'User-Agent':'Mozilla/5.0'})
   p.write_bytes(urllib.request.urlopen(req,timeout=30).read())
  return {'advisory_id':aid,'url':r['url'],'file':str(p.relative_to(ROOT)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
 except Exception as e: return {'advisory_id':aid,'url':r['url'],'error':str(e)}
with ThreadPoolExecutor(max_workers=8) as pool: records=[r for r in pool.map(fetch,a.items()) if r]
(CACHE/'manifest.json').write_text(json.dumps(records,indent=2),encoding='utf8')
schema=ROOT/'data/standards/cyclonedx-1.7';schema.mkdir(exist_ok=True)
for name in ['bom-1.7.schema.json','spdx.schema.json','jsf-0.82.schema.json']:
 p=schema/name
 if not p.exists(): p.write_bytes(urllib.request.urlopen('https://raw.githubusercontent.com/CycloneDX/specification/1.7/schema/'+name,timeout=30).read())
print(json.dumps({'downloaded':sum('error' not in r for r in records),'errors':[r for r in records if 'error' in r]}))
