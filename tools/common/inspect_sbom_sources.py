from pathlib import Path
import json, collections
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
R=Path(__file__).resolve().parents[2]
cats=collections.Counter(); missing=[]; n=0
files=list((R/'icsa/csaf').glob('*.json'))
with ThreadPoolExecutor(max_workers=24) as pool:
 docs=list(pool.map(lambda f:(f,json.loads(f.read_bytes())),files))
for f,d in docs:
 leaves=[]
 def walk(bs):
  for b in bs:
   cats[b['category']]+=1
   if b.get('product'):leaves.append(b['product'])
   walk(b.get('branches',[]))
 walk(d.get('product_tree',{}).get('branches',[]))
 if not leaves: missing.append(f.stem)
 n+=len(leaves)
print('CSAF',cats,'leaves',n,'missing',missing)
for f in (R/'data/icsa_sbom_source_html').glob('*.html'):
 soup=BeautifulSoup(f.read_bytes(),'html.parser'); sections=[]
 for h in soup.find_all(['h2','h3','h4']):
  if 'AFFECTED PRODUCTS' not in h.get_text(' ',strip=True).upper():continue
  items=[]
  for x in h.next_siblings:
   if getattr(x,'name',None) in ['h2','h3','h4']:break
   if hasattr(x,'get_text'):
    items.append(x.get_text(' ',strip=True))
  sections.append(' | '.join(items))
 print(f.stem, json.dumps(sections,ensure_ascii=True))
