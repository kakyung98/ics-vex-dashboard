"""Published flags from the newest locally collected CSAF snapshot."""
from collections import Counter
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]


def snapshot_directory():
    folders=sorted(p for p in (ROOT/'data/public_sbom').glob('*/csaf') if p.is_dir())
    return folders[-1] if folders else None


@lru_cache(maxsize=2)
def _collect(folder):
    directory=Path(folder);pairs=[];labels=Counter();vendors=Counter();advisories=set();scanned=0;inventory=[];errors=[]
    records=json.loads((ROOT/'data/cisa_advisories.json').read_text(encoding='utf-8'))
    for path in sorted(directory.glob('*.json')):
        try:raw=path.read_bytes();document=json.loads(raw)
        except (OSError,ValueError) as exc:errors.append({'file':path.name,'error':str(exc)});continue
        scanned+=1;inventory.append((path.name,hashlib.sha256(raw).hexdigest()))
        aid=path.stem;record=records.get(aid,{})
        title=document.get('document',{}).get('title') or record.get('title') or aid
        vendor=record.get('vendor') or 'Unknown'
        for vulnerability in document.get('vulnerabilities',[]):
            cve=vulnerability.get('cve');flags=vulnerability.get('flags',[])
            if not cve or not flags:continue
            names=[flag['label'] for flag in flags if isinstance(flag,dict) and flag.get('label')]
            if not names:continue
            from src.operational_versions import products
            tree=products(document);scoped=[]
            for flag in flags:
                for pid in flag.get('product_ids',[]):
                    product=tree.get(pid,{})
                    scoped.append({'product_id':pid,'product':product.get('product') or product.get('name') or pid,
                        'version':product.get('version',''),'label':flag.get('label')})
            advisories.add(aid);labels.update(names);vendors[vendor]+=1
            pairs.append({'advisory':aid,'cve':cve,'title':title,'justification':names[0],
                'labels':names,'flags':flags,'url':record.get('url'),'vendor':vendor,'products':scoped,
                'csaf_url':('https://raw.githubusercontent.com/cisagov/CSAF/develop/'+record['csaf_path']) if record.get('csaf_path') else None,
                'csaf_local':'published_csaf/'+aid+'.json',
                'source_sha256':hashlib.sha256(raw).hexdigest(),
                'release':document.get('document',{}).get('tracking',{}).get('current_release_date'),
                'product_status':vulnerability.get('product_status',{}),'authority':'published vendor/CISA assertion; not benchmark truth'})
    return {'advisories':len(advisories),'pairs':len(pairs),'label_instances':sum(labels.values()),
        'by_justification':dict(labels),'by_vendor':dict(vendors),'rows':sorted(pairs,key=lambda r:(r['cve'],r['advisory'])),
        'documents_scanned':scanned,'source_snapshot':directory.relative_to(ROOT).as_posix(),
        'snapshot_fingerprint':hashlib.sha256(json.dumps(inventory,sort_keys=True).encode()).hexdigest(),
        'collection_errors':errors,'available':True,
        'note':'Explicit vulnerabilities[].flags in the locally collected CSAF snapshot. Counts are recomputed from files; assertions are separate from synthetic gold and system predictions.'}


def collect():
    directory=snapshot_directory()
    if not directory:return {'advisories':0,'pairs':0,'label_instances':0,'by_justification':{},'by_vendor':{},
        'rows':[],'available':False,'documents_scanned':0,'source_snapshot':None,'note':'No local CSAF snapshot is available.'}
    return _collect(str(directory))


def evidence(advisory):
    if not re.fullmatch(r'icsa-[a-z0-9-]+',advisory):raise ValueError('Invalid advisory ID')
    root=snapshot_directory()
    if root is None or not (root/(advisory+'.json')).is_file():raise FileNotFoundError(advisory)
    return json.loads((root/(advisory+'.json')).read_text(encoding='utf-8'))
