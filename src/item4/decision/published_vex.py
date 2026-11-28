"""Published flags from the newest locally collected CSAF snapshot."""
from collections import Counter
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[3]


def snapshot_directory():
    folders=sorted(p for p in (ROOT/'data/public_sbom').glob('*/csaf') if p.is_dir())
    if folders:return folders[-1]
    # The collected full corpus was moved during workspace cleanup.
    relocated=ROOT/'icsa/csaf'
    return relocated if relocated.is_dir() and any(relocated.glob('*.json')) else None


@lru_cache(maxsize=2)
def _collect(folder):
    directory=Path(folder);pairs=[];labels=Counter();vendors=Counter();advisories=set();scanned=0;inventory=[];errors=[]
    metadata=ROOT/'data/cisa_advisories.json'
    records=json.loads(metadata.read_text(encoding='utf-8')) if metadata.is_file() else {}
    for path in sorted(directory.glob('*.json')):
        try:raw=path.read_bytes();document=json.loads(raw)
        except (OSError,ValueError) as exc:errors.append({'file':path.name,'error':str(exc)});continue
        scanned+=1;inventory.append((path.name,hashlib.sha256(raw).hexdigest()))
        aid=path.stem;record=records.get(aid,{})
        title=document.get('document',{}).get('title') or record.get('title') or aid
        references=document.get('document',{}).get('references',[])
        urls=[r['url'] for r in references if isinstance(r,dict) and isinstance(r.get('url'),str)]
        advisory_url=record.get('url') or next((url for url in urls if re.match(r'https://(?:www\.)?cisa.gov/(?:news-events/ics-advisories|uscert/ics/advisories)/',url)),None)
        from src.item4.assets.installed_version_evidence import products
        tree=products(document)
        for vulnerability in document.get('vulnerabilities',[]):
            cve=vulnerability.get('cve');flags=vulnerability.get('flags',[])
            if not cve or not flags:continue
            names=[flag['label'] for flag in flags if isinstance(flag,dict) and flag.get('label')]
            if not names:continue
            scoped=[];product_vendors=set()
            for flag in flags:
                if not isinstance(flag,dict) or not flag.get('label'):continue
                for pid in flag.get('product_ids',[]):
                    product=tree.get(pid,{})
                    if product.get('vendor'):product_vendors.add(product['vendor'])
                    scoped.append({'product_id':pid,'product':product.get('product') or product.get('name') or pid,
                        'version':product.get('version',''),'label':flag.get('label')})
            vendor=record.get('vendor') or ', '.join(sorted(product_vendors)) or 'Unknown'
            advisories.add(aid);labels.update(names);vendors[vendor]+=1
            pairs.append({'advisory':aid,'cve':cve,'title':title,'justification':names[0],
                'labels':names,'flags':flags,'url':advisory_url,'vendor':vendor,'products':scoped,
                'csaf_url':('https://raw.githubusercontent.com/cisagov/CSAF/develop/'+record['csaf_path']) if record.get('csaf_path') else next((r['url'] for r in document.get('document',{}).get('references',[]) if isinstance(r,dict) and str(r.get('url','')).startswith('https://raw.githubusercontent.com/cisagov/CSAF/')),None),
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
