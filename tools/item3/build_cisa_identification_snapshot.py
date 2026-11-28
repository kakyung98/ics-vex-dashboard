"""Reconnect hashed CISA source documents; never read SBOM CVE answers as labels."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from datetime import datetime,timezone
import argparse,hashlib,json,re,shutil

ROOT=Path(__file__).resolve().parents[2]


def digest(raw):return hashlib.sha256(raw).hexdigest()


def product_tree(document):
    products={}
    def walk(branches,vendor='',family=''):
        for branch in branches:
            v=branch.get('name','') if branch.get('category')=='vendor' else vendor
            p=branch.get('name','') if branch.get('category')=='product_name' else family
            leaf=branch.get('product')
            if leaf:products[leaf['product_id']]={'vendor':v,'product':p,'name':leaf.get('name','')}
            walk(branch.get('branches',[]),v,p)
    walk(document.get('product_tree',{}).get('branches',[]))
    return products


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csaf-dir',type=Path,required=True)
    args=parser.parse_args()
    manifest_path=ROOT/'benchmark/icsa-cpe-synthetic sbom/source_manifest.jsonl'
    product_path=ROOT/'benchmark/icsa-cpe-synthetic sbom/source_products.jsonl'
    sources=[json.loads(s) for s in manifest_path.read_text(encoding='utf-8').splitlines()]
    extracted={r['advisory_id']:r for r in map(json.loads,product_path.read_text(encoding='utf-8').splitlines())}
    destination=ROOT/'data/cisa_identification_csaf';destination.mkdir(parents=True,exist_ok=True)

    def one(entry):
        aid=entry['advisory_id'];name=entry.get('source_file') or ''
        csaf='csaf' in name.lower()
        path=args.csaf_dir/(aid+'.json') if csaf else ROOT/'data/icsa_sbom_source_html'/(aid+'.html')
        if not path.is_file():return None,{'advisory_id':aid,'status':'source_unavailable'}
        raw=path.read_bytes();actual=digest(raw)
        if actual!=entry.get('source_file_sha256'):
            return None,{'advisory_id':aid,'status':'source_hash_mismatch','actual_sha256':actual,'expected_sha256':entry.get('source_file_sha256')}
        row={'url':'https://www.cisa.gov/news-events/ics-advisories/'+aid,'source_raw_sha256':actual}
        if csaf:
            document=json.loads(raw);tree=product_tree(document)
            affected={pid for v in document.get('vulnerabilities',[]) for pid in v.get('product_status',{}).get('known_affected',[])}
            leaves=[r for pid,r in tree.items() if pid in affected]
            row.update(source='CISA CSAF',title=document.get('document',{}).get('title',''),
                       cves=sorted({v['cve'] for v in document.get('vulnerabilities',[]) if re.fullmatch(r'CVE-\d{4}-\d{4,}',v.get('cve',''))}),
                       vendors=sorted({r['vendor'] for r in leaves if r['vendor']}),
                       products=sorted({r['product'] for r in leaves if r['product']}),
                       affected_products=sorted({r['name'] for r in leaves if r['name']}),
                       csaf_path=aid+'.json',local_csaf_file='data/cisa_identification_csaf/'+aid+'.json',
                       csaf_sha256=digest(json.dumps(document,sort_keys=True).encode()))
            target=destination/(aid+'.json')
            if target.exists():
                if digest(target.read_bytes())!=actual:raise ValueError('Conflicting local CSAF: '+aid)
            else:shutil.copyfile(path,target)
        else:
            from bs4 import BeautifulSoup
            soup=BeautifulSoup(raw,'html.parser');article=soup.select_one('main article') or soup.select_one('article') or soup.select_one('main')
            if article is None:return None,{'advisory_id':aid,'status':'html_body_unresolved'}
            for element in article.select('script,style,nav,footer'):element.decompose()
            body=article.get_text(' ',strip=True)
            body=re.split(r'\bRelated Advisories\b',body,maxsplit=1,flags=re.I)[0]
            rows=extracted.get(aid,{}).get('source_rows',[])
            row.update(source='CISA HTML',title='',affected_text=body,
                       cves=sorted(set(re.findall(r'\bCVE-\d{4}-\d{4,}\b',body))),
                       vendors=sorted({r.get('vendor','') for r in rows if r.get('vendor')}),
                       products=sorted({r.get('name','') for r in rows if r.get('name')}))
        row['vendor']=row['vendors'][0] if len(row['vendors'])==1 else ''
        return (aid,row),{'advisory_id':aid,'status':'verified','kind':row['source'],'source_sha256':actual}

    records={};audit=[]
    with ThreadPoolExecutor(max_workers=8) as pool:
        for i,(result,check) in enumerate(pool.map(one,sources),1):
            audit.append(check)
            if result:records[result[0]]=result[1]
            if i%500==0:print(f'Checked {i}/{len(sources)} CISA source documents',flush=True)
    raw=(json.dumps(records,ensure_ascii=False,separators=(',',':'))+'\n').encode()
    output=ROOT/'data/cisa_advisories.json';tmp=output.with_suffix('.json.tmp');tmp.write_bytes(raw);tmp.replace(output)
    report={'built_at':datetime.now(timezone.utc).isoformat(),'advisories_in_source_manifest':len(sources),
            'verified_advisories':len(records),'csaf':sum(r['source']=='CISA CSAF' for r in records.values()),
            'html':sum(r['source']=='CISA HTML' for r in records.values()),
            'unresolved_sources':[r for r in audit if r['status']!='verified'],
            'index_sha256':digest(raw),'source_manifest_sha256':digest(manifest_path.read_bytes()),
            'source_product_extraction_sha256':digest(product_path.read_bytes()),
            'retrieval_policy':'Exact vendor/product source relations produce unconfirmed candidates, not installed-version verdicts.',
            'sbom_answers_used_for_index':False}
    (ROOT/'data/cisa_reference_manifest.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False),flush=True)


if __name__=='__main__':main()
