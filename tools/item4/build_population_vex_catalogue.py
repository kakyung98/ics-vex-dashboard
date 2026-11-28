"""Compile every fixed-population CVE from local primary CSAF and source spans."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from collections import defaultdict,Counter
import hashlib,json,sqlite3,time
from src.item4.decision import scoped_vex_review as A
from src.item4.decision import population_condition_rules as P
ROOT=Path(__file__).resolve().parents[2];OUT=P.HOME
def products(doc):
    found={}
    def walk(branches,ancestry,pointer):
        for i,b in enumerate(branches):
            chain=ancestry+[(b.get('category',''),b.get('name',''))];ptr=f'{pointer}/{i}'
            if 'product' in b:
                p=b['product'];names=[n for k,n in chain if k in ('product_name','product_family','product_version','product_version_range','vendor')]
                models=[n for k,n in chain if k=='product_name'];vendors=[n for k,n in chain if k=='vendor'];versions=[n for k,n in chain if k in ('product_version','product_version_range')]
                model=' '.join(models);vendor=' '.join(vendors);version=versions[-1] if versions else ''
                if not model:
                    split=p.get('name','').rsplit(':',1);model=split[0];version=split[1] if len(split)==2 else ''
                aliases=list(dict.fromkeys(v for v in [model,(vendor+' '+model).strip(),p.get('name','') if not version else ''] if v))
                found[p['product_id']]=dict(name=p.get('name',''),model=model,aliases=aliases,version_text=version,version_predicate=P.version_predicate(version),product_pointer=ptr+'/product')
            walk(b.get('branches',[]),chain,ptr+'/branches')
    walk(doc.get('product_tree',{}).get('branches',[]),[],'/product_tree/branches')
    def plain(p,pointer):
        if not p.get('product_id'):return
        name=p.get('name','');split=name.rsplit(':',1);model=split[0].strip();version=split[1].strip() if len(split)==2 else ''
        found[p['product_id']]=dict(name=name,model=model,aliases=[model],version_text=version,version_predicate=P.version_predicate(version),product_pointer=pointer)
    tree=doc.get('product_tree',{})
    for i,p in enumerate(tree.get('full_product_names',[])):plain(p,f'/product_tree/full_product_names/{i}')
    for i,r in enumerate(tree.get('relationships',[])):
        if r.get('full_product_name'):plain(r['full_product_name'],f'/product_tree/relationships/{i}/full_product_name')
    return found
def main():
    OUT.mkdir(parents=True,exist_ok=True);population=A.catalogue()['cves'];wanted={c['cve'] for c in population};by_cve=defaultdict(list);documents=[];counts=Counter();start=time.monotonic()
    for path in sorted((ROOT/'icsa/csaf').glob('*.json')):
        raw=path.read_bytes();doc=json.loads(raw.decode('utf-8-sig'));models=products(doc);sha=hashlib.sha256(raw).hexdigest();sid=path.stem
        documents.append(dict(path=str(path.relative_to(ROOT)),sha256=sha))
        urls=[r.get('url') for r in doc.get('document',{}).get('references',[]) if r.get('category')=='self' and r.get('url')]
        url=urls[0] if urls else 'https://www.cisa.gov/news-events/ics-advisories/'+sid
        for vi,vuln in enumerate(doc.get('vulnerabilities',[])):
            cve=vuln.get('cve')
            if cve not in wanted:continue
            for state in ('known_affected','fixed','known_not_affected','under_investigation'):
                for pi,pid in enumerate(vuln.get('product_status',{}).get(state,[])):
                    if pid not in models:counts['dangling_product_status_ids']+=1;continue
                    item=dict(models[pid],key=sid+':'+pid,status=state,document_sha256=sha,source_file=str(path.relative_to(ROOT)),source_url=url,status_pointer=f'/vulnerabilities/{vi}/product_status/{state}/{pi}',cve_pointer=f'/vulnerabilities/{vi}/cve')
                    by_cve[cve].append(item);counts['source_product_status_rows']+=1
    target=OUT/'catalog.sqlite3';stage=OUT/'catalog.building.sqlite3'
    if stage.exists():raise ValueError('An unfinished build already exists; inspect it instead of overwriting')
    with sqlite3.connect(stage) as db:
        db.execute('CREATE TABLE records(cve TEXT PRIMARY KEY,payload TEXT NOT NULL,sha256 TEXT NOT NULL)')
        ledger=[]
        for i,item in enumerate(population):
            cve=item['cve'];record=A.detail(cve)
            for source in record['sources']:
                if hashlib.sha256(source['text'].encode()).hexdigest()!=source['text_sha256']:raise ValueError('Source text integrity failed: '+cve)
            if not record['sources']:
                record['sources']=[dict(id='missing:'+cve,text='',text_sha256=hashlib.sha256(b'').hexdigest(),url='https://nvd.nist.gov/vuln/detail/'+cve,product_keys=[],subject_ambiguous=True)]
            compiled=P.compile_paths(record)
            row=dict(cve=cve,products=by_cve[cve],sources=record['sources'],compiled=compiled,original_record_digest=record['record_digest'],identity_unresolved=record.get('identity_ambiguous',False) or record.get('original_nvd_status')=='Rejected',source_backing='primary_csaf' if by_cve[cve] else 'cve_description_without_csaf_status')
            row['sha256']=P.digest(row);raw=json.dumps(row,ensure_ascii=False,separators=(',',':'));db.execute('INSERT INTO records VALUES (?,?,?)',(cve,raw,P.digest(row)))
            counts['cves']+=1;counts['with_primary_status' if row['products'] else 'without_primary_status']+=1
            counts['with_translated_operational_questions' if compiled['questions'] else 'without_translated_operational_questions']+=1
            counts['translated_operational_questions']+=len(compiled['questions']);counts['untranslated_source_gaps']+=len(compiled['gaps'])
            ledger.append(dict(cve=cve,sha256=row['sha256'],product_rows=len(row['products']),operating_questions=len(compiled['questions']),unknown_conditions=len(compiled['gaps'])))
            if (i+1)%1000==0:db.commit();print('Compiled CVEs:',i+1,flush=True)
        db.commit()
    db.close()
    if {r['cve'] for r in ledger}!=wanted or len(ledger)!=12418:raise ValueError('Full population membership failed')
    manifest=dict(version=P.VERSION,population_count=12418,population_sha256=P.digest(sorted(wanted)),source_documents=documents,counts=dict(counts),elapsed_seconds=time.monotonic()-start,not_independent_semantic_validation=True,compiler_policy='Unknown operands and missing status references are retained; no LLM or CVSS/CWE truth mapping.',records=ledger)
    manifest['sha256']=P.digest(manifest)
    if target.exists():raise ValueError('An existing catalogue must be versioned; refusing overwrite')
    stage.replace(target);(OUT/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8');print(json.dumps(dict(counts=dict(counts),elapsed=manifest['elapsed_seconds'])))
if __name__=='__main__':main()
