"""Build CycloneDX 1.7 product collections from advisories, without a CPE gate."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import argparse, collections, hashlib, json, re, shutil, uuid
from jsonschema import Draft7Validator, RefResolver, FormatChecker
from tools.common.icsa_advisory_products import extract, digest
from tools.common.icsa_reviewed_product_overrides import apply_review_policy

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'benchmark/icsa-cpe-synthetic sbom'
SCHEMA = ROOT / 'data/standards/cyclonedx-1.7'
WORKBOOK = ROOT / 'SBOM 데이터필드 정의-CycloneDX.xlsx'
DATASET = 'icsa-advisory-products-sbom-v2'

def encoded(v): return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf8')
def formatted(v):
    # Keep presentation bytes separate from canonical evidence digests.
    return (json.dumps(v, ensure_ascii=False, indent=2) + '\n').encode('utf8')

def write(p,v):
    # Publish complete files atomically; readers never see a truncated JSON BOM.
    temporary=p.with_name(p.name+'.'+uuid.uuid4().hex+'.tmp')
    try:
        temporary.write_bytes(formatted(v));temporary.replace(p)
    finally:
        if temporary.exists():temporary.unlink()
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()
def props(d): return [{'name':k,'value':str(v)} for k,v in d.items()]

def org(name='unknown'):
    return {'name':name or 'unknown','address':{k:'unknown' for k in ('country','region','locality')},
            'contact':[{'name':'unknown','phone':'unknown'}]}

def base_component(name,version,ref,vendor='unknown',kind='application'):
    return {'type':kind,'bom-ref':ref,'name':name,'version':version or 'unknown','description':'unknown',
            'publisher':'unknown','manufacturer':org(vendor),'supplier':org(),
            'tags':['synthetic','advisory-product-candidate'],'licenses':[{'license':{'name':'unknown'}}],
            'copyright':'unknown','properties':props({'dataset:unknown-fields':'scope,purl,cpe,hashes,manufacturer.contact.email,supplier.contact.email',
                                                    'dataset:installed-version':'unknown'})}

def make_component(aid,row,url):
    helper=row.get('helpers',{}); cpe=helper.get('cpe')
    kind={'a':'application','o':'operating-system','h':'device'}.get(cpe.split(':')[2] if cpe and len(cpe.split(':'))>2 else '', 'application')
    c=base_component(row['name'],row['version'],'product-'+digest({'advisory':aid,'row':row}),row.get('vendor'),kind)
    c['description']=row['source_label']
    c['externalReferences']=[{'type':'advisories','url':url,'comment':row['source_kind']}] if url else []
    for field in ('cpe','purl'):
        if helper.get(field): c[field]=helper[field]
    c['properties']+=props({'dataset:source-kind':row['source_kind'],'dataset:source-label':row['source_label'],
        'dataset:source-product-id':row.get('source_product_id') or 'unknown',
        'dataset:source-version-expression':row.get('source_version_expression',row['version']),
        'dataset:source-row-sha256':digest(row),'dataset:version-semantics':'source expression; not an installed release',
        'dataset:type-basis':'source CPE' if cpe else 'CycloneDX default application; exact type unknown',
        'dataset:parse-review-required':str(row.get('parse_review_required',False)).lower(),'dataset:deployment-verified':'false'})
    return c

def build_document(aid,record,csaf,now):
    rows,statements,status=extract(aid,record,csaf)
    rows=list({digest(r):r for r in rows}.values())
    components=[make_component(aid,r,record.get('url')) for r in rows]
    by_pid=collections.defaultdict(list)
    for r,c in zip(rows,components):
        if r.get('source_product_id'): by_pid[r['source_product_id']].append(c['bom-ref'])
    notes='\n'.join(n.get('text','') for n in (csaf or {}).get('document',{}).get('notes',[])) or record.get('affected_text','')
    conflict=bool(re.search(r'do not (?:impact|affect)|not affected|remov(?:e|ing).*vulnerability notice',notes,re.I))
    ids=[c if isinstance(c,str) else c.get('id') or c.get('cve') or c.get('cve_id') for c in record.get('cves',[])]
    source_vulns={v.get('cve'):v for v in (csaf or {}).get('vulnerabilities',[])}
    vulns=[]; links=[]
    for cve in dict.fromkeys(ids):
        statuses=source_vulns.get(cve,{}).get('product_status',{})
        refs=sorted({ref for pid in statuses.get('known_affected',[]) for ref in by_pid.get(pid,[])})
        link_status='source-conflict-review' if conflict else ('source-explicit' if refs else 'unknown')
        v={'id':cve,'source':{'name':'CISA','url':record['url']},
           'properties':props({'dataset:product-link-status':link_status,'dataset:source-product-status':json.dumps(statuses,sort_keys=True)})}
        if refs and not conflict: v['affects']=[{'ref':ref} for ref in refs]
        vulns.append(v)
        links.append({'advisory_id':aid,'cve':cve,'source_product_status':statuses,
                      'component_refs':refs if not conflict else [],'source_conflict':conflict,'mapping_status':link_status})
    root=base_component(record.get('title') or aid,'unknown','collection:'+aid,kind='data')
    root['description']='Synthetic advisory product collection; alternatives, not one verified installation.'
    root['externalReferences']=[{'type':'advisories','url':record['url'],'comment':'Source advisory'}]
    doc={'$schema':'https://cyclonedx.org/schema/bom-1.7.schema.json','bomFormat':'CycloneDX','specVersion':'1.7',
         'serialNumber':'urn:uuid:'+str(uuid.uuid5(uuid.NAMESPACE_URL,DATASET+':'+aid)),'version':1,
         'properties':props({'SBOM_CREATION_DATE':now.strftime('%Y-%m-%d %H:%M:%S'),'SBOM_MODIFY_DATE':now.strftime('%Y-%m-%d %H:%M:%S'),
            'dataset:id':DATASET,'dataset:advisory-id':aid,'dataset:synthetic-inventory':'true','dataset:deployment-verified':'false',
            'dataset:source-status':status,'dataset:source-conflict-review':str(conflict).lower(),'dataset:source-record-sha256':digest(record),
            'dataset:unknown-fields':'distributionConstraints.tlp,dependencies,metadata.manufacturer.contact.email',
            'dataset:evaluation-role':'Separate export; not item-3 evaluation input or Gold','dataset:source-notes':notes}),
         'metadata':{'timestamp':now.isoformat().replace('+00:00','Z'),'lifecycles':[{'name':'unknown'}],'manufacturer':org(),
            'tools':{'components':[{'type':'application','bom-ref':'tool:icsa-advisory-sbom-v2','name':'build_icsa_cpe_sbom.py','version':'2',
                       'publisher':'unknown','description':'Advisory product/version extraction; no CPE membership gate','externalReferences':[]}]},
            'component':root},'components':components,'vulnerabilities':vulns,
         'externalReferences':[{'type':'advisories','url':record['url'],'comment':'Source advisory'}]}
    review={'advisory_id':aid,'status':status,'component_count':len(components),'source_rows':rows,'affected_product_statements':statements,
            'source_conflict_review':conflict,'source_error':record.get('error'),
            'structured_product_names':record.get('products',[]),'structured_affected_products':record.get('affected_products',[])}
    doc=apply_review_policy(doc,aid)
    review['status']=next((p['value'] for p in doc['properties'] if p['name']=='dataset:source-status'),review['status'])
    return doc,review,links

def validator():
    schema=json.loads((SCHEMA/'bom-1.7.schema.json').read_bytes())
    store={url:json.loads(p.read_bytes()) for p in SCHEMA.glob('*.json') for url in [p.name,'http://cyclonedx.org/schema/'+p.name,'https://cyclonedx.org/schema/'+p.name]}
    return Draft7Validator(schema,resolver=RefResolver(SCHEMA.as_uri()+'/',schema,store=store),format_checker=FormatChecker())

def workbook_mapping():
    import openpyxl
    book=openpyxl.load_workbook(WORKBOOK,data_only=True,read_only=True); definitions=[]
    for sheet in book:
        parents={}
        for n,values in enumerate(sheet.values,1):
            if n<3: continue
            for level,cell in enumerate(values[:5]):
                if cell is not None:
                    parents={k:v for k,v in parents.items() if k<level};parents[level]=str(cell)
                    definitions.append({'sheet':sheet.title,'row':n,'path':'.'.join(parents[k] for k in sorted(parents)),
                                        'description':values[5],'example':str(values[6]) if values[6] is not None else None})
    book.close()
    return {'workbook':WORKBOOK.name,'sha256':sha(WORKBOOK),'definitions':definitions,
        'unknown_policy':'unknown for unconstrained strings; constrained/absent evidence fields omitted and listed in properties',
        'exceptions':{'scope':'enum; unknown in properties','cpe,purl':'Only source supplied identifiers',
            'hashes':'No component binaries: no fabricated hashes','licenses.license.id':'Use license.name=unknown, not a false SPDX ID',
            'contact.email':'unknown is not an email: omitted with unknown marker','dependencies':'No source dependency graph: unknown in properties',
            'distributionConstraints.tlp':'unknown not in enum: unknown in properties','metadata.component':'Advisory product collection of type data',
            'metadata.tools':'Actual generator name and version'}}

def build(out=OUT):
    marker=out/'manifest.json'
    if marker.is_file() and json.loads(marker.read_bytes()).get('dataset_id')=='icsa-advisory-products-sbom-v3':
        raise FileExistsError('Preserve the active CPE-enriched corpus; use a fresh output directory.')
    print('Preparing output and loading advisory records',flush=True)
    out.mkdir(parents=True,exist_ok=True);(out/'sbom').mkdir(exist_ok=True)
    old=out/'icsa-cpe-sbom-v1.zip'
    if old.exists():
        backup_dir=ROOT/'results/icsa_sbom_v1_archive_20261118';backup_dir.mkdir(exist_ok=True);backup=backup_dir/old.name
        if not backup.exists(): shutil.copy2(old,backup)
        assert sha(old)==sha(backup),'Prior export must be preserved before replacement'
        old.unlink()
    raw=json.loads((ROOT/'data/cisa_advisories.json').read_bytes());now=datetime.now(timezone.utc).replace(microsecond=0)
    print(f'Loaded {len(raw)} advisory records',flush=True)
    index=[]; reviews=[]; links=[];counts=collections.Counter();declared=set(); check=validator()
    def load(item):
        aid,record=item;p=ROOT/'icsa/csaf'/(aid+'.json')
        return aid,record,json.loads(p.read_bytes()) if p.exists() else None
    writes=[]
    writers=ThreadPoolExecutor(max_workers=12)
    with ThreadPoolExecutor(max_workers=16) as pool:
        for i,(aid,record,csaf) in enumerate(pool.map(load,sorted(raw.items())),1):
            doc,review,edges=build_document(aid,record,csaf,now);check.validate(doc)
            p=out/'sbom'/(aid+'.json');wire=formatted(doc);writes.append(writers.submit(write,p,doc));reviews.append(review);links.extend(edges)
            ids=[v['id'] for v in doc['vulnerabilities']];declared.update(ids)
            counts['components']+=len(doc['components']);counts['nonempty_sboms']+=bool(doc['components']);counts['CVE_occurrences']+=len(ids)
            counts['components_without_CPE']+=sum('cpe' not in c for c in doc['components']);counts['source_conflict_advisories']+=review['source_conflict_review']
            index.append({'advisory_id':aid,'title':record.get('title'),'url':record['url'],'file':'sbom/'+p.name,
                          'component_count':len(doc['components']),'declared_cves':ids,'status':review['status'],'sha256':hashlib.sha256(wire).hexdigest()})
            if i%50==0: print(f'Validated {i}/{len(raw)} advisories',flush=True)
    writers.shutdown(wait=True)
    for future in writes:future.result()
    write(out/'field_mapping.json',workbook_mapping())
    for name,records in [('source_products.jsonl',reviews),('linkage.jsonl',links)]:
        with (out/name).open('wb') as f:
            for row in records:f.write(encoded(row)+b'\n')
    unresolved=[r for r in reviews if not r['component_count']];write(out/'unresolved.json',unresolved);write(out/'excluded.json',[])
    summary={'dataset_id':DATASET,'generated_at':now.isoformat(),'advisories':len(index),'sbom_json_files':len(index),**dict(counts),
        'empty_sboms':len(unresolved),'declared_unique_cves':len(declared),'included_unique_cves':len(declared),'schema_version':'1.7',
        'schema_validated_documents':len(index),'unresolved_advisories':[r['advisory_id'] for r in unresolved],
        'schema_sha256':sha(SCHEMA/'bom-1.7.schema.json'),'workbook_sha256':sha(WORKBOOK),
        'product_membership_policy':'Advisory products and version expressions, irrespective of CVE/CPE availability',
        'dependency_graph':'unknown','real_asset_accuracy_verified':False,'source_semantic_accuracy_independently_verified':False,
        'item3_evaluation_dataset_changed':False,'source_manifest':'data/icsa_sbom_source_html/manifest.json'}
    write(out/'manifest.json',summary);write(out/'index.json',{'summary':summary,'advisories':index})
    (out/'README.txt').write_text('CycloneDX 1.7 synthetic advisory product collections, following the supplied field-definition workbook.\n'
        'Products/versions: CSAF product trees and original HTML AFFECTED PRODUCTS sections. No CVE/CPE membership gate.\n'
        'Ranges remain source expressions, not installed releases. BOM author and unknown free text: unknown.\n'
        'No invented identifier, hash, email, license ID, dependency or device. Unknown constrained fields are marked in properties.\n'
        'metadata.component is the advisory collection; components[] are product/version candidates, not a simultaneous installation.\n'
        'field_mapping.json: workbook mapping. source_products.jsonl: extraction evidence. unresolved.json: incomplete sources/non-product notices.\n'
        'Source conflicts/retractions keep their notes and uncertain CVE-product edges stay unknown.\n'
        'Item-3 evaluation inputs/Gold/results are separate. Audit is data integrity, not field accuracy.\n',encoding='utf8')
    print(json.dumps(summary),flush=True)
    return summary

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,default=OUT)
    build(parser.parse_args().output)
