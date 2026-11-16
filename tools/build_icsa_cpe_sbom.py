"""Advisory-centred source-linked SBOM export, separate from item-3 Gold."""
from pathlib import Path
import collections, hashlib, json, re, sqlite3, sys, uuid, zipfile
from datetime import datetime, timezone
from jsonschema import Draft7Validator, RefResolver

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'site/icsa-cpe-sbom'
SOURCE = ROOT / 'data/item3_spelling_noise_v10/dataset.sqlite3'
SCHEMA = ROOT / 'data/standards/cyclonedx-1.6'
BOUNDS = ('versionStartIncluding','versionStartExcluding','versionEndIncluding','versionEndExcluding')

def encoded(x): return json.dumps(x, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''): h.update(b)
    return h.hexdigest()
def write(p,x): p.write_bytes(encoded(x))
def props(d): return [{'name':k,'value':str(v)} for k,v in d.items()]
def parts(cpe):
    # Preserve escaped colons; keep the original CPE intact in the output.
    fields=re.split(r'(?<!\\):',cpe)
    return fields if len(fields)==13 and fields[:2]==['cpe','2.3'] and fields[2] in {'a','o','h'} else None
def display(value): return re.sub(r'\\(.)',r'\1',value).replace('_',' ')

def build():
    (OUT/'sbom').mkdir(parents=True,exist_ok=True)
    advisory_file=ROOT/'data/cisa_advisories.json'
    advisories=json.loads(advisory_file.read_bytes())
    cvemap=collections.defaultdict(list); invalid=[]; all_source=set()
    with sqlite3.connect(SOURCE.as_uri()+'?mode=ro',uri=True) as db:
        for cve,path,condition,vulnerable,raw in db.execute('select cve,path,condition_id,vulnerable,raw_match from source_coverage order by cve,path'):
            all_source.add(cve)
            if not vulnerable: continue
            match=json.loads(raw)
            if not parts(match['criteria']):
                invalid.append({'cve':cve,'path':path,'match':match});continue
            cvemap[cve].append({'source_path':path,'source_condition_id':condition,'match':match})
    schema=json.loads((SCHEMA/'bom-1.6.schema.json').read_bytes())
    resolver=RefResolver(base_uri=SCHEMA.as_uri()+'/',referrer=schema)
    validator=Draft7Validator(schema,resolver=resolver)
    rows=[]; declared=collections.Counter(); included=collections.Counter(); excluded=[]
    ncomponents=0; nlinks=0; nbounds=0; sizes=[]
    with (OUT/'linkage.jsonl').open('wb') as ledger:
        for aid,record in sorted(advisories.items()):
            assert re.fullmatch(r'icsa-[a-z0-9-]+',aid),aid
            ids=[x if isinstance(x,str) else x.get('id') or x.get('cve') or x.get('cve_id') for x in record.get('cves',[])]
            assert all(isinstance(c,str) and re.fullmatch(r'CVE-\d{4}-\d+',c) for c in ids),aid
            declared.update(ids)
            components={}; relations=collections.defaultdict(set); kept=[]; dropped=[]
            for occurrence,cve in enumerate(ids):
                atoms=cvemap.get(cve,[])
                if not atoms:
                    reason='no_CPE_source' if cve not in all_source else 'no_usable_vulnerable_CPE'
                    dropped.append(cve);excluded.append({'advisory_id':aid,'occurrence':occurrence,'cve':cve,'reason':reason});continue
                included.update([cve]);kept.append(cve)
                refs=[]
                for atom in atoms:
                    m=atom['match']; cp=m['criteria']; f=parts(cp)
                    bounds={k:m[k] for k in BOUNDS if k in m}
                    key=hashlib.sha256(encoded({'cpe':cp,'bounds':bounds})).hexdigest()
                    ref='component-'+key
                    if ref not in components:
                        p={'dataset:source-condition-id':atom['source_condition_id'],
                           'dataset:deployment-verified':'false',
                           'dataset:inventory-role':'source-affected-product-candidate'}
                        p.update({'nvd:'+k:v for k,v in bounds.items()})
                        comp={'bom-ref':ref,'type':{'a':'application','o':'operating-system','h':'device'}[f[2]],
                              'name':display(f[4]),'manufacturer':{'name':display(f[3])},'cpe':cp,'properties':props(p)}
                        if f[5] not in {'*','-',''}: comp['version']=re.sub(r'\\(.)',r'\1',f[5])
                        else:comp['properties']+=props({'dataset:installed-version':'unknown' if f[5]=='*' else 'not-applicable'})
                        components[ref]=comp;nbounds+=bool(bounds)
                    relations[cve].add(ref);refs.append(ref)
                ledger.write(encoded({'advisory_id':aid,'occurrence':occurrence,'cve':cve,
                                      'component_refs':sorted(set(refs)),'source_atoms':atoms})+b'\n')
            unique=list(dict.fromkeys(kept))
            doc={'$schema':'https://cyclonedx.org/schema/bom-1.6.schema.json','bomFormat':'CycloneDX','specVersion':'1.6',
                 'serialNumber':'urn:uuid:'+str(uuid.uuid5(uuid.NAMESPACE_URL,'ics-vex:icsa-cpe-sbom-v1:'+aid)),
                 'version':1,'components':list(components.values()),
                 'properties':props({'dataset:id':'icsa-cpe-sbom-v1','dataset:advisory-id':aid,
                  'dataset:synthetic-inventory':'true','dataset:deployment-verified':'false',
                  'dataset:status':'CPE-backed' if components else 'empty-no-eligible-CVE',
                  'dataset:source-record-sha256':hashlib.sha256(encoded(record)).hexdigest(),
                  'dataset:inventory-semantics':'Alternative source-affected product/version conditions; not a verified simultaneous installation',
                  'dataset:evaluation-role':'Separate export; not item-3 evaluation input or independent Gold'}),
                 'vulnerabilities':[{'id':cve,'source':{'name':'NVD','url':'https://nvd.nist.gov/vuln/detail/'+cve},
                                     'affects':[{'ref':ref} for ref in sorted(relations[cve])]} for cve in unique]}
            if record.get('url'):doc['externalReferences']=[{'type':'advisories','url':record['url']}]
            validator.validate(doc)
            # Independent integrity gates: no invented release and no dangling reference.
            assert {v['id'] for v in doc['vulnerabilities']}==set(kept)
            assert all(a['ref'] in components for v in doc['vulnerabilities'] for a in v['affects'])
            path=OUT/'sbom'/f'{aid}.json';write(path,doc)
            ncomponents+=len(components);nlinks+=sum(map(len,relations.values()));sizes.append((len(components),aid))
            rows.append({'advisory_id':aid,'title':record.get('title',''),'url':record.get('url',''),
                'declared_cves':ids,'included_cves':kept,'excluded_cves':dropped,'component_count':len(components),
                'status':'CPE-backed' if components else 'empty-no-eligible-CVE','file':'sbom/'+aid+'.json',
                'sha256':sha(path)})
    assert len(declared)==12418,('Target population drift',len(declared))
    write(OUT/'excluded.json',excluded);write(OUT/'invalid_cpe.json',invalid)
    summary={'dataset_id':'icsa-cpe-sbom-v1','generated_at':datetime.now(timezone.utc).isoformat(),
       'advisories':len(rows),'sbom_json_files':len(rows),'nonempty_sboms':sum(bool(r['component_count']) for r in rows),
       'empty_sboms':sum(not r['component_count'] for r in rows),'declared_unique_cves':len(declared),
       'declared_cve_occurrences':sum(declared.values()),'included_unique_cves':len(included),
       'included_cve_occurrences':sum(included.values()),'excluded_unique_cves':len(set(declared)-set(included)),
       'excluded_cve_occurrences':len(excluded),'components_across_advisories':ncomponents,
       'cve_component_links':nlinks,'components_with_version_bounds':nbounds,
       'advisories_over_100_components':sum(n>100 for n,a in sizes),'max_components':max(sizes)[0],
       'cves_repeated_across_advisories':sum(n>1 for n in included.values()),
       'duplicate_example':next(({'cve':c,'advisory_ids':[r['advisory_id'] for r in rows if c in r['included_cves']]} for c,n in included.items() if n>1),None),
       'precision':None,'independent_gold':False,'item3_evaluation_dataset_changed':False,
       'scope':'Source-linked synthetic candidate inventory, not a verified ICS installation or VEX judgement',
       'policy':{'unit':'one JSON per cached ICSA; empty records explicitly marked','CVE_filter':'usable vulnerable:true source CPE',
                 'CVE_duplicates':'retain each advisory occurrence','component_key':'CPE literal plus original version bounds within advisory',
                 'version':'literal CPE release only; wildcard not converted to invented installed release',
                 'platform_CPEs':'vulnerable:false predicates excluded from affected-component inventory'},
       'validation':{'cyclonedx_schema':'1.6','documents_schema_validated':len(rows),'dangling_affects_refs':0},
       'sources':[{'path':str(p.relative_to(ROOT)).replace('\\','/'),'sha256':sha(p)} for p in [advisory_file,SOURCE,*sorted(SCHEMA.glob('*.json'))]]}
    write(OUT/'manifest.json',summary);write(OUT/'index.json',{'summary':summary,'advisories':rows})
    (OUT/'README.txt').write_text('ICSA -> explicitly listed CVE -> vulnerable:true source CPE.\nOne SBOM per advisory; empty documents are marked and are not usable inventory.\nRepeated CVEs across advisories are retained. Multiple affected CPE conditions may represent alternative products/releases, not a verified installation.\nOriginal version bounds are component properties. Wildcards do not imply an installed release.\nlinkage.jsonl preserves original source CPE matches and NVD configuration paths. Full AND/OR configuration applicability is not asserted.\nExcluded CVEs are in excluded.json. This export is separate from the existing item-3 evaluation and Gold. No new precision measured.\n',encoding='utf-8')
    archive=OUT/'icsa-cpe-sbom-v1.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for p in sorted(OUT.rglob('*')):
            if p.is_file() and p!=archive:z.write(p,p.relative_to(OUT))
    print(json.dumps({k:v for k,v in summary.items() if k not in {'sources','policy','duplicate_example'}},ensure_ascii=False))
    print(json.dumps({'archive_bytes':archive.stat().st_size,'archive_sha256':sha(archive)}))

if __name__=='__main__':build()
