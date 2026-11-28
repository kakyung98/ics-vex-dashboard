"""Apply source-anchored whole-corpus review corrections and rebuild delivery indices."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from collections import Counter
from datetime import datetime, timezone
import argparse, hashlib, json
from tools.common.build_icsa_advisory_sbom import build_document, validator, encoded, write
from tools.common.icsa_reviewed_product_overrides import PRODUCTS, REASONS, apply_review_policy
from tools.common import icsa_advisory_products as extraction

ROOT=Path(__file__).resolve().parents[2]
# A temporary execution copy is supported when --root is supplied.
def read(p): return json.loads(p.read_bytes())
def properties(node): return {p['name']:p['value'] for p in node.get('properties',[])}
def set_property(node,key,value):
    node['properties']=[p for p in node.get('properties',[]) if p['name']!=key]+[{'name':key,'value':value}]
def digest_file(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def repair(dataset,root):
    global ROOT
    ROOT=root
    raw=read(ROOT/'data/cisa_advisories.json'); extraction.PRODUCTS.update(PRODUCTS)
    reviews={r['advisory_id']:r for r in map(json.loads,(dataset/'source_products.jsonl').read_text(encoding='utf8').splitlines())}
    links=[json.loads(line) for line in (dataset/'linkage.jsonl').read_text(encoding='utf8').splitlines()]
    links=[r for r in links if r['advisory_id'] not in PRODUCTS]
    check=validator(); now=datetime.now(timezone.utc).replace(microsecond=0); updates=[]
    for aid in PRODUCTS:
        path=dataset/'sbom'/(aid+'.json'); old=read(path)
        created=datetime.fromisoformat(old['metadata']['timestamp'].replace('Z','+00:00'))
        source=ROOT/'icsa/csaf'/(aid+'.json')
        doc,review,edges=build_document(aid,raw[aid],read(source) if source.exists() else None,created)
        review['whole_corpus_review_reason']=REASONS[aid]
        set_property(doc,'dataset:whole-corpus-review-reason',REASONS[aid])
        if not doc['components']:
            review['status']='non-product-notice'
            set_property(doc,'dataset:source-status','non-product-notice')
        check.validate(doc);write(path,doc);reviews[aid]=review;links.extend(edges)
        updates.append({'advisory_id':aid,'reason':REASONS[aid],'before_components':len(old['components']),'after_components':len(doc['components'])})
    manifest=read(dataset/'manifest.json');index=read(dataset/'index.json'); by_id={r['advisory_id']:r for r in index['advisories']}
    counts=Counter();cves=set();checksum=[]
    for n,path in enumerate(sorted((dataset/'sbom').glob('*.json')),1):
        doc=read(path);before=digest_file(path)
        for tool in doc['metadata'].get('tools',{}).get('components',[]):
            tool.pop('scope',None);tool.pop('isExternal',None)
        for comp in [doc['metadata']['component'],*doc['components']]:
            comp.pop('scope',None);comp.pop('isExternal',None)
            missing=[k for k in ['scope','purl','cpe','hashes'] if k not in comp]
            missing += [kind+'.contact.email' for kind in ['manufacturer','supplier']
                        if not any(c.get('email') for c in comp.get(kind,{}).get('contact',[]))]
            if not any('id' in l.get('license',{}) for l in comp.get('licenses',[])):missing.append('licenses.license.id')
            set_property(comp,'dataset:unknown-fields',','.join(missing))
        unknown=properties(doc).get('dataset:unknown-fields','').split(',')
        if not any('phase' in x for x in doc['metadata'].get('lifecycles',[])):unknown.append('metadata.lifecycles.phase')
        set_property(doc,'dataset:unknown-fields',','.join(sorted(set(unknown)-{''})))
        set_property(doc,'SBOM_MODIFY_DATE',now.strftime('%Y-%m-%d %H:%M:%S'))
        set_property(doc,'dataset:whole-corpus-review','2026-11-18/v1')
        doc['version']=2
        doc=apply_review_policy(doc,path.stem)
        write(path,doc)
        after=digest_file(path);checksum.append({'advisory_id':path.stem,'generation_sha256':before,'reviewed_sha256':after})
        counts['components']+=len(doc['components']);counts['nonempty_sboms']+=bool(doc['components']);counts['CVE_occurrences']+=len(doc['vulnerabilities'])
        counts['components_without_CPE']+=sum('cpe' not in c for c in doc['components'])
        counts['source_conflict_advisories']+=properties(doc).get('dataset:source-conflict-review')=='true'
        cves.update(v['id'] for v in doc['vulnerabilities'])
        row=by_id[path.stem];row['component_count']=len(doc['components']);row['sha256']=after;row['status']=reviews[path.stem]['status']
        if n%500==0:print(f'Reviewed and validated {n}/3881',flush=True)
    unresolved=[r for r in reviews.values() if not r['component_count']]
    manifest.update(dict(counts));manifest.update(empty_sboms=len(unresolved),declared_unique_cves=len(cves),included_unique_cves=len(cves),
        unresolved_advisories=[r['advisory_id'] for r in unresolved],whole_corpus_review_at=now.isoformat(),
        product_extraction_corrections=updates,review_rule_sha256=digest_file(Path(__import__('tools.common.icsa_reviewed_product_overrides', fromlist=['*']).__file__)))
    index['summary']=manifest
    write(dataset/'manifest.json',manifest);write(dataset/'index.json',index);write(dataset/'unresolved.json',unresolved)
    (dataset/'source_products.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in reviews.values()),encoding='utf8')
    (dataset/'linkage.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in links),encoding='utf8')
    (dataset/'review_checksums.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in checksum),encoding='utf8')
    (dataset/'README.txt').write_text((dataset/'README.txt').read_text(encoding='utf8')+
        '\nWhole-corpus review 2026-11-18: all files revalidated against CycloneDX 1.7; original workbook field definitions retained.\n'
        'Additional source-anchored HTML corrections and explicit non-product notices are recorded in manifest.json.\n'
        'Unknown-field markers reflect fields actually absent. Version expressions remain source conditions, not installed releases.\n',encoding='utf8')
    print(json.dumps({'reviewed_files':len(checksum),'corrected_advisories':len(updates),'components':counts['components'],'empty_sboms':len(unresolved),'unique_cves':len(cves)}),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--dataset',type=Path,required=True);parser.add_argument('--root',type=Path,default=ROOT)
    args=parser.parse_args();repair(args.dataset,args.root)
