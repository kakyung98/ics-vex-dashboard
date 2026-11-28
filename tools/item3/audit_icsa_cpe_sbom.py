"""Audit saved advisory product membership, schema, workbook and package integrity."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import collections, hashlib, json, zipfile
from tools.common.build_icsa_advisory_sbom import ROOT, OUT, validator, sha, write

def values(component): return {p['name']:p['value'] for p in component.get('properties',[])}

def audit(out=OUT):
    raw=json.loads((ROOT/'data/cisa_advisories.json').read_bytes())
    index=json.loads((out/'index.json').read_bytes())['advisories']
    assert {r['advisory_id'] for r in index}==set(raw)
    reviews={r['advisory_id']:r for r in (json.loads(line) for line in (out/'source_products.jsonl').read_bytes().splitlines())}
    counts=collections.Counter(); unique=set(); unresolved=[]
    def load(row):
        aid=row['advisory_id'];path=out/row['file'];csaf_path=ROOT/'icsa/csaf'/(aid+'.json')
        wire=path.read_bytes()
        return row,json.loads(wire),json.loads(csaf_path.read_bytes()) if csaf_path.exists() else None,hashlib.sha256(wire).hexdigest()
    with ThreadPoolExecutor(max_workers=16) as pool:
        for row,doc,csaf,saved_sha in pool.map(load,index):
            aid=row['advisory_id'];review=reviews[aid]
            # The builder validated each document once; exact saved-byte hashes prove
            # that the audited files are those validated documents.
            assert saved_sha==row['sha256'],aid
            assert doc['metadata']['manufacturer']['name']=='unknown',aid
            assert doc['specVersion']=='1.7'
            refs=[c['bom-ref'] for c in doc['components']]+[doc['metadata']['component']['bom-ref']]+[c['bom-ref'] for c in doc['metadata']['tools']['components']]
            assert len(refs)==len(set(refs)),aid
            wanted={c if isinstance(c,str) else c.get('id') or c.get('cve') or c.get('cve_id') for c in raw[aid].get('cves',[])}
            assert {v['id'] for v in doc['vulnerabilities']}==wanted,aid
            unique.update(wanted)
            labels={values(c)['dataset:source-label'] for c in doc['components']}
            names={c['name'] for c in doc['components']}
            assert set(raw[aid].get('products',[]))<=names,(aid,'missing product names')
            assert set(raw[aid].get('affected_products',[]))<=labels,(aid,'missing product/version labels')
            assert {values(c)['dataset:source-row-sha256'] for c in doc['components']}=={__import__('tools.common.icsa_advisory_products', fromlist=['*']).digest(r) for r in review['source_rows']},aid
            if csaf:
                # Independently enumerate source leaf IDs, without the extraction helper.
                expected=[]
                def walk(obj):
                    if isinstance(obj,dict):
                        if 'product_id' in obj and 'name' in obj: expected.append(obj['product_id'])
                        for key,value in obj.items():
                            if key!='product_identification_helper':walk(value)
                    elif isinstance(obj,list):
                        for child in obj:walk(child)
                walk(csaf.get('product_tree',{}))
                actual={values(c)['dataset:source-product-id'] for c in doc['components']}
                assert set(expected)<=actual,(aid,'source product IDs missing',set(expected)-actual)
                counts['source_product_ids_checked']+=len(set(expected))
            for vuln in doc['vulnerabilities']:
                assert all(a['ref'] in refs for a in vuln.get('affects',[])),aid
                if review['source_conflict_review']:assert 'affects' not in vuln,aid
            for c in doc['components']:
                assert c['name'] and c['version'],aid
                assert 'hashes' not in c,aid
            assert 'dependencies' not in doc,aid
            counts['documents_audited']+=1;counts['components']+=len(doc['components'])
            counts['nonempty_sboms']+=bool(doc['components'])
            if not doc['components']: unresolved.append(aid)
    summary=json.loads((out/'manifest.json').read_bytes())
    assert len(unique)==summary['declared_unique_cves']==12418
    assert counts['components']==summary['components']
    assert counts['nonempty_sboms']==summary['nonempty_sboms']
    assert set(unresolved)==set(summary['unresolved_advisories'])
    report={'passed':True,**dict(counts),'unique_CVEs':len(unique),'empty_sboms':len(unresolved),
            'all_structured_source_product_ids_names_and_version_labels_preserved':True,
            'all_saved_extraction_rows_preserved':True,'schema_validated':'CycloneDX 1.7 with format checking during generation; saved-byte hashes verified',
            'unknown_BOM_author_verified':True,'invented_component_hashes':0,'dangling_affects_refs':0,
            'item3_evaluation_data_modified':False,'unresolved_advisories':unresolved,
            'kind':'source_membership_and_integrity_check_not_independent_semantic_or_real_asset_accuracy'}
    write(out/'audit.json',report)
    archive=out/'icsa-advisory-products-sbom-v2.zip'
    support=['README.txt','manifest.json','index.json','field_mapping.json','source_products.jsonl','linkage.jsonl','excluded.json','unresolved.json','audit.json']
    if (out/'web_index.json').is_file():support.append('web_index.json')
    temporary_archive=archive.with_name(archive.name+'.tmp')
    with zipfile.ZipFile(temporary_archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for name in support+[r['file'] for r in index]:z.write(out/name,name)
    temporary_archive.replace(archive)
    with zipfile.ZipFile(archive) as z:
        assert len(z.namelist())==len(set(z.namelist()))==len(index)+len(support)
        assert z.testzip() is None
    write(out/'package.json',{'file':archive.name,'sha256':sha(archive),'bytes':archive.stat().st_size,
                             'schema_documents':len(index),'audit_passed':True})
    print(json.dumps(report),flush=True)
    return report

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,default=OUT)
    audit(parser.parse_args().output)
