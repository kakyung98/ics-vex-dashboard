"""Check rebuilt CPE relations against both preserved CSAF BOMs and the CVE DB."""
from collections import Counter
from pathlib import Path
import argparse
import json
import sys

ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from tools.item3.build_item3_advisory_dataset import compact,digest,sha,write,properties
from tools.item3.rebuild_icsa_cpe_source import BOUNDS,version_expression


def verify(rebuilt,original,cve_source):
    rebuilt,original,cve_source=Path(rebuilt).resolve(),Path(original).resolve(),Path(cve_source).resolve()
    manifest=json.loads((rebuilt/'manifest.json').read_bytes())
    if sha(cve_source)!=manifest['source_CVE_DB_sha256'] or sha(original/'index.json')!=manifest['source_v2_index_sha256']:
        raise ValueError('Source snapshot hash differs')
    allowed={}
    for s in cve_source.read_text(encoding='utf-8').splitlines():
        row=json.loads(s)
        allowed[row['id']]={digest([m['criteria'],{k:m.get(k) for k in BOUNDS}]):m
            for node in row.get('configurations',[]) for m in node.get('cpeMatch',[]) if m.get('vulnerable') is True}
    index=json.loads((rebuilt/'index.json').read_bytes())['advisories']
    if {r['file'] for r in index}!={r['file'] for r in json.loads((original/'index.json').read_bytes())['advisories']}:
        raise ValueError('Original document population changed')
    counts=Counter();covered=set()
    for row in index:
        if sha(rebuilt/row['file'])!=row['sha256']:
            raise ValueError('Rebuilt index hash mismatch')
        before=json.loads((original/row['file']).read_bytes());after=json.loads((rebuilt/row['file']).read_bytes())
        n=len(before['components'])
        if after['components'][:n]!=before['components']:
            raise ValueError('An original CSAF/HTML component changed')
        originals={v['id']:v for v in before.get('vulnerabilities',[])}
        if set(originals)!={v['id'] for v in after.get('vulnerabilities',[])}:
            raise ValueError('CVE membership changed')
        added={c['bom-ref']:c for c in after['components'][n:]}
        if len(added)!=len(after['components'])-n:
            raise ValueError('Duplicate NVD component')
        seen=set()
        for v in after.get('vulnerabilities',[]):
            old=originals[v['id']]
            if not {r['ref'] for r in old.get('affects',[])}<={r['ref'] for r in v.get('affects',[])}:
                raise ValueError('Original CSAF links lost')
            for p in old.get('properties',[]):
                if p not in v.get('properties',[]):raise ValueError('Original source status changed')
            refs=json.loads(properties(v).get('dataset:nvd-cpe-component-refs','[]'))
            if v['id'] in allowed and not refs:
                raise ValueError('CPE-linked CVE has no explicit new CPE relation')
            for ref in refs:
                component=added[ref];p=properties(component)
                criteria=p['dataset:source-cpe-criteria'];bounds=json.loads(p['dataset:source-version-bounds'])
                key=digest([criteria,{k:bounds.get(k) for k in BOUNDS}])
                if key not in allowed[v['id']] or component['cpe']!=criteria:
                    raise ValueError('Unsupported CVE/CPE product/version link')
                if component['version']!=version_expression(allowed[v['id']][key]):
                    raise ValueError('Version expression not source-preserving')
                seen.add(ref);covered.add(v['id'])
        if seen!=set(added):raise ValueError('Unlinked NVD candidate')
        counts.update(documents=1,original_components=n,new_CPE_components=len(added))
    if covered!=set(allowed):raise ValueError('CPE CVE population lost')
    result=dict(passed=True,**dict(counts),covered_CVEs=len(covered),original_components_preserved=True,
        original_CSAF_links_and_statuses_preserved=True,all_new_CPE_links_backed_by_CVE_DB=True,
        source_CVE_DB_sha256=sha(cve_source),original_index_sha256=sha(original/'index.json'),
        rebuilt_manifest_sha256=sha(rebuilt/'manifest.json'),scope='Source linkage/transform audit, not real-asset accuracy')
    write(rebuilt/'CPE_rebuild_verification.json',result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    published=ROOT/'benchmark/icsa-cpe-synthetic sbom'
    p.add_argument('--rebuilt',type=Path,default=published if (published/'manifest.json').is_file() and json.loads((published/'manifest.json').read_bytes()).get('dataset_id')=='icsa-advisory-products-sbom-v3' else ROOT/'benchmark/icsa-cpe-source-v3-staged')
    backup=ROOT/'benchmark/icsa-cpe-synthetic sbom-v2-backup-20261125'
    p.add_argument('--original',type=Path,default=backup if backup.exists() else ROOT/'benchmark/icsa-cpe-synthetic sbom')
    p.add_argument('--cve-source',type=Path,default=ROOT/'data/item3_identification_sources_v11/cves.jsonl')
    a=p.parse_args();print(json.dumps(verify(a.rebuilt,a.original,a.cve_source),ensure_ascii=False,indent=2))
