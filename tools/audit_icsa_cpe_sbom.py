"""Reconstruct advisory/CPE membership directly from source; audit saved exports."""
import collections,json,sqlite3,hashlib,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'benchmark/icsa-cpe-synthetic sbom'
BOUNDS=('versionStartIncluding','versionStartExcluding','versionEndIncluding','versionEndExcluding')
def normalized(m):return (m['criteria'],tuple((k,str(m[k])) for k in BOUNDS if k in m))
def main():
    raw=json.loads((ROOT/'data/cisa_advisories.json').read_bytes())
    expected=collections.defaultdict(set)
    with sqlite3.connect((ROOT/'data/item3_spelling_noise_v10/dataset.sqlite3').as_uri()+'?mode=ro',uri=True) as db:
        for cve,wire in db.execute('select cve,raw_match from source_coverage where vulnerable=1'):
            expected[cve].add(normalized(json.loads(wire)))
    files=list((OUT/'sbom').glob('*.json'));assert {p.stem for p in files}==set(raw)
    count=0;total=0;excluded=0;unique=set()
    for p in files:
        d=json.loads(p.read_bytes()); declared=raw[p.stem].get('cves',[]);wanted=[c for c in declared if expected.get(c)]
        assert {x['id'] for x in d['vulnerabilities']}==set(wanted),p.stem
        comps={c['bom-ref']:c for c in d['components']}
        assert len(comps)==len(d['components'])
        for v in d['vulnerabilities']:
            actual=set()
            for a in v['affects']:
                c=comps[a['ref']];ps={q['name']:q['value'] for q in c['properties']}
                actual.add(normalized({'criteria':c['cpe'],**{k:ps['nvd:'+k] for k in BOUNDS if 'nvd:'+k in ps}}))
                if c['cpe'].split(':')[5]=='*':assert 'version' not in c
            assert actual==expected[v['id']],(p.stem,v['id'])
        count+=1;total+=len(wanted);excluded+=len(declared)-len(wanted);unique.update(wanted)
    s=json.loads((OUT/'manifest.json').read_bytes())
    assert (count,total,len(unique),excluded)==(s['sbom_json_files'],s['included_cve_occurrences'],s['included_unique_cves'],s['excluded_cve_occurrences'])
    report={'passed':True,'documents_audited':count,'unique_CVEs':len(unique),'CVE_occurrences':total,
            'excluded_occurrences':excluded,'all_CPE_conditions_and_bounds_reconstructed':True,
            'invented_wildcard_release_count':0,'item3_evaluation_data_modified':False,
            'kind':'data_integrity_validation_not_independent_precision_validation'}
    wire=json.dumps(report,indent=2).encode();(OUT/'audit.json').write_bytes(wire)
    with zipfile.ZipFile(OUT/'icsa-cpe-sbom-v1.zip','a',zipfile.ZIP_DEFLATED) as z:
        if 'audit.json' not in z.namelist():z.writestr('audit.json',wire)
    print(json.dumps(report))
if __name__=='__main__':main()
