"""Revalidate and refresh HTML-derived records without rerunning unchanged CSAF BOMs."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse,collections,json
from pathlib import Path
from datetime import datetime,timezone
from tools.common.build_icsa_advisory_sbom import ROOT, OUT, build_document, validator, write, encoded, sha

def refresh(out=OUT):
    raw=json.loads((ROOT/'data/cisa_advisories.json').read_bytes())
    manifest=json.loads((out/'manifest.json').read_bytes())
    index=json.loads((out/'index.json').read_bytes())['advisories'];by_id={r['advisory_id']:r for r in index}
    reviews=[json.loads(line) for line in (out/'source_products.jsonl').read_bytes().splitlines()]
    by_review={r['advisory_id']:r for r in reviews}
    links=[json.loads(line) for line in (out/'linkage.jsonl').read_bytes().splitlines()]
    changed=set();new_links=[];check=validator()
    created=datetime.fromisoformat(manifest['generated_at']);modified=datetime.now(timezone.utc).replace(microsecond=0)
    for aid,record in raw.items():
        if (ROOT/'icsa/csaf'/(aid+'.json')).exists():continue
        doc,review,edges=build_document(aid,record,None,created)
        doc['version']=2
        for prop in doc['properties']:
            if prop['name']=='SBOM_MODIFY_DATE':prop['value']=modified.strftime('%Y-%m-%d %H:%M:%S')
        check.validate(doc);p=out/'sbom'/(aid+'.json');write(p,doc)
        by_id[aid].update(component_count=len(doc['components']),status=review['status'],sha256=sha(p))
        by_review[aid]=review;new_links.extend(edges);changed.add(aid)
    reviews=[by_review[r['advisory_id']] for r in reviews]
    links=[r for r in links if r['advisory_id'] not in changed]+new_links
    for name,rows in [('source_products.jsonl',reviews),('linkage.jsonl',links)]:
        temporary=out/(name+'.refresh.tmp')
        with temporary.open('wb') as f:
            for row in rows:f.write(encoded(row)+b'\n')
        temporary.replace(out/name)
    unresolved=[r for r in reviews if not r['component_count']]
    reasons={
        'icsa-10-228-01':'General administrator-account practice notice; no named product inventory',
        'icsa-11-025-01':'GPS testing notice; no named vendor product inventory',
        'icsa-11-041-01a':'Malware indicators; no identified affected product/version inventory',
        'icsa-13-291-01b':'Index of related vendor advisories; product inventories are in those separate sources',
        'icsa-14-178-01':'Havex malware report; tested OPC product/vendor identities are redacted',
    }
    for row in unresolved:row['reason']=reasons.get(row['advisory_id'],'Original advisory unavailable in the source cache')
    write(out/'unresolved.json',unresolved)
    components=sum(r['component_count'] for r in reviews)
    cpes=sum(bool(r.get('helpers',{}).get('cpe')) for review in reviews for r in review['source_rows'])
    manifest.update(components=components,nonempty_sboms=len(reviews)-len(unresolved),empty_sboms=len(unresolved),
        components_without_CPE=components-cpes,unresolved_advisories=[r['advisory_id'] for r in unresolved],
        html_refresh_at=modified.isoformat(),html_refreshed_documents=len(changed),
        source_conflict_advisories=sum(r['source_conflict_review'] for r in reviews))
    write(out/'manifest.json',manifest);write(out/'index.json',{'summary':manifest,'advisories':index})
    print(json.dumps({'refreshed':len(changed),'components':components,'with_products':manifest['nonempty_sboms'],
                      'unresolved':[{k:r[k] for k in ('advisory_id','reason')} for r in unresolved]}),flush=True)
    return manifest

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,default=OUT)
    refresh(parser.parse_args().output)
