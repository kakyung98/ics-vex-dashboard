"""Build a live synthetic SBOM snapshot without mutating frozen evaluation inputs."""
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.training_io import read_json,atomic_json


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    return mod


def main():
    now=datetime.now(timezone.utc)
    folder=ROOT/'data/public_sbom'/now.strftime('%Y%m%dT%H%M%SZ')
    documents=folder/'documents';csaf=folder/'csaf'
    csaf.mkdir(parents=True)
    advisories=read_json(ROOT/'data/cisa_advisories.json')
    expected={aid for aid,a in advisories.items() if not a.get('error')}
    builder=module('live_reverse_builder','src/build_reverse_sbom.py')
    builder.OUT_SBOM=str(documents);builder.OUT_DATA=str(folder)
    builder.DOC_TIMESTAMP=now.strftime('%Y-%m-%dT%H:%M:%SZ')
    builder.DOC_DATE_TIME=now.strftime('%Y-%m-%d %H:%M:%S')
    # Historical label manifests are frozen evaluation inputs, not current facts.
    builder.load_upstream_vex=lambda:{}
    builder.main()
    variants=module('live_variants','tools/inject_product_variants.py')
    with zipfile.ZipFile(ROOT/'data/upstream_csaf_latest.zip') as z:
        for aid in sorted(expected):
            a=advisories[aid];path=a.get('csaf_path')
            if not path:continue
            name=next((n for n in z.namelist() if n.endswith('/'+path)),None)
            if not name:raise RuntimeError('Missing pinned CSAF: '+aid)
            source=csaf/(aid+'.json');source.write_bytes(z.read(name))
            sp=documents/(aid+'_SBOM-CVE.json')
            result=variants.inject(str(sp),str(source))
            if result:atomic_json(sp,result[0])
    seen=set()
    for path in documents.glob('*.json'):
        aid=path.name.removesuffix('_SBOM-CVE.json');seen.add(aid)
        doc=read_json(path)
        assert {v['id'] for v in doc.get('vulnerabilities',[])}==set(advisories[aid].get('cves',[])),aid
        refs={c['bom-ref'] for c in doc['components']}|{doc['metadata']['component']['bom-ref']}
        assert all(a['ref'] in refs for v in doc.get('vulnerabilities',[]) for a in v.get('affects',[])),aid
    assert seen==expected,(expected-seen,seen-expected)
    indexer=module('live_sbom_index','tools/build_sbom_index.py')
    indexer.RSBOM=str(documents);indexer.OUT=str(folder/'sbom_index.json')
    indexer.main()
    index=read_json(folder/'sbom_index.json')
    excluded=[{'advisory_id':aid,'reason':a['error']} for aid,a in sorted(advisories.items()) if a.get('error')]
    index.update(generated_at=now.isoformat(),source_directory=documents.relative_to(ROOT).as_posix(),
                 advisory_records=len(advisories),excluded_advisories=excluded,
                 source_csaf_commit=read_json(ROOT/'data/public_corpus_freshness.json').get('csaf_commit'))
    # Switch the live index only after the complete snapshot passes integrity checks.
    atomic_json(ROOT/'sbom_index.json',index)
    report={'status':'complete','generated':len(seen),'advisory_records':len(advisories),
            'excluded_advisories':excluded,'source_directory':index['source_directory'],
            'evaluation_policy':'New snapshot; historical evaluation results are not carried forward','generated_at':now.isoformat()}
    atomic_json(ROOT/'results/public_sbom_refresh.json',report)
    print(json.dumps(report),flush=True)


if __name__=='__main__':main()
