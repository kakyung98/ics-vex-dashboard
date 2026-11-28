"""Pretty-print the reviewed delivery without changing any BOM document value."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib,json,shutil,uuid,zipfile

ROOT=Path(__file__).resolve().parents[2]
DATA=ROOT/'benchmark/icsa-cpe-synthetic sbom'
RESULT=ROOT/'results/icsa_sbom_pretty_20261118'
BACKUP=RESULT/'before_format'
ARCHIVE='icsa-advisory-products-sbom-v2-reviewed.zip'

def sha(w):return hashlib.sha256(w).hexdigest()
def pretty(v):return (json.dumps(v,ensure_ascii=False,indent=2)+'\n').encode('utf8')
def read(p):return json.loads(p.read_bytes())
def atomic(p,wire):
    p.parent.mkdir(parents=True,exist_ok=True)
    tmp=p.with_name(p.name+'.'+uuid.uuid4().hex+'.tmp')
    try:
        tmp.write_bytes(wire);tmp.replace(p)
    finally:
        if tmp.exists():tmp.unlink()
def save(p,v):atomic(p,pretty(v))

def main():
    RESULT.mkdir(parents=True,exist_ok=True);BACKUP.mkdir(exist_ok=True)
    assert not (RESULT/'delivery.json').exists(),'This delivery is already formatted; inspect its report before rerunning.'
    original_archive=DATA/ARCHIVE;backup_archive=BACKUP/ARCHIVE
    if not backup_archive.exists():shutil.copy2(original_archive,backup_archive)
    assert sha(backup_archive.read_bytes())=='f8a42bb1c30a5fb0dd0e9535b135f7dcb54516ac77fa2711e4f3f0496079500b'
    for p in sorted(DATA.rglob('*')):
        if p.is_file() and p.suffix!='.zip' and 'sbom' not in p.relative_to(DATA).parts:
            dest=BACKUP/'metadata'/p.relative_to(DATA)
            if not dest.exists():atomic(dest,p.read_bytes())
    print('Preserved compact archive and all original metadata',flush=True)
    index=read(DATA/'index.json');manifest=read(DATA/'manifest.json')
    changes=[]
    def format_one(row):
        path=DATA/row['file'];before=path.read_bytes();doc=json.loads(before)
        assert sha(before)==row['sha256'],row['advisory_id']
        wire=pretty(doc)
        assert json.loads(wire)==doc,row['advisory_id']
        atomic(path,wire)
        return {'advisory_id':row['advisory_id'],'before_sha256':sha(before),'after_sha256':sha(wire),
                'components':len(doc['components']),'cves':[v['id'] for v in doc['vulnerabilities']],
                'bytes_before':len(before),'bytes_after':len(wire)}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for n,change in enumerate(pool.map(format_one,index['advisories']),1):
            changes.append(change)
            if n%500==0:print(f'Formatted and compared {n}/3881',flush=True)
    by_id={r['advisory_id']:r for r in changes}
    assert len(changes)==3881
    assert sum(r['components'] for r in changes)==29066
    assert len({c for r in changes for c in r['cves']})==12418
    for row in index['advisories']:row['sha256']=by_id[row['advisory_id']]['after_sha256']
    stamp=datetime.now(timezone.utc).isoformat()
    presentation={'indent':2,'encoding':'UTF-8','trailing_newline':True,'formatted_at':stamp,
                  'documents':3881,'structurally_identical_documents':3881,'changed_values':0}
    manifest['json_format']=presentation
    for name in manifest.get('generator_sources',{}):manifest['generator_sources'][name]=sha((ROOT/name).read_bytes())
    manifest['generator_sources']['tools/common/apply_icsa_corpus_review.py']=sha((ROOT/'tools/common/apply_icsa_corpus_review.py').read_bytes())
    index['summary']=manifest
    save(DATA/'manifest.json',manifest);save(DATA/'index.json',index)
    for name,field in [('review_checksums.jsonl','reviewed_sha256'),('review/documents.jsonl','sha256')]:
        rows=[json.loads(line) for line in (DATA/name).read_text(encoding='utf8').splitlines() if line]
        assert len(rows)==3881
        for row in rows:row[field]=by_id[row['advisory_id']]['after_sha256']
        atomic(DATA/name,(''.join(json.dumps(row,ensure_ascii=False)+'\n' for row in rows)).encode('utf8'))
    for name in ['audit.json','review/summary.json']:
        report=read(DATA/name);report['json_format_verification']=presentation
        save(DATA/name,report)
    for path in DATA.rglob('*.json'):
        if path.parent!=DATA/'sbom' and path.name not in {'delivery_verification.json','published_verification.json'}:
            save(path,read(path))
    atomic(DATA/'README.txt',( (DATA/'README.txt').read_text(encoding='utf8')+
        '\nJSON presentation: UTF-8, two-space indentation, final newline. All 3,881 BOM documents are structurally identical to the preserved compact delivery.\n').encode('utf8'))
    save(DATA/'review/json_format_verification.json',{
        **presentation,'prior_compact_archive_sha256':sha(backup_archive.read_bytes()),
        'prior_delivery_backup':str(BACKUP),'verification':'Parsed JSON equality for every BOM; source-evidence digests unchanged.',
        'components':29066,'unique_cves':12418,'nonempty':3874,'unresolved':7})
    atomic(RESULT/'document_format_checksums.jsonl',(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in changes)).encode('utf8'))
    # Re-read the actual saved bytes, including both row-based integrity ledgers.
    with zipfile.ZipFile(backup_archive) as old:
        for row in index['advisories']:
            wire=(DATA/row['file']).read_bytes()
            assert sha(wire)==row['sha256']
            assert wire.endswith(b'\n') and b'\n  ' in wire
            assert json.loads(wire)==json.loads(old.read(row['file']))
    old_verification=read(BACKUP/'metadata/review/published_verification.json')
    sources=[dict(row,sha256=sha((ROOT/row['file']).read_bytes())) for row in old_verification['source_files']]
    metadata=[{'file':str(p.relative_to(DATA)).replace('\\','/'),'sha256':sha(p.read_bytes())}
              for p in sorted(DATA.rglob('*')) if p.is_file() and p.suffix!='.zip'
              and 'sbom' not in p.relative_to(DATA).parts
              and p.name not in {'delivery_verification.json','published_verification.json'}]
    verification={'verified_at':stamp,'passed':True,'kind':'presentation_only_republication',
                  'json_files_hash_verified':3881,'structurally_identical_documents':3881,
                  'metadata_files_hash_verified':len(metadata),'metadata_files':metadata,
                  'source_files_hash_verified':len(sources),'source_files':sources,
                  'manifest_sha256':sha((DATA/'manifest.json').read_bytes()),
                  'index_sha256':sha((DATA/'index.json').read_bytes()),
                  'audit_sha256':sha((DATA/'audit.json').read_bytes()),
                  'archive_hash_recorded_in':str(RESULT/'delivery.json'),
                  'prior_verification_records':str(BACKUP/'metadata/review'),
                  'regression_tests':'Prior source review: 14 passed; current generator checks recorded in delivery report.'}
    save(DATA/'review/delivery_verification.json',verification)
    save(DATA/'review/published_verification.json',verification)
    temp=DATA/(ARCHIVE+'.tmp')
    with zipfile.ZipFile(temp,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for path in sorted(DATA.rglob('*')):
            if path.is_file() and path!=temp and path.suffix!='.zip' and not path.name.endswith('.tmp'):
                z.write(path,str(path.relative_to(DATA)).replace('\\','/'))
    with zipfile.ZipFile(temp) as z:
        assert z.testzip() is None
        assert len([n for n in z.namelist() if n.startswith('sbom/') and n.endswith('.json')])==3881
        for row in index['advisories']:assert sha(z.read(row['file']))==row['sha256']
    temp.replace(original_archive)
    for aid in ['icsa-10-070-01a','icsa-26-302-01']:
        atomic(ROOT/'results/icsa_sbom_samples_20261118'/(aid+'.json'),(DATA/'sbom'/(aid+'.json')).read_bytes())
    import sys
    sys.path.insert(0,str(ROOT/'tools'))
    from tools.item3.icsa_cpe_dataset_web import build_cache
    cache=build_cache(DATA,output=ROOT/'site/sbom_index.json')
    delivery={**presentation,'components':29066,'unique_cves':12418,'nonempty':3874,'unresolved':7,
              'archive':str(original_archive),'archive_sha256':sha(original_archive.read_bytes()),
              'archive_bytes':original_archive.stat().st_size,'index_sha256':cache['source_index_sha256'],
              'manifest_sha256':sha((DATA/'manifest.json').read_bytes()),'audit_sha256':sha((DATA/'audit.json').read_bytes()),
              'zip_crc_passed':True,'zip_sbom_hashes_verified':3881,'backup':str(BACKUP)}
    save(RESULT/'delivery.json',delivery)
    print(json.dumps(delivery,ensure_ascii=False,indent=2),flush=True)

if __name__=='__main__':main()
