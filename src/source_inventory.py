"""Count observed source snapshots separately from compiler analysis attempts."""
from pathlib import Path
from collections import Counter
import json,os,re


def inventory(root,corpus_cves):
    root=Path(root).resolve();corpus=set(corpus_cves);folder=root/'data/source_snapshots';snapshots=set()
    if folder.is_dir():
        for path in folder.iterdir():
            if path.is_symlink() or not path.is_dir() or not re.fullmatch(r'CVE-\d{4}-\d{4,}',path.name):continue
            # Snapshot presence is only file presence, not vulnerable-version,
            # product completeness, compilation success or exploitability proof.
            for current,dirs,files in os.walk(path,followlinks=False):
                dirs[:]=[d for d in dirs if not (Path(current)/d).is_symlink()]
                if any(not (Path(current)/f).is_symlink() for f in files):snapshots.add(path.name);break
    records={};campaign=None;error=None
    try:
        pointer=json.loads((root/'results/current_source_campaign.json').read_text(encoding='utf-8'))
        candidate=(root/pointer['path']).resolve()
        if not candidate.is_relative_to((root/'results').resolve()):raise ValueError('Campaign path escapes results')
        campaign=candidate
        summary=json.loads((campaign/'summary.json').read_text(encoding='utf-8'))
        for row in summary.get('results',[]):
            if isinstance(row,dict) and row.get('cve') in snapshots:records[row['cve']]=row
    except (OSError,ValueError,KeyError,TypeError) as e:error=type(e).__name__
    present=snapshots&corpus;attempted=set(records)&present
    return {'corpus_cves':len(corpus),'snapshots_total':len(snapshots),'snapshots_in_corpus':len(present),
        'snapshots_outside_corpus':len(snapshots-corpus),'outside_corpus_cves':sorted(snapshots-corpus),
        'no_local_snapshot':len(corpus-present),'analysis_attempted_in_corpus':len(attempted),
        'analysis_state_in_corpus':dict(Counter(records[c].get('analysis_state','unknown') for c in sorted(attempted))),
        'campaign':campaign.relative_to(root).as_posix() if campaign else None,'campaign_error':error,
        'snapshot_store_available':folder.is_dir(),
        'collection_basis':'nonempty CVE-named snapshot directories on disk',
        'analysis_basis':'per-CVE records from the selected compiler campaign; attempts, not complete-product proofs',
        'snapshot_presence_verifies_vulnerable_version':False,
        'snapshot_presence_verifies_complete_product':False,
        'snapshot_cves':snapshots,'corpus_snapshot_cves':present,'analysis_records':records}


def public_summary(result):
    return {k:v for k,v in result.items() if k not in {'snapshot_cves','corpus_snapshot_cves','analysis_records'}}
