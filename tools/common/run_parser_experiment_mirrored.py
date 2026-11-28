"""Run the unchanged evaluator on byte-identical temporary source copies.

This avoids repeated slow-volume metadata/SQLite access. A 200-case pilot must
match the already running same-engine replay's complete assessment hashes.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from datetime import datetime
from pathlib import Path
from unittest.mock import patch
import gzip,json,shutil,sys,tempfile,time
from src.item4.decision import evidence_based_vex as E; from src.item4.decision import population_condition_rules as P; from src.item4.assets import operating_profile_catalog as M; from src.item4.decision import scoped_vex_review as A
from tools.item4 import compare_full_population_benchmark as B

ROOT=B.ROOT
HOME=ROOT/'results/nist_version_parser_20261118_v4'
OUTPUT=ROOT/'results/nist_population_vex_comparison_20261118_v4_release'


def main():
    if OUTPUT.exists():raise ValueError('Output already exists')
    workspace=Path(tempfile.mkdtemp(prefix='ics-vex-parser-v4-')).resolve()
    control=dict(workspace=str(workspace),output=str(OUTPUT),status='copying public source snapshots')
    (HOME/'mirror_control.json').write_text(json.dumps(control,indent=2),encoding='utf-8')
    files=[]
    for source,target in [(E.ROOT/'data/nist_auto_vex',workspace/'data/nist_auto_vex'),
                          (P.HOME,workspace/'population'),(A.DATA,workspace/'asset_sources')]:
        shutil.copytree(source,target)
        for p in source.rglob('*'):
            if not p.is_file():continue
            copied=target/p.relative_to(source);sha=B.file_hash(p)
            if B.file_hash(copied)!=sha:raise ValueError('Copied source bytes differ: '+str(p))
            files.append(dict(source=str(p),copy=str(copied),sha256=sha))
    E.ROOT=workspace;P.HOME=workspace/'population';A.DATA=workspace/'asset_sources'
    E._registry.cache_clear();P._get.cache_clear();P._manifest.cache_clear();A.shard.cache_clear()
    before={}
    with (ROOT/'results/nist_population_vex_comparison_20261118_v4_verified/predictions.jsonl').open(encoding='utf-8') as f:
        for _,line in zip(range(200),f):
            row=json.loads(line);before[row['case_id']]=row
    if len(before)!=200:raise ValueError('A complete 200-case pilot reference is required')
    frozen=datetime.fromisoformat(json.loads((B.BASE/'protocol.json').read_text())['frozen_at'])
    class Clock(datetime):
        @classmethod
        def now(cls,tz=None):return frozen.astimezone(tz) if tz else frozen.replace(tzinfo=None)
    start=time.monotonic()
    with patch.object(E,'now',return_value=frozen),patch.object(M,'datetime',Clock),patch('socket.socket.connect',side_effect=AssertionError('No network/LLM')),gzip.open(B.BASE/'inputs.jsonl.gz','rt',encoding='utf-8') as inputs:
        for _,line in zip(range(200),inputs):
            item=json.loads(line);payload=item['payload'];plan=E.plan(payload['cve'],payload['profile'],payload.get('product_key'))
            updated=B.reseal_payload(payload,plan,'source-bound-operational-auto-vex/2')
            result=E.evaluate(updated)
            if result['assessment_sha256']!=before[item['case_id']]['assessment_sha256']:
                raise ValueError('Mirrored evaluation differs from the ordinary same-engine run: '+item['case_id'])
    pilot=dict(cases=200,all_complete_assessment_hashes_identical=True,elapsed_seconds=round(time.monotonic()-start,3))
    control.update(status='running full population',pilot=pilot,source_files=len(files))
    (HOME/'mirror_control.json').write_text(json.dumps(control,indent=2),encoding='utf-8');print(json.dumps(control),flush=True)
    temporary_output=workspace/'replay'
    sys.argv=['comparison','--output',str(temporary_output)]
    B.main()
    for row in files:
        if B.file_hash(Path(row['source']))!=row['sha256'] or B.file_hash(Path(row['copy']))!=row['sha256']:
            raise ValueError('A source snapshot changed during replay')
    shutil.copytree(temporary_output,OUTPUT)
    for file in temporary_output.iterdir():
        if file.is_file() and B.file_hash(file)!=B.file_hash(OUTPUT/file.name):raise ValueError('Output copy hash differs')
    storage=dict(pilot=pilot,source_files=files,original_and_mirrored_sources_unchanged=True,
        engine_code_unchanged=True,only_physical_storage_locations_changed=True,all_output_copy_hashes_identical=True)
    (OUTPUT/'storage_validation.json').write_text(json.dumps(storage,indent=2),encoding='utf-8')
    control.update(status='complete',temporary_workspace_retained_for_cleanup=True)
    (HOME/'mirror_control.json').write_text(json.dumps(control,indent=2),encoding='utf-8')
    print(json.dumps(control),flush=True)


if __name__=='__main__':main()
