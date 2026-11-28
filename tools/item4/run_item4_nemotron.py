"""Run the entire frozen ICSA synthetic population with fingerprinted Nemotron inference."""
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import sys
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from src.item4.evaluation import scenario_evaluation_runner as runs; from src.item4.evaluation import frozen_evidence_packets as item4_frozen_packets; from src.item4.evaluation import bulk_scenario_runner as item4_bulk_run
from src.item4.models.nemotron_inference_provider import NemotronBatch


from src.common.paths import source_path

def prepare(provider, resume=None):
    base=json.loads(runs.BASELINE.read_bytes())
    replay=json.loads((runs.REPLAY/'report.json').read_bytes())
    delivery=Path(base['artifact_directory'])
    manifest=runs.sealed_json(delivery/'delivery_manifest.json',replay['source_manifest_sha256'])
    pop_key=runs.PREFIX+'/population_ledger.json'
    population=sorted(runs.sealed_json(delivery/pop_key,manifest[pop_key])['cves'])
    folder=item4_frozen_packets.stage(delivery,manifest,base['archive']['sha256'],population)
    seen=set()
    selected={}
    for cve in population:
        packet=runs.input_packet(folder,manifest,cve)
        for case in packet['cases']:
            if case['id'] in seen or case['cve']!=cve or case['synthetic'] is not True:
                raise ValueError('Duplicate, out-of-scope or non-synthetic case.')
            seen.add(case['id'])
        selected[cve]=manifest[f'{runs.PREFIX}/cves/{cve}.json']
    if (len(population),len(seen))!=(12418,97553):
        raise ValueError('The full population is incomplete.')
    pins={'v3 delivery manifest':replay['source_manifest_sha256'],'frozen CVE population':manifest[pop_key],
          'selected input packets':runs.sha(json.dumps(selected,sort_keys=True).encode()),
          'selected case IDs':runs.sha(json.dumps(sorted(seen),separators=(',',':')).encode())}
    for name in ('cisa_reference_manifest.json','cisa_advisories.json'):
        pins[name]=runs.file_sha(ROOT/'data'/name)
    for year in sorted({c.split('-')[1] for c in population}):
        name=f'records_{year}.json'
        pins[name]=runs.file_sha(runs.asset_vulntology.DATA/name)
    names=set(runs.CODE)|{'item4_frozen_packets','item4_moe_batch','item4_bulk_run','item4_vex_assessment',
                         'candidate_advisories','cpe23','llm_output_schema','model_paths','item4_nemotron_provider',
                         'item4_moe_h200'}
    code={n+'.py':runs.file_sha(source_path(n+'.py', root=ROOT)) for n in sorted(names)}
    code['src/__init__.py']=runs.file_sha(ROOT/'src/__init__.py')
    for command_source in ('tools/__init__.py','tools/common/paths.py'):
        code[command_source]=runs.file_sha(ROOT/command_source)
    pins['command layout']=runs.file_sha(ROOT/'tools/layout.json')
    pins['source layout']=runs.file_sha(ROOT/'src/layout.json')
    code['tools/item4/run_item4_nemotron.py']=runs.file_sha(Path(__file__))
    code['GPU runtime identity']=runs.sha(json.dumps(provider.identity,sort_keys=True).encode())
    models={**provider.identity['base_files_sha256'],**provider.identity['tokenizer_sha256']}
    spec=dict(generation_method='scenario_moe_h200_llm',total=len(seen),code_hashes=code,model_hashes=models,data_hashes=pins)
    if resume:
        record=runs.ledger.resume_run(resume,**spec)
    else:
        run_id='nemotron-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-')+uuid.uuid4().hex[:10]
        record=runs.ledger.start_run(run_id,**spec,resumable=True)
    return record,(folder,manifest,population,'all')


if __name__=='__main__':
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--manifest',type=Path,required=True)
    cli.add_argument('--port',type=int,default=18128)
    cli.add_argument('--resume')
    cli.add_argument('--batch-size',type=int,default=32)
    cli.add_argument('--chunk-size',type=int,default=128)
    cli.add_argument('--concurrency',type=int,default=8)
    args=cli.parse_args()
    if args.chunk_size<1 or not 1<=args.batch_size<=256 or not 1<=args.concurrency<=16:
        cli.error('Use a positive chunk size, batch size 1–256 and concurrency 1–16.')
    provider=NemotronBatch(args.port,args.manifest,concurrency=args.concurrency)
    record,plan=prepare(provider,args.resume)
    print(record['run_id'],flush=True)
    result=item4_bulk_run.execute(record,plan,resume=bool(args.resume),provider=provider,
                                 batch_size=args.batch_size,chunk_size=args.chunk_size)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    sys.exit(0 if result['status']=='completed' else 1)
