"""Plan or run the active CVE-description extractor across the fixed target population."""
from pathlib import Path
import argparse
import json
import sys

ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from src.item4.workflow.source_analysis_jobs import description_packet
from src.item4.analysis import exploitation_prerequisites as V
from src.item4.evaluation.cvss_extraction_scoring import score


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True,help='New output directory')
    parser.add_argument('--run-llm',action='store_true',help='Actually invoke the configured extraction model; without this option create a plan only')
    parser.add_argument('--limit',type=int,default=0,help='Explicit smoke-test limit; zero keeps the full target population')
    parser.add_argument('--gold',type=Path,help='Optional independently human-reviewed, source-pinned condition gold JSONL')
    args=parser.parse_args()
    if args.limit<0:parser.error('--limit must be nonnegative')
    args.output.mkdir(parents=True,exist_ok=False)
    targets=[]
    for path in sorted((ROOT/'site/asset_vulntology').glob('records_*.json')):
        targets.extend(json.loads(path.read_text(encoding='utf-8')))
    if len(set(targets))!=len(targets):raise ValueError('Duplicate target CVE')
    selected=sorted(targets)[:args.limit or None]
    manifest=dict(version='item4-cvss-source-extraction/1',target_cves=len(targets),selected_cves=len(selected),
        full_population=len(selected)==len(targets),llm_requested=args.run_llm,phase='running' if args.run_llm else 'planned',
        source_policy='CVE description only',gold_used_in_extraction=False,historical_predictions_reused=False)
    (args.output/'run.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    if not args.run_llm:
        (args.output/'selected_cves.json').write_text(json.dumps(selected,indent=2),encoding='utf-8')
        print(json.dumps(manifest));return
    rows=[]
    with (args.output/'extractions.jsonl').open('w',encoding='utf-8') as stream:
        for cve in selected:
            row=dict(cve=cve,status='unresolved',source_record_sha256=None)
            try:
                packet=description_packet(cve)
                if packet.get('status')=='unresolved':row['error']=packet.get('reason')
                else:
                    row['source_record_sha256']=V.digest(packet)
                    # No reference labels, expected answers or prior predictions are provided.
                    row.update(status='extracted',artifact=V.extract(packet))
            except Exception as error:row['error']=type(error).__name__+': '+str(error)[:500]
            rows.append(row);stream.write(json.dumps(row,ensure_ascii=False)+'\n');stream.flush()
            manifest.update(completed_cves=len(rows),failed_cves=sum(r['status']!='extracted' for r in rows))
            (args.output/'run.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    gold=[json.loads(line) for line in args.gold.read_text(encoding='utf-8').splitlines() if line.strip()] if args.gold else []
    report=score(rows,gold);report.update(run=manifest,llm_requested=True,independent_gold_available=bool(gold))
    manifest['phase']='completed';report['run']=manifest
    (args.output/'run.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    (args.output/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='run'},ensure_ascii=False))


if __name__=='__main__':main()
