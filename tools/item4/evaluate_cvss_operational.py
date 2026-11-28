"""Replay retired CVSS question/logic contracts from the historical archive."""
from pathlib import Path
import argparse
import json
import sys

ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from src.item4.evaluation.cvss_operational_benchmark import run,population_index,DATA


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases',type=Path,default=DATA/'cases.jsonl')
    parser.add_argument('--output',type=Path,required=True,help='New output directory')
    parser.add_argument('--population-index',action='store_true',help='Index all target CVEs without model calls or invented gold labels')
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    cases=[json.loads(line) for line in args.cases.read_text(encoding='utf-8').splitlines() if line.strip()]
    report=run(cases)
    if args.population_index:
        counts=dict(cves=0,with_supported_cvss=0,with_description=0,model_extractions_run=0,independent_gold_labels=0)
        with (args.output/'population.jsonl').open('w',encoding='utf-8') as stream:
            for row in population_index():
                counts['cves']+=1;counts['with_supported_cvss']+=bool(row['cvss_assessments']);counts['with_description']+=row['description_available']
                stream.write(json.dumps(row,ensure_ascii=False)+'\n')
        report['population_index']=counts
    (args.output/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},ensure_ascii=False))
    return 0 if report['correct']==report['cases'] else 1


if __name__=='__main__':raise SystemExit(main())
