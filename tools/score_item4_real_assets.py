"""Score separately annotated real ICS asset scopes; never synthesize labels."""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.item4_scoring import score
from src.training_io import atomic_json


def rows(path):
    text=path.read_text(encoding='utf-8-sig')
    if path.suffix.lower()=='.jsonl':return [json.loads(s) for s in text.splitlines() if s.strip()]
    value=json.loads(text)
    return value if isinstance(value,list) else [value]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--predictions',type=Path,required=True)
    parser.add_argument('--gold',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.resolve() in {args.predictions.resolve(),args.gold.resolve()}:
        parser.error('Output must not overwrite predictions or Gold')
    try:report=score(rows(args.predictions),rows(args.gold),target_percent=85)
    except (ValueError,KeyError,TypeError) as exc:parser.error(str(exc))
    report.update(synthetic=False,gold_path=str(args.gold.resolve()),predictions_path=str(args.predictions.resolve()))
    atomic_json(args.output,report)
    print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':main()
