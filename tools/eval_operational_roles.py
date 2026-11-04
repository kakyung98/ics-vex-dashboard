"""Score frozen predictions against separately adjudicated test references."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.operational_evaluation import evaluate_assessments,evaluate_questions

def main():
    p=argparse.ArgumentParser();p.add_argument('--role',choices=['questions','assessment'],required=True)
    p.add_argument('--gold',type=Path,required=True);p.add_argument('--predictions',type=Path,required=True)
    p.add_argument('--question-reviews',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    def read(path):return [json.loads(l) for l in path.read_text(encoding='utf-8').splitlines() if l.strip()]
    gold=read(a.gold)
    if not gold or any(r.get('split')!='test' for r in gold):raise ValueError('Provide independently adjudicated held-out test rows only.')
    if a.role=='questions':
        if not a.question_reviews:raise ValueError('--question-reviews is required; no LLM-as-judge scoring.')
        result=evaluate_questions(gold,read(a.predictions),read(a.question_reviews))
    else:result=evaluate_assessments(gold,read(a.predictions))
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
