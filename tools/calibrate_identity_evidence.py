"""Propose validation thresholds only; no model/weak/test gold accepted."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.identity_calibration import calibrate
from src.training_io import atomic_json

def main():
    p=argparse.ArgumentParser();p.add_argument('--validation',type=Path,required=True)
    p.add_argument('--minimum-precision',type=float,default=.99);p.add_argument('--minimum-accepted',type=int,default=50)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if not 0<a.minimum_precision<=1 or a.minimum_accepted<1:raise ValueError('Invalid acceptance requirement.')
    rows=[json.loads(l) for l in a.validation.read_text(encoding='utf-8').splitlines() if l.strip()]
    result=calibrate(rows,minimum_precision=a.minimum_precision,minimum_accepted=a.minimum_accepted)
    atomic_json(a.output,result);print(json.dumps(result,indent=2))

if __name__=='__main__':main()
