"""Compatibility entry; implementation lives with the #3 benchmark."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from benchmark.item3_evaluation.evaluation import run_item3_test as implementation
if __name__=='__main__':raise SystemExit(implementation.main())
sys.modules[__name__]=implementation
