"""Compatibility import for the relocated #3 split helpers."""
import sys
from benchmark.item3_evaluation.evaluation import item3_splits as implementation
sys.modules[__name__]=implementation
