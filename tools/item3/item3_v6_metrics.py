"""Compatibility import for the relocated #3 metrics."""
import sys
from benchmark.item3_evaluation.evaluation import item3_v6_metrics as implementation
sys.modules[__name__]=implementation
