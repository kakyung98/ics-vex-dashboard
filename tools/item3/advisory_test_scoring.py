"""Compatibility import for the relocated #3 scorer."""
import sys
from benchmark.item3_evaluation.evaluation import advisory_test_scoring as implementation
sys.modules[__name__]=implementation
