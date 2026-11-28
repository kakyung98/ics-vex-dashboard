"""Compatibility entrypoint; implementation: tools.common.runtime_release."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.common.entrypoints import execute_legacy
execute_legacy(__name__,'tools.common.runtime_release')
