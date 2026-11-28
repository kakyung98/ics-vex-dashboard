"""Compatibility entrypoint; implementation: tools.common.ncp_service."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.common.entrypoints import execute_legacy
execute_legacy(__name__,'tools.common.ncp_service')
