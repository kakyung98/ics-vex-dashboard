"""Run a maintained command: python -m tools <old-name-or-path> [arguments]."""
import runpy
import sys
from tools.common.paths import tool_module

if len(sys.argv)<2 or sys.argv[1] in {'-h','--help'}:
    print('Usage: python -m tools <command> [arguments]\nDomains: item3, item4, common')
    raise SystemExit(0)
command=sys.argv.pop(1)
try:module=tool_module(command)
except ValueError as exc:raise SystemExit(str(exc)) from exc
runpy.run_module(module,run_name='__main__',alter_sys=True)
