"""Share legacy CLI/import forwarding without duplicate command state."""
from importlib import import_module
import runpy
import sys

def execute_legacy(name,target):
    if name=='__main__':
        runpy.run_module(target,run_name='__main__',alter_sys=True)
    else:
        sys.modules[name]=import_module(target)
