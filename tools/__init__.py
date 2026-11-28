"""Command domains; keep legacy `from tools import command` imports compatible."""
from importlib import import_module
import json
from pathlib import Path

def __getattr__(name):
    layout=json.loads((Path(__file__).parent/'layout.json').read_bytes())
    relative=layout.get(name+'.py')
    if relative is None:raise AttributeError(name)
    module=import_module('tools.'+relative[:-3].replace('/','.'))
    globals()[name]=module
    return module
