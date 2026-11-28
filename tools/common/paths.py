"""Resolve maintained commands/tests without depending on a flat repository tree."""
from functools import lru_cache
import json
from pathlib import Path

PROJECT_ROOT=Path(__file__).resolve().parents[2]

@lru_cache(maxsize=2)
def _layout(family):
    return json.loads((PROJECT_ROOT/family/'layout.json').read_bytes())

def _path(family,name,root):
    root=Path(root) if root is not None else PROJECT_ROOT
    name=str(name).replace('\\','/')
    if name.startswith(family+'/'):name=name[len(family)+1:]
    if Path(name).is_absolute() or '..' in Path(name).parts:raise ValueError('Path must stay inside '+family)
    original=root/family/name
    if root.resolve()!=PROJECT_ROOT and original.is_file():return original
    return root/family/_layout(family).get(name,name)

def tool_path(name, *, root=None):return _path('tools',name,root)

def test_path(name, *, root=None):return _path('tests',name,root)

def tool_module(name):
    name=str(name).replace('\\','/')
    if name.startswith('tools/'):name=name[6:]
    name=name.removesuffix('.py')+'.py'
    if Path(name).is_absolute() or '..' in Path(name).parts:raise ValueError('Invalid command path.')
    relative=_layout('tools').get(name,name)
    if not (PROJECT_ROOT/'tools'/relative).is_file():raise ValueError('Unknown command: '+name)
    return 'tools.'+relative.removesuffix('.py').replace('/','.')
