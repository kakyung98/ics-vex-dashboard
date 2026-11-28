"""Domain packages, with a small facade for legacy `from src import module` callers."""
from importlib import import_module
from importlib.abc import Loader, MetaPathFinder
from importlib.util import spec_from_loader
import json
from pathlib import Path
import sys


_LAYOUT = json.loads((Path(__file__).parent/'layout.json').read_bytes())
_ALIASES = {
    'src.'+old[:-3].replace('/', '.'): 'src.'+new[:-3].replace('/', '.')
    for old, new in _LAYOUT.items()
    if '/' in old and old.endswith('.py') and old != new
}
_PACKAGE_ALIASES = {
    'src.item3.ics_agent_matcher_full': 'src.item3.matching',
    'src.item3.ics_agent_matcher_full.ics_agent_matcher': 'src.item3.matching',
    'src.ics_agent_matcher_full': 'src.item3.matching',
    'src.ics_agent_matcher_full.ics_agent_matcher': 'src.item3.matching',
}


class _LegacySourceLoader(Loader):
    """Old imports return the canonical module, including its shared state."""
    def __init__(self, target):
        self.target = target

    def create_module(self, spec):
        module = import_module(self.target)
        self.canonical_spec = module.__spec__
        return module

    def exec_module(self, module):
        # Import machinery assigns the legacy spec to the returned object.
        # Retain the real spec so reload(), tooling and resource APIs see its home.
        module.__spec__ = self.canonical_spec


class _LegacySourceFinder(MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        canonical = _ALIASES.get(fullname) or _PACKAGE_ALIASES.get(fullname)
        if canonical:
            return spec_from_loader(fullname, _LegacySourceLoader(canonical),
                                    is_package=fullname in _PACKAGE_ALIASES)


sys.meta_path.insert(0, _LegacySourceFinder())

def __getattr__(name):
    relative=_LAYOUT.get(name+'.py')
    if relative is None:raise AttributeError(name)
    module=import_module('src.'+relative[:-3].replace('/','.'))
    globals()[name]=module
    return module
