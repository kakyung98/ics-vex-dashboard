"""Locate the same pinned Hugging Face snapshot after a cache relocation."""
import os
from pathlib import Path


def pinned_base(marker):
    recorded=Path(marker['base'])
    if recorded.is_dir():
        return recorded
    # Never replace a missing base with another repository/revision. The
    # runtime subsequently verifies every recorded base-file SHA-256.
    parts=recorded.parts
    if 'hub' not in parts or not marker.get('base_files_sha256'):
        raise FileNotFoundError('Pinned model base is unavailable: '+str(recorded))
    relative=Path(*parts[parts.index('hub')+1:])
    hubs=[]
    if os.environ.get('HF_HUB_CACHE'):
        hubs.append(Path(os.environ['HF_HUB_CACHE']))
    if os.environ.get('HF_HOME'):
        hubs.append(Path(os.environ['HF_HOME'])/'hub')
    for hub in hubs:
        candidate=hub/relative
        if candidate.is_dir() and all((candidate/name).is_file() for name in marker['base_files_sha256']):
            return candidate
    raise FileNotFoundError('Pinned model snapshot is absent from the recorded and configured cache paths')
