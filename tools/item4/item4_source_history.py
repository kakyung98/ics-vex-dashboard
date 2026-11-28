"""Locate exact producer bytes when replaying a fingerprinted, historical #4 run."""
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / 'research_records/item4_v2_source_snapshot'


def pinned_source(path, expected):
    relative = Path(path).resolve().relative_to(ROOT)
    for candidate in (ROOT / relative, SNAPSHOT / relative):
        if candidate.is_file() and hashlib.sha256(candidate.read_bytes()).hexdigest() == expected:
            return candidate
    raise ValueError('Missing pinned source for ' + str(relative))
