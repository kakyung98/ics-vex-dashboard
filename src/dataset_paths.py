"""Resolve maintained dataset locations without reviving retired directories."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OPERATIONAL_CURRICULUM=ROOT/'data/operational_curriculum_v3'
OPERATIONAL_BENCHMARK=ROOT/'data/operational_review_benchmark_v2'


def new_public_sbom_directory(root=None):
    from datetime import datetime,timezone
    return Path(root or ROOT)/'data/public_sbom'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')/'documents'


def public_sbom_directory(root=None):
    root=Path(root or ROOT).resolve()
    index=root/'sbom_index.json'
    if not index.is_file():raise FileNotFoundError('Public SBOM index is missing: '+str(index))
    relative=json.loads(index.read_text(encoding='utf-8')).get('source_directory')
    if not isinstance(relative,str) or not relative:raise ValueError('Public SBOM index has no source_directory.')
    directory=(root/relative).resolve()
    if not directory.is_relative_to((root/'data/public_sbom').resolve()):
        raise ValueError('Public SBOM source_directory must stay inside data/public_sbom.')
    if not directory.is_dir():raise FileNotFoundError('Indexed public SBOM snapshot is missing: '+str(directory))
    return directory


def public_sbom_file(name,root=None):
    if not isinstance(name,str) or Path(name).name!=name or '/' in name or '\\' in name or not name.endswith('.json'):
        raise ValueError('Provide a plain JSON SBOM filename.')
    path=public_sbom_directory(root)/name
    if not path.is_file():raise FileNotFoundError('Public SBOM is missing: '+name)
    return path
