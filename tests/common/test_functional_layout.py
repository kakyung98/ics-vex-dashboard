"""Functional regrouping preserves shared modules, roots and colocated UI assets."""
import importlib
import json
from pathlib import Path

from src.common.paths import PROJECT_ROOT, source_path


def test_every_relocated_source_resolves_from_its_old_path():
    manifest = json.loads((PROJECT_ROOT/'results/functional_layout_20261123/manifest.json').read_text())
    for old, new in manifest['moves'].items():
        assert source_path(old) == source_path(new)
        assert source_path(old).is_file()


def test_legacy_imports_share_runtime_state_and_canonical_specs():
    for old, new in [
        ('src.item3.identity_versions', 'src.item3.evidence.version_evidence'),
        ('src.item4.item4_run_ledger', 'src.item4.evaluation.evaluation_run_records'),
        ('src.common.model_paths', 'src.common.runtime.model_paths'),
    ]:
        legacy = importlib.import_module(old)
        current = importlib.import_module(new)
        assert legacy is current
        assert current.__spec__.name == new


def test_project_roots_and_sibling_ui_resources_survive_relocation():
    from src.item4.assets import operating_profile_catalog as nist_table_profiles
    from src.item4.web.scoped_vex_review_page import widget_parts
    assert nist_table_profiles.ROOT == PROJECT_ROOT
    html, script = widget_parts()
    assert '<' in html and '<script>' in script
    assert (source_path('item4_questionnaire.py').parent.parent/'web/asset_vex_questionnaire.html').is_file()
