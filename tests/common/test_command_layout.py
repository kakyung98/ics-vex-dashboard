"""The domain layout must keep dispatch, legacy imports and standalone CLI working."""
import importlib
from pathlib import Path
import subprocess
import sys

import pytest
from tools.common.paths import PROJECT_ROOT, tool_module, tool_path


def test_command_dispatch_resolves_old_names_and_canonical_paths():
    target='tools.item4.run_item4_nemotron'
    assert tool_module('run_item4_nemotron')==target
    assert tool_module('tools/item4/run_item4_nemotron.py')==target
    assert tool_path('run_item4_nemotron.py')==PROJECT_ROOT/'tools/item4/run_item4_nemotron.py'
    with pytest.raises(ValueError):tool_path('../README.md')


def test_old_and_canonical_imports_share_state():
    canonical=importlib.import_module('tools.item4.run_item4_nemotron')
    assert importlib.import_module('tools.run_item4_nemotron') is canonical


def test_legacy_cli_works_outside_the_repository(tmp_path):
    command=PROJECT_ROOT/'tools/run_item4_nemotron.py'
    result=subprocess.run([sys.executable,'-B',str(command),'--help'],cwd=tmp_path,
                          capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    assert '--manifest' in result.stdout
