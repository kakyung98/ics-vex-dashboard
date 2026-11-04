import importlib.util
from pathlib import Path
import pytest


@pytest.mark.parametrize('product',[r'xerces-c\+\+',r'product\:edition',r'path\\'])
def test_feed_preserves_escaped_cpe_fields(monkeypatch,product):
    root=Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(root/'tools'))
    spec=importlib.util.spec_from_file_location('feed_codec_under_test',root/'tools/refresh_cpe_feed.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    name='cpe:2.3:a:vendor:'+product+':1.0:*:*:*:*:*:*:*'
    parts=module.cpe_parts(name)
    assert len(parts)==13 and parts[4]==product and ':'.join(parts)==name
    assert module.cpe_parts('not-a-cpe')==[]
