from bs4 import BeautifulSoup
from tools.item4.export_questionnaire_pages import export,ASSETS,PAGES,ROOT


def test_export_preserves_pages_bridge_and_project_relative_resources(tmp_path):
    files=export(tmp_path)
    assert 'pages-bridge.js' in files
    for page in PAGES:
        soup=BeautifulSoup((tmp_path/page).read_text(encoding='utf-8'),'html.parser')
        scripts=[s['src'].split('?')[0] for s in soup.find_all('script',src=True)]
        assert scripts[0]=='pages-bridge.js'
        assert scripts.index('item4-question-tree.js')<scripts.index('item4-questionnaire.js')
        assert all(not element[attr].startswith('/') for element in soup.find_all(True)
            for attr in ('href','src') if isinstance(element.get(attr),str))
    for destination,source in ASSETS.items():
        assert (tmp_path/destination).read_bytes()==(ROOT/'src/item4/web'/source).read_bytes()
