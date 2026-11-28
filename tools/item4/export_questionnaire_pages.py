"""Export current questionnaire UI while preserving the GitHub Pages bridge."""
if __package__ in (None, ''):
    import sys
    from pathlib import Path
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]))

from pathlib import Path
import hashlib
import shutil
from bs4 import BeautifulSoup

ROOT=Path(__file__).resolve().parents[2]
PAGES=('item4.html','bom-vex.html','asset-vex.html','vex-decision.html')
ASSETS={'item4-questionnaire.js':'asset_vex_questionnaire_ui.js',
    'item4-question-tree.js':'operating_question_tree.js',
    'item4-cluster-diagnostics.js':'cluster_diagnostics_ui.js',
    'item4-evaluation.js':'source_evaluation_ui.js',
    'item4-operating-questions.css':'operating_questions.css'}


def export(output):
    from tools.item4.serve_nist_operational_vex import item4_page
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    soup=BeautifulSoup(item4_page().body.decode('utf-8'),'html.parser')
    for element in soup.find_all(True):
        for attribute in ('href','src'):
            value=element.get(attribute)
            if isinstance(value,str) and value.startswith('/') and not value.startswith('//'):
                element[attribute]=value[1:]
    bridge=ROOT/'site/pages-bridge.js'
    version=hashlib.sha256(bridge.read_bytes()).hexdigest()[:12]
    script=soup.new_tag('script',src='pages-bridge.js?v='+version,defer='')
    first=soup.body.find('script')
    if first:first.insert_before(script)
    else:soup.body.append(script)
    for name in PAGES:(output/name).write_text(str(soup),encoding='utf-8')
    if bridge.resolve()!=(output/'pages-bridge.js').resolve():shutil.copy2(bridge,output/'pages-bridge.js')
    for destination,source in ASSETS.items():shutil.copy2(ROOT/'src/item4/web'/source,output/destination)
    return list(PAGES)+list(ASSETS)+['pages-bridge.js']


if __name__=='__main__':
    import argparse,json
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,default=ROOT/'site')
    args=parser.parse_args();print(json.dumps(dict(files=export(args.output))))
