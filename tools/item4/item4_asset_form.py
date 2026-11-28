"""Generate/validate concrete operator inventory forms for one or more ICS asset types."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from src.item4.assets.operator_asset_form import build_form; from src.item4.assets.operator_asset_form import validate_input


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--asset-types',nargs='+',required=True)
    p.add_argument('--output',type=Path);p.add_argument('--input',type=Path);a=p.parse_args()
    form=build_form(a.asset_types)
    if a.input:
        data=json.loads(a.input.read_text(encoding='utf-8'))
        print(json.dumps(validate_input(form['definition'],data.get('input',data))))
    elif a.output:
        with a.output.open('x',encoding='utf-8') as stream:json.dump(form,stream,ensure_ascii=False,indent=2)
    else:p.error('--output or --input required')
