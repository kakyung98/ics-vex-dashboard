"""Refresh the browser-only English presentation without changing stored answers."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import json
import csv
import gzip
from pathlib import Path
from src.research.item4_asset_english import presentation


def main():
    root = Path(__file__).resolve().parents[2]
    path = root / 'src/item4/web/asset_vex_questionnaire_ui.js'
    groups = {}
    with gzip.open(root / 'data/operator_asset_keys.csv.gz', 'rt', encoding='utf-8-sig', newline='') as source:
        for row in csv.DictReader(source):
            groups.setdefault(row['asset_type_id'], []).append(dict(
                asset_type_id=row['asset_type_id'], key=row['key'],
                yes_criterion=row['o_판정기준'], no_criterion=row['x_판정기준']))
    text = path.read_text(encoding='utf-8')
    start = '/* ASSET_ENGLISH_PRESENTATION_START */'
    end = '/* ASSET_ENGLISH_PRESENTATION_END */'
    data = json.dumps(presentation({'asset_types': groups}), ensure_ascii=True, separators=(',', ':'))
    block = start + '\nconst assetEnglish=' + data + ';\n' + end
    text = text[:text.index(start)] + block + text[text.index(end) + len(end):]
    path.write_text(text, encoding='utf-8')


if __name__ == '__main__':
    main()
