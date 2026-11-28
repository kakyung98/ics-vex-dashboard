"""Update the existing development-site evidence page without restarting it."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse
from hashlib import sha256
import json
from pathlib import Path

from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[2]


def install(live_home):
    source = ROOT/'site/nist-operating-information.html'
    target = live_home/'derivation.html'
    report = ROOT/'results/nist_information_20261118'
    backup = report/'before_167'
    backup.mkdir(parents=True, exist_ok=True)
    names = ['derivation.html', 'operating_profiles.html', 'bom_workflow.html']
    for name in names:
        saved = backup/name
        if not saved.exists():
            saved.write_bytes((live_home/name).read_bytes())
    old = BeautifulSoup(target.read_text(encoding='utf-8'), 'html.parser')
    page = BeautifulSoup(source.read_text(encoding='utf-8'), 'html.parser')
    legacy = old.find(id='profile-derivation')
    if legacy:
        legacy = legacy.extract()
    else:
        legacy = page.new_tag('section', id='profile-derivation')
        heading = page.new_tag('h2')
        heading.string = 'Existing asset-profile derivation (82 candidate fields)'
        legacy.append(heading)
        for part in list(old.find_all('section')):
            legacy.append(part.extract())
    assert len(legacy.find_all('details')) == 82
    page.main.append(legacy)
    page.find(id='catalog-rows')['id'] = 'nist-source-catalogue'
    page.find('a', string='Asset profile derivation')['href'] = '#profile-derivation'
    assert len(page.select('.source-row')) == 54
    assert len(page.select('.collection-element')) == 167
    assert not page.select('.source-row details')
    combined = str(page)
    target.write_text(combined, encoding='utf-8')
    # Retain the complete rendered page alongside source data in the project.
    (ROOT/'site/operating-profile-derivation.en.html').write_text(combined, encoding='utf-8')
    for name in names[1:]:
        path = live_home/name
        markup = BeautifulSoup(path.read_text(encoding='utf-8'), 'html.parser')
        banner = markup.find(id='nist-source-link')
        if banner is None:
            banner = markup.new_tag('p', id='nist-source-link')
            banner['class'] = 'op-note'
            markup.find(['h1', 'h2']).insert_after(banner)
        banner.clear()
        link = markup.new_tag('a', href='/operating-profile-derivation.en.html#nist-source-catalogue', target='_blank', rel='noopener')
        strong = markup.new_tag('strong')
        strong.string = 'NIST source catalogue · 54 original items · 167 collection elements · Full English evidence ↗'
        link.append(strong)
        banner.append(link)
        banner.append(markup.new_tag('br'))
        banner.append('v0.4 · Collection IDs, Korean information labels, English excerpts, source columns, table/page references, and interpretation notes.')
        path.write_text(str(markup), encoding='utf-8')
    manifest = {str(live_home/name): sha256((live_home/name).read_bytes()).hexdigest() for name in names}
    (report/'live_files.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps(dict(source_rows=54, collection_elements=167, live_page=str(target), restart_required=False)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--live-home', required=True, type=Path)
    install(parser.parse_args().live_home)
