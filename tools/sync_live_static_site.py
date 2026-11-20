"""Export the currently running local website, including its active workflow.

Only public pages/resources are exported. Analysis jobs, uploaded BOMs and
operator answers remain on the connected backend.
"""
from argparse import ArgumentParser
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen
import hashlib
from copy import deepcopy
import json
import re

from bs4 import BeautifulSoup
from src.web_locale import english_ui

PAGES = ['index.html', 'vex-decision.html', 'bom-vex.html', 'item4.html',
         'dataset.html', 'ics-sbom.html', 'source.html', 'published-vex.html']
SNAPSHOTS = {'api/summary': 'cve_level.json', 'api/by_year': 'by_year.json',
             'api/advisories': 'advisories.json', 'api/advisories/list': 'advisories_list.json',
             'api/sbom_index': 'sbom_index.json', 'api/published_vex': 'published_vex.json'}
ALIASES = {'asset-vex.html': 'vex-decision.html', 'context-vex.html': 'vex-decision.html',
           'vex-method.html': 'vex-decision.html', 'icsa-cpe-sbom.html': 'ics-sbom.html',
           'corpus.html': 'source.html', 'collectable.html': 'source.html'}
BANNER = '''<section class="card" id="pages-backend" style="margin-bottom:22px">
<h2>Analysis backend</h2><p class="hint" id="pages-backend-status">Public data is available. Connect the local backend for analysis.</p>
<div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center">
<label for="pages-backend-url">Backend URL</label><input id="pages-backend-url" type="url" value="http://127.0.0.1:8100" autocomplete="off">
<button class="primary" id="pages-backend-connect">Connect</button><button id="pages-backend-disconnect" hidden>Disconnect</button>
<a id="pages-open-local" href="http://127.0.0.1:8100" target="_blank" rel="noopener">Open local site</a></div></section>'''


def export(base, output):
    output.mkdir(parents=True, exist_ok=True)
    files = {}
    def get(path):
        with urlopen(base.rstrip('/') + '/' + path, timeout=30) as response:
            return response.read()
    def write(name, data):
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        files[name] = hashlib.sha256(data).hexdigest()
    for name in PAGES:
        raw = get(name)
        soup = BeautifulSoup(english_ui(raw.decode('utf-8')), 'html.parser')
        soup.html['lang'] = 'en'
        soup.html['translate'] = 'no'
        # The running service can repair an older shell in the browser. Export
        # that same shared chrome directly so the static page is self-contained.
        main = soup.select_one('main.main')
        if name != 'index.html':
            reference = BeautifulSoup((output / 'index.html').read_text(encoding='utf-8'), 'html.parser')
            for selector in ('.workspace-topbar', '.foot'):
                element = reference.select_one('main.main > ' + selector)
                if element and not main.select_one(':scope > ' + selector):
                    if selector == '.workspace-topbar':
                        main.insert(0, deepcopy(element))
                    else:
                        main.append(deepcopy(element))
        # Fetch the very scripts referenced by the active local server, rather
        # than assuming the older api_server.make_page is the current UI.
        for tag in soup.find_all(['script', 'link', 'img', 'a']):
            for attr in ('src', 'href'):
                value = tag.get(attr)
                if not value:
                    continue
                url = urlsplit(value)
                if url.scheme or url.netloc or not url.path.startswith('/') or url.path.startswith('/api/'):
                    continue
                relative = value.lstrip('/') or 'index.html'
                tag[attr] = relative
                if tag.name == 'script' and attr == 'src':
                    data = get(url.path.lstrip('/'))
                    write(url.path.lstrip('/'), data)
                    tag[attr] = url.path.lstrip('/') + '?v=' + hashlib.sha256(data).hexdigest()[:12]
        # Page-to-page handoff URLs inside the active scripts must also remain
        # relative under the GitHub Pages repository prefix.
        for script in soup.find_all('script'):
            if not script.get('src') and script.string:
                script.string = re.sub(r"([\"'])/([a-zA-Z0-9_.-]+\.html)", r'\1\2', script.string)
        if not soup.find(id='pages-backend'):
            main = soup.select_one('main.main')
            anchor = main.select_one(':scope > .workspace-topbar')
            banner = BeautifulSoup(BANNER, 'html.parser').section
            if anchor:
                anchor.insert_after(banner)
            else:
                main.insert(0, banner)
        bridge_hash = hashlib.sha256((output / 'pages-bridge.js').read_bytes()).hexdigest()[:12]
        bridge = soup.new_tag('script', src='pages-bridge.js?v=' + bridge_hash)
        soup.head.append(bridge)
        html = '\n'.join(line.rstrip() for line in str(soup).splitlines()) + '\n'
        write(name, html.encode('utf-8'))
    for alias, canonical in ALIASES.items():
        write(alias, (output / canonical).read_bytes())
    for endpoint, filename in SNAPSHOTS.items():
        data = get(endpoint)
        json.loads(data)
        write(filename, data)
    report = dict(exported_at=datetime.now(timezone.utc).isoformat(), source=base,
                  workflow='item4-asset-key-input', files=files,
                  private_analysis_state_exported=False)
    (output / 'live-site-sync.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(dict(pages=len(PAGES)+len(ALIASES), resources=len(files), output=str(output))))


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--base', default='http://127.0.0.1:8100')
    parser.add_argument('--output', type=Path, default=Path('site'))
    args = parser.parse_args()
    export(args.base, args.output)
