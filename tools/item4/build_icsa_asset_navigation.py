"""Keep the original 18 asset categories as advisory-first navigation."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from collections import defaultdict
import hashlib
import json

ROOT = Path(__file__).resolve().parents[2]


def build():
    folder = ROOT/'site/asset_vulntology'
    clusters = json.loads((folder/'icsa_role_groups.json').read_text(encoding='utf-8'))
    catalogue = json.loads((folder/'catalogue.json').read_text(encoding='utf-8'))
    by_id = {a['id']:a for a in clusters['advisories']}
    asset_ids = {a['asset_id'] for a in catalogue['assets']}
    links = defaultdict(set)
    evidence = defaultdict(list)
    hashes = {}
    for path in sorted(folder.glob('records_*.json')):
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        for record in json.loads(path.read_text(encoding='utf-8')).values():
            for product in record.get('products', []):
                aid = product.get('advisory_id')
                if aid not in by_id:
                    continue
                for category in product.get('asset_ids', []):
                    if category in asset_ids:
                        links[aid].add(category)
                        item = dict(asset_id=category, product_key=product['key'], product=product['name'],
                                    binding=product['binding'])
                        if item not in evidence[aid]:
                            evidence[aid].append(item)
    categories = []
    for asset in catalogue['assets']:
        members = [a for a in clusters['advisories'] if asset['asset_id'] in links[a['id']]]
        categories.append(dict(id=asset['asset_id'],name=asset['name'],
            advisory_ids=[a['id'] for a in members],advisory_count=len(members),
            cves=sorted({c for a in members for c in a['cves']}),
            cve_count=len({c for a in members for c in a['cves']})))
    unresolved = [a for a in clusters['advisories'] if not links[a['id']]]
    unknown = dict(id='unassigned',name='Asset type unassigned',
        advisory_ids=[a['id'] for a in unresolved],advisory_count=len(unresolved),
        cves=sorted({c for a in unresolved for c in a['cves']}),
        cve_count=len({c for a in unresolved for c in a['cves']}))
    result = dict(version='icsa-asset-navigation/1',categories=categories,unassigned=unknown,
        advisory_asset_ids={aid:sorted(links[aid]) for aid in by_id},
        advisory_product_evidence=dict(evidence),
        summary=dict(asset_types=18,advisories=len(by_id),cves=len(clusters['cve_memberships']),
                     unassigned_advisories=len(unresolved)),
        policy='Existing advisory-scoped product asset labels select ICSA records; linked CVEs are browsing associations, not newly asserted affected asset roles.',
        input_shard_sha256=hashes)
    assert len(categories)==18
    assert {aid for g in categories+[unknown] for aid in g['advisory_ids']}==set(by_id)
    text=json.dumps(result,ensure_ascii=False,separators=(',',':'))+'\n'
    (folder/'icsa_asset_navigation.json').write_text(text,encoding='utf-8')
    output=ROOT/'results/icsa_role_clusters_k18/asset_navigation.json'
    output.write_text(text,encoding='utf-8')
    # The running app reads this HTML on every request. Keep navigation usable
    # without restarting an unrelated SBOM/model service just to add a read API.
    inline=dict(categories=categories,unassigned=unknown,summary=result['summary'],
                advisory_product_evidence={})
    encoded=json.dumps(inline,ensure_ascii=False,separators=(',',':')).replace('<','\\u003c')
    html_path=ROOT/'src/item4/web/scoped_vex_review.html'
    html=html_path.read_text(encoding='utf-8')
    import re
    html=re.sub(r'<(?:script|div)[^>]*id="av-asset-navigation-data"[^>]*>.*?</(?:script|div)>\n?', '', html, flags=re.S)
    html=html.replace('<section id="av-workspace">','<section id="av-workspace">\n<div id="av-asset-navigation-data" hidden>'+encoded+'</div>',1)
    temp=html_path.with_name(html_path.name+'.codex-tmp');temp.write_text(html,encoding='utf-8');temp.replace(html_path)
    print(json.dumps(result['summary']))


if __name__=='__main__':
    build()
