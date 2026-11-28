"""Representative asset classification from product-bound CISA advisory evidence."""
from functools import lru_cache
from src.item3.evidence.cisa_advisory_lookup import advisory_index; from src.item3.evidence.cisa_advisory_lookup import structured_product_match; from src.item3.evidence.cisa_advisory_lookup import vendor_key; from src.item3.evidence.cisa_advisory_lookup import words
from src.item4.decision.scoped_vex_review import asset_navigation

VERSION = 'asset-classification-agent/1'

def representative(bom):
    if bom.get('bomFormat') == 'CycloneDX':
        return (bom.get('metadata') or {}).get('component') or {}, '/metadata/component'
    if str(bom.get('spdxVersion', '')).startswith('SPDX-2.'):
        ids = bom.get('documentDescribes') or []
        packages = [p for p in bom.get('packages', []) if p.get('SPDXID') in ids]
        if len(ids) == 1 and len(packages) == 1:
            return packages[0], '/packages/' + str(bom['packages'].index(packages[0]))
    return {}, None

def _name(value):
    return value.get('name', '') if isinstance(value, dict) else str(value or '')

@lru_cache(maxsize=128)
def _match(name, vendor):
    nav = asset_navigation()
    vendor = vendor_key(vendor)
    if not vendor or len(words(name)) < 4:
        return ()
    found = []
    for aid, row, affected in advisory_index().get(vendor, []):
        url = row.get('url', '')
        if not url.startswith('https://www.cisa.gov/news-events/ics-advisories/'):
            continue
        phrase = words(name)
        if phrase.startswith(vendor + ' '): phrase = phrase[len(vendor) + 1:]
        products = [p for p in row.get('products', []) if structured_product_match(name, vendor, p)]
        if not products and (len(phrase) < 10 or len(phrase.split()) < 2 or ' ' + phrase + ' ' not in ' ' + affected + ' '): continue
        detail = nav.get('assignment_details', {}).get(aid, {})
        asset = detail.get('asset_id')
        found.append(dict(asset_type_id=asset, advisory_id=aid, url=url,
            matched_product=products[0] if products else name,
            product_match='vendor-scoped CSAF product family' if products else 'vendor-scoped affected-product phrase',
            classification_status=detail.get('status', 'unreviewed'),
            classification_evidence=(detail.get('literal_evidence') or detail.get('term_contributions') or [])[:3]))
    return tuple(found)

def classify(bom):
    asset, pointer = representative(bom)
    name = _name(asset.get('name'))
    vendor = _name(asset.get('manufacturer')) or _name(asset.get('supplier')) or _name(asset.get('originator'))
    evidence = list(_match(name, vendor)) if name and vendor else []
    types = sorted({e['asset_type_id'] for e in evidence if e.get('asset_type_id')})
    from src.item4.assets.asset_classification_inference import predict
    if not name:
        prediction = dict(status='unresolved', asset_type_id=None, reason='representative_missing')
    elif len(types)>1:
        prediction = dict(status='conflicting', asset_type_id=None, reason='conflicting_advisory_classifications')
    else:
        try:
            prediction = predict(name, evidence)
        except (OSError, ValueError, ImportError) as error:
            prediction = dict(status='unresolved', asset_type_id=None, reason='model_unavailable', detail=str(error))
    state = prediction['status']
    return dict(version=VERSION, status=state, asset_type_id=prediction['asset_type_id'], prediction=prediction,
        candidate_types=types, representative=dict(name=name, vendor=vendor, pointer=pointer),
        evidence=evidence, source_scope='Local CISA ICSA/CSAF snapshots; vendor advisories not separately retrieved',
        policy='Existing model inference is provisional collection context, not proof of installation, exploitability or VEX status.')
