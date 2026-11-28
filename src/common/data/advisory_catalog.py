"""Normalize the collected CISA records for the advisory browser."""
import json
import re
from pathlib import Path


def normalize_advisories(raw, root):
    root = Path(root)
    records = raw.items() if isinstance(raw, dict) else (('', a) for a in raw)
    result = []
    for key, original in records:
        a = dict(original)
        match = re.search(r'icsa-\d{2}-\d{3}-\d+[a-z]?', a.get('url', ''), re.I)
        aid = (a.get('advisory_id') or key or (match.group() if match else '')).upper()
        doc = {}
        slug = aid.lower()
        for folder in ('data/cisa_identification_csaf', 'icsa/csaf'):
            path = root / folder / (slug + '.json')
            if path.is_file():
                doc = json.loads(path.read_text(encoding='utf-8'))
                break
        document = doc.get('document', {})
        date = document.get('tracking', {}).get('initial_release_date') or a.get('publication_date')
        products = list(dict.fromkeys(p for p in a.get('products', []) if p))
        a.update(advisory_id=aid, title=a.get('title') or document.get('title', ''),
                 products=products, product_name='; '.join(products),
                 publication_date=date[:10] if date else None,
                 year=int(date[:4]) if date else a.get('year'))
        result.append(a)
    return result
