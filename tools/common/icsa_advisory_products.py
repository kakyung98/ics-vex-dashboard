"""Preserve source product/version records without requiring a CVE or CPE."""
import hashlib
import json
import re
from pathlib import Path
from bs4 import BeautifulSoup
from tools.common.icsa_html_product_corrections import PRODUCTS

ROOT = Path(__file__).resolve().parents[2]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def clean(value):
    return re.sub(r'\s+', ' ', value or '').strip()


def source_vendor(record, text):
    vendor = record.get('vendor') or 'unknown'
    # Expand cached prefixes only when the full entity is in this source.
    expansions = {'rockwell':['Rockwell Automation'], 'wind':['Wind River Systems'],
        'scada':['SCADA Engine'], 'agg':['AGG Software'], 'inductive':['Inductive Automation'],
        'certec':['Certec EDV GmbH'], 'beijer':['Beijer Electronics'],
        'schneider':['Schneider Electric'], 'saia':['Saia Burgess Controls','Saia-Burgess Controls']}
    for full in expansions.get(vendor.casefold(),[]):
        if full.casefold() in text.casefold():return full
    return vendor


def product_vendor(name, advisory_vendor, text):
    # A multi-vendor advisory must not stamp its primary ICS vendor onto Windows.
    if re.match(r'^(?:Microsoft )?(?:Windows|SQL Server|Active Directory)\b', name, re.I) and re.search(r'\bMicrosoft\b',text):
        return 'Microsoft'
    if re.match(r'^(?:Siemens )?(?:SIMATIC(?:®)? )?(?:Siemens )?(?:WinCC|Step ?7)\b',name,re.I) and re.search(r'\bSiemens\b',text):
        return 'Siemens'
    if name.casefold()=='clearscada' and 'control microsystems' in text.casefold():return 'Control Microsystems'
    if name=='SCX' and 'Serck UK' in text:return 'unknown'
    if name=='NTP' and 'Network Time Foundation' in text:return 'unknown'
    # The aggregate exploit-pack advisory's GLEG is not every target's maker.
    if advisory_vendor=='GLEG':
        makers=[('Indusoft','Indusoft'),('Automated Solutions','Automated Solutions'),
            ('BACnet OPC client','SCADA Engine'),('Advantech','Advantech'),('ICONICS','ICONICS'),
            ('BECK GMBH','BECK GMBH'),('SafeNet','SafeNet'),('Sentinel Keys Server','SafeNet'),
            ('SCADA MOXA','MOXA'),('Ecava','Ecava'),('GE Fanuc','GE Fanuc'),
            ('Citect','Citect'),('Invensys','Invensys'),('DATAC','DATAC')]
        if name=='OPC Modbus Ethernet OPC Server' and 'Automated Solutions' in text:return 'Automated Solutions'
        for prefix,maker in makers:
            if name.casefold().startswith(prefix.casefold()) and maker.casefold() in text.casefold():return maker
        return 'unknown'
    return advisory_vendor


def product_rows(csaf):
    """Keep every named product leaf, including ranges, fixed and unaffected products."""
    rows = []

    def walk(branches, trail=()):
        for i, branch in enumerate(branches):
            path = trail + ((branch.get('category'), branch.get('name')),)
            prod = branch.get('product')
            if prod:
                names = [n for c, n in path if c in ('product_name', 'product_family', 'model')]
                vendors = [n for c, n in path if c == 'vendor']
                versions = [n for c, n in path if c in ('product_version', 'product_version_range')]
                name = names[-1] if names else prod['name']
                label = prod.get('name', name)
                version = versions[-1] if versions else 'unknown'
                # Prefer the literal human-readable expression to a CSAF vers encoding.
                if label.startswith(name + ':'):
                    version = label[len(name) + 1:].strip() or version
                rows.append({'name': name, 'version': version, 'vendor': vendors[-1] if vendors else 'unknown',
                             'source_product_id': prod.get('product_id', ''), 'source_label': label,
                             'source_version_expression': versions[-1] if versions else 'unknown',
                             'source_path': list(path), 'source_kind': 'csaf-product-tree',
                             'helpers': prod.get('product_identification_helper', {})})
            elif branch.get('category') == 'product_name' and not branch.get('branches'):
                rows.append({'name': branch['name'], 'version': 'unknown', 'vendor': next((n for c,n in reversed(path) if c=='vendor'), 'unknown'),
                             'source_product_id': '', 'source_label': branch['name'], 'source_path': list(path),
                             'source_kind': 'csaf-product-name-without-version'})
            walk(branch.get('branches', []), path)

    tree = csaf.get('product_tree', {})
    walk(tree.get('branches', []))
    for prod in tree.get('full_product_names', []) + [r['full_product_name'] for r in tree.get('relationships', []) if 'full_product_name' in r]:
        if any(r['source_product_id'] == prod.get('product_id') for r in rows):
            continue
        rows.append({'name': prod['name'], 'version': 'unknown', 'vendor': 'unknown',
                     'source_product_id': prod.get('product_id', ''), 'source_label': prod['name'],
                     'source_kind': 'csaf-full-product-name', 'helpers': prod.get('product_identification_helper', {})})
    return rows


def split_statement(text):
    """Separate an explicit version delimiter; never turn a range into an installed release."""
    text = clean(text).strip(' ;')
    text = re.sub(r'[,;]?\s+and\s*$', '', text).strip(' ,;')
    m = re.match(r'^([^:]+):\s*(.+)$', text)
    if not m:
        m = re.match(r'^(.+?)\s+(?:[Ff]irmware\s+)?[Vv]ersions?\s*:?\s+(.+)$', text)
    if m and re.search(r'\d|all versions|prior|earlier|through', m[2], re.I):
        version = re.sub(r'\s+(?:is|are) affected.*$', '', m[2], flags=re.I)
        version = re.sub(r'[,;]?\s+and\s*$', '', version)
        return m[1].strip(' ,:'), version.strip(' .,;')
    m = re.match(r'^(.+?)\s+\((all versions[^)]*|v\d[^)]*)\)', text, re.I)
    if m:
        return m[1].strip(' ,'), m[2]
    m = re.match(r'^(.+?)\s+(all (?:firmware )?versions.*|prior to [Vv]ersion .*)$', text, re.I)
    if m:
        return m[1], m[2].rstrip('.')
    return text.rstrip('.'), 'unknown'


def html_rows(aid, record, cache):
    """Read the actual affected-product section, which older affected_text caches omitted."""
    if not cache.exists():
        return [], [], 'source-unavailable'
    soup = BeautifulSoup(cache.read_bytes(), 'html.parser')
    root = soup.select_one('.csaf-imported') or soup.select_one('main') or soup
    full_text = clean(root.get_text(' ', strip=True))
    vendor = source_vendor(record, full_text)
    statements = []
    contexts = []
    for heading in root.find_all(['h2', 'h3', 'h4']):
        if not re.search(r'AFFECTED\s+(?:PRODUCTS|VERSIONS|SOFTWARE|SYSTEMS|OPERATING SYSTEMS)', heading.get_text(' ', strip=True), re.I):
            continue
        current_context = ''
        for node in heading.next_siblings:
            if getattr(node, 'name', '') in ('h2', 'h3', 'h4'):
                if int(node.name[1]) <= int(heading.name[1]):
                    break
                # Update markers inside the affected-products section are not its end.
                if re.search(r'(?:Begin|End) Update', node.get_text(' ', strip=True), re.I):
                    continue
            if not hasattr(node, 'get_text'):
                continue
            leaves = [li for li in node.find_all('li') if not li.find('li')] if getattr(node, 'name', '') in ('ul', 'ol') else []
            if getattr(node, 'name', '') == 'table':
                leaves = node.find_all('tr')
            for leaf in leaves or [node]:
                text = clean(leaf.get_text(' ', strip=True))
                ancestor = leaf.find_parent('li') if getattr(leaf, 'name', '') == 'li' else None
                context = clean(' '.join(c.get_text(' ', strip=True) if hasattr(c,'get_text') else str(c)
                                        for c in ancestor.contents if getattr(c,'name','') not in ('ul','ol'))) if ancestor else current_context
                if text:
                    statements.append(text)
                    contexts.append(context)
                if not leaves and text and len(text) < 100 and not re.search(r'following|versions|affected|Update|https?://',text,re.I):
                    current_context = text.rstrip(':')
    rows = []
    if aid in PRODUCTS:
        for name, version in PRODUCTS[aid]:
            assert name.casefold() in full_text.casefold(), (aid, 'product not in source', name)
            assert version == 'unknown' or version.casefold() in full_text.casefold(), (aid, 'version not in source', version)
            at = full_text.casefold().index(name.casefold())
            rows.append({'name': name, 'version': version, 'vendor': product_vendor(name,vendor,full_text),
                         'vendor_original_cached_value': record.get('vendor') or 'unknown',
                         'source_product_id': '', 'source_label': full_text[max(0,at-100):at+1000],
                         'source_kind': 'html-source-anchored-correction', 'source_path': 'main',
                         'source_html_sha256': hashlib.sha256(cache.read_bytes()).hexdigest()})
        if aid=='icsa-10-070-01a':
            assert 'RSHWare.exe' in full_text and '1.0.4.0' in full_text
            for row in rows:
                if row['name']=='EDS Hardware Installation Tool':
                    row['alternate_names']=['RSHWare.exe']
                    row['source_observed_versions']=['1.0.4.0']
                    row['observed_version_scope']='executable version observed in RSLinx Classic 2.41.00; not a second affected-product range'
        return rows, statements, 'html-source-anchored-correction'
    for i, text in enumerate(statements):
        # Introductory prose is retained as context, never mistaken for a product.
        if re.search(r'(?:Begin|End) Update', text, re.I):
            continue
        if text.endswith(':'):
            continue
        if re.search(r'^Please refer|^https?://|^Directory Traversal Vulnerability$', text, re.I):
            continue
        context = contexts[i]
        if re.match(r'^(?:V\d|All versions)',text,re.I) and context:
            name, version = context, text.strip(' .,;')
        else:
            name, version = split_statement(text)
        if re.match(r'^FRN\s+\d', context):
            version = context + '; ' + version
        rows.append({'name': name, 'version': version, 'vendor': product_vendor(name,vendor,full_text),
                     'source_product_id': '', 'source_label': text, 'source_kind': 'html-affected-products',
                     'source_path': f'AFFECTED PRODUCTS/statement/{i}',
                     'source_context': context,
                     'parse_review_required': version == 'unknown' or len(name) > 180})
    return rows, statements, 'html-affected-products' if rows else 'no-product-section'


def extract(aid, record, csaf=None):
    if csaf is not None:
        rows = product_rows(csaf)
        # Preserve structured product labels even if the CSAF tree is incomplete.
        for label in record.get('affected_products', []):
            if not any(r['source_label'] == label for r in rows):
                name, version = split_statement(label)
                rows.append({'name': name, 'version': version, 'vendor': record.get('vendor') or 'unknown',
                             'source_label': label, 'source_product_id': '', 'source_kind': 'advisory-affected-products'})
        for name in record.get('products', []):
            if not any(r['name'] == name for r in rows):
                rows.append({'name': name, 'version': 'unknown', 'vendor': record.get('vendor') or 'unknown',
                             'source_label': name, 'source_product_id': '', 'source_kind': 'advisory-products'})
        return rows, [], 'csaf-product-tree' if rows else 'no-product-tree'
    return html_rows(aid, record, ROOT/'data/icsa_sbom_source_html'/f'{aid}.html')
