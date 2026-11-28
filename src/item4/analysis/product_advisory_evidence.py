"""Resolve declared CVEs to product-scoped local ICSA evidence without item #3."""
from copy import deepcopy
import hashlib
import json
import re
from src.item4.decision import scoped_vex_review as A
from src.item3.evidence.cisa_advisory_lookup import structured_product_match; from src.item3.evidence.cisa_advisory_lookup import vendor_key; from src.item3.evidence.cisa_advisory_lookup import words
from src.common.data.cpe_parser import formatted_parts
from src.common.source_version_parser import membership, version_predicate

STATUS_POLICY = 'csaf-product-status/3'
PRODUCT_STATUSES = ('known_affected', 'fixed', 'known_not_affected', 'under_investigation')
PROVENANCE_FIELDS = ('source_file', 'status_pointer', 'product_pointer', 'document_sha256')


def cpes(value):
    result = [value['cpe']] if isinstance(value.get('cpe'), str) else []
    result += [r.get('referenceLocator', '') for r in value.get('externalRefs', [])
               if isinstance(r, dict) and r.get('referenceType') in {'cpe22Type', 'cpe23Type'}]
    return sorted({c for c in result if c.startswith(('cpe:2.3:', 'cpe:/'))})


def component_identity(component):
    value = component['value']
    vendor = value.get('manufacturer') or value.get('supplier') or value.get('originator') or ''
    if isinstance(vendor, dict):
        vendor = vendor.get('name', '')
    if str(vendor).strip().casefold() in {'unknown', 'unspecified', 'noassertion', '-'}:
        vendor = ''
    return dict(ref=component['ref'], name=component['name'],
                version=value.get('version') or value.get('versionInfo'),
                vendor=vendor, cpes=cpes(value))


def cpe_family(cpe):
    fields = re.split(r'(?<!\\):', cpe)
    if cpe.startswith('cpe:2.3:') and len(fields) == 13:
        family = fields[2:5]
    elif cpe.startswith('cpe:/') and len(fields) >= 4:
        family = [fields[1][1:], *fields[2:4]]
    else:
        return None
    return tuple(family) if all(f and f not in {'*', '-'} for f in family) else None


def unverified_cpe_scope(product, identity):
    # The family match alone does not establish edition/platform restrictions.
    for cpe in product['cpes']:
        fields = formatted_parts(cpe)
        if not fields:
            if cpe not in identity['cpes']:
                return True
        else:
            if fields[5] != '*' and fields[5] != identity['version']:
                return True
            if any(field != '*' for field in fields[6:]) and cpe not in identity['cpes']:
                return True
    return False


def clearance_identity(identity, product, families, exact_cpe):
    if len(families) > 1:
        return False
    for cpe in identity['cpes']:
        fields = formatted_parts(cpe)
        if fields and fields[5] not in {'*', identity['version']}:
            return False
    if exact_cpe:
        return True
    name = words(identity['name'])
    qualified_name = words(product['vendor']+' '+product['name'])
    vendor_matches = vendor_key(identity['vendor']) == vendor_key(product['vendor'])
    return bool(product['vendor'] and product['name'] and (
        name == qualified_name or (vendor_matches and name == words(product['name']))))


def source_products(document):
    out = {}
    duplicates = set()
    def walk(branches, pointer, vendor='', name='', version='', qualified=False):
        for i, branch in enumerate(branches):
            location = f'{pointer}/{i}'
            category = branch.get('category')
            restricted = qualified or category not in {'vendor','product_family','product_name','product_version','product_version_range'}
            ve = branch.get('name', '') if category == 'vendor' else vendor
            na = branch.get('name', '') if category == 'product_name' else name
            ver = branch.get('name', '') if category in {'product_version', 'product_version_range'} else version
            product = branch.get('product')
            if product:
                helper = product.get('product_identification_helper', {})
                if product['product_id'] in out:
                    duplicates.add(product['product_id'])
                out[product['product_id']] = dict(vendor=ve, name=na, version=ver,
                    product_pointer=location+'/product', qualified=restricted,
                    cpes=[helper['cpe']] if helper.get('cpe') else [])
            walk(branch.get('branches', []), location+'/branches', ve, na, ver, restricted)
    walk(document.get('product_tree', {}).get('branches', []), '/product_tree/branches')
    for pid in duplicates:
        del out[pid]
    return out


def status_rows(document, cve):
    for i, vuln in enumerate(document.get('vulnerabilities', [])):
        if vuln.get('cve') == cve:
            for status in PRODUCT_STATUSES:
                for j, pid in enumerate(vuln.get('product_status', {}).get(status, [])):
                    yield pid, status, f'/vulnerabilities/{i}/product_status/{status}/{j}'


def _document(aid, detail):
    """Only read the two local mirrors of an advisory explicitly indexed for this CVE."""
    if aid not in detail.get('advisory_ids', []) or not re.fullmatch(r'icsa-\d{2}-\d{3}-\d+[a-z]?', aid):
        return None
    sources = [s for s in detail.get('sources', []) if s.get('id', '').startswith(aid + ':')]
    pins = {s['document_sha256'] for s in sources if s.get('document_sha256')}
    if not pins:
        from src.item3.evidence.cisa_advisory_lookup import source_records
        pins = {source_records().get(aid, {}).get('source_raw_sha256')}
    if len(pins) != 1 or None in pins:
        return None
    for directory in ('icsa/csaf', 'data/cisa_identification_csaf'):
        path = A.ROOT / directory / (aid + '.json')
        if not path.is_file():
            continue
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest not in pins:
            continue
        try:
            document = json.loads(raw)
        except (UnicodeError, ValueError):
            continue
        if not isinstance(document, dict) or not isinstance(document.get('vulnerabilities'), list):
            continue
        return path, digest, document, sources
    return None


def _product_evidence_id(cve, key, status, fields):
    source = [cve, key, status, fields['document_sha256'], fields['status_pointer'], fields['product_pointer']]
    wire = json.dumps(source, ensure_ascii=False, separators=(',', ':')).encode()
    return 'v1-' + hashlib.sha256(wire).hexdigest()


def verified_product_claims(record):
    """Source-only V1 references. Validate the selected CVE entry and product tree against pinned bytes."""
    cve = record['cve']
    products = [p for p in record['products'] if all(p.get(field) for field in PROVENANCE_FIELDS)]
    if not products:
        return {}
    try:
        detail = A.detail(cve)
    except KeyError:
        return {}
    if detail.get('original_nvd_status') == 'Rejected':
        return {}
    authorities = {}
    claims = {}
    for product in products:
        key = product['key']
        aid, _, pid = key.partition(':')
        if aid not in authorities:
            pinned = _document(aid, detail)
            if pinned:
                path, digest, document, _ = pinned
                authorities[aid] = (path, digest, source_products(document), set(status_rows(document, cve)))
            else:
                authorities[aid] = None
        if not authorities[aid]:
            continue
        path, digest, tree, rows = authorities[aid]
        status = product.get('status')
        entry = tree.get(pid)
        if (not entry or product['document_sha256'] != digest
                or product['source_file'].replace('\\', '/') != path.relative_to(A.ROOT).as_posix()
                or product['product_pointer'] != entry['product_pointer']
                or (pid, status, product['status_pointer']) not in rows
                or product.get('version', product.get('version_text')) != entry['version']):
            continue
        fields = {field: product[field] for field in PROVENANCE_FIELDS}
        eid = _product_evidence_id(cve, key, status, fields)
        claims[eid] = dict(product_evidence_id=eid, vep_category='V1', product_key=key,
                           source_status=status, source_fields=fields)
    return claims


def lookup(cve, components, *, source_issues=None):
    """CVE narrows sources; a separate product match is always required."""
    try:
        detail = A.detail(cve)
    except KeyError:
        return dict(cve=cve, products=[], sources=[], matches=[])
    if detail.get('original_nvd_status') == 'Rejected':
        return dict(cve=cve, products=[], sources=[], matches=[])
    matches = []; products = {}; sources = {}
    for aid in detail.get('advisory_ids', []):
        pinned = _document(aid, detail)
        if not pinned:
            if source_issues is not None:
                source_issues.append({'advisory_id': aid, 'reason': 'missing_or_unverified_source'})
            continue
        path, digest, document, advisory_sources = pinned
        scoped = [s for s in advisory_sources if s.get('document_sha256') == digest and not s.get('subject_ambiguous')]
        tree = source_products(document)
        rows = list(status_rows(document, cve))
        if source_issues is not None and any(pid not in tree for pid, _, _ in rows):
            source_issues.append({'advisory_id': aid, 'reason': 'unresolved_supplier_product_id'})
        for component in components:
            identity = component_identity(component)
            for pid, status, status_pointer in rows:
                product = tree.get(pid)
                if not product:
                    continue
                vendor = vendor_key(product['vendor'])
                if identity['vendor'] and vendor_key(identity['vendor']) != vendor:
                    continue
                families = {cpe_family(c) for c in identity['cpes']} - {None}
                product_families = {cpe_family(c) for c in product['cpes']} - {None}
                exact_cpe = bool(families & product_families)
                if families and product_families and not exact_cpe:
                    continue
                name_match = (words(identity['name']) in {words(product['name']), words(product['vendor']+' '+product['name'])}
                              or structured_product_match(identity['name'], vendor, product['name']))
                if not (exact_cpe or name_match):
                    continue
                key = aid+':'+pid
                supporting = [s for s in scoped if key in s.get('product_keys', [])]
                state = membership(version_predicate(product['version']), identity['version'] or '')
                if state == 'true' and (product['qualified'] or unverified_cpe_scope(product, identity)):
                    state = 'unknown'
                if (state == 'true' and (source_issues is not None or status in {'fixed', 'known_not_affected'})
                        and not clearance_identity(identity, product, families, exact_cpe)):
                    state = 'unknown'
                # A version mismatch is reported and cannot supply extraction context.
                match = dict(component_ref=identity['ref'], component=identity, cve=cve,
                    advisory_id=aid, url=next((s['url'] for s in scoped if s.get('url')),
                        'https://www.cisa.gov/news-events/ics-advisories/'+aid), product_key=key,
                    product_match='CPE vendor/product identity' if exact_cpe else 'product name and vendor scope',
                    source_version=product['version'], version_membership=state,
                    document_sha256=digest, source_ids=[s['id'] for s in supporting],
                    status=status,source_product_id=pid,source_file=path.relative_to(A.ROOT).as_posix(),
                    product_pointer=product['product_pointer'],status_pointer=status_pointer)
                matches.append(match)
                if state == 'false' or status != 'known_affected' or not supporting:
                    continue
                products[key] = dict(key=key, aliases=[product['name'], product['vendor']+' '+product['name']],
                    status=status, source_file=match['source_file'],status_pointer=status_pointer,
                    document_sha256=digest,**product)
                sources.update({s['id']:deepcopy(s) for s in supporting})
    return dict(cve=cve, products=list(products.values()), sources=list(sources.values()), matches=matches)


def verified_version_evidence(cve, component):
    """Re-read pinned supplier statements for one BOM component independently of any model output."""
    from src.item4.decision.asset_vex_assessment import concrete

    identity = component_identity(component)
    issues = []
    context = lookup(cve, [component], source_issues=issues)
    evidence = []
    for row in context['matches']:
        eid = _product_evidence_id(cve, row['product_key'], row['status'], row)
        evidence.append(dict(row, evidence_id=eid))

    states = {row['status'] for row in evidence if row['version_membership'] == 'true'}
    reasons = [issue['reason'] for issue in issues]
    state = 'unknown'
    if not concrete(identity['version']):
        reasons.append('missing_or_nonconcrete_build')
    elif len(states) > 1:
        state = 'conflicting'
        reasons.append('conflicting_supplier_statuses')
    elif any(row['version_membership'] == 'unknown' for row in evidence):
        reasons.append('unresolved_version_or_product_qualifier')
    elif not states:
        reasons.append('no_in_scope_supplier_status')
    elif not issues:
        state = next(iter(states))
    return dict(cve=cve, component_ref=identity['ref'], version=identity['version'], state=state,
                evidence=evidence, reasons=sorted(set(reasons)), source_issues=issues)


def packet(cve, declarations):
    context = lookup(cve, declarations)
    return dict(cve=cve, products=context['products'], sources=context['sources']), context


def scenarios_for(result, ref):
    scenarios = result.get('prerequisite', {}).get('draft', {}).get('scenarios', [])
    context = result.get('advisory_context')
    if not context:
        return scenarios
    if result.get('description_fallback'):
        return []
    keys = {m['product_key'] for m in context['matches']
            if m['component_ref'] == ref and m['version_membership'] == 'true' and m.get('status') == 'known_affected'}
    return [s for s in scenarios if keys.intersection(s.get('product_keys', []))]
