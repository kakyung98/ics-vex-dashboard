"""Lossless, offline ICSA/CVE source bundles for stage 1; no condition inference."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

VERSION = 'item4-stage1/1'
CVE = re.compile(r'CVE-\d{4}-\d{4,}\Z')


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def text_hash(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def unique(values):
    return sorted(set(values))


def seal(value, key):
    value[key] = digest({k: v for k, v in value.items() if k != key})
    return value


def verify_seal(value, key):
    if value.get(key) != digest({k: v for k, v in value.items() if k != key}):
        raise ValueError(key + ' mismatch')


def _products(payload, source_id):
    """Keep exact CSAF product names and their ancestry; do not parse versions."""
    rows = {}

    def add(product, pointer, ancestry):
        pid = product.get('product_id')
        if not isinstance(pid, str) or not pid:
            return
        if pid in rows:
            raise ValueError('Duplicate CSAF product_id: ' + pid)
        rows[pid] = dict(id=source_id + ':' + pid, native_id=pid,
                         name=product.get('name', ''), ancestry=ancestry,
                         source_id=source_id, source_json_pointer=pointer)

    tree = payload.get('product_tree', {})

    def walk(branches, pointer, ancestry):
        for i, branch in enumerate(branches):
            p = f'{pointer}/{i}'
            path = ancestry + [dict(category=branch.get('category', ''), name=branch.get('name', ''))]
            if 'product' in branch:
                add(branch['product'], p + '/product', path)
            walk(branch.get('branches', []), p + '/branches', path)

    walk(tree.get('branches', []), '/product_tree/branches', [])
    for i, product in enumerate(tree.get('full_product_names', [])):
        add(product, f'/product_tree/full_product_names/{i}', [])
    for i, relation in enumerate(tree.get('relationships', [])):
        if 'full_product_name' in relation:
            add(relation['full_product_name'], f'/product_tree/relationships/{i}/full_product_name', [])
    return rows


def source_document(raw, filename=''):
    """One original JSON document. Source and text hashes have different meanings."""
    payload = json.loads(raw.decode('utf-8-sig'))
    sha = hashlib.sha256(raw).hexdigest()
    sid = 'source-' + sha
    segments, bindings, cves = [], [], set()
    products = _products(payload, sid) if 'document' in payload else {}
    refs = payload.get('document', {}).get('references', [])
    urls = unique(r['url'] for r in refs if isinstance(r.get('url'), str))
    unknown_product_refs = set()

    def add(text, pointer, role, scoped_cves, product_refs=(), binding_pointer=None):
        if not isinstance(text, str) or not text.strip():
            return
        scoped_cves = unique(scoped_cves)
        if any(not CVE.fullmatch(c) for c in scoped_cves):
            raise ValueError('Invalid explicit CVE ID')
        cves.update(scoped_cves)
        segid = 'segment-' + digest([sid, pointer])
        bids = []
        for cve in scoped_cves:
            for pid in product_refs or [None]:
                if pid is not None and pid not in products:
                    unknown_product_refs.add(pid)
                    continue
                bound_product = products[pid]['id'] if pid is not None else None
                binding = dict(source_id=sid, segment_id=segid, cve=cve,
                               product_id=bound_product,
                               source_json_pointer=binding_pointer or pointer,
                               kind='explicit_vulnerability_scope' if role != 'advisory_context' else 'advisory_membership_only')
                binding['id'] = 'binding-' + digest(binding)
                bindings.append(binding); bids.append(binding['id'])
        segments.append(dict(id=segid, source_id=sid, source_json_pointer=pointer,
                             text=text, text_sha256=text_hash(text), source_role=role,
                             cves=scoped_cves,
                             product_ids=unique(products[p]['id'] for p in product_refs if p in products),
                             binding_ids=bids))

    def descriptions(container, pointer, cve):
        for j, desc in enumerate(container.get('descriptions', [])):
            add(desc.get('value'), f'{pointer}/descriptions/{j}/value',
                'cve_description', [cve], binding_pointer=pointer)

    if 'document' in payload and 'vulnerabilities' in payload:
        kind = 'ICSA_CSAF'
        advisory_id = payload['document'].get('tracking', {}).get('id', filename)
        all_cves = unique(v['cve'] for v in payload['vulnerabilities'] if v.get('cve'))
        cves.update(all_cves)
        for i, note in enumerate(payload['document'].get('notes', [])):
            add(note.get('text'), f'/document/notes/{i}/text', 'advisory_context', all_cves)
        for i, vuln in enumerate(payload['vulnerabilities']):
            scoped = [vuln['cve']] if vuln.get('cve') else []
            affected = vuln.get('product_status', {}).get('known_affected', [])
            for j, note in enumerate(vuln.get('notes', [])):
                role = 'mitigation' if note.get('category') == 'mitigation' else 'cve_description'
                add(note.get('text'), f'/vulnerabilities/{i}/notes/{j}/text', role,
                    scoped, affected, f'/vulnerabilities/{i}')
            for j, rem in enumerate(vuln.get('remediations', [])):
                add(rem.get('details'), f'/vulnerabilities/{i}/remediations/{j}/details',
                    'mitigation', scoped, rem.get('product_ids', []), f'/vulnerabilities/{i}')
    elif 'cveMetadata' in payload:
        kind = 'CVE5'; advisory_id = payload['cveMetadata']['cveId']
        cves.add(advisory_id)
        containers = payload.get('containers', {})
        descriptions(containers.get('cna', {}), '/containers/cna', advisory_id)
        for i, adp in enumerate(containers.get('adp', [])):
            descriptions(adp, f'/containers/adp/{i}', advisory_id)
        # CVE affected-product interpretation is not silently borrowed from CSAF.
    elif 'id' in payload and 'descriptions' in payload:
        kind = 'NVD_CVE'; advisory_id = payload['id']; cves.add(advisory_id)
        descriptions(payload, '', advisory_id)
    else:
        raise ValueError('Unsupported source; use individual CSAF, CVE5 or NVD CVE JSON')
    if any(not isinstance(c, str) or not CVE.fullmatch(c) for c in cves):
        raise ValueError('Invalid document CVE ID')
    return dict(document=dict(id=sid, document_sha256=sha, filename=filename,
                              kind=kind, advisory_id=advisory_id, urls=urls,
                              cves=sorted(cves)), products=list(products.values()),
                segments=segments, bindings=bindings,
                warnings=[dict(code='unresolved_product_ref', native_id=p) for p in sorted(unknown_product_refs)])


def build_bundle(paths, target_cves=None):
    documents, products, segments, bindings, ledger = [], [], [], [], []
    seen = set()
    for path in sorted(map(Path, paths)):
        try:
            raw = path.read_bytes()
        except OSError as exc:
            ledger.append(dict(file=str(path), status='source_unavailable', error=type(exc).__name__))
            continue
        try:
            row = source_document(raw, str(path))
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            ledger.append(dict(file=str(path), document_sha256=hashlib.sha256(raw).hexdigest(),
                               status='parse_failed', error=str(exc)))
            continue
        sid = row['document']['id']
        if sid in seen:
            ledger.append(dict(file=str(path), source_id=sid, status='duplicate_source'))
            continue
        seen.add(sid)
        documents.append(row['document']); products.extend(row['products'])
        segments.extend(row['segments']); bindings.extend(row['bindings'])
        ledger.append(dict(file=str(path), source_id=sid, status='prepared', warnings=row['warnings']))
    observed = unique(c for d in documents for c in d['cves'])
    population = unique(target_cves if target_cves is not None else observed)
    if any(not isinstance(c, str) or not CVE.fullmatch(c) for c in population):
        raise ValueError('Invalid target population')
    bycve = {c: [] for c in population}
    for s in segments:
        if s['source_role'] == 'cve_description':
            for c in s['cves']:
                if c in bycve:
                    bycve[c].append(s['id'])
    return seal(dict(contract_version=VERSION, documents=documents, products=products,
                     segments=segments, bindings=bindings, source_ledger=ledger,
                     population=population,
                     cve_ledger=[dict(cve=c, status='source_prepared' if bycve[c] else 'no_cve_specific_passage',
                                      segment_ids=bycve[c]) for c in population]), 'bundle_sha256')


def resolve_pointer(payload, pointer):
    value = payload
    for part in pointer.split('/')[1:]:
        part = part.replace('~1', '/').replace('~0', '~')
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def audit_sources(bundle):
    """Compare prepared text and structured scope against original source bytes."""
    verify_seal(bundle, 'bundle_sha256')
    errors, payloads, expected = [], {}, {}
    for doc in bundle['documents']:
        try:
            raw = Path(doc['filename']).read_bytes()
            if hashlib.sha256(raw).hexdigest() != doc['document_sha256']:
                raise ValueError('document_sha256 mismatch')
            row = source_document(raw, doc['filename'])
            if row['document'] != doc:
                raise ValueError('document metadata mismatch')
            payloads[doc['id']] = json.loads(raw.decode('utf-8-sig'))
            for key in ('segments', 'products', 'bindings'):
                expected.setdefault(key, []).extend(row[key])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(dict(source_id=doc['id'], error=str(exc)))
    for key in ('segments', 'products', 'bindings'):
        if expected.get(key, []) != bundle[key]:
            errors.append(dict(collection=key, error='original_source_reconstruction_mismatch'))
    return dict(passed=not errors, errors=errors, documents=len(bundle['documents']),
                provenance_only=True, semantic_accuracy_verified=False)
