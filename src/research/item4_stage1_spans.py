"""BERT span extraction contracts, source adapters and aligned Cohen kappa.

Offsets use Python Unicode code points. No inferred logic or VEX decisions.
Heavy ML dependencies are loaded only by the training/inference module.
"""
from collections import Counter
import hashlib
import re

from src.research.reviewer_agreement import cohen_kappa

ROLES = ('necessary_condition', 'explicit_nonrequirement', 'conditional_context',
         'trigger', 'impact', 'mitigation', 'applicability', 'observed_context')
LABELS = ['O'] + [prefix + role for role in ROLES for prefix in ('B-', 'I-')]


def sha(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def units(text):
    """Fixed, model-independent evaluation units (non-whitespace words)."""
    return [(m.start(), m.end()) for m in re.finditer(r'\S+', text)]


def validate_record(row, annotated=False):
    for key in ('id', 'source_id', 'source_type', 'text', 'text_sha256', 'group_id'):
        if not isinstance(row.get(key), str) or not row[key].strip():
            raise ValueError('Missing nonempty field: ' + key)
    if row['source_type'] not in {'ICSA', 'CVE'}:
        raise ValueError('source_type must be ICSA or CVE')
    if sha(row['text']) != row['text_sha256']:
        raise ValueError('Source hash mismatch: ' + row['id'])
    if not isinstance(row.get('cves'), list) or any(
            not isinstance(c, str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}', c) for c in row['cves']):
        raise ValueError('cves must contain explicit CVE IDs')
    if annotated and (row.get('annotation_complete') is not True or not row.get('annotator')):
        raise ValueError('Completed human annotation with annotator identity required')
    spans = row.get('spans', [])
    if not isinstance(spans, list):
        raise ValueError('spans must be an array')
    boundaries = units(row['text']); starts = {a for a, _ in boundaries}; ends = {b for _, b in boundaries}
    last = 0
    for span in sorted(spans, key=lambda s: s['start']):
        a, b = span['start'], span['end']
        if type(a) is not int or type(b) is not int or not 0 <= a < b <= len(row['text']):
            raise ValueError('Invalid Unicode span offsets')
        if a < last or a not in starts or b not in ends:
            raise ValueError('Spans must be nonoverlapping and align to whole whitespace words')
        if span.get('role') not in ROLES or span.get('quote') != row['text'][a:b]:
            raise ValueError('Invalid role or non-exact quote')
        last = b
    return row


def bio(row):
    validate_record(row)
    result = ['O'] * len(units(row['text']))
    positions = units(row['text'])
    for span in row.get('spans', []):
        inside = [i for i, (a, b) in enumerate(positions) if span['start'] <= a and b <= span['end']]
        for n, i in enumerate(inside):
            result[i] = ('B-' if n == 0 else 'I-') + span['role']
    return result


def decode(row, labels):
    positions = units(row['text'])
    if len(labels) != len(positions) or any(x not in LABELS for x in labels):
        raise ValueError('Prediction labels must align with every source word')
    spans = []
    previous = None
    for (a, b), label in zip(positions, labels):
        if label == 'O':
            previous = None
            continue
        role = label[2:]
        # Invalid I transitions start a new span; never drop source coverage.
        if label.startswith('B-') or previous != role:
            spans.append(dict(start=a, end=b, role=role, quote=row['text'][a:b]))
        else:
            spans[-1].update(end=b, quote=row['text'][spans[-1]['start']:b])
        previous = role
    return spans


def check_splits(train, dev, test):
    """Reject shared advisories, CVEs, records or exact texts across splits."""
    seen = {}
    for name, rows in [('train', train), ('dev', dev), ('test', test)]:
        local_ids = set()
        for row in rows:
            validate_record(row, annotated=True)
            if row['id'] in local_ids:
                raise ValueError('Duplicate record ID: ' + row['id'])
            local_ids.add(row['id'])
            keys = [('id', row['id']), ('group', row['group_id']), ('source', row['source_id']),
                    ('text', sha(' '.join(row['text'].split()).casefold()))]
            keys += [('cve', c) for c in row['cves']]
            for key in keys:
                if key in seen and seen[key] != name:
                    raise ValueError('Split leakage: ' + repr(key))
                seen[key] = name


def evaluate(gold, predictions):
    """Nominal unweighted kappa; O is a real label, never a missing rating."""
    def index(rows):
        result = {}
        for row in rows:
            validate_record(row)
            if row['id'] in result:
                raise ValueError('Duplicate evaluation ID')
            result[row['id']] = row
        return result
    a, b = index(gold), index(predictions)
    if a.keys() != b.keys():
        raise ValueError('Evaluation IDs must match exactly; no dropped documents')
    left, right = [], []
    counts = Counter()
    for key in sorted(a):
        validate_record(a[key], annotated=True)
        if b[key].get('prediction_complete') is not True:
            raise ValueError('Full prediction coverage must be explicit')
        for field in ('text', 'text_sha256', 'source_id', 'source_type', 'group_id', 'cves'):
            if a[key][field] != b[key][field]:
                raise ValueError('Evaluation alignment mismatch: ' + field)
        x, y = bio(a[key]), bio(b[key]); left.extend(x); right.extend(y)
        counts[a[key]['source_type']] += len(x)
    role = lambda x: x[2:] if x != 'O' else x
    roles_a, roles_b = list(map(role, left)), list(map(role, right))
    positives_a = {(r['id'], s['start'], s['end'], s['role']) for r in gold for s in r['spans']}
    positives_b = {(r['id'], s['start'], s['end'], s['role']) for r in predictions for s in r['spans']}
    tp = len(positives_a & positives_b)
    return dict(schema='item4-bert-evaluation/1', unit='whole whitespace word; Unicode offsets',
                documents=len(a), units_by_source_type=dict(counts),
                primary_role_kappa=cohen_kappa(roles_a, roles_b),
                boundary_bio_kappa=cohen_kappa(left, right),
                exact_span=dict(true_positive=tp, gold=len(positives_a), predicted=len(positives_b),
                                f1=2*tp/(len(positives_a)+len(positives_b)) if positives_a or positives_b else None),
                warning='Kappa is agreement with human labels, not proof of semantic truth; inspect O prevalence and confusion.')


def annotation_records(payload, source_id=None, url=''):
    """Adapt local CISA aggregate, CSAF, CVE JSON 5 and NVD CVE JSON.

    Shared advisory text stays advisory-scoped, never duplicated as CVE truth.
    """
    output = []
    def add(sid, kind, text, cves, group, pointer, product_refs=None):
        if not isinstance(text, str) or not text.strip():
            return
        output.append(dict(id=sid + ':' + sha(pointer)[:12], source_id=sid,
            source_type=kind, url=url, source_json_pointer=pointer, text=text,
            text_sha256=sha(text), group_id=group, cves=sorted(set(cves)),
            product_refs=product_refs or [], scope_status='requires_human_review',
            annotation_complete=False, annotator=None, spans=[]))
    if 'document' in payload and 'vulnerabilities' in payload:
        sid = source_id or payload['document']['tracking']['id']
        self_urls = [r['url'] for r in payload['document'].get('references', [])
                     if r.get('category') == 'self' and r.get('url')]
        if not url:
            url = next((u for u in self_urls if 'cisa.gov/news-events/ics-advisories/' in u), '')
        all_cves = [v['cve'] for v in payload['vulnerabilities'] if v.get('cve')]
        for i, note in enumerate(payload['document'].get('notes', [])):
            add(sid, 'ICSA', note.get('text'), all_cves, sid, f'/document/notes/{i}/text')
        for i, vuln in enumerate(payload['vulnerabilities']):
            for j, note in enumerate(vuln.get('notes', [])):
                add(sid, 'ICSA', note.get('text'), [vuln['cve']] if vuln.get('cve') else [], sid,
                    f'/vulnerabilities/{i}/notes/{j}/text', vuln.get('product_status', {}).get('known_affected'))
            for j, rem in enumerate(vuln.get('remediations', [])):
                add(sid, 'ICSA', rem.get('details'), [vuln['cve']] if vuln.get('cve') else [], sid,
                    f'/vulnerabilities/{i}/remediations/{j}/details', rem.get('product_ids'))
        for row in output:
            row['source_urls'] = self_urls
    elif 'cveMetadata' in payload:
        cve = payload['cveMetadata']['cveId']; sid = source_id or cve
        containers = payload.get('containers', {})
        for name, container in [('cna', containers.get('cna', {}))] + [
                (f'adp/{i}', value) for i, value in enumerate(containers.get('adp', []))]:
            for j, desc in enumerate(container.get('descriptions', [])):
                add(sid, 'CVE', desc.get('value'), [cve], cve, f'/containers/{name}/descriptions/{j}/value')
    elif 'descriptions' in payload and 'id' in payload:
        cve = payload['id']; sid = source_id or cve
        for j, desc in enumerate(payload['descriptions']):
            add(sid, 'CVE', desc.get('value'), [cve], cve, f'/descriptions/{j}/value')
    elif 'vulnerabilities' in payload:
        for item in payload['vulnerabilities']:
            output.extend(annotation_records(item['cve'], url=url))
    elif 'affected_text' in payload:
        sid = source_id or payload['advisory_id']
        add(sid, 'ICSA', payload['affected_text'], payload.get('cves', []), sid, '/affected_text')
    elif payload and all(isinstance(v, dict) and 'affected_text' in v for v in payload.values()):
        for key, value in payload.items():
            rows = annotation_records(value, source_id=key, url=value.get('url', ''))
            output.extend(rows)
    else:
        raise ValueError('Unsupported source JSON; expected CISA aggregate, CSAF, CVE JSON 5 or NVD')
    for row in output:
        validate_record(row)
    return output
