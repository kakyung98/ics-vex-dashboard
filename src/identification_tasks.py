"""Shared contracts for the README's three generative identification agents."""
import json
import re

SYSTEM = 'You are an ICS SBOM identification assistant. Return one JSON object only. Never invent evidence. Preserve vendor revisions. Abstain on insufficient evidence.'
# Version-1 prompt bytes are preserved for reproducing the trained adapters.
# "upstream product key" below means the NVD CPE product field, including vendor
# devices and proprietary firmware; it is not restricted to upstream OSS projects.
INSTRUCTIONS = {
    'L2': 'Normalize the component name to the upstream product key. Return {"normalized": string or null, "status": "resolved" or "unresolved"}. Do not confuse a device supplier with an upstream vendor.',
    'L3': 'Normalize only a leading v/V immediately before a digit and surrounding whitespace in raw_version. Preserve all epochs, suffixes and vendor revisions exactly. Missing, unknown, latest, unspecified and NOASSERTION mean unresolved. Return {"normalized": string or null, "status": "present" or "unresolved"}.',
    'L4': 'Select an identity only from supplied candidates with origin nvd_dictionary and a valid unescaped 13-field CPE 2.3. Its product must match normalized_name (punctuation separators may normalize to underscores). Input SBOM CPE alone is not proof. Missing or ambiguous distinct identities and lookup_error mean unresolved. Return {"vendor": string or null, "product": string or null, "status": "validated" or "unresolved"}.',
}


def messages(task, payload):
    return [{'role': 'system', 'content': SYSTEM},
            {'role': 'user', 'content': INSTRUCTIONS[task] + '\nInput: ' + json.dumps(payload, ensure_ascii=False)}]


def version_gold(raw):
    raw = str(raw or '').strip()
    value = re.sub(r'^[vV](?=\d)', '', raw)
    if not value or value.lower() in {'unknown', 'latest', 'unspecified', 'noassertion'}:
        return {'normalized': None, 'status': 'unresolved'}
    return {'normalized': value, 'status': 'present'}


def identity_gold(payload):
    identities = set()
    for candidate in payload.get('candidates', []):
        cpe = candidate.get('cpe', '')
        parts = cpe.split(':')
        if (candidate.get('origin') == 'nvd_dictionary' and '\\' not in cpe
                and len(parts) == 13 and parts[:2] == ['cpe', '2.3']
                and parts[2] in {'a', 'o', 'h'} and parts[3] not in {'', '*', '-'}
                and re.sub('[^a-z0-9]+', '_', parts[4].lower()).strip('_') ==
                    re.sub('[^a-z0-9]+', '_', str(payload.get('normalized_name','')).lower()).strip('_')):
            identities.add((parts[3], parts[4]))
    if len(identities) != 1 or payload.get('lookup_error'):
        return {'vendor': None, 'product': None, 'status': 'unresolved'}
    vendor, product = next(iter(identities))
    return {'vendor': vendor, 'product': product, 'status': 'validated'}


def parse_output(text):
    # A malformed output is an error, not an abstention or a repaired correct answer.
    try:
        value = json.loads(text.strip())
        return value if isinstance(value, dict) else None
    except (ValueError, TypeError):
        return None


def valid_output(task, value):
    if not isinstance(value, dict): return False
    if task in {'L2', 'L3'}:
        active = 'resolved' if task == 'L2' else 'present'
        return (set(value) == {'normalized', 'status'} and
                ((value['status'] == active and isinstance(value['normalized'], str) and bool(value['normalized']))
                 or (value['status'] == 'unresolved' and value['normalized'] is None)))
    return (set(value) == {'vendor', 'product', 'status'} and
            ((value['status'] == 'validated' and all(isinstance(value[k], str) and value[k] for k in ('vendor', 'product')))
             or (value['status'] == 'unresolved' and value['vendor'] is None and value['product'] is None)))
