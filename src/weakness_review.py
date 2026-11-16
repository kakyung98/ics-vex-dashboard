"""Read the original 17 weakness families as review hints, never CVE verdicts."""
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
from pathlib import Path

DATASET = Path(__file__).resolve().parents[1]/'results/ics_vex_clusters_v1'


@lru_cache(maxsize=2)
def snapshot(directory):
    directory = Path(directory)
    try:
        manifest = json.loads((directory/'manifest.json').read_text(encoding='utf-8'))
        for name in ('profiles.json', 'assignments.jsonl', 'summary.json'):
            if hashlib.sha256((directory/name).read_bytes()).hexdigest() != manifest['files'][name]:
                raise ValueError('Weakness snapshot integrity check failed: '+name)
        profiles = json.loads((directory/'profiles.json').read_text(encoding='utf-8'))['profiles']
        rows = {}
        with (directory/'assignments.jsonl').open(encoding='utf-8') as stream:
            for line in stream:
                row = json.loads(line)
                if row['cve'] in rows:
                    raise ValueError('Duplicate weakness assignment')
                rows[row['cve']] = row
        if len(profiles) != 17:
            raise ValueError('Expected the original 17 weakness families')
        return {'status':'available', 'profiles':profiles, 'rows':rows,
                'signature':hashlib.sha256((directory/'manifest.json').read_bytes()).hexdigest()}
    except (OSError, ValueError, KeyError, TypeError) as error:
        return {'status':'unavailable', 'reason':str(error), 'profiles':[], 'rows':{}}


def catalog():
    data = snapshot(str(DATASET))
    return {'status':data['status'], 'reason':data.get('reason'), 'family_count':len(data['profiles']),
            'population':len(data['rows']), 'signature':data.get('signature'),
            'profiles':deepcopy(data['profiles']), 'vex_authority':False,
            'boundary':'17 weakness families select investigation topics; they do not establish necessary conditions or a VEX status.'}


def explain(cve):
    data = snapshot(str(DATASET))
    row = data['rows'].get(cve)
    profiles = {p['id']:p for p in data['profiles']}
    members = []
    for member in (row or {}).get('memberships', []):
        profile = profiles.get(member['cluster'])
        if profile:
            members.append({**deepcopy(profile), 'basis':member['basis'],
                            'evidence':deepcopy(member['evidence']), 'can_refute':False})
    return {'status':data['status'] if row else 'unavailable' if data['status'] != 'available' else 'not_in_snapshot',
            'family_count':len(profiles), 'primary':(row or {}).get('primary_cluster'),
            'memberships':members, 'reported_cwes':deepcopy((row or {}).get('cwes', [])),
            'signature':data.get('signature'), 'vex_authority':False}
