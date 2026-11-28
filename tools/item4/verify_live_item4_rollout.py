"""Exercise the loopback service with two explicitly scoped supplier status records."""
import argparse
import json
import sys
import time
import uuid
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.analysis import product_advisory_evidence as advisory
from src.item4.decision import asset_vex_assessment as assessment

CASES = {
    'CVE-2022-45789': ('fixed', 'fixed', 'resolved'),
    'CVE-2024-10083': ('known_not_affected', 'not_affected', 'not_affected'),
}


def example(cve, claim):
    for aid in advisory.A.detail(cve)['advisory_ids']:
        path = ROOT / 'data/cisa_identification_csaf' / (aid + '.json')
        if not path.is_file():
            continue
        doc = json.loads(path.read_bytes())
        tree = advisory.source_products(doc)
        for pid, status, _ in advisory.status_rows(doc, cve):
            if status != claim or pid not in tree:
                continue
            product = tree[pid]
            version = advisory.version_predicate(product['version'])
            if version.get('op') != '=':
                continue
            component = {'bom-ref': cve + '-smoke', 'name': product['name'], 'type': 'application',
                         'version': version['version'], 'supplier': {'name': product['vendor']}}
            row = dict(ref=component['bom-ref'], name=component['name'], value=component)
            context = advisory.lookup(cve, [row])
            expected = 'fixed' if claim == 'fixed' else 'unaffected'
            if assessment.version_binding(cve, advisory.component_identity(row),
                                          {'advisory_context': context})['state'] == expected:
                return component
    raise ValueError('Pinned example no longer available for ' + cve)


def main(port, output):
    def api(path, body=None):
        request = Request(f'http://127.0.0.1:{port}' + path,
                          data=json.dumps(body).encode() if body is not None else None,
                          headers={'Content-Type': 'application/json'})
        with urlopen(request, timeout=180) as response:
            return json.load(response)

    roles = api('/api/operational-vex/llm-status')['role_adapters']
    adapter = next(r for r in roles if r['role'] == 'exploitation-prerequisites')
    assert adapter['evaluation_passed'] is False and adapter['experimental_use_approved'] is True
    components = [example(cve, claim) for cve, (claim, _, _) in CASES.items()]
    bom = dict(bomFormat='CycloneDX', specVersion='1.6', version=1, components=components,
               vulnerabilities=[{'id': cve, 'affects': [{'ref': c['bom-ref']}]}
                                for cve, c in zip(CASES, components)])
    key = uuid.uuid4().hex
    job = api('/api/item4/analyses/start', dict(bom=bom, representative_ref=components[0]['bom-ref'], request_id=key))
    url = '/api/item4/analyses/jobs/' + job['id']
    print('Started live verification', job['id'], flush=True)
    deadline = time.monotonic() + 1800
    while job['status'] in {'queued', 'running'} and time.monotonic() < deadline:
        time.sleep(2)
        job = api(url)
    if job['status'] != 'completed':
        raise RuntimeError('Source analysis did not complete: ' + job['status'])
    context = {'scope': 'current_single'}
    for case in job['assessment_cases']:
        context[case['prefix'] + 'runtime'] = 'bom'
        context[case['prefix'] + 'deployment'] = 'running'
    def token(record):
        return {k: record[k] for k in ('revision', 'plan_sha256')}
    saved = api(url + '/answers', dict(token(job), context_answers=context))
    api(url + '/assess', token(saved))
    report = api(url + '/export/review')
    ov = {s['vulnerability']['name']: s['status'] for s in api(url + '/export/openvex')['statements']}
    cd = {v['id']: v['analysis']['state'] for v in api(url + '/export/cyclonedx')['vulnerabilities']}
    assert len(report['decisions']) == len(ov) == len(cd) == len(CASES)
    for row in report['decisions']:
        _, want, want_cd = CASES[row['cve']]
        assert row['status'] == ov[row['cve']] == want and cd[row['cve']] == want_cd
        assert row['attack_graph']['generation_status'] == 'not_required'
    record = dict(job=job['id'], port=port, adapter_state=adapter['state'],
                  source='local supplier snapshots', deployment_input='synthetic operator confirmation',
                  report_sha256=report['sha256'], version=report['version'], openvex=ov, cyclonedx=cd)
    output.write_text(json.dumps(record, indent=2), encoding='utf-8')
    print(json.dumps(record), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--port', type=int, default=8100)
    args = parser.parse_args()
    main(args.port, args.output)
