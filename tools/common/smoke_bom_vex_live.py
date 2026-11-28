"""Live HTTP wiring check: real identification/model/MulVAL, synthetic asset.

No model, graph, CVE association or expected verdict is injected. Output is
connection evidence, not a measurement of accuracy on a real installation.
"""
import argparse
import json
from pathlib import Path
import sys
import time

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.item4.auto_vex_fixture_support import profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='http://127.0.0.1:8100')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--job-id', required=True)
    parser.add_argument('--cve', default='CVE-2010-5298')
    args = parser.parse_args()
    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    report = dict(scope='Real local model and remote MulVAL; synthetic asset and operating records',
                  job_id=args.job_id, steps=[], passed=False)

    def call(name, method, path, payload=None):
        start = time.monotonic()
        print(name, flush=True)
        response = requests.request(method, args.base + path, json=payload, timeout=(10, 600))
        report['steps'].append(dict(name=name, http=response.status_code,
                                    seconds=round(time.monotonic()-start, 3)))
        (out/(name+'.json')).write_text(response.text, encoding='utf-8')
        response.raise_for_status()
        return response.json()

    try:
        state = call('identification-status', 'GET', '/api/bom-vex/identification-jobs/'+args.job_id)
        if state['status'] != 'completed':
            raise RuntimeError('Identification has not completed: '+state['status'])
        w = call('workflow', 'POST', '/api/bom-vex/from-job', {'job_id': args.job_id})
        candidates = [c for c in w['cases'] if c['cve']==args.cve]
        if len(candidates) != 1:
            raise RuntimeError('Identification did not produce the requested CVE/component case')
        case = candidates[0]
        report['case'] = case
        if case['match_status'] != 'match':
            raise RuntimeError('Live identification did not confirm the CVE association')
        p = profile(asset_ref='SYNTHETIC-LIVE-WIRING-ONLY')
        p['scope']['reviewer'] = 'Automated wiring smoke; synthetic records, no real installation'
        p['evidence']['inventory']['excerpt'] = (
            'SYNTHETIC wiring fixture. Complete current deployed-component inventory for '
            'SYNTHETIC-LIVE-WIRING-ONLY: the component OpenSSL 1.0.1g is installed and executing. '
            'The running component version is 1.0.1g and matches the assessed BOM.')
        p['evidence']['configuration']['excerpt'] = (
            'SYNTHETIC wiring fixture, not a real installation. Current applied configuration '
            'inspection for OpenSSL 1.0.1g on SYNTHETIC-LIVE-WIRING-ONLY, baseline '
            'SYNTHETIC-BASELINE, normal operating mode: SSL_MODE_RELEASE_BUFFERS is enabled. '
            'The application uses OpenSSL concurrently from multiple threads. '
            'This describes the current setting on this component, not a proposed change.')
        w = call('saved-profile', 'POST', '/api/bom-vex/workflows/'+w['id']+'/profiles',
                 dict(revision=w['revision'], bom_sha256=w['bom_sha256'],
                      component_ref=case['component_ref'], profile=p,
                      component_binding=dict(review_confirmed=True, source='SYNTHETIC smoke inventory',
                                             quote=p['evidence']['inventory']['excerpt'])))
        plan = call('plan', 'POST', '/api/operational-vex/plan', dict(cve=case['cve'], profile=p))
        report['extraction'] = plan['condition_extraction']
        report['graph_generation'] = plan['attack_graph']['generation_status']
        answers = {}
        for q in plan['questions']:
            identity = q['id'] in ('deployment', 'runtime_version', 'product_family')
            value = ('running' if q['id']=='deployment' else 'bom' if q['id']=='runtime_version'
                     else 'from_evidence' if q.get('record_review', {}).get('supported') else 'unknown')
            answers[q['id']] = dict(value=value, evidence_ids=['inventory' if identity else 'configuration'],
                                    coverage='complete', scope_sha256=plan['scope_sha256'])
        assessment = dict(cve=case['cve'], profile=p, product_key=plan['product']['key'],
                          plan_sha256=plan['plan_sha256'], auto_observations=answers)
        result = call('assessment', 'POST', '/api/bom-vex/workflows/'+w['id']+'/cases/'+case['id']+'/assess',
                      dict(revision=w['revision'], bom_sha256=w['bom_sha256'],
                           assessment=assessment, mapping_review={}))
        root = '/api/bom-vex/workflows/'+w['id']+'/cases/'+case['id']+'/export/'
        ov = call('openvex', 'GET', root+'openvex')
        cdx = call('cyclonedx', 'GET', root+'cyclonedx')
        expected_cdx = {'affected':'exploitable', 'not_affected':'not_affected',
                        'fixed':'resolved', 'under_investigation':'in_triage'}
        status = result['decision']['status']
        checks = dict(real_vep=bool(plan.get('prerequisite', {}).get('llm_used')) if plan.get('prerequisite') else False,
                      mulval_complete=plan['attack_graph']['generation_status']=='complete',
                      mulval_steps_checked=bool(plan['attack_graph'].get('mulval', {}).get('all_inference_steps_checked')),
                      real_record_review=result['operational_record_review']['executed']>0,
                      valid_record_observations=any(c.get('records') and not c.get('reasons')
                                                   for c in result['operational_record_review']['comparisons']),
                      unresolved_conditions_kept_open=not plan['untranslated_conditions'] or status=='under_investigation',
                      openvex_agrees=ov['statements'][0]['status']==status,
                      cyclonedx_agrees=cdx['vulnerabilities'][0]['analysis']['state']==expected_cdx[status])
        report.update(checks=checks, passed=all(checks.values()), decision=result['decision'],
                      source_conditions_resolved=result['prerequisite_status']=='satisfied',
                      untranslated_conditions=plan['untranslated_conditions'],
                      operating_review=result['operational_record_review'],
                      asset_type_context=p['asset_type_id'],
                      asset_type_note='Synthetic PLC scope selected explicitly for wiring only; not inferred hardware identity')
    except Exception as exc:
        report['error'] = type(exc).__name__+': '+str(exc)
    finally:
        (out/'live-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps({k:report[k] for k in ('passed','checks','error') if k in report}), flush=True)
    return 0 if report['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
