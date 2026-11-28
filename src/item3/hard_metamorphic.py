"""Predeclared relational oracle; no absolute CVE labels or output filtering."""
from collections import Counter

VERSION='hard-identification-relations/1'
INVARIANT={'redundant_purl','release_relocated_to_purl','singleton_interval','cross_component_isolation'}


def effective_version(s,version):
    if s.get('version')==version:return True
    r=s.get('range') or {};parts=r.get('intervals',[r])
    return len(parts)==1 and parts[0].get('lower')==version and parts[0].get('upper')==version and parts[0].get('lower_inclusive') is True and parts[0].get('upper_inclusive') is True


def valid(row):return row is not None and not row.get('error') and not row.get('agent_failures') and bool(row.get('target')) and not row['target'].get('lookup_error')


def compare(relation,original,variant,ref):
    a=(original or {}).get('target',{});b=(variant or {}).get('target',{});good=valid(original) and valid(variant)
    # Strong explicit source anchors are a precondition, never a sample filter.
    base_ok=valid(original) and a.get('identity')==['validated',*ref['identity']] and effective_version(a,ref['version'])
    ac=dict(a.get('cves',[]));bc=dict(b.get('cves',[]));am={k for k,v in ac.items() if v=='match'};bm={k for k,v in bc.items() if v=='match'}
    if relation in INVARIANT:
        tests=dict(identity=b.get('identity')==a.get('identity'),release=effective_version(b,ref['version']),cve_states=bc==ac)
    elif relation=='conflicting_release_evidence':
        tests=dict(identity=b.get('identity')==a.get('identity'),unresolved_release=b.get('version') is None and bool(b.get('conflicts')),no_confirmed_cves=not bm,prior_matches_unknown=all(bc.get(k)=='unknown' for k in am))
    elif relation=='release_information_removed':
        tests=dict(identity=b.get('identity')==a.get('identity'),unresolved_release=b.get('version') is None,no_new_confirmed_cves=bm<=am)
    elif relation=='conflicting_manufacturer':
        tests=dict(identity_deferred=b.get('identity',[None])[0]!='validated',no_confirmed_cves=not bm)
    else:raise ValueError('Unknown frozen relation')
    return dict(passed=bool(good and base_ok and all(tests.values())),baseline_anchor_valid=bool(base_ok),inference_valid=bool(good),checks=tests)


def summarize(inputs,rows,references):
    rows={r['id']:r for r in rows};refs={r['id']:r for r in references};counts=Counter();types={};failures=[];hashes=Counter()
    for c in inputs:
        if c['relation']=='original':continue
        a=rows.get(c['base_id']+'__original');b=rows.get(c['id']);j=compare(c['relation'],a,b,refs[c['base_id']]);counts.update(pairs=1,passed=j['passed'],baseline_anchor_valid=j['baseline_anchor_valid'],inference_valid=j['inference_valid'])
        types.setdefault(c['relation'],Counter()).update(total=1,passed=j['passed'])
        hashes['same_model_input_pairs']+=bool(a and b and a.get('model_hashes') and a['model_hashes']==b.get('model_hashes'))
        if not j['passed']:failures.append(dict(id=c['id'],relation=c['relation'],judgement=j,original=(a or {}).get('target'),variant=(b or {}).get('target'),error=(b or {}).get('error')))
    rates={k:dict(v,rate=v['passed']/v['total']) for k,v in types.items()};overall=counts['passed']/counts['pairs']
    return dict(version=VERSION,counts=dict(counts),overall_rate=overall,relations=rates,model_input_audit=dict(hashes),above_90=overall>.9 and all(v['rate']>.9 for v in rates.values()),failures=failures,
        scope='End-to-end CVE identification robustness: explicit-source anchors, invariance and directional uncertainty relations; no absolute CVE-accuracy claim. Missing/error/failed baseline cases remain failures.')
