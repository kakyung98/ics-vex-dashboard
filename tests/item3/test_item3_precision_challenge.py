"""The challenge keeps source exclusions and unknown labels separate."""
import json
import sqlite3

from benchmark.item3_precision_challenge_v1.build_dataset import select_hard, add_noise
from tools.item3.item3_truth_oracle import Oracle, condition


def fixture_oracle():
    connection=sqlite3.connect(':memory:')
    connection.execute('CREATE TABLE cves(cve TEXT,payload TEXT)')
    matches=[
        ('CVE-TEST-1', {'criteria':'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*',
                        'versionEndExcluding':'2.0','vulnerable':True}),
        ('CVE-TEST-2', {'criteria':'cpe:2.3:a:vendor:product:2.0:*:enterprise:*:*:*:*:*','vulnerable':True}),
        ('CVE-TEST-3', {'criteria':'cpe:2.3:a:vendor:product:2.0:*:community:*:*:*:*:*','vulnerable':True}),
    ]
    for cid,match in matches:
        connection.execute('INSERT INTO cves VALUES (?,?)',(cid,json.dumps({
            'id':cid,'vulnStatus':'Analyzed','configurations':[{'cpeMatch':[match]}]})))
    return Oracle(connection)


def test_hard_negatives_exclude_entire_cve_and_preserve_unknowns():
    oracle=fixture_oracle()
    selected,counts=select_hard(oracle,17,10)
    assert counts['version_boundary'] and counts['edition_target']
    assert [(r[0],r[1]) for r in selected]==[(r[0],r[1]) for r in select_hard(oracle,17,10)[0]]
    for kind,fields,source,change,truth in selected:
        assert condition(fields,source['match']) is False
        assert source['cve'] not in truth['expected_cves']+truth['unknown_cves']
    boundary=next(r for r in selected if r[0]=='version_boundary')
    # Unknown edition cannot be treated as a confirmed false mapping.
    assert set(boundary[-1]['unknown_cves'])=={'CVE-TEST-2','CVE-TEST-3'}


def test_cpe_mask_keeps_one_complete_copy_and_does_not_mutate_control():
    import random
    cpe='cpe:2.3:a:vendor:product:2.0:*:enterprise:*:*:*:*:*'
    control={'metadata':{'component':{'name':'product','version':'2.0','cpe':cpe}},
             'components':[{'name':'product','version':'2.0','cpe':cpe}]}
    noisy=add_noise(control,'I3',random.Random(1))
    assert sum('cpe' in c for c in (noisy['metadata']['component'],noisy['components'][0]))==1
    assert control['metadata']['component']['cpe']==control['components'][0]['cpe']==cpe
