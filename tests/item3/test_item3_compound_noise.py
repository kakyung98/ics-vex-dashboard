from copy import deepcopy
import json

from benchmark.item3_precision_challenge_v2.build_dataset import perturb,seeded_rng,noisy_version


FIELDS=['a','vendor','product_server','1.2.3',None,'enterprise',None,None,'windows',None,None]


def fixture():
    c={'bom-ref':'x','name':'product server','version':'1.2.3',
       'cpe':'cpe:2.3:a:vendor:product_server:1.2.3:*:enterprise:*:*:windows:*:*',
       'purl':'pkg:generic/product@1.2.3','manufacturer':{'name':'vendor'},
       'hashes':[{'alg':'SHA-256','content':'a'*64}]}
    return {'metadata':{'component':deepcopy(c)},'components':[deepcopy(c)]}


def test_compound_noise_is_repeatable_and_removes_every_identifier_copy():
    control=fixture();snapshot=deepcopy(control)
    a,audit=perturb(control,FIELDS,'I1',3,seeded_rng(22,'case'))
    b,other=perturb(control,FIELDS,'I1',3,seeded_rng(22,'case'))
    assert a==b and audit==other and control==snapshot
    assert 'cpe:' not in json.dumps(a) and 'pkg:' not in json.dumps(a)
    for component in (a['metadata']['component'],a['components'][0]):
        assert all(k not in component for k in ('cpe','purl','hashes','manufacturer'))
        assert component['name']!=control['components'][0]['name']
        assert component['version']!='1.2.3'
        assert 'product: product_server' in component['description']
        assert 'release: 1.2.3' in component['description']
        assert 'edition: enterprise' in component['description']
        assert 'target software: windows' in component['description']
    assert audit['contradictory_identity_injected'] is False


def test_noise_does_not_invent_unknown_or_not_applicable_versions():
    for level in (1,2,3):
        assert noisy_version(None,level,'I2')=='NOASSERTION'
        assert noisy_version('*',level,'I2')=='NOASSERTION'
        assert noisy_version('-',level,'I2')=='-'


def test_severity_and_axis_apply_compound_noise_to_both_representations():
    for level in (1,2,3):
        for axis in ('I1','I2','I3'):
            doc,audit=perturb(fixture(),FIELDS,axis,level,seeded_rng(22,axis))
            assert doc['metadata']['component']==doc['components'][0]
            assert len(audit['operators'])==4 and audit['dominant_axis']==axis
