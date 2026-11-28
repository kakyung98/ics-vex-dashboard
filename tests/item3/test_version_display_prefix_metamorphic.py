import pytest
from src.item3.evidence.version_evidence import version_info
from src.item3.matching.product_version_cve_matching import identify


@pytest.mark.parametrize('version',['5.008','1.03d','2.0.0'])
def test_display_prefix_does_not_change_comparison_value_or_obscure_source(version):
    def read(raw):return version_info(dict(name='device',version=raw,cpes=[]))
    plain,prefixed=read(version),read('v'+version)
    assert plain['comparison_version']==prefixed['comparison_version']==version
    assert prefixed['raw']=='v'+version and prefixed['observations'][0]['evidence']=='v'+version


@pytest.mark.parametrize('source_version',['1.2','v1.2'])
def test_cpe_literal_version_matches_either_display_spelling(source_version):
    config=[dict(cpeMatch=[dict(criteria='cpe:2.3:a:vendor:product:'+source_version+':*:*:*:*:*:*:*',vulnerable=True)])]
    assert [identify(config,['a','vendor','product',version]+[None]*7) for version in ['1.2','v1.2']]==['true','true']


def test_display_prefix_does_not_create_an_order_for_unsupported_vendor_versions():
    config=[dict(cpeMatch=[dict(criteria='cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*',vulnerable=True,versionEndExcluding='1.04z')])]
    assert identify(config,['a','vendor','product','v1.03d']+[None]*7)=='unknown'


def test_unknown_source_version_is_not_a_pattern_error():
    config=[dict(cpeMatch=[dict(criteria='cpe:2.3:a:vendor:product:unknown:*:*:*:*:*:*:*',vulnerable=True)])]
    assert identify(config,['a','vendor','product',None]+[None]*7)=='unknown'
