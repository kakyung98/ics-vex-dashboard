"""Boundary/Boolean/source-scope tests independent of the 224-case outcomes."""
import pytest
from src.common import source_version_parser as V
from src.item4.decision import population_condition_rules as P


@pytest.mark.parametrize('source,actual,expected',[
    ('vers:intdot/<=1.5.0.14','1.5.0.15','false'),
    ('vers:intdot/<=1.5.0.14','1.5.0.14','true'),
    ('vers:intdot/>=1.0|<2.0','0.9','false'),
    ('vers:intdot/>=1.0|<2.0','1.0','true'),
    ('vers:intdot/>=1.0|<2.0','2.0','false'),
    ('vers:intdot/1.0|>=2.0|<3.0','1.5','false'),
    ('vers:intdot/1.0|>=2.0|<3.0','2.5','true'),
    ('vers:intdot/>=1|!=1.5|<2','1.5','false'),
    ('vers:intdot/>=1|!=1.5|<2','1.6','true'),
    ('vers:intdot/<=01.002.003','1.2.3suffix','true'),
    ('>=1.0|<=2.0','0.5','false'),
    ('>=1.0|<=2.0','2.1','false'),
    ('>=1.0|<=2.0','1.5','true'),
    ('<=1.0|>=2.0','1.5','false'),
    ('< 1.99 | 2.20 | 2.40','2.20','true'),
    ('<= 1.12.0.27 | 1.12.13.2 | 1.12.14.5','1.12.13.2','true'),
    ('>= 2.0.0 | 2.6.2','2.6.2','true'),
    ('>= 2.0.0 | 2.6.2','1.0','false'),
    ('11.3.1 | 11.3.2 | <= R6','11.3.1','true'),
    ('2.7 | >= 4.0.x | <= 4.6.4 | 4.7.2','2.7','true'),
    ('>= 6.0.0.0 | <= 6.0.0.4','1.0.0','false'),
    ('6.1|7.0','6.1','true'),
    ('6.1|7.0','6.5','false'),
    ('>=V8.7.0_and_<V8.7.1.3','8.7.1.2','true'),
    ('>=V8.7.0_and_<V8.7.1.3','8.7.1.3','false'),
    ('>=V33.1.262_<V33.1.263','33.1.261','false'),
    ('>=V33.1.262_<V33.1.263','33.1.262','true'),
    ('>=2.5.0|<=2.6.0_beta','1.0.0','false'),
    ('vers:generic/<SV3.60','SV3.60','false'),
    ('vers:generic/<=SV3.60','SV3.60','true'),
    ('vers:generic/<SV3.60','SV3.59','unknown'),
    ('vers:all/*','1.0','true'),
    ('vers:none/*','1.0','false'),
    ('vers:all/<1.3.10','1.3.10','unknown'),
    ('vers:TRO600/<=9.1.1.0','9.1.2.0','unknown'),
    ('* (with the nossl tag)','1.0','unknown'),
    ('<= 2.0.0.10 (RES670 2.0.0.4 and prior)','1.0','unknown'),
    ('<=1.0','master','unknown'),
    ('<7.122','5.x','unknown'),
    ('vers:intdot/<7.122','5.x','unknown'),
    ('vers:intdot/*','release1','unknown'),
    ('vers:all/*','R15x','unknown'),
    ('vers:all/*','3xx','unknown'),
    ('vers:all/*','>=1.0','unknown'),
    ('vers:intdot/=1.0','1.0','unknown'),
    ('vers:intdot/>=2.0|<1.0','1.5','unknown'),
    ('vers:intdot/>=1.0|<1.0','1.0','unknown'),
    ('vers:intdot/>=1.0|>=2.0','1.5','unknown'),
    ('vers:intdot/>=1.0|2.0','1.5','unknown'),
    ('vers:intdot/>=1.0 |<2.0','1.5','unknown'),
    ('vers:intdot/<=abc','1.5','unknown'),
])
def test_source_ranges(source,actual,expected):
    assert V.membership(V.version_predicate(source),actual)==expected


def test_numeric_intervals_agree_with_integer_set_boundaries():
    for lower in range(1,5):
        for upper in range(lower+1,7):
            p=V.version_predicate(f'vers:intdot/>={lower}|<{upper}')
            for actual in range(9):
                assert V.membership(p,str(actual))==('true' if lower<=actual<upper else 'false')


def test_raw_source_is_reparsed_instead_of_mutating_the_frozen_catalog():
    row=dict(status='known_affected',version_text='vers:intdot/<=1.5.0.14',
        version_predicate=dict(op='unknown',raw='vers:intdot/<=1.5.0.14'))
    rule=dict(source_product_rows=[row,dict(status='fixed',version_predicate=dict(op='=',version='1.5.0.15'))])
    assert P.status(rule,'1.5.0.15')=='fixed'
    assert row['version_predicate']['op']=='unknown'


def test_resolved_range_conflicts_and_unresolved_vendor_ordering_are_preserved():
    rows=[dict(status='fixed',version_predicate=dict(op='=',version='1.0')),
          dict(status='known_affected',version_text='vers:intdot/<=1.0',version_predicate=dict(op='unknown'))]
    assert P.status(dict(source_product_rows=rows),'1.0')=='conflicting'
    rows[1]['version_text']='vers:unknown-vendor/<=1.0'
    assert P.status(dict(source_product_rows=rows),'1.0')=='unknown'
