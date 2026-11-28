from src.item3.evidence import cisa_advisory_lookup as cisa


def test_advisory_family_cache_is_version_independent_and_mutation_isolated(monkeypatch):
    cisa._retrieve_sources.cache_clear();calls=[]
    row=dict(source='CISA CSAF',products=['Fixture Product'],vendor='Fixture Vendor',
             url='https://www.cisa.gov/news-events/ics-advisories/fixture')
    monkeypatch.setattr(cisa,'family_index',lambda:({
        ('fixture vendor',('fixture','product')):{'fixture':('fixture',row,'fixture product')}},{}))
    def relations(aid):
        calls.append(aid)
        tree={'wanted':dict(vendor='Fixture Vendor',product='Fixture Product',product_id='wanted'),
              'unrelated':dict(vendor='Other Vendor',product='Other Product',product_id='unrelated')}
        return [('CVE-2099-0001',tree,{'wanted'},'source-sha')]
    monkeypatch.setattr(cisa,'structured_relations',relations)
    try:
        first=cisa.retrieve(dict(name='Fixture Product',manufacturer='Fixture Vendor',version='1'))
        first[0]['evidence']['csaf_product_ids'].append('caller mutation')
        second=cisa.retrieve(dict(name='Fixture Product',manufacturer='Fixture Vendor',version='2'))
        assert calls==['fixture']
        assert second[0]['evidence']['csaf_product_ids']==['wanted']
        assert second[0]['match_status']=='unknown'
        assert second[0]['evidence']['version_confirmed'] is False
    finally:cisa._retrieve_sources.cache_clear()
