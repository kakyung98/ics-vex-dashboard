"""Validate optional, immutable vendor-only evidence supplements before use."""
import hashlib
import json
from pathlib import Path
from .asset_vulntology import digest
from .context_vex_pipeline import leaves

ROOT=Path(__file__).resolve().parents[1]
CONFIG=ROOT/'data/asset_vulntology_vendor_sources.json'


def load():
    if not CONFIG.is_file():return {},None
    config=json.loads(CONFIG.read_text(encoding='utf-8'))
    path=(ROOT/config['supplement']).resolve()
    if ROOT.resolve() not in path.parents:raise ValueError('Vendor supplement must be inside this workspace')
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=config['sha256']:raise ValueError('Vendor supplement hash mismatch')
    values={}
    for line in raw.decode('utf-8').splitlines():
        if not line.strip():continue
        item=json.loads(line);cve=item['cve']
        if cve in values:raise ValueError('Duplicate vendor supplement CVE')
        if digest({k:v for k,v in item.items() if k!='supplement_digest'})!=item['supplement_digest']:
            raise ValueError('Vendor supplement record digest mismatch')
        validate(item)
        values[cve]=item
    expected=json.loads((ROOT/config['targets']).read_text(encoding='utf-8'))['cve_ids']
    if set(values)!=set(expected) or len(values)!=7563:raise ValueError('Frozen vendor target population changed')
    return values,config


def validate(item):
    sources={s['id']:s for s in item['sources']};products={p['key'] for p in item['products']}
    if len(sources)!=len(item['sources']) or len(products)!=len(item['products']):raise ValueError('Duplicate vendor scope/source')
    for source in sources.values():
        if hashlib.sha256(source['text'].encode()).hexdigest()!=source['text_sha256']:raise ValueError('Vendor text hash mismatch')
        if not set(source['product_keys'])<=products:raise ValueError('Vendor source cannot inherit unbound CISA product IDs')
    def ref(value):
        text=sources[value['source_id']]['text'];a,b=value['span']
        if not 0<=a<b<=len(text) or text[a:b]!=value['quote']:raise ValueError('Vendor source quote/span mismatch')
    scenario_ids=set()
    for scenario in item['scenarios']:
        if scenario['id'] in scenario_ids:raise ValueError('Duplicate vendor scenario ID')
        scenario_ids.add(scenario['id'])
        if not set(scenario['product_keys'])<=products:raise ValueError('Vendor path has an unbound product')
        if not leaves(scenario['expression'])<={c['id'] for c in scenario['conditions']}:raise ValueError('Vendor formula has an unbound condition')
        if scenario.get('coverage_complete') is not False or scenario.get('review_status')!='pending_source_review':
            raise ValueError('Automatic vendor drafts must not confer complete coverage or human approval')
        ref(scenario['source_ref'])
        for condition in scenario['conditions']:
            ref(condition['source_ref']);ref(condition['context_ref'])
    for claim in item.get('action_claims',[]):
        ref(claim)
        if claim['role']!='action_or_impact_not_prerequisite':raise ValueError('Action claims must remain outside executable prerequisites')


def apply(record,item):
    if record['cve']!=item['cve']:raise ValueError('Vendor supplement CVE mismatch')
    if record['scenarios']:raise ValueError('Vendor expansion targets must match the frozen no-path baseline')
    if record.get('original_nvd_status')=='Rejected' and item['scenarios']:
        raise ValueError('Rejected CVE identity cannot gain an executable scenario')
    record['products'].extend(item['products']);record['sources'].extend(item['sources'])
    record['scenarios'].extend(item['scenarios'])
    record['vendor_action_claims']=item.get('action_claims',[])
    record['vendor_review']=item['vendor_review']
    record['vendor_supplement_digest']=item['supplement_digest']
    return record
