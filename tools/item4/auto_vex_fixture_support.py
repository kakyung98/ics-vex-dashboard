"""Synthetic asset operational information only; no VEX conclusion enters an assessment."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
from src.item4.assets import operating_profile_catalog as M
from src.item4.decision import evidence_based_vex as E
def profile(product='OpenSSL',version='1.0.1g',asset_index=2,stamp=None,asset_ref='SYNTHETIC-INSTANCE'):
    stamp=stamp or datetime.now(timezone.utc);p=deepcopy(M.catalogue()['profiles'][asset_index]['blank'])
    p['scope'].update(asset_ref=asset_ref,product=product,build=version,config_baseline='SYNTHETIC-BASELINE',mode='normal',origin='SYNTHETIC-ORIGIN',reviewer='Synthetic benchmark',observed_at=(stamp-timedelta(minutes=10)).isoformat(),valid_until=(stamp+timedelta(days=1)).isoformat())
    for eid,kind in [('inventory','inventory_record'),('configuration','configuration_record'),('analysis','assessment_record'),('vendor','vendor_document')]:
        p['evidence'][eid]=dict(source='SYNTHETIC '+kind,excerpt='SYNTHETIC operational record, not a claim about any real installation.',kind=kind,reviewed=True,**{k:p['scope'][k] for k in ('asset_ref','build','config_baseline')},observed_at=(stamp-timedelta(hours=1)).isoformat(),valid_until=(stamp+timedelta(days=1)).isoformat())
    return p
def request(cve,p,facts=None):
    pl=E.plan(cve,p);facts=facts or {};answers={}
    for q in pl['questions']:
        value=facts.get(q['id'],'running' if q['id']=='deployment' else 'bom' if q['id']=='runtime_version' and 'bom' in q['options'] else 'unknown')
        answers[q['id']]=dict(value=value,evidence_ids=[] if value=='unknown' else ['inventory' if q['id'] in ('deployment','runtime_version','product_family') else 'configuration'],coverage='complete',scope_sha256=pl['scope_sha256'])
    return dict(cve=cve,product_key=pl['product']['key'],profile=p,plan_sha256=pl['plan_sha256'],auto_observations=answers)
