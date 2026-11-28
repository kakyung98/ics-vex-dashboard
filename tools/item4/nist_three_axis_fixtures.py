"""Clearly fictional evidence fixtures; never loaded into the live website."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import hashlib
from src.item4.assets import operating_profile_catalog as M
from src.item4.decision import scoped_proof_evaluation as T

def source_record():
    text='FICTIONAL TEST ONLY. Network access is required for this fictional vulnerability.'
    ref=dict(source_id='fictional-source',span=[21,len(text)],quote=text[21:])
    return dict(cve='CVE-2099-90001',description='FICTIONAL TEST ONLY',original_nvd_status='Analyzed',cwes=[],asset_ids=[],
      products=[dict(key='fictional-product',name='FICTIONAL Controller 1.0',binding='CSAF_known_affected',asset_ids=[])],
      sources=[dict(id='fictional-source',text=text,text_sha256=hashlib.sha256(text.encode()).hexdigest(),url='https://example.invalid/fictional',product_keys=['fictional-product'],subject_ambiguous=False)],
      scenarios=[dict(id='fictional-route',product_keys=['fictional-product'],scope_ambiguous=False,derivation='fixture',source_ref=ref,expression=dict(condition='network'),conditions=[dict(id='network',kind='network_access',proposition='network access',question='Can the stated origin reach this fictional service?',operator_observable=True,source_ref=ref,context_ref=ref)])])

def case(asset_index=2,now=None):
    now=now or datetime.now(timezone.utc);c=M.catalogue();p=deepcopy(c['profiles'][asset_index]['blank'])
    p['scope'].update(asset_ref='FICTIONAL-ASSET',product='FICTIONAL Controller',build='1.0',config_baseline='FICTIONAL-BASELINE',mode='normal',origin='FICTIONAL-ORIGIN',reviewer='FICTIONAL reviewer',observed_at=(now-timedelta(minutes=10)).isoformat(),valid_until=(now+timedelta(days=1)).isoformat())
    for eid,kind in [('inventory','inventory_record'),('vendor','vendor_document'),('analysis','assessment_record'),('test','test_record')]:
        p['evidence'][eid]=dict(source='FICTIONAL '+kind+' record',excerpt='FICTIONAL SYNTHETIC INPUT; no assertion about a real asset or CVE',kind=kind,reviewed=True,**{k:p['scope'][k] for k in ('asset_ref','build','config_baseline')},observed_at=(now-timedelta(hours=1)).isoformat(),valid_until=(now+timedelta(days=1)).isoformat())
    def observation(fid,choice,eid,value=None):
        f=c['answer_specs'][fid];rid=fid.split('.')[0]
        p['gates'][rid]=dict(state='present',evidence_ids=[eid],coverage_scope='assessed_asset')
        refs=[]
        option=next(o for o in f['options'] if o['code']==choice)
        if option['requires_value_reference']:
            key='value-'+fid;refs=[key]
            p['reference_values'][key]=dict(kind=f['reference_kind'],label=value or 'FICTIONAL source value',asset_ref=p['scope']['asset_ref'],evidence_ids=[eid])
        p['inventory']['values'][fid]=dict(state='recorded',data=dict(choice=choice,coverage='complete',value_refs=refs),evidence_ids=[eid],coverage_scope='assessed_asset',unknown_reason='')
    observation('C13-01.01','listed','inventory','FICTIONAL Controller')
    observation('C13-01.03','listed','inventory','1.0')
    observation('C13-05.05','reachable','test')
    observation('C12-01.01','included','inventory')
    return p,source_record()

def proof(plan,p,kind,conclusion,mechanism,eid,fields=None):
    return dict(kind=kind,conclusion=conclusion,mechanism=mechanism,cve=plan['cve'],product_key=plan['product']['key'],asset_type_id=p['asset_type_id'],source_digest=plan['source_digest'],scope={k:p['scope'][k] for k in T.SCOPE},evidence_ids=[eid],field_ids=fields or [],question_id='',source_quote_sha256='',coverage='complete',reviewed=True)

def bundle(plan,p,status=None):
    b=T.blank();b['records']['identity']=proof(plan,p,'product_identity','matches','inventory_match','inventory',['C13-01.01','C13-01.03'])
    if status:b['records']['status']=proof(plan,p,'product_status',status,'supplier_statement','vendor')
    b['selected_ids']=list(b['records']);return b

def condition(plan,p,value='true',structural=False):
    p['inventory']['values']['C13-05.05']['data']['choice']='reachable' if value=='true' else 'blocked'
    q=plan['questions'][0]
    e=proof(plan,p,'condition',value,'structural_nonexecution' if structural else 'direct_observation','analysis' if structural else 'test',['C13-05.05'])
    e.update(question_id=q['id'],source_quote_sha256=q['source_quote_sha256']);return e

def add(b,key,p):b['records'][key]=p;b['selected_ids'].append(key)
