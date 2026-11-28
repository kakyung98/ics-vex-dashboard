"""Real-description semantic annotations plus a small contrast supplement.

Annotations below were reviewed for source meaning in this task. They are not
independent expert Gold, and the many unannotated CVEs are not negative labels.
The immutable parent source groups determine train/test membership.
"""
from pathlib import Path
from collections import Counter
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.analysis import exploitation_prerequisites as V
from src.common.data.prerequisite_research_schema import enrich
from tools.item4.build_operator_vep_curriculum import case,sha

HOME=ROOT/'results/operator_vep_adapter_v2'
POSITIVE={
 'CVE-2024-2617':[('feature_enabled','secure update feature','enabled','if secure update feature was not enabled on all CMUs of a RTU500',True)],
 'CVE-2023-0345':[('feature_enabled','secure shell (SSH) server','enabled','The Akuvox E11 secure shell (SSH) server is enabled by default',False)],
 'CVE-2026-1301':[('feature_enabled','PubSub','enabled','In builds with PubSub and JSON enabled',False),('feature_enabled','JSON','enabled','In builds with PubSub and JSON enabled',False)],
 'CVE-2003-0190':[('feature_enabled','PAM support','enabled','with PAM support enabled',False)],
 'CVE-2014-9293':[('configuration_required','auth key','configured','when an auth key is not configured',True)],
 'CVE-2026-8598':[('network_reachable','configuration export port','','An undocumented configuration export port is accessible on some models of ZKTeco CCTV cameras.',False)],
 'CVE-2023-3453':[('network_reachable','web management portal','','an attacker with adjacent network access',False)],
 'CVE-2011-0517':[('feature_enabled','Run TCP/IP server','enabled','when Run TCP/IP server is enabled',False)],
 'CVE-2023-40463':[('configuration_required','operating mode','debugging','When configured in debugging mode by an authenticated user with administrative privileges',False)],
 'CVE-2026-13348':[('feature_enabled','redirect handling','enabled','when redirect handling is disabled',True)],
 'CVE-2023-29463':[('interface_reachable','JMX Console','','The JMX Console within the Rockwell Automation Pavilion8 is exposed to application users',False)],
 'CVE-2023-40709':[('feature_enabled','built-in web server','enabled','if the controller has the built-in web server enabled',False)],
 'CVE-2023-4518':[('configuration_required','goose receiving blocks','configured','goose receiving blocks need to be configured',False)],
 'CVE-2012-4690':[('feature_enabled','Static status','enabled','when Static status is not enabled',True)],
 'CVE-2016-9347':[('feature_enabled','SSH (Secure Shell) functionality','enabled','have the SSH (Secure Shell) functionality enabled unnecessarily',False)],
 'CVE-2014-2361':[('user_performs_action','OleumTech WIO setup','use BreeZ','when BreeZ is used',False)],
 'CVE-2024-39870':[('privilege_required','own-user management','manage own users','the affected applications can be configured to allow users to manage own users',False)],
 'CVE-2026-100292':[('configuration_required','hidden debug interface','active','Once active, this pathway can unintentionally expose system‑level functionality',False)],
 'CVE-2014-3888':[('feature_enabled','FCS/Test Function','enabled','when FCS/Test Function is enabled',False)],
 'CVE-2024-42512':[('feature_enabled','deprecated Basic128Rsa15 security policy','enabled','when the deprecated Basic128Rsa15 security policy is enabled',False)],
 'CVE-2024-32754':[('configuration_required','controller operating state','factory reset waiting for initial setup','when the controller is in factory reset mode waiting for initial setup',False)],
 'CVE-2020-28393':[('feature_enabled','OSPF','enabled','Successful exploitation requires OSPF to be enabled',False)],
 'CVE-2025-13957':[('feature_enabled','SOCKS Proxy','enabled','when SOCKS Proxy is enabled',False)],
 'CVE-2025-50121':[('feature_enabled','HTTP','enabled','HTTP when enabled',False)],
 'CVE-2025-7353':[('feature_enabled','web-based debugger agent','enabled','the web-based debugger agent enabled on Rockwell Automation ControlLogix® Ethernet Modules',False)],
}
PARTIAL={
 'CVE-2023-40463':'The source also requires particular actor privileges; actual attacker possession is not established by operating records.',
 'CVE-2023-40709':'The source additionally requires an incompletely configured web server; the precise completion criterion is not specified.',
 'CVE-2014-2361':'Physical proximity, key acquisition and access alternatives require separate evidence; the stated BreeZ workflow alone is not a complete attack path.',
 'CVE-2026-100292':'The source also describes crafted inputs reaching a handler; an operator-verifiable trigger relationship is not established.',
 'CVE-2025-13957':'Administrator and database credential possession is an actor state, not an operator-verifiable prerequisite.',
 'CVE-2025-50121':'The source describes a malicious-folder trigger in addition to the HTTP setting; it is not a normal operating fact.',
 'CVE-2025-7353':'The specific required connection address is not stated. The enabled debugger alone does not establish the complete route.',
}
NO_CONDITION_NOTES={
 'CVE-2006-6488':'The long ActiveX argument is an exploit input, not a separately stated operating configuration or workflow.',
 'CVE-2021-22801':'Specially crafted event actions describe the attack input; the source does not establish a separately verifiable normal operating prerequisite.',
 'CVE-2026-32645':'Persistent factory credentials describe the defect; no independent operating prerequisite is stated.',
 'CVE-2022-2104':'An unsafe sudo policy is the reported configuration defect. No separate exploitation precondition is specified.',
 'CVE-2020-35565':'Disabled default brute-force protection is the defect description, not evidence of an independently selectable exploit prerequisite.',
 'CVE-2022-2179':'The missing response header is the defect, not a demonstrated operational setting or user action.',
 'CVE-2019-19000':'Misconfigured cache headers describe the defect; do not invent a cache-control operating switch.',
 'CVE-2017-6866':'The source specifies actor authentication/privilege and an impact, but no separately verifiable deployment restriction.',
 'CVE-2021-22636':'Heap implementation and allocator behavior are internal implementation details, not operator-verifiable settings in this source.',
 'CVE-2026-49035':'ASLR-disabled RCE is a demonstrated scenario, not a stated necessary condition for the CVE; other impacts remain possible with ASLR enabled.',
 'CVE-2018-10630':'Default disabled authentication describes the vulnerability; it is not a source-supported independent prerequisite.',
 'CVE-2026-81321':'Cleartext credential storage is the defect. Actual adversary filesystem access remains an actor capability, not an established operating fact.',
 'CVE-2012-5861':'Missing validation and absent authentication are defect/nonrequirement descriptions, not operator-checkable exploitation prerequisites.',
 'CVE-2024-41161':'Immutable hard-coded accounts are the defect. Do not manufacture a disable-account setting.',
 'CVE-2016-5815':'Missing default authentication is the defect rather than a separately stated operating precondition.',
 'CVE-2020-14478':'The source describes an XXE defect and actor access; it does not specify a normal operator workflow or exact configurable prerequisite.',
 'CVE-2024-3982':'Logging can be enabled by an attacker. Its default disabled state must not be inverted into an exploitation requirement; privileged actor possession is unresolved.',
 'CVE-2025-35451':'Immutable credentials and services describe the defect. Do not invent operator-controlled disabling as a precondition.',
 'CVE-2026-77975':'Exposure of credentials in exported configuration is the defect; actual attacker acquisition is unobservable here.',
 'CVE-2024-26155':'Hidden HTML containing credentials is an implementation defect, not a secure/unsafe operating-mode choice.',
 'CVE-2020-15790':'The source says insecure configuration but does not identify the particular setting or value.',
 'CVE-2022-34758':'A disabled watchdog is an outcome, and possession of privileged credentials is an unobservable actor state.',
 'CVE-2021-42797':'The description reports traversal and token theft; it does not establish a separate operational prerequisite.',
 'CVE-2017-16748':'Accepting a disabled account and blank password describes the authentication defect, not a condition an operator should attest as sufficient.',
 'CVE-2022-29962':'Hard-coded FTP credentials describe a defect. The text does not explicitly establish a complete operational prerequisite route.',
 'CVE-2025-24522':'Unconfigured default authentication is the reported defect, not a separate operator-verifiable prerequisite.',
}
NONREQUIREMENT_IDS={'CVE-2014-2356','CVE-2023-29155','CVE-2015-3459','CVE-2015-6480','CVE-2016-4860',
                    'CVE-2025-24924','CVE-2016-2296','CVE-2012-6068','CVE-2011-4051'}


def annotated(row):
    text=row['text'];cve=row['cve'];source=dict(id='nvd:'+cve,text=text,
        text_sha256=hashlib.sha256(text.encode()).hexdigest(),product_keys=[],
        scope_binding='unresolved',url='https://nvd.nist.gov/vuln/detail/'+cve)
    record=dict(cve=cve,sources=[source],products=[]);packet=V.extraction_packet(record)
    reference=[dict(evidence_id=packet['evidence'][0]['evidence_id'])]
    atoms=[];expressions=[]
    for i,(predicate,target,value,quote,negative) in enumerate(POSITIVE.get(cve,[])):
        # Quotes are manual annotations, not keyword-generated labels.
        if quote not in text:
            # Preserve the exact original capitalisation without editing source words.
            start=text.casefold().find(quote.casefold())
            if start<0:raise ValueError(cve+': annotation quote not found: '+quote)
            quote=text[start:start+len(quote)]
        kind='network_access' if predicate in {'network_reachable','interface_reachable'} else 'operating_workflow' if predicate=='user_performs_action' else 'access_policy' if predicate=='privilege_required' else 'configuration'
        record_type='firewall_acl' if kind=='network_access' else 'operating_procedure' if kind=='operating_workflow' else 'access_control_record' if kind=='access_policy' else 'configuration_export'
        cid='condition'+str(i+1)
        statement=target+' is enabled' if predicate=='feature_enabled' else target+' satisfies the recorded state: '+value
        atoms.append(dict(id=cid,predicate=predicate,target=target,value=value,statement=statement,
            operational_quote=quote,operator_observable=True,operator='eq',expected=True,
            observation=dict(kind=kind,record_type=record_type,check='Verify '+target+' against the stated source configuration or workflow'),
            source_refs=reference,necessity='required',review_status='pending',evidence_directness='direct_evidence'))
        if cve=='CVE-2024-2617':
            atoms[-1]['observation']['quantifier']='all'
            atoms[-1]['observation']['check']='Verify secure update is enabled on every CMU of the assessed RTU500'
            atoms[-1]['statement']='The secure update feature is enabled on all CMUs of the assessed RTU500'
        leaf={'condition':cid};expressions.append(dict(op='not',args=[leaf]) if negative else leaf)
    unknowns=[PARTIAL[cve]] if cve in PARTIAL else []
    if not atoms:
        if cve not in NO_CONDITION_NOTES and cve not in NONREQUIREMENT_IDS:raise ValueError('Unreviewed CVE: '+cve)
        unknowns=[NO_CONDITION_NOTES.get(cve,'Authentication is explicitly unnecessary, but the source provides no separately verifiable operating prerequisite.')]
    nonrequirements=[dict(statement=text,source_refs=reference)] if cve in NONREQUIREMENT_IDS else []
    excluded=[]
    if not atoms and cve in NO_CONDITION_NOTES:
        reason='unobservable_actor_state' if cve in {'CVE-2022-34758','CVE-2026-81321'} else 'impact' if cve=='CVE-2026-49035' else 'internal_architecture' if cve=='CVE-2021-22636' else 'implementation_defect'
        excluded=[dict(statement=text,reason=reason,source_refs=reference)]
    # Partial routes are deliberately non-executable until their remaining required relationship is established.
    scenarios=[] if not expressions or cve in PARTIAL else [dict(id='source_path',product_keys=[],product_binding='unresolved',
        expression=expressions[0] if len(expressions)==1 else dict(op='and',args=expressions),source_refs=reference)]
    target=enrich(dict(format=V.VERSION,cve=cve,prerequisites=atoms,scenarios=scenarios,nonrequirements=nonrequirements,
        excluded_facts=excluded,unknowns=unknowns))
    V.validate(V.resolve_references(target,packet),record)
    return dict(id='real-'+cve,cve=cve,split=row['split'],source_group=row['group'],synthetic=False,
        annotation_method='assistant_semantic_review_of_exact_NVD_description',expert_gold=False,
        family='negative' if any(p[-1] for p in POSITIVE.get(cve,[])) else 'ordinary' if atoms else 'defect_only',
        system=V.SYSTEM,packet=packet,target=target)


def build():
    candidates=json.loads((HOME/'real_candidates.json').read_text(encoding='utf-8'));output=HOME/'real_dataset';output.mkdir(exist_ok=True)
    data={split:[annotated(row) for row in candidates if row['split']==split] for split in ('train','test')}
    # Only eight fictional boundary cases supplement the real training descriptions.
    data['train'] += [case('train',i) for i in (0,1,4,5,7,8,10,11)]
    data['test'] += [case('test',i) for i in range(64)]
    groups={split:{r['source_group'] for r in rows if not r['synthetic']} for split,rows in data.items()}
    if groups['train']&groups['test']:raise ValueError('Source group leakage')
    hashes={}
    for split,items in data.items():
        path=output/(split+'.jsonl');path.write_text(''.join(json.dumps(r,ensure_ascii=False,separators=(',',':'))+'\n' for r in items),encoding='utf-8');hashes[path.name]=sha(path)
    manifest=dict(version='real-description-operator-vep/2',policy=V.VERSION,counts={s:len(v) for s,v in data.items()},sha256=hashes,
        real_counts={s:sum(not r['synthetic'] for r in v) for s,v in data.items()},
        source_groups_disjoint=True,all_unreviewed_cves_remain_unlabelled=True,annotation_method='assistant semantic review',
        expert_gold=False,independent_real_asset_accuracy_verified=False,
        primary_training_source='Exact real CVE descriptions; fictional boundary cases are supplemental')
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8');print(json.dumps(manifest));return manifest

if __name__=='__main__':build()
