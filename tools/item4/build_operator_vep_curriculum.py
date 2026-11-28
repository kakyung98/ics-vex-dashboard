"""Synthetic corrective curriculum for operator-only VEP extraction.

This is contract supervision with fictional products/CVE IDs, not independent
real-CVE Gold. The parent adapter's full-population provenance is retained by
the trainer; no real held-out CVE labels are used for this corrective stage.
"""
from copy import deepcopy
from pathlib import Path
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.analysis import exploitation_prerequisites as V
from src.common.data.prerequisite_research_schema import enrich

OUT=ROOT/'results/operator_vep_adapter_v2/dataset'


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def case(split,index):
    family=index%16;variant=index//16
    services=['FTP','SSH','Telnet','HTTP'] if split=='train' else ['SNMP','MQTT','OPC UA','RDP']
    service=services[variant%len(services)]
    product=('Curriculum' if split=='train' else 'Challenge')+' Device '+str(variant)
    interface=service+' management interface';kind='ordinary'
    quotes=[];atoms=[];expression=None;excluded=[];nonrequirements=[]
    def atom(cid,predicate,target,value='',negative=False,observation='configuration',record='configuration_export'):
        atoms.append(dict(id=cid,predicate=predicate,target=target,value=value,
            extraction_confidence=0.95,category={'feature_enabled':'OTHER','configuration_required':'OTHER',
                'authentication_required':'PR','privilege_required':'PR','file_import':'UI',
                'user_performs_action':'UI','remote_maintenance':'AV','physical_access':'AV',
                'network_reachable':'AV','interface_reachable':'AV','local_console_access':'AV'}.get(predicate,'OTHER'),
            statement=target+' is enabled' if predicate=='feature_enabled' else 'The required operating state of '+target+' is present',
            operator_observable=True,operator='eq',expected=True,
            observation=dict(kind=observation,record_type=record,check='Check the recorded state of '+target),
            necessity='required',review_status='pending',evidence_directness='direct_evidence'))
        leaf={'condition':cid}
        return dict(op='not',args=[leaf]) if negative else leaf
    if family==0:
        quotes=[f'Exploitation requires {service} enabled.'];expression=atom('service','feature_enabled',service,'enabled')
    elif family==1:
        kind='negative';quotes=[f'Exploitation is possible only when {service} is disabled.']
        expression=atom('service','feature_enabled',service,'enabled',negative=True)
    elif family==2:
        quotes=[f'Exploitation requires network access to the {interface}.']
        expression=atom('path','network_reachable',interface,observation='network_access',record='firewall_acl')
    elif family==3:
        quotes=[f'Exploitation requires an operator to open an externally supplied project file in {product}.']
        expression=atom('action','user_performs_action',product,'open an externally supplied project file',observation='operating_workflow',record='operating_procedure')
    elif family==4:
        kind='and';quotes=[f'Exploitation requires {service} enabled and network access to the {interface}.']
        expression=dict(op='and',args=[atom('service','feature_enabled',service,'enabled'),
            atom('path','network_reachable',interface,observation='network_access',record='firewall_acl')])
    elif family==5:
        kind='or';quotes=[f'Exploitation requires either {service} enabled or an operator to import an external project file into {product}.']
        expression=dict(op='or',args=[atom('service','feature_enabled',service,'enabled'),
            atom('action','user_performs_action',product,'import an external project file',observation='operating_workflow',record='operating_procedure')])
    elif family==6:
        kind='mixed_defect';quotes=['The software does not properly validate the server certificate when initiating a TLS connection.',f'Exploitation requires {service} enabled.']
        excluded=[dict(statement=quotes[0],reason='implementation_defect',source_refs=[dict(evidence_id='e1')])]
        expression=atom('service','feature_enabled',service,'enabled')
    elif family in (7,8,9):
        kind='defect_only'
        quotes=[{7:'The affected software does not properly validate the server certificate when initiating a TLS connection.',
                 8:'The application fails to properly sanitize or escape data received from the backend before rendering it in the user interface.',
                 9:'The vulnerable front end is integrated with Node.js, allowing arbitrary JavaScript execution.'}[family]]
        excluded=[dict(statement=quotes[0],reason='internal_architecture' if family==9 else 'implementation_defect',source_refs=[dict(evidence_id='e1')])]
    elif family==10:
        kind='nonrequirement';quotes=['Exploitation does not require authentication.']
        nonrequirements=[dict(statement=quotes[0],category='PR',source_refs=[dict(evidence_id='e1')])]
    elif family==11:
        kind='and_not';quotes=[f'Exploitation requires {service} enabled and the diagnostic listener disabled.']
        expression=dict(op='and',args=[atom('service','feature_enabled',service,'enabled'),
            atom('diagnostic','feature_enabled','diagnostic listener','enabled',negative=True)])
    elif family==12:
        quotes=[f'Exploitation requires the application to run in maintenance mode.']
        expression=atom('mode','configuration_required','application operating mode','maintenance',observation='operating_mode',record='maintenance_log')
    elif family==13:
        quotes=[f'Exploitation requires authentication to be enabled for the {interface}.']
        expression=atom('authentication','authentication_required',interface,observation='access_policy',record='access_control_record')
    elif family==14:
        quotes=[f'Exploitation requires the remote maintenance path to the {interface} to be enabled.']
        expression=atom('maintenance','remote_maintenance',interface,observation='network_access',record='firewall_acl')
    else:
        quotes=[f'Exploitation requires physical access to the {service} maintenance connector.']
        expression=atom('physical','physical_access',service+' maintenance connector',observation='physical_access',record='access_control_record')
    # Every source has a fictional product identifier; no asset truth is implied.
    text=product+'.\n\n'+'\n\n'.join(quotes)
    cve='CVE-2096-'+str((10000 if split=='train' else 50000)+index)
    source=dict(id='synthetic:'+cve,text=text,text_sha256=hashlib.sha256(text.encode()).hexdigest(),
        product_keys=['p1'],url='https://example.invalid/operator-vep/'+cve,subject_ambiguous=False)
    record=dict(cve=cve,sources=[source],products=[dict(key='p1',aliases=[product])])
    packet=V.extraction_packet(record)
    # e1 is the product paragraph; resolve exact paragraph IDs from the catalogue.
    evidence={e['quote']:e['evidence_id'] for e in packet['evidence']}
    for row in excluded+nonrequirements:row['source_refs']=[dict(evidence_id=evidence[row['statement']])]
    support=quotes[-1]
    for item in atoms:
        item['operational_quote']=support
        item['source_refs']=[dict(evidence_id=evidence[support])]
    scenarios=[] if expression is None else [dict(id='path',product_keys=['p1'],product_binding='source_bound',
        expression=expression,source_refs=[dict(evidence_id=evidence[support])])]
    target=enrich(dict(format=V.VERSION,cve=cve,prerequisites=atoms,scenarios=scenarios,
        nonrequirements=nonrequirements,excluded_facts=excluded,
        unknowns=[] if atoms else ['No operator-verifiable exploitation prerequisite is stated; exploitability remains unknown.']))
    V.validate(V.resolve_references(target,packet),record)
    return dict(id=split+'-'+str(index),split=split,family=kind,synthetic=True,
                system=V.SYSTEM,packet=packet,target=target)


def build(output=OUT):
    output.mkdir(parents=True,exist_ok=True)
    counts={'train':512,'test':64};hashes={}
    for split,count in counts.items():
        path=output/(split+'.jsonl')
        with path.open('w',encoding='utf-8') as stream:
            for i in range(count):stream.write(json.dumps(case(split,i),ensure_ascii=False,separators=(',',':'))+'\n')
        hashes[path.name]=sha(path)
    manifest=dict(version='operator-vep-corrective-curriculum/2',policy=V.VERSION,
        counts=counts,sha256=hashes,synthetic=True,expert_gold=False,
        real_cve_labels_used=False,test_examples_used_for_optimization=False,
        training_scope='Corrective continuation of the separately trained full-population VEP adapter',
        evaluation_scope='Synthetic contract and polarity challenges; not independent real-CVE accuracy')
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(manifest));return manifest


if __name__=='__main__':build()
