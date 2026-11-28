"""Explicit, reviewable answer domains for every v0.4 detail. No model calls."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from html import escape
import json,hashlib

ROOT=Path(__file__).resolve().parents[2]
F={}
def family(name,options,reference_kind=None):
    F[name]=dict(options=[dict(code=code,label=label,requires_complete_scope=negative,
                             requires_value_reference=bool(reference_kind) and code not in {'none','unavailable','not_used','absent'})
                         for code,label,negative in options],reference_kind=reference_kind)

family('design',[('included','Documented in the assessed design',False),('partial','Documented for only part of the assessed design',False),('not_included','Confirmed not included in the assessed design',True)])
family('review',[('completed','Review completed for the current assessed scope',False),('partial','Review covers only part of the scope or an older baseline',False),('not_done','Confirmed no review for the current scope',True)])
family('presence',[('present','Present or used in the assessed scope',False),('mixed','Present for some assessed subjects, absent for others',False),('absent','Confirmed absent throughout the assessed scope',True)])
family('implementation',[('implemented','Implemented for the assessed subjects',False),('partial','Implemented for only some assessed subjects',False),('absent','Confirmed not implemented in the assessed scope',True)])
family('capability',[('supported','Supported for the assessed function',False),('limited','Supported with documented limitations',False),('unsupported','Confirmed unsupported for the assessed function',True)])
family('registry',[('listed','Current values are available in the selected source records',False),('partial','Only a partial or outdated inventory is available',False),('unavailable','Confirmed no applicable inventory is available',True)],'inventory')
family('change',[('controlled','Changes follow the documented change process',False),('exceptions','Changes include documented process exceptions',False),('uncontrolled','Changes occurred outside the documented process',False),('none','No changes in the assessed period, confirmed from records',True)])
family('perimeter',[('defined','Boundary and crossing points are documented',False),('partial','Only part of the boundary or crossing points is documented',False),('undefined','Confirmed no defined boundary for this scope',True)])
family('traffic',[('shared','Control and non-control traffic share the assessed network',False),('separated','The assessed traffic classes use separated networks',True),('mixed','Separation differs across the assessed paths',False)])
family('dependency',[('required','The assessed function depends on the external service or link',False),('optional','The external service or link is used without being required for this function',False),('mixed','Dependencies differ across the assessed functions',False),('none','No such dependency in the complete assessed scope',True)])
family('collection',[('covered','Required records are collected and retained for the assessed period',False),('gaps','Collection, retention, or time coverage has known gaps',False),('none','No such records in the assessed period, confirmed',True)])
family('segmentation',[('enforced','The documented boundary policy is applied to the assessed paths',False),('exceptions','Applied with documented exceptions or bypass paths',False),('not_enforced','The assessed paths do not enforce the documented boundary',False)])
family('patch',[('available','A patch for this vulnerability and product/build is available',False),('pending','The vendor identifies a pending or delayed patch',False),('unavailable','The vendor confirms no patch for this product/build',False)])
family('patch_status',[('installed','The identified applicable patch is installed in the assessed baseline',False),('missing','An identified applicable patch is available but not installed',False),('awaiting','The applicable patch is pending vendor release or validation',False),('mixed','Installation or validation status differs across the assessed patches',False)],'patch')
family('encryption',[('encrypted','Encryption is applied to the selected communication paths',False),('plaintext','The selected communication paths transmit without encryption',False),('mixed','Encryption differs across the selected paths',False)],'cryptography')
family('log_adequacy',[('adequate','A documented review finds the records adequate for its stated investigation purpose',False),('gaps','The review identifies missing events, periods, or required record sources',False),('unavailable','The required records are confirmed unavailable for that purpose',True)],'analysis')
family('support',[('supported','Security patches are supported for the assessed release',False),('limited','Support is limited or subject to a documented exception',False),('ended','Security patch support has ended or is explicitly unavailable',False)])
family('test',[('passed','Relevant tests passed for the current baseline and tested scope',False),('failed','Relevant tests identified failures or adverse effects',False),('limited','Testing covers only part of the scope or a different baseline',False),('not_done','Confirmed no relevant tests were performed',True)])
family('mitigation',[('implemented','A documented interim measure is applied in this scope',False),('planned','A measure is documented but not yet applied',False),('none','No interim measure for this scope, confirmed',True)])
family('plan',[('approved','An approved plan covers the current subject and scope',False),('partial','A draft, partial, or outdated plan is available',False),('none','Confirmed no applicable plan',True)])
family('deferral',[('deferred','Patching is deferred to a documented maintenance window',False),('not_deferred','Patching is not deferred to operational downtime',True),('mixed','Deferral differs across assessed patches or assets',False)])
family('isolation',[('physical','Physical isolation is documented for the assessed connections',True),('logical','Connected through documented logical isolation controls',False),('connected','Connected without an isolation claim',False),('mixed','Isolation differs across the assessed connections',False)])
family('exposure',[('reachable','A path is reachable from the stated external origin',False),('restricted','A path exists with documented access restrictions',False),('blocked','No permitted path from that origin in the complete assessed scope',True),('mixed','Reachability differs across the assessed paths',False)])
family('test_environment',[('separate','Testing uses a separate environment',False),('production','Testing uses the live operational system',False),('mixed','Both separate and operational environments are used',False),('none','No testing environment or activity in the assessed scope',True)])
family('coordination',[('coordinated','Testing is coordinated with the vendor/integrator',False),('not_coordinated','Testing proceeded without that coordination',True),('not_required','A documented vendor/integrator decision states coordination is not required',False)])
family('access',[('restricted','Access is limited to the documented allowed subjects',False),('exceptions','Restrictions include documented exceptions',False),('unrestricted','Assessed access is not limited to the documented allowed subjects',False)])
family('default_config',[('default','Vendor default configuration remains in use',False),('changed','The assessed defaults have been changed',True),('mixed','Some assessed subjects retain defaults and others do not',False)])
family('backup',[('current','A current recoverable copy covers this configuration',False),('outdated','A copy exists but is outdated or incomplete',False),('none','Confirmed no stored or backup copy for this configuration',True)])
family('cleartext',[('cleartext','Sensitive information is stored or transferred in cleartext',False),('protected','The complete assessed information flow/storage is protected from cleartext exposure',True),('mixed','Protection differs across assessed information or paths',False)])
family('default_credentials',[('in_use','Vendor default credentials remain in use',False),('replaced','All assessed vendor defaults are replaced or disabled',True),('mixed','Some assessed defaults remain in use',False)])
family('policy',[('conforms','Evidence shows conformance to the identified policy in this scope',False),('exceptions','Documented policy exceptions apply',False),('violations','Evidence shows policy violations in this scope',False)])
family('privilege_fit',[('aligned','Privileges match the documented responsibilities',False),('excessive','At least one assessed subject has privileges beyond its responsibilities',False),('insufficient','At least one assessed subject lacks required operational privileges',False),('mixed','Both excessive and insufficient assignments are documented',False)])
family('impact',[('adverse','The cited record documents an adverse operational effect',False),('not_observed','The cited scoped test or incident record reports no such effect',True),('mixed','Results differ across the assessed cases',False)])
family('update',[('current','Current against the identified vendor/update baseline',False),('outdated','Behind the identified baseline',False),('mixed','Currency differs across assessed installations',False)])
family('enabled',[('enabled','Enabled for the assessed function or interface',False),('disabled','Disabled for the complete assessed function or interface',True),('mixed','Enabled state differs across the assessed subjects',False)])
family('configuration_control',[('consistent','Settings can be consistently applied and audited in this scope',False),('limited','Application or audit has documented limitations',False),('unsupported','Consistent application or auditing is not supported',False)])
family('disable_limit',[('can_disable','All assessed unnecessary services can be disabled',False),('cannot_disable','A documented device limitation prevents disabling a service',False),('mixed','Disable capability differs across the assessed services',False)])
family('cloud_control',[('customer','The assessed settings are visible and configurable by the customer',False),('shared','Customer and provider responsibilities divide visibility or control',False),('provider','Settings are provider-managed without customer configuration control',False),('limited','Visibility or control has documented gaps',False)])
family('visibility',[('available','Relevant configuration or monitoring information is available',False),('partial','Only part of the required information is visible',False),('unavailable','Relevant information is unavailable to the organization',False)])
family('disturbance',[('documented','The cited assessment documents exposure to this disturbance',False),('excluded','The cited complete assessment excludes this exposure for its stated conditions',True),('mixed','Exposure differs across assessed locations or conditions',False)])
family('power_behavior',[('safe_shutdown','The cited record documents a defined safe shutdown',False),('continues','The cited record documents continued operation',False),('disruption','The cited record documents loss of control, restart failure, or another disruption',False),('mixed','Behavior differs across assessed cases',False)],'impact')
family('volatile',[('volatile','Relevant programs or data depend on volatile memory',False),('nonvolatile','All assessed relevant state is retained without that volatile-memory dependency',True),('mixed','Retention differs across assessed programs or data',False)])
family('environment',[('within_limits','The assessed conditions meet the documented device limits',False),('outside_limits','At least one assessed condition exceeds a documented device limit',False),('control_gaps','Environmental control has documented coverage gaps',False)],'environment')
family('validation_evidence',[('vendor_confirms','A product/build-specific vendor or analysis record confirms the validation behavior',False),('defect_confirmed','A product/build-specific advisory or analysis documents a validation defect',False),('limited','Available evidence covers only part of the inputs or another build',False)],'analysis')
family('defect_evidence',[('defect_confirmed','An advisory or qualified analysis documents a defect for this product/build',False),('scoped_exclusion','Qualified analysis excludes the named defect in its explicit scope',True),('limited','Evidence is insufficient for this product/build or affected function',False)],'analysis')
family('authentication',[('required','Authentication is enforced on the assessed interaction',False),('none','The assessed interaction does not require authentication',False),('mixed','Authentication differs across the assessed interactions',False)],'authentication')
family('capability_evidence',[('supported','The cited product/protocol record documents support',False),('unsupported','The cited product/protocol record explicitly documents no support',False),('limited','Support is conditional or limited to documented modes',False)],'capability')
family('mutual_auth',[('mutual','Both client and access point authenticate each other',False),('one_way','Only one side authenticates the other',False),('none','Neither side is authenticated on the assessed link',False),('mixed','Authentication direction differs across assessed links',False)],'authentication')
family('write_protect',[('enabled','Hardware write protection restricts the assessed wireless configuration',False),('disabled','Hardware write protection is available but not applied',False),('unsupported','The cited device record documents no such hardware write protection',False),('mixed','Protection differs across assessed devices',False)])

# Exact values come from source-linked registered records, never a fixed vendor,
# port, version, or product-name vocabulary invented by the questionnaire.
for name,kind in [('identity','identity'),('version','version'),('location','location'),('topology','topology'),
 ('mechanism','control'),('service','service'),('network_location','network'),('path','path'),('settings','configuration'),
 ('role','role'),('link','data_link'),('interface','interface'),('personnel','personnel'),('physical_port','physical_port'),
 ('protocol','protocol'),('wireless','wireless'),('monitoring','monitoring'),('cloud','cloud'),('loop','control_loop')]:
    family(name,[('listed','Select the current source-record values for this subject',False),('partial','Only partial or outdated source-record values are available',False),('none','No such values or objects in the complete assessed scope',True)],kind)

ASSIGN={}
def assign(family_name,ids):
    for fid in ids.split():
        assert fid not in ASSIGN,fid
        ASSIGN[fid]=family_name

assign('design','C12-01.01 C12-01.02 C12-01.05 C12-09.01 C12-11.02')
assign('mechanism','C12-01.03 C13-10.03 C13-12.01 C14-02.03 C15-02.01 C16-01.02 C16-07.02')
assign('topology','C12-01.04')
assign('change','C12-02.01 C13-01.04 C13-02.05')
assign('review','C12-02.02 C12-10.02 C12-11.03 C13-08.04 C16-11.03')
assign('presence','C12-02.03 C12-04.01 C12-07.01 C12-08.01 C12-10.01 C12-11.01 C13-07.01 C13-10.01 C13-13.03 C13-13.04 C13-14.01 C13-15.01 C13-18.01 C13-20.04 C14-01.03 C14-03.01 C17-01.02 C17-01.03 C17-02.01 C17-03.02 C16-02.01 C16-09.01')
assign('perimeter','C12-03.01')
assign('implementation','C12-03.02 C12-06.04 C12-10.03 C13-07.04 C13-14.04 C14-01.02 C14-05.02 C15-03.03 C16-01.01 C16-07.01 C17-01.01 C17-01.04 C17-02.03 C17-03.03 C13-07.02')
assign('traffic','C12-04.02')
assign('service','C12-05.01 C13-08.01 C13-08.02')
assign('network_location','C12-05.02')
assign('dependency','C12-05.03 C12-08.02 C16-11.01')
assign('collection','C12-06.01 C12-06.02 C12-06.03 C13-19.01 C13-19.02 C16-03.01 C16-03.02')
assign('path','C12-07.02 C12-08.03 C13-21.04 C16-02.03 C16-10.04 C16-11.02')
assign('segmentation','C12-07.03 C16-10.05')
assign('capability','C12-09.02 C12-09.03')
assign('identity','C13-01.01')
assign('location','C13-01.02')
assign('version','C13-01.03 C13-02.03')
assign('patch','C13-02.01 C13-03.01 C13-04.02')
assign('settings','C13-02.02 C13-14.03 C13-20.01 C13-21.02 C16-02.02')
assign('registry','C13-02.04')
assign('test','C13-03.02 C13-06.01 C13-16.01 C13-18.03')
assign('mitigation','C13-03.03')
assign('support','C13-04.01 C13-05.03')
assign('plan','C13-04.03 C13-05.01 C13-06.02 C13-09.03')
assign('deferral','C13-05.02')
assign('isolation','C13-05.04')
assign('exposure','C13-05.05')
assign('test_environment','C13-06.03')
assign('coordination','C13-06.04')
assign('role','C13-07.03 C13-13.01 C15-03.02')
assign('default_config','C13-08.03')
assign('backup','C13-09.01 C13-09.02')
assign('cleartext','C13-10.02 C16-04.02 C16-09.02 C16-10.01')
assign('default_credentials','C13-11.01 C13-20.03')
assign('policy','C13-12.02')
assign('privilege_fit','C13-13.02')
assign('link','C13-14.02')
assign('update','C13-15.02 C13-15.03')
assign('impact','C13-16.02 C13-17.01 C13-17.02 C14-03.04 C14-04.02')
assign('monitoring','C13-18.02 C16-03.03')
assign('configuration_control','C13-20.02')
assign('disable_limit','C13-20.05')
assign('cloud_control','C13-21.01')
assign('visibility','C13-21.03')
assign('personnel','C14-01.01')
assign('disturbance','C14-02.01 C14-02.02')
assign('power_behavior','C14-03.02')
assign('volatile','C14-03.03')
assign('environment','C14-04.01')
assign('physical_port','C14-05.01')
assign('validation_evidence','C15-01.01 C15-01.02')
assign('defect_evidence','C15-01.03 C16-06.03')
assign('enabled','C15-02.02')
assign('authentication','C15-03.01 C16-05.01 C16-05.02 C16-05.03 C16-10.02')
assign('protocol','C16-04.01')
assign('capability_evidence','C16-06.01 C16-06.02')
assign('mutual_auth','C16-08.02')
assign('wireless','C16-08.01 C17-02.02')
assign('write_protect','C17-02.04')
assign('loop','C17-03.01')
assign('implementation','C16-10.03')
# Explicit corrections preserve installation vs patch availability, and
# encryption vs the broader concept of cleartext exposure.
ASSIGN['C13-02.01']='patch_status'
ASSIGN['C12-01.05']='mechanism'
ASSIGN['C16-09.02']='encryption';ASSIGN['C16-10.01']='encryption'
ASSIGN['C16-03.03']='log_adequacy'

def main():
    labels=dict(line.split('|',1) for line in (ROOT/'src/research/ui/nist_profile_details.en.txt').read_text().splitlines() if line)
    assert set(ASSIGN)==set(labels),(set(labels)-set(ASSIGN),set(ASSIGN)-set(labels))
    source=json.loads((ROOT/'site/nist-operating-information.json').read_text(encoding='utf-8'))
    details={e['id']:(r,e) for r in source['rows'] for e in r['collection_elements']}
    specs={}
    for fid,kind in ASSIGN.items():
        row,detail=details[fid];family_spec=F[kind]
        specs[fid]=dict(id=fid,label=labels[fid],answer_family=kind,**family_spec,
            question='Select the evidence-supported finding for: '+labels[fid],
            source=dict(row_id=row['source_id'],table=row['table'],pdf_page=row['pdf_page'],printed_page=row['printed_page'],
                        url=row['url'],column=detail['source_column'],quote=detail['quote']),
            evidence_required=True,coverage_options=['complete','partial'],
            scope_definition='Current assessed asset/component or explicitly selected system context; exceptions remain visible.',
            direct_vex_inference=False,
            allowed_evidence_kinds=(['vendor_document','assessment_record'] if kind in {'validation_evidence','defect_evidence','capability_evidence'} else
                ['test_record','vendor_document','assessment_record'] if kind in {'test','impact','power_behavior','disturbance','log_adequacy'} else
                ['inventory_record','configuration_record','operating_record','vendor_document','test_record','assessment_record']),
            interpretation='Options are project-designed observation codes, not NIST-prescribed answers or an assessment of security effectiveness.')
    result=dict(version='nist-selectable-answers/1',review_status='Expert-review candidate; not independently expert-validated',
        source_document_sha256=source['mapping_document_sha256'],source_items=54,detail_count=167,
        answer_states=['unknown','recorded','not_applicable','conflicting'],
        unknown_reasons=['not_surveyed','evidence_missing','outside_inventory','value_not_represented','scope_mismatch'],
        rules=['No text interpretation or LLM call in answer validation or VEX evaluation.',
               'Unknown and unrepresented values never become absence.',
               'Negative or exhaustive choices require complete surveyed scope and referenced evidence.',
               'Support, enablement, reachability, and demonstrated CVE-specific effect are distinct.',
               'Exact identities, ports, versions and paths are selected from a registered inventory, not invented enumerations.',
               'Source-only implementation questions require product/build-specific vendor or analysis records.',
               'A choice does not establish a CVE prerequisite. Condition rules must be source-specific and reviewed.',
               'A control, backup, log, patch plan, or test does not alone establish not_affected.'],fields=specs)
    result['sha256']=hashlib.sha256(json.dumps(result,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
    path=ROOT/'docs/nist_selectable_answers.v1.json';path.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    parts=['<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Selectable answer design review</title><style>body{font:16px/1.6 system-ui;max-width:1100px;margin:30px auto;padding:20px}section{border-top:1px solid #ddd;padding:20px 0}td,th{padding:12px;text-align:left;vertical-align:top;border:1px solid #ddd}table{border-collapse:collapse;width:100%}blockquote{border-left:3px solid #999;padding-left:15px}code{overflow-wrap:anywhere}</style><h1>54 source items / 167 selectable observations</h1><p>'+escape(result['review_status'])+'</p><p>All answers below are project-designed, versioned codes. Independent semantic and expert validation remains outstanding.</p><ul>']
    parts += ['<li>'+escape(rule)+'</li>' for rule in result['rules']]
    parts.append('</ul>')
    for fid in labels:
        f=specs[fid];parts.append('<section id="'+fid+'"><h2>'+escape(fid+' · '+f['label'])+'</h2><p>'+escape(f['question'])+'</p><p>Answer family: '+f['answer_family']+' · Registered-value type: '+str(f['reference_kind'])+'</p><table><tr><th>Code</th><th>Meaning</th><th>Complete scope required</th><th>Registered values required</th></tr>')
        for o in f['options']:parts.append('<tr><td>'+o['code']+'</td><td>'+escape(o['label'])+'</td><td>'+str(o['requires_complete_scope'])+'</td><td>'+str(o['requires_value_reference'])+'</td></tr>')
        parts.append('</table><p>Unknown, not applicable, conflicting evidence, and unrepresented values remain separate states.</p><a href="'+f['source']['url']+'">NIST source, Table '+str(f['source']['table'])+', PDF p.'+str(f['source']['pdf_page'])+'</a><blockquote>'+escape(f['source']['quote'])+'</blockquote><p>'+escape(f['interpretation'])+'</p></section>')
    parts.append('</html>');(ROOT/'site/nist-answer-design.html').write_text(''.join(parts),encoding='utf-8')
    print(json.dumps(dict(fields=len(specs),families=len({f['answer_family'] for f in specs.values()}),hash=result['sha256'])))
if __name__=='__main__':main()
