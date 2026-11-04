"""Fictional #4 v3 contract pretraining; leaves all real annotation gold null."""
from pathlib import Path
import sys, json, hashlib, random
from collections import Counter
ROOT = Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.vex_routing import classify
from src.item4_questions import SYSTEM, topics
from src.operational_questions import ASSESSMENT_SYSTEM
from src.item4_role_tasks import check

PROFILES = [
    ('CWE-319', 'transport', 'sends credentials in cleartext over its documented network interface',
     'does the configured transport policy permit unencrypted traffic?', 'can untrusted clients access the {feature} network interface?', 'network_path'),
    ('CWE-327', 'cryptography', 'uses a vendor-documented weak TLS cipher on its network service',
     'are legacy cipher suites permitted by the configured TLS policy?', 'is the documented weak TLS cipher enabled on {feature}?', 'configuration'),
    ('CWE-306', 'authentication', 'permits unauthenticated requests to its documented service interface',
     'does the configured service access policy permit requests without sign-in?', 'can a client access {feature} without signing in?', 'authentication'),
    ('CWE-521', 'password', 'permits weak passwords under the documented account policy',
     'does the configured account policy permit weak passwords?', 'does the weak password policy apply to accounts for {feature}?', 'configuration'),
    ('CWE-614', 'cookie', 'uses a session cookie without its documented Secure attribute',
     'does the configured session-cookie policy permit cookies without the Secure attribute?', 'is the {feature} session cookie configured without the Secure attribute?', 'configuration'),
    ('CWE-732', 'permissions', 'grants excessive file permissions on its documented configuration resource',
     'does the configured file permission policy permit changes by non-maintenance accounts?', 'can non-maintenance accounts change the {feature} configuration resource?', 'privileges')]


def build():
    directory = ROOT/'data/operational_curriculum_v3'
    if (directory/'manifest.json').exists():raise FileExistsError('Frozen curriculum exists; use a new version.')
    roles = ('item4-questions','operation-assessment')
    data = {role: {} for role in roles}
    manifest = {'schema':'ics-vex-operational-curriculum/3', 'experimental':True, 'human_gold':False,
                'deployment_approved':False, 'test_loaded_for_training':False, 'heldout_test_created':True,
                'real_cve_annotation_files_modified':False, 'contract':'CWE-first common/specific source-ID questions + advisory assessment',
                'limitations':['Fictional cases, not real CVE gold.', 'Shared construction grammar; validation is not semantic generalization.',
                               'Scenario expectations follow explicit synthetic premises, never silently inferred real-world AND prerequisites.',
                               'Unknown versions and unsupported operating reports cannot establish clearance.',
                               'No automatic deployment; real paired reviewer ratings and Cohen kappa remain unavailable.'], 'roles':{}}
    for split, count in [('train',800),('validation',100),('test',100)]:
        scenarios = [i%8 for i in range(count)];random.Random('item4-v3-'+split).shuffle(scenarios)
        for role in roles:data[role][split] = []
        for i in range(count):
            cwe, profile, detail, common, specific, kind = PROFILES[i%len(PROFILES)]
            rid = 'SIM-'+split.upper()+'-'+str(i).zfill(4)
            feature = f'{split} station {i:04d} {profile} service'
            description = f'FICTIONAL CONTROLLED SCENARIO, not a real CVE. The {feature} {detail}. For this fixture only, the issue requires the named capability to be implemented, active and exposed to untrusted clients. Disabling the capability or filtering access is reversible mitigation, not code absence.'
            route = classify({'cve':rid,'cwe':[cwe],'description':description})
            assert route['requirement']=='operational_review', (cwe,route)
            sid = rid+':description'
            sources = [{'id':sid,'text':description,'source_kind':'description','condition_eligible':True,
                        'source':{'source':'controlled_synthetic_fixture','independently_verified':False}}]
            questions = [{'scope':scope,'question':'On this asset, '+question.format(feature=feature),
                          'purpose':purpose,'evidence_ids':[sid],'kind':qkind,'answer_type':'yes_no_unknown'}
                         for scope, question, purpose, qkind in [
                             ('common',common,'Check the configured weakness-type policy.','configuration'),
                             ('specific',specific,'Check the documented service-specific operating fact.',kind)]]
            qpacket = {'cve':rid,'description':description,'vector':None,'cwe':[cwe], 'component':'fictional-device',
                       'version':None,'cwe_context':{'entries':[{'id':cwe}]},'analysis_route':{k:route[k] for k in ['requirement','pillars','policy_version']},
                       'pillar_ids':route['pillars'],'common_topics':topics({'analysis_route':route}),
                       'extraction':{'status':'synthetic_reference','usable':True,'condition_evidence_ids':[sid],'function_candidates':[]},'sources':sources}
            scenario = scenarios[i]
            # Operational answers collect facts; the fictional scenario record is explicit evidence.
            qa = [{**q,'id':rid+':q:'+str(j),'origin':'llm', 'evidence':description,
                   'answer':{'value':'yes','evidence':'SIMULATED vendor and configuration record: capability implemented, active and exposed.',
                             'provenance':'synthetic_operator_report','independently_verified':False}} for j,q in enumerate(questions)]
            labels = ['likely_affected','likely_affected','likely_not_affected','likely_mitigated',
                      'likely_mitigated','likely_cannot_determine','likely_cannot_determine','likely_cannot_determine']
            reasons = ['The explicit simulated record reports all fixture prerequisites; independent verification is still needed.']*2 + [
                'The simulated vendor variant record states that the required capability is not implemented; this supports an advisory negative only.',
                'The simulated configuration disables an implemented capability. This is reversible mitigation, not code absence.',
                'The simulated access rule filters untrusted clients. This is mitigation, not permanent immunity.',
                'All operating answers are unknown; missing facts do not refute or satisfy prerequisites.',
                'The reported answers have no supporting records, so the advisory result is unresolved.',
                'The installed version has not been established. Reported operating facts do not resolve applicability.']
            # Explicit synthetic premises avoid guessing the meaning of yes/no across differently phrased questions.
            records = ['Capability absent in vendor product variant','Capability present but disabled','Capability present; client access filtered']
            if scenario in (2,3,4):
                for q in qa:q['answer'].update(value='no',evidence='SIMULATED signed scenario record: '+records[scenario-2]+'.')
            if scenario==5:
                for q in qa:q['answer'].update(value='unknown',evidence='')
            if scenario==6:
                for q in qa:q['answer']['evidence']=''
            apacket = {'cve':rid,'description':description,'vector':None,'version_decided':scenario!=7,
                       'version_evaluation':{'version_decided':scenario!=7,'components':[], 'fixture_only':True},
                       'questions_and_answers':qa,'question_generation_valid':True}
            target = {'assessment':labels[scenario],'explanation':reasons[scenario],
                      'answer_refs':[q['id'] for q in qa], 'missing_evidence':['Independent verification of synthetic operating reports']}
            for role, packet, prediction, system in [('item4-questions',qpacket,{'questions':questions},SYSTEM),
                                                      ('operation-assessment',apacket,target,ASSESSMENT_SYSTEM)]:
                checked = check(role,packet,prediction)
                assert all(checked.values()), (rid,role,checked)
                data[role][split].append({'id':role+':'+rid,'split':split,'group_id':split+'-family-'+str(i//8),
                    'packet':packet,'target':prediction,'scenario':scenario,'simulation':True,
                    'annotation_basis':'explicit_controlled_synthetic_premises_not_expert_gold',
                    'messages':[{'role':'system','content':system},{'role':'user','content':json.dumps(packet,ensure_ascii=False)},
                                {'role':'assistant','content':json.dumps(prediction,ensure_ascii=False)}]})
    for role in roles:
        folder = directory/role;folder.mkdir(parents=True,exist_ok=True)
        spec = {'references':'Explicit fictional curriculum, not independent CVE/VEX accuracy.','splits':{}}
        for split, rows in data[role].items():
            path = folder/(split+'.jsonl');path.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows),encoding='utf-8')
            spec['splits'][split] = {'examples':len(rows),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                'advisory_labels':dict(Counter(r['target']['assessment'] for r in rows)) if role=='operation-assessment' else {}}
        manifest['roles'][role] = spec
    (directory/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps({r:{s:len(v) for s,v in splits.items()} for r,splits in data.items()},indent=2))


if __name__=='__main__':build()
