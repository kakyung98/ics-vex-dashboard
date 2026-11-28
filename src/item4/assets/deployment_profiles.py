"""Operator-owned deployment profiles. Templates never populate installation facts."""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
from jsonschema import Draft202012Validator
from src.item4.assets.operator_asset_form import build_form; from src.item4.assets.operator_asset_form import ROWS; from src.item4.assets.operator_asset_form import obj
from src.item4.assets.asset_profile_fields import asset_catalog
from src.item4.analysis.advisory_source_bundles import seal; from src.item4.analysis.advisory_source_bundles import verify_seal

ROOT = Path(__file__).resolve().parents[3]
VERSION = 'ics-operating-profile/1'
SCOPE = {
    'asset_ref': '실제 자산 / 구성요소 식별자', 'product': '제조사·제품·모델',
    'build': '설치·실행 버전 / 펌웨어', 'config_baseline': '구성 기준선 / 설정 백업 식별자',
    'mode': '평가 대상 운전 모드', 'origin': '접근을 검토할 출발 구간 / 주체',
    'reviewer': '작성자 / 확인 담당자', 'observed_at': '관측 시각 (시간대 포함)',
    'valid_until': '유효기한 (시간대 포함)',
}
EXTRA = {
    'operational_dependencies': '제어·안전·통신 의존 대상, 이중화와 허용 중단 시간을 기록하십시오.',
    'patch_and_recovery': '패치 승인·적용 창, 재시작 제한, 설정·프로그램 백업과 복구 확인 기록을 적으십시오.',
    'monitoring_and_changes': '로그 수집·보존, 시간 동기화와 설정 변경 감시·승인 절차를 기록하십시오.',
}


def catalogue():
    profiles = []
    for asset in asset_catalog(ROOT/'data/standards/ics-attack-20.1.json'):
        form = build_form([asset['id']])
        definition = form['definition']
        properties = definition['schema']['properties']['values']['properties']
        required = definition['schema']['properties']['values']['required']
        for fid, question in EXTRA.items():
            properties[fid] = deepcopy(properties['services'])
            properties[fid]['oneOf'][1]['properties']['data']['items'] = obj({'detail': {'type':'string','minLength':1}})
            required.append(fid)
            definition['fields'].append(dict(id=fid, question=question, data_kind='notes',
                evidence_required=True, absence_not_inferred=True, maps_to_cve_condition_automatically=False))
            form['input']['values'][fid] = dict(state='unknown', data=None, evidence_ids=[])
        seal(definition, 'definition_sha256')
        profiles.append(dict(asset=asset, definition=definition,
            row_shapes={**deepcopy(ROWS), 'notes':obj({'detail':{'type':'string','minLength':1}})},
            blank=dict(version=VERSION, asset_type_id=asset['id'], template_sha256=definition['definition_sha256'],
                scope={key:'' for key in SCOPE}, inventory=form['input'], evidence={})))
    return dict(version=VERSION, scope_fields=SCOPE, profiles=profiles,
        policy='Operator inventory templates only. All observations start unknown. Type labels, controls, empty inventories and completed forms do not establish CVE prerequisites, non-exploitability or a VEX status.')


def validate(payload, templates=None):
    templates = templates or catalogue()
    if not isinstance(payload, dict) or set(payload) != {'version','asset_type_id','template_sha256','scope','inventory','evidence'}:
        raise ValueError('Profile structure does not match the registered format')
    profile = next((p for p in templates['profiles'] if p['asset']['id']==payload['asset_type_id']), None)
    if profile is None or payload['version'] != VERSION:
        raise ValueError('Unknown asset type or profile version')
    definition = profile['definition']; verify_seal(definition, 'definition_sha256')
    if payload['template_sha256'] != definition['definition_sha256']:
        raise ValueError('Template changed; review the current questions before reusing observations')
    if not isinstance(payload['scope'],dict) or set(payload['scope']) != set(SCOPE):
        raise ValueError('Profile scope fields are incomplete')
    if not all(isinstance(v,str) and len(v)<=2000 for v in payload['scope'].values()):
        raise ValueError('Invalid scope text')
    errors = list(Draft202012Validator(definition['schema']).iter_errors(payload['inventory']))
    if errors:
        raise ValueError(errors[0].message)
    evidence = payload['evidence']
    if not isinstance(evidence,dict) or len(evidence)>200:
        raise ValueError('Invalid evidence registry')
    for key, item in evidence.items():
        if not isinstance(key,str) or not isinstance(item,dict) or set(item)!={'source','excerpt'}:
            raise ValueError('Invalid evidence record')
        if not all(isinstance(v,str) and v.strip() and len(v)<=20000 for v in item.values()):
            raise ValueError('Evidence needs a source and a supporting passage / observation')
    missing = [key for key,value in payload['scope'].items() if not value.strip()]
    for value in payload['inventory']['values'].values():
        if any(key not in evidence for key in value['evidence_ids']):
            raise ValueError('Observation refers to an unavailable evidence record')
    scope=payload['scope']; dates={}
    for key in ['observed_at','valid_until']:
        if scope[key].strip():
            try:
                dates[key]=datetime.fromisoformat(scope[key].replace('Z','+00:00'))
                if dates[key].utcoffset() is None:raise ValueError()
            except ValueError as exc:raise ValueError('Use ISO 8601 with timezone for '+key) from exc
    if len(dates)==2 and dates['valid_until']<=dates['observed_at']:
        raise ValueError('Evidence expiry must be later than observation')
    mode=payload['inventory']['values']['operating_mode']
    if mode['state']=='recorded' and scope['mode'].strip() and mode['data']['name']!=scope['mode'].strip():
        raise ValueError('Operating-mode observation differs from profile scope')
    unknown=sum(v['state']=='unknown' for v in payload['inventory']['values'].values())
    stamp=datetime.now(timezone.utc)
    expired=bool(dates.get('valid_until') and dates['valid_until']<=stamp)
    future=bool(dates.get('observed_at') and dates['observed_at']>stamp)
    return dict(valid=True, state='expired' if expired else 'draft',
        recorded_fields=len(definition['fields'])-unknown, unknown_fields=unknown,
        missing_scope=missing, observation_in_future=future, evidence_expired=expired,
        inventory_complete=not missing and not unknown and not expired and not future,
        automatic_cve_mapping=False, proves_non_exploitability=False, vex_status=None)


def widget_parts():
    folder=ROOT/'site/asset_vulntology'
    data=(folder/'operating_profiles.json').read_text(encoding='utf-8')
    from html import escape
    markup=(ROOT/'src/item4/assets/deployment_profiles.html').read_text(encoding='utf-8')
    markup += '<div id="op-template-data" hidden>'+escape(data,quote=False)+'</div>'
    script='<script>'+(ROOT/'src/item4/assets/deployment_profiles_ui.js').read_text(encoding='utf-8')+'</script>'
    return markup,script
