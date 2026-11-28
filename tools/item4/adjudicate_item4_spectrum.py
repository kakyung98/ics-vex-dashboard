"""Publish and replay the evidence adjudication of the last disputed Spectrum Power case."""
import argparse
from html import escape
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.evaluation import evidence_adjudication_records as ledger
from src.item4.evaluation import scenario_evaluation_runner as runs
from tools.item4 import publish_item4_blind_agent_review as first
from tools.item4.render_item4_scenario_run_ko import CSS, table


PARENT = 'policy-review-67e32a945fc69f95b109'
CASE = 'R-1B72A00A9560A9'
CVE = 'CVE-2019-6579'
SCENARIO = 'OX3-a2e8e683c2d12be5154ce98bbdad'
SITE = 'http://127.0.0.1:8100'
REVISION = 'item4/spectrum-evidence-adjudication/1'
REQUIRED = [
    ('실행 릴리스', '대상 노드의 실행 중인 Spectrum Power 인스턴스에서 수집한 릴리스·빌드 또는 서비스 기동 기록'),
    ('Web Office Portal 설치·사용', '같은 인스턴스의 고객별 프로젝트 확장(PE) 설치 명세와 포털을 사용하는 프로젝트의 배포·설정 기록'),
    ('수정 적용 여부', '같은 설치본에 bf-47456_PE_WOP_fix가 적용됐는지 확인할 수 있는 패치 명세 또는 변경 이력'),
]


def parent_evidence():
    previous = runs.ledger.get_run(PARENT)
    def pinned(path, digest):
        raw = path.read_bytes()
        first.require(first.sha(raw)==digest, 'Source differs from the previous ledger: '+path.name)
        return raw
    old = pinned(runs.OUTPUT/PARENT/'comparisons.jsonl',previous['data_hashes']['comparisons.jsonl'])
    source = first.packets.DEFAULT_OUTPUT/'coordinator/neutral_evidence.jsonl'
    neutral = pinned(source,previous['data_hashes']['neutral_evidence'])
    row, = [d for d in map(json.loads,old.splitlines()) if d['review_id']==CASE]
    card, = [d for d in map(json.loads,neutral.splitlines()) if d['review_id']==CASE]
    first.require(previous['status']=='completed' and previous['agent_review']['disagreements']==1
                  and row['agreement'] is False and row['source_scenario_id']==SCENARIO
                  and row['cve']==card['cve']==CVE, 'Expected one disputed case in the prior policy run.')
    exhibits = {e['evidence_id']:e for e in card['evidence']}
    bom, op = exhibits['B01'],exhibits['O01']
    first.require(bom['facts']['bom_properties'].get('dataset:synthetic-inventory')=='true'
                  and bom['facts']['bom_properties'].get('dataset:deployment-verified')=='false'
                  and op['source']['packet_sha256']==bom['source']['packet_sha256']
                  and bom['facts']['component']['version']=='with_Web_Office_Portal',
                  'The frozen synthetic product or operation observation differs.')
    cisa = exhibits['S01']['source']
    pinned(ROOT/cisa['file'],cisa['document_sha256'])
    hashes = dict(previous_comparisons=first.sha(old),neutral_evidence=first.sha(neutral),
                  frozen_operator_input=op['source']['original_line_sha256'],cisa_csaf=cisa['document_sha256'])
    return row,card,hashes


def assess(supplier,field,row):
    first.require(supplier['cve_id']==CVE and supplier['source_id']=='SSA-324467'
                  and field['review_id']==row['review_id']==CASE and field['cve']==CVE
                  and field['source_scenario_id']==row['source_scenario_id']==SCENARIO,
                  'Evidence must belong to this CVE, asset scenario and prior case.')
    # This is the adjudicator's decision on the captured records. New linked evidence
    # needs a fresh adjudication before this historical hold can be published again.
    first.require(field['verified_field_records']==0 and all(field[k] is None for k in
                  ('running_release_verified','portal_installation_verified','bugfix_installation_verified')),
                  'This decision only applies to the audited snapshot with no linked field proof.')
    return dict(previous_run_id=PARENT,review_id=CASE,cve=CVE,
                previous_statuses={slot:row[slot]['status'] for slot in first.SLOTS},
                status='under_investigation',reviewer_kind='ai_agent',human_reviewed_scenarios=0,
                verified_field_records=0,running_release_verified=False,portal_installation_verified=False,
                supplier_advisory=supplier['url'])


def render(report, decision, supplier):
    a = decision['adjudication']
    parent = f'{SITE}/api/item4/evaluation-runs/{PARENT}/agent-review/report.ko.html#{CASE}'
    def para(text):
        return '<p>'+escape(text)+'</p>'
    html = ['<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
            '<title>CVE-2019-6579 · 현장 근거 대조</title><style>'+CSS+
            'main{overflow-wrap:anywhere}td,th{vertical-align:top}.scroll{overflow-x:auto}.files a{display:inline-block;margin:.25rem .8rem .25rem 0}.verdict{font-size:1.3rem;color:#624600}</style></head><body><main>',
            f'<h1 id="{CASE}">{CVE} · Spectrum Power 현장 근거 대조</h1>',
            '<p class="verdict"><strong>조사 보류 · under_investigation</strong></p>',
            para(decision['rationale_ko']),
            f'<p>선행 A/B 판정　A {first.STATES[a["previous_statuses"]["reviewer_a"]]} / B {first.STATES[a["previous_statuses"]["reviewer_b"]]}　'
            f'<a href="{parent}">두 검토자의 원본 의견</a></p>',
            '<h2>Siemens 원문과 시나리오의 대조</h2>',
            '<div class="scroll">'+table(['항목','확인한 내용'],[(escape(k),escape(v)) for k,v in decision['evidence_comparison']])+'</div>',
            f'<p>Siemens ProductCERT · {escape(supplier["source_id"])} {escape(supplier["document_version"])} · '
            f'{escape(supplier["last_updated"])} · 1쪽 제품 표와 수정란, 2쪽 CVE 항목. '
            f'<a href="{escape(supplier["url"],quote=True)}">Siemens 공급사 원문 PDF</a></p>',
            '<h2>대조한 운영 기록</h2>',para(decision['field_scope_ko']),para(decision['field_match_ko']),
            para(decision['intake_ko']),
            '<p>AI 후속 판정 1건 · 사람이 검토한 사례 0건 · 이 사례에 연결된 현장 원기록 0건.</p>',
            '<h2>보류를 해소할 자료</h2>',para('동일한 자산 식별자, 인스턴스, 관측 시점(시간대 포함)으로 다음 기록을 연결합니다.'),
            '<ul>'+''.join('<li><strong>'+escape(k)+'</strong>　'+escape(v)+'</li>' for k,v in REQUIRED)+'</ul>',
            '<h2>원장 반영</h2>',para(report['accounting_ko']),
            '<p class="files">'+''.join(f'<a href="{path}">{label}</a>' for path,label in (
                ('decision.json','판정 및 근거 대조표'),('supplier_evidence.json','공급사 원문 위치·지문'),
                ('field_audit.json','운영 기록 대조 내역'),('source_receipt.json','출처 및 원본 지문'),('report.json','보고서 JSON')))+'</p>',
            f'<p>사례 <code>{CASE}</code> · 실행 <code>{escape(report["run_id"])}</code></p></main></body></html>']
    return '\n'.join(html)


def assemble(supplier,field):
    row,card,hashes = parent_evidence()
    a = assess(supplier,field,row)
    exhibits = {e['evidence_id']:e for e in card['evidence']}
    code = {p:runs.file_sha(ROOT/p) for p in (
        'tools/item4/adjudicate_item4_spectrum.py','tools/item4/item4_spectrum_supplier.py',
        'tools/item4/audit_item4_spectrum_field_records.py','tools/item4/audit_item4_field_record_links.py',
        'src/item4/evaluation/evidence_adjudication_records.py','tools/item4/render_item4_scenario_run_ko.py')}
    hashes.update(siemens_advisory=supplier['sha256'],supplier_snapshot=first.sha(first.encoded(supplier)),
                  field_snapshot=first.sha(first.encoded(field)))
    rid = 'evidence-review-'+first.sha(first.packets.json_bytes([REVISION,a,hashes,code]))[:20]
    local = field['scope_groups']['active_8100']
    hits = [hit for store in local['stores'].values() for hit in store.get('candidates',[])]
    first.require(all(h['disposition']=='generated_identification_candidate_only' for h in hits),
                  'An operational record needs a fresh case assessment.')
    found = ', '.join(sorted({h['product_candidate'] for h in hits}))
    result_text = (f'유사 제품명이 포함된 기록 {len(hits)}건은 제품 식별 결과에서 {found}을 후보로 열거했습니다. '
                   '대상 노드의 실행 릴리스나 포털 설치를 기록한 자료는 이 검색에서 확인되지 않았습니다.'
                   if hits else '대상 노드의 실행 릴리스나 포털 설치에 연결할 운영 기록이 검색되지 않았습니다.')
    intake = field['frozen_case']
    first.require(intake['asset_reference']=='hypothetical-asset' and intake['asset_observation_timestamp'] is None
                  and not intake['intake_fields_populated'],
                  'The review intake now contains asset, observation or submitted record data.')
    decision = dict(schema=REVISION,run_id=rid,adjudication=a,source_scenario_id=SCENARIO,
        rationale_ko='공급사 권고의 대상은 Web Office Portal을 사용하는 Spectrum Power 4입니다. 이 사례에 연결되는 실행 릴리스, 포털 설치·사용 및 수정 적용 기록을 확인할 수 없어 해당 설비의 영향 여부를 조사 보류합니다.',
        evidence_comparison=[
            ('공급사 제품 범위','권고문 제목에는 4.7이 있고, 본문과 영향 제품 표는 고객별 프로젝트 확장인 Web Office Portal을 사용하는 Spectrum Power 4를 지목합니다. 표에 숫자형 릴리스의 하한·상한이나 4.7 한정 조건은 없습니다.'),
            ('공급사 수정 정보','Siemens가 지정한 포털 수정 식별자는 bf-47456_PE_WOP_fix입니다. 권고문에는 수정 완료 릴리스 번호가 기재돼 있지 않습니다.'),
            ('합성 BOM · B01','제품은 Spectrum Power 4이고 버전 칸에는 with_Web_Office_Portal이 들어 있습니다. 이 값은 제품 옵션을 나타냅니다. 실제 실행 빌드 번호와 포털 설치 증빙은 제공되지 않았습니다.'),
            ('합성 운영 응답 · O01','시나리오는 현재 단일 자산에서 BOM의 제품이 가동된다고 가정합니다. 별도로 수집한 운영 응답과 릴리스·모듈 조회 기록은 없습니다.'),
            ('이전 A/B 의견','B가 인용한 포털 조건은 Siemens 원문과 일치합니다. A가 지적한 실행 릴리스 공백은 남아 있습니다. 공급사 적용 범위와 실제 설치 사실을 개별 확인해 후속 상태를 정했습니다.')],
        field_scope_ko=(f'8100 운영 저장소 {field["active_store_count"]}개의 기록 {field["records_examined"]}건을 대조했습니다. '
                        f'이전 저장소·백업과 지정된 접수·내보내기 위치의 파일 {len(field["local_file_screen"]["files"])}개도 확인했습니다. '
                        '백업에는 중복 기록이 있어 운영 건수에 합산하지 않았습니다. 검색 범위는 접근 가능한 로컬 자료입니다.'),
        field_match_ko=result_text,
        intake_ko=f'원본 BOM의 자산 식별자는 hypothetical-asset이고 현장 관측 시각은 비어 있습니다. 이 사례의 현장 자료 제출란도 {intake["intake_fields_total"]}개 중 작성된 항목이 0개여서 동일 설비·시점으로 연결할 식별 근거가 없습니다.',
        asset_observations={'running_release':None,'portal_installed':None,'portal_in_use':None,'bugfix_applied':None},
        needed_records=[dict(purpose=k,record=v) for k,v in REQUIRED])
    report = dict(schema=REVISION,run_id=rid,adjudication=a,source_scenario_id=SCENARIO,
                  ai_adjudications=1,confirmed_site_statuses=0,previous_agreements=94,previous_disagreements=1,
                  accounting_ko='95건의 맹검 원본에는 일치 94건과 불일치 1건이 기록돼 있습니다. 이 불일치 1건에 AI 후속 판정 ‘조사 보류’를 연결했습니다. 현장 상태가 확정된 사례는 이번 대조에서 0건입니다.',
                  code_hashes=code,input_hashes=hashes,needed_records=decision['needed_records'])
    receipt = dict(schema=REVISION,run_id=rid,previous_run_id=PARENT,source_scenario_id=SCENARIO,
                   input_hashes=hashes,code_hashes=code,pdf_source=supplier['url'],pdf_snapshot=supplier['snapshot_path'],
                   neutral_exhibits={i:exhibits[i]['source'] for i in ('B01','O01','D01','S01')})
    documents = {'report.json':report,'decision.json':decision,'supplier_evidence.json':supplier,
                 'field_audit.json':field,'source_receipt.json':receipt}
    files = {name:first.encoded(document) for name,document in documents.items()}
    files['report.ko.html'] = render(report,decision,supplier).encode('utf-8')
    return rid,report,files


def publish():
    from tools.item4.audit_item4_spectrum_field_records import audit
    from tools.item4.item4_spectrum_supplier import supplier_evidence
    rid,report,files = assemble(supplier_evidence(),audit())
    target = runs.OUTPUT/rid
    with tempfile.TemporaryDirectory(dir=runs.OUTPUT,prefix='.spectrum-adjudication-') as tmp:
        stage = Path(tmp)/rid
        stage.mkdir()
        for name,raw in files.items():
            (stage/name).write_bytes(raw)
        try:
            stage.rename(target)
        except OSError:
            if not target.is_dir() or any((target/n).read_bytes()!=v for n,v in files.items()):
                raise
    ledger.publish_adjudication(rid,code_hashes=report['code_hashes'],adjudication=report['adjudication'],
                                data_hashes={**report['input_hashes'],**{k:first.sha(v) for k,v in files.items()}})
    return target


def verify(directory):
    from tools.item4.item4_spectrum_supplier import supplier_evidence
    directory = directory.resolve()
    first.require(directory.parent==runs.OUTPUT.resolve(),'Expected a published review directory.')
    entry = runs.ledger.get_run(directory.name)
    field = runs.sealed_json(directory/'field_audit.json',entry['data_hashes']['field_audit.json'])
    rid,report,files = assemble(supplier_evidence(),field)
    first.require(rid==directory.name and entry['status']=='completed' and entry['generation_method']==ledger.METHOD
                  and entry['total']==entry['completed']==1 and entry['expert_reviewed_count']==0
                  and entry['candidate_count']==entry['prediction_count']==0 and entry['adjudication']==report['adjudication']
                  and entry['code_hashes']==report['code_hashes']
                  and entry['data_hashes']=={**report['input_hashes'],**{k:first.sha(v) for k,v in files.items()}}
                  and all((directory/k).read_bytes()==v for k,v in files.items()),
                  'The sealed adjudication, evidence, prior case or ledger differs.')
    return report['adjudication']


if __name__=='__main__':
    cli = argparse.ArgumentParser(description=__doc__)
    actions = cli.add_subparsers(dest='action',required=True)
    actions.add_parser('publish')
    actions.add_parser('verify').add_argument('directory',type=Path)
    args = cli.parse_args()
    if args.action=='publish':
        print(publish())
    else:
        print(json.dumps(verify(args.directory),ensure_ascii=False,indent=2))
