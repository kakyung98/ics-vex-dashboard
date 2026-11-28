"""Issue and verify a policy-aware blind review form for each reviewer of the sealed #4 sample."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.item4 import build_item4_blind_sample as original


VERSION = 'item4-policy-blind-packet/2'
BALLOT = 'item4-independent-agent-ballot/2'
SOURCE = original.DEFAULT_OUTPUT
SOURCE_MANIFEST_SHA256 = '7d8dc8ad637e6a6f60883d57e1395f11eaaf41ceafbfb33dc1b0721c5c360d49'
OUTPUT = ROOT / 'results/item4_policy_blind_packet_20261122'
SLOTS = ('reviewer_a', 'reviewer_b')
BASES = ('deployment_absence', 'supplier_status', 'version_range', 'other', 'insufficient_evidence')
STATUSES = ('affected', 'not_affected', 'fixed', 'under_investigation')
FIELD_TYPES = ('asset_scope', 'deployment_inventory', 'inventory_completeness', 'running_build',
               'configuration_state', 'change_history', 'supplier_scope')

INSTRUCTIONS = [
    '각 검토자는 이 파일만 사용해 모든 합성 시나리오를 개별적으로 판정합니다. 같은 CVE도 사례별 운영 응답과 대상 범위를 다시 읽습니다. 판정 사유와 추가 요청은 한국어로 기록합니다.',
    '사례의 자산·구성요소·운영 시점과 공급사 문서의 제품·버전·조건을 대조하세요. affected는 해당 시나리오에서 영향 조건이 충족되는 경우, fixed는 적용된 수정 버전이나 조치가 확인되는 경우에 선택합니다. not_affected에는 배제할 수 있는 구체적 근거가 필요합니다. 근거가 부족하거나 충돌하면 under_investigation을 선택합니다.',
    '운영 응답이 not_deployed인 사례에서 미배포를 이유로 not_affected를 판정하려면, 동일 자산·구성요소·동결 관측시점의 명시적 완전 재고를 확인해야 합니다. 같은 사례의 O 운영 근거에 deployment=not_deployed, scope=current_single, inventory_coverage=complete가 있어야 하며 B 구성요소 근거와 대상 및 동결 출처가 일치해야 합니다. 두 항목의 실제 evidence_id를 evidence_ids와 inventory_evidence_ids에 모두 적고 범위·시점이 일치하는 이유를 설명하세요.',
    'inventory_coverage가 누락되었거나 partial·unknown이거나 해당 자산·구성요소·시점과 맞지 않으면 미배포에 의존하는 판단은 under_investigation입니다. not_deployed 응답, current_single 범위 또는 BOM 항목만으로 완전 재고를 추정할 수 없습니다. decision_basis의 명칭을 바꾸어 미배포 판단에 필요한 근거를 생략할 수 없습니다.',
    'supplier_status나 version_range를 판정의 주된 근거로 삼으면 인용한 원문에서 제품·버전·판정 범위를 확인하고 해당 시나리오의 대상에 어떻게 적용되는지 설명합니다. 공급사 제품 상태는 현장의 배포·버전 및 재고 완전성과 별개입니다. other에는 해당 사유를 설명하고 조사 보류의 주된 근거가 자료 부족이면 insufficient_evidence를 사용합니다.',
    '각 사례에서 실제로 읽은 근거 ID를 evidence_ids에 기입하고 그중 사용한 O/B 재고 근거만 inventory_evidence_ids에 기입합니다. 재고 근거를 쓰지 않았다면 빈 배열을 사용합니다. 추가로 필요한 현장 기록과 확인할 자산·범위·시점을 needed_records에 적습니다. 동결 입력에서 확인한 내용을 실제 설비의 관측 결과로 확대하지 않습니다.',
]


def output_contract(packet_id, slot):
    return dict(
        ballot_fields=dict(schema_version=BALLOT, packet_id=packet_id, reviewer_kind='ai_agent',
                           reviewer_slot=slot, ratings='사례마다 아래 형태의 객체 1개. 각 review_id는 정확히 한 번 사용.'),
        rating_fields=dict(review_id='이 사례의 review_id', status=list(STATUSES),
                           evidence_ids='사례 안에서 인용한 고유 ID 1개 이상',
                           rationale='인용한 구체적인 사실과 판정으로 이어지는 이유를 담은 비어 있지 않은 문자열',
                           needed_records='확인에 필요한 구체적 현장 원기록을 담은 비어 있지 않은 문자열',
                           field_record_types=list(FIELD_TYPES), decision_basis=list(BASES),
                           inventory_evidence_ids='evidence_ids 중 사용한 사례 내 O 또는 B 근거 ID의 고유 배열'),
        representation='status와 decision_basis는 제시된 값 중 문자열 하나, field_record_types는 해당하는 값의 고유 배열입니다. field_record_types에 supplier_scope 외의 현장 자료 유형을 적어도 하나 포함하세요. 제시된 필드명을 그대로 사용하고 모든 필드를 작성하세요.')


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode('utf-8')


def expected_files(source=SOURCE):
    manifest_bytes = (source / 'coordinator/manifest.json').read_bytes()
    original.require(original.digest(manifest_bytes) == SOURCE_MANIFEST_SHA256, 'Original manifest seal differs.')
    original.verify(source, rerun=False)
    source_manifest = json.loads(manifest_bytes)
    neutral = 'coordinator/neutral_evidence.jsonl'
    raw = (source / neutral).read_bytes()
    evidence_sha = original.digest(raw)
    original.require(evidence_sha == source_manifest['files'][neutral], 'Original evidence seal differs.')
    cases = [json.loads(line) for line in raw.splitlines()]
    ids = [c['review_id'] for c in cases]
    original.require(len(ids) == len(set(ids)) == source_manifest['sample_scenarios'] == 95,
                     'Original blind IDs or sample size differ.')
    # Hash every instruction and both the ballot header and rating contracts before assigning the packet ID.
    packet_id = 'P-' + original.digest(original.json_bytes([
        VERSION, SOURCE_MANIFEST_SHA256, evidence_sha, INSTRUCTIONS, output_contract('<packet_id>', '<slot>')
    ]))[:24]
    outputs = {}
    for slot in SLOTS:
        form = dict(version=VERSION, packet_id=packet_id, reviewer_slot=slot, instructions=INSTRUCTIONS,
                    output_contract=output_contract(packet_id, slot), cases=cases)
        outputs[slot + '/form.json'] = encode(form)
    manifest = dict(version=VERSION, ballot_schema_version=BALLOT, packet_id=packet_id,
                    source_packet_id=source_manifest['packet_id'], source_manifest_sha256=SOURCE_MANIFEST_SHA256,
                    neutral_evidence_sha256=evidence_sha, case_ids_sha256=original.digest(original.json_bytes(ids)),
                    sample_scenarios=len(ids), sample_cves=len({c['cve'] for c in cases}),
                    evidence_items=sum(len(c['evidence']) for c in cases),
                    files={name: original.digest(raw_form) for name, raw_form in outputs.items()})
    outputs['manifest.json'] = encode(manifest)
    return outputs


def verify(directory, source=SOURCE):
    expected = expected_files(source)
    names = {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()}
    original.require(names == set(expected), 'Unexpected or missing files in blind packet.')
    for name, value in expected.items():
        original.require((directory / name).read_bytes() == value, f'Blind packet differs at {name}.')
    return json.loads(expected['manifest.json'])


def build(directory, source=SOURCE):
    directory = directory.resolve()
    if directory.exists():
        raise FileExistsError(f'Blind packet already exists at {directory}.')
    outputs = expected_files(source)
    directory.parent.mkdir(exist_ok=True, parents=True)
    with tempfile.TemporaryDirectory(dir=directory.parent, prefix='.policy-review-') as tmp:
        stage = Path(tmp) / 'packet'
        for name, value in outputs.items():
            file = stage / name
            file.parent.mkdir(exist_ok=True, parents=True)
            file.write_bytes(value)
        manifest = verify(stage, source)
        stage.rename(directory)
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('build', 'verify'))
    parser.add_argument('directory', type=Path, default=OUTPUT, nargs='?')
    args = parser.parse_args()
    action = build if args.action == 'build' else verify
    print(json.dumps(action(args.directory), indent=2))
