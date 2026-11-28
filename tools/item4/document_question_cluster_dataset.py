"""Write the dataset README from the frozen manifests and actual shared cases."""
from pathlib import Path
from collections import Counter
import argparse
import hashlib
import json

ROOT=Path('C:/ICS-VEX')
def read(path):return json.loads(path.read_bytes())

def document(data):
    manifest=read(data/'manifest.json');counts=manifest['counts']
    verification=read(data/'verification.json')
    assert verification['passed']
    cat=read(data/'catalog/question_clusters.json')['profiles']
    nav=read(data/'catalog/asset_navigation_snapshot.json')
    usage=Counter()
    for row in read(data/'index.json')['entries']:
        for aid in set(nav['advisory_asset_ids'].get(row['original_filename'][:-5],[]))&set(cat):usage[aid]+=1
    classified=sum(usage.values());unclassified=counts['unresolved_asset_type_boms']
    assert classified+unclassified==counts['boms']
    assert classified*30==counts['synthetic_question_scenarios']
    lines=[]
    for aid,profile in cat.items():
        cases=read(data/f'scenarios/{aid}.json')['scenarios']
        assert len(cases)==30
        clusters=[s['sampling']['selected_cluster_count'] for s in cases]
        questions=[s['sampling']['selected_question_count'] for s in cases]
        lines.append(f"| {aid} | {profile['name_ko']} | {len(profile['questions'])} | {len(profile['clusters'])} | {min(clusters)}~{max(clusters)} | {min(questions)}~{max(questions)} | {usage[aid]:,} | 30 | {usage[aid]*30:,} |")
    table='\n'.join(lines)
    text=f'''# 시험 항목 #4 자산 유형별 질문 클러스터 합성 데이터

정리일: 2026-11-25
데이터 버전: {manifest['version']}
생성 규칙: {manifest['scenario_design']['version']}
위치: C:/ICS-VEX/benchmark/item4_evaluation

## 1. 데이터의 목적과 정답 범위

공개 합성 BOM의 제품·버전·컴포넌트·CVE 구성을 유지한 채, 자산 유형별 질문 클러스터에서
일부 클러스터와 질문을 무작위 선택해 가상 운영 답변 O/X/모름을 구성한 데이터이다.
LLM을 호출하지 않았다. 현재 정답은 질문 응답과 클러스터별 집계 결과이며,
CVE별 악용 가능성·최종 VEX 상태의 독립 검증된 골드가 아니다.
gold.actual_affected, gold.actual_status 및 시나리오의 대응 필드는 null로 유지한다.

## 2. 전체 규모와 수량의 의미

| 항목 | 수량 | 집계 기준 |
|---|---:|---|
| 공개 BOM | {counts['boms']:,} | 실제 다운로드 문서 수 |
| annotation | {counts['annotations']:,} | BOM 하나당 하나, 동일한 숫자 파일명 |
| 컴포넌트 기록 | {counts['components']:,} | 하위·메타데이터 컴포넌트를 포함한 BOM 내 위치별 기록 합계; 고유 제품 수 아님 |
| 고유 CVE | {counts['unique_cves']:,} | 다운로드 BOM 전체에서 중복 제거 |
| BOM별 CVE 수 합계 | {counts['cve_occurrences']:,} | 같은 CVE가 서로 다른 BOM에 있으면 각각 집계 |
| 컴포넌트·CVE가 없는 BOM | {counts['empty_component_boms']:,} | 원본 그대로 보존; 삭제하거나 CVE를 추가하지 않음 |
| 유형 후보가 연결된 BOM | {classified:,} | 기존 권고문 분류의 후보; 자산 유형 확정 또는 실제 설치 검증을 뜻하지 않음 |
| 유형 미분류 BOM | {unclassified:,} | 분류 대기, 시나리오 적용 0건 |
| 질문 사전 | 18개 유형 / 120개 클러스터 / 505개 질문 | 동결 CSV·JSON 사본 |
| 공통 합성 패턴 | {counts['shared_synthetic_patterns']:,} | 18개 유형 × 유형당 30개, 실제 저장된 패턴 |
| 현재 BOM이 참조하는 공통 패턴 | {counts['used_shared_patterns']:,} | 17개 유형 × 30개; A0012 유형 후보 BOM은 현재 0개 |
| BOM-패턴 적용 건수 | {counts['synthetic_question_scenarios']:,} | {classified:,}개 BOM × 30개 참조 |

540개는 서로 다른 유형별 답변 패턴의 저장 수이고, 108,600건은 그 패턴을 BOM에 적용한 건수이다.
108,600개 패턴을 별도로 무작위 생성한 것이 아니다. 같은 유형의 BOM은 같은 30개 공통 패턴을 참조한다.
반복 적용 건수를 독립적인 현장 표본 수 또는 서로 다른 운영 환경의 수로 해석하지 않는다.
CVE마다 5개를 생성하거나, BOM의 CVE 개수로 파일을 분할하지 않는다.

## 3. 유형별 구성과 실제 무작위 선택 범위

아래 선택 범위는 설정 상한이 아니라, 현재 저장된 유형당 30개 패턴에서 관측된 최솟값~최댓값이다.
선택 질문 수는 해당 패턴에서 선택된 모든 클러스터의 질문 수를 합친 값이다.

| 유형 ID | 자산 유형 | 질문 수 | 클러스터 수 | 패턴당 선택 클러스터 | 패턴당 선택 질문 | 후보 BOM | 공통 패턴 | BOM 적용 건수 |
|---|---|---:|---:|---|---|---:|---:|---:|
{table}

## 4. 무작위 생성 규칙과 재현

1. 기본 난수 시드는 20261125이다.
2. 유형 ID와 추출 회차를 포함한 문자열의 SHA-256에서 개별 draw_seed를 만든다.
   draw_seed = int(SHA256("seeded-cluster-question-sampling/1:20261125:<유형 ID>:<회차>")[:16], 16)
3. random.Random(draw_seed)를 사용해 선택 클러스터 수를 1~해당 유형의 전체 클러스터 수에서 균등 추출한다.
   정해진 개수만큼 서로 다른 클러스터를 비복원 추출한다.
4. 선택한 클러스터마다 질문 수를 1~min(4, 그 클러스터의 질문 수)에서 균등 추출하고,
   정해진 개수만큼 서로 다른 질문을 비복원 추출한다.
5. 각 선택 질문에는 o, x, unknown 중 하나를 각각 1/3 확률로 부여한다.
   선택하지 않은 질문은 모두 unknown이다. 미선택을 x로 처리하지 않는다.
6. 선택 질문의 unknown과 미선택 질문의 unknown은 답변값은 같지만,
   sampling.selected_clusters의 질문 ID 목록으로 선택 여부를 구별할 수 있다.
7. 유형 내에서 전체 질문 답변 벡터가 중복되면 재추출하여 서로 다른 30개를 채운다.
   같은 시드와 기록된 생성 규칙으로 재현 가능하다.

sampling에는 generator, base_seed, draw_seed, draw_number, python_version,
selected_cluster_count, selected_clusters, selected_question_count를 기록한다.
selected_clusters의 각 원소에는 cluster_id, question_ids, question_count가 들어 있다.
모든 조합 또는 모든 질문 쌍의 9가지 조합을 포함한다고 주장하지 않는다.
이전 고정 83개 추가 패턴·직교배열·전수 조합 제안은 현재 생성 방식이 아니다.

## 5. 폴더와 파일 관계

sboms/sbom_000001.json                  공개 BOM 원본 바이트 복사본
annotations/sbom_000001.json            같은 번호 BOM의 출처·유형 후보·질문·시나리오 참조·미확정 CVE 라벨
scenarios/A0001.json                    A0001 공통 패턴 30개와 선택 내역·집계 정답
catalog/question_clusters.json          18개 유형·120개 클러스터·505개 질문의 정의
catalog/operator_asset_keys_clustered.csv  생성에 사용한 원본 질문 사전 사본
catalog/asset_navigation_snapshot.json  기존 권고문 자산 유형 후보의 동결 사본
catalog/scenario_sets.json              공통 패턴 파일 경로·유형·개수·SHA-256
index.json                             숫자 파일명과 원본 파일명·URL·BOM/annotation 해시의 대응
manifest.json                          버전·생성 규칙·전체 수량·소스 해시
verification.json                      전수 무결성·시드 재현·응답 집계 검사 결과
README.txt                             이 설명

번호는 원본 공개 파일명을 정렬한 순서이다. BOM 내부 bom-ref·CVE·affects는 바꾸지 않았다.
annotation.scenario_sets가 공통 파일의 경로와 해시를 참조하고,
inputs.question_profiles[].scenario_ids가 해당 유형의 사용할 패턴 ID 30개를 참조한다.
유형 미분류 BOM은 질문 사전 18개 유형을 미선택 대안으로 보존하되 시나리오 참조는 비워 둔다.

## 6. annotation과 평가 입력 사용법

- source: 공개 URL, 원본 파일명, 실제 다운로드 해시, 공개 목록의 선언 해시 및 일치 여부.
- inventory: 원본 컴포넌트 위치·참조·버전과 CVE 선언·원래 component_refs.
- asset_classification: 권고문 수준의 유형 후보와 근거. confirmed_asset_type_id는 null이다.
- inputs.question_profiles: 유형별 질문 문장, 확인 대상 단위, o/x 기준, 확인 자료, 클러스터,
  기본 unknown 값, 공통 시나리오 참조. 컴포넌트·질문 대상의 확정 연결은 아직 아니다.
- scenario_sets: 외부 공통 패턴 참조. BOM마다 패턴 본문을 중복 저장하지 않는다.
- gold: CVE별 actual_affected/actual_status는 null이고, 경로 완전성은 미확인이다.
- generation: 생성 규칙·기본 시드·질문 사전 및 분류 스냅샷 해시·LLM 미사용 기록.

공통 패턴의 inputs.answer_assignment.question_values는 선택 질문의 o/x/unknown 값이다.
default_value=unknown이 나머지 질문의 값이다. 같은 클러스터 안에서도 서로 다른 값이 존재할 수 있다.
expected_question_results는 클러스터별 o_count/x_count/unknown_count, has_o, all_x,
coverage를 담는다. 여기서 coverage는 답변 완전성만 뜻하며 공격 경로 전체를 다뤘다는 의미가 아니다.

모델에는 원본 BOM과 펼친 질문·답변 입력만 제공하고,
sampling·expected_question_results·gold 등 생성/채점용 정보는 제공하지 않는다.
아래 도우미는 공통 파일 해시를 검사하고 답변을 펼치며 채점 필드를 제외한다.

from tools.item4.rebuild_question_cluster_annotations import read, model_input
from pathlib import Path
data = Path("C:/ICS-VEX/benchmark/item4_evaluation")
annotation = read(data / "annotations/sbom_000001.json")
scenario_id = annotation["inputs"]["question_profiles"][0]["scenario_ids"][0]
packet = model_input(annotation, scenario_id, data)
# 미분류 annotation은 scenario_ids가 비어 있으므로 먼저 후보/참조 존재 여부를 확인한다.

## 7. 출처·보존·해석 경계

공개 출처: {manifest['source_url']}
동결 원본: {manifest['source_snapshot']}
실제 다운로드 BOM {counts['boms']:,}개의 바이트를 복사했다.
공개 목록의 선언 해시와 실제 다운로드 해시는 {manifest['public_index_hash_mismatches']:,}개 모두 불일치하여,
목록 메타데이터로 내용을 대체하지 않고 실제 다운로드 파일과 해시를 기준으로 삼았다.
따라서 과거 별도 자료의 12,418개 CVE·29,066개 컴포넌트 등의 집계와 혼합하지 않는다.
현재 다운로드 BOM의 고유 CVE는 10,847개이다. 빈 BOM과 미분류 BOM도 원본 모집단에 보존했다.

O가 없다는 사실은 질문 응답의 요약이다. 공격 벡터 부재·전체 경로 차단·not_affected의 정답으로 바꾸지 않는다.
질문 클러스터는 확인 주제의 묶음이며 CVE별 AND/OR 조건식이나 모든 악용 경로를 자동 정의하지 않는다.
실제 설치·실행 버전·컴포넌트·CVE 조건·운영 범위의 연결 및 경로 완전성은 별도 확인이 필요하다.
합성 답변은 현장 관측·전문가 라벨·독립 검증된 VEX 상태가 아니다.
현재 설정들의 현장 실현 가능성도 독립 검증하지 않았다.
같은 유형의 반복 패턴을 학습/시험에 나누어 쓰면 패턴 공유에 따른 노출을 따로 고려해야 한다.
현재 데이터에는 학습/개발/시험 분할이나 독립 홀드아웃 정확도를 주장하는 결과가 없다.

## 8. 검증 결과와 실행

verification.json의 passed=true이다. 다음 검사를 통과했다.
- BOM {verification['source_boms_byte_identical']:,}개가 동결 공개 다운로드 원본과 바이트 단위로 동일함.
- 원래 CVE 선언 및 BOM 내 연결 보존, annotation 인덱스/해시/공통 패턴 참조 확인.
- 505개 질문 정의, 120개 클러스터, 540개 공통 패턴 및 108,600건 적용의 정합성 확인.
- 기록된 난수 시드로 클러스터·질문·답변 추출을 재현하고 유형별 30개 답변 벡터의 중복이 없음을 확인.
- 선택하지 않은 질문은 unknown이며 expected_question_results의 집계가 실제 답변과 일치함.
- 미분류 261개 BOM에는 시나리오 참조가 없고 최종 VEX 정답을 임의 생성하지 않았음.
- model_input에서 생성/채점 필드를 제외하는 별도 검사 통과.

재생성(동결 공개 다운로드 사본 사용, 기존 경로를 덮어쓰지 않는 새 stage 필요):
python -m tools.item4.rebuild_question_cluster_annotations --stage <새 경로>

검증:
python -m tools.item4.verify_question_cluster_annotations --data benchmark/item4_evaluation

README 갱신(검증된 manifest·공통 패턴에서 표와 수량을 다시 계산):
python -m tools.item4.document_question_cluster_dataset --data benchmark/item4_evaluation

--publish는 전수 검증 후 기존 데이터 폴더를 docs/archive/item4_question_cluster_rebuild_*/로
옮겨 보존하고 검증된 stage로 교체한다. 과거 스키마용 평가 스크립트는 현재 참조 방식과 자동 호환되지 않는다.
'''
    (data/'README.txt').write_text(text,encoding='utf-8')
    print(json.dumps(dict(readme=str((data/'README.txt').resolve()),
        bytes=len(text.encode('utf-8')),shared_patterns=540,bom_applications=classified*30),ensure_ascii=False))
    return text

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--data',type=Path,default=ROOT/'benchmark/item4_evaluation')
    document(parser.parse_args().data)
