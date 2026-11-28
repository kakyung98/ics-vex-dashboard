# #4 1단계 실행 안내

현재 기본 실행은 [사람 라벨링이 필수가 아닌 자동 4단계 경로](ITEM4_AUTOMATIC_PIPELINE.md)다. 아래 사람 검토 필수 정책은 이전 수동 경로에만 적용한다.
상세 계약은 [설계 문서](ITEM4_STAGE1_EXTRACTION_DESIGN.md)를 참고한다. 본 도구는 원문 구간 후보와 검토 승인 조건을 생성한다. 공격 그래프·자산 운영 정보·VEX 상태는 생성하지 않는다. 규칙 추출은 미학습 baseline이며, BERT는 별도 학습 체크포인트가 필요하다.

## 구성

| 파일 | 역할 |
| --- | --- |
| `src/item4_stage1_sources.py` | 원문 바이트/텍스트 해시, CSAF·CVE5·NVD 개별 JSON 어댑터, 원문 재대조 |
| `src/item4_stage1_contracts.py` | 엄격한 JSON Schema와 검증 |
| `schemas/item4_stage1_v1/` | 배포 가능한 5개 JSON Schema: bundle, claim, extraction, review, gold |
| `src/item4_stage1.py` | 원문 구간 후보, 적용 범위 검사, 사람 검토 승인, 전수 원장 |
| `src/item4_stage1_spans.py` | BIO 라벨·구간 변환·학습 분할·역할 κ/구간 평가 |
| `src/item4_stage1_bert.py` | 긴 원문 윈도 처리, BERT 학습·추론, 장치 기록 |
| `src/item4_stage1_evaluation.py` | 독립 Gold·정확 구간/역할/범위 평가, 학습 준비 검사 |
| `tools/research/item4_stage1.py` | prepare, propose, audit, review-template, export, evaluate, train-readiness, train, schemas |
| `tools/research/run_item4_stage1_h200.py` | 현재 서비스를 교체하지 않는 H200 격리 실행 |

## 로컬: 원문 준비부터 검토까지

프로젝트 루트에서 실행한다. 출력은 기존 파일을 덮어쓰지 않으므로 새 실행 폴더를 사용한다.

```powershell
python tools/research/item4_stage1.py prepare --input icsa/csaf --population "benchmark/icsa-cpe-synthetic sbom/index.json" --expected-advisories "benchmark/icsa-cpe-synthetic sbom/index.json" --output results/item4_stage1/manual_v1/bundle.json
python tools/research/item4_stage1.py audit --bundle results/item4_stage1/manual_v1/bundle.json --output results/item4_stage1/manual_v1/source_audit.json
python tools/research/item4_stage1.py propose --bundle results/item4_stage1/manual_v1/bundle.json --method rules --output results/item4_stage1/manual_v1/candidates.json
python tools/research/item4_stage1.py review-template --bundle results/item4_stage1/manual_v1/bundle.json --extraction results/item4_stage1/manual_v1/candidates.json --output results/item4_stage1/manual_v1/reviews.json
```

`--expected-advisories`는 원문 파일이 없는 ICSA도 source_unavailable로 원장에 유지한다. `--population`은 제외 CVE를 포함한 index의 declared_cves를 사용한다. 합성 SBOM은 이 단계에서 조건 근거로 사용하지 않으며, index는 모집단/원문 파일 목록으로만 참조한다. JSON 폴더 아래 파일만 읽고 재귀 탐색이나 임의 네트워크 수집은 하지 않는다.

검토자는 원문과 주변 문맥을 확인한 뒤 reviews.json의 각 주장에 대해 content·necessity·scope·qualifiers·conflicts를 검토한다. 필요성·범위가 불명확하면 unresolved, 원문이 지지하지 않으면 rejected다. accepted에는 다섯 항목 supported, 검토자, 시간대 포함 시각, 이유, 정확한 근거가 필요하다. 모델 응답을 human 검토로 표시하지 않는다.

```powershell
python tools/research/item4_stage1.py export --bundle results/item4_stage1/manual_v1/bundle.json --extraction results/item4_stage1/manual_v1/candidates.json --reviews results/item4_stage1/manual_v1/reviews.json --output results/item4_stage1/manual_v1/export.json
```

내보내기는 원본 파일을 다시 읽어 해시·구간·제품/범위 참조를 재구성한다. 원문이 없거나 바뀌면 중단한다. 공통 권고문, 잘못된 CVE 귀속, 제품 미귀속, 상충 검토는 accepted에 포함하지 않는다. 미검토도 전수 원장에 남는다. accepted 조건에도 `vex_eligible=false`, `coverage_complete=false`를 유지한다.

현재 리뷰는 파일로 제공되는 오프라인 주장이다. 사람 신원·검토 권한을 인증하는 서비스는 구현 범위에 포함되지 않는다. 스키마/해시 검증이 악의적으로 재작성된 원본이나 거짓 리뷰를 인증하는 것은 아니다.

## 독립 Gold와 평가

`gold.schema.json`의 계약을 따른다. 두 검토자가 모델 출력을 보지 않고 원문 구간과 역할, CVE/제품 범위를 표시한다. annotation_complete는 전체 지정 구간을 검토한 경우에만 true다. 해소되지 않는 모호성은 ambiguous로 보존한다. 실제 사람 검토가 없는 템플릿에 독립 Gold 표시를 채워 넣지 않는다.

```powershell
python tools/research/item4_stage1.py evaluate --bundle results/item4_stage1/manual_v1/bundle.json --extraction results/item4_stage1/manual_v1/candidates.json --gold data/item4_stage1/test_gold.json --exported results/item4_stage1/manual_v1/export.json --output results/item4_stage1/manual_v1/evaluation.json
```

평가는 정확 구간·역할·CVE·제품 범위의 일치를 측정한다. 표현이 다르지만 의미가 같은 조건의 매칭, 근거 없는 주장인지/구간 경계 오류인지의 구분은 추가 의미 검토가 필요하다. 이 지표를 근거 없는 추출률이라고 바꾸어 부르지 않는다. 모호한 Gold와 미라벨 구간 수, 실패를 포함한 처리 상태를 보고한다. 후보와 승인 결과를 별도 평가하며, 소스 문서가 두 개 이상이면 문서 단위 bootstrap 구간을 제공한다. 관측 오류 0건은 실제 오류 0%의 증명이 아니다.

## H200 실행과 학습

```powershell
python tools/research/run_item4_stage1_h200.py --config hysage-kubeconfig.yaml --run-id stage1_20261116_run01
```

실행 경로는 H200의 `/home/irteam/data-vol1/ics-vex-migration-20261116/stage1-runs/<run-id>`다. 기존 project/서비스를 덮어쓰지 않고 원문만 읽는다. 코드 파일은 명시 목록으로 전송하고 SHA-256을 기록한다. kubeconfig는 전송하지 않는다. status.json에서 완료/실패와 현재 단계를 확인한다. GPU 점검과 작은 CUDA 학습 회귀 테스트 후 전체 원문 무결성·후보 추출을 실행한다.

`--run-id`는 영문·숫자·밑줄·하이픈으로 새 이름을 지정한다. `--reuse-source-run <이전 ID>`로 불변 원문 bundle을 복사해 사용할 수 있으며, 모집단 index 해시를 비교하고 원본 원문을 다시 대조한다. 후보·검토 결과는 재사용하지 않는다. `--fetch`를 추가하면 기존 실행의 상태·검사 증거·원문 라벨링 템플릿을 로컬 results/item4_stage1/<run-id>로 받아 해시를 검증한다.

**작은 CUDA 회귀 테스트는 가상 문장·무작위 tiny BERT의 학습/추론 동작 검사다. 실제 CVE 추출 정확성 검증이나 운영용 모델 학습이 아니다.**

실제 학습용 각 JSONL 행은 BIO용 text·spans·원문 위치·annotation_complete·annotator와 함께 `annotation_origin="human"`, `model_predictions_seen=false`, source_file, source_document_sha256을 가져야 한다. 원문 해시·JSON pointer와 학습/개발/시험 누출을 검사한다. 같은 ICSA/CVE/원문은 여러 split에 둘 수 없다. near-duplicate·번역·재게시 누출은 별도 사람/코퍼스 감사가 필요하다.

```sh
python tools/research/item4_stage1.py train-readiness --train data/train.jsonl --dev data/dev.jsonl --test data/test.jsonl --output readiness.json
python tools/research/item4_stage1.py train --train data/train.jsonl --dev data/dev.jsonl --test data/test.jsonl --base-model /path/to/pinned/bert --output models/new_stage1_bert
```

train은 원문에 연결된 사람 라벨과 H200 CUDA가 없으면 중단한다. 로컬 CPU/GPU로 자동 전환하지 않는다. base-model은 준비된 로컬 BERT 체크포인트를 지정하며 자동 다운로드하지 않는다. dev 역할 κ로 체크포인트를 선택하고 선택 후 test를 평가한다. κ가 정의되지 않으면 null을 보존한다. GPU 이름, seed, 하이퍼파라미터, 데이터 해시와 결과를 기록한다.

```sh
python tools/research/item4_stage1.py propose --bundle bundle.json --method bert --checkpoint models/new_stage1_bert --device cuda --output bert_candidates.json
```

체크포인트가 없으면 규칙으로 몰래 대체하지 않는다. BERT도 원문 구간 후보만 출력하며 제품 귀속·필수조건 의미·전체 경로를 확정하지 않는다.

## 검증

로컬에서는 학습을 제외한 계약/CLI 테스트를 실행한다.

```powershell
python -m pytest tests/test_item4_stage1.py tests/test_item4_stage1_spans.py -k "not real_tiny_bert" -q
```

H200에서는 `ITEM4_TEST_DEVICE=cuda`로 전체 테스트를 실행한다. 전수 처리 보고서의 null 정확도·0건 승인·미확인 상태를 실제 모델 성능으로 바꾸어 보고하지 않는다.

2026-11-16 최종 실행의 [검증 보고서](../results/item4_stage1/stage1_20261116_v4/validation_report.json)에는 H200 60개 테스트, 원문 3,802개 무결성 검사, CVE 12,418개 처리 원장, 규칙 필수조건 후보 1,301건과 승인 0건을 기록했다. 독립 사람 라벨이 없어 운영용 학습은 시작하지 않았다. 별도의 미라벨 원문 표본 100개/3,396구간을 준비했으며, 이를 train/dev/test에 동시에 넣어 수행한 readiness 검사는 **준비되지 않은 데이터가 거절되는지 확인한 검사**다. 실제 데이터 분할이나 학습 데이터 10,188건을 뜻하지 않는다.
