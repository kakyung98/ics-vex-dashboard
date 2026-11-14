# #4 군집화 결과 CSV와 안정성 평가

기준일: 2026-11-15 KST. 이미 계산한 결과를 CSV로 내보낸 자료다. 모델을 새로 학습하거나 군집을 변경하지 않았다. **군집 CSV 네 개는 각각 고유 CVE 12,418개를 모두 포함**한다. 첫 줄은 헤더이며 데이터는 12,418행이다.

## 군집 배정 CSV

| 파일 | 내용 | 최종 군집 수 | 데이터 행 |
| --- | --- | ---: | ---: |
| [cve_clusters_cisa_self_supervised.csv](cve_clusters_cisa_self_supervised.csv) | 기본 파일. CISA 권고문 풀링 + 이웃 기반 대조 자기지도학습 16차원 | 126 | 12,418 |
| [cve_clusters_cisa_context_svd16.csv](cve_clusters_cisa_context_svd16.csv) | CISA 맥락 + SVD16. 자기지도학습 없는 기준선 | 16 | 12,418 |
| [cve_clusters_mixed_svd256.csv](cve_clusters_mixed_svd256.csv) | 혼합 입력 + SVD256. 공통 참조 공간 기준 후보 | 164 | 12,418 |
| [cve_clusters_mixed_dae64.csv](cve_clusters_mixed_dae64.csv) | 혼합 입력 + Denoising Autoencoder 64차원 | 204 | 12,418 |

UTF-8 BOM·쉼표 구분·CRLF 형식이다. 최종 군집 ID, CVE ID 순으로 정렬했다. 동일 군집의 CVE가 연속해서 나타난다. 원본 JSONL의 모든 단계별 배정과 대조했고 누락·중복이 없다.

### 주요 열

| 열 | 의미 |
| --- | --- |
| `cve` | 원래 대상 CVE ID |
| `leaf_cluster_id` | seed 42 기준 최종 잎 군집의 트리 노드 ID. CWE 번호나 의미 범주명이 아님 |
| `leaf_cluster_size` | 해당 후보의 최종 군집에 속한 CVE 수 |
| `tree_leaf_depth` | 실제 부모 간선 기준 트리 깊이. 최대 6 |
| `resolution_1`~`resolution_6` | 여섯 중첩 해상도의 노드 ID. `resolution_6`이 최종 잎 군집 |
| `reported_cwes` | 원래 보고된 CWE를 `|`로 구분. 새 CWE를 배정하지 않음 |
| `cisa_advisory_ids` | 연결된 CISA 권고문 ID를 `|`로 구분 |
| `cisa_has_cve_specific_description` | 저장된 CISA 자료에 해당 CVE별 설명이 있는지 |
| `cisa_only_shared_context_available` | CVE별 설명 없이 권고문 공유 맥락만 이용 가능한지 |
| `original_nvd_status`, `identity_ambiguous`, `original_excluded_flag` | 원래 상태·모호성 표시. 이 표시를 이유로 CSV에서 제외하지 않음 |

군집 ID는 트리 전체의 노드 번호를 유지하므로 126개 잎 군집이라도 번호가 126을 넘거나 중간 번호가 비어 있을 수 있다. 다른 후보나 다른 seed의 같은 숫자가 같은 군집이라는 뜻도 아니다. 해상도 번호와 실제 트리 깊이를 구분한다. CISA 설명 가용성 열은 자료의 존재 여부이며 실제 자산의 영향 여부를 뜻하지 않는다.

## 평가 파일

| 파일 | 내용 |
| --- | --- |
| [evaluation_summary.csv](evaluation_summary.csv) | 네 후보의 전수 Silhouette, 군집 수, 반복·재표집 ARI 요약 |
| [stability_by_resolution.csv](stability_by_resolution.csv) | 후보별·실험별·해상도별 ARI 평균·표준편차·범위·공통 CVE 수. 48행 |
| [ari_pairwise.csv](ari_pairwise.csv) | 네 후보의 모든 실행 쌍·해상도별 원시 ARI. 1,320행 |
| [cluster_summary_cisa_self_supervised.csv](cluster_summary_cisa_self_supervised.csv) | 기본 후보 126개 군집의 CVE 수·깊이·CVE ID 예시. 예시는 사전순이며 대표성 평가가 아님 |
| [evaluation_summary.json](evaluation_summary.json) | 네 후보의 전수 지표·선택 조건·계층 구조·안정성 원본 값 |
| [stability_explanation.json](stability_explanation.json) | 기본 후보의 ARI 정의와 두 실험 조건 |
| `cisa_self_supervised_ari_pairs.jsonl` | 기본 후보의 원시 실행 쌍 비교 |
| `cisa_self_supervised_stability_summary.json` | 기본 후보의 원시 안정성 집계 |
| `cisa_self_supervised_selection.json`, `cisa_self_supervised_structure.json`, `cisa_self_supervised_tree.json` | 기본 후보 선택 조건과 저장 계층 |
| [verification.json](verification.json), `export_manifest.json` | CSV 재읽기 검증과 파일 해시 |

## ARI 0.688과 0.753의 의미

대상은 `trained_native_gain`, 표현은 `cisa_advisory_pool_neighbor16_seed42`다. 아래는 **최종 잎 군집(해상도 6)**에 대한 실행 쌍 ARI의 산술평균이며 계층 전체 평균이 아니다.

| 실험 | 무엇을 바꿨는가 | 실행 수 | 비교 쌍 | ARI 평균 |
| --- | --- | ---: | ---: | ---: |
| 초기값 반복 | 전처리·자료는 고정. seed 42~46에서 인코더를 재학습하고 군집화도 다시 수행. 매번 CVE 12,418개 전체 사용 | 5 | 10 | 0.6876356500551994 |
| 표현 고정 재표집 | 전처리·학습된 인코더는 고정. 입력 벡터가 동일한 CVE 그룹의 약 80%를 복원 없이 뽑고 군집화만 다시 수행 | 10 | 45 | 0.7526760201472672 |

재표집 실행 쌍은 **공통으로 포함된 CVE ID를 같은 순서로 정렬**해 비교한다. 기본 후보의 공통 CVE 수는 쌍마다 7,561~8,381개이며 평균 약 8,020.47개였다. 이는 안정성 평가의 교집합 크기이고 최종 전수 CSV의 CVE 수는 여전히 12,418개다. 군집 번호를 수동 대응하지 않는다.

ARI=1은 번호 순열을 제외하고 같은 분할, 0 부근은 무작위 일치 수준을 뜻하며 음수도 가능하다. 0.688은 68.8% 정답률이 아니다. 두 번째 실험은 표현을 고정했으므로 더 높은 값이 더 정확하다는 뜻도 아니다. 실행 쌍은 서로 자료를 공유하며 표준편차·분위수는 신뢰구간이 아니다. 유형 의미·운영 질문 호환성·악용 가능성·VEX 정확도는 별도로 검증해야 한다.

기본 후보의 전수 native Silhouette는 0.4473861074715556, 공통 참조 점수는 0.025647545640889037이다. native는 해당 후보의 벡터 공간 점수이며 다른 공간의 값과 직접 같은 품질로 해석하지 않는다.

상위 [실험 README](../../../docs/item4_ssl_hierarchy/README.md)에서 전체 방법과 비교 이력을 확인할 수 있다.

## 자기지도 모델 과제 평가

기존 Silhouette·ARI는 군집 평가이며 학습 손실 감소만으로 독립 시험 성능을 확인한 것은 아니다. 후속으로 출처를 분리해 같은 알고리즘을 별도 재학습한 자기지도 쌍 판별 평가를 수행했다. 시험 Accuracy 0.7784, Precision 0.7143, Recall 0.9281, F1 0.8073이며 학습 전 F1 0.7283, 원본 SVD F1 0.8293이다. 입력의 이웃 관계를 정답으로 정의한 평가로 취약점 유형 정확도가 아니다. [평가 방법과 저장 결과](../../item4_ssl_pretext_evaluation_v1/README.md)를 참조한다. 기존 전수 군집 모델과 12,418개 CSV 배정은 유지했다.
