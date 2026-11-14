# ICS-VEXForge

Local ICS/OT **SBOM → CVE candidates → evidence-based VEX review**.
Updated **2026-11-06 (KST)**. Retained experiments are not current independent accuracy.

**Current execution policy:** product/CVE identification, CWE routing, source
analysis, condition/function extraction, operational questions and answer
assessment use deterministic rules. Only the final VEX explanation uses an LLM.


## #4 최종 선택과 전체 실험 — 2026-11-15


**최종 선택: CISA 권고문 맥락 텍스트 → TF-IDF → SVD16 → GPU K-means. 군집은 16개, 전수 native cosine Silhouette는 0.5866171296755885입니다.** 대상 **12,418개 CVE 전체**를 배정했습니다. 전수 평가한 최종 잎 분할 후보들의 native Silhouette를 기준으로 선택했으며, 자기지도학습은 사용하지 않았습니다. 공통 참조 Silhouette는 **0.017200194323733996**, seed 5회 ARI는 **0.8479**, 표현 고정 재표집 10회 ARI는 **0.8362**입니다. Ward 상위 계층을 추가해도 최종 16개 배정은 유지합니다.

자기지도 대조학습 후보는 **126개 군집·native Silhouette 0.4474**인 비교 결과로 보존합니다. 별도로 재학습한 자기지도 과제 F1 **0.8073**은 최종 선택한 16개 군집 방법의 성능이 아닙니다. 서로 다른 공간의 native 점수만으로 의미적 정확도가 개선됐다고 주장하지 않습니다. 모든 방법·설정·결과는 [실험 README](docs/item4_ssl_hierarchy/README.md)에 기록했습니다.

### 수행한 방법 전체 요약

| 방법군 / 단계 | 방법론 | 수행 범위와 결과 |
| --- | --- | --- |
| 초기 기준선 | 혼합 출처 → TF-IDF/SVD256 → 재귀 K-means | 최대 깊이 6, 마지막 깊이 평균 참조 Silhouette 0.0971 |
| 초기 자기지도 표현 비교 | 같은 SVD256 → 잡음 복원 DAE64 → 같은 재귀 K-means | 마스킹·Gaussian 잡음에서 MSE 복원. 마지막 깊이 평균 참조 0.0880 |
| 초기 군집화 알고리즘 비교 | 동일 DAE64 → 재귀 Ward | 마지막 깊이 평균 참조 0.0857. 위 3방법의 seed·표현 고정 및 전체 파이프라인 재표집 합계 **105개 계층 결과** |
| 1차 입력·표현 탐색 | 입력 5종 × SVD64/128/256·DAE32/64·이웃 대조학습32/64 × K 6종 | **210개 평면 조건**, 선별 표현 5종 × 재귀 K-means/Ward = 10개 계층 비교 |
| 전역 잎 + 프로토타입 계층 | 전역 GPU K-means → 잎 중심 Ward 병합 | 혼합 SVD256 119개, 혼합 DAE64 125개, CISA 풀링 DAE32 114개, CISA 설명 SVD256 119개 군집. 각 전수·seed 5회·재표집 10회 |
| 2차 저차원·K 확대 탐색 | 입력 5종 × SVD16/32·DAE16·이웃 대조학습16 × K 6종 + 기존 3표현 K 확대 | **129개 추가 조건**. 승격 후보의 최종 군집 수 164 / 204 / **16** / 126개. 각각 전수·seed 5회·재표집 10회 |
| 결합 입력 수정 대조군 | 혼합·CISA 맥락의 차원을 절반씩 유지한 SVD16/32/64/128 × K 6종 | **24개 조건**. 단순 prefix가 첫 입력만 남기는 문제를 수정·검증. 최종 선택을 대체하지 않음 |
| 자기지도 과제 자체 평가 | CISA 권고문 풀링 → 학습 출처만으로 전처리·이웃 대조학습 → 양성/음성 쌍 판별 | CVE 학습/검증/시험 8,692/1,863/1,863. 혼합 시험 F1: 원본 0.8293 / 학습 전 0.7283 / 학습 후 0.8073. 군집 정확도와 구분 |

### 결과 파일

| 자료 | 프로젝트 내 위치 / 바로가기 |
| --- | --- |
| 군집화 실험 결과 폴더 | `results/item4_cisa_lowrank_v1/` |
| 전수 군집 CSV·평가 자료 폴더 안내 | [results/item4_cisa_lowrank_v1/export/README.md](results/item4_cisa_lowrank_v1/export/README.md) |
| **최종 선택 16개 군집 CSV — 12,418행** | [cve_clusters_cisa_context_svd16.csv](results/item4_cisa_lowrank_v1/export/cve_clusters_cisa_context_svd16.csv) |
| 비교용 자기지도 126개 군집 CSV — 12,418행 | [cve_clusters_cisa_self_supervised.csv](results/item4_cisa_lowrank_v1/export/cve_clusters_cisa_self_supervised.csv) |
| 자기지도 모델 과제 평가 폴더 안내 | [results/item4_ssl_pretext_evaluation_v1/README.md](results/item4_ssl_pretext_evaluation_v1/README.md) |
| Accuracy·Precision·Recall·F1 원시 결과 | [metrics.json](results/item4_ssl_pretext_evaluation_v1/metrics.json) |
| #4 전체 실험 방법·비교 결과 | [docs/item4_ssl_hierarchy/README.md](docs/item4_ssl_hierarchy/README.md) |

현재 로컬 프로젝트 경로는 `C:\Users\user\Desktop\ICS-VEX`이며 위 위치는 이 폴더를 기준으로 합니다.

### 상세 비교와 평가

**2026-11-15 현재 완료된 실험 요약**입니다. 이 절은 CVE 텍스트의 표현 학습·군집화 실험을 설명합니다. SBOM·운영자 응답을 군집화 입력으로 사용하지 않았으며, 아래 군집을 이용한 운영 질문 생성·VEX 판단의 정확도는 검증하지 않았습니다.

**최종 채택은 `cisa_context_raw16_seed42`: TF-IDF → SVD16 → GPU K-means, 16개 군집 / native Silhouette 0.5866171296755885 / CVE 12,418개 전수 포함입니다.** 아래 표의 126개 군집은 자기지도 비교 후보입니다. 전체 방법 총괄과 최종 선택의 정확한 실행 설정은 [실험 README](docs/item4_ssl_hierarchy/README.md)에 기록했습니다.

| 항목 | 실제 수행 내용 |
| --- | --- |
| 대상 | 고정된 **12,418개 CVE 전체**, 최종 배정 누락·중복 없음 |
| 자기지도 비교 후보 입력 | CVE에 연결된 CISA ICS 권고문 텍스트. 권고문별 TF-IDF/SVD256 벡터를 CVE별로 평균·정규화 |
| 자기지도 알고리즘 | 무작위 초기화 MLP의 **이웃 기반 대조학습**. 양성 이웃 대칭 InfoNCE + 코사인 관계 보존 MSE, 잠재 차원 16 |
| 군집화 | 잠재벡터의 GPU K-means로 잎 군집 생성 후, 잎 중심의 Ward 병합으로 최대 깊이 6의 상위 계층 구성 |
| 자기지도 비교 후보 군집 수 | 요청 K=128에서 작은 군집을 병합한 **126개 잎 군집**. 최종 채택 SVD16 기준선은 **16개 군집** |
| 군집 평가 | 전수 native Silhouette **0.4474**, 공통 참조 **0.0256**. seed 5회 ARI **0.6876**, 표현 고정 재표집 10회 ARI **0.7527** |
| 자기지도 과제 평가 | 출처 분리 후 평가용 별도 재학습: Accuracy **0.7784**, Precision **0.7143**, Recall **0.9281**, F1 **0.8073**. 취약점 유형 정답률과 구분 |
| 저장 결과 | [전수 군집 CSV](results/item4_cisa_lowrank_v1/export/cve_clusters_cisa_self_supervised.csv), [실험 상세](docs/item4_ssl_hierarchy/README.md), [자기지도 평가](results/item4_ssl_pretext_evaluation_v1/README.md) |

이 실험에서는 LLM·Sentence Transformer·사전학습 언어모델·CWE 정답 라벨을 사용하지 않았습니다. 인코더 학습이 끝난 뒤 표현을 고정해 군집화했습니다. 아래에는 초기 비교부터 최종 후보까지의 결과와 한계를 구분해 기록합니다.

2026-11-14부터 CVE **12,418개**의 출처 텍스트를 대상으로 `TF-IDF/SVD + 재귀 K-means`, `Denoising Autoencoder + 같은 재귀 K-means`, `동일 잠재벡터 + 재귀 Ward 분할`을 비교했습니다.

초기 혼합 입력에는 검증된 CISA CSAF의 CVE별 설명이 **8,926개 CVE**에 포함돼 있었습니다. 세 방법은 같은 혼합 입력에서 학습·분할 방식을 비교했습니다. 위 최종 후보의 권고문 풀링 입력과 구분합니다.

후속으로 `results/item4_cisa_silhouette_search_v1`부터 CISA 중심 입력·자기지도 표현을 반복 탐색했습니다. **모든 전수 후보에 12,418개 CVE를 실제로 배정했으며 제외를 통한 점수 개선은 허용하지 않았습니다.** 탐색용 평면 군집과 최대 깊이 6의 최종 계층 평가를 구분하고, 최종 후보에는 전수 Silhouette와 반복·재표집 ARI를 함께 보고합니다. 자세한 입력·선별·범위 표시 기준은 같은 #4 실험 README에 기록합니다.

최대 깊이는 고정한 CWE v5.0 / CWE-1000 `ChildOf` 그래프의 최장 경로에서 계산한 **6**입니다. 가상 전체 루트는 깊이 0이며, 학습 군집의 단계가 CWE 추상화 수준에 대응한다는 뜻은 아닙니다. 조기 종료한 가지는 이후 깊이에도 유지합니다.

각 깊이에서 native 공간과 공통 참조 공간의 Silhouette를 병기하고, 초기값 반복·표현 고정 재표집·전처리와 학습부터 재실행한 재표집의 ARI를 구분합니다. ARI는 실행 쌍의 공통 CVE를 정렬해 계산합니다. 자세한 설계·파라미터·실행과 재개 방법은 [#4 실험 README](docs/item4_ssl_hierarchy/README.md)에 기록합니다. 현재 실행 상태는 `results/item4_ssl_hierarchy_v1/status.json`을 확인합니다.

기존 고정 조건의 **105개 계층 결과는 완료**됐고 전수 실행의 12,418개 보존을 확인했습니다. 최대 깊이 6의 평균 공통 참조 Silhouette는 기준선 0.0971, 자기지도 K-means 0.0880, 자기지도 Ward 0.0857이었습니다. 자기지도학습의 개선을 확인한 결과는 아니며, 세부 반복·재표집 지표와 후속 CISA 탐색은 #4 README에서 구분합니다.

후속 탐색은 평면 **363개 조건**과 선택 후보의 계층·반복 평가까지 완료했습니다. 전역 잎 군집에 최대 6단계의 프로토타입 상위 계층을 구성한 결과, **자기지도 CISA 후보는 native Silhouette 0.4474, seed ARI 0.6876, 재표집 ARI 0.7527**이었습니다. 자기지도학습 없는 CISA 맥락 SVD16 기준선은 native 0.5866이었습니다. 두 후보의 공통 참조 점수는 각각 0.0256·0.0172이므로 원래 혼합 입력의 거리 기준에서 같은 개선을 의미하지 않습니다. 공통 참조 기준 최고 후보는 0.1918이었습니다. native 공간·군집 수·알고리즘을 구분한 전수 표와 [결과 비교](results/item4_cisa_lowrank_v1/report.html)를 제공합니다.

파일을 다시 읽어 평면 363개 조건의 라벨 배열과 최종 전수 배정 파일 11개 모두 **12,418개 CVE 포함, 중복·누락 없음**을 확인했습니다. 수정한 두 입력 결합 기준선과 해상도 단계·실제 부모 간선 깊이의 차이도 #4 README에 기록했습니다.

ARI 0.6876은 전수 자료의 seed 5회 결과를 비교한 10쌍 평균, 0.7527은 표현을 고정한 약 80% 그룹 재표집 10회의 45쌍 평균입니다. 최종 잎 군집의 안정성 지표이며 정답률이나 계층 전체 평균이 아닙니다. [비교용 자기지도 CISA 군집 CSV](results/item4_cisa_lowrank_v1/export/cve_clusters_cisa_self_supervised.csv)와 [후보별 CSV·평가 자료](results/item4_cisa_lowrank_v1/export/README.md)를 저장했습니다. 후보별 군집 CSV 네 개는 각각 고유 CVE 12,418개를 모두 포함합니다.

자기지도 모델의 과제 평가도 별도로 수행했습니다. CISA 출처를 분리하고 전처리·인코더를 학습 자료만으로 재학습한 시험에서 이웃 쌍 판별 **Accuracy 0.7784, Precision 0.7143, Recall 0.9281, F1 0.8073**이었습니다. 학습 전 인코더 F1 0.7283보다 높지만 원본 SVD 기준선 0.8293보다 낮았습니다. 입력 이웃을 정답으로 만든 자기지도 과제 성능이며 취약점 유형 정확도가 아닙니다. [자기지도 과제 평가 방법·결과](results/item4_ssl_pretext_evaluation_v1/README.md)에 분할·기준선·한계를 명시했습니다. 기존 12,418개 전수 군집은 유지했습니다.

이 실험은 군집의 분리도·안정성과 자기지도 과제를 평가하며 공인시험 #4의 Affected 정밀도, 운영 질문 호환성, 악용 가능성 또는 VEX 정확도 검증을 대신하지 않습니다.


## Run

```powershell
cd C:\Users\user\Desktop\ICS-VEX
python -m pip install -r requirements.txt
python src/api_server.py --host 127.0.0.1 --port 8100
```

Keep the terminal open while using the application; `Ctrl+C` stops it. If port
8100 is already in use, open the existing local application instead of starting
a second server. Dependency installation is not needed for every startup.

Open [the local analyzer](http://127.0.0.1:8100/index.html). Supply CycloneDX or
SPDX JSON, identify candidates, then start the CWE-first review. Identification
accepts up to 100 components per job.

Only final VEX writing requires compatible CUDA/PyTorch, the local Qwen3-8B base
referenced by the writer configuration, and `models/vex-writer-qwen3-8b-v1/`.
Its model-loading dependencies are listed in `requirements-training.txt`.
Identification and operational review do not require analysis adapters or a GPU.
For a fresh GitHub checkout, first build the generated CPE dictionary with
`python tools/refresh_cpe_feed.py`. The current 156 MiB dictionary is kept locally
and is not distributed as a Git blob; its importer and provenance are included.
For optional C/C++ compiler-backed analysis, run `python tools/setup_clang.py` (requires 7-Zip), or set
`ICSVEX_CLANG`.

[GitHub Pages](https://kakyung98.github.io/ics-vex-dashboard/) serves the English
interface/public snapshots. Select **Connect local backend** for analysis.
Pages does not host FastAPI, inference, uploaded source or weights.

The shared light workspace theme lives in `src/ui_theme.py`: charcoal navigation,
white cards on a gray canvas, lime actions and lavender analysis accents. All
primary pages use the same shell, including the embedded identification widget.
The analyzer leads with upload and review actions; model/evidence settings and
long technical explanations use expandable sections. Methodology maps use larger
cards, role icons and separate expandable stage details. Input IDs, evidence
checks and export behavior remain shared with the backend workflows.

## #3: deterministic SBOM → CVE candidates

L2/L3/L4 use original SBOM evidence and local dictionaries only. No LLM, base
model, adapter, model critic or model fallback runs during identification.

| Stage | Processing |
| --- | --- |
| L2 | Preserve model identifiers; retrieve CPE candidates with BM25/character matching and rank fusion; keep competitors |
| L3 | Preserve versions, revisions and provenance; reject conflicts and unverified CPE versions; synthetic/range evidence is not installation proof |
| L4 | Accept only a unique dictionary identity supported by original evidence, with no unresolved vendor/type/identifier conflict |
| CVE lookup | Merge separately attributed NVD and CISA candidates; retain component links and unknown applicability |

`metadata.component.cpe` receives separate CPU asset analysis; identifiers are not
inherited by dependencies. Asset and component findings enter VEX review.
Legacy method names (`base`, `tuned`, `evidence_llm`) are compatibility aliases for
the deterministic path; they cannot enable analysis inference.

CPE syntax, dictionary membership, type conflicts and missing evidence are shown
in the result. Unsupported escaped CPEs remain unresolved. The local flattened
NVD cache cannot prove full platform AND/OR applicability. An empty result is not
proof of safety. Input SBOM vulnerability answers are not identification ground truth.

## #4: CWE-first CVE → VEX

**LLM policy: final VEX explanation writing only.** Qwen3-8B plus the VEX-writer
adapter is loaded lazily at that final stage. Other adapters and analysis-model
queues are disabled. Existing model files and historical reports are retained.

**Current #4 limitation (2026-11-06): automatic evidence routing is disabled.**
The previous manual CWE-to-source/operational mappings, nearest-ancestor method
inheritance, 26-type operational allowlist and keyword route refinements were
removed because their decision criteria were not sufficiently justified.
Policy `cwe-evidence-v2.2-unassigned` preserves the 944 official detailed CWE
records and all 10 Pillars. Each record now has an **evidence collection plan**:
596 entries list their own official detection methods; 348 start with CVE/vendor
mechanism evidence because their entry contains no detection method. Every plan
includes the exact definition, direct method descriptions, artifact requests,
case-selection prerequisites and source/plan hashes. Methods are alternatives,
not proof that source is mandatory or an operator questionnaire is sufficient.
No method is inherited from another CWE. Final asset-specific requirements are
still unassigned. New CWE-first reviews
remain `routing_unknown` / `under_investigation`, regardless of keywords or source
availability. Source uploads and operator answers cannot bypass that state.

[Evidence-plan implementation](src/cwe_evidence_plans.py) is a deterministic
translation of directly listed methods to artifact requests; it does not run a model
or assign CWE IDs. Runtime/compiled/formal methods are requests for independently
provided reports, not newly implemented analyzers.

Source analyzers, operational review engines, the four execution workflows,
locked-status VEX writer and export validators remain as capabilities. Execution
unit tests use explicit synthetic routing contracts to check those engines; these
fixtures are not production classification rules, gold labels or accuracy tests.
No replacement classification is inferred from the official CWE hierarchy.
Only CWE IDs already reported by the CVE sources are used. The system does not
assign new CWEs; assignment-guidance grades and their tables are removed from
project displays and derived outputs.

See the [current criteria and removed rules](docs/CWE_ROUTING_CRITERIA.md),
[all 944 unassigned records](docs/CWE_EVIDENCE_POLICY_V2.md),
[JSON](data/cwe_routing/v2/profiles.json), [CSV](data/cwe_routing/v2/profiles.csv),
and the [official Pillar grouping](docs/CWE_PILLAR_GROUPS_V5.md).
[Reproducible current outputs](data/cwe_routing/v2/criteria_results.json) distinguish
real cached inputs from constructed controls; all final requirements currently remain unassigned while collection plans are provided.
Rebuild with `python tools/build_cwe_evidence_policy.py`.
Changed policy versions/hashes require a new review; existing runtime records are
historical evidence and are not silently relabeled as current results.

The following describes retained evidence-engine capabilities, **not automatically
assigned routes for the 944 CWEs**:

| Evidence | Permitted conclusion |
| --- | --- |
| Compiler-backed supported targets absent in declared complete product/build scope, no blockers | Scoped `not_affected / vulnerable_code_not_present` |
| Compiler-backed targets unreachable from complete declared roots, no blockers | Scoped `not_affected / vulnerable_code_not_in_execute_path` |
| Exact vendor-fixed build + scoped operator-attested installation record | `fixed`, retaining deployment-verification limits |
| Required mapping, source/build, routing or facts unresolved | `under_investigation` |

Reachability does not establish attacker control/exploitation. Disabled features
or network controls are not code absence. Advisory `likely_*` labels are separate
from standard VEX. Source completeness/deployed binary identity are not independently
attested. Joern, CodeQL, taint and symbolic feasibility are not implemented.

### Source text analysis (not firmware binaries)

Upload a ZIP containing **C, C++, Python, Java, SQL, JavaScript, Go, R or Ruby**
source. No executable, interpreter runtime or build database is required for
source parsing. `src/multilang_source.py` uses the pinned
[Tree-sitter language pack](https://github.com/xberg-io/tree-sitter-language-pack/tree/v0.13.0)
to record function/routine definitions, byte spans, file/line locations, control
constructs and syntax-derived call candidates. Comments and string literals are
not treated as executable calls. Parser errors, unresolved/ambiguous calls and
file/language coverage remain visible. No uploaded code or build script runs.

The source analyzer selector supports `auto` (default), `syntax` (no compilation)
and `clang` (C/C++ build evidence). Auto uses Clang/LLVM for C/C++-only projects
with supplied compilation settings; otherwise it parses source directly. A
blocked compiler attempt falls back to syntax evidence and retains its diagnostics.
Mixed-language projects use source AST analysis so non-C/C++ files are not silently
excluded. Explicit Clang on a mixed project blocks negative verdicts.

**AST support is not complete semantic analysis for every language.** Name-based
same-file call candidates are not a CFG/runtime reachability proof. Dynamic
dispatch, import linking, framework entry points, taint and cross-language FFI
are unresolved; SQL dialects, quoted procedure bodies and dynamic SQL have
additional coverage limits. Syntax analysis never clears missing/unreachable
targets as `not_affected`. Scoped negative source decisions remain restricted to
the guarded compiler-backed path.

Default APIs: `/api/item4/start`, `/api/item4/{review_id}/questions`,
`/api/item4/{review_id}/answers`, `/api/item4/reviews/{review_id}` and guarded
`/api/source/judge`. Older direct arm endpoints are compatibility interfaces.
SQLite retains reviews/questionnaires for 24 hours and completed identification
jobs for seven days, including across backend restart.
See [the #4 contract](docs/CWE_FIRST_ITEM4.md).

## Models and retrieval

Only `vex-writer` is permitted by `src/inference_policy.py`. The final writer
receives a locked status, product, CVE, evidence IDs and analysis scope. It cannot
change the decision. Invalid/repetitive drafts are rejected and at most one
corrective writing attempt is made; rule evidence can still be exported.

Condition/function extraction uses literal source spans and pattern rules. These
partial observations do not establish a complete exploitation-condition set or
independently verified CVE-to-function mapping. Source review never consumes old
LLM mapping caches. Operational questions use source-linked CWE templates, and
answers are summarized by rules. Exact vendor-fixed builds plus scoped attested
installation records can support `fixed`; unverified reports retain investigation.
Legacy model-generated questionnaires must be regenerated before answer submission.

Model runtime loads the writer adapter directly; L2/L3/L4 or operational adapter
files are not prerequisites. GPU memory is required only for writing. If the
writer is unavailable, the assigned status/evidence remain available for export.
No independent vector-RAG or Claude/Gemini service is connected. Retrieval uses
CPE/NVD/CISA indexes and the pinned source catalog.

## Datasets and training

Earlier L2/L3/L4/operational training datasets and reports are historical experiments, not active inference dependencies.

Maintained dataset paths are resolved by `src/dataset_paths.py`. Public SBOM
readers use `sbom_index.json.source_directory` under `data/public_sbom/`.
Tests consume this retained snapshot; they do not reproduce retired-corpus
performance figures. The retained `operational_curriculum_v3` and
`operational_review_benchmark_v2` belong to earlier training/annotation work;
operational inference and its model queues are now disabled.
Old preparation/repair entry points verify the retained benchmark without
recreating deleted inputs. Frozen manifests keep their historical provenance.

Refresh the CPE dictionary with `python tools/refresh_cpe_feed.py`. It verifies
the official NVD 2.0 bulk publication, applies API modifications through a pinned
UTC cutoff, and atomically publishes non-deprecated entries for the corpus's
vendors. Provenance and progress are in `data/cpe_feed/provenance.json` and
`results/cpe_dictionary_refresh.json`. The CPE dictionary refresh does not update
the separate CVE applicability index or make earlier evaluation scores current.

| Historical dataset snapshot | Train | Validation | Test | Reference status |
| --- | ---: | ---: | ---: | --- |
| #3 L2 (legacy name contract) | 4,096 | 1,024 | 1,024 | Historical NVD-derived/procedural |
| #3 L3 | 4,096 | 1,024 | 1,024 | Procedural versions/abstention |
| #3 L4 | 4,096 | 1,024 | 1,024 | Dictionary/procedural |
| #4 v3 unique real CVEs | 800 | 100 | 100 | Independent references pending |
| #4 source-required predictions | 675 | 76 | 89 | Policy predictions, not gold |
| #4 operational predictions | 31 | 10 | 5 | Policy predictions, not gold |
| #4 unresolved routing | 94 | 14 | 6 | Deferred |

#4 has **1,000 unique CVEs**, reused in **1,840 simulated control-flow scenarios**.
Scenarios do not assert complete source exists. Role queues inherit the original
group split: zero cross-split group overlap, without established vendor/product-family
independence.

**Independent gold: 0. Real-CVE train-ready v3 examples: 0. Real-CVE supervised
training has not started.** Separate experimental operational-role pretraining
started on 2026-11-02, 22:53 KST, using controlled synthetic data: 800/100/100 per
role; both runs/evaluations finished on 2026-11-03 at 00:12 KST. These were
experiments on the previous model-generated question/assessment contract.
Their adapters are not used by the current rule pipeline, and their scores do
not measure its accuracy.
See [run details and progress paths](docs/ITEM4_ROLE_TUNING.md).
Only 46 inputs currently qualify for operator review; expansion and policy
adjudication are needed before reliable per-type training/evaluation claims.

Retained historical sets: source fixtures 800/100/100; conditions 386/59/50;
writer 800/100; operational curricula 800/100 per role. Their targets/weights are
not qualified for the new #4 contract. Legacy hashes are registered.
See [the inventory](docs/DATASET_INVENTORY.md).
Rebuild queues: `python tools/build_item4_v3.py`.

## Cohen’s κ and evaluation

Cohen’s κ measures **two-rater categorical agreement corrected for chance**:
`κ = (p_o - p_e) / (1 - p_e)`. It is not accuracy or proof of correct labels.
See the [official definition](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.cohen_kappa_score.html).

Use **independent, pre-adjudication ratings** on fixed aligned units, separately
for routing, condition/function support, question support, operator answerability
and VEX status, and separately by split. Report raw agreement, sample size,
label marginals, confusion, missing/unmatched units and group-bootstrap uncertainty.
Missing ratings differ from explicit `unknown`; single identical-category ratings
have undefined κ. No universal κ threshold establishes annotation correctness.

```powershell
python tools/eval_reviewer_agreement.py --a reviewer-a.jsonl --b reviewer-b.jsonl --output results/reviewer-agreement.json
```

The tool rejects adjudicated ratings, duplicate/misaligned units and identical
rater identities. Claude/Gemini agreement is **cross-model agreement**, not human
agreement or gold. Metadata cannot prove blinding/independence.
**Current κ: unavailable — no independent paired ratings collected.**
See [the rating protocol](docs/REVIEWER_AGREEMENT.md).

## Historical research and current evaluation limits

Operational input expansion found 563 eligible real CVEs: 385 train candidates,
63 validation, 48 test and 67 quarantined split-bridge cases. These remain
unlabelled. Current extraction uses source-span rules and operational assessment
uses deterministic evidence gates. The historical Clang campaign processed all
267 snapshots (222 partial / 45
blocked; 174 with project functions); all remain under investigation. The first
same-base pilot completed 24 operational and 16 mapping cases. Only two mapping
outputs passed their contract and both remained uncertain. Its LLM source-search
and mapping follow-ups are retired; the current source path excludes their caches.
Bounded LLVM def-use
paths support input-influence review but cannot prove non-controllability.
See [scope, limits and live progress](docs/LLM_REMEDIATION_RUN.md).

Evaluate routing, extraction, questions, assessment and authoring separately.
Report unsafe clearances, coverage and deferral alongside precision/recall.

## Verification and limitations

- CWE evidence policy, multilingual-source, four-workflow and writer-only regression on 2026-11-06: **284 passed**, including
  rejection of non-writer model roles, model-free identification aliases,
  rule questionnaires, operating evidence, writer contracts and compiler checks.
  All 944 profiles have collection plans; final asset requirements remain unassigned.
  Checks verify entry-specific definition/method provenance, alternative semantics,
  no inherited methods, no automatic necessity claims, and reject heuristic routing and verify
  questionnaire/source-result bypass protection. Execution-only workflow tests use
  explicit synthetic route contracts, not CWE classification labels.
  Software tests are not independently labelled CVEs or model accuracy.
- A historical model-based #4 smoke produced common/specific questions for one eligible CVE and
  excluded a source-required case. Acceptance required presentation normalization;
  raw strict format failed. Semantic accuracy was not measured. See `results/item4_v3_smoke/`.
- A historical #3 smoke completed eight components / 24 tuned calls without stage errors;
  this is integration coverage, not independent real-device accuracy.
- Historical condition-span literal support fell **85.86% → 54.50%** after tuning.
  The old candidate campaign's 77.12% scorable-subset precision failed its 80%
  criterion. Neither is a current unified-pipeline accuracy claim.
- A previous writer failed repetition checks. Rejected drafts remain excluded.
- **267** means collected CVE-associated source directories. Historical pycparser
  completed 0/267. The new Clang campaign processed 267/267; complete product/build
  applicability and exploitability verification are not established.
- Browser visual QA was restricted. Static/API/compiler checks do not establish
  visual quality or semantic correctness.
- Current live API verification completed rule-based CoreTec identification and
  a rule questionnaire without model inference. That single identification run
  took 6.18 seconds and returned 2 unique CVE candidates / 5 component links;
  this is a smoke observation, not a general latency or accuracy benchmark.
  See `results/writer_only_runtime_verification.json`. Actual GPU writer generation
  was not exercised in that verification; writer contracts use controlled outputs.

Historical reports remain in `results/four_hour_run_20261101/OUTCOME.json` and
`results/item3_identification_v2_run/summary.json`; retain frozen inputs/raw failures.

```powershell
python -m pytest tests -q
node tests/pages_bridge_test.cjs
node tests/shared_vex_export_test.cjs
```

## Workspace cleanup

Historical cleanup plans and verification are retained under `results/`.
The user executed the 2026-11-02 plan locally; its recorded logical size was
3,144.74 MiB, not measured physical recovered space. Old allowlists are dated
records and do not define current deletion targets. Current model requirements
are the Qwen base referenced by the writer and `models/vex-writer-qwen3-8b-v1/`.
Retired analysis weights are not inference dependencies. Preserve source/data
provenance and private review records when preparing any new cleanup plan.

## Corpus and publication

Snapshot recorded 2026-11-02: **3,881** CISA records, **3,879** collected advisories/
live synthetic SBOMs and **12,418** advisory CVEs. Two fetch failures remain
explicit; 17 advisory CVEs were missing from retrieved NVD feeds. Synthetic
inventories are not measured device data.

`sbom_index.json` selects the live `data/public_sbom/` snapshot. The overlapping
historical cohort was removed; readers now resolve the retained public snapshot.
Source commits, timestamps,
hashes and exclusions are retained in freshness metadata/refresh reports.

```powershell
gh api repos/cisagov/CSAF/commits/develop --jq .sha
python tools/refresh_public_corpus.py --commit <40-character-SHA>
python tools/build_pages_frontend.py
python tools/publish_pages_frontend.py
```

Restart after refresh. The publisher updates only explicit public assets, without
staging local work or uploading private reviews/source/weights. See
[corpus refresh](docs/PUBLIC_CORPUS_REFRESH.md). Request schemas are in `/docs`;
optional live NVD lookup reads the server-side `NVD_API_KEY`.

## Source map

| Path | Responsibility |
| --- | --- |
| `src/api_server.py` | FastAPI entry and generated UI |
| `src/candidate_web.py`, `src/unified_identification.py` | #3 jobs and L2/L3/L4 orchestration |
| `src/identity_retrieval.py`, `src/identity_evidence.py`, `src/identity_versions.py` | Retrieval, original-evidence acceptance and versions |
| `src/cwe_taxonomy.py`, `src/cwe_evidence_policy.py`, `src/vex_routing.py`, `data/cwe_evidence_policy_v2.json` | Official hierarchy, 944 detailed evidence profiles and CVE-specific routing |
| `src/item4_review.py` | Durable #4 review and mixed-branch aggregation |
| `src/rule_analysis.py`, `src/cve_source_evidence.py` | Literal source-span extraction, rule questions and answer summaries |
| `src/vex_roles.py` | Evidence packets, locked-decision authoring and writer validation |
| `src/source_evidence.py`, `src/multilang_source.py`, `src/clang_source.py` | Source AST, patch evidence and optional C/C++ build/CFG analysis |
| `src/operational_questions.py`, `src/operational_versions.py` | Rule questionnaire lifecycle, answers and scoped version evidence |
| `src/inference_policy.py`, `src/identification_agents.py`, `src/llm_output_schema.py` | Writer-only model boundary, lazy writer loading and output constraints |
| `src/sbom_vex.py`, `src/sbom_schema.py`, `src/review_store.py` | Export, schema validation and persistence |
| `src/reviewer_agreement.py`, `tools/eval_reviewer_agreement.py` | Pre-adjudication κ reporting |
| `data/item4_v3/`, `docs/CWE_FIRST_ITEM4.md` | Retained #4 cohort and current routing contract |
| `site/` | Generated public assets; edit generators instead |

Sources: [CISA CSAF](https://github.com/cisagov/CSAF),
[NVD feeds](https://nvd.nist.gov/vuln/data-feeds),
[CWE downloads](https://cwe.mitre.org/data/downloads.html), and upstream repositories
recorded in provenance. Third-party licenses remain applicable.

Source coverage on the dataset page is computed from nonempty CVE snapshot
folders intersected with the current advisory corpus. Compiler attempt coverage
comes separately from the selected Clang campaign. Missing local source does not
establish proprietary licensing or unobtainability. Snapshot presence establishes
neither vulnerable-version applicability nor whole-product build completeness.
