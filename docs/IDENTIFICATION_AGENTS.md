# SBOM → CVE 식별 에이전트의 학습과 평가

이 문서의 L2/L3/L4는 첨부 매처 README의 역할을 따른다.

| 단계 | 학습 대상 | 최종 검증 |
|---|---|---|
| L2 | 이름에서 NVD CPE의 제품 식별자로 정규화 | 실제 NVD 제품 사전 조회 |
| L3 | 버전 정규화, 공급자 리비전 보존, 불명 버전 유보 | 원문과 무손실 정규화 규칙 비교 |
| L4 | 제공된 CPE 후보에서 정당한 식별자 선택 | NVD 출처·제품 일치·유일성·조회 오류 검사 |

SecureBERT를 사용하지 않는다. Qwen3-8B 기반 가중치를 4-bit NF4로 로딩하고,
각 역할마다 독립적인 rank-8 LoRA를 학습한다. 입력 프롬프트의 토큰은 손실에서
제외하고, 정답 JSON에만 손실을 적용한다. 학습·추론 모두 thinking을 끈다.

여기서 제품 식별자는 오픈소스 upstream에 한정되지 않는다. 입력 구성요소가
장비·상용 펌웨어이면 해당 제조사 제품의 식별자, 내장 라이브러리이면 그
라이브러리의 식별자를 뜻한다. 장비를 내장 라이브러리로 바꾸는 작업이 아니다.
v1 학습 프롬프트에는 `upstream product key`라는 부정확한 표현이 남아 있다.
v1 가중치와 평가의 재현을 위해 프롬프트 원문은 보존하지만, 실제 학습 정답은
NVD의 `product` 필드이며 상용 장비·펌웨어를 포함한다.

## 실행

CUDA PyTorch 환경에서 `requirements-training.txt`를 설치한다. 기본 모델은
`ICSVEX_AGENT_BASE` 또는 `--base`로 지정한다. 이 PC의 기존 Qwen3-8B 모델을
읽기만 하며, 다른 프로젝트의 학습 가중치를 가져와 재사용하지 않는다.

```powershell
python tools/build_identification_agent_data.py
python tools/train_identification_agents.py --base C:/Users/user/Desktop/ICS-VEXForge/models/Qwen3-8B
python tools/eval_identification_agents.py --pipeline
```

학습을 다시 하지 않고 별도의 정답 JSONL을 채점하려면
`python tools/eval_identification_agents.py --task-data data/identification_agents/test.jsonl`
을 실행한다. 각 행은 `id`, `task` (`L2`/`L3`/`L4`), `input`, `gold`를 포함한다.
기본·튜닝 모델에 같은 입력을 주고 원문 출력과 데이터 해시를 함께 저장한다.

첫 학습은 역할별 학습 512건·검증 64건·시험 64건, 1에폭이다. 저장 위치:

- 데이터·분할 해시: `data/identification_agents/`
- 실제 세 어댑터: `models/identification-agents-v1/L2`, `L3`, `L4`
- 기본 모델/튜닝 모델 원문 출력과 채점: `results/identification_agents/L2.json` 등
- 전체 비교 결과: `results/identification_agents/summary.json`

완료 표시가 없는 어댑터는 서비스에서 로딩하지 않는다. 학습을 재개하려면
`--resume`을 사용하고, 새 실험은 별도의 `--out` 디렉터리에 저장한다.
모델 폴더는 gitignore 대상이므로 코드와 별도로 보관해야 한다.

## 평가 해석

각 단계는 동일한 시험 입력으로 기본 Qwen과 튜닝 Qwen을 비교한다. 보고 지표는
정답 JSON 일치율, 스키마 유효율, 판정 Precision/Recall, 판정률, 유보율,
잘못된 확정 횟수다. 잘못된 JSON은 유보로 감추지 않고 오류로 분모에 남긴다.
L3는 접두부만 남겨 리비전을 잘라낸 횟수를 별도로 기록한다.

L2/L4는 `(vendor, product)` 그룹, L3는 원본 버전 문자열 그룹 단위로 분리한다.
현재 데이터는 NVD 사전에서 파생하고 절차적으로 변형한 **1차 데이터**다.
실제 제조사 SBOM을 독립 검토한 최종 평가셋이 아니며, 학습 손실이나 이 데이터의
정확도를 실제 CVE 식별 정밀도로 표시해서는 안 된다. 같은 제품군의 상관관계가
남을 수 있어 외부 일반화 평가는 별도로 필요하다.

`--pipeline`은 로컬 NVD 데이터에서 추출한 curl/OpenSSH 경계 사례 5개에 대해
규칙·기본 Qwen·L2만 튜닝·L3만 튜닝·L4만 튜닝·전체 튜닝을 비교한다. NVD 응답을
고정해 네트워크 없이 재현하며, SHA-256을 기록한다. 이 5건은 연결 회귀 검증으로,
공인시험이나 전체 제품군의 성능 지표가 아니다. GT에 없는 예측은 FP로 추정하지
않고 미채점으로 분리한다. Recall은 라벨이 있는 양성에 대한 값이다.

모델 원문은 보존하며, 서비스는 별도 검증기를 통과한 출력만 사용한다. L3가
리비전을 훼손하거나 L4가 CPE를 지어내면 해당 단계는 유보한다. 모호한 CPE가
모델의 직감만으로 확정되지는 않는다.

## 확대 데이터 v2

데이터를 역할별 4,096 / 1,024 / 1,024로 확대한 버전은
`data/identification_agents_v2`에 있으며, 기존 v1과 별도로 관리한다.
규모의 선정 근거·고유 표본 수·반복·학습 곡선 계획은
[IDENTIFICATION_DATASET_SIZE.md](IDENTIFICATION_DATASET_SIZE.md)에 기록했다.

```powershell
python tools/audit_identification_agent_data.py data/identification_agents_v2 --previous data/identification_agents
python tools/train_identification_agents.py --data data/identification_agents_v2 --out models/identification-agents-v2 --reports results/identification_agents_v2 --validation-only --batch 4 --accum 2 --eval-batch 16
python tools/eval_identification_agents.py --reports results/identification_agents_v2
```

v2의 첫 실행은 시험을 보지 않고 **검증 분할**을 평가한다. 최종 모델 설정을 고정한
후에 별도로 시험을 실행한다. 이 단계에서 v2 성능이 이미 향상됐다고 주장하지 않는다.
v2 어댑터를 사용하려면 서비스 시작 전에 `ICSVEX_AGENT_ADAPTERS`를 해당 모델 폴더로
지정한다. 로컬 웹 통합 이후 기본 서비스는 완료된 v2를 가리킨다. v1을 쓰려면
`ICSVEX_AGENT_ADAPTERS`에 `models/identification-agents-v1`의 절대 경로를 지정한다.

## 웹/API

`/cve-matcher.html`에서 식별 방식을 선택한다. `POST /api/cve-match`의
`agent_mode`는 `rules`, `base`, `tuned` 중 하나다. 기본값은 `rules`이며,
세 어댑터의 학습·평가가 모두 완료되어야 `base`/`tuned` 비교를 실행할 수 있다.
GPU 모델은 지연 로딩하고, 공통 기본 가중치 하나에 어댑터를 전환하며 요청을 직렬화한다.

```json
{"sbom":{"bomFormat":"CycloneDX","components":[{"name":"curl","version":"7.23.1"}]},"agent_mode":"tuned","offline":false}
```

오프라인 모드에서 NVD fixture가 없으면 모델을 사용해도 CPE 식별은 유보한다.
모델 출력이 NVD 사전의 실제 관측을 대체할 수 없기 때문이다.

### 실제 로컬 웹 실행

```powershell
python src/api_server.py --host 127.0.0.1 --port 8100
```

`http://127.0.0.1:8100/cve-matcher.html`에서 실제 SBOM JSON을 업로드하거나 붙여 넣는다.
기본 식별 방식은 v2 튜닝 Qwen이고 조회 방식은 로컬 NVD 수집본이다.
화면은 작업을 등록하고 진행 상태를 조회하며, 추론·조회·검증은 백엔드에서 실행한다.

- `GET /api/cve-match/models`: 모델 버전, 가중치 준비 상태, 학습/평가 건수.
- `POST /api/cve-match/jobs`: `{sbom, agent_mode, lookup_mode}`로 작업 등록(202).
- `GET /api/cve-match/jobs/{id}`: 진행 상태 또는 전체 결과 조회.
- 기존 동기 `POST /api/cve-match`도 유지한다.

`lookup_mode`는 `local`, `live`, `none`이다. `local`은 실제 수집한 NVD CPE 사전과
CVE 색인을 읽는다. CVE 색인은 원래 플랫폼·AND/OR 조건이 평탄화되어 있으므로
CVE 후보를 모두 `unknown`으로 표시하며 전체 영향 조건이 확인됐다고 주장하지 않는다.
`live`는 NVD API를 호출해 원본 조건을 대조한다. `none`은 NVD 조회를 생략한다.

결과 화면은 구성요소별 L2/L3/L4, 모델 원문, 검증 거부·유보 이유, CVE 후보를
보여 주고 전체 JSON을 저장할 수 있다. 상태가 `match`여도 최종 VEX가 아니다.
작업 큐는 GPU를 공유하도록 직렬 실행하고, 동시 대기는 최대 3건이다. 작업은 메모리에
저장되므로 서버 재시작 시 사라진다. 결과가 필요하면 JSON을 내려받아 보관한다.

### 버전 미상·NVD 미등재 제품의 후보 조회

설치 버전이 NOASSERTION이어도 제품 후보 조회를 중단하지 않는다. NVD CPE가
확인되면 `virtualMatchString`으로 제품 수준의 CVE를 조회하고 상태는 `unknown`으로
남긴다. 모델이 원문 버전을 훼손한 경우에도 훼손된 값을 조회에 사용하지 않는다.

NVD 경로와 별도로 `data/cisa_advisories.json`의 수집 자료에서 제조사와 영향 제품의
정확한 문구를 대조한다. 수정 버전·완화 지침·관련 권고문 푸터는 매칭 구간에서 제외한다.
이 경로는 `candidate_advisories.py`의 결정적 검색이며 모델의 CPE 예측 성공으로
보고하지 않는다. 공급자와 제품의 같은 문구가 있어도 설치 버전은 확인하지 못하므로
CVE는 후보(`unknown`)다. SBOM에 동봉된 vulnerabilities 정답이나 평가 GT 파일을
읽어 결과를 채우지 않는다.

EasyIO Neo Series 업로드 회귀 검증은 원래 권고문으로 역생성한 합성 SBOM을 이용한다.
같은 권고 코퍼스를 검색해 후보를 찾는 것은 연결 동작 검증이며 독립적인 모델 성능
시험이 아니다. UI는 NVD 확인 제품 수·CISA 권고 연결 수·고유 CVE 수·구성요소–CVE
연결 수를 구분한다. 로컬 NVD에 최신 제품 CPE가 없다는 이유로 권고 근거까지
없는 것으로 해석해서는 안 된다.
