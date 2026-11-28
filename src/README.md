# ICS-VEX 소스 구조

| 상위 폴더 | 기능별 묶음 |
| --- | --- |
| [item3/](item3/README.md) | `matching`, `agents`, `evidence`, `web` |
| [item4/](item4/README.md) | `assets`, `analysis`, `decision`, `workflow`, `models`, `evaluation`, `web` |
| [common/](common/README.md) | `web`, `data`, `runtime`, `evaluation` 및 `paths.py` |
| research/ | 연구용 실험과 분석 코드 |

주요 진입점은 다음과 같습니다.

| 작업 | 소스 |
| --- | --- |
| #3 매칭 흐름 | [identification_pipeline.py](item3/matching/identification_pipeline.py) |
| #3 웹 작업 | [identification_jobs_api.py](item3/web/identification_jobs_api.py) |
| #4 분석 작업 | [source_analysis_jobs.py](item4/workflow/source_analysis_jobs.py) |
| #4 다섯 항목 조건 추출 | [prerequisite_taxonomy.py](item4/analysis/prerequisite_taxonomy.py), [ics_operating_conditions.py](item4/analysis/ics_operating_conditions.py) |
| #4 VEX 판단 | [asset_vex_assessment.py](item4/decision/asset_vex_assessment.py) |
| #4 질문·조건 계약 평가 | [source_question_benchmark.py](item4/evaluation/source_question_benchmark.py) |
| 공통 웹 서버 | [api_server.py](common/web/api_server.py) |
| 공통 경로 | [paths.py](common/paths.py) |

기존 통합 웹 서비스 실행 명령은 유지합니다.

```powershell
python -B -X utf8 tools/item4/serve_nist_operational_vex.py 8100
```

새 코드는 기능별 import 경로를 사용합니다.

```python
from src.item3.matching import identification_pipeline
from src.item4.decision import asset_vex_assessment
from src.common.runtime import model_paths
```

기존 `from src import 모듈`과 `src.item3.모듈`·`src.item4.모듈`·`src.common.모듈` import도 동일한 모듈로 연결됩니다. `layout.json`은 이전 파일 이름과 경로를 현재 위치에 연결하고, `source_path()`는 실제 파일을 찾습니다. 웹 리소스와 실행 도구의 경로도 새 위치를 사용합니다.

이동 전 파일은 `research_records/functional_layout_20261123_before.zip`에 보관했습니다. 기존 평가 기록과 데이터는 이동하거나 수정하지 않았습니다. `sealed_source_receipt()`는 현재 소스와 보관된 과거 소스를 구분합니다. 이동 내역은 [manifest.json](../results/functional_layout_20261123/manifest.json)에 있습니다.

파일명은 역할을 설명하는 `snake_case`를 사용합니다. 불필요한 단계 번호와 버전 접미사를 제거하고 API·화면·실행·평가 역할을 구분합니다. [이전 이름과 현재 이름 비교](FILE_NAMES.md).
