# 테스트 구조

```text
tests/
├─ item3/       제품·버전·식별자 검증
├─ item4/       운영 조건·VEX·원장·보고서·추출 실험
├─ common/      코퍼스·모델 경로·배포·명령 호환성
├─ conftest.py  공유 fixture
└─ layout.json 기존 테스트 파일과 현재 위치의 대응표
```

프로젝트 루트에서 실행합니다.

```powershell
python -m pytest tests/item3 -q
python -m pytest tests/common/test_command_layout.py -q
node tests/item4/test_item4_questionnaire_ui.cjs
```

`python -m pytest tests`로 전체 테스트를 탐색합니다. 실제 모델·MulVAL 통합 검사에는 해당 환경이 필요합니다. 과거 분류 데이터·DB와 Git 저장소가 없는 데서 발생하는 기존 실패 15건은 이번 이동 회귀 범위와 분리했습니다. 실행한 범위와 제외 목록은 `../results/tools_tests_layout_20261123/test-scope.json`에 기록합니다.
