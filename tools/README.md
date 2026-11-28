# 실행 도구

```text
tools/
├─ item3/              제품·버전·CPE 식별과 #3 평가
├─ item4/              운영 조건·VEX·원장·보고서·전수 실행
│  └─ research/        조건 추출 학습·과거 실험
├─ common/             배포·전송·코퍼스·제출·공통 검증
├─ __main__.py         통합 명령 진입점
└─ layout.json         기존 명령명과 현재 파일의 대응표
```

프로젝트 루트에서 명령명을 그대로 사용합니다.

```powershell
python -m tools serve_nist_operational_vex 8100
python -B -X utf8 tools/item4/validate_cvss_source_population.py --help
python tools/item3/run_item3_test.py --help
python -m tools runtime_release --help
```

원문 조건 전수 검증은 `item4/validate_cvss_source_population.py`를 사용합니다. 운영 API의 ICSA 수집과 구분되는 CVE Description 전용 실험이며, 기존 결과와 코드·프롬프트가 다르면 새 출력 폴더를 지정합니다. 진행 중인 네 항목 실행은 루트 README에 명시된 고정 코드 사본에서 재개합니다.

기존 서비스·전수 실행·복구의 주요 CLI는 최상위의 얇은 호환 파일로 유지했습니다. `python tools/serve_nist_operational_vex.py 8100`은 계속 동작합니다. 이 파일들은 알고리즘을 복사하지 않고 새 모듈로 전달합니다. 내부 코드는 `tools.item3`, `tools.item4`, `tools.common`의 명시적인 가져오기를 사용합니다.

| 작업 | 실제 구현 |
| --- | --- |
| 8100 서비스 | `item4/serve_nist_operational_vex.py` |
| 원문 조건 전수·체크포인트 재개 | `item4/validate_cvss_source_population.py` |
| 해당 전수 검증의 보고서 재검사 | 동일 명령의 `--report-only` (실행 당시 고정 코드 사용) |
| #3 현재 평가 | `item3/run_item3_test.py` |
| 패키지 배포·복원 | `common/runtime_release.py` |
| #4 원문 조건·질문 계약 검증 | `item4/evaluate_source_question_contract.py` |

이동 목록과 검증 범위는 `../results/tools_tests_layout_20261123/`에 있습니다. `--help` 확인은 실제 학습·모델 평가 실행을 의미하지 않습니다.

2026-11-25 완료된 구조 이관 스크립트와 미사용 연구 명령을 제거했습니다. 과거 평가 재현에 연결된 도구는 유지합니다. 삭제 목록과 외부 복구 위치는 `../results/current_logic_cleanup_20261125/manifest.json`에 있습니다.
