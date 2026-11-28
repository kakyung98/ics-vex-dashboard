# 공통 지원 기능

기능별로 관련 모듈과 리소스를 묶었습니다.

| 폴더 | 역할 |
| --- | --- |
| [web/](web/) | 공통 웹 서버, 테마, 영문 표시 및 공통 화면 |
| [data/](data/) | CISA/CVE/CWE 데이터, SBOM 스키마, 버전 처리 및 저장소 |
| [runtime/](runtime/) | 공유 모델 경로, GPU 사용 제어, 추론 및 학습 지원 |
| [evaluation/](evaluation/) | 공통 평가 도구, 데이터셋 통계 및 기준 정보 |

`paths.py`는 프로젝트 루트와 소스 경로를 해석하므로 이 위치에 유지합니다.

새 코드는 기능별 패키지 경로를 사용합니다. 이전 `src.common.모듈명` import도 같은 모듈로 연결되며 실행 상태를 중복 생성하지 않습니다. 파일 경로는 `src.common.paths.source_path()`로 확인할 수 있습니다.

전체 안내: [src/README.md](../README.md). 이동 내역: [manifest.json](../../results/functional_layout_20261123/manifest.json).
