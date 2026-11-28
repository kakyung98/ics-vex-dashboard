# 악용 조건 추출의 CVSS·CWE 정합성 평가

이 도구는 저장된 LLM 추출 결과와 공개 CVSS 벡터·CWE를 비교하는 보조 분석입니다. CWE·CVSS별 분포를 통해 추출물이나 군집의 특성을 다양한 관점에서 해석하는 자료로 사용할 수 있습니다. VEX 상태 결정, 운영자 답변 평가, 추출 결과 수정은 수행하지 않습니다. 결과는 메타데이터 정합성이며, 조건 추출의 의미 정확도·Precision·Recall 또는 AND/OR 관계의 정확성을 증명하지 않습니다. 이 도구 자체는 새 군집을 생성하거나 기존 군집의 품질을 측정하지 않습니다.

## 실행

프로젝트 루트 `C:\ICS-VEX`에서 실행합니다.

```powershell
python tools/item4/evaluate_prerequisite_consistency.py --extractions extraction.json --references references.json
# 자유로운 표현을 기존 모델로 매핑하려면 명시적으로 선택합니다.
python tools/item4/evaluate_prerequisite_consistency.py --extractions extraction.json --references references.json --projection-model
python -m pytest tests/item4/test_prerequisite_consistency.py -q
```

기본 모드는 제한된 영어 명시 표현만 규칙으로 인식합니다. 인식하지 못한 문장은 추측하지 않고 `unmapped_condition_ids`에 남깁니다. 임의의 자연어 전체를 다루는 추출 정확도 평가로 해석하면 안 됩니다.

`--projection-model`은 기존 JSON 추론 제공자의 `operating-record-review` 역할을 사용합니다. 모델에는 추출된 조건 문장과 논리식, 출력 스키마만 제공하며 CVE ID·원문·정답 CVSS·CWE는 제공하지 않습니다. 모델의 매핑 자체도 오류 가능성이 있는 중간 결과입니다. 인용문이 추출 문장에 존재하는지, 값·버전·ID가 유효한지 검사하고, 실패하면 종료 코드 2를 반환하며 규칙 결과로 대체하지 않습니다. 제공자는 기존 `ICS_PREREQUISITE_LLM_URL`, `ICS_PREREQUISITE_LLM_MODEL` 등의 설정을 사용합니다.

원래 조건 추출 호출에 CWE·CVSS가 포함됐는지는 별도로 감사해야 합니다. 이 평가기의 매핑 입력이 블라인드라는 사실만으로 원래 추출도 블라인드였다고 주장하지 않습니다. 기존 인용문에 CVSS 벡터가 들어 있는 경우도 원래 추출의 누출 가능성을 확인해야 합니다.

## 입력

추출 입력은 JSON 단일 객체·배열 또는 JSONL입니다. 각 레코드에 `cve`가 필요하며 `prerequisites` 또는 `conditions`의 `id`, `statement`를 사용합니다. 기존 `extraction`, `prerequisite`, `draft` 래퍼도 지원합니다. `nonrequirements`는 별도 ID로 포함합니다. 원문의 인용문을 다시 읽어 추출 결과의 누락을 보충하지 않습니다.

```json
{
  "cve": "CVE-2099-90001",
  "synthetic": true,
  "prerequisites": [
    {"id": "c1", "statement": "Attacker requires high privileges."},
    {"id": "c2", "statement": "No user interaction is required."}
  ]
}
```

위 ID는 사용법 설명을 위한 가상 사례입니다. 참조 입력은 NVD `vulnerabilities[].cve` 형식 또는 다음 정규화 형식을 지원합니다. 같은 CVE의 복수 출처·버전 벡터는 각각 비교하며 합의 벡터로 합치지 않습니다. CVSS 총점에서 벡터를 복원하지 않습니다.

```json
{
  "cve": "CVE-2099-90001",
  "vectors": [{"source": "fictional-test-reference", "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
  "cwes": ["CWE-787"]
}
```

## 비교 규칙

- CVSS 3.0·3.1의 AV/PR/UI/AC와 4.0의 AV/PR/UI/AC/AT를 구분합니다. 2.0과 잘못된 참조 벡터는 미지원·오류로 보존합니다. UI:R을 v4의 P 또는 A로 임의 변환하지 않습니다.
- `match`는 해당 참조와의 일치, `contradiction`은 원문과 스코어링 범위의 재검토가 필요한 모순 후보입니다. 공개 벡터 자체가 무조건 정답이라는 의미는 아닙니다.
- 조건 미추출·매핑 불가·서로 충돌하는 주장·버전 불일치는 `not_comparable`로 기록합니다. 누락을 반대 조건의 주장으로 바꾸지 않습니다.
- 여러 시나리오, 제품별 조건, NOT/OR 내부 조건은 CVE 전체 벡터로 평탄화하지 않습니다. 범위가 맞는지 확인되지 않으면 비교를 보류합니다. 같은 제품에 대한 단일 시나리오라도 이 버전은 보수적으로 보류할 수 있습니다.
- 인증 기능 활성화는 공격자의 사전 권한과 다르고, 공격자가 파일을 올리는 것은 다른 사용자의 상호작용과 다릅니다. 이러한 항목에서 PR/UI를 추측하지 않습니다.
- 직접 구조화한 `metric_claims`도 사용할 수 있습니다. 각 항목에 `condition_id`, `metric`, `value`, `version`(3.0/3.1/4.0), `scope`(cve/unresolved), 추출 문장 내부의 정확한 `quote`를 지정합니다. AC/AT도 이 계약으로 평가할 수 있습니다. 직접 제공한 매핑의 독립성은 별도 검토 대상입니다.
- CWE는 `weakness_claims`에 명시된 약점 기전 주장만 비교합니다. 각 주장에는 `condition_id`, `cwe`, 추출 문장 내부의 `quote`가 필요합니다. 운영 조건만 있고 약점 주장이 없으면 판단 불가입니다. CWE로부터 권한·접근 경로 같은 조건을 생성하지 않습니다.
- CWE는 정확한 코드 일치와 고정한 로컬 CWE-1000 분류의 조상·자손 관계를 구분합니다. 서로 다른 유형은 `review_required`이며 자동 기각하지 않습니다. 분류가 없거나 불완전하면 계층 일치를 추정하지 않습니다.

## 결과와 해석

기본 출력은 `results/prerequisite_consistency_v1/`입니다.

- `comparisons.jsonl`: 조건별 투영 근거, 벡터 출처·버전별 판정, CWE 보조 검토, 입력·참조 해시
- `projections.jsonl`: 모델 모드의 매핑 결과·모델 정보·블라인드 입력 해시
- `report.json`: 전체 입력·오류·참조 누락·매핑 불가 건수, 비교 가능한 항목의 일치율·모순율

일치율 분모는 `match + contradiction`입니다. 비교할 항목이 없으면 비율은 null입니다. 버전·출처별 비교이므로 하나의 CVE가 여러 비교를 만들 수 있습니다. 오류 레코드와 참조만 있고 추출이 없는 CVE도 별도로 기록합니다. 출력 비율은 조건별 정답 Precision이 아닙니다. 모델 모드를 선택하지 않은 실행은 새 LLM 성능 측정도 아닙니다.

공식 정의: [CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document), [CVSS 4.0](https://www.first.org/cvss/v4.0/specification-document), [CWE 매핑 지침](https://cwe.mitre.org/documents/cwe_usage/guidance.html).

## 실제 전수 보조 분석

```powershell
# 기존 12,418개 CVE 추출물과 고정 CSAF 참조를 사용합니다.
python -X utf8 -u tools/item4/run_prerequisite_consistency_population.py --workers 4
# 체크포인트를 재사용하고 실패한 모델 호출만 재시도합니다.
python -X utf8 -u tools/item4/run_prerequisite_consistency_population.py --workers 4 --retry-errors
python tools/item4/characterize_prerequisite_population.py results/prerequisite_auxiliary_population_20261124
```

기존 인증된 로컬 H200 터널의 18128 포트와 고정 Nemotron 모델을 사용합니다. 조건이 존재하는 추출물에 대해서만 실제 LLM 매핑을 호출하며, 빈 추출물·미해결 추출물에 조건을 새로 만들지 않습니다. 이 레코드들도 전수 결과에 보존하고 실제 호출 수를 별도로 보고합니다. 원래 추출의 출처 문장에 CVSS가 포함된 건수도 기록하므로, 매핑의 블라인드 처리와 원래 추출의 블라인드 여부를 구분할 수 있습니다.

`progress.json`은 진행 상태, `preparation.json`은 모집단·입력 해시와 조건 존재 분포, `checkpoints/`는 CVE별 실제 매핑·실패·비교 결과입니다. `report.json`과 `comparisons.jsonl`은 전수 실행 결과이며, `characterization.json`은 원래 추출 상태·CWE·CVSS 항목별 보조 분포입니다. `population_ledger.jsonl`은 모든 CVE의 원래 식별자와 상태를 유지합니다. 이 원장은 군집 할당 결과가 아니며, 군집화 수행 또는 군집화 품질 검증으로 세지 않습니다.

### 2026-11-24 실행 결과

전체 12,418개 CVE를 보존했고, 진술이 있는 146개 CVE에 실제 Nemotron 매핑을 완료했습니다. 최종 오류는 0건입니다. 저장된 진술은 긍정 악용 전제조건 90개와 명시적 비요구사항 88개이며, 둘을 합한 178개입니다. 진술이 없는 12,272건은 원문에 조건이 없음을 증명한 결과가 아니며, 빈 추출과 미해결 상태를 그대로 보존한 것입니다.

CVSS 비교는 일치 40개·모순 후보 9개·판단 불가 69,276개입니다. 모순 후보 9개는 서로 다른 8개 CVE에 해당하며 출처·버전별 비교입니다. CWE 기전 주장을 비교할 수 있는 CVE는 2개로, 정확한 코드 일치 1건·추가 검토 필요 1건입니다. 그 외 CWE는 참조 라벨별 분포를 제공하며 조건의 정확성을 추정하지 않습니다.

기존 추출 원문 중 2,818건에 CVSS가 포함되어 있었으므로, 이번 매핑이 정답을 보지 않았다는 사실만으로 원래 추출까지 독립 검증했다고 할 수 없습니다. 따라서 결과는 군집이나 추출물의 특성을 살펴보는 보조 분석이며, 군집화 정확도·조건 추출 정확도·전체 CVE 집단의 일치율로 해석하지 않습니다. 이번 작업에서 새 군집을 만들거나 기존 군집의 순도·실루엣을 계산하지 않았습니다.
