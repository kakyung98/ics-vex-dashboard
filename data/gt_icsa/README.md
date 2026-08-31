# gt_icsa — 공개 ICS 생태계의 VEX 정답지 (전량)

CISA 공식 CSAF 저장소([cisagov/CSAF](https://github.com/cisagov/CSAF))의 OT 어드바이저리
**3,706건(icsa-*)** 을 전수 조사해, VEX 판정에 해당하는 라벨을 가진 것만 고정 보관한다.
임시 clone 없이 재현·대조가 가능하도록 원본 JSON 을 그대로 복사해 둔다.

재수집: `python tools/collect_gt_icsa.py --csaf-repo /path/to/cisagov-CSAF`
대조  : `python tools/compare_cisa_csaf.py --csaf-repo /path/to/cisagov-CSAF`

## 규모

| 계층 | 정의 | ICSA | 라벨된 CVE |
|---|---|---|---|
| **tier1** | `vulnerabilities[].flags[].label` 보유 — **CISA justification 명시** | **12** | **18** |
| tier2 | `known_not_affected` 는 있으나 `flags` 없음 — 근거 미기재 | 13 | — |
| (전체 OT icsa-*) | | 3,706 | |

tier1 은 전체의 **0.32%** 다. 2010–2023 어드바이저리에는 **0건**이며,
최초 사례는 2024-08-22(`icsa-24-235-03`)이다.

## justification 분포 (tier1, 18 CVE)

```
component_not_present                              10
vulnerable_code_not_in_execute_path                 5
vulnerable_code_not_present                         4
vulnerable_code_cannot_be_controlled_by_adversary    0   <- 환경 기반
inline_mitigations_already_exist                     0   <- 환경 기반
```

**환경(배치 맥락)을 근거로 삼은 사례는 0건이다.** 실제 ICS 생태계가 `not_affected` 에
동원한 근거는 100% 소스코드/빌드 사실이며, 이것이 본 시스템이 코드 축을 VEX status 로,
운영 맥락을 SSVC 우선순위로 분리하는 실증 근거다.

벤더: 11건 Siemens, 1건 Mobotix(`icsa-24-235-03`).

## 구성

```
manifest.json                         ICSA 별 메타 + flags(CVE->label) + 우리 SBOM 링크
tier1_justification/cisa_csaf/*.json  CISA 원본 CSAF 12건
tier1_justification/our_sbom/*.json   같은 ICSA 의 우리 역방향 SBOM 12건 (1:1 대응)
tier2_status_only/cisa_csaf/*.json    CISA 원본 CSAF 13건
```

축이 ICSA 이므로 `tier1_justification/` 안의 두 디렉터리는 파일 단위로 짝을 이룬다.

## 현재 성적과 그 이유

`tools/compare_cisa_csaf.py` 기준 **18쌍 중 일치 0건(0%)**. 원인은 구조적이다:

1. 우리 SBOM 은 어드바이저리에서 *역으로* 만들어져 **어드바이저리가 언급한 컴포넌트만**
   들어 있다. "그 컴포넌트가 없다"를 표현할 수 없어 `component_not_present`(10/18)가
   원리적으로 발화하지 않는다.
2. CISA 는 같은 ICSA 안에서 **제품 모델별로** 판정을 가른다
   (`icsa-25-191-06`: SIPROTEC 5 CP300 44개 affected / CP200 20개 not_affected).
   우리 역방향 SBOM 에는 **모델 변형 단위가 없다.**

→ 좁히는 방법: CISA CSAF 의 `product_tree` 를 역방향 SBOM 에 주입해 모델 변형 단위를
만들면 18쌍 전부가 판정 가능한 대상이 된다.
