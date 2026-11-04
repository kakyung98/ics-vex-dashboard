# 빌드구성 축 GT — `vulnerable_code_not_present` 를 제품 소스 없이 판정하기

> **이 문서가 기록하는 것**
> 소스 코퍼스 267건은 **제품이 아니라 부품(라이브러리·유틸) 트리**다. 제품 소스는
> 입수 불가(`W10`, 소스 폐쇄 90.87%)이므로 "제품 엔트리포인트에서 도달하는가"는
> 이 코퍼스로 답할 수 없다. 그러나 VEX justification 하나는 제품 소스를 **전혀**
> 요구하지 않는다 — `vulnerable_code_not_present`. 임베디드 벤더는 플래시 예산
> 때문에 거의 항상 축소 빌드를 하고, 취약 함수가 그 구성에서 컴파일되지 않으면
> 그 함수는 출하 바이너리에 **없다**. 이것은 추론이 아니라 빌드 사실이다.
>
> 산출물: `data/build_gates.jsonl`, `results/build_gate_coverage.json`,
> `data/symbol_presence_gt.jsonl`, `results/symbol_gt_summary.json`
> 도구: `tools/resolve_build_gates.py` (1단계), `tools/build_symbol_gt.py` (2단계)

---

## 0. 코퍼스 구성 — 부품 트리 267건

| 구분 | CVE | 종 | 비고 |
|---|---:|---:|---|
| 엔트리포인트 보유 (실행파일/커널) | **69** | 13 | busybox, u-boot, nginx, lighttpd, dnsmasq, openvpn, openssh, dropbear, wpa_supplicant, net-snmp, ntp, linux-kernel, FreeRTOS |
| 순수 라이브러리 | **198** | 12 | openssl, sqlite, libcurl, libxml2, glibc, zlib, libssh2, libexpat, libpcap, log4j2, spring, sqlparse |
| **합계** | **267** | **25** | 전체 11.7 GB, 빈 스냅샷 0건 |

버전 다중성: libcurl 18 릴리스, openssl 16, sqlite 15, busybox 13 (CVE마다 적용
릴리스가 달라 같은 부품의 여러 릴리스가 독립 복제돼 있다).

취약함수 국소화 현황 (`data/source_locations.json`):

| 항목 | 값 |
|---|---:|
| 국소화된 CVE | **222 / 267 = 83.1%** |
| 국소화 함수 총수 | **914** |
| 국소화 근거 `patch` (패치 커밋이 수정한 함수) | **155** |
| 국소화 근거 `cti` (어드바이저리 산문에서 추출) | **83** |
| 국소화 실패 `none` | **29** |

---

## 1. 측정 환경 — 컴파일 불가, 빌드선언으로 대체

이 머신에서 Linux 툴체인을 쓸 수 없다.

```
WSL2 Ubuntu : Wsl/Service/CreateInstance/MountDisk/HCS/ERROR_FILE_SYSTEM_LIMITATION
Docker      : CLI 29.2.1 설치됨, 데몬(WSL2 백엔드) 연결 실패
Windows     : gcc/clang/make/nm 없음 (MSVC 2022만 존재, busybox·u-boot 빌드 불가)
```

따라서 `nm`으로 심볼을 읽는 대신 **빌드 시스템이 스스로 선언한 게이팅**을 파싱한다.
증거가 덤프가 아니라 인용 가능한 한 줄이라 재현성은 더 좋다. 산출물 전체에
`evidence_kind: "build-rule-declaration"`, `compiled_symbol_check: false` 가 박히며,
툴체인이 복구되면 이 두 필드만 올라가고 파이프라인은 그대로다.

---

## 2. 게이트 두 종류 — 의도적으로 합치지 않음

| 종류 | 의미 | 증거 예 | 강도 |
|---|---|---|---|
| **build-rule** | 설정 심볼이 꺼지면 **번역 단위 전체**가 링크되지 않음 | `busybox editors/awk.c:36  //kbuild:lib-$(CONFIG_AWK) += awk.o` | 확정 — 심볼까지 통째로 사라짐 |
| **cpp-guard** | 함수 본문이 전처리 조건 안에 있음 | `openssl ssl/d1_both.c  #ifndef OPENSSL_NO_HEARTBEATS` | 약함 — 기본값 on일 수 있고 `#else` 대체 정의 가능 |
| **unconditional** | 게이트 없음 | — | 해당 릴리스의 **모든** 빌드에 존재 → 이 justification 사용 불가 (이것도 유효한 GT 라벨) |

**게이트는 조건이지 판정이 아니다.** "CONFIG_AWK로 게이팅됨"은 특정 RTU가
CONFIG_AWK를 켰는지 말하지 않는다. 그건 2단계의 빌드 프로파일 질문이다.

### 2.1 다중 심볼은 논리합이다

같은 오브젝트를 여러 규칙이 요구한다. busybox `decompress_unlzma.o` 는
`CONFIG_UNLZMA | CONFIG_LZCAT | CONFIG_LZMA | CONFIG_FEATURE_UNZIP_LZMA |
CONFIG_FEATURE_SEAMLESS_LZMA` **다섯 개 중 하나라도** 켜지면 링크된다. 첫 심볼만
집으면 프로파일이 꺼야 할 것을 과소 진술하므로 전부 보존하고 `combine: "any"` 로
기록한다. 이 보정 전 busybox 게이트율은 12/15, 보정 후 **15/15** 였다.

---

## 3. 1단계 측정값 — 게이트 해석 결과

함수 914개 기준:

| 게이트 종류 | 함수 수 | 비율 |
|---|---:|---:|
| build-rule | **43** | 4.7% |
| cpp-guard | **196** | 21.4% |
| unconditional | **675** | 73.9% |

CVE 기준:

| 항목 | 값 |
|---|---:|
| 국소화 CVE | 222 |
| 게이트 보유 CVE (build-rule 또는 cpp-guard) | **89** |
| 게이트율 / 국소화 CVE | **40.1%** |
| 게이트율 / 코퍼스 267 | **33.3%** |
| build-rule 보유 CVE | **18** |

### 3.1 부품별 — 수율이 극단적으로 갈린다

| 부품 | CVE | 국소화 | build-rule | cpp-guard | 게이트없음 | 게이트율 |
|---|---:|---:|---:|---:|---:|---:|
| busybox | 18 | 15 | **14** | 1 | 0 | **83.3%** |
| libssh2 | 6 | 5 | 0 | 4 | 1 | 66.7% |
| libcurl | 26 | 24 | 0 | 16 | 8 | 61.5% |
| u-boot | 9 | 9 | **4** | 1 | 4 | 55.6% |
| sqlite | 34 | 31 | 0 | 17 | 14 | 50.0% |
| openssh | 6 | 4 | 0 | 3 | 1 | 50.0% |
| dnsmasq | 4 | 3 | 0 | 2 | 1 | 50.0% |
| openvpn | 4 | 4 | 0 | 2 | 2 | 50.0% |
| libxml2 | 22 | 22 | 0 | 9 | 13 | 40.9% |
| libexpat | 8 | 8 | 0 | 2 | 6 | 25.0% |
| nginx | 4 | 2 | 0 | 1 | 1 | 25.0% |
| zlib | 6 | 4 | 0 | 1 | 3 | 16.7% |
| wpa_supplicant | 12 | 4 | 0 | 2 | 2 | 16.7% |
| glibc | 21 | 19 | 0 | 2 | 17 | 9.5% |
| **openssl** | **69** | 54 | 0 | 5 | 49 | **7.2%** |
| linux-kernel | 5 | 5 | 0 | 0 | 5 | 0.0% |
| spring / log4j2 / lighttpd / libpcap / sqlparse | 7 | 6 | 0 | 0 | 6 | 0.0% |
| **합계** | **266**\* | **222** | **18** | **71** | **133** | **33.5%** |

\* ntp 1건은 국소화 함수가 0이라 집계에서 빠진다 (267 − 1).

**가장 큰 부품이 가장 낮다.** openssl 69건 중 게이트 보유는 5건(7.2%)뿐이다.
취약함수가 `crypto/` 94개 · `ssl/` 72개에 몰려 있고 이들은 `no-*` 로 떼어낼 수
있는 알고리즘 모듈이 아니라 핵심 경로다. 반대로 busybox(applet 단위 Kconfig)와
u-boot(cmd/drivers 단위 Kconfig)는 설계상 게이팅이 촘촘하다.

### 3.2 실제로 잡힌 심볼 — 임베디드에서 끄는 것들

build-rule 상위:

| 심볼 | 함수 수 |
|---|---:|
| `CONFIG_AWK` | 10 |
| `CONFIG_LMB` | 8 |
| `CONFIG_CMD_I2C` | 7 |
| `CONFIG_CMD_TFTPBOOT` | 5 |
| `CONFIG_NET` | 3 |
| `CONFIG_CMD_BOOTM` / `CONFIG_SPL_NAND_BASE` / `CONFIG_HUSH` | 2 각 |

cpp-guard 상위:

| 매크로 | 함수 수 |
|---|---:|
| `CURL_DISABLE_TFTP` | 15 |
| `USE_NGTCP2` / `USE_NGHTTP3` | 13 각 |
| `USE_NTLM` | 12 |
| `USE_QUICHE` | 10 |
| `SQLITE_OMIT_VIRTUALTABLE` | 7 |
| `CURL_DISABLE_FTP` | 7 |
| `USE_WINDOWS_SSPI` / `USE_OPENSSL` | 6 각 |
| `SQLITE_OMIT_JSON` | 6 |
| `OPENSSL_NO_TLSEXT` | 5 |
| `HAVE_DNSSEC` | 5 |

busybox awk 10건이 단일 최대 묶음이다. awk applet을 싣지 않는 RTU에서는 그
10건이 **일괄 `not_affected`** 이고 근거는 `lib-$(CONFIG_AWK) += awk.o` 한 줄이다.

---

## 4. 2단계 — 프로파일은 선언된 입력이다

`W9`(운영맥락이 SBOM에 없음)과 동일한 규율을 빌드구성에도 적용한다. 빌드 구성은
SBOM에서 복원 불가(`version` NOASSERTION 100%)이므로 **자산 소유자가 선언**해야
하고, 출처가 함께 실려야 한다.

| 프로파일 | `profile_basis` | 용도 |
|---|---|---|
| `upstream-default` | `upstream-default` | 모든 게이트 상류 기본값. **전건 `affected`** 가 나와야 한다 — 이 축이 근거 없이 면제를 만들어내지 않음을 증명하는 기준선 |
| `ics-rtu-min` | `declared-reference-profile` | 축소 RTU 이미지: 스크립트 인터프리터·파일전송 클라이언트·미사용 SQL 기능·부트셸 디버그 명령 제외 (21 심볼) |
| 자산 프로파일 | `declared` | 실제 기기의 선언 구성, `--profile-file` 로 주입 |

`CURL_DISABLE_*` · `SQLITE_OMIT_*` · `OPENSSL_NO_*` 는 **극성이 반대**다 (정의되면
코드가 빠진다). 게이트는 매크로만 기록하므로 극성은 2단계에서 프로젝트들의 작명
관례로 해소한다.

### 4.1 라벨 어휘

| 라벨 | justification | 조건 |
|---|---|---|
| `not_affected` | `vulnerable_code_not_present` | 함수가 컴파일되지 않음 |
| `affected` | — | 함수가 바이너리에 존재 |
| `under_investigation` | — | 프로파일이 그 게이트를 선언하지 않음 |

**어떤 라벨도 단독으로 VEX 문장이 아니다.** 라벨은 *부품 빌드*에 대한 사실이고,
제품에 올리려면 제품이 그 빌드를 출하한다는 선언이 필요하다 — `profile_basis` 가
그 책임 소재를 기록한다.

### 4.2 미결 — 함수별 상태를 CVE 라벨로 합치는 규칙

CVE 하나가 여러 함수를 갖고(222 CVE / 914 함수, libssh2 CVE-2019-3858은 단독
108개) 프로파일 아래에서 상태가 **엇갈린다**. busybox CVE-2022-28391이 그 예다.

| 함수 | 파일 | 게이트 | `ics-rtu-min` 상태 |
|---|---|---|---|
| `parse_reply` | `networking/nslookup.c` | build-rule `CONFIG_NSLOOKUP` | **absent** |
| `sockaddr2str` | `libbb/xconnect.c` | 없음 (libbb는 항상 링크) | **present** |

이 리스트를 라벨 하나로 접는 규칙이 `tools/build_symbol_gt.py:collapse()` 이며
아직 미구현이다. 선택지와 비용은 그 함수의 `TODO(human)` 주석에 적어뒀다 —
ALL-absent(엄격) / ANY-absent(느슨) / `localization_source` 가중 / `gate_kind`
가중 / `unresolved` 처리. **항목#4 precision 숫자가 이 규칙을 기준으로 읽히므로
규칙 이름이 모든 GT 행에 기록된다** (`label_rule` 필드).
