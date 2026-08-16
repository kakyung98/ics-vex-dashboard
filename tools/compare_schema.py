#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
원본 KISA 샘플(.jsonc) 과 생성된 ICS SBOM 의 구조를 기계적으로 비교한다.

docs/README-스키마확장.md 의 "0. 구조 동일성 검증" 절 근거를 재현한다.

사용법:
    python tools/compare_schema.py [샘플.jsonc 경로] [비교대상.json 경로]

인자를 생략하면 기본 경로를 사용한다.
"""

import glob
import json
import os
import re
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DEFAULT_SAMPLE = os.path.join(os.path.expanduser("~"), "Downloads",
                              "1_2_1_2_VxWorks_RTOS_SBOM 샘플.jsonc")


def load_jsonc(path):
    """// 주석을 제거하고 JSON 으로 읽는다(문자열 내부의 // 는 이 샘플에 없다)."""
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    raw = re.sub(r"^\s*//.*$", "", raw, flags=re.M)
    return json.loads(raw)


def diff(label, sample_keys, gen_keys):
    only_gen = [k for k in gen_keys if k not in sample_keys]
    only_sample = [k for k in sample_keys if k not in gen_keys]
    print("=== %s ===" % label)
    print("  sample: %s" % sample_keys)
    print("  gen   : %s" % gen_keys)
    if not only_gen and not only_sample:
        print("  -> 완전 일치")
    else:
        print("  -> gen 에만 : %s" % (only_gen or "없음"))
        print("  -> sample 에만: %s" % (only_sample or "없음"))
    print()
    return only_gen, only_sample


def main():
    sample_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SAMPLE
    if len(sys.argv) > 2:
        gen_path = sys.argv[2]
    else:
        candidates = sorted(glob.glob(os.path.join(BASE_DIR, "sbom", "*_SBOM.json")))
        if not candidates:
            print("비교할 SBOM 이 없다. 먼저 tools/generate_ics_sbom.py 를 실행하라.")
            return 1
        gen_path = candidates[0]

    if not os.path.exists(sample_path):
        print("원본 샘플을 찾을 수 없다: %s" % sample_path)
        print("첫 번째 인자로 샘플 .jsonc 경로를 지정하라.")
        return 1

    sample = load_jsonc(sample_path)
    with open(gen_path, encoding="utf-8") as f:
        gen = json.load(f)

    print("sample: %s" % os.path.basename(sample_path))
    print("gen   : %s" % os.path.basename(gen_path))
    print()

    removed_total = []

    _, rm = diff("최상위 키", list(sample.keys()), list(gen.keys()))
    removed_total += rm

    _, rm = diff("metadata 키",
                 list(sample["metadata"].keys()), list(gen["metadata"].keys()))
    removed_total += rm

    _, rm = diff("metadata.component 키",
                 list(sample["metadata"]["component"].keys()),
                 list(gen["metadata"]["component"].keys()))
    removed_total += rm

    # 내부 components[] 는 샘플의 대표 항목(properties 를 가진 것)과 비교
    s_inner = next((c for c in sample["components"] if "properties" in c), sample["components"][0])
    g_inner = next((c for c in gen["components"] if c["bom-ref"].startswith("pkg:oss")),
                   gen["components"][0])
    _, rm = diff("components[] 항목 키", list(s_inner.keys()), list(g_inner.keys()))
    # group 은 OSS 부품에서 의도적으로 미사용 (docs/README-스키마확장.md 3절 참조)
    removed_total += [k for k in rm if k != "group"]

    print("=== properties 규약 계승 확인 ===")
    print("  sample inner: %s" % s_inner.get("properties"))
    print("  gen   inner: %s" % g_inner.get("properties"))
    print()

    print("=== 판정 ===")
    if removed_total:
        print("  삭제된 필드 발견: %s" % removed_total)
        return 1
    print("  삭제되거나 이름이 바뀐 필드 없음. 확장은 추가로만 이루어짐.")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
