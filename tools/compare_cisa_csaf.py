#!/usr/bin/env python3
"""우리 VEX 판정을 CISA 원본 CSAF 와 ICSA 단위로 1:1 대조한다.

축이 ICSA 어드바이저리이므로, 우리 산출물(reverse_sbom/<icsa-id>_SBOM-CVE.json,
results/vex_batch.jsonl)과 CISA 원본
(cisagov/CSAF: csaf_files/OT/white/<year>/<icsa-id>.json)이 파일 단위로 대응한다.

사용:
  git clone --depth 1 https://github.com/cisagov/CSAF.git /path/to/CSAF
  python tools/compare_cisa_csaf.py --csaf-repo /path/to/CSAF

CISA 는 OT 어드바이저리에 csaf_vex 프로파일을 쓰지 않고 justification(flags)도
거의 남기지 않으므로, 대조 가능한 라벨은 극소수다. 그 희소성 자체가 결과다.
"""
import argparse
import collections
import glob
import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_ours():
    """ICSA -> {cve: (status, justification)}"""
    out = collections.defaultdict(dict)
    p = os.path.join(BASE, "results", "vex_batch.jsonl")
    for line in open(p, encoding="utf-8"):
        r = json.loads(line)
        out[r["device"]][r["cve"]] = (r["final_vex"], r.get("justification"), r.get("route"))
    return out


def load_cisa(repo):
    """ICSA -> {"category":…, "status":{cve:{status}}, "flags":{cve:{label}}}"""
    out = {}
    for f in glob.glob(os.path.join(repo, "csaf_files", "OT", "**", "*.json"),
                       recursive=True):
        aid = os.path.basename(f)[:-5]
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        rec = {"category": d.get("document", {}).get("category"),
               "status": {}, "flags": {}}
        for v in d.get("vulnerabilities", []) or []:
            cve = v.get("cve")
            if not cve:
                continue
            rec["status"][cve] = {k for k, ids in (v.get("product_status") or {}).items() if ids}
            labs = {fl.get("label") for fl in (v.get("flags") or []) if fl.get("label")}
            if labs:
                rec["flags"][cve] = labs
        out[aid] = rec
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csaf-repo", required=True, help="local clone of cisagov/CSAF")
    a = ap.parse_args()

    ours, cisa = load_ours(), load_cisa(a.csaf_repo)
    common = sorted(set(ours) & set(cisa))
    print("우리 ICSA        : %d" % len(ours))
    print("CISA OT CSAF     : %d" % len(cisa))
    print("대조 가능 ICSA   : %d" % len(common))

    prof = collections.Counter(cisa[a_]["category"] for a_ in common)
    print("\nCISA 문서 프로파일: %s" % dict(prof))

    # CISA 가 justification(flags) 을 남긴 건 = 유일한 외부 정답지
    labelled = [a_ for a_ in common if cisa[a_]["flags"]]
    print("\nCISA 가 justification 을 남긴 ICSA: %d" % len(labelled))
    n_pairs = 0
    ingested = derived_agree = derived_total = just_match = 0
    rows = []
    for aid in labelled:
        for cve, labs in cisa[aid]["flags"].items():
            got = ours[aid].get(cve)
            if not got:
                continue
            ours_st, ours_j, route = got
            n_pairs += 1
            is_up = (route == "upstream-cisa-csaf")
            if is_up:
                ingested += 1
                just_match += bool(ours_j in labs)
            else:
                derived_total += 1
                derived_agree += bool(ours_st == "LIKELY_NOT_AFFECTED")
            rows.append((aid, cve, sorted(labs)[0], ours_st, ours_j,
                         "ingested" if is_up else "derived"))
    print("대조된 (ICSA, CVE) 쌍  : %d" % n_pairs)
    print()
    print("  [A] 상류 채택 (CISA CSAF 를 그대로 실은 것) : %d" % ingested)
    if ingested:
        print("      justification 까지 일치            : %d/%d" % (just_match, ingested))
    print("      -> 자체 판정 성능이 아니다. 성능 지표에서 반드시 제외한다.")
    print()
    print("  [B] 자체 유도 대상                         : %d" % derived_total)
    if derived_total:
        print("      우리도 not_affected                : %d (%.0f%%)"
              % (derived_agree, 100.0 * derived_agree / derived_total))
    else:
        print("      (전량 상류 채택되어 자체 유도로 남은 쌍이 없다)")
    print(
          "%-18s %-16s %-36s %-22s %-34s %s"
          % ("ICSA", "CVE", "CISA flag", "ours", "our justification", "origin"))
    for r in rows[:40]:
        print("%-18s %-16s %-36s %-22s %-34s %s"
              % (r[0], r[1], r[2], r[3], r[4] or "-", r[5]))

    # CISA 가 known_not_affected 를 쓴 건 (flags 없이도)
    kna = [a_ for a_ in common if any("known_not_affected" in v
                                      for v in cisa[a_]["status"].values())]
    print("\nCISA 가 known_not_affected 를 쓴 ICSA: %d" % len(kna))


if __name__ == "__main__":
    main()
