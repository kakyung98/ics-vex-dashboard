#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-GENIE 공개 데이터셋(Apache 2.0)에서 (CVE 정보 -> PoC exploit) SFT 코퍼스 수집.

각 재현 CVE 폴더에서:
  conversations/cve_info.json  -> 명령(instruction) 재료 (CVE 설명·CWE·근본원인)
  scripts/exploit.py           -> 완성(completion) 타깃 (실제 작동 PoC)

출력: data/poc_sft.jsonl  { cve, instruction, completion, lang }
출처: github.com/BUseclab/cve-genie (Apache-2.0), CVE-GENIE (Ullah et al.)
"""
import base64, json, os, subprocess, sys, time

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUT = os.path.join(BASE, "data", "poc_sft.jsonl")
GH = r"C:\Users\user\AppData\Local\Microsoft\WinGet\Packages\GitHub.cli_Microsoft.Winget.Source_8wekyb3d8bbwe\bin\gh.exe"
REPO = "BUseclab/cve-genie"
ROOT = "results/reproduced_cves"


def gh_json(path):
    try:
        o = subprocess.run([GH, "api", path], capture_output=True, text=True, timeout=40, encoding="utf-8")
        return json.loads(o.stdout) if o.returncode == 0 else None
    except Exception:
        return None


def gh_file(path):
    d = gh_json("repos/%s/contents/%s" % (REPO, path))
    if not d or "content" not in d:
        return None
    try:
        return base64.b64decode(d["content"]).decode("utf-8", "replace")
    except Exception:
        return None


def build_instruction(cve_info_raw, cve):
    """cve_info.json 에서 명령 프롬프트 구성."""
    try:
        info = json.loads(cve_info_raw)
    except Exception:
        info = {}
    # 필드는 유연하게 추출
    def g(*keys):
        for k in keys:
            for kk in (k, k.lower(), k.upper()):
                if isinstance(info, dict) and kk in info and info[kk]:
                    return str(info[kk])
        return ""
    desc = g("description", "cve_description", "summary")
    cwe = g("cwe", "cwe_data", "cwes")
    root = g("root_cause", "root_cause_analysis")
    parts = ["Write a working Python proof-of-concept exploit for the following vulnerability.",
             "CVE: %s" % cve]
    if cwe:
        parts.append("CWE: %s" % cwe[:200])
    if desc:
        parts.append("Description: %s" % desc[:800])
    if root:
        parts.append("Root cause: %s" % root[:800])
    parts.append("Output a self-contained exploit.py that triggers the vulnerability.")
    return "\n".join(parts)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    # GitHub contents API 는 디렉터리 항목 전체를 한 응답에 반환한다(페이지네이션 불필요)
    listing = gh_json("repos/%s/contents/%s" % (REPO, ROOT)) or []
    cves = sorted({x["name"] for x in listing if x.get("type") == "dir"})
    print("reproduced CVEs: %d" % len(cves), flush=True)

    done = {}
    if os.path.exists(OUT):
        for line in open(OUT, encoding="utf-8"):
            r = json.loads(line); done[r["cve"]] = r

    n_ok = len(done)
    f = open(OUT, "a", encoding="utf-8")
    for i, cve in enumerate(cves, 1):
        if cve in done:
            continue
        exploit = gh_file("%s/%s/scripts/exploit.py" % (ROOT, cve))
        if not exploit or len(exploit) < 40:
            continue
        cve_info = gh_file("%s/%s/conversations/cve_info.json" % (ROOT, cve)) or "{}"
        instr = build_instruction(cve_info, cve)
        rec = {"cve": cve, "instruction": instr, "completion": exploit.strip(),
               "lang": "python"}
        f.write(json.dumps(rec, ensure_ascii=False) + "\n"); f.flush()
        n_ok += 1
        if i % 20 == 0 or i == len(cves):
            print("[%d/%d] collected %d" % (i, len(cves), n_ok), flush=True)
        time.sleep(0.05)
    f.close()
    print("DONE  SFT examples: %d -> %s" % (n_ok, OUT), flush=True)


if __name__ == "__main__":
    main()
