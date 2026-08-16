#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSS CVE -> 실제 취약/패치 코드 수집 (인증된 gh api 사용, 고신뢰).

각 CVE 의 FIX 커밋 URL(NVD 참조 + OSV)을 모아, gh api 로 커밋 상세를 받아
첫 코드 파일의 patch hunk 에서 취약/패치 코드를 재구성한다.

출력: data/code_evidence.json (병합)
"""
import json, os, re, subprocess, sys, time

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(BASE, "tools"))
from generate_ics_sbom import OSS
import collect_code_evidence as C   # osv_commits, parse_diff 재사용
OUT = os.path.join(BASE, "data", "code_evidence.json")
GH = r"C:\Users\user\AppData\Local\Microsoft\WinGet\Packages\GitHub.cli_Microsoft.Winget.Source_8wekyb3d8bbwe\bin\gh.exe"
CODE_EXT = (".c", ".h", ".cc", ".cpp", ".cxx", ".java", ".py", ".go", ".js", ".rb", ".php")


def gh_commit(owner_repo, sha):
    try:
        out = subprocess.run([GH, "api", "repos/%s/commits/%s" % (owner_repo, sha)],
                             capture_output=True, text=True, timeout=40, encoding="utf-8")
        if out.returncode != 0:
            return None
        return json.loads(out.stdout)
    except Exception:
        return None


def reconstruct(patch):
    vuln, patched = [], []
    for ln in patch.splitlines():
        if not ln or ln.startswith("@@"):
            continue
        t, code = ln[0], ln[1:]
        if t == " ":
            vuln.append(code); patched.append(code)
        elif t == "-":
            vuln.append(code)
        elif t == "+":
            patched.append(code)
    v = "\n".join(vuln).strip(); p = "\n".join(patched).strip()
    return (v[:1200], p[:1200]) if v and p and v != p else None


def commit_urls(cve, nvd):
    urls = []
    for u in (nvd.get(cve) or {}).get("references", []):
        if "github.com" in u and "/commit/" in u:
            urls.append(u)
    urls += C.osv_commits(cve)
    seen, out = set(), []
    for u in urls:
        m = re.search(r"github.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})", u)
        if m:
            k = (m.group(1), m.group(2))
            if k not in seen:
                seen.add(k); out.append(k)
    return out


def main():
    from generate_ics_sbom import OSS
    oss_cves = set()
    for spec in OSS.values():
        for _v, cl in spec["versions"]:
            oss_cves.update(cl)
    nvd = json.load(open(os.path.join(BASE, "data", "nvd_cache.json"), encoding="utf-8"))
    ce = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}

    todo = [c for c in sorted(oss_cves) if not ce.get(c, {}).get("vuln_code")]
    print("todo (no code yet): %d" % len(todo), flush=True)
    got = sum(1 for v in ce.values() if v.get("vuln_code"))
    for i, cve in enumerate(todo, 1):
        found = False
        for owner_repo, sha in commit_urls(cve, nvd)[:4]:
            data = gh_commit(owner_repo, sha)
            if not data:
                continue
            for f in data.get("files", []):
                fn = f.get("filename", "")
                if fn.lower().endswith(CODE_EXT) and f.get("patch"):
                    rc = reconstruct(f["patch"])
                    if rc:
                        ce[cve] = {"cve": cve, "repo": owner_repo, "commit": sha[:12],
                                   "file": fn, "vuln_code": rc[0], "patched_code": rc[1], "src": "gh"}
                        got += 1; found = True
                        break
            if found:
                break
        if i % 15 == 0 or i == len(todo):
            json.dump(ce, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
            print("[%d/%d] with_code=%d" % (i, len(todo), got), flush=True)
        time.sleep(0.1)
    json.dump(ce, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("DONE with_real_code=%d / %d OSS CVEs" % (got, len(oss_cves)), flush=True)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
