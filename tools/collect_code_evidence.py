#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSS CVE -> collect the real vulnerable and patched code (input for CodeBERT).

Finds each CVE's FIX commit (on GitHub) through OSV, fetches the diff, and reconstructs
the vulnerable (pre-patch) and patched (post-patch) code from the first code file's
hunk.

  vuln_code    = context + the deleted (-) lines   (pre-patch = vulnerable)
  patched_code = context + the added (+) lines     (post-patch = fixed)

Output: data/code_evidence.json  { CVE: {repo, file, commit, vuln_code, patched_code} }
Coverage is partial - only CVEs for which OSV supplies a commit. The rest stay without
code.
"""
import json, os, re, sys, time, urllib.request, urllib.error

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(BASE, "tools"))
from generate_ics_sbom import OSS
OUT = os.path.join(BASE, "data", "code_evidence.json")
UA = {"User-Agent": "ics-vex-research/1.0"}
CODE_EXT = (".c", ".h", ".cc", ".cpp", ".cxx", ".java", ".py", ".go", ".js", ".rb", ".php")


def get(url, timeout=25, raw=False):
    for a in range(3):
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout)
            data = r.read().decode("utf-8", "replace")
            return data if raw else json.loads(data)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            time.sleep(1.5 * (a + 1))
        except Exception:
            time.sleep(1.5 * (a + 1))
    return None


def osv_commits(cve):
    d = get("https://api.osv.dev/v1/vulns/" + cve)
    if not d:
        return []
    urls = []
    for r in d.get("references", []):
        u = r.get("url", "")
        if r.get("type") == "FIX" and "github.com/" in u and "/commit/" in u:
            urls.append(u.split("#")[0])
    return urls


def parse_diff(diff):
    """The first hunk of the first code file -> (file, vuln_code, patched_code)."""
    # Split into file blocks
    blocks = re.split(r"(?m)^diff --git ", diff)
    for b in blocks:
        fm = re.search(r"^\+\+\+ b/(.+)$", b, re.M)
        if not fm:
            continue
        fpath = fm.group(1).strip()
        if not fpath.lower().endswith(CODE_EXT):
            continue
        # the first hunk
        hm = re.search(r"(?ms)^@@[^\n]*@@\n(.*?)(?=\n@@|\Z)", b)
        if not hm:
            continue
        lines = hm.group(1).splitlines()
        vuln, patched = [], []
        for ln in lines:
            if not ln:
                continue
            tag, code = ln[0], ln[1:]
            if tag == " ":
                vuln.append(code); patched.append(code)
            elif tag == "-":
                vuln.append(code)
            elif tag == "+":
                patched.append(code)
        v = "\n".join(vuln).strip(); p = "\n".join(patched).strip()
        if v and p and v != p:
            return fpath, v[:1200], p[:1200]
    return None


def main():
    cves = {}
    for spec in OSS.values():
        for _ver, cl in spec["versions"]:
            for c in cl:
                cves.setdefault(c, spec["name"])
    cves = sorted(cves)
    print("OSS CVEs to resolve: %d" % len(cves), flush=True)

    cache = {}
    if os.path.exists(OUT):
        cache = json.load(open(OUT, encoding="utf-8"))
    got = 0
    for i, cve in enumerate(cves, 1):
        if cve in cache:
            if cache[cve].get("vuln_code"):
                got += 1
            continue
        commits = osv_commits(cve)
        rec = {"cve": cve, "commits_found": len(commits)}
        for cu in commits[:4]:
            diff = get(cu + ".diff", raw=True)
            if not diff:
                continue
            parsed = parse_diff(diff)
            if parsed:
                m = re.search(r"github.com/([^/]+/[^/]+)/commit/([0-9a-f]+)", cu)
                rec.update({"repo": m.group(1) if m else "", "commit": m.group(2)[:12] if m else "",
                            "file": parsed[0], "vuln_code": parsed[1], "patched_code": parsed[2]})
                got += 1
                break
        cache[cve] = rec
        if i % 10 == 0 or i == len(cves):
            json.dump(cache, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
            print("[%d/%d] resolved with code: %d" % (i, len(cves), got), flush=True)
        time.sleep(0.25)
    json.dump(cache, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("DONE  CVEs=%d  with_real_code=%d (%.0f%%)" % (len(cves), got, 100 * got / len(cves)), flush=True)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
