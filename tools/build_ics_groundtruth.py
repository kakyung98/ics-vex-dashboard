#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build vuln/patched ground-truth pairs for ALL ICS source-available CVEs.

Fetches each CVE's upstream fix commit and reconstructs the changed C/C++ code's
before (vulnerable) and after (patched) from the diff. Commit URLs come from:
  1. data/code_evidence.json      (repo + commit, 34 CVEs) — full function code kept as-is
  2. cve-genie icsvex_tierA.json  (patch_commits[].url — GitHub commit URLs)

For (2) and any missing (1) code, fetch <commit>.diff from GitHub and parse
C/C++ hunks: before = context+removed, after = context+added.

Output: data/ics_gt_pairs.jsonl  [{cve, cwe, repo, vuln_code, patched_code, src}]
"""
import json
import os
import re
import time
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CE = os.path.join(BASE, "data", "code_evidence.json")
TIERA = os.environ.get("TIERA_JSON", r"C:\Users\user\Desktop\cve-genie\webapp\data\icsvex_tierA.json")
SNAP = os.path.join(BASE, "data", "source_snapshots")
OUT = os.path.join(BASE, "data", "ics_gt_pairs.jsonl")
C_EXT = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh")
UA = {"User-Agent": "Mozilla/5.0"}


def fetch_diff(commit_url):
    url = commit_url.split("#")[0].rstrip("/")
    if "/commit/" not in url:
        return None
    for suf in (".diff", ".patch"):
        try:
            req = urllib.request.Request(url + suf, headers=UA)
            return urllib.request.urlopen(req, timeout=25).read().decode("utf-8", "ignore")
        except Exception:
            continue
    return None


def parse_unified_diff(diff):
    """Reconstruct C/C++ before/after from a unified git diff."""
    before, after = [], []
    cur_c = False
    for line in diff.split("\n"):
        if line.startswith("diff --git") or line.startswith("+++ ") or line.startswith("--- "):
            m = re.search(r"[ab]/(\S+)", line)
            if line.startswith("diff --git"):
                cur_c = bool(m) and m.group(1).lower().endswith(C_EXT)
            continue
        if line.startswith("@@") or line.startswith("index ") or line.startswith("new file") or line.startswith("deleted file"):
            continue
        if not cur_c:
            continue
        if line.startswith("-"):
            before.append(line[1:])
        elif line.startswith("+"):
            after.append(line[1:])
        elif line.startswith(" "):
            before.append(line[1:]); after.append(line[1:])
    return "\n".join(before).strip(), "\n".join(after).strip()


def commit_urls_for(cve, ce_entry, tiera_entry):
    urls = []
    if ce_entry and ce_entry.get("repo") and ce_entry.get("commit"):
        urls.append("https://github.com/%s/commit/%s" % (ce_entry["repo"], ce_entry["commit"]))
    for pc in (tiera_entry or {}).get("patch_commits", []) or []:
        if pc.get("url"):
            urls.append(pc["url"])
    # de-dup, keep order
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u); out.append(u)
    return out


def main():
    ce = json.load(open(CE, encoding="utf-8"))
    ta = json.load(open(TIERA, encoding="utf-8")) if os.path.isfile(TIERA) else {}
    # target universe = the ICS source-available CVEs (snapshots ∪ code_evidence ∪ tierA)
    snaps = set(os.listdir(SNAP)) if os.path.isdir(SNAP) else set()
    cves = sorted(snaps | {c for c, v in ce.items() if isinstance(v, dict) and v.get("vuln_code")} | set(ta.keys()))

    pairs, stats = {}, {"code_evidence": 0, "fetched": 0, "no_commit": 0, "fetch_fail": 0, "no_cdiff": 0}
    for cve in cves:
        ce_e = ce.get(cve) if isinstance(ce.get(cve), dict) else None
        ta_e = ta.get(cve)
        cwe = ""
        if ta_e:
            cw = ta_e.get("cwes") or [""]
            cwe = cw[0] if isinstance(cw, list) and cw else ""
        # 1) full-function pair already collected
        if ce_e and ce_e.get("vuln_code") and ce_e.get("patched_code"):
            pairs[cve] = {"cve": cve, "cwe": ce_e.get("cwe", cwe), "repo": ce_e.get("repo", ""),
                          "vuln_code": ce_e["vuln_code"], "patched_code": ce_e["patched_code"],
                          "src": "code_evidence"}
            stats["code_evidence"] += 1
            continue
        # 2) fetch the fix commit diff and reconstruct
        urls = commit_urls_for(cve, ce_e, ta_e)
        if not urls:
            stats["no_commit"] += 1
            continue
        b_all, a_all, repo = [], [], ""
        ok = False
        for u in urls[:4]:
            mrepo = re.search(r"github\.com/([^/]+/[^/]+)/commit", u)
            if mrepo and not repo:
                repo = mrepo.group(1)
            diff = fetch_diff(u)
            if not diff:
                continue
            ok = True
            b, a = parse_unified_diff(diff)
            if b:
                b_all.append(b)
            if a:
                a_all.append(a)
            time.sleep(0.2)
        if not ok:
            stats["fetch_fail"] += 1
            continue
        vuln, patched = "\n".join(b_all).strip(), "\n".join(a_all).strip()
        if vuln and patched and "{" in (vuln + patched) and vuln != patched and len(vuln) > 30:
            pairs[cve] = {"cve": cve, "cwe": cwe, "repo": repo,
                          "vuln_code": vuln, "patched_code": patched, "src": "fetched_diff"}
            stats["fetched"] += 1
        else:
            stats["no_cdiff"] += 1
        print("  %-18s %s" % (cve, "OK" if cve in pairs else "skip"), flush=True)

    with open(OUT, "w", encoding="utf-8") as f:
        for r in pairs.values():
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("\nICS target universe: %d CVEs | ground-truth pairs built: %d" % (len(cves), len(pairs)))
    print("breakdown:", stats)
    print("->", OUT)


if __name__ == "__main__":
    main()
