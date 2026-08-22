#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Data Processor — faithful reimplementation of CVE-Genie paper §3.1.1.

For each tier-A CVE whose vuln/patched code pair is NOT already collected, this
does the paper's two Data-Processor jobs:

  A1 Source Code Extraction:
     component -> upstream repo + latest-affected version tag ->
     sw_version_wget (GitHub archive .zip) -> download+extract to data/source_snapshots/<CVE>/
  A2 Vulnerability Information Extraction (4 items, paper-exact):
     (1) description  (2) cwes[{id,value}]
     (3) patch_commits[{url,content}]  (multi-resolver git-diff)
     (4) sec_adv[{url,content}]        (advisory URLs filtered by keyword, scraped)

Outputs:
  cve-genie/webapp/data/icsvex_tierA.json  merged cache the cve-genie Builder reads
  data/source_snapshots/<CVE>/             extracted vulnerable source tree
  results/data_processor_report.json       per-CVE outcome + resolver provenance

vuln/patched code pair is NOT required (user decision): a downloaded source tree
alone counts as a successful collection. patch_commits/sec_adv are best-effort and,
when present, feed the KnowledgeBuilder.

Usage:
  python tools/genie_data_processor.py --dry-run        # resolve tags, HEAD archives, no download
  python tools/genie_data_processor.py --limit 5        # pilot
  python tools/genie_data_processor.py --only openssl   # one component
  python tools/genie_data_processor.py                  # all
"""
import os, sys, re, json, csv, subprocess, argparse, urllib.request, urllib.error, zipfile, tarfile, io, collections

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(BASE, "tools"))
from generate_ics_sbom import OSS
import oss_repos as R
import collect_code_evidence as C   # osv_commits(), parse_diff()

GH = r"C:\Users\user\AppData\Local\Microsoft\WinGet\Packages\GitHub.cli_Microsoft.Winget.Source_8wekyb3d8bbwe\bin\gh.exe"
SNAP = os.path.join(BASE, "data", "source_snapshots")
CACHE_DIR = os.path.join(BASE, "..", "cve-genie", "webapp", "data")
CACHE = os.path.join(CACHE_DIR, "icsvex_tierA.json")
REPORT = os.path.join(BASE, "results", "data_processor_report.json")
CE = os.path.join(BASE, "data", "code_evidence.json")
FIND = os.path.join(BASE, "data", "findings.csv")
NVD = os.path.join(BASE, "data", "nvd_cache.json")
UA = {"User-Agent": "ics-vex-research/1.0"}
ADV_KW = ("security", "advisory", "advisories", "bounty", "poc", "exploit", "ghsa", "cve", "vuln")


def gh_api(path, jq=None):
    cmd = [GH, "api", path]
    if jq:
        cmd += ["--jq", jq]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=40, encoding="utf-8")
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None


def http(url, timeout=25, raw=False, method="GET"):
    for a in range(3):
        try:
            req = urllib.request.Request(url, headers=UA, method=method)
            r = urllib.request.urlopen(req, timeout=timeout)
            if method == "HEAD":
                return r.status
            data = r.read()
            return data if raw else data.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None if method != "HEAD" else 404
            return None
        except Exception:
            pass
    return None


def vparts(v):
    return re.findall(r"\d+|[a-zA-Z]+", v)


def _fmt(t, v):
    u = v.replace(".", "_")
    maj = (re.findall(r"\d+", v) or ["0"])[0]
    return t.replace("{v}", v).replace("{u}", u).replace("{maj}", maj)


def candidate_tags(comp, v):
    spec = R.OSS_REPOS.get(comp, {})
    cands = [_fmt(t, v) for t in spec.get("tags", [])]
    # generic fallbacks
    cands += [f"v{v}", v, f"v{v.replace('.', '_')}", v.replace(".", "_")]
    if comp == "openssh":
        cands = ["V_" + v.replace(".", "_").replace("p", "_P").replace("P", "P").upper()] + cands
    # de-dup, preserve order
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c); out.append(c)
    return out


def tag_exists(gh, tag):
    return gh_api(f"repos/{gh}/git/refs/tags/{urllib.parse.quote(tag, safe='')}") is not None


def resolve_tag(comp, gh, v):
    """Return (tag, 'template'|'fuzzy') or (None,None)."""
    for t in candidate_tags(comp, v):
        if tag_exists(gh, t):
            return t, "template"
    # fuzzy: list tags, match by numeric+alpha token equality
    want = [p.lower() for p in vparts(v)]
    out = gh_api(f"repos/{gh}/tags?per_page=100", jq=".[].name")
    names = out.splitlines() if out else []
    # paginate a bit more for big repos
    for pg in (2, 3, 4):
        if len(names) < 100 * (pg - 1):
            break
        more = gh_api(f"repos/{gh}/tags?per_page=100&page={pg}", jq=".[].name")
        if not more:
            break
        names += more.splitlines()
    best = None
    for n in names:
        toks = [p.lower() for p in vparts(n)]
        # want must appear as a contiguous suffix of the tag's tokens
        if len(toks) >= len(want) and toks[-len(want):] == want:
            if best is None or len(n) < len(best):
                best = n
    return (best, "fuzzy") if best else (None, None)


import urllib.parse

# move the stray import up top usage is fine (defined before first call at runtime)

def download_extract(url, dest, is_zip, timeout=120):
    """Download archive to dest dir, extract, return top-level source dir or None."""
    data = http(url, timeout=timeout, raw=True)
    if not data or len(data) < 200:
        return None
    os.makedirs(dest, exist_ok=True)
    try:
        if is_zip:
            zf = zipfile.ZipFile(io.BytesIO(data))
            zf.extractall(dest)
        else:
            tf = tarfile.open(fileobj=io.BytesIO(data))
            tf.extractall(dest)
    except Exception:
        return None
    tops = [d for d in os.listdir(dest) if os.path.isdir(os.path.join(dest, d))]
    return os.path.join(dest, tops[0]) if tops else dest


def find_patch_commits(cve, nvd):
    """Multi-resolver git-diff of the fix commit(s). Returns (list[{url,content}], resolver)."""
    refs = (nvd.get(cve) or {}).get("references", [])
    pairs = []   # (owner_repo, sha)
    resolver = None
    # 1) OSV FIX refs (reuse)
    for u in (C.osv_commits(cve) or []):
        m = re.search(r"github.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})", u)
        if m:
            pairs.append((m.group(1), m.group(2))); resolver = resolver or "osv-fix-ref"
    # 2) NVD github commit refs
    for u in refs:
        m = re.search(r"github.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})", u)
        if m:
            pairs.append((m.group(1), m.group(2))); resolver = resolver or "nvd-commit-ref"
    # 3) OSV git-range fixed SHA
    d = C.get("https://api.osv.dev/v1/vulns/" + cve) if hasattr(C, "get") else None
    if d:
        for aff in d.get("affected", []):
            repo = (aff.get("package", {}) or {}).get("name", "")
            gm = re.search(r"github.com/([^/]+/[^/]+)", repo)
            for rg in aff.get("ranges", []):
                if rg.get("type") == "GIT":
                    base = re.search(r"github.com/([^/]+/[^/]+)", rg.get("repo", "") or repo)
                    for ev in rg.get("events", []):
                        if ev.get("fixed") and base:
                            pairs.append((base.group(1).replace(".git", ""), ev["fixed"]))
                            resolver = resolver or "osv-git-range"
    # 4) GHSA advisory refs
    if not pairs:
        out = gh_api(f"advisories?cve_id={cve}", jq=".[0].references[]?")
        for u in (out or "").splitlines():
            m = re.search(r"github.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})", u)
            if m:
                pairs.append((m.group(1), m.group(2))); resolver = resolver or "ghsa"
    # 5) commit search by CVE id within the mapped repo
    # (added by caller which knows gh repo)
    # de-dup
    seen, uniq = set(), []
    for owner_repo, sha in pairs:
        k = (owner_repo, sha[:12])
        if k not in seen:
            seen.add(k); uniq.append((owner_repo, sha))
    commits = []
    for owner_repo, sha in uniq[:4]:
        j = gh_api(f"repos/{owner_repo}/commits/{sha}")
        if not j:
            continue
        try:
            cd = json.loads(j)
        except Exception:
            continue
        patch_txt = []
        for f in cd.get("files", []):
            if f.get("patch"):
                patch_txt.append(f"Filename: {f.get('filename')}:\n```\n{f['patch']}\n```")
        if patch_txt:
            commits.append({"url": f"https://github.com/{owner_repo}/commit/{sha}",
                            "content": "\n\n".join(patch_txt)[:6000]})
    return commits, resolver


def commit_search(cve, gh):
    out = gh_api(f"search/commits?q={urllib.parse.quote(cve + ' repo:' + gh)}", jq=".items[0].sha?")
    sha = (out or "").strip()
    if not sha:
        return [], None
    j = gh_api(f"repos/{gh}/commits/{sha}")
    if not j:
        return [], None
    cd = json.loads(j)
    patch_txt = [f"Filename: {f.get('filename')}:\n```\n{f['patch']}\n```"
                 for f in cd.get("files", []) if f.get("patch")]
    if not patch_txt:
        return [], None
    return [{"url": f"https://github.com/{gh}/commit/{sha}",
             "content": "\n\n".join(patch_txt)[:6000]}], "commit-search"


def scrape_advisories(cve, nvd, limit=3):
    refs = (nvd.get(cve) or {}).get("references", [])
    picked = [u for u in refs if any(k in u.lower() for k in ADV_KW)]
    out = []
    for u in picked[:limit]:
        body = http(u, timeout=20)
        if not body:
            continue
        txt = re.sub(r"<script.*?</script>", " ", body, flags=re.S | re.I)
        txt = re.sub(r"<style.*?</style>", " ", txt, flags=re.S | re.I)
        txt = re.sub(r"<[^>]+>", " ", txt)
        txt = re.sub(r"\s+", " ", txt).strip()
        if len(txt) > 200:
            out.append({"url": u, "content": txt[:4000]})
    return out

def load_targets():
    """The tier-A CVEs missing a code pair, with component + latest affected version."""
    ce = json.load(open(CE, encoding="utf-8")) if os.path.exists(CE) else {}
    have = {k for k, v in ce.items() if isinstance(v, dict) and v.get("vuln_code")}
    rows = list(csv.DictReader(open(FIND, encoding="utf-8-sig")))
    tierA = {r["cve"] for r in rows if r["tier"] == "A"}
    cwe_of = {}
    for r in rows:
        if r["cve"] not in cwe_of and r.get("cwe"):
            cwe_of[r["cve"]] = r["cwe"]
    miss = tierA - have
    cve_cv = collections.defaultdict(lambda: collections.defaultdict(list))
    for comp, spec in OSS.items():
        for ver, cl in spec["versions"]:
            for c in cl:
                if c in miss:
                    cve_cv[c][comp].append(ver)
    tgts = {}
    for c, comps in cve_cv.items():
        comp = sorted(comps)[0]
        vers = sorted(comps[comp], key=lambda v: [int(x) for x in re.findall(r"\d+", v)])
        tgts[c] = {"component": comp, "version": vers[-1], "cwe": cwe_of.get(c, "")}
    return tgts


def cwe_value(cwe_id):
    try:
        import build_ground_truth as G
        nm = G.CWE_NAME.get(cwe_id, "")
        return f"{cwe_id} {nm}".strip()
    except Exception:
        return cwe_id


def process_one(cve, meta, nvd, dry=False):
    comp, ver = meta["component"], meta["version"]
    spec = R.OSS_REPOS.get(comp, {})
    rec = {"cve": cve, "component": comp, "version": ver, "status": "", "reason": ""}
    if spec.get("closed"):
        rec["status"] = "closed-source"; rec["reason"] = "no public source"
        return rec, None
    gh = spec.get("gh")
    tag, how = (None, None)
    sw_url, is_zip = None, True
    # huge repos (e.g. linux): the GitHub archive endpoint is ~200MB and flaky;
    # prefer the canonical release tarball, but still resolve the tag for provenance.
    if gh and spec.get("huge") and spec.get("tarball"):
        tag, how = resolve_tag(comp, gh, ver)
        sw_url = _fmt(spec["tarball"], ver); is_zip = sw_url.endswith(".zip")
        how = "tarball-huge"
    if not sw_url and gh:
        tag, how = resolve_tag(comp, gh, ver)
        if tag:
            sw_url = f"https://github.com/{gh}/archive/refs/tags/{tag}.zip"
    if not sw_url and spec.get("tarball"):
        sw_url = _fmt(spec["tarball"], ver); is_zip = sw_url.endswith((".zip",))
        how = how or "tarball"
    if not sw_url:
        rec["status"] = "no-tag"; rec["reason"] = f"could not resolve tag for {comp} {ver}"
        return rec, None
    rec.update({"tag": tag, "tag_resolver": how, "sw_version_wget": sw_url, "is_zip": is_zip})

    # description + cwe
    desc = (nvd.get(cve) or {}).get("description", "") or f"{comp} {ver} — {cve}"
    cwe_id = meta["cwe"]
    cwes = [{"id": cwe_id, "value": cwe_value(cwe_id)}] if cwe_id else []

    if dry:
        st = http(sw_url, method="HEAD", timeout=25)
        rec["archive_head"] = st
        rec["status"] = "ok" if st in (200, 302, None) else f"archive-{st}"
        return rec, None

    # download + extract
    dest = os.path.join(SNAP, cve)
    subprocess.run(["rm", "-rf", dest], capture_output=True)
    srcdir = download_extract(sw_url, dest, is_zip, timeout=(600 if spec.get('huge') else 180))
    if not srcdir:
        rec["status"] = "fetch-failed"; rec["reason"] = f"could not download/extract {sw_url}"
        return rec, None
    rec["source_dir"] = os.path.relpath(srcdir, BASE)

    # patch commits (best-effort)
    commits, presolver = find_patch_commits(cve, nvd)
    if not commits and gh:
        commits, presolver = commit_search(cve, gh)
    rec["patch_resolver"] = presolver
    rec["n_patch_commits"] = len(commits)
    # advisories (best-effort)
    sec = scrape_advisories(cve, nvd)
    rec["n_sec_adv"] = len(sec)
    rec["status"] = "collected"

    entry = {"description": desc, "cwes": cwes, "sw_version": tag or ver,
             "sw_version_wget": sw_url, "patch_commits": commits, "sec_adv": sec}
    return rec, (entry if is_zip else None)   # cve-genie cache needs a .zip


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--only", default=None, help="restrict to one component key")
    ap.add_argument("--cve", default=None, help="one CVE id")
    a = ap.parse_args()

    nvd = json.load(open(NVD, encoding="utf-8")) if os.path.exists(NVD) else {}
    tgts = load_targets()
    items = sorted(tgts.items())
    if a.only:
        items = [(c, m) for c, m in items if m["component"] == a.only]
    if a.cve:
        items = [(c, m) for c, m in items if c == a.cve]
    if a.limit:
        items = items[:a.limit]

    os.makedirs(SNAP, exist_ok=True)
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    cache = {}
    if os.path.exists(CACHE):
        try:
            cache = json.load(open(CACHE, encoding="utf-8"))
        except Exception:
            cache = {}

    report = []
    by_status = collections.Counter()
    by_resolver = collections.Counter()
    for i, (cve, meta) in enumerate(items, 1):
        rec, entry = process_one(cve, meta, nvd, dry=a.dry_run)
        report.append(rec)
        by_status[rec["status"]] += 1
        if rec.get("tag_resolver"):
            by_resolver[rec["tag_resolver"]] += 1
        if entry and not a.dry_run:
            cache[cve] = entry
            os.makedirs(CACHE_DIR, exist_ok=True)
            json.dump(cache, open(CACHE, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print(f"[{i}/{len(items)}] {cve:18s} {meta['component']:14s} {meta['version']:10s} "
              f"-> {rec['status']} ({rec.get('tag') or rec.get('reason','')})", flush=True)

    summary = {"n": len(items), "by_status": dict(by_status),
               "by_tag_resolver": dict(by_resolver),
               "cache_entries": len(cache), "dry_run": a.dry_run,
               "records": report}
    json.dump(summary, open(REPORT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("\n== DATA PROCESSOR ==")
    print("status  :", dict(by_status))
    print("tag res :", dict(by_resolver))
    print("cache   :", len(cache), "->", os.path.relpath(CACHE, BASE) if os.path.exists(CACHE) else CACHE)
    print("report  :", os.path.relpath(REPORT, BASE))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
