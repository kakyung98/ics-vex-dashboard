#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Find fix commits by searching a project's own git history, locally.

GitHub commit search found fixes for 11 of 37 CVEs, but it misses a lot: the
index skips mirrors and non-default branches, and most projects cite a bug or
ticket number rather than the CVE ID in the fixing commit (a CVE-ID-only pilot
over busybox/sqlite/openssh/dnsmasq found 1 of 15). Each project's repository is
therefore cloned blobless (history only, contents fetched on demand) and searched
with keys taken from the CVE's own references, all URL-decoded first - dnsmasq's
NVD link carries `a=commit%3Bh=<sha>`, which an undecoded match missed:

  commit   a commit id written in a reference URL (gitweb h=, cgit id=,
           /commit/<sha>) - resolved directly in the local mirror
  fossil   sqlite check-ins (/src/info/<h>, vdiff ...&to=<h>, with or without
           cgi/) - sqlite's GitHub mirror carries `FossilOrigin-Name: <hash>` on
           every commit, which maps a Fossil check-in to its git commit
  ticket   sqlite tickets (tktview?name=<id>) - cited as [<id>] in messages
  bug      UPSTREAM trackers only: glibc's sourceware bugzilla ("BZ #NNNN"),
           bugs.busybox.net, the project's own GitLab/GitHub issues ("#NNN"),
           OSS-Fuzz. Distribution bugzillas (Red Hat, SUSE, Launchpad) are never
           cited upstream and only produced false keys
  jira     Apache JIRA keys (LOG4J2-3201), only from issues.apache.org links -
           a looser pattern harvested USN-/RHSA-/DSA- advisory ids
  cve      the CVE ID itself

Every hit is written as a git-format patch to data/patches/<CVE>/<sha>.diff, the
cache tools/extract_vuln_funcs.py reads, so it faces the same checks as any fix
commit: release commits yield, the diff's files must agree with the snapshot by
identifier content, header hunk context does not vote. A found commit is a
candidate, not a verdict.

Output: data/git_grep_hits.json {CVE: [{"sha", "subject", "key", "repo"}]}
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.parse

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIRRORS = os.environ.get("GIT_MIRRORS", r"C:\Users\user\Desktop\gitmirrors")
REFS = os.path.join(BASE, "data", "nvd_refs_full.json")
PATCHD = os.path.join(BASE, "data", "patches")
OUT = os.path.join(BASE, "data", "git_grep_hits.json")

# component (tier-A) -> local mirror directory name
REPO_OF = {"busybox": "busybox", "sqlite": "sqlite", "openssh": "openssh",
           "dnsmasq": "dnsmasq", "wpa-supplicant": "hostap", "libxml2": "libxml2",
           "u-boot": "u-boot", "glibc": "glibc", "log4j": "log4j", "spring": "spring",
           "zlib": "zlib", "nginx": "nginx", "libcurl": "curl", "openssl": "openssl",
           "linux-kernel": "linux", "dropbear": "dropbear"}
MAX_HITS = 6

# Fix commits no reference key reaches, each taken from a primary source named
# beside it and checked by reading the commit. Keys search what a CVE's references
# say; these CVEs' references say nothing a commit carries.
#   repo, commit, evidence
ADVISORY_FIX = {
    # the snapshot is dropbear, not OpenSSH: the fix must be dropbear's own
    "CVE-2023-48795": [("dropbear", "6e43be5c7b99dbee49dc72b6f989f29fdd7e9356",
                        "dropbear CHANGES 2024.84: strict KEX (Terrapin)")],
    "CVE-2020-10648": [("u-boot", "67acad3db71bb372458fbb8a77749f5eb88aa324",
                        "message: another configuration's signature bypasses the check")],
    "CVE-2021-42376": [("busybox", "1b7a9b68d0e9aa19147d7fda16eb9a6b54156985",
                        "NVD: hush NULL deref after a \\x03 (^C) delimiter")],
    # Inferred, not stated: Claroty names the characters ($ { } #), VSLENGTH is
    # ash's ${#var} parse, and it is the only ash parser fix in 1_34_0 (the
    # fixed release) and not in 1_33_1
    "CVE-2021-42375": [("busybox", "53a7a9cd8c15d64fcc2278cf8981ba526dfbe0d2",
                        "INFERRED: Claroty trigger chars $ { } # = ${#var} (VSLENGTH) parse")],
    # A Spring Security CVE whose snapshot held only spring-framework 6.0.9; the
    # spring-security 6.1.0 tree beside it is the release Spring Boot 3.1.0
    # pairs with that framework. Fixed in 6.1.2 by this commit (gh-13551), which
    # changes the requestMatchers(String) registry the advisory is about.
    "CVE-2023-34035": [("spring-security", "df239b6448ccf138b0c95b5575a88f33ac35cd9a",
                        "6.1.2 fix gh-13551: AbstractRequestMatcherRegistry.requestMatchers")],
    "CVE-2022-22965": [("spring","002546b3e4b8d791ea6acccb81eb3168f51abb15",
                        "Spring4Shell fix in 5.3.18: CachedIntrospectionResults")],
}

# A commit id in a reference URL. `id=` is only a commit on a cgit commit page:
# a generic `[?&]id=` read Red Hat bugzilla's show_bug.cgi?id=1924886 as a
# commit prefix, and a purely numeric string is valid hex, so it could have
# resolved to whichever commit happened to start with those digits. Kernel
# links (git.kernel.org/linus/<sha>, .../c/<sha>) are the other common form.
_COMMIT_URL = re.compile(
    r"(?:[;?&]h=|/commit/?\?id=|/commit/|/-/commit/|git\.kernel\.org/linus/"
    r"|git\.kernel\.org/[^\s]*?/c/)([0-9a-f]{7,40})\b")
_FOSSIL = re.compile(r"sqlite\.org/(?:cgi/)?src/(?:info/|vdiff\?\S*?\bto=|timeline\?c=)"
                     r"([0-9a-f]{10,64})")
_TICKET = re.compile(r"sqlite\.org/(?:cgi/)?src/tktview\?name=([0-9a-f]{8,40})")
_JIRA = re.compile(r"issues\.apache\.org/jira/browse/([A-Z][A-Z0-9]+-\d+)")
_UPSTREAM_BUG = [
    (re.compile(r"sourceware\.org/bugzilla/show_bug\.cgi\?id=(\d+)"),
     r"BZ ?#?%s\b"),                                 # glibc: "[BZ #27705]"
    (re.compile(r"bugs\.busybox\.net/show_bug\.cgi\?id=(\d+)"),
     r"(bug|Bug|#) ?%s\b"),
    # GitLab/GitHub issue numbers are handled in keys_for(): they are only
    # meaningful in the repository the issue belongs to
    (re.compile(r"bugs\.chromium\.org/p/oss-fuzz/issues/detail\?id=(\d+)"),
     r"(oss-fuzz|OSS-Fuzz|ossfuzz|clusterfuzz)[^\n]{0,40}%s\b"),
]


# repository names a project's issues live under, per local mirror
REPO_NAMES = {"openssh": {"openssh-portable", "openssh"}, "log4j": {"logging-log4j2"},
              "spring": {"spring-framework", "spring-security"}, "curl": {"curl"},
              "libxml2": {"libxml2"}, "u-boot": {"u-boot"}, "zlib": {"zlib"},
              "nginx": {"nginx"}, "openssl": {"openssl"}, "sqlite": {"sqlite"},
              "busybox": {"busybox"}, "glibc": {"glibc"}, "dnsmasq": {"dnsmasq"},
              "hostap": {"hostap"}, "linux": {"linux"}}
_ISSUE = re.compile(r"(?:github\.com|gitlab\.[^/]+)/(?:[^\s?#]+/)?([^/\s?#]+)/(?:-/)?issues/(\d+)")


def keys_for(cve, refs, project=None):
    """(kind, value) pairs for one CVE, strongest first."""
    ks = []
    for r in refs:
        u = urllib.parse.unquote(r.get("url") or "")
        # An issue number means nothing outside its own repository: NVD cited
        # other projects' GitHub issues for Terrapin, and "#445" then matched an
        # unrelated OpenSSH "Bug #445" commit.
        m = _ISSUE.search(u)
        if m and project and m.group(1).lower() in REPO_NAMES.get(project, {project}):
            ks.append(("bug", r"(#|issue ?|Fixes ?#?)%s\b" % m.group(2)))
        for m in _COMMIT_URL.finditer(u):
            if re.search(r"[a-f]", m.group(1)):     # all-digit ids are bug numbers
                ks.append(("commit", m.group(1)))
        m = _FOSSIL.search(u)
        if m:
            ks.append(("fossil", "FossilOrigin-Name: " + m.group(1)))
        m = _TICKET.search(u)
        if m:
            ks.append(("ticket", m.group(1)))
        m = _JIRA.search(u)
        if m:
            ks.append(("jira", re.escape(m.group(1))))
        for pat, tmpl in _UPSTREAM_BUG:
            m = pat.search(u)
            if m:
                ks.append(("bug", tmpl % m.group(1)))
    ks.append(("cve", re.escape(cve)))
    seen, out = set(), []
    for k in ks:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def git(repo, *args):
    p = subprocess.run(["git", "-C", repo] + list(args), capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    return p.stdout.strip() if p.returncode == 0 else ""


def resolve_commit(repo, sha):
    """Full sha and subject if this id is a commit in the local mirror."""
    full = git(repo, "rev-parse", "--verify", "--quiet", sha + "^{commit}")
    if not full:
        return None
    return full, git(repo, "log", "-1", "--format=%s", full)


def search(repo, pattern):
    out = git(repo, "log", "--all", "-E", "-i", "--grep=" + pattern, "--format=%H%x09%s")
    return [tuple(l.split("\t", 1)) for l in out.splitlines() if "\t" in l]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="comma-separated components to run")
    a = ap.parse_args()
    only = {x.strip() for x in a.only.split(",") if x.strip()}

    refs = json.load(open(REFS, encoding="utf-8")) if os.path.exists(REFS) else {}
    # The Debian security tracker records upstream fix commits as NOTE lines for
    # CVEs whose NVD entry cites none (busybox, openssh, the kernel ...); its
    # references go through exactly the same key extraction.
    deb = os.path.join(BASE, "data", "debian_refs.json")
    if os.path.exists(deb):
        for c, lst in json.load(open(deb, encoding="utf-8")).items():
            refs.setdefault(c, [])
            refs[c] = refs[c] + lst
    todo = json.load(open(os.path.join(BASE, "results", "_remaining36.json"), encoding="utf-8"))
    res = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}

    for item in todo:
        cve, comp = item["cve"], item["component"]
        if only and comp not in only:
            continue
        repo = os.path.join(MIRRORS, REPO_OF.get(comp, comp))
        if not os.path.isdir(repo) and cve not in ADVISORY_FIX:
            print("%-16s %-14s -- no local mirror" % (cve, comp))
            continue
        found = []
        for kind, val in (keys_for(cve, refs.get(cve) or [], REPO_OF.get(comp, comp))
                          if os.path.isdir(repo) else []):
            if kind == "commit":
                hit = resolve_commit(repo, val)
                hits = [hit] if hit else []
            else:
                hits = search(repo, val)[:MAX_HITS]
            for sha, subj in hits:
                if sha not in {f["sha"] for f in found}:
                    found.append({"sha": sha, "subject": subj[:120], "key": kind,
                                  "repo": REPO_OF.get(comp, comp)})
        for rname, sha, why in ADVISORY_FIX.get(cve, ()):
            hit = resolve_commit(os.path.join(MIRRORS, rname), sha)
            if hit and hit[0] not in {f["sha"] for f in found}:
                found.insert(0, {"sha": hit[0], "subject": hit[1][:120],
                                 "key": "advisory", "repo": rname, "evidence": why})
        res[cve] = found
        d = os.path.join(PATCHD, cve)
        for f in found[:MAX_HITS]:
            dst = os.path.join(d, f["sha"] + ".diff")
            if os.path.exists(dst):
                continue
            # A merge's plain `git show` is a combined diff of conflicts only -
            # sqlite's CVE-2018-8740 fix merged a branch and showed just the
            # manifest. Against the first parent it is the whole change.
            patch = git(os.path.join(MIRRORS, f["repo"]), "show",
                        "--diff-merges=first-parent", "--format=email", f["sha"])
            if "@@ -" not in patch:
                continue
            os.makedirs(d, exist_ok=True)
            open(dst, "w", encoding="utf-8", newline="\n").write(patch + "\n")
        print("%-16s %-14s %d hit(s) %s" % (cve, comp, len(found),
              "; ".join("%s:%s" % (f["key"], f["subject"][:48]) for f in found[:3])),
              flush=True)
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("->", OUT)


if __name__ == "__main__":
    sys.exit(main())
