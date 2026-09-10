#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Locate each CVE's vulnerable function WITHOUT depending on a fix commit.

Three paths, strongest first. The path that produced a target is recorded,
because it bounds what the downstream Q2/Q3 verdict may claim:

  A patch        diff hunk -> enclosing function            (data/vuln_funcs.json)
  B description  NVD text names the function, and that name
                 is really defined in the snapshot          (this file)
  C codebert     fine-tuned CodeBERT ranks candidate
                 functions by vulnerability score           (rank_codebert.py)

A and B may set `not_affected`; C may not — a guessed target that is unreachable
says nothing about the CVE. See README "The evidence ladder".

Output: data/vuln_targets.json
  {CVE: {"targets": [...], "source": "patch|description", "evidence": "..."}}
"""
import json
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDX = os.path.join(BASE, "data", "func_index")
NVD = os.path.join(BASE, "data", "nvd_cache.json")
PATCH = os.path.join(BASE, "data", "vuln_funcs.json")
OUT = os.path.join(BASE, "data", "vuln_targets.json")

_TOK = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
_FILE = re.compile(r"[\w./-]+\.(?:c|h|cc|cpp|cxx)\b")


# A name can be defined in the snapshot and still be a useless target. Two kinds
# showed up and reached the Q2/Q3/Q4 stages before being caught:
#   ZLIB_INTERNAL  an export macro the parser read as a function name
#   memset         libc, which the NVD text mentions as the *called* primitive
#                  ("can memset() too much data"), not the vulnerable function
_LIBC = {
    "memcpy", "memmove", "memset", "memcmp", "strcpy", "strncpy", "strcat",
    "strncat", "strcmp", "strlen", "strdup", "sprintf", "snprintf", "vsnprintf",
    "printf", "fprintf", "malloc", "calloc", "realloc", "free", "alloca",
    "atoi", "atol", "strtol", "abort", "exit", "assert", "qsort", "bsearch",
    "open", "close", "read", "write", "fopen", "fclose", "fread", "fwrite",
}


def usable_target(name):
    """Reject export macros and libc primitives as vulnerable-function targets."""
    if name in _LIBC:
        return False
    if name.isupper() or (name.replace("_", "").isupper() and len(name) > 3):
        return False
    return True


def code_context(desc, tok):
    """Is this token used as code in the prose, not as an English word?

    Two independent signals, either is enough:
      shape  - an identifier no English sentence would produce (_ or CamelCase)
      prose  - written as a call, or explicitly called a function/routine/method
    """
    if "_" in tok or not tok.islower():
        return "shape"
    t = re.escape(tok)
    if re.search(r"\b%s\s*\(" % t, desc):
        return "call"
    if re.search(r"\b(?:the\s+)?%s\s+(?:function|routine|method|handler)\b" % t, desc):
        return "named"
    if re.search(r"\b(?:function|routine|method)\s+%s\b" % t, desc):
        return "named"
    return None


def from_description(desc, index):
    """Function names the NVD text points at that really exist in this snapshot."""
    hits = {}
    for tok in set(_TOK.findall(desc or "")):
        if tok not in index or not usable_target(tok):
            continue
        why = code_context(desc, tok)
        if why:
            hits[tok] = why
    return hits


def files_in_description(desc, index):
    """Source files the NVD text names, mapped to files present in the snapshot."""
    want = set()
    for m in _FILE.findall(desc or ""):
        want.add(m.replace("\\", "/").lower())
    if not want:
        return []
    present = set()
    for locs in index.values():
        for f, _s, _e in locs:
            fl = f.lower()
            if any(fl == w or fl.endswith("/" + w.lstrip("./")) for w in want):
                present.add(f)
    return sorted(present)


def main():
    nvd = json.load(open(NVD, encoding="utf-8")) if os.path.exists(NVD) else {}
    patch = json.load(open(PATCH, encoding="utf-8")) if os.path.exists(PATCH) else {}
    out = {}
    agree = disagree = 0
    for fn in sorted(os.listdir(IDX)):
        cve = fn[:-5]
        index = json.load(open(os.path.join(IDX, fn), encoding="utf-8"))["functions"]
        desc = (nvd.get(cve) or {}).get("description", "")
        hits = from_description(desc, index)
        files = files_in_description(desc, index)

        if cve in patch:                       # path A wins; B is scored against it
            keep = [t for t in patch[cve] if usable_target(t)]
            if keep:
                out[cve] = {"targets": keep, "source": "patch",
                            "evidence": "fix-commit hunk"}
            if hits:
                if set(hits) & set(patch[cve]):
                    agree += 1
                else:
                    disagree += 1
                    print("  B!=A %-18s A=%s B=%s" % (cve, patch[cve][:3], sorted(hits)))
        elif hits:
            out[cve] = {"targets": sorted(hits), "source": "description",
                        "evidence": "NVD text (%s) + defined in snapshot"
                                    % ",".join(sorted(set(hits.values())))}
        elif files:
            out[cve] = {"targets": [], "source": "description-file",
                        "files": files[:20],
                        "evidence": "NVD text names a file, not a function"}

    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    n = lambda s: sum(1 for v in out.values() if v["source"] == s)  # noqa: E731
    tot = len(os.listdir(IDX))
    print("\n== targets located: %d / %d snapshots ==" % (
        sum(1 for v in out.values() if v["targets"]), tot))
    print("   A patch             %d" % n("patch"))
    print("   B description       %d" % n("description"))
    print("   file only (no func) %d" % n("description-file"))
    print("   none                %d" % (tot - len(out)))
    if agree + disagree:
        print("\n   B checked against A on %d CVEs: agree %d, disagree %d (precision %.2f)"
              % (agree + disagree, agree, disagree, agree / (agree + disagree)))
    print("->", OUT)


if __name__ == "__main__":
    main()
