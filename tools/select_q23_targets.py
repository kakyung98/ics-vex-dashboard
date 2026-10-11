#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Which CVEs are worth running Q2 (reachability) and Q3 (controllability) on?

Q2 and Q3 are OPTIONAL in this pipeline: they never decide a verdict, they only
grade the evidence tier behind an `affected` (see tools/vex_judge_v2). So running
them is a cost/benefit question, not a correctness one — and they are expensive,
because Joern builds a fresh CPG per snapshot.

Two filters, and the second is the point of this file:

  1. Q1 must say `present`. With no located function there is nothing to trace
     from, and `component_only` already carries its own (weaker) tier.

  2. The weakness class must be one where "can an attacker reach this, and does
     he control the values" is actually the open question. For a memory-safety
     or input-handling bug it is: the fault fires when attacker data arrives at
     the sink, so reachability and controllability are exactly the missing half
     of the argument.

     For a cryptographic or credential weakness it is not. CVE-2023-0464's
     policy-chain blowup, a broken cipher (CWE-327), a bad certificate check
     (CWE-295), weak randomness (CWE-330) — these are wrong *by construction*
     wherever they sit. Tracing a path to them neither strengthens nor weakens
     the claim, so a `reachable` verdict there would decorate the record with
     evidence that does not bear on it. Spending an hour of CPG build per
     snapshot to produce that is the wrong trade.

The split is recorded per CVE with its reason, so the exclusions are auditable
rather than silent.

Out: data/q23_targets.json  {"run": [...], "skip": [{cve, reason}], ...}
"""
import argparse
import collections
import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOC = os.path.join(BASE, "data", "source_locations.json")
NVD = os.path.join(BASE, "data", "nvd_cache.json")
REACH = os.path.join(BASE, "data", "reachability.json")
CTRL = os.path.join(BASE, "data", "controllability.json")
OUT = os.path.join(BASE, "data", "q23_targets.json")

# Weakness classes whose verdict turns on attacker data arriving at a sink.
# Reachability and controllability are the open question for exactly these.
INPUT_DRIVEN = {
    # memory safety
    "CWE-119": "buffer bounds", "CWE-120": "classic overflow",
    "CWE-121": "stack overflow", "CWE-122": "heap overflow",
    "CWE-124": "buffer underwrite", "CWE-125": "out-of-bounds read",
    "CWE-126": "buffer over-read", "CWE-127": "buffer under-read",
    "CWE-787": "out-of-bounds write", "CWE-788": "out-of-bounds access",
    "CWE-415": "double free", "CWE-416": "use after free",
    "CWE-476": "NULL dereference", "CWE-824": "uninitialized pointer",
    # arithmetic that becomes a memory fault
    "CWE-190": "integer overflow", "CWE-191": "integer underflow",
    "CWE-193": "off-by-one", "CWE-369": "divide by zero",
    "CWE-681": "numeric conversion",
    # untrusted input reaching an interpreter or a path
    "CWE-20": "improper input validation", "CWE-22": "path traversal",
    "CWE-74": "injection", "CWE-78": "OS command injection",
    "CWE-79": "cross-site scripting", "CWE-88": "argument injection",
    "CWE-89": "SQL injection", "CWE-94": "code injection",
    "CWE-116": "improper encoding", "CWE-134": "format string",
    "CWE-611": "XXE", "CWE-918": "SSRF",
    # resource exhaustion driven by attacker-sized input
    "CWE-400": "resource exhaustion", "CWE-401": "memory leak",
    "CWE-404": "improper resource shutdown", "CWE-606": "unchecked loop condition",
    "CWE-674": "uncontrolled recursion", "CWE-770": "allocation without limits",
    "CWE-835": "infinite loop",
}

# Classes that are wrong by construction wherever they sit. A path to them adds
# nothing, so the CPG build is not worth paying for.
BY_CONSTRUCTION = {
    "CWE-295": "certificate validation", "CWE-297": "host mismatch",
    "CWE-310": "cryptographic issue", "CWE-311": "missing encryption",
    "CWE-326": "weak key strength", "CWE-327": "broken algorithm",
    "CWE-328": "weak hash", "CWE-330": "insufficient randomness",
    "CWE-331": "insufficient entropy", "CWE-338": "weak PRNG",
    "CWE-347": "signature verification", "CWE-521": "weak password",
    "CWE-522": "unprotected credentials", "CWE-798": "hardcoded credentials",
}


def classify(cwes):
    """(run?, reason) for a CVE's weakness list.

    Any input-driven class is enough to run: a CVE filed under both a crypto and
    a memory class still has a memory fault to trace.
    """
    hit = [c for c in cwes if c in INPUT_DRIVEN]
    if hit:
        return True, "input-driven: %s" % ", ".join(
            "%s (%s)" % (c, INPUT_DRIVEN[c]) for c in hit)
    blocked = [c for c in cwes if c in BY_CONSTRUCTION]
    if blocked:
        return False, "wrong by construction, a path adds nothing: %s" % ", ".join(
            "%s (%s)" % (c, BY_CONSTRUCTION[c]) for c in blocked)
    if not cwes:
        # No class to reason about. Run it: Q2/Q3 can only ADD evidence behind an
        # `affected`, never remove it, so the failure mode of running is wasted
        # CPU while the failure mode of skipping is a weaker record.
        return True, "no CWE recorded; run rather than assume"
    return True, "unclassified CWE (%s); run rather than assume" % ", ".join(cwes)


def cwes_of(rec):
    w = (rec or {}).get("cwes")
    if isinstance(w, str):
        return [w]
    out = []
    for x in (w or []):
        if isinstance(x, str):
            out.append(x)
        elif isinstance(x, dict):
            v = x.get("value") or x.get("cweId") or x.get("id")
            if v:
                out.append(v)
    return [c for c in out if c.upper().startswith("CWE-")]


def select(pending_only=True):
    loc = json.load(open(LOC, encoding="utf-8"))
    nvd = json.load(open(NVD, encoding="utf-8")) if os.path.isfile(NVD) else {}
    done = set()
    if pending_only:
        for p in (REACH, CTRL):
            if os.path.isfile(p):
                done |= set(json.load(open(p, encoding="utf-8")))

    run, skip, no_func = [], [], []
    for cve in sorted(loc):
        if loc[cve].get("q1") != "present":
            no_func.append(cve)
            continue
        if pending_only and cve in done:
            continue
        ok, why = classify(cwes_of(nvd.get(cve)))
        (run if ok else skip).append({"cve": cve, "reason": why})
    return {
        "run": run, "skip": skip,
        "held_no_located_function": no_func,
        "counts": {"run": len(run), "skip": len(skip),
                   "no_located_function": len(no_func),
                   "already_analysed": len(done & set(loc)) if pending_only else 0},
        "rule": "Q2/Q3 grade the evidence tier behind `affected`; they never "
                "decide a verdict. Run them where attacker reachability and value "
                "control are the open question (memory safety, input handling, "
                "input-sized resource use), skip them where the weakness is wrong "
                "by construction (crypto, credentials, certificate validation).",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true",
                    help="ignore the existing Q2/Q3 caches and classify every "
                         "Q1=present CVE")
    ap.add_argument("--list", action="store_true", help="print the run list only")
    a = ap.parse_args()

    res = select(pending_only=not a.all)
    if a.list:
        for r in res["run"]:
            print(r["cve"])
        return

    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    c = res["counts"]
    print("=== Q2/Q3 target selection ===")
    print("  run                    : %d" % c["run"])
    print("  skip (by construction) : %d" % c["skip"])
    print("  no located function    : %d" % c["no_located_function"])
    print("  already analysed       : %d" % c["already_analysed"])
    by = collections.Counter(r["reason"].split(":")[0] for r in res["run"])
    for k, v in by.most_common():
        print("    run/%-34s %d" % (k, v))
    for r in res["skip"]:
        print("    skip %-18s %s" % (r["cve"], r["reason"][:70]))
    print("->", OUT)


if __name__ == "__main__":
    main()
