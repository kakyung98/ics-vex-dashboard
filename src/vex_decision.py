#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The VEX decision logic, in one place.

Until now the rules lived in three modules that could drift apart:
  tools/taint_reach.py      the Q3 gate and its evidence-strength guard
  src/vex_source_unavailable.py  the closed-firmware decision tree
  src/vex_batch.py          the evidence ladder over the corpus

This module is the single source of truth the console's "VEX Decision Logic"
page renders from, so the documented rule and the executed rule cannot diverge.

The governing principle is CONSERVATIVE GENERATION: a status is only ever
lowered to `not_affected` by evidence strong enough to survive being wrong.
Everything else falls to `under_investigation` - including, deliberately, every
CVE whose source we could not obtain.
"""

AFFECTED = "affected"
NOT_AFFECTED = "not_affected"
UNDER_INV = "under_investigation"

# --- how a target function was identified, and what that permits -------------
# A judgment is only as strong as the evidence that picked the function it
# judged. A model-ranked guess can keep a CVE in the affected pool; it can never
# clear one, because "the function I guessed is unreachable" says nothing about
# the CVE.
TARGET_SOURCES = {
    "patch": {
        "label": "Fix-commit hunk",
        "how": "the vulnerable function is the one the upstream fix edits",
        "may_clear": True,
        "n": 24,
    },
    "description": {
        "label": "NVD description",
        "how": "the advisory names the function, and that name is really defined "
               "in the collected snapshot",
        "may_clear": True,
        "n": 28,
    },
    "codebert": {
        "label": "CodeBERT ranking",
        "how": "a Devign-fine-tuned classifier ranks candidate functions",
        "may_clear": False,
        "n": 0,
        "note": "measured top-20 recall 0.148 against known targets - NOT ADOPTED",
    },
    "none": {
        "label": "Not identified",
        "how": "no fix commit, no description mention",
        "may_clear": False,
        "n": 45,
    },
}

# --- the four CISA justification questions -----------------------------------
QUESTIONS = [
    {"id": "Q1", "ask": "Is the vulnerable code present?",
     "clears_with": ["component_not_present", "vulnerable_code_not_present"],
     "how": "SBOM component match; fix-commit construct present in the build",
     "state": "implemented",
     "result": "the fine-tuned judge scores macro-F1 0.892 held-out but collapses "
               "to `affected` on the 34 ICS pairs (macro-F1 0.333), so no ICS "
               "statement currently rests on its output"},
    {"id": "Q2", "ask": "Is it on an executed path?",
     "clears_with": ["vulnerable_code_not_in_execute_path"],
     "how": "static call graph from all entry points (tools/callgraph_reach.py)",
     "state": "implemented",
     "result": "reachable 54, target-not-found 47, no-source 3 - unreachable 0"},
    {"id": "Q3", "ask": "Can an adversary control it?",
     "clears_with": ["vulnerable_code_cannot_be_controlled_by_adversary"],
     "how": "the same call graph walked only from tainted entries - I/O readers, "
            "public-header API, and every address-taken function "
            "(tools/taint_reach.py)",
     "state": "implemented",
     "result": "controllable 52, target-not-found 49, no-source 3 - "
               "not-controllable 0"},
    {"id": "Q4", "ask": "Is an inline mitigation already present?",
     "clears_with": ["inline_mitigations_already_exist"],
     "how": "preprocessor guards around the vulnerable function, plus the -D "
            "flags and compiled files on the real compile lines in "
            "results/verify_build_logs (tools/mitigation_scan.py)",
     "state": "implemented",
     "result": "0 clearances of 104. 48 have no usable build log, 3 logs are too "
               "partial to argue absence from, 2 targets sit under a guard whose "
               "macro the -D flags cannot resolve. Hardening flags are recorded "
               "but never clear: they turn corruption into abort(), which "
               "reduces impact, not applicability"},
]

# --- why the call graph is walked conservatively ------------------------------
SOUNDNESS = [
    ("K&R definitions",
     "tree-sitter emits ERROR nodes on old-style C and drops the definition "
     "(zlib 1.2.8's inflate.c: 89 errors, `inflate` lost). A regex scanner "
     "supplements the parse.",
     "a lost definition makes its callees look unreachable = a false clearance"),
    ("Macro-wrapped headers",
     "`ZEXTERN int ZEXPORT inflate OF((z_streamp, int));` parsed to 3 of zlib's "
     "public functions; a regex fallback recovers them.",
     "a missed public entry shrinks the attack surface = a false clearance"),
    ("Indirect calls",
     "a static graph sees only `f()`. Dispatch tables and callbacks "
     "(`sqlite3_create_function(..., rtreenode, ...)`) are invisible, so every "
     "address-taken function is treated as a root.",
     "this single fix overturned all 6 clearances the first Q3 run produced"),
    ("Partial build logs",
     "the first Q4 run counted `clang-format` and configure chatter "
     "(\"gcc accepts -g... yes\") as compile lines, so files that were built "
     "looked unbuilt. A compile line must now start with a compiler and name a "
     "source, the log must cover half the project, and a file another "
     "translation unit #includes cannot be called absent.",
     "it produced 5 false `vulnerable_code_not_present` clearances"),
    ("Graph completeness",
     "call resolution = defined callees / all callees, median 0.67. Below 0.50 "
     "the graph is too incomplete to argue from.",
     "an argument from absence needs the graph to be near-complete"),
]


def resolve(q1=None, q2=None, q3=None, q4=None, target_source="none",
            call_resolution=0.0, upstream=None, sbom_absent=False,
            source_available=True, min_resolution=0.5):
    """Final VEX status for one (product, vulnerability) statement.

    Returns (status, justification, reason). Gates are tried strongest-first;
    anything that does not clear a gate outright falls through to
    `under_investigation` rather than to `affected`, because failing to prove
    absence is not evidence of presence.
    """
    # 1. upstream assertion - the vendor already published a justification
    if upstream:
        return NOT_AFFECTED, upstream, "adopted from the published CSAF flag"

    # 2. SBOM evidence - the affected component is simply not in this asset
    if sbom_absent:
        return NOT_AFFECTED, "component_not_present", "absent from the SBOM"

    # 3. no source, no code argument. Deployment context is NOT a substitute:
    #    no CISA justification accepts it, and a verdict resting on topology
    #    turns false the moment the topology changes.
    if not source_available:
        return UNDER_INV, None, "source not obtainable; context does not set status"

    # 4. a code-level clearance requires a trustworthy target and a usable graph
    clears = {"q1": q1, "q2": q2, "q3": q3, "q4": q4}
    cleared = [k for k, v in clears.items() if v == "clear"]
    if cleared:
        src = TARGET_SOURCES.get(target_source, TARGET_SOURCES["none"])
        if not src["may_clear"]:
            return UNDER_INV, None, "target identified by %s, which may not clear" % src["label"]
        if call_resolution < min_resolution:
            return UNDER_INV, None, "call graph too incomplete (%.2f)" % call_resolution
        just = next(q["clears_with"][0] for q in QUESTIONS
                    if q["id"].lower() == cleared[0])
        return NOT_AFFECTED, just, "cleared at %s" % cleared[0].upper()

    # 5. every gate answered "still vulnerable" -> affected, but only when the
    #    chain was actually evaluated end to end
    if all(clears[k] == "pass" for k in ("q1", "q2", "q3")):
        return AFFECTED, None, "vulnerable code present, reachable and controllable"

    return UNDER_INV, None, "insufficient evidence"


CORPUS = {
    "snapshots": 104, "targets_located": 52,
    "q2_reachable": 54, "q2_unreachable": 0,
    "q3_controllable": 52, "q3_not_controllable": 0,
    "q4_mitigation_cleared": 0,
    "clearances_from_source_analysis": 0,
}
