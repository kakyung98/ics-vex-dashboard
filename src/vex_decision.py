#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The VEX decision logic, in one place.

The source-level Q1-Q3 gates are now the VEX-v2 engines (tools/source_locate.py,
joern_reachability.py, z3_controllability.py, orchestrated by vex_judge_v2.py). The
other rule surfaces this module keeps aligned with:
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
        "how": "the vulnerable function is the one the upstream fix edits - the fix "
               "commit comes from NVD references, the project's own advisory data, "
               "or a commit whose message names the CVE",
        "may_clear": True,
        "n": 75,
    },
    "patch-partial": {
        "label": "Fix-commit hunk, partial snapshot",
        "how": "as above, but only the files the fix touches were collected (at the "
               "fix's parent commit) - the function is located from real code, yet "
               "no whole-program question can run on one file",
        "may_clear": False,
        "n": 2,
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
        "n": 1,
    },
}

# --- the code-level CISA justification questions -----------------------------
QUESTIONS = [
    {"id": "Q1", "ask": "Is the vulnerable code present?",
     "clears_with": ["component_not_present", "vulnerable_code_not_present"],
     "how": "the CTI-located vulnerable function is defined in the collected source "
            "(tools/source_locate.py; CTI function names, else the patch-localised "
            "targets, checked against the snapshot function index)",
     "state": "implemented",
     "result": "over the 104 source-collectable CVEs: present 92, component-only 12 "
               "(the function could not be located)"},
    {"id": "Q2", "ask": "Is it on an executed path?",
     "clears_with": ["vulnerable_code_not_in_execute_path"],
     "how": "Joern CPG call-graph reachability from entry points "
            "(tools/joern_reachability.py, call-graph-only - no dataflow)",
     "state": "implemented",
     "result": "over the 104 source-collectable CVEs: reachable 65, not-reachable 1, "
               "unknown 38 (16 oversized snapshots skipped, 12 with no located function)"},
    {"id": "Q3", "ask": "Can an adversary control it?",
     "clears_with": ["vulnerable_code_cannot_be_controlled_by_adversary"],
     "how": "Z3 decides whether attacker-controlled inputs satisfy the trigger, from "
            "an LLM formalisation of the CTI (tools/z3_controllability.py)",
     "state": "implemented",
     "result": "controllable 56, not-controllable 3, unknown 45 (trigger not "
               "formalisable to SMT); the model formalises, the solver decides"},
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
    ("Entry-model completeness",
     "Q3 seeds its walk from I/O readers, the public API and address-taken "
     "functions. When neither of the last two is found - Java, where requests "
     "arrive through reflection and framework dispatch - a missing tainted path "
     "is not evidence.",
     "Spring4Shell (CVE-2022-22965) was cleared as not-controllable by exactly this gap"),
    ("Graph completeness",
     "call resolution = defined callees / all callees, median 0.67. Below 0.50 "
     "the graph is too incomplete to argue from.",
     "an argument from absence needs the graph to be near-complete"),
]


# --- triage inside under_investigation ---------------------------------------
# When the source cannot be obtained the VEX status is `under_investigation`,
# full stop - that never changes, and no amount of advisory text may move it.
# But holding 11,232 statements in one undifferentiated bucket is useless to an
# asset owner, so they carry a SEPARATE likelihood label derived from the CSAF
# remediation categories.
#
# This label is NOT a VEX status. OpenVEX and CSAF admit only four statuses, and
# `likely_*` is none of them; it is exported as its own field so that nothing
# downstream can mistake a triage hint for a judgment.
# NAMING: the legacy pipeline stores the VEX status `affected` as the literal
# string "LIKELY_AFFECTED" (src/api_server.py:93) and renders it back to
# "Affected" in the UI. These triage values would then differ from a real status
# only by case, so they are prefixed - a status and a triage hint must never be
# one typo apart.
LIKELY_AFFECTED = "triage_likely_affected"
LIKELY_NOT_AFFECTED = "triage_likely_not_affected"
LIKELIHOOD_UNKNOWN = "triage_unknown"

# An operator-side mitigation reduces exploitability where it is applied, so a
# statement carrying one is the weaker candidate for attention.
_MITIGATING = {"mitigation", "workaround"}
# A fix that exists but is not yet applied protects nothing, and "no fix
# planned" protects nothing ever - both leave the exposure standing.
_UNSHIELDED = {"vendor_fix", "none_available", "no_fix_planned"}


def triage(remediation_categories):
    """(likelihood, reason) for a statement held at under_investigation.

    Judged on whether a MITIGATION exists, not whether a fix exists: a mitigation
    blunts the vulnerability where deployed, whereas an unapplied vendor patch
    leaves the product exactly as vulnerable as before.
    """
    cats = set(remediation_categories or ())
    if not cats:
        return LIKELIHOOD_UNKNOWN, "no remediation recorded in any advisory"
    if cats & _MITIGATING:
        return LIKELY_NOT_AFFECTED, ("advisory publishes a mitigation (%s); "
                                     "applied, it blunts exploitation"
                                     % ",".join(sorted(cats & _MITIGATING)))
    if cats & _UNSHIELDED:
        return LIKELY_AFFECTED, ("only %s - nothing shields the product until the "
                                 "fix is applied"
                                 % ",".join(sorted(cats & _UNSHIELDED)))
    return LIKELIHOOD_UNKNOWN, "remediation categories not recognised"


def resolve(q1=None, q2=None, q3=None, target_source="none",
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
        # Held here unconditionally. `triage()` may attach a likelihood label to
        # this statement, but it is a separate field and never a status.
        return UNDER_INV, None, "source not obtainable; context does not set status"

    # 4. a code-level clearance requires a trustworthy target and a usable graph
    clears = {"q1": q1, "q2": q2, "q3": q3}
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


# The execution-verification campaign attempted 106 CVEs; 2 of them
# (CVE-2021-33909, CVE-2023-32233) died in the CVE-processor step before any
# source was downloaded, so 104 snapshots exist and 104 is the population every
# code-level number below is measured over.
CORPUS = {
    "snapshots": 104, "targets_located": 105,
    "q2_reachable": 100, "q2_unreachable": 0,
    "q3_controllable": 99, "q3_not_controllable": 1,
    "clearances_from_source_analysis": 0,
}
