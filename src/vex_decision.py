#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The VEX decision logic, in one place.

The source-level Q2-Q4 gates are now the VEX-v2 engines (tools/source_locate.py,
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
import collections
import json
import os


def _corpus():
    """The code-level counts, READ FROM THE CACHES rather than written down.

    These were hard-coded at 104 snapshots / Q3 100 / Q4 99 from the old
    execution-verification campaign, and stayed on the published page after the
    population grew to the full collected-source corpus - the site was quoting a
    superseded run. Deriving them means the page cannot drift from the caches
    again; a missing cache yields 0 and shows as such instead of as a stale number
    that still looks plausible.
    """
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _load(rel, default):
        p = os.path.join(base, rel)
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default

    snapdir = os.path.join(base, "data", "source_snapshots")
    loc = _load("data/source_locations.json", {})
    reach = _load("data/reachability.json", {})
    ctrl = _load("data/controllability.json", {})
    v2 = _load("data/vex_v2.json", {})

    c2 = collections.Counter((x or {}).get("verdict") for x in reach.values())
    c3 = collections.Counter((x or {}).get("verdict") for x in ctrl.values())
    rows = v2 if isinstance(v2, list) else list(v2.values())
    # vex_v2 records carry the verdict in `final_vex` (not `vex`); reading the wrong
    # key silently returned 0 clearances regardless of the data.
    cleared = sum(1 for r in rows if isinstance(r, dict)
                  and r.get("final_vex") == "not_affected"
                  and (r.get("justification") or "").startswith(
                      ("vulnerable_code_not_in_execute_path",
                       "vulnerable_code_cannot_be_controlled")))
    q1_fixed = sum(1 for r in rows if isinstance(r, dict)
                   and r.get("final_vex") == "fixed")
    _present = sum(1 for v in loc.values() if (v or {}).get("any_function_found"))
    return {
        "snapshots": len(os.listdir(snapdir)) if os.path.isdir(snapdir) else 0,
        "targets_located": _present,
        # Q2 split, read from the cache so the page cannot quote the old 104/92/12.
        "q2_total": len(loc),
        "q2_present": _present,
        "q2_component_only": len(loc) - _present,
        "q1_fixed": q1_fixed,
        "q3_reachable": c2.get("reachable", 0),
        "q3_unreachable": c2.get("not-reachable", 0),
        "q3_unknown": c2.get("unknown", 0),
        "q4_controllable": c3.get("controllable", 0),
        "q4_not_controllable": c3.get("not-controllable", 0),
        # A refutation that only holds once the LLM's own environment defaults are
        # pinned is reported separately by tools/z3_controllability, because it is
        # not a refutation - see that module.
        "q4_environment_dependent": c3.get("environment-dependent", 0),
        "clearances_from_source_analysis": cleared,
    }


CORPUS = _corpus()


QUESTIONS = [
    {"id": "Q1", "ask": "Is the vulnerable component present?",
     "clears_with": ["component_not_present"],
     "how": "the affected component / model the advisory names is listed in this "
            "asset's SBOM (the CSAF product_tree -> component mapping); an absent "
            "component needs no version match, so it holds even where every version "
            "is NOASSERTION",
     "state": "implemented",
     "result": "the SBOM-level gate, decided before any source is read: a CVE whose "
               "affected component is not in the asset is not_affected "
               "(component_not_present). All %(q2_total)d source-collected CVEs clear "
               "this by construction (their component is present)" % CORPUS},
    {"id": "Q2", "ask": "Is the vulnerable code present?",
     "clears_with": ["vulnerable_code_not_present"],
     "how": "the CTI-located vulnerable function is defined in the collected source "
            "(tools/source_locate.py; CTI function names, else the patch-localised "
            "targets, checked against the snapshot function index)",
     "state": "implemented",
     "result": "over the %(q2_total)d source-collectable CVEs: present %(q2_present)d, "
               "component-only %(q2_component_only)d (the function could not be located)"
               % CORPUS},
    {"id": "Q3", "ask": "Is it on an executed path?",
     "clears_with": ["vulnerable_code_not_in_execute_path"],
     "how": "Joern CPG call-graph reachability from entry points "
            "(tools/joern_reachability.py, call-graph-only - no dataflow)",
     "state": "implemented",
     "result": "reachable %(q3_reachable)d, not-reachable %(q3_unreachable)d, "
               "unknown %(q3_unknown)d. Joern refutes almost nothing soundly here: of its "
               "4 not-reachable verdicts, 2 contradict the public-header authority "
               "(GENERAL_NAME_cmp, zlib inflate), which is why Q3 only grades the tier "
               "and never refutes" % CORPUS},
    {"id": "Q4", "ask": "Can an adversary control it?",
     "clears_with": ["vulnerable_code_cannot_be_controlled_by_adversary"],
     "how": "Z3 decides whether attacker-controlled inputs satisfy the trigger, from "
            "an LLM formalisation of the CTI (tools/z3_controllability.py)",
     "state": "implemented",
     "result": "controllable %(q4_controllable)d, not-controllable "
               "%(q4_not_controllable)d, environment-dependent "
               "%(q4_environment_dependent)d. The solver refutes NOTHING on this "
               "corpus, and that is the honest reading: every refutation it used to "
               "report disappeared once the LLM's own `environment_fixed` defaults "
               "were unpinned, so those cases are reported as "
               "environment-dependent rather than quoted as clearances"
               % CORPUS},
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
     "this single fix overturned all 6 clearances the first Q4 run produced"),
    ("Entry-model completeness",
     "Q4 seeds its walk from I/O readers, the public API and address-taken "
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


def resolve(q2=None, q3=None, q4=None, target_source="none",
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
    clears = {"q2": q2, "q3": q3, "q4": q4}
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
    if all(clears[k] == "pass" for k in ("q2", "q3", "q4")):
        return AFFECTED, None, "vulnerable code present, reachable and controllable"

    return UNDER_INV, None, "insufficient evidence"


