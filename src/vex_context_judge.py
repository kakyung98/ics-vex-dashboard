#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VEX from the CVSS Exploitability metrics and the ICS asset's operational context.

Which half of the vector decides a status, and which half may not
-----------------------------------------------------------------
VEX answers one question: can an adversary exploit this vulnerability in this
product. It is not a severity judgment and has no severity field. CVSS already
splits its Base group along exactly that line, and this module follows it:

  Exploitability metrics  AV / AC / PR / UI   can it be triggered
  Impact metrics          C / I / A           what is lost if it is

`cvss.preconditions()` returns the first group only, and those - plus the CTI
service requirement - are the ONLY inputs that can set a status. The Impact
metrics leave through `cvss.impact_profile()` into the `score` field and can
never reach the verdict. Hold the exploitability half fixed and swing the impact
half from C:H/I:N/A:N to C:H/I:H/A:H: the status is `affected` either way and
only the score moves.

Network position is the one arguable input, because segmentation really is a
reachability fact. It is barred from setting a status not because it is
irrelevant but because it is REVERSIBLE - a verdict one firewall rule overturns
does not belong in a published document - so it is recorded as a mitigation and
lowers the score instead.

The score exists because VEX stops at "exploitable" and one L1 PLC ends up with
5,129 affected statements; the owner still has to order them. It is a separate
output that sits beside the VEX judgment, not part of it.


This is the judge for the 93.5% of components whose source cannot be obtained -
which is to say, for almost the whole problem. It replaces the single-metric
`AV x attack-surface` match in src/asset_av_judge.py with the complete vector,
and it replaces that module's `likely_mitigated` state with a distinction that
actually carries: a structural impossibility sets a status, a control does not.

The procedure
-------------
  Q1  SBOM    is the affected component in this asset, in an affected version?
              absent -> not_affected / component_not_present. Decided before any
              CVSS is read, by src/cpe_match_l0l3.py.
  P   vector  the CVSS vector states the environmental PRECONDITIONS of the
              exploit as scored (src/cvss.preconditions).
  C   context each precondition is evaluated against the asset's facts as
              impossible / mitigated / satisfied / unknown (src/ics_context).
  V   verdict any precondition structurally IMPOSSIBLE -> not_affected with the
              matching CISA justification. Otherwise `affected`, because VEX puts
              the burden of proof on not_affected and an unanswered question is
              not evidence of safety.
  R   rank    the CVSS environmental score (modified base + CR/IR/AR + threat)
              orders the affected statements. A score is a priority, never a
              status.

What the verdict does and does not claim
----------------------------------------
A refutation here is sound with respect to THE PATH CVSS SCORED. NVD scores the
most severe realistic path, not every path, so "the network channel this CVE was
scored on does not exist here" is not the same sentence as "this CVE can never
be exploited on this asset". Every refutation therefore carries `scope:
as-scored` and, when another channel is still open on the asset, an explicit
residual-risk note. Saying this out loud is the difference between a defensible
VEX document and an attractive one.

Every structural fact is an ASSERTION BY THE ASSET OWNER, not a machine
measurement. The result records that (`evidence_basis`) and whether the
assertion was attested, because a reviewer must be able to see that the
refutation rests on a human statement about hardware rather than on analysis.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cvss                       # noqa: E402
import ics_context as ctxmod      # noqa: E402

AFFECTED = "affected"
NOT_AFFECTED = "not_affected"
UNDER_INV = "under_investigation"
FIXED = "fixed"

# The CISA justification each kind of structural impossibility earns. There is no
# entry producing `inline_mitigations_already_exist` or
# `vulnerable_code_not_present`, and that absence is the design:
#   * inline_mitigations_already_exist means the SUPPLIER built a mitigation into
#     the product. An operator control is not that.
#   * vulnerable_code_not_present requires looking at the code. Closed firmware
#     cannot be looked at, so this judge may never claim it.
JUSTIFICATION = {
    "channel": "vulnerable_code_cannot_be_controlled_by_adversary",
    "privilege": "vulnerable_code_cannot_be_controlled_by_adversary",
    "interaction": "vulnerable_code_cannot_be_controlled_by_adversary",
    "service": "vulnerable_code_not_in_execute_path",
}

# Channels the asset could still present even after the scored one is refuted.
_CHANNEL_CHECKS = [
    ("AV:N", "network"), ("AV:A", "adjacent network"),
    ("AV:L", "local execution"), ("AV:P", "physical access"),
]


def _service_precondition(cve_requirements, ctx):
    """The CVE-side service/protocol requirement, when the CTI stated one.

    This is not a CVSS metric - it comes from the advisory text - but it is the
    single most useful precondition in ICS, because a controller that does not
    implement the affected protocol cannot run the affected code path at all.
    """
    req = (cve_requirements or {}).get("required_service")
    if not req:
        return None
    impl = cve_requirements.get("service_implemented")
    if impl is False:
        return ("SERVICE:" + str(req), ctxmod.IMPOSSIBLE, "service",
                "the asset does not implement or run %s, the service this CVE is "
                "reached through, so the affected code path is never entered" % req)
    if impl is True:
        enabled = cve_requirements.get("service_enabled")
        if enabled is False:
            return ("SERVICE:" + str(req), ctxmod.MITIGATED, "service",
                    "%s is implemented but currently disabled by configuration - a "
                    "control, reversible by a settings change" % req)
        return ("SERVICE:" + str(req), ctxmod.SATISFIED, "service",
                "the asset implements and runs %s" % req)
    return ("SERVICE:" + str(req), ctxmod.UNKNOWN, "service",
            "whether the asset implements %s was not stated" % req)


def judge(cve, vector, ctx, cve_requirements=None, signals=None,
          remediation_categories=None, component_present=True,
          version_in_range=True, patched=False):
    """One (asset, CVE) statement.

    cve                  : CVE id, for the record only.
    vector               : the CVSS vector string (v3.x preferred, v2 accepted).
    ctx                  : the asset's operational context (src/ics_context).
    cve_requirements     : CTI-derived facts, e.g. {"required_service": "FTP",
                           "service_implemented": False}.
    signals              : {"kev": bool, "epss_percentile": float}.
    remediation_categories: the CSAF remediation categories for this CVE.
    component_present / version_in_range / patched: the SBOM-layer answers (Q1)
                           and the patch pre-gate, decided elsewhere.
    """
    rec = {"cve": cve, "status": None, "justification": None,
           "preconditions": [], "mitigations": [], "notes": [],
           "score": {}, "evidence_basis": "asset-owner assertion (not machine-verified)",
           "attested_by": ctx.get("_attested_by") or None}

    # --- the pre-gates that do not need CVSS at all --------------------------
    if patched:
        rec.update(status=FIXED, reason="the installed build carries the fix")
        return rec
    if not component_present:
        rec.update(status=NOT_AFFECTED, justification="component_not_present",
                   reason="the affected component is not listed in this asset's SBOM")
        return rec
    if not version_in_range:
        rec.update(status=NOT_AFFECTED, justification="component_not_present",
                   reason="the installed version lies outside the advisory's "
                          "affected range")
        return rec

    # --- the vector ----------------------------------------------------------
    cv = cvss.summarise(vector)
    rec["cvss"] = {k: cv.get(k) for k in ("available", "version", "complete", "base")}
    pre = list(cv.get("preconditions") or [])
    if cv.get("note"):
        rec["notes"].append(cv["note"])

    svc = _service_precondition(cve_requirements, ctx)

    if not cv.get("available") and not svc:
        # Nothing to reason from: no vector, no CTI requirement. This is the one
        # honest `under_investigation` in this branch - the analysis cannot start,
        # as distinct from starting and finding no refutation.
        rec.update(status=UNDER_INV, reason="no CVSS vector and no CTI-derived "
                                            "requirement for this CVE - there is "
                                            "nothing the context can be tested against")
        rec["triage"] = _triage(remediation_categories)
        return rec

    # --- evaluate every precondition ----------------------------------------
    rows = []
    for p in pre:
        outcome, why = ctxmod.evaluate(p, ctx)
        meta = cvss.PRECONDITIONS.get(p, {})
        rows.append({"id": p, "metric": meta.get("metric"), "kind": meta.get("kind"),
                     "need": meta.get("need"), "outcome": outcome, "why": why})
    if svc:
        pid, outcome, kind, why = svc
        rows.append({"id": pid, "metric": "CTI", "kind": kind,
                     "need": "the affected service must be implemented and running",
                     "outcome": outcome, "why": why})
    rec["preconditions"] = rows

    # --- verdict -------------------------------------------------------------
    impossible = [r for r in rows if r["outcome"] == ctxmod.IMPOSSIBLE]
    rec["mitigations"] = ctxmod.active_mitigations(ctx)

    if impossible:
        # Prefer a service refutation: "the code path is never entered" is a
        # narrower and stronger claim than "the attacker has no channel".
        chosen = next((r for r in impossible if r["kind"] == "service"), impossible[0])
        rec.update(status=NOT_AFFECTED,
                   justification=JUSTIFICATION.get(chosen["kind"]),
                   reason=chosen["why"], refuted_by=chosen["id"], scope="as-scored")
        rec["notes"].append(
            "Sound only for the attack path CVSS scored. NVD scores the most "
            "severe realistic path, not every path, so this refutes exploitation "
            "via %s and nothing wider." % (chosen["need"] or chosen["id"]))
        residual = _residual_channels(ctx, rows)
        if residual:
            rec["notes"].append(
                "Residual risk: the asset still presents %s. A CVE scored on one "
                "of those channels would not be refuted by this reasoning."
                % ", ".join(residual))
        if not rec["attested_by"]:
            rec["notes"].append(
                "UNATTESTED: this not_affected rests on a structural claim about "
                "the hardware or build that no one has signed. Attach an attester "
                "before publishing the statement.")
        rec["score"] = _score(cv, ctx, signals, remediation_categories, refuted=True)
        return rec

    # No refutation. VEX puts the burden of proof on not_affected, so an
    # unanswered precondition leaves the statement AFFECTED rather than pending:
    # failing to prove absence is not evidence of absence.
    rec.update(status=AFFECTED)
    unknowns = [r["id"] for r in rows if r["outcome"] == ctxmod.UNKNOWN]
    mitigated = [r["id"] for r in rows if r["outcome"] == ctxmod.MITIGATED]
    bits = []
    if mitigated:
        bits.append("controls currently obstruct %s, which lowers priority but "
                    "cannot clear the statement" % ", ".join(mitigated))
    if unknowns:
        bits.append("%s could not be decided from the facts given; an unanswered "
                    "question is not evidence of safety" % ", ".join(unknowns))
    if not bits:
        bits.append("the asset supplies every precondition the CVE requires")
    rec["reason"] = "; ".join(bits)
    rec["confidence"] = ("evaluated" if not unknowns else "partial")
    rec["score"] = _score(cv, ctx, signals, remediation_categories)
    if mitigated:
        rec["remediations"] = [{"category": "mitigation", "details": m["detail"]}
                               for m in rec["mitigations"]]
    return rec


def _residual_channels(ctx, rows):
    """Channels still open on the asset, other than the refuted one.

    Computed from the context directly rather than from the CVE, because the
    question is what this asset exposes, not what this CVE used.
    """
    out = []
    refuted = {r["id"] for r in rows if r["outcome"] == ctxmod.IMPOSSIBLE}
    for pid, label in _CHANNEL_CHECKS:
        if pid in refuted:
            continue
        outcome, _ = ctxmod.evaluate(pid, ctx)
        if outcome == ctxmod.SATISFIED:
            out.append(label)
    return out


def _score(cv, ctx, signals, remediation_categories, refuted=False):
    """Base / environmental score and the full derivation, for ranking only."""
    m = cv.get("metrics") or {}
    out = {"base": cv.get("base"), "version": cv.get("version"), "why": []}
    if refuted:
        # A refuted statement has no priority to rank, and scoring it anyway
        # produces a self-contradiction: the same fact that refutes "the attacker
        # must hold an account" (no account model exists) also drives MPR:N,
        # which RAISES the modified score. Reporting both in one record would
        # claim the CVE both does not apply and applies harder than published.
        out["environmental"] = 0.0
        out["zero_reason"] = "refuted"
        out["why"].append("environmental score 0: the statement is not_affected, so "
                          "there is no exposure on this asset to rank. The base "
                          "score is kept for reference only.")
        return out
    if not cv.get("complete"):
        out["environmental"] = None
        out["why"].append("no environmental score: the vector is not a complete "
                          "CVSS v3 base vector, and modifying metrics that were "
                          "never published would fabricate a number")
        return out
    threat, twhy = ctxmod.derive_threat(signals, remediation_categories)
    mod, mwhy = ctxmod.derive_modified_base(ctx, cv.get("impact"))
    req, rwhy = ctxmod.impact_requirements(ctx)
    mod = dict(mod)
    mod.update(req or {})
    out["environmental"] = cvss.environmental_score(m, mod, threat)
    out["threat"] = threat
    out["modifiers"] = mod
    out["why"] = twhy + mwhy + list(rwhy or [])
    if not req:
        out["why"].append("CR/IR/AR left unweighted - no mission fact was stated, so "
                          "the environmental score reflects exposure but not mission "
                          "criticality")
    # An environmental 0 on an AFFECTED statement means something different from an
    # environmental 0 on a refuted one, and a reviewer cannot tell them apart from
    # the number. It arises when every impact dimension the CVE has was modified
    # away - e.g. a confidentiality-only CVE on an asset the owner states holds no
    # sensitive data - so the CVE applies but has nothing to damage here.
    if out["environmental"] == 0.0:
        out["zero_reason"] = "no_impact_lands"
        out["why"].append("environmental score 0 while AFFECTED: every impact "
                          "dimension this CVE carries was modified away by the "
                          "asset's own profile, so it applies but has nothing on "
                          "this asset to damage. This rests on the stated profile, "
                          "not on a refutation - the statement stays affected.")
    return out


def _triage(remediation_categories):
    """A likelihood hint for a statement that could not be analysed. NOT a status."""
    cats = set(remediation_categories or ())
    if cats & {"mitigation", "workaround"}:
        return {"likelihood": "triage_likely_not_affected",
                "why": "the advisory publishes a mitigation or workaround"}
    if cats & {"vendor_fix", "none_available", "no_fix_planned"}:
        return {"likelihood": "triage_likely_affected",
                "why": "nothing shields the product until a fix is applied"}
    return {"likelihood": "triage_unknown", "why": "no remediation recorded"}


# --- readiness report, so a reviewer can see what the context can decide -----
def impact_cannot_set_status(ctx):
    """Assert the boundary the module docstring claims, rather than only stating it.

    Severity is not exploitability. If a change confined to the Impact metrics
    (C/I/A) or to the asset's network position ever moved a VEX status, the
    pipeline would be publishing a risk opinion as an exploitability claim. This
    sweeps both and returns the violations, so the self-test can fail loudly
    instead of the drift being noticed in review - or not at all.
    """
    bad = []
    expl = "AV:N/AC:L/PR:N/UI:N/S:U"
    impacts = ["C:H/I:N/A:N", "C:N/I:H/A:N", "C:N/I:N/A:H", "C:H/I:H/A:H",
               "C:L/I:L/A:L"]
    seen = {judge("X", "CVSS:3.1/%s/%s" % (expl, i), ctx)["status"] for i in impacts}
    if len(seen) > 1:
        bad.append("Impact metrics moved the status across %s: %s" % (impacts, seen))

    vec = "CVSS:3.1/%s/C:H/I:H/A:H" % expl
    seen = {judge("X", vec, dict(ctx, network_exposure=e))["status"]
            for e in ("remote-accessible", "dmz-routable", "control-network",
                      "isolated-cell")}
    if len(seen) > 1:
        bad.append("Network position moved the status: %s" % seen)
    return bad


def readiness(ctx):
    """Which decisions this context is currently able to support."""
    miss_s = ctxmod.missing(ctx, ctxmod.STRUCTURAL_KEYS)
    miss_c = ctxmod.missing(ctx, ctxmod.CONTROL_KEYS)
    miss_m = ctxmod.missing(ctx, ctxmod.MISSION_KEYS)
    return {
        "can_refute": len(miss_s) < len(ctxmod.STRUCTURAL_KEYS),
        "missing_structural": miss_s,
        "missing_control": miss_c,
        "missing_mission": miss_m,
        "note": ("Refutation needs structural facts; a control answers only change "
                 "the priority. A fully blank structural set can never produce "
                 "not_affected, which is the intended failure mode."),
    }


if __name__ == "__main__":
    headless_plc = {
        "net_interface_present": True, "radio_hardware_present": False,
        "sole_path_hardware_diode": False, "physical_port_access": "sealed-policy",
        "interactive_operator": False, "local_execution_possible": False,
        "account_subsystem": "none", "network_exposure": "control-network",
        "purdue_level": "1", "host_firewall": True, "auth_enforced": False,
        "device_class": "plc", "safety_function": True, "sil": "SIL2",
        "availability_tolerance": "continuous", "data_sensitivity": "none",
        "patch_cadence": "frozen-validated-state",
        "_attested_by": "plant engineer, 2026-10-22",
    }
    cases = [
        ("CVE-A  phishing-style, needs a user",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", None),
        ("CVE-B  unauthenticated network RCE",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", None),
        ("CVE-C  needs an admin account",
         "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", None),
        ("CVE-D  in a protocol the device does not speak",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         {"required_service": "the FTP server", "service_implemented": False}),
        ("CVE-E  local privilege escalation",
         "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", None),
    ]
    for label, vec, reqs in cases:
        r = judge(label.split()[0], vec, headless_plc, reqs,
                  signals={"kev": True}, remediation_categories={"vendor_fix": 1})
        print("\n%s\n  -> %s %s" % (label, r["status"].upper(),
                                    "/ " + r["justification"] if r["justification"] else ""))
        print("     %s" % r["reason"][:150])
        print("     base %s  env %s" % (r["score"].get("base"), r["score"].get("environmental")))
    print("\nreadiness:", readiness(headless_plc)["can_refute"],
          "| missing mission:", readiness(headless_plc)["missing_mission"])

    # The boundary that keeps this a VEX judgment and not a risk opinion:
    # severity must never move a status. Run on an asset that refutes nothing,
    # so any status change would have to have come from the impact half.
    open_asset = dict(headless_plc, interactive_operator=True,
                      local_execution_possible=True, account_subsystem="multi-user",
                      physical_port_access="open")
    violations = impact_cannot_set_status(open_asset)
    for v in violations:
        print("BOUNDARY VIOLATION:", v)
    print("boundary: impact metrics and network position cannot set a status -",
          "OK" if not violations else "BROKEN")
