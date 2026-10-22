#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVSS v3.1 / v2 vectors: parse, score, and expose the ENVIRONMENTAL group.

Why this module exists
----------------------
The old context branch read exactly one metric out of the CVSS vector - the
Attack Vector - and threw the other seven away (src/asset_av_judge.py). That is
a large waste: AV says which channel an exploit rides, but PR says whether the
attacker must already hold an account, UI whether a human has to act, and C/I/A
how much of the asset's mission the exploit can take. On ICS assets those are
exactly the metrics the operational context can speak to.

Two things are computed here, and they must never be confused:

  score  - CVSS's own numbers (base / threat / environmental). A score is a
           PRIORITY, never a VEX status. Nothing in this file returns a status.
  needs  - the environmental PRECONDITIONS a vector implies (`preconditions`).
           These are what src/vex_context_judge.py tests against asset facts,
           and only a precondition that is STRUCTURALLY impossible on the asset
           can move a status to not_affected.

The environmental score is the official CVSS v3.1 environmental metric group
(modified base metrics + CR/IR/AR), computed with the spec's formulas and its
exact Roundup, not an invented weighting. Instantiating a standard is defensible
in a certification context in a way that a bespoke 0-10 heuristic is not.

Reference: CVSS v3.1 Specification Document, section 7 (formulas) and the
Roundup definition in section 7.4.
"""
import math

# --- v3.1 metric weights (spec table) ----------------------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # Scope Changed
_UI = {"N": 0.85, "R": 0.62}
# v3 impact values are High / Low / None. ("M"edium is CVSS v2's scale and
# belongs in _V2_CIA; mixing them silently made every C:L vector unscoreable.)
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
# Requirement modifiers and the threat group. X ("not defined") is 1.0 so an
# undefined metric cannot change a score - the spec's own behaviour.
_REQ = {"H": 1.5, "M": 1.0, "L": 0.5, "X": 1.0}
_E = {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
_RL = {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}
_RC = {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}

BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def roundup(x):
    """CVSS v3.1 Roundup: the smallest multiple of 0.1 that is >= x.

    Implemented with the spec's integer arithmetic rather than math.ceil, which
    the spec explicitly warns against: float representation makes ceil(x*10)/10
    return 4.0 for an input of 4.000000000000001.
    """
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse(vector):
    """({metric: value}, version) from a CVSS vector string.

    Accepts "CVSS:3.1/AV:N/..." and a bare "AV:N/AC:L/..." (CISA publishes the
    bare form in some advisory fields). v2 vectors come back with ver "2.0";
    their metric names differ (Au instead of PR, no S/UI) and callers must branch.
    """
    if not vector:
        return {}, None
    parts = [p for p in str(vector).strip().split("/") if p]
    ver = None
    out = {}
    for p in parts:
        if p.upper().startswith("CVSS:"):
            ver = p.split(":", 1)[1]
            continue
        if ":" not in p:
            continue
        k, v = p.split(":", 1)
        out[k.strip().upper()] = v.strip().upper()
    if ver is None:
        # No prefix: v2 is the one that carries Au, v4 the one that carries AT.
        ver = "2.0" if "AU" in out else ("4.0" if "AT" in out else "3.1")
    return out, ver


def is_v3_complete(m):
    """True when every v3 base metric is present with a legal value."""
    legal = {"AV": _AV, "AC": _AC, "UI": _UI, "C": _CIA, "I": _CIA, "A": _CIA}
    if any(k not in m for k in BASE_METRICS):
        return False
    if m.get("S") not in ("U", "C") or m.get("PR") not in _PR_U:
        return False
    return all(m[k] in tbl for k, tbl in legal.items())


# --- scores -------------------------------------------------------------------

def _impact(c, i, a, scope_changed):
    iss = 1 - (1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a])
    if not scope_changed:
        return 6.42 * iss
    return 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15


def _mod_impact(c, i, a, cr, ir, ar, scope_changed):
    miss = min(1 - (1 - _REQ[cr] * _CIA[c]) * (1 - _REQ[ir] * _CIA[i])
               * (1 - _REQ[ar] * _CIA[a]), 0.915)
    if not scope_changed:
        return 6.42 * miss
    return 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13


def base_score(m):
    """CVSS v3.1 base score from a parsed metric dict, or None if incomplete."""
    if not is_v3_complete(m):
        return None
    changed = m["S"] == "C"
    imp = _impact(m["C"], m["I"], m["A"], changed)
    if imp <= 0:
        return 0.0
    expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] \
        * (_PR_C if changed else _PR_U)[m["PR"]] * _UI[m["UI"]]
    return roundup(min((1.08 if changed else 1.0) * (imp + expl), 10))


def environmental_score(m, mod=None, threat=None):
    """CVSS v3.1 environmental score.

    mod    : modified base metrics {MAV,MAC,MPR,MUI,MS,MC,MI,MA} and the
             requirements {CR,IR,AR}. Anything absent falls back to the base
             metric, which is the spec's "X / not defined" behaviour.
    threat : {E,RL,RC}. Absent -> X -> multiplier 1.0.

    Returns None when the base vector is incomplete, because a modified score
    built on guessed base metrics would be a fabrication.
    """
    if not is_v3_complete(m):
        return None
    mod = {k.upper(): v for k, v in (mod or {}).items() if v}
    threat = {k.upper(): v for k, v in (threat or {}).items() if v}

    def g(name):
        v = mod.get("M" + name, "X")
        return m[name] if v in ("X", "") else v

    mav, mac, mui = g("AV"), g("AC"), g("UI")
    mpr, ms = g("PR"), g("S")
    mc, mi, ma = g("C"), g("I"), g("A")
    cr, ir, ar = (mod.get(k, "X") for k in ("CR", "IR", "AR"))
    changed = ms == "C"
    imp = _mod_impact(mc, mi, ma, cr, ir, ar, changed)
    if imp <= 0:
        return 0.0
    expl = 8.22 * _AV[mav] * _AC[mac] * (_PR_C if changed else _PR_U)[mpr] * _UI[mui]
    sub = roundup(min((1.08 if changed else 1.0) * (imp + expl), 10))
    return roundup(sub * _E.get(threat.get("E", "X"), 1.0)
                   * _RL.get(threat.get("RL", "X"), 1.0)
                   * _RC.get(threat.get("RC", "X"), 1.0))


# --- v2, for the corpus CVEs that have nothing newer --------------------------
_V2_AV = {"L": 0.395, "A": 0.646, "N": 1.0}
_V2_AC = {"H": 0.35, "M": 0.61, "L": 0.71}
_V2_AU = {"M": 0.45, "S": 0.56, "N": 0.704}
_V2_CIA = {"N": 0.0, "P": 0.275, "C": 0.660}


def v2_base_score(m):
    """CVSS v2 base score. Kept separate: v2 has no Scope and no UI, so it
    cannot be mapped into the v3 formulas without inventing the missing metrics."""
    try:
        imp = 10.41 * (1 - (1 - _V2_CIA[m["C"]]) * (1 - _V2_CIA[m["I"]])
                       * (1 - _V2_CIA[m["A"]]))
        expl = 20 * _V2_AV[m["AV"]] * _V2_AC[m["AC"]] * _V2_AU[m["AU"]]
    except KeyError:
        return None
    fimp = 0 if imp == 0 else 1.176
    return round(((0.6 * imp) + (0.4 * expl) - 1.5) * fimp, 1)


def v2_preconditions(m):
    """The precondition facts a v2 vector can honestly supply.

    AV carries across unchanged. v2 `Au` (number of authentication instances) is
    NOT PR (privilege level) - Au:S says one authentication happened, which says
    nothing about the privilege it conferred - so it becomes a weaker
    `account_required` fact rather than being mapped onto PR. v2 has no UI at
    all, so user interaction is left unknown instead of assumed absent.
    """
    out = []
    av = m.get("AV")
    if av in ("N", "A", "L", "P"):
        out.append("AV:" + av)
    if m.get("AU") in ("S", "M"):
        out.append("ACCOUNT:REQUIRED")
    return out


# --- what a vector REQUIRES of the environment -------------------------------
# One entry per precondition a CVSS metric imposes. These are the only things an
# operational context is entitled to argue about: a CVSS metric states a
# requirement, and the asset either can or cannot satisfy it.
PRECONDITIONS = {
    "AV:N": {"metric": "AV", "kind": "channel",
             "need": "a network path from beyond the asset's own broadcast domain"},
    "AV:A": {"metric": "AV", "kind": "channel",
             "need": "a path from the adjacent network (same L2 segment, radio, or local bus)"},
    "AV:L": {"metric": "AV", "kind": "channel",
             "need": "the ability to act locally on the asset (console, shell, loaded "
                     "logic, or an account session)"},
    "AV:P": {"metric": "AV", "kind": "channel",
             "need": "physical contact with the asset or its ports"},
    "PR:L": {"metric": "PR", "kind": "privilege",
             "need": "an account on the asset with ordinary user privilege"},
    "PR:H": {"metric": "PR", "kind": "privilege",
             "need": "an account on the asset with administrative privilege"},
    "UI:R": {"metric": "UI", "kind": "interaction",
             "need": "a human operator who acts on attacker-supplied content "
                     "(opens a file, clicks a link, confirms a dialog)"},
    "AC:H": {"metric": "AC", "kind": "condition",
             "need": "a special condition outside the attacker's control "
                     "(a race window, a specific configuration, reconnaissance)"},
    "ACCOUNT:REQUIRED": {"metric": "Au", "kind": "privilege",
                         "need": "at least one authentication to the asset "
                                 "(CVSS v2 Au; privilege level unstated)"},
}


def preconditions(m):
    """The precondition ids a parsed v3 vector imposes.

    Only metrics that state a REQUIREMENT appear. PR:N, UI:N and AC:L state the
    ABSENCE of a requirement, so they contribute nothing to test - which is the
    point: an AV:N/PR:N/UI:N/AC:L CVE has exactly one precondition, and context
    can refute it only by removing the network itself.
    """
    out = []
    av = m.get("AV")
    if av in ("N", "A", "L", "P"):
        out.append("AV:" + av)
    if m.get("PR") in ("L", "H"):
        out.append("PR:" + m["PR"])
    if m.get("UI") == "R":
        out.append("UI:R")
    if m.get("AC") == "H":
        out.append("AC:H")
    return out


def impact_profile(m):
    """{C,I,A,scope_changed} - the mission dimensions an exploit would hit.

    Read by the ICS context layer to set the requirement metrics (CR/IR/AR): on
    a safety-instrumented asset an A:H CVE outranks a C:H one, and that judgment
    belongs to the asset, not to the CVE.
    """
    return {"C": m.get("C"), "I": m.get("I"), "A": m.get("A"),
            "scope_changed": m.get("S") == "C"}


def summarise(vector):
    """Everything the judge needs out of one vector, in one call."""
    m, ver = parse(vector)
    if not m:
        return {"available": False, "version": None}
    if ver and ver.startswith("2"):
        return {"available": True, "version": ver, "metrics": m, "complete": False,
                "base": v2_base_score(m), "preconditions": v2_preconditions(m),
                "impact": None,
                "note": "CVSS v2: no Scope and no User Interaction metric, and Au is "
                        "not a privilege level - fewer preconditions are testable"}
    return {"available": True, "version": ver, "metrics": m,
            "complete": is_v3_complete(m), "base": base_score(m),
            "preconditions": preconditions(m), "impact": impact_profile(m)}


if __name__ == "__main__":
    checks = [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:L/A:N", 4.7),
        ("CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H", 6.3),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
    ]
    ok = True
    for v, want in checks:
        got = base_score(parse(v)[0])
        if got != want:
            ok = False
        print("%s base %-5s want %-5s %s" % ("OK " if got == want else "BAD", got, want, v))
    m, _ = parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
    print("\nA:H CVE  base", base_score(m),
          "| AR:H ->", environmental_score(m, {"AR": "H"}),
          "| MAV:P ->", environmental_score(m, {"MAV": "P"}),
          "| AR:H+KEV ->", environmental_score(m, {"AR": "H"}, {"E": "H"}),
          "| AR:L+MAV:P ->", environmental_score(m, {"AR": "L", "MAV": "P"}))
    print("preconditions:", preconditions(parse("CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H")[0]))
    print("ALL BASE OK" if ok else "BASE MISMATCH")
