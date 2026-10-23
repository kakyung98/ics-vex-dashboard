#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The ICS asset operational context, and what it is allowed to decide.

The one rule this module exists to enforce
------------------------------------------
A CVSS vector states what an exploit REQUIRES of its environment. An asset
either can or cannot supply that requirement. But "cannot" comes in two very
different flavours, and conflating them is how context-based VEX goes wrong:

  STRUCTURAL   the requirement cannot be supplied because of what the asset IS -
               there is no radio in the enclosure, the maintenance port is
               potted, the controller is headless so no human ever opens a file.
               Changing this means changing hardware or firmware. A structural
               impossibility is a SOUND refutation and may set `not_affected`.

  CONTROL      the requirement is currently not supplied because of how the
               asset is CONFIGURED or GOVERNED - a firewall rule, a network
               segment, a locked cabinet, an approval workflow. Every one of
               these can be undone by a change window, a misconfiguration or an
               engineer with a laptop. A control NEVER sets `not_affected`. It
               produces a CSAF `remediation` of category `mitigation` on a
               statement that stays `affected`, and it lowers the environmental
               PRIORITY score.

The previous context branch (src/asset_av_judge.py) blurred this: a host
firewall and a sealed port both ended up closing an "attack vector", and the
`likely_mitigated` state sat in the same field as a verdict. Here the two are
separate types with separate consequences.

What this module does NOT do
----------------------------
  * It never uses `inline_mitigations_already_exist`. CISA defines that
    justification as a mitigation built INTO the product by the supplier; an
    operator's firewall is not that, and borrowing the label would export a
    false claim into a machine-readable document. Operator controls leave the
    status `affected` and are exported as remediations.
  * It never answers "is the vulnerable code present". No amount of deployment
    context can see inside closed firmware. That question stays unanswerable for
    the 93.5% of corpus components whose source cannot be obtained, and the
    methodology says so instead of guessing (see docs/METHODOLOGY_V3.md).
  * It never expresses the ABSENCE of an interactive operator as CVSS `MUI:N`.
    MUI:N means "no user interaction is needed", which RAISES the score; the
    absence of any user means the requirement cannot be met, which is a
    refutation. A metric value and an impossibility are not interchangeable.
"""

STRUCTURAL = "structural"
CONTROL = "control"
MISSION = "mission"

# Evaluation outcomes for one precondition.
IMPOSSIBLE = "impossible"    # structurally cannot be satisfied -> may refute
MITIGATED = "mitigated"      # a control currently obstructs it -> never refutes
SATISFIED = "satisfied"      # the asset supplies what the CVE needs
UNKNOWN = "unknown"          # not decidable from the facts given

# --- the context schema ------------------------------------------------------
# (key, kind, type, label, help). type: "bool" | "tri" | "enum:a|b|c"
# `tri` fields are three-valued on purpose: an unanswered question must be
# distinguishable from a "no", because only a real "no" can refute anything.
CONTEXT_FIELDS = [
    # ---- STRUCTURAL: properties of the hardware / firmware build ----
    ("net_interface_present", STRUCTURAL, "tri",
     "Has any network interface (wired or wireless)",
     "No interface at all means a network-borne exploit has no channel to ride. "
     "This is about the hardware, not about what the interface is connected to."),
    ("radio_hardware_present", STRUCTURAL, "tri",
     "Has radio hardware fitted (Wi-Fi / cellular / Bluetooth / proprietary RF)",
     "A disabled radio is a control; an absent radio is structural. Answer No "
     "only when the module is not fitted in this order variant."),
    ("sole_path_hardware_diode", STRUCTURAL, "tri",
     "Its only network path is a hardware unidirectional gateway (data diode)",
     "A hardware diode has no inbound circuit, so inbound traffic is physically "
     "impossible - unlike a software one-way rule, which is a control."),
    ("physical_port_access", STRUCTURAL, "enum:open|sealed-policy|sealed-structural",
     "Access to physical / maintenance ports",
     "sealed-structural = potted, de-populated or physically removed (refutes). "
     "sealed-policy = a locked cabinet, a tamper seal, a procedure (mitigates)."),
    ("interactive_operator", STRUCTURAL, "tri",
     "A human operator acts on content on this asset (HMI session, browser, file handling)",
     "Headless controllers have no one to click a link or open a file, so a CVE "
     "requiring user interaction has no actor. Engineering workstations do."),
    ("local_execution_possible", STRUCTURAL, "tri",
     "Code or logic can be executed locally on the asset (console, shell, logic download)",
     "A sealed appliance with no console, no shell and no user-loadable logic "
     "cannot host a local-vector exploit."),
    ("account_subsystem", STRUCTURAL, "enum:none|single-fixed|multi-user",
     "Account model on the affected interface",
     "none = the interface has no concept of a login at all. Note this cuts both "
     "ways: it refutes a CVE that needs a privileged account, and it makes an "
     "unauthenticated CVE worse - the judge reports both."),

    # ---- CONTROL: configuration and governance ----
    ("network_exposure", CONTROL,
     "enum:remote-accessible|dmz-routable|control-network|isolated-cell",
     "Where the asset sits in the network",
     "Segmentation is a configuration, so it lowers priority and is exported as a "
     "mitigation - it never clears a CVE."),
    ("purdue_level", CONTROL, "enum:0|1|2|3|3.5|4",
     "Purdue / IEC 62443 zone level", "Used for priority and for the impact profile."),
    ("host_firewall", CONTROL, "tri", "Host or in-line firewall filters the affected service", ""),
    ("software_unidirectional", CONTROL, "tri", "One-way communication enforced in software/config", ""),
    ("auth_enforced", CONTROL, "tri", "Authentication is actually enforced on the affected interface", ""),
    ("transport_encrypted", CONTROL, "tri", "Traffic to the affected service is encrypted/authenticated", ""),
    ("app_allowlisting", CONTROL, "tri", "Application allowlisting / signed-code enforcement is active", ""),
    ("removable_media_blocked", CONTROL, "tri", "Removable media and maintenance devices are blocked by policy", ""),
    ("cabinet_locked", CONTROL, "tri", "The asset is in a locked cabinet / access-controlled area", ""),
    ("vendor_remote_access", CONTROL, "tri", "Vendor remote access to the asset is possible", ""),
    ("work_approval", CONTROL, "tri", "Work on the asset requires prior approval", ""),

    # ---- MISSION: what a successful exploit would cost (priority only) ----
    ("device_class", MISSION,
     "enum:plc|rtu|ied|hmi|engineering-workstation|historian|sis-logic-solver|network-device",
     "Device class", ""),
    ("safety_function", MISSION, "tri", "Performs or protects a safety function", ""),
    ("sil", MISSION, "enum:none|SIL1|SIL2|SIL3|SIL4", "Safety integrity level", ""),
    ("availability_tolerance", MISSION, "enum:continuous|scheduled|interruptible",
     "How much downtime the process tolerates", ""),
    ("data_sensitivity", MISSION, "enum:none|low|high",
     "Sensitivity of data held on the asset", ""),
    ("patch_cadence", MISSION,
     "enum:frozen-validated-state|on-advisory-only|maintenance-window-quarterly|continuous",
     "How often the asset can be patched", "Drives the remediation level, not the status."),
]

FIELDS_BY_KEY = {f[0]: f for f in CONTEXT_FIELDS}
STRUCTURAL_KEYS = [f[0] for f in CONTEXT_FIELDS if f[1] == STRUCTURAL]
CONTROL_KEYS = [f[0] for f in CONTEXT_FIELDS if f[1] == CONTROL]
MISSION_KEYS = [f[0] for f in CONTEXT_FIELDS if f[1] == MISSION]


def _t(ctx, key):
    """Three-valued read: True / False / None(unanswered)."""
    v = ctx.get(key)
    if v in (True, "y", "yes", "true", "Y"):
        return True
    if v in (False, "n", "no", "false", "N"):
        return False
    return None


def missing(ctx, keys=None):
    """Context keys not answered. Structural ones gate refutation; mission ones
    only soften the score, so callers check them separately."""
    return [k for k in (keys or [f[0] for f in CONTEXT_FIELDS])
            if ctx.get(k) in (None, "")]


# --- SBOM-carried context ----------------------------------------------------
# The generated ICS SBOMs put operational facts in metadata.component.properties
# (docs/README-SBOM 스키마확장.md). Whatever is there is read rather than asked
# for again; everything else is the asset owner's to supply. Measured over the
# 3,845-asset reverse_sbom corpus, 0% carry the operational properties, so in
# practice this pre-fills little and the owner supplies the rest - which the
# methodology states as an input requirement rather than hiding.
_SBOM_PROP_MAP = {
    "ics:purdue-level": "purdue_level",
    "ics:network-exposure": "_exposure_raw",
    "ics:device-class": "device_class",
    "ics:safety-integrity-level": "_sil_raw",
    "ics:patch-cadence": "patch_cadence",
}
_EXPOSURE_VALUES = ("remote-accessible", "dmz-routable", "control-network", "isolated-cell")


def from_sbom(sbom):
    """Pre-fill what the SBOM already asserts. Unknown values are dropped rather
    than coerced, so a vendor's free-text never becomes a fact the judge trusts."""
    out = {}
    mc = ((sbom or {}).get("metadata") or {}).get("component") or {}
    for p in mc.get("properties") or []:
        key = _SBOM_PROP_MAP.get(p.get("name"))
        if not key:
            continue
        val = (p.get("value") or "").strip()
        if key == "_exposure_raw":
            if val in _EXPOSURE_VALUES:
                out["network_exposure"] = val
        elif key == "_sil_raw":
            for lvl in ("SIL4", "SIL3", "SIL2", "SIL1"):
                if lvl in val.upper().replace(" ", ""):
                    out["sil"] = lvl
                    break
        elif key == "purdue_level":
            if val in ("0", "1", "2", "3", "3.5", "4"):
                out[key] = val
        else:
            out[key] = val
    return out


# --- threat metric group (CVSS E / RL / RC) ----------------------------------
# These are real CVSS metrics with published definitions, so each mapping below
# names the definition it satisfies rather than inventing a scale.
def derive_threat(signals=None, remediation_categories=None):
    """{E, RL, RC} + the reasons, from KEV / EPSS and the CSAF remediations."""
    signals = signals or {}
    cats = set(remediation_categories or ())
    why = []

    # Exploit Code Maturity. KEV means exploitation has been OBSERVED, which is
    # the definition of E:H ("High"). EPSS is a probability, not a maturity, so
    # it is only allowed to reach E:P ("Proof-of-Concept") - the weakest non-X
    # value - and only at a high percentile, where the model is in effect saying
    # exploit material is circulating.
    if signals.get("kev"):
        e, r = "H", "listed in CISA KEV - exploitation observed in the wild"
    elif (signals.get("epss_percentile") or 0) >= 0.95:
        e, r = "P", ("EPSS percentile %.2f - exploit material likely circulating "
                     "(capped at Proof-of-Concept: EPSS is a probability, not a "
                     "maturity measure)" % signals["epss_percentile"])
    else:
        e, r = "X", "no exploitation signal"
    why.append("E:%s - %s" % (e, r))

    # Remediation Level, from the CSAF remediation category the advisory published.
    if "vendor_fix" in cats:
        rl, r = "O", "an official vendor fix is published"
    elif "mitigation" in cats:
        rl, r = "T", "the advisory publishes a temporary mitigation"
    elif "workaround" in cats:
        rl, r = "W", "the advisory publishes a workaround only"
    elif cats & {"none_available", "no_fix_planned"}:
        rl, r = "U", "no remediation is available"
    else:
        rl, r = "X", "no remediation recorded"
    why.append("RL:%s - %s" % (rl, r))

    # Report Confidence. A CVE with an NVD-published CVSS vector and a CISA
    # advisory is a confirmed report; that is the only case this pipeline scores.
    why.append("RC:C - NVD-published vector with a CISA advisory behind it")
    return {"E": e, "RL": rl, "RC": "C"}, why


# --- environmental metric group: modified base metrics ------------------------
# CVSS's own purpose for the Modified Attack Vector is exactly this: "the asset
# is behind a firewall, so a network attack becomes an adjacent or local one".
# So segmentation belongs HERE, as a score modifier, and not in the status.
_MAV_FLOOR = {"remote-accessible": None, "dmz-routable": None,
              "control-network": "A", "isolated-cell": "L"}
_AV_ORDER = ["N", "A", "L", "P"]


def derive_modified_base(ctx, impact):
    """{MAV, MPR, MC, MI, MA} + reasons, from the asset's deployment.

    Only downgrades that the context actually justifies are emitted; everything
    else is left at the base metric (CVSS "X"). MUI is deliberately never set -
    see the module docstring.
    """
    mod, why = {}, []
    exp = ctx.get("network_exposure")
    floor = _MAV_FLOOR.get(exp)
    if floor:
        mod["MAV"] = floor
        why.append("MAV:%s - the asset sits on a %s, so a network-borne exploit "
                   "must originate no further away than that (CVSS environmental "
                   "MAV; a configuration, so it lowers priority only)" % (floor, exp))
    if _t(ctx, "net_interface_present") is False:
        mod["MAV"] = "P"
        why.append("MAV:P - no network interface is fitted, so only a physical "
                   "vector remains")

    # An ICS device that enforces no authentication turns a CVE that assumes an
    # authenticated attacker into an unauthenticated one. This RAISES the score,
    # and is reported because an operator who reads "PR:L, we are fine" is wrong.
    if ctx.get("account_subsystem") == "none" or _t(ctx, "auth_enforced") is False:
        mod["MPR"] = "N"
        why.append("MPR:N - the affected interface enforces no authentication, so "
                   "the privilege the CVE assumes is not actually required here")

    # Modified impact: what a successful exploit would really cost on THIS asset.
    if ctx.get("data_sensitivity") == "none" and (impact or {}).get("C") != "N":
        mod["MC"] = "N"
        why.append("MC:N - the asset holds no sensitive data, so the "
                   "confidentiality impact does not land here")
    if _t(ctx, "safety_function") is True and (impact or {}).get("A") == "H":
        why.append("MA left at base H - a safety function makes the availability "
                   "impact real rather than nominal")
    return mod, why


# --- environmental metric group: the impact REQUIREMENTS (CR / IR / AR) ------
# What the asset's MISSION requires of confidentiality, integrity and availability.
# This is the one place in the environmental group where ICS operating reality -
# not network topology - sets the number, and the direction is not the IT default:
# on a protection relay a loss of availability is a trip, while a loss of
# confidentiality is a nuisance.
#
# Starting point per device class, as (CR, IR, AR). Read "what does this box exist
# to do, and which property of it does the process depend on":
#   process controllers (plc/rtu/ied/sis) command physical equipment, so a forged
#     command (IR) and a dead controller (AR) are both process events, while the
#     setpoints themselves are rarely secret;
#   hmi / engineering workstation sit between the operator and the controllers -
#     they WRITE logic, so their integrity is a controller-integrity problem one
#     step removed, and they hold project files worth something;
#   a historian is an information asset: its value is the record, so a falsified
#     or exposed record outranks a few hours of downtime;
#   a network device carries everyone else's traffic, so availability dominates.
_CLASS_REQ = {
    "plc":                     ("L", "H", "H"),
    "rtu":                     ("L", "H", "H"),
    "ied":                     ("L", "H", "H"),
    "sis-logic-solver":        ("L", "H", "H"),
    "hmi":                     ("M", "H", "M"),
    "engineering-workstation": ("M", "H", "M"),
    "historian":               ("H", "M", "L"),
    "network-device":          ("L", "M", "H"),
}
_AVAIL_AR = {"continuous": "H", "scheduled": "M", "interruptible": "L"}
_SENS_CR = {"high": "H", "low": "M", "none": "L"}
# Purdue levels where the asset's job is the process rather than information.
_PROCESS_LEVELS = {"0", "1", "2"}
_INFORMATION_LEVELS = {"3", "3.5", "4"}


def impact_requirements(ctx):
    """({CR, IR, AR}, reasons) from the asset's mission facts.

    CVSS defines these as the organisation's security requirements for the asset,
    with H = 1.5, M = 1.0, L = 0.5 multiplying the matching impact sub-score.

    Two rules shape the result beyond the per-class table:

      * A SAFETY asset raises INTEGRITY as well as availability. The intuitive
        move is to raise AR alone - "if it stops, the protection is gone" - but a
        safety instrumented function that keeps running while reporting a forged
        process value is worse than one that fails to a safe state. Corrupted
        trip logic defeats the function silently; a dead logic solver is at least
        visible.
      * The three requirements are never all H. CVSS's weighting is RELATIVE, so
        raising everything raises nothing: it restores the base ordering at a
        higher multiplier and the ranking loses exactly the discrimination the
        metric exists to add. When all three would be High, the one the asset's
        mission depends on least is demoted to Medium - confidentiality on a
        process asset, availability on an information asset.

    Returns ({}, []) when no mission fact is stated, which leaves every
    requirement at CVSS "X" (multiplier 1.0) rather than inventing a posture.
    """
    dev = ctx.get("device_class")
    sil = (ctx.get("sil") or "").upper()
    safety = _t(ctx, "safety_function") is True or dev == "sis-logic-solver" \
        or sil in ("SIL2", "SIL3", "SIL4")
    avail = ctx.get("availability_tolerance")
    sens = ctx.get("data_sensitivity")
    level = str(ctx.get("purdue_level") or "")

    if not any((dev, avail, sens, level)) and not safety:
        return {}, []

    why = []
    if dev in _CLASS_REQ:
        cr, ir, ar = _CLASS_REQ[dev]
        why.append("CR:%s/IR:%s/AR:%s - starting point for a %s: %s"
                   % (cr, ir, ar, dev,
                      "it commands physical equipment, so a forged command and a "
                      "dead controller are both process events while setpoints are "
                      "rarely secret"
                      if dev in ("plc", "rtu", "ied", "sis-logic-solver") else
                      "it writes controller logic, so its integrity is a controller "
                      "integrity problem one step removed"
                      if dev in ("hmi", "engineering-workstation") else
                      "it is an information asset - the record is the value"
                      if dev == "historian" else
                      "it carries other assets' traffic, so availability dominates"))
    else:
        # No class stated. Start from the OT default rather than the IT one, and
        # say so, because an unstated class is not a reason to weight an ICS asset
        # like a web server.
        cr, ir, ar = "L", "H", "H"
        why.append("CR:L/IR:H/AR:H - no device class stated; defaulting to the OT "
                   "posture (integrity and availability over confidentiality) "
                   "rather than the IT one")

    # An explicitly stated tolerance or sensitivity is a fact about THIS asset and
    # outranks the class stereotype it was started from.
    if avail in _AVAIL_AR and _AVAIL_AR[avail] != ar:
        why.append("AR:%s - the process tolerates %s downtime, which the stated "
                   "tolerance settles more directly than the device class (was %s)"
                   % (_AVAIL_AR[avail], avail, ar))
        ar = _AVAIL_AR[avail]
    if sens in _SENS_CR and _SENS_CR[sens] != cr:
        why.append("CR:%s - data sensitivity on this asset is %s, which settles "
                   "the confidentiality requirement directly (was %s)"
                   % (_SENS_CR[sens], sens, cr))
        cr = _SENS_CR[sens]

    if safety:
        reason = ("it performs or protects a safety function"
                  if _t(ctx, "safety_function") is True else
                  "it is a safety logic solver" if dev == "sis-logic-solver"
                  else "it carries %s" % sil)
        if ir != "H" or ar != "H":
            why.append("IR:H/AR:H - %s. Availability is obvious (no function, no "
                       "protection); integrity matters as much, because a safety "
                       "function that keeps running on forged values defeats the "
                       "protection silently, where a dead one fails visibly."
                       % reason)
        ir, ar = "H", "H"

    # Never all three High - see the docstring.
    if cr == ir == ar == "H":
        information = (level in _INFORMATION_LEVELS
                       or (not level and dev in ("historian", "engineering-workstation")))
        if information:
            why.append("AR:M - all three requirements came out High, which flattens "
                       "the ranking back to the base order. This asset's mission is "
                       "informational, so availability is the one it depends on "
                       "least and is demoted.")
            ar = "M"
        else:
            why.append("CR:M - all three requirements came out High, which flattens "
                       "the ranking back to the base order. This is a process asset, "
                       "so confidentiality is the one its mission depends on least "
                       "and is demoted.")
            cr = "M"

    # Purdue level only breaks a tie the stated facts left open; it never
    # overrides a fact, because a zone is where a thing sits, not what it does.
    if not avail and not safety and level in _PROCESS_LEVELS and ar == "M":
        why.append("AR:H - no tolerance was stated, and a Level-%s asset is in the "
                   "process path where downtime is a process event" % level)
        ar = "H"

    return {"CR": cr, "IR": ir, "AR": ar}, why


# --- evaluating one CVSS precondition against the context --------------------
# Each entry returns (outcome, reason). Only IMPOSSIBLE may lead to
# not_affected, and only ever from a STRUCTURAL fact.

def _eval_av_n(ctx):
    if _t(ctx, "net_interface_present") is False:
        return IMPOSSIBLE, ("no network interface is fitted to this asset, so there "
                            "is no channel a network-borne exploit could ride")
    if _t(ctx, "sole_path_hardware_diode") is True:
        return IMPOSSIBLE, ("the asset's only network path is a hardware "
                            "unidirectional gateway, which has no inbound circuit")
    exp = ctx.get("network_exposure")
    if exp in ("remote-accessible", "dmz-routable"):
        return SATISFIED, "the asset is reachable from a routable network (%s)" % exp
    if exp in ("control-network", "isolated-cell"):
        return MITIGATED, ("the asset is only reachable from within the %s; "
                           "segmentation is a configuration, so it lowers priority "
                           "but cannot clear the CVE" % exp)
    if _t(ctx, "host_firewall") is True:
        return MITIGATED, "a firewall filters the affected service (a configuration)"
    if _t(ctx, "net_interface_present") is True:
        return UNKNOWN, "an interface exists but its exposure was not stated"
    return UNKNOWN, "network exposure not stated"


def _eval_av_a(ctx):
    nic = _t(ctx, "net_interface_present")
    radio = _t(ctx, "radio_hardware_present")
    if nic is False and radio is False:
        return IMPOSSIBLE, ("neither a network interface nor radio hardware is "
                            "fitted, so there is no adjacent-network channel")
    if radio is False and nic is None:
        return UNKNOWN, ("no radio is fitted, but whether a wired adjacent path "
                         "exists was not stated")
    if ctx.get("network_exposure") == "isolated-cell":
        return MITIGATED, ("the adjacent segment is an isolated cell, which "
                           "shrinks but does not remove the adjacency")
    if nic is True or radio is True:
        return SATISFIED, "the asset shares a segment or radio space with other devices"
    return UNKNOWN, "adjacency not stated"


def _eval_av_l(ctx):
    if _t(ctx, "local_execution_possible") is False:
        return IMPOSSIBLE, ("nothing can be executed locally on this asset - no "
                            "console, no shell and no user-loadable logic")
    if _t(ctx, "app_allowlisting") is True:
        return MITIGATED, "application allowlisting / signed code is enforced (a configuration)"
    if _t(ctx, "local_execution_possible") is True:
        return SATISFIED, "local execution is possible on this asset"
    return UNKNOWN, "local execution capability not stated"


def _eval_av_p(ctx):
    acc = ctx.get("physical_port_access")
    if acc == "sealed-structural":
        return IMPOSSIBLE, ("the physical/maintenance ports are potted or "
                            "de-populated on this variant, so there is nothing to "
                            "connect to")
    if acc == "sealed-policy":
        return MITIGATED, ("the ports are closed by a seal or procedure, which an "
                           "authorised change can reopen")
    if _t(ctx, "cabinet_locked") is True or _t(ctx, "removable_media_blocked") is True:
        return MITIGATED, "physical access is governed by access control or media policy"
    if acc == "open":
        return SATISFIED, "the physical and maintenance ports are accessible"
    return UNKNOWN, "physical port access not stated"


def _eval_privilege(ctx, level):
    sub = ctx.get("account_subsystem")
    if sub == "none":
        return IMPOSSIBLE, ("the affected interface has no account model at all, so "
                            "an attacker cannot hold the %s account this CVE "
                            "requires. NOTE: the same fact makes any "
                            "unauthenticated CVE on this asset worse"
                            % ("administrative" if level == "H" else "user"))
    if level == "H" and sub == "single-fixed":
        return MITIGATED, ("the asset has a single fixed account; whether it carries "
                           "administrative privilege is a configuration matter")
    if _t(ctx, "auth_enforced") is True:
        return MITIGATED, ("authentication is enforced, so the attacker must first "
                           "obtain credentials - a control, not an impossibility")
    if sub == "multi-user":
        return SATISFIED, "the asset has a multi-user account model with obtainable accounts"
    return UNKNOWN, "account model not stated"


def _eval_ui_r(ctx):
    io = _t(ctx, "interactive_operator")
    if io is False:
        return IMPOSSIBLE, ("no human acts on content on this asset (it is a "
                            "headless controller), so the user interaction this CVE "
                            "requires cannot occur")
    if io is True:
        return SATISFIED, "an operator works on this asset and can be induced to act"
    return UNKNOWN, "whether an interactive operator uses this asset was not stated"


def _eval_ac_h(ctx):
    # Deliberately never refutable. AC:H is a statement about the attacker's luck
    # and reconnaissance, not about the asset, so no asset fact can rule it out.
    return UNKNOWN, ("AC:H describes a condition outside the attacker's control "
                     "(a race window, a specific configuration); deployment facts "
                     "cannot refute it, so it is recorded as evidence only")


_EVAL = {
    "AV:N": _eval_av_n, "AV:A": _eval_av_a, "AV:L": _eval_av_l, "AV:P": _eval_av_p,
    "PR:L": lambda c: _eval_privilege(c, "L"), "PR:H": lambda c: _eval_privilege(c, "H"),
    "ACCOUNT:REQUIRED": lambda c: _eval_privilege(c, "L"),
    "UI:R": _eval_ui_r, "AC:H": _eval_ac_h,
}


def evaluate(precondition, ctx):
    """(outcome, reason) for one precondition id against the context."""
    fn = _EVAL.get(precondition)
    if not fn:
        return UNKNOWN, "no evaluation rule for %s" % precondition
    return fn(ctx)


def active_mitigations(ctx):
    """The controls currently in force, as CSAF-exportable mitigation details.

    These accompany an `affected` statement. They are never a justification -
    `inline_mitigations_already_exist` is for mitigations the SUPPLIER built into
    the product, and an operator's firewall is not one.
    """
    out = []
    checks = [
        ("host_firewall", True, "a host or in-line firewall filters the affected service"),
        ("software_unidirectional", True, "communication is restricted to one direction in software"),
        ("auth_enforced", True, "authentication is enforced on the affected interface"),
        ("transport_encrypted", True, "traffic to the affected service is encrypted and authenticated"),
        ("app_allowlisting", True, "application allowlisting / signed-code enforcement is active"),
        ("removable_media_blocked", True, "removable media and maintenance devices are blocked by policy"),
        ("cabinet_locked", True, "the asset is in a locked cabinet or access-controlled area"),
        ("work_approval", True, "work on the asset requires prior approval"),
        ("vendor_remote_access", False, "vendor remote access is not permitted"),
    ]
    for key, want, text in checks:
        if _t(ctx, key) is want:
            out.append({"control": key, "detail": text})
    exp = ctx.get("network_exposure")
    if exp in ("control-network", "isolated-cell"):
        out.append({"control": "network_exposure",
                    "detail": "the asset is segmented into a %s" % exp})
    if ctx.get("physical_port_access") == "sealed-policy":
        out.append({"control": "physical_port_access",
                    "detail": "maintenance ports are closed by seal or procedure"})
    return out


if __name__ == "__main__":
    headless = {"net_interface_present": True, "radio_hardware_present": False,
                "sole_path_hardware_diode": False, "physical_port_access": "open",
                "interactive_operator": False, "local_execution_possible": False,
                "account_subsystem": "none", "network_exposure": "isolated-cell"}
    for p in ("AV:N", "AV:A", "AV:L", "AV:P", "PR:L", "UI:R", "AC:H"):
        o, r = evaluate(p, headless)
        print("%-16s %-10s %s" % (p, o, r[:92]))
    print("\nthreat:", derive_threat({"kev": True}, {"vendor_fix": 1}))
    print("modified base:", derive_modified_base(headless, {"C": "H", "A": "H"})[0])
    print("mitigations:", [m["control"] for m in active_mitigations(headless)])
