#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ground-truth construction (v3, evidence-tier based).

The governing principle: a verdict never exceeds the strength of the evidence
obtained for it.

  The evidence tier comes from the `tier` column of findings.csv, which
  build_reverse_sbom.py writes as the SBOM attribute
  `component:source-availability`. It states exactly how obtainable the source is.

    tier A  source obtained (OSS, with a vulnerable/patched code pair)
              -> with an execution-verification result: AFFECTED / NOT_AFFECTED
              -> without one: UNDER_INVESTIGATION (awaiting verification)
    tier C  an OSS component whose code was not collected -> UNDER_INVESTIGATION
    tier E  closed vendor firmware, source unobtainable   -> UNDER_INVESTIGATION

  So the primary status (vex_status) is conclusive only where the source was
  obtained AND execution verification succeeded; everything else is
  UNDER_INVESTIGATION.

Model routing (`route`) - source availability decides the pipeline path:

    tier A       SecureBERT -> CodeBERT -> sLLM / execution verification.
                 There is code to compare against, so it is handed to the code leg
                 and a conclusive verdict is attempted.
    tier C / E   Ends at SecureBERT. With no code to compare against it is not
                 handed to CodeBERT - CodeBERT output produced without the code has
                 no grounds and yields only false positives.

Secondary VEX estimate (estimated_status):
  For records whose primary status is UNDER_INVESTIGATION, reachability is computed
  from the only signals obtainable - the CVSS Attack Vector and deployment exposure -
  and the status is ESTIMATED. This is not a VEX statement, and it ships with
  estimate_confidence alongside. The training target (`label`) is the conclusive
  value where one exists and this estimate otherwise.

Justification:
  Uses the five controlled not_affected justifications of CSAF VEX / OpenVEX:
    component_not_present
    vulnerable_code_not_present
    vulnerable_code_not_in_execute_path
    vulnerable_code_cannot_be_controlled_by_adversary
    inline_mitigations_already_exist
  The standard defines no justification vocabulary for `affected` (its fields are
  impact_statement / action_statement), so the five above are inverted into a
  matching vocabulary carried as an extension, with the standard fields filled in
  as well. The `justification_vocabulary` field tells the two apart.

Removed since v2 - everything that was synthesised without grounds:
  - neg_evidence(): invented patched / component-absent / version-out-of-range /
    function-disabled from a hash. Deleted, since there was no actual evidence.
  - the hash-based vague tail: replaced by records whose AV really is unstated
    (av == "").
  - annotator noise: no longer applied to execution-verified records, only to
    estimates - analysts differ over estimates, not over facts.

Still synthetic, stated as such:
  - exposure: deployment exposure. Real plant-network information is not in public
    data. Marked with structured.exposure_synthetic = true.

Output: data/vex_dataset.jsonl
"""
import csv
import hashlib
import json
import os
import sys

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
FIND = os.path.join(BASE, "data", "findings.csv")
CODE_EV = os.path.join(BASE, "data", "code_evidence.json")
EXEC_PY = os.path.join(BASE, "results", "exec_verification.json")
EXEC_C = os.path.join(BASE, "results", "exec_verification_c.json")
EXEC_BATCH = os.path.join(BASE, "results", "exec_verification_batch.json")
OUT = os.path.join(BASE, "data", "vex_dataset.jsonl")
# The subset for the code leg (OSS-attributed = tier A of tier A/C). Whether the code
# is actually held is carried per record in code_evidence_available.
OUT_CODE = os.path.join(BASE, "data", "vex_dataset_code.jsonl")
# Only what execution verification settled - the real ground truth
OUT_GT = os.path.join(BASE, "data", "vex_ground_truth.jsonl")

AFFECTED = "LIKELY_AFFECTED"
NOT_AFFECTED = "LIKELY_NOT_AFFECTED"
UNDER_INV = "UNDER_INVESTIGATION"

# The tier from findings.csv. Its SBOM attribute is called component:source-availability,
# but what it actually states is "was this CVE attributed to the OSS catalogue"
# (build_reverse_sbom.py:202), which is not the same as holding the code.
TIER_DESC = {"A": "oss-attributed", "C": "oss-inferred", "E": "vendor-proprietary"}

# Model routing - source availability decides the pipeline path.
#   source present (tier A) : SecureBERT -> CodeBERT -> sLLM / execution verification
#                             (a conclusive verdict is possible)
#   source absent (tier C/E): ends at SecureBERT and is not handed to the code leg -
#                             with no code to compare against, CodeBERT only emits
#                             output that has no grounds.
ROUTE_CODE = "securebert->codebert->sllm"
ROUTE_CONTEXT_ONLY = "securebert-only"
# The 2026-08 move to static analysis: the live pipeline (src/vex_pipeline.py) neither
# generates nor runs a PoC, and settles VEX purely by static analysis (an sLLM static
# analyst plus a grounding critic). The sllm-static-analyst label below is that path.
# The 5 historical execution-verified records are kept as a historical conclusive tier
# only, on the strength of the measurements in results/exec_verification*.json.
ROUTE_STAGES = {
    ROUTE_CODE: ["securebert", "codebert", "sllm-static-analyst"],
    ROUTE_CONTEXT_ONLY: ["securebert"],
}

# The five controlled not_affected justifications of CSAF VEX / OpenVEX
JUSTIFY_NOT_AFFECTED = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}
# The matching vocabulary for `affected` (an extension - the five above, inverted)
JUSTIFY_AFFECTED = {
    "component_present",
    "vulnerable_code_present",
    "vulnerable_code_in_execute_path",
    "vulnerable_code_controllable_by_adversary",
    "no_inline_mitigations",
}

EXPOSURES = ["isolated-cell", "control-network", "dmz-routable", "remote-accessible"]

# Exposure paraphrases - same meaning, varied wording
EXP_POOL = {
    "isolated-cell": [
        "The asset sits in an air-gapped cell with no routable link to other networks.",
        "This equipment is fully segmented; nothing outside the local cabinet can address it.",
        "Deployed standalone behind a hard network break, unreachable from any routed segment.",
        "The unit operates islanded, with no IP path in from plant or enterprise networks.",
    ],
    "control-network": [
        "It resides on the OT control LAN, addressable only by peers already inside that segment.",
        "Reachable strictly from within the process control network, not from outside it.",
        "The device answers only to hosts that already have a foothold on the control network.",
        "Confined to the supervisory control subnet with no direct external routing.",
    ],
    "dmz-routable": [
        "The device is reachable across the industrial DMZ from the enterprise boundary.",
        "Routed paths reach this unit from the corporate edge through the OT DMZ.",
        "Exposed via the plant DMZ, so enterprise-side hosts can open sessions to it.",
        "Sessions can be initiated from the business network through the DMZ to this device.",
    ],
    "remote-accessible": [
        "The unit is reachable remotely, including through vendor remote-support tunnels.",
        "Remote operators and third-party maintenance links can reach this device directly.",
        "Internet-adjacent management paths expose this equipment to remote sessions.",
        "The device accepts connections from remote and enterprise-wide origins.",
    ],
}
# Attack-surface prose: it implies the AV rather than stating it
AV_POOL = {
    "N": [
        "A remote actor can trigger the flaw by sending crafted traffic to a listening service.",
        "The weakness is driven through network messages accepted by an exposed interface.",
        "Exploitation proceeds over the wire against a service the device publishes.",
        "Malformed protocol input from across the network reaches the vulnerable routine.",
    ],
    "A": [
        "An attacker sharing the local link layer can steer the device into the fault.",
        "Triggering it requires a foothold on the same broadcast segment as the target.",
        "The path opens only to an adjacent station on the same physical network.",
        "It is reachable from a neighbor on the local segment, not from routed distance.",
    ],
    "L": [
        "Reaching the flaw first requires an authenticated session or shell on the device.",
        "The issue is driven by an already-logged-in local user, not from the network.",
        "Prior local access to the unit is a precondition for triggering it.",
        "Only a party with an existing account on the device can exercise the path.",
    ],
    "P": [
        "The fault can only be reached by someone with hands-on physical access.",
        "Triggering requires direct physical manipulation of the hardware.",
        "The path opens solely at the console or physical ports of the device.",
        "Exploitation demands bodily access to the equipment itself.",
    ],
    "": [
        "The precise conditions needed to reach the flaw are not clearly documented.",
        "How an attacker would drive this weakness is not spelled out in the source material.",
        "The advisory does not state how an attacker would reach this weakness.",
        "No attack-surface description accompanies this entry in the source advisory.",
    ],
}
KEV_POOL = [
    "This weakness is being exploited in live campaigns right now.",
    "It appears on the catalog of vulnerabilities known to be exploited in the wild.",
    "Threat actors are actively leveraging this issue against deployed systems.",
]
KEVNEG_POOL = [
    "No confirmed in-the-wild exploitation has been reported to date.",
    "There is no evidence yet that this issue is being used in real attacks.",
    "Active exploitation of this weakness has not been observed.",
]
PRESENT_POOL = [
    "The affected component ships in the running firmware build.",
    "This build includes the vulnerable module in its active image.",
    "The impacted software is compiled into the deployed firmware.",
]
# The fact that the SBOM records component versions as NOASSERTION (a real property
# of this data)
VERSION_UNKNOWN_POOL = [
    "The inventory records no version for this component, so the affected range cannot be checked.",
    "No version string is asserted for this module in the bill of materials.",
    "The build inventory leaves this component's release unspecified.",
    "Version information for the module is absent from the recorded inventory.",
]
# Source unobtainable (tier E - closed vendor firmware)
SRC_UNAVAIL_POOL = [
    "The vendor ships this module as closed firmware, so its source cannot be obtained for inspection.",
    "No source is retrievable for this proprietary component; only the binary image is distributed.",
    "This part of the stack is vendor-proprietary and its code is unavailable for review.",
    "The supplier does not publish source for this module, blocking any code-level check.",
]
# OSS, but the code was not collected (tier C)
SRC_PENDING_POOL = [
    "The component is open source, but no vulnerable or fixed code has been retrieved for it yet.",
    "Upstream code exists for this module, though none has been collected for comparison here.",
    "This is an open component, yet the relevant patch material has not been gathered.",
    "Source is in principle obtainable for this module, but nothing has been pulled down so far.",
]
# Code held, awaiting execution verification (tier A, unverified)
SRC_AVAIL_POOL = [
    "Vulnerable and fixed source for this module has been obtained, but it has not been executed.",
    "Both the flawed and corrected code are on hand; no run-time trigger has been attempted.",
    "The relevant source pair is available, awaiting an execution test to settle the question.",
    "Code for both states of this module is collected, with dynamic confirmation still outstanding.",
]
# Execution-verification results
EXEC_AFF_POOL = [
    "Running the recorded trigger against this build reproduced the fault under a sanitizer.",
    "A controlled execution of the module drove it into the documented failure state.",
    "The flaw was reproduced by executing the collected trigger against this code.",
    "Dynamic testing of the module produced the expected crash signature.",
]
EXEC_NOT_POOL = [
    "Executing the same trigger against this build produced no fault, unlike the flawed release.",
    "The corrected code withstood the recorded trigger without entering the failure state.",
    "A run against this build failed to reproduce the fault that the flawed release exhibits.",
    "Dynamic testing showed the vulnerable path is no longer reachable in this code.",
]

CWE_NAME = {
    "CWE-78": "OS command injection", "CWE-79": "cross-site scripting", "CWE-89": "SQL injection",
    "CWE-119": "memory buffer error", "CWE-120": "buffer copy without size check",
    "CWE-121": "stack-based buffer overflow", "CWE-122": "heap-based buffer overflow",
    "CWE-125": "out-of-bounds read", "CWE-190": "integer overflow", "CWE-200": "information exposure",
    "CWE-269": "improper privilege management", "CWE-287": "improper authentication",
    "CWE-295": "improper certificate validation", "CWE-306": "missing authentication",
    "CWE-311": "missing encryption", "CWE-327": "broken crypto algorithm",
    "CWE-352": "cross-site request forgery", "CWE-362": "race condition",
    "CWE-400": "uncontrolled resource consumption", "CWE-401": "memory leak",
    "CWE-416": "use after free", "CWE-434": "unrestricted file upload",
    "CWE-476": "null pointer dereference", "CWE-502": "deserialization of untrusted data",
    "CWE-787": "out-of-bounds write", "CWE-798": "hard-coded credentials",
    "CWE-862": "missing authorization", "CWE-863": "incorrect authorization",
}


def h(*p):
    return int(hashlib.sha256("::".join(map(str, p)).encode()).hexdigest(), 16)


def pick(pool, *seed):
    return pool[h(*seed) % len(pool)]


# ------------------------------------------------------------- loading evidence

def load_exec_verification():
    """Normalise execution-verification results into a CVE -> verdict map.

    Both harnesses are read:
      results/exec_verification.json    (Python libraries, isolated pip install)
      results/exec_verification_c.json  (C libraries, WSL + AddressSanitizer)

    When a new CVE is verified, adding it to that file is enough to promote the
    corresponding findings to the conclusive tier. No code change is needed.
    """
    out = {}
    # Results from the batch runner (src/exec_verify_batch.py). Only settled verdicts
    # are taken - NEEDS_TRIGGER, BUILD_FAILED and the like are job states, not evidence.
    if os.path.exists(EXEC_BATCH):
        for e in json.load(open(EXEC_BATCH, encoding="utf-8")):
            if e.get("verdict") not in ("EXPLOITABLE", "NOT_TRIGGERED"):
                continue
            out[e["cve"]] = {
                "exploitable": bool(e.get("vuln_crash")),
                "discriminates": bool(e.get("vuln_crash")) and not e.get("patched_crash"),
                "vuln_version": e.get("vuln_version"), "patched_version": e.get("patched_version"),
                "component": e.get("component", ""),
                "signal": e.get("signal", ""),
                "method": e.get("method", "build vuln vs patched, execute trigger"),
            }
    if os.path.exists(EXEC_PY):
        for e in json.load(open(EXEC_PY, encoding="utf-8")):
            vuln_v = patched_v = None
            exploitable = False
            for v in e.get("versions", []):
                if v.get("triggered"):
                    vuln_v = v.get("version")
                    exploitable = True
                else:
                    patched_v = v.get("version")
            out[e["cve"]] = {
                "exploitable": exploitable,
                "discriminates": bool(e.get("discriminates")),
                "vuln_version": vuln_v, "patched_version": patched_v,
                "component": e.get("package", ""),
                "signal": "; ".join(sorted({s for v in e.get("versions", [])
                                            for s in v.get("evidence", [])})),
                "method": "isolated pip install + subprocess execution",
            }
    if os.path.exists(EXEC_C):
        for e in json.load(open(EXEC_C, encoding="utf-8")):
            out[e["cve"]] = {
                "exploitable": bool(e.get("vuln_crash")),
                "discriminates": bool(e.get("vuln_crash")) and not e.get("patched_crash"),
                "vuln_version": e.get("vuln_version"), "patched_version": e.get("patched_version"),
                "component": e.get("component", ""),
                "signal": e.get("signal", ""),
                "method": e.get("method", "build vuln vs patched, execute trigger"),
            }
    return out


def load_code_available():
    """The set of CVEs for which a vulnerable/patched code pair is actually held."""
    if not os.path.exists(CODE_EV):
        return set()
    ce = json.load(open(CODE_EV, encoding="utf-8"))
    return {k for k, v in ce.items()
            if isinstance(v, dict) and v.get("vuln_code") and v.get("patched_code")}


# ------------------------------------------- deployment context (synthetic)

def exposure_for(device):
    """Deployment exposure. Synthesised, because real plant-network information is not
    in public data. Sampled deterministically (by a hash of the device) from a prior
    distribution per device class."""
    d = device.lower()
    if any(k in d for k in ("plc", "rtu", "relay", "controller", "safety", "ied", "drive")):
        w = [0.42, 0.34, 0.16, 0.08]
    elif any(k in d for k in ("gateway", "firewall", "router", "switch", "vpn", "remote")):
        w = [0.05, 0.20, 0.40, 0.35]
    elif any(k in d for k in ("scada", "hmi", "historian", "server", "workstation", "engineering")):
        w = [0.10, 0.34, 0.34, 0.22]
    else:
        w = [0.25, 0.30, 0.28, 0.17]
    r = (h("exp", device) % 1000) / 1000.0
    acc = 0.0
    for e, wi in zip(EXPOSURES, w):
        acc += wi
        if r <= acc:
            return e
    return EXPOSURES[-1]


# ------------------------------------------- primary verdict (evidence-based)

def exec_verdict(exec_rec):
    """An execution-verification record -> (status, basis), or (None, None) when it
    settles nothing.

    The same rule as adjudicate()'s layer 1, split out so that callers without version
    information (vex_batch and friends) can use it too.
    """
    if not (exec_rec and exec_rec.get("discriminates")):
        return (None, None)
    sig = exec_rec.get("signal") or "documented failure state"
    return (AFFECTED,
            "execution-verified: the recorded trigger reproduced the fault (%s)" % sig)


def adjudicate(tier, has_code, exec_rec, version_asserted, upstream=None):
    """The primary VEX status, decided from the obtained evidence alone.

    Careful - findings.csv's `tier` is named component:source-availability in the SBOM,
    but all it actually states is "was this CVE attributed to the OSS catalogue"
    (build_reverse_sbom.py:202). Of the 132 CVEs at tier=="A", only 15 actually hold a
    vulnerable/patched code pair, so entry to the code leg is decided by `has_code`
    (actually present in code_evidence.json), never by the tier letter.

    Returns: (status, justification, justification_vocabulary,
           impact_statement, action_statement, evidence_tier, detail)
    """
    # --- layer 0: upstream (CISA CSAF) already adjudicated it ----------------
    # CISA or the vendor stated the justification via flags[].label. We did not derive
    # it, so evidence_tier keeps it separate and it can be excluded when measuring our
    # own adjudication performance.
    if upstream:
        return (NOT_AFFECTED, upstream, "csaf-openvex",
                "CISA CSAF asserts this product is not affected (%s)." % upstream,
                "No action required; upstream vendor/CISA assertion.",
                "upstream-asserted",
                {"upstream_source": "cisa-csaf", "derived_here": False})

    # --- layer 1: execution verification completed --------------------------
    if exec_rec and exec_rec["discriminates"]:
        sig = exec_rec["signal"] or "documented failure state"
        if version_asserted and version_asserted == exec_rec.get("patched_version"):
            return (NOT_AFFECTED, "vulnerable_code_not_present", "csaf-openvex",
                    "The corrected code is deployed; the recorded trigger does not reproduce the fault.",
                    "No action required for this component version.",
                    "execution-verified",
                    {"exec_method": exec_rec["method"], "exec_signal": sig,
                     "version_basis": "asserted", "version_unconfirmed": False})
        # Either the version was asserted to be the vulnerable one, or the SBOM does not
        # state a version at all. The latter assumes the vulnerable build, on the ICS
        # safety-first principle (fail-safe).
        unconfirmed = not version_asserted
        return (AFFECTED, "vulnerable_code_present", "extension",
                "Execution of the recorded trigger reproduced the fault (%s)." % sig,
                "Upgrade the component to the fixed release, or apply the vendor mitigation.",
                "execution-verified",
                {"exec_method": exec_rec["method"], "exec_signal": sig,
                 "version_basis": "assumed-vulnerable" if unconfirmed else "asserted",
                 "version_unconfirmed": unconfirmed})

    # --- layer 2: code actually held, execution not verified -----------------
    if has_code:
        return (UNDER_INV, None, None, None, None, "source-available-unverified",
                {"blocker": "source obtained but no execution result recorded for this CVE"})

    # --- layer 3: OSS-attributed but the code was not collected --------------
    if tier in ("A", "C"):
        return (UNDER_INV, None, None, None, None, "source-pending",
                {"blocker": "component is open source but no vulnerable/fixed code pair has been collected",
                 "oss_attributed": True})

    # --- layer 4: closed vendor firmware -------------------------------------
    return (UNDER_INV, None, None, None, None, "source-unavailable",
            {"blocker": "vendor-proprietary firmware; source cannot be obtained"})


# ---------------- secondary estimate (AV x exposure, when nothing is conclusive)

# The reachability estimate (CVSS AV x deployment exposure) was removed.
#
# Why - exposure in this pipeline was synthetic throughout (rnd.choice), and
# reachability cannot be grounds for a VEX status, so it was only being passed through
# as an estimation subfield. But an estimate derived from synthetic input is not a claim
# about any real asset, and the moment it appears on screen as a number it misleads. So
# the axis was removed outright.
#
# Operational context enters through SSVC only - its System Exposure is not synthetic
# but a value the user picks for their own deployment.


# ------------------------------------------------------------- text rendering

# Only the sentence kinds that causally decide the training target (label) are marked as
# grounds. kev / epss / severity change the status on no path, so they are excluded.
DRIVER_EXEC = {"exec_affected", "exec_not_affected"}
# The sentences that decide the primary status (vex_status), for primary_rationale_ids.
# A conclusive record is grounded in the execution-verification sentence; an inconclusive
# one in the sentence about the source being unobtainable.
DRIVER_PRIMARY = ({"src_unavailable", "src_pending", "src_available", "version_unknown"}
                  | DRIVER_EXEC)


def render(device, vendor, product, cve, cwe, av, sev, epss, kev,
           exposure, has_code, oss_attributed, exec_rec, exec_status):
    S = []

    def add(txt, kind, eid):
        S.append({"id": eid, "text": txt, "kind": kind})

    cwe_name = CWE_NAME.get(cwe, (cwe or "an unspecified weakness"))
    sevw = {"critical": "critical-severity", "high": "high-severity",
            "medium": "moderate-severity", "low": "low-severity"}.get(sev, "unrated")
    add("%s is a %s %s issue (%s)." % (cve, sevw, cwe_name, cwe or "CWE-unknown"), "cve_desc", "CVE-1")
    # Attack surface, implied rather than stated. av == "" gives the 'not stated' sentence.
    add(pick(AV_POOL.get(av, AV_POOL[""]), "av", device, cve),
        "av" if av else "av_unstated", "CVE-2")
    add(pick(KEV_POOL if kev else KEVNEG_POOL, "kev", device, cve),
        "kev" if kev else "kev_neg", "CVE-3")
    if epss is not None:
        add("Statistical models put its near-term exploitation likelihood around %.2f." % epss,
            "epss", "CVE-4")

    add("Asset: %s %s." % (vendor, product), "product", "ASSET-1")
    add(pick(EXP_POOL[exposure], "exp", device), "exposure", "ASSET-2")
    add(pick(PRESENT_POOL, "pres", device, cve), "present", "ASSET-3")
    # The actual fact that the SBOM records the version as NOASSERTION
    add(pick(VERSION_UNKNOWN_POOL, "ver", device, cve), "version_unknown", "ASSET-4")

    # Source-availability state
    if has_code:
        if exec_rec is None:
            add(pick(SRC_AVAIL_POOL, "src", device, cve), "src_available", "SRC-1")
    elif oss_attributed:
        add(pick(SRC_PENDING_POOL, "src", device, cve), "src_pending", "SRC-1")
    else:
        add(pick(SRC_UNAVAIL_POOL, "src", device, cve), "src_unavailable", "SRC-1")

    # Execution-verification result (only where it settled the verdict)
    if exec_status == AFFECTED:
        add(pick(EXEC_AFF_POOL, "exec", device, cve), "exec_affected", "EXEC-1")
    elif exec_status == NOT_AFFECTED:
        add(pick(EXEC_NOT_POOL, "exec", device, cve), "exec_not_affected", "EXEC-1")
    return S


# --------------------------------------------------------------------- main

def main():
    exec_map = load_exec_verification()
    code_cves = load_code_available()
    print("execution-verified CVEs : %d %s" % (len(exec_map), sorted(exec_map)))
    print("CVEs with code held     : %d" % len(code_cves))

    rows = list(csv.DictReader(open(FIND, encoding="utf-8-sig")))
    n = 0
    tiers = {}
    prim = {}
    labels = {}
    routes = {}
    n_code = n_gt = 0
    with open(OUT, "w", encoding="utf-8") as out, \
            open(OUT_CODE, "w", encoding="utf-8") as out_code, \
            open(OUT_GT, "w", encoding="utf-8") as out_gt:
        for r in rows:
            device, vendor, product = r["device"], r["vendor"], r["product"]
            cve, cwe, tier = r["cve"], r["cwe"], r["tier"]
            av, sev = r["av"], r["severity"]
            av_source = r.get("av_source", "")
            kev = r["kev"] == "True"
            epss = float(r["epss"]) if r["epss"] not in ("", None) else None
            exposure = exposure_for(device)
            exec_rec = exec_map.get(cve)

            # The SBOM records every component version as NOASSERTION, so there is no
            # confirmed version. Once real versions are filled in, read them here and
            # pass them to adjudicate().
            version_asserted = None

            # Entry to the code leg is decided by actually holding the code, not by the
            # tier letter.
            has_code = cve in code_cves
            oss_attributed = tier in ("A", "C")

            (status, just, vocab, impact, action,
             ev_tier, detail) = adjudicate(tier, has_code, exec_rec, version_asserted,
                                           upstream=(r.get("upstream_justification") or "").strip() or None)

            # Only a record with code to compare against is sent to the code leg
            # (CodeBERT -> sLLM).
            route = ROUTE_CODE if has_code else ROUTE_CONTEXT_ONLY

            # The training target is the evidence-based status itself. No label is
            # manufactured from an estimate.
            clean_label = label = status
            gold_kinds = DRIVER_EXEC

            sents = render(device, vendor, product, cve, cwe, av, sev, epss, kev,
                           exposure, has_code, oss_attributed, exec_rec,
                           status if ev_tier == "execution-verified" else None)

            rec = {
                "sampleId": "S%06d" % n, "device": device, "cve": cve,
                "arm": r["arm"], "tier": tier,

                # --- primary: the evidence-based VEX statement (standard-compatible) ---
                "vex_status": status,
                "justification": just,
                "justification_vocabulary": vocab,   # csaf-openvex | extension | None
                "impact_statement": impact,
                "action_statement": action,
                "evidence_tier": ev_tier,            # execution-verified | source-available-unverified
                                                     # | source-pending | source-unavailable
                "evidence_detail": detail,
                "source_availability": TIER_DESC.get(tier, "unknown"),
                "code_evidence_available": has_code,   # a vuln/patched pair is held
                "oss_attributed": oss_attributed,      # attributed to the OSS catalogue (tier A/C)

                # --- model routing (source availability decides the path) ---
                "route": route,
                "route_stages": ROUTE_STAGES[route],
                "route_terminal_model": "codebert" if route == ROUTE_CODE else "securebert",

                # --- training target ---
                "label": label,                      # the conclusive value, else the estimate
                "clean_label": clean_label,          # before annotator noise
                "label_source": ("upstream-cisa-csaf" if ev_tier == "upstream-asserted"
                                 else "execution" if ev_tier == "execution-verified"
                                 else "evidence-tier"),

                "sentences": sents,
                "gold_rationale_ids": [s["id"] for s in sents if s["kind"] in gold_kinds],
                "primary_rationale_ids": [s["id"] for s in sents if s["kind"] in DRIVER_PRIMARY],

                "structured": {
                    "av": av, "av_source": av_source, "exposure": exposure,
                    "kev": kev, "epss": epss, "severity": sev,
                    "version_asserted": version_asserted,
                    "source_availability": tier,
                    "exposure_synthetic": True,       # deployment exposure is synthetic
                    "neg": "", "vague": (av == ""),   # v2 compatibility fields
                },
            }
            line = json.dumps(rec, ensure_ascii=False) + "\n"
            out.write(line)
            if tier == "A":
                out_code.write(line)
                n_code += 1
            if ev_tier == "execution-verified":
                out_gt.write(line)
                n_gt += 1
            n += 1
            tiers[ev_tier] = tiers.get(ev_tier, 0) + 1
            prim[status] = prim.get(status, 0) + 1
            labels[label] = labels.get(label, 0) + 1
            routes[route] = routes.get(route, 0) + 1

    print("\nsamples: %d" % n)
    print("\n[evidence tier]")
    for k in ("execution-verified", "source-available-unverified", "source-pending", "source-unavailable"):
        if k in tiers:
            print("  %-30s %6d (%5.2f%%)" % (k, tiers[k], 100 * tiers[k] / n))
    print("\n[model routing - decided by source availability]")
    for k in (ROUTE_CODE, ROUTE_CONTEXT_ONLY):
        if k in routes:
            print("  %-30s %6d (%5.2f%%)" % (k, routes[k], 100 * routes[k] / n))
    print("\n[primary VEX statement - evidence-based]")
    for k in (AFFECTED, NOT_AFFECTED, UNDER_INV):
        print("  %-22s %6d (%5.2f%%)" % (k, prim.get(k, 0), 100 * prim.get(k, 0) / n))
    print("\n[training target label - conclusive value plus estimate]")
    for k in (AFFECTED, NOT_AFFECTED, UNDER_INV):
        print("  %-22s %6d (%5.2f%%)" % (k, labels.get(k, 0), 100 * labels.get(k, 0) / n))
    print("\n[output]")
    print("  %-46s %6d" % (os.path.relpath(OUT, BASE), n))
    print("  %-46s %6d  (OSS-attributed tier A - code-leg candidates)"
          % (os.path.relpath(OUT_CODE, BASE), n_code))
    print("  %-46s %6d  (settled by execution verification - the real ground truth)"
          % (os.path.relpath(OUT_GT, BASE), n_gt))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
