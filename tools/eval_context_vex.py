#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Measure the context arm over the whole corpus, per asset archetype.

Why archetypes rather than real assets: the measured corpus carries operational
context for 0% of its 3,845 assets (problem W9), so there is no real context to
run against. Inventing one asset's attributes and reporting the result as "the
method's accuracy" would be the synthetic-estimate mistake the old AV x exposure
branch was removed for.

What CAN be measured honestly is the method's SENSITIVITY: given a realistic
asset profile, how much of the real identified CVE population does the complete
CVSS vector plus that profile actually decide? That is a property of the method
and of the CVE population, and it is what this reports - one column per
archetype, with the archetype's facts printed beside it so a reader can see
exactly which assertion bought which clearance.

Run: python tools/eval_context_vex.py [--json results/context_vex_sensitivity.json]
"""

from sbom_paths import public_sbom_directory
import argparse
import collections
import json
import os
import sys

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(BASE, "src"))

import vex_context_judge as J   # noqa: E402

# Realistic ICS asset profiles. Each is a complete context: no field is left
# unanswered, because an incomplete context cannot refute anything and the
# sensitivity would then measure the blanks rather than the method.
ARCHETYPES = {
    "L1 headless PLC, isolated cell": {
        "net_interface_present": True, "radio_hardware_present": False,
        "sole_path_hardware_diode": False, "physical_port_access": "sealed-policy",
        "interactive_operator": False, "local_execution_possible": False,
        "account_subsystem": "none",
        "network_exposure": "isolated-cell", "purdue_level": "1",
        "host_firewall": False, "software_unidirectional": False,
        "auth_enforced": False, "transport_encrypted": False,
        "app_allowlisting": False, "removable_media_blocked": True,
        "cabinet_locked": True, "vendor_remote_access": False, "work_approval": True,
        "device_class": "plc", "safety_function": False, "sil": "none",
        "availability_tolerance": "continuous", "data_sensitivity": "none",
        "patch_cadence": "frozen-validated-state",
    },
    "SIS logic solver, potted ports": {
        "net_interface_present": True, "radio_hardware_present": False,
        "sole_path_hardware_diode": True, "physical_port_access": "sealed-structural",
        "interactive_operator": False, "local_execution_possible": False,
        "account_subsystem": "none",
        "network_exposure": "isolated-cell", "purdue_level": "1",
        "host_firewall": True, "software_unidirectional": True,
        "auth_enforced": True, "transport_encrypted": False,
        "app_allowlisting": True, "removable_media_blocked": True,
        "cabinet_locked": True, "vendor_remote_access": False, "work_approval": True,
        "device_class": "sis-logic-solver", "safety_function": True, "sil": "SIL3",
        "availability_tolerance": "continuous", "data_sensitivity": "none",
        "patch_cadence": "frozen-validated-state",
    },
    "L2 HMI / engineering workstation": {
        "net_interface_present": True, "radio_hardware_present": False,
        "sole_path_hardware_diode": False, "physical_port_access": "open",
        "interactive_operator": True, "local_execution_possible": True,
        "account_subsystem": "multi-user",
        "network_exposure": "control-network", "purdue_level": "2",
        "host_firewall": True, "software_unidirectional": False,
        "auth_enforced": True, "transport_encrypted": True,
        "app_allowlisting": False, "removable_media_blocked": False,
        "cabinet_locked": False, "vendor_remote_access": True, "work_approval": True,
        "device_class": "engineering-workstation", "safety_function": False,
        "sil": "none", "availability_tolerance": "scheduled",
        "data_sensitivity": "high", "patch_cadence": "maintenance-window-quarterly",
    },
    "L3.5 DMZ historian, remote vendor access": {
        "net_interface_present": True, "radio_hardware_present": False,
        "sole_path_hardware_diode": False, "physical_port_access": "sealed-policy",
        "interactive_operator": True, "local_execution_possible": True,
        "account_subsystem": "multi-user",
        "network_exposure": "dmz-routable", "purdue_level": "3.5",
        "host_firewall": True, "software_unidirectional": False,
        "auth_enforced": True, "transport_encrypted": True,
        "app_allowlisting": False, "removable_media_blocked": True,
        "cabinet_locked": True, "vendor_remote_access": True, "work_approval": False,
        "device_class": "historian", "safety_function": False, "sil": "none",
        "availability_tolerance": "interruptible", "data_sensitivity": "high",
        "patch_cadence": "maintenance-window-quarterly",
    },
    "Wireless-capable RTU, radio not fitted": {
        "net_interface_present": True, "radio_hardware_present": False,
        "sole_path_hardware_diode": False, "physical_port_access": "open",
        "interactive_operator": False, "local_execution_possible": True,
        "account_subsystem": "single-fixed",
        "network_exposure": "control-network", "purdue_level": "1",
        "host_firewall": False, "software_unidirectional": False,
        "auth_enforced": True, "transport_encrypted": False,
        "app_allowlisting": False, "removable_media_blocked": False,
        "cabinet_locked": False, "vendor_remote_access": False, "work_approval": False,
        "device_class": "rtu", "safety_function": False, "sil": "none",
        "availability_tolerance": "continuous", "data_sensitivity": "low",
        "patch_cadence": "on-advisory-only",
    },
    "Context not supplied (control case)": {},
}


def load_population():
    """Every distinct CVE the corpus identifies, with its vector and signals."""
    cvss_p = os.path.join(BASE, "data", "nvd_cvss.json")
    sig_p = os.path.join(BASE, "data", "exploit_signals.json")
    rem_p = os.path.join(BASE, "data", "remediations.json")

    def _load(p):
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    cv, sig, rem = _load(cvss_p), _load(sig_p), _load(rem_p)
    rdir = str(public_sbom_directory())
    cves = set()
    for fn in sorted(os.listdir(rdir)):
        try:
            with open(os.path.join(rdir, fn), encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            continue
        for v in d.get("vulnerabilities") or []:
            if v.get("id"):
                cves.add(v["id"])
    pop = []
    for c in sorted(cves):
        pop.append({"cve": c,
                    "vector": (cv.get(c) or {}).get("vector"),
                    "signals": sig.get(c) or {},
                    "remediation_categories": list((rem.get(c) or {}).get("categories") or {})})
    return pop


def run(pop, ctx):
    """Status distribution and the justification / refuting-metric breakdown."""
    status = collections.Counter()
    just = collections.Counter()
    refuted_by = collections.Counter()
    env = []
    for row in pop:
        r = J.judge(row["cve"], row["vector"], ctx,
                    signals=row["signals"],
                    remediation_categories=row["remediation_categories"])
        status[r["status"]] += 1
        if r["status"] == J.NOT_AFFECTED:
            just[r["justification"]] += 1
            refuted_by[r.get("refuted_by")] += 1
        e = (r.get("score") or {}).get("environmental")
        if r["status"] == J.AFFECTED and e is not None:
            env.append(e)
    return {"status": dict(status), "justification": dict(just),
            "refuted_by": dict(refuted_by),
            "affected_env_mean": round(sum(env) / len(env), 2) if env else None,
            "affected_env_ge9": sum(1 for x in env if x >= 9.0),
            "affected_scored": len(env)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=os.path.join(BASE, "results",
                                                   "context_vex_sensitivity.json"))
    args = ap.parse_args()

    pop = load_population()
    print("population: %d distinct CVEs identified across the corpus" % len(pop))
    have = sum(1 for p in pop if p["vector"])
    print("            %d (%.1f%%) carry a CVSS vector\n" % (have, 100.0 * have / len(pop)))

    out = {"population": len(pop), "with_cvss": have, "archetypes": {}}
    hdr = "%-42s %8s %8s %8s %7s" % ("archetype", "affected", "NOT_AFF", "under_inv", "env>=9")
    print(hdr)
    print("-" * len(hdr))
    for name, ctx in ARCHETYPES.items():
        res = run(pop, ctx)
        out["archetypes"][name] = {"context": ctx, "result": res}
        s = res["status"]
        print("%-42s %8d %8d %8d %7s"
              % (name[:42], s.get(J.AFFECTED, 0), s.get(J.NOT_AFFECTED, 0),
                 s.get(J.UNDER_INV, 0), res["affected_env_ge9"]))
    print()
    for name, ctx in ARCHETYPES.items():
        res = out["archetypes"][name]["result"]
        if not res["refuted_by"]:
            continue
        print("%s\n  refuted by: %s" % (name, ", ".join(
            "%s x%d" % (k, v) for k, v in sorted(res["refuted_by"].items(),
                                                 key=lambda x: -x[1]))))
        print("  justifications: %s" % res["justification"])
        print("  affected mean environmental score: %s (of %d scored)"
              % (res["affected_env_mean"], res["affected_scored"]))
    os.makedirs(os.path.dirname(args.json), exist_ok=True)
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    print("\nwrote", os.path.relpath(args.json, BASE))


if __name__ == "__main__":
    main()
