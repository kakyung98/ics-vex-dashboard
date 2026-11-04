#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Turn build gates into VEX ground-truth labels, one label per (CVE, build profile).

STAGE 2 of the build-configuration axis. Stage 1 (tools/resolve_build_gates.py)
answered "under what condition is this vulnerable function compiled in?" and wrote
data/build_gates.jsonl. This stage answers "given a product that declares its build
configuration, is the function in the shipped binary?" and emits the label.

    gate (condition)  x  profile (declared config)  ->  label (verdict)

THE PROFILE IS A DECLARED INPUT, NOT AN INFERENCE. METHODOLOGY_V3 W9 settles this
for operational context and the same rule applies here: a build configuration is not
recoverable from an SBOM (version is NOASSERTION in 100% of parts), so it must be
declared by whoever owns the asset and carried with its provenance. A profile here
is therefore one of:

    upstream-default   every gate at the upstream default. The baseline: it produces
                       `affected` for everything and exists to prove the axis does
                       not manufacture dismissals out of nothing.
    ics-rtu-min        a reduced embedded build. The symbols below are the ones ICS
                       vendors routinely leave out of an RTU image - no scripting
                       interpreters, no file-transfer clients, no SQL features a
                       historian never issues, no boot-time debug commands.
    (asset profiles)   a real device's declared config, loaded from --profile-file.

Labels follow CSAF/CycloneDX VEX vocabulary:

    not_affected / vulnerable_code_not_present   the function is compiled out
    affected                                     the function is in the binary
    under_investigation                          the gate could not be resolved

NO LABEL IS A VEX STATEMENT ON ITS OWN. A label here says what is true of the
COMPONENT build. Mapping it onto a product requires the product's own declaration
that it ships that build, which is recorded as `profile_basis`.

Outputs:
  data/symbol_presence_gt.jsonl     one label per (cve, profile)
  results/symbol_gt_summary.json    counts per profile, component and label

Usage:
  python tools/build_symbol_gt.py
  python tools/build_symbol_gt.py --profile ics-rtu-min --verbose
"""
import argparse
import json
import os
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATES = os.path.join(ROOT, "data", "build_gates.jsonl")
OUT_JSONL = os.path.join(ROOT, "data", "symbol_presence_gt.jsonl")
OUT_SUMMARY = os.path.join(ROOT, "results", "symbol_gt_summary.json")


# ---------------------------------------------------------------------------
# Build profiles. `unset` lists the symbols the profile does NOT define; every
# symbol absent from this list keeps its upstream default, which stage 1 cannot
# know, so a gate on such a symbol stays unresolved rather than guessed.
# ---------------------------------------------------------------------------
PROFILES = {
    "upstream-default": {
        "description": "every gate at its upstream default - the no-dismissal baseline",
        "profile_basis": "upstream-default",
        "unset": [],
    },
    "ics-rtu-min": {
        "description": (
            "reduced RTU image: no scripting interpreters, no file-transfer clients, "
            "no unused SQL features, no boot-shell debug commands"
        ),
        "profile_basis": "declared-reference-profile",
        "unset": [
            # busybox: an RTU ships one shell and no text-processing language
            "CONFIG_AWK",
            "CONFIG_HUSH",
            "CONFIG_SH_IS_HUSH",
            "CONFIG_BASH_IS_HUSH",
            "CONFIG_NSLOOKUP",
            "CONFIG_UNLZMA",
            "CONFIG_LZCAT",
            "CONFIG_LZMA",
            "CONFIG_FEATURE_UNZIP_LZMA",
            "CONFIG_FEATURE_SEAMLESS_LZMA",
            # u-boot: no interactive debug commands on a fielded device
            "CONFIG_CMD_I2C",
            "CONFIG_CMD_TFTPBOOT",
            "CONFIG_CMD_NFS",
            "CONFIG_USB_FUNCTION_DFU",
            # libcurl: a telemetry client speaks HTTPS only
            "CURL_DISABLE_TFTP",
            "CURL_DISABLE_FTP",
            "USE_NTLM",
            # sqlite: a historian issues plain INSERT/SELECT
            "SQLITE_OMIT_VIRTUALTABLE",
            "SQLITE_OMIT_JSON",
            "SQLITE_OMIT_WINDOWFUNC",
            # libxml2: config parsing needs no compressed input
            "LIBXML_LZMA_ENABLED",
        ],
    },
}

# A CURL_DISABLE_* / SQLITE_OMIT_* macro is inverted: the code is compiled out when
# the macro IS defined. The gate records the macro, not its polarity, so polarity is
# resolved here from the naming conventions the projects themselves use.
DISABLE_PREFIXES = ("CURL_DISABLE_", "SQLITE_OMIT_", "OPENSSL_NO_", "NO_")


def gate_present(rec, profile):
    """Is this function's code in the binary under `profile`?

    Returns (state, reason) where state is "present", "absent" or "unresolved".
    """
    unset = set(profile["unset"])
    kind = rec["gate_kind"]

    if kind == "unconditional":
        return "present", "no gate: compiled into every build of this release"

    if kind == "build-rule":
        syms = rec["build_rule"]["config_symbols"]
        # `combine: any` - the object is linked if ANY symbol is set, so it is
        # compiled out only when the profile unsets every one of them.
        if syms and all(s in unset for s in syms):
            return "absent", "all linking symbols unset: " + "|".join(syms)
        if any(s in unset for s in syms):
            return "present", "some linking symbols still set: " + "|".join(
                s for s in syms if s not in unset
            )
        return "unresolved", "profile declares none of: " + "|".join(syms)

    if kind == "cpp-guard":
        macros = rec["cpp_guard"]["macros"]
        for m in macros:
            inverted = m.startswith(DISABLE_PREFIXES)
            if inverted and m in unset:
                return "absent", "disable macro defined by profile: " + m
            if not inverted and m in unset:
                return "absent", "feature macro unset by profile: " + m
        return "unresolved", "profile declares none of: " + ",".join(macros)

    return "unresolved", "unknown gate kind: " + kind


# ---------------------------------------------------------------------------
# TODO(human): decide how per-function states become one label for the CVE.
#
# A CVE often carries SEVERAL localized functions (914 functions over 222 CVEs;
# libssh2 CVE-2019-3858 alone has 108). Under a profile they can disagree: in
# busybox CVE-2022-28391 `parse_reply` is gated by CONFIG_NSLOOKUP (absent in
# ics-rtu-min) while `sockaddr2str` sits in libbb and is unconditional (present).
# This function must collapse that list into one GT label.
#
# Implement `collapse(states)` below. `states` is a list of dicts, each with:
#     {"function": str, "state": "present"|"absent"|"unresolved",
#      "gate_kind": "build-rule"|"cpp-guard"|"unconditional",
#      "localization_source": "patch"|"cti"|"none", "reason": str}
# Return a dict: {"label": ..., "justification": ..., "rule": "<short name>"}
#   label         "not_affected" | "affected" | "under_investigation"
#   justification "vulnerable_code_not_present" when not_affected, else None
#   rule          the name of the rule you applied, recorded in every GT row
#
# The trade-offs to weigh:
#  - ALL-absent (strict): not_affected only when every function is compiled out.
#    Highest precision, and it is the only reading that is sound when the
#    localization list is complete - any surviving function may hold the bug.
#  - ANY-absent (loose): one compiled-out function is enough. Raises the dismissal
#    rate, but a CVE whose real defect sits in a function that IS present would be
#    wrongly cleared - a false not_affected, the costly direction in VEX.
#  - Weight by `localization_source`: "patch" functions come from the fix commit and
#    are strong evidence of where the defect lives; "cti" functions are names
#    scraped from advisory prose and may be incidental mentions. Letting only
#    patch-derived functions decide is defensible, but it drops the 83 cti-only CVEs
#    out of the GT entirely.
#  - Weight by `gate_kind`: a build-rule gate removes the whole translation unit, so
#    "absent" is certain. A cpp-guard "absent" is weaker - an #else branch may
#    define a replacement, which stage 1 does not check.
#  - What "unresolved" should do. Any unresolved function means the profile is silent
#    about that gate; treating silence as "present" is conservative, treating the CVE
#    as under_investigation is honest but shrinks the labelled set.
#
# Whatever you pick, it must be stated in the GT rows, because item #4's precision
# number is read against it.
# ---------------------------------------------------------------------------
def collapse(states):
    raise NotImplementedError("TODO(human): implement the per-CVE label rule")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", action="append", help="profile name (repeatable)")
    ap.add_argument("--profile-file", help="JSON file with extra profiles")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    profiles = dict(PROFILES)
    if args.profile_file:
        with open(args.profile_file, encoding="utf-8") as fh:
            profiles.update(json.load(fh))
    names = args.profile or list(profiles)

    by_cve = defaultdict(list)
    meta = {}
    with open(GATES, encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            by_cve[rec["cve"]].append(rec)
            meta[rec["cve"]] = {
                "component": rec["component"],
                "release": rec["release"],
                "snapshot": rec["snapshot"],
                "localization_source": rec["localization_source"],
            }

    rows = []
    counts = defaultdict(Counter)
    per_comp = defaultdict(lambda: defaultdict(Counter))
    for name in names:
        profile = profiles[name]
        for cve, recs in sorted(by_cve.items()):
            states = []
            for rec in recs:
                state, reason = gate_present(rec, profile)
                states.append(
                    {
                        "function": rec["function"],
                        "state": state,
                        "gate_kind": rec["gate_kind"],
                        "localization_source": rec["localization_source"],
                        "reason": reason,
                    }
                )
            verdict = collapse(states)
            row = {
                "cve": cve,
                "profile": name,
                "profile_basis": profile["profile_basis"],
                "label": verdict["label"],
                "justification": verdict.get("justification"),
                "label_rule": verdict.get("rule"),
                "functions": states,
                "evidence_kind": "build-rule-declaration",
                "compiled_symbol_check": False,
                **meta[cve],
            }
            rows.append(row)
            counts[name][verdict["label"]] += 1
            per_comp[name][meta[cve]["component"]][verdict["label"]] += 1
            if args.verbose:
                print(
                    "%-16s %-14s %-20s %s"
                    % (cve, name, verdict["label"], verdict.get("justification") or "")
                )

    os.makedirs(os.path.dirname(OUT_JSONL), exist_ok=True)
    os.makedirs(os.path.dirname(OUT_SUMMARY), exist_ok=True)
    with open(OUT_JSONL, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    summary = {
        "rows": len(rows),
        "cves": len(by_cve),
        "profiles": {n: dict(c) for n, c in counts.items()},
        "per_component": {
            n: {c: dict(v) for c, v in sorted(d.items())} for n, d in per_comp.items()
        },
        "evidence_kind": "build-rule-declaration",
        "compiled_symbol_check": False,
        "note": (
            "Labels rest on build-system declarations, not on symbols read out of a "
            "compiled artifact. A toolchain run would upgrade evidence_kind to "
            "compiled-symbol; nothing else in the pipeline changes."
        ),
    }
    with open(OUT_SUMMARY, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)

    for name, c in counts.items():
        print("\nprofile %s" % name)
        for label, n in c.most_common():
            print("  %-22s %d" % (label, n))
    print("\nwrote %s" % OUT_JSONL)
    print("wrote %s" % OUT_SUMMARY)
    return 0


if __name__ == "__main__":
    sys.exit(main())
