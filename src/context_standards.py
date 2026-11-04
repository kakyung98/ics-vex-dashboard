#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Standards basis for the asset operational context schema.

Why this module exists
----------------------
`ics_context.CONTEXT_FIELDS` decides whether a CVE can be cleared on an asset.
The first question any assessor asks is "where did these fields come from", and
"we thought they were the relevant ones" is not an answer in a certification
context. This module is the answer: every context field is traced to the
recognised requirement families an ICS operator is already assessed against, and
a field with no basis fails the self-test.

It also makes the OMISSIONS explicit, which matters more than the mappings. The
schema deliberately covers only the requirement families that bear on
EXPLOITABILITY - can an adversary reach, authenticate to, and trigger this. It
omits detection, response and training families, not by oversight but because
they do not change whether an exploit can be triggered. An IDS does not make a
buffer overflow unreachable. Declaring that boundary is what stops the context
form from drifting into a general security questionnaire.

Verification status - read this before citing anything here
-----------------------------------------------------------
Each reference carries a `status`:

  "primary"    confirmed against the publisher's own page in this repository's
               research notes (title, number, date).
  "secondary"  the structure is consistent across independent third-party
               summaries but was not read from the standard text. Safe to use
               as an organising frame; NOT safe to quote as a clause.
  "unverified" taken from a third-party table of contents and not yet checked
               against the issuing body's own document.

Nothing here quotes a clause number below the family level (no "SR 1.1", no
NIST chapter numbers), because those could not be verified from the standard
text and a wrong clause number in an assessment document is worse than no clause
number. The family level is enough to carry the traceability argument.
"""

STANDARDS = {
    "IEC62443-3-3": {
        "title": "IEC 62443-3-3 - System security requirements and security levels",
        "status": "secondary",
        "note": "The seven Foundational Requirements (FR1-FR7) and the SL1-SL4 "
                "scheme are consistent across independent summaries. Per-FR "
                "System Requirement numbers were NOT verified and are not cited.",
        "families": {
            "FR1": "Identification and Authentication Control (IAC)",
            "FR2": "Use Control (UC)",
            "FR3": "System Integrity (SI)",
            "FR4": "Data Confidentiality (DC)",
            "FR5": "Restricted Data Flow (RDF)",
            "FR6": "Timely Response to Events (TRE)",
            "FR7": "Resource Availability (RA)",
        },
    },
    "IEC62443-3-2": {
        "title": "IEC 62443-3-2 - Security risk assessment for system design",
        "status": "secondary",
        "note": "Contributes the zone-and-conduit model and the system-under-"
                "consideration partitioning that the exposure and level fields "
                "instantiate.",
        "families": {"ZC": "Zones and conduits / system under consideration"},
    },
    "IEC61508-61511": {
        "title": "IEC 61508 / IEC 61511 - Functional safety, SIL",
        "status": "secondary",
        "note": "The source of the SIL vocabulary. SIL is a safety integrity "
                "level, not a security level - it is read here only as a measure "
                "of what a successful exploit would cost.",
        "families": {"SIL": "Safety integrity level"},
    },
    "NIST-SP800-82r3": {
        "title": "NIST SP 800-82 Rev. 3 - Guide to Operational Technology (OT) "
                 "Security (September 2023)",
        "status": "primary",
        "note": "Title, revision and date confirmed from the NIST publication "
                "page. Chapter numbers are NOT cited: independent summaries "
                "disagree on them and the text was not read directly.",
        "families": {
            "ARCH": "OT security architecture - defence in depth, network "
                    "segmentation, boundary protection, the Purdue reference model",
            "PHYS": "Physical access control to OT equipment",
            "PATCH": "OT patch and update management under availability constraints",
            "ASSET": "Asset inventory and characterisation",
        },
    },
    "KR-KIIP": {
        "title": "주요정보통신기반시설 기술적 "
                 "취약점 분석·평가 방법 상세가이드 "
                 "(KISA) - 제어시스템 분야",
        "status": "unverified",
        "note": "The control-system check categories below come from a third-party "
                "table of contents, NOT from the KISA document. MUST be checked "
                "against the KISA original before any assessment relies on it; the "
                "category names, their count and their codes may all differ.",
        "families": {
            "ACC": "계정 관리",
            "SVC": "서비스 관리",
            "PATCH": "패치 관리",
            "NET": "네트워크 접근통제",
            "PHYS": "물리적 접근통제",
            "DET": "보안위협 탐지",
            "REC": "복구대응",
            "MGMT": "보안 관리",
            "EDU": "교육훈련",
        },
    },
}

# --- field -> requirement families -------------------------------------------
# Each entry: (standard key, family key). A field with an empty list fails
# check_traceability(), which is the point: nothing enters the schema without a
# recognised basis.
FIELD_REFS = {
    # ---- structural: what the asset IS ----
    "net_interface_present": [("IEC62443-3-3", "FR5"), ("NIST-SP800-82r3", "ARCH"),
                              ("KR-KIIP", "NET")],
    "radio_hardware_present": [("IEC62443-3-3", "FR5"), ("NIST-SP800-82r3", "ARCH"),
                               ("KR-KIIP", "NET")],
    "sole_path_hardware_diode": [("IEC62443-3-3", "FR5"), ("IEC62443-3-2", "ZC"),
                                 ("NIST-SP800-82r3", "ARCH")],
    "physical_port_access": [("NIST-SP800-82r3", "PHYS"), ("KR-KIIP", "PHYS")],
    "interactive_operator": [("IEC62443-3-3", "FR2"), ("KR-KIIP", "ACC")],
    "local_execution_possible": [("IEC62443-3-3", "FR3"), ("IEC62443-3-3", "FR2"),
                                 ("KR-KIIP", "SVC")],
    "account_subsystem": [("IEC62443-3-3", "FR1"), ("KR-KIIP", "ACC")],

    # ---- control: how it is configured and governed ----
    "network_exposure": [("IEC62443-3-2", "ZC"), ("IEC62443-3-3", "FR5"),
                         ("NIST-SP800-82r3", "ARCH"), ("KR-KIIP", "NET")],
    "purdue_level": [("IEC62443-3-2", "ZC"), ("NIST-SP800-82r3", "ARCH")],
    "host_firewall": [("IEC62443-3-3", "FR5"), ("NIST-SP800-82r3", "ARCH"),
                      ("KR-KIIP", "NET")],
    "software_unidirectional": [("IEC62443-3-3", "FR5"), ("NIST-SP800-82r3", "ARCH")],
    "auth_enforced": [("IEC62443-3-3", "FR1"), ("KR-KIIP", "ACC")],
    "transport_encrypted": [("IEC62443-3-3", "FR4"), ("KR-KIIP", "NET")],
    "app_allowlisting": [("IEC62443-3-3", "FR3"), ("KR-KIIP", "SVC")],
    "removable_media_blocked": [("IEC62443-3-3", "FR3"), ("NIST-SP800-82r3", "PHYS"),
                                ("KR-KIIP", "PHYS")],
    "cabinet_locked": [("NIST-SP800-82r3", "PHYS"), ("KR-KIIP", "PHYS")],
    "vendor_remote_access": [("IEC62443-3-3", "FR1"), ("IEC62443-3-3", "FR5"),
                             ("KR-KIIP", "NET"), ("KR-KIIP", "MGMT")],
    "work_approval": [("KR-KIIP", "MGMT")],

    # ---- mission: what a successful exploit would cost ----
    "device_class": [("IEC62443-3-2", "ZC"), ("NIST-SP800-82r3", "ASSET")],
    "safety_function": [("IEC61508-61511", "SIL"), ("IEC62443-3-2", "ZC")],
    "sil": [("IEC61508-61511", "SIL")],
    "availability_tolerance": [("IEC62443-3-3", "FR7"), ("NIST-SP800-82r3", "ARCH")],
    "data_sensitivity": [("IEC62443-3-3", "FR4")],
    "patch_cadence": [("NIST-SP800-82r3", "PATCH"), ("KR-KIIP", "PATCH")],
}

# --- families deliberately NOT collected, and why -----------------------------
# These are real requirements an operator is assessed against. They are absent
# from the context schema on purpose: VEX asks whether an exploit can be
# triggered, and none of these change that answer. Detection tells you an
# exploit happened; recovery tells you what to do afterwards; training changes
# how likely a person is to be fooled, which is a probability, not a
# precondition. Collecting them would turn the form into a general security
# questionnaire whose answers could not legitimately move a status.
EXCLUDED = [
    (("IEC62443-3-3", "FR6"),
     "Detection and event response does not change whether the vulnerable code "
     "can be reached and triggered. An IDS does not make an overflow unreachable."),
    (("KR-KIIP", "DET"),
     "Same reasoning as FR6 - a detection control observes exploitation rather "
     "than preventing the precondition."),
    (("KR-KIIP", "REC"),
     "Recovery acts after a successful exploit, so it bears on consequence, not "
     "on exploitability."),
    (("KR-KIIP", "EDU"),
     "Training changes how likely an operator is to be fooled. UI:R asks whether "
     "an interactive operator EXISTS at all, which is the precondition; how well "
     "trained they are is a probability and cannot refute anything."),
]


def check_traceability(field_keys):
    """Problems with the mapping, as a list of strings. Empty list = sound.

    Checks three ways, because each catches a different kind of drift:
      * a schema field with no standards basis (someone invented a question)
      * a mapping entry for a field that no longer exists (schema was renamed)
      * a reference to a standard or family this module does not define (typo)
    """
    problems = []
    for key in field_keys:
        if not FIELD_REFS.get(key):
            problems.append("context field %r has no standards basis" % key)
    for key in FIELD_REFS:
        if key not in field_keys:
            problems.append("FIELD_REFS maps %r, which is not in the schema" % key)
    for key, refs in FIELD_REFS.items():
        for std, fam in refs:
            if std not in STANDARDS:
                problems.append("%s: unknown standard %r" % (key, std))
            elif fam not in STANDARDS[std]["families"]:
                problems.append("%s: unknown family %s/%s" % (key, std, fam))
    return problems


def coverage():
    """Per standard: which families the schema collects, and which it omits.

    An omitted family is reported with its stated reason when there is one, and
    flagged as UNEXPLAINED when there is not - so a family cannot quietly fall
    out of scope without someone writing down why.
    """
    used = set()
    for refs in FIELD_REFS.values():
        used.update(refs)
    explained = {k: v for k, v in EXCLUDED}
    out = {}
    for std, meta in STANDARDS.items():
        rows = []
        for fam, label in meta["families"].items():
            covered = (std, fam) in used
            rows.append({
                "family": fam, "label": label, "covered": covered,
                "fields": sorted(k for k, refs in FIELD_REFS.items()
                                 if (std, fam) in refs),
                "excluded_because": None if covered else explained.get((std, fam)),
                "unexplained": (not covered) and (std, fam) not in explained,
            })
        out[std] = {"title": meta["title"], "status": meta["status"],
                    "note": meta["note"], "families": rows}
    return out


def refs_for(field_key):
    """Human-readable references for one field, for the UI and the report."""
    out = []
    for std, fam in FIELD_REFS.get(field_key, []):
        meta = STANDARDS.get(std, {})
        out.append({"standard": std, "title": meta.get("title"),
                    "family": fam,
                    "label": (meta.get("families") or {}).get(fam),
                    "status": meta.get("status")})
    return out


def report(field_keys):
    """Everything an assessor needs: the mapping, the gaps, the caveats."""
    return {
        "standards": {k: {kk: v[kk] for kk in ("title", "status", "note")}
                      for k, v in STANDARDS.items()},
        "fields": {k: refs_for(k) for k in field_keys},
        "coverage": coverage(),
        "problems": check_traceability(field_keys),
        "caveat": "Family-level traceability only. No clause or item number is "
                  "cited: they could not be verified against the standard texts, "
                  "and a wrong clause number in an assessment document is worse "
                  "than none. The KR-KIIP categories are UNVERIFIED third-party "
                  "content and must be checked against the KISA original.",
    }


if __name__ == "__main__":
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    sys.stdout.reconfigure(encoding="utf-8")
    from ics_context import CONTEXT_FIELDS

    keys = [f[0] for f in CONTEXT_FIELDS]
    rep = report(keys)
    for k, v in rep["standards"].items():
        print("%-18s [%s] %s" % (k, v["status"], v["title"]))
    print()
    for std, c in rep["coverage"].items():
        cov = [r for r in c["families"] if r["covered"]]
        print("%-18s %d/%d families collected" % (std, len(cov), len(c["families"])))
        for r in c["families"]:
            if r["covered"]:
                continue
            mark = "UNEXPLAINED" if r["unexplained"] else "excluded"
            print("    %-6s %-55s %s" % (r["family"], r["label"][:55], mark))
    print()
    probs = rep["problems"]
    for p in probs:
        print("PROBLEM:", p)
    print("traceability:", "OK - every context field has a standards basis"
          if not probs else "BROKEN (%d)" % len(probs))
