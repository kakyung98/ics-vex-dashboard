"""Advisory remediation triage hints, separate from asset VEX decisions."""
UNDER_INV = "under_investigation"

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

