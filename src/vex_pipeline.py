#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Genie-style SBOM -> VEX pipeline, STATIC-ANALYSIS edition (no PoC, no execution).

Restructures the CVE-Genie multi-agent design (Processor -> Builder -> Exploiter ->
CTF Verifier) so that VEX is decided purely by STATIC analysis. Nothing is built,
no exploit is generated, and nothing is executed -- the execution CTF oracle is
replaced by a static-evidence grounding critic.

  SBOM (CycloneDX)
    -> [1] Knowledge Builder     : match components/versions to CVEs -> KB sentences
    -> [2] Presence+Reachability : component/version present? AV x exposure reachable?
           (deterministic; can TERMINATE as not_affected)
    -> [3] SecureBERT context leg (live)  -> VEX signal + rationale       [signal]
    -> [4] CodeBERT code leg (live, if code pair) -> patch-diff signal     [signal]
    -> [5] sLLM static exploitability     -> structured assessment         [developer]
    -> [6] static critic (ReAct loop)     -> grounded? refine once         [critic]
    -> [7] VEX adjudicator                -> status + CSAF/OpenVEX justif  [verdict]

Evidence tiers (new findings): static-analysis-verified (code pair + grounded critic)
/ static-reasoned (reachability/CWE grounded) / under-investigation.

Emits one JSON object per line to stdout (progress events), then a final
{"event":"result", ...}. Driven by the ICS-VEXForge webapp as a subprocess.

Usage:
  python src/vex_pipeline.py --sbom results/example_sbom.json --exposure control-network
"""
import os, sys, json, argparse

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

KB_PATH = os.path.join(BASE, "results", "cve_kb.json")
CODE_EV = os.path.join(BASE, "data", "code_evidence.json")

AFFECTED = "LIKELY_AFFECTED"
NOT_AFFECTED = "LIKELY_NOT_AFFECTED"
UNDER_INV = "UNDER_INVESTIGATION"


def emit(**ev):
    sys.stdout.write(json.dumps(ev, ensure_ascii=False) + "\n")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# SBOM parsing + CVE matching
# ---------------------------------------------------------------------------
def parse_sbom(sbom):
    """CycloneDX -> [(name, version)]."""
    out = []
    for c in sbom.get("components", []):
        name = (c.get("name") or "").strip()
        ver = (c.get("version") or "").strip()
        if name:
            out.append((name, ver))
    return out


def load_kb():
    kb = json.load(open(KB_PATH, encoding="utf-8"))["components"]
    idx = {}
    for comp in kb:
        for key in {comp["key"], comp["name"].lower(), comp.get("cpe_product", "")}:
            if key:
                idx[key.lower()] = comp
    return kb, idx


def match_cves(components, idx):
    """-> list of findings. `version_pinned` records whether the SBOM asserted a
    version that the KB knows about (drives the presence check in stage 2)."""
    findings = []
    for name, ver in components:
        comp = idx.get(name.lower())
        if not comp:
            continue
        vmap = comp.get("versions", {})
        cves = vmap.get(ver)
        version_pinned = cves is not None
        if cves is None:  # version not pinned -> union of all known (best-effort)
            seen = set(); cves = []
            for lst in vmap.values():
                for cv in lst:
                    if cv["id"] not in seen:
                        seen.add(cv["id"]); cves.append(cv)
        for cv in cves:
            findings.append({
                "component": comp["name"], "version": ver or "(unpinned)",
                "version_pinned": version_pinned,
                "cve": cv["id"], "sev": cv.get("sev", ""), "av": cv.get("av", "N"),
                "kev": bool(cv.get("kev")), "epss": cv.get("epss"),
            })
    return findings


# ---------------------------------------------------------------------------
# [2] Presence & Reachability analyzer (static, deterministic)
#     Replaces the CVE-Genie "Builder" (which rebuilt + ran the environment).
# ---------------------------------------------------------------------------
def presence_reachability(finding, exposure, reachability_fn):
    """Static gate. Returns (terminal_status_or_None, info dict).

    - component matched in the KB   -> present
    - SBOM records every version as NOASSERTION, so we cannot confirm the deployed
      build is the vulnerable one; ICS safety-first, we assume-vulnerable and do NOT
      terminate as not_affected on version grounds (kept as version_unconfirmed).
    - reachability = CVSS AV x deployment exposure. AV=P / unreachable -> can
      terminate as not_affected (vulnerable_code_cannot_be_controlled_by_adversary).
    """
    reach = reachability_fn(finding["av"], exposure)
    info = {
        "component_present": True,               # matched against the KB catalogue
        "version_pinned": finding["version_pinned"],
        "version_unconfirmed": not finding["version_pinned"],
        "reachability": reach,
        "exposure": exposure,
    }
    if reach == "no":
        return (NOT_AFFECTED, {**info,
                "justification": "vulnerable_code_cannot_be_controlled_by_adversary",
                "justification_vocabulary": "csaf-openvex",
                "basis": "AV:%s is unreachable at exposure tier '%s'" % (
                    finding["av"], exposure)})
    return (None, info)


# ---------------------------------------------------------------------------
# [4] CodeBERT static patch-diff signal (only when a vuln/patched pair exists)
# ---------------------------------------------------------------------------
def code_diff_signal(cve, code_ev, cb):
    """Static reference match on the collected vuln/patched code pair. No execution.
    We have no *deployed* source (SBOM has none), so this measures how cleanly the
    fix is distinguishable from the flaw -- a signal for how decidable the CVE is."""
    ev = code_ev.get(cve) or {}
    vuln, patched = ev.get("vuln_code"), ev.get("patched_code")
    if not vuln or not patched:
        return None
    # deployed unknown -> compare vuln vs patched as the two reference poles.
    m = cb.match(vuln, vuln, patched)  # deployed:=vuln pole (ICS assume-vulnerable)
    return {
        "has_pair": True,
        "repo": ev.get("repo"), "commit": ev.get("commit"), "file": ev.get("file"),
        "sim_vulnerable": m["sim_vulnerable"], "sim_patched": m["sim_patched"],
        "separable": abs(m["sim_vulnerable"] - m["sim_patched"]) >= 0.02,
    }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
def run(sbom_path, exposure=None, use_sllm=True, max_critic_iters=2):
    import build_ground_truth as G
    import vex_infer as VI

    sbom = json.load(open(sbom_path, encoding="utf-8"))
    comps = parse_sbom(sbom)
    emit(event="sbom", components=len(comps),
         names=[f"{n} {v}".strip() for n, v in comps][:40])

    _kb, idx = load_kb()
    findings = match_cves(comps, idx)
    emit(event="matched", findings=len(findings))
    if not findings:
        emit(event="result", findings=[], summary={"total": 0, "by_vex": {}})
        return

    code_ev = json.load(open(CODE_EV, encoding="utf-8")) if os.path.exists(CODE_EV) else {}

    emit(event="stage", stage="load-securebert")
    sv = VI.SecureBertVex()

    cb = None  # CodeBERT loaded lazily only if a code pair is actually needed
    analyst = None
    if use_sllm:
        emit(event="stage", stage="load-sllm-static-analyst")
        analyst = VI.SllmStaticAnalyst()

    results = []
    for i, f in enumerate(findings):
        cve, av, kev, epss = f["cve"], f["av"], f["kev"], f["epss"]
        comp = f["component"]
        exp = exposure or G.exposure_for(comp)
        ev = code_ev.get(cve) or {}
        has_pair = bool(ev.get("vuln_code") and ev.get("patched_code"))

        # [2] Presence + reachability (deterministic; may terminate) --------------
        terminal, pr = presence_reachability(f, exp, G.reachability)
        reach = pr["reachability"]

        if terminal is not None:
            rec = _record(f, exp, pr, route="presence-reachability",
                          final=terminal, justification=pr["justification"],
                          justification_vocabulary=pr["justification_vocabulary"],
                          tier="static-reasoned",
                          adjudication={"status": terminal, "justification": pr["basis"]})
            emit(event="finding", i=i, total=len(findings), cve=cve, component=comp,
                 final_vex=terminal, route="presence-reachability",
                 evidence_tier="static-reasoned", justification=pr["justification"])
            results.append(rec)
            continue

        # [3] SecureBERT context leg -> SIGNAL ONLY ------------------------------
        sents = G.render(comp, comp, comp, cve, "", av, f["sev"], epss, kev,
                         exp, has_pair, True, None, None)
        sb = sv.predict(sents)
        sb_rationale = [s["text"] for s in sents if s["id"] in sb["rationale_ids"]]

        # [4] CodeBERT static patch-diff signal (only if a pair exists) ----------
        code_sig = None
        if has_pair:
            if cb is None:
                emit(event="stage", stage="load-codebert")
                cb = VI.CodeBertRefMatch()
            code_sig = code_diff_signal(cve, code_ev, cb)

        # Build the static evidence block shared by developer/critic/adjudicator.
        evidence = _evidence_block(cve, comp, f, av, exp, reach, pr, sb,
                                   sb_rationale, code_sig)

        static_assessment = critic = None
        route = "presence-reachability->securebert"
        if analyst is not None:
            # [5] developer: static exploitability assessment (no exploit code) --
            emit(event="stage", stage="sllm-static-assess", cve=cve)
            static_assessment = analyst.assess_exploitability(evidence)

            # [6] critic: ReAct grounding loop -----------------------------------
            for it in range(max_critic_iters):
                critic = analyst.critique(evidence, static_assessment)
                if critic["grounded"]:
                    break
                # refine once with the critic's feedback appended to the evidence.
                refine = evidence + "\n\nCritic feedback (address it, stay grounded): " \
                    + critic.get("feedback", "")
                static_assessment = analyst.assess_exploitability(refine)
            evidence = evidence + "\n\nStatic exploitability: " + json.dumps(
                {k: static_assessment[k] for k in
                 ("adversary_controllable", "reachable_in_deployment", "exploitability")},
                ensure_ascii=False)
            route = ("presence-reachability->securebert->codebert->sllm-static-analyst"
                     if has_pair else
                     "presence-reachability->securebert->sllm-static-analyst")

            # [7] adjudicator: final static VEX verdict --------------------------
            emit(event="stage", stage="sllm-adjudicate", cve=cve)
            adjudication = analyst.adjudicate_vex(evidence)
        else:
            # sLLM disabled -> fall back to the deterministic estimate.
            est_status, est_just, est_vocab, est_basis, est_conf, _r = G.estimate(
                av, exp, "per-cve", "A" if has_pair else "C", kev)
            adjudication = {"status": est_status,
                            "justification": est_basis or "static reachability estimate"}

        final = adjudication["status"]
        tier = _tier(final, has_pair, code_sig, critic)
        justification, vocab = _map_justification(final, pr, has_pair, code_sig)

        rec = _record(f, exp, pr, route=route, final=final,
                      justification=justification, justification_vocabulary=vocab,
                      tier=tier, adjudication=adjudication,
                      securebert_signal={
                          "probs": {k: round(v, 3) for k, v in sb["probs"].items()},
                          "rationale": sb_rationale},
                      code_signal=code_sig, static_assessment=static_assessment,
                      critic=critic)
        emit(event="finding", i=i, total=len(findings), cve=cve, component=comp,
             final_vex=final, route=route, evidence_tier=tier,
             justification=(justification or ""),
             critic_grounded=(critic["grounded"] if critic else None))
        results.append(rec)

    emit(event="result", findings=results, summary=_summary(results))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _evidence_block(cve, comp, f, av, exp, reach, pr, sb, sb_rationale, code_sig):
    lines = [
        f"CVE: {cve} on {comp} {f['version']} (severity {f['sev']}).",
        f"CVSS attack vector: {av}. Deployment exposure: {exp}. Reachability: {reach}.",
        ("SBOM version is NOASSERTION; deployed build unconfirmed -> ICS safety-first "
         "assumes the vulnerable version is present."
         if pr["version_unconfirmed"] else
         "SBOM pins the vulnerable version as present."),
        (f"SecureBERT context signal: P(affected)={sb['probs'][AFFECTED]:.2f}, "
         f"P(not_affected)={sb['probs'][NOT_AFFECTED]:.2f}, "
         f"P(under_investigation)={sb['probs'][UNDER_INV]:.2f}."),
        "SecureBERT rationale: " + " | ".join(sb_rationale),
    ]
    if code_sig:
        lines.append(
            f"CodeBERT patch-diff signal: sim_vulnerable={code_sig['sim_vulnerable']}, "
            f"sim_patched={code_sig['sim_patched']}, fix separable from flaw: "
            f"{code_sig['separable']} (static diff only; nothing executed).")
    else:
        lines.append("No vulnerable/patched code pair collected for this CVE.")
    return "\n".join(lines)


def _tier(final, has_pair, code_sig, critic):
    critic_ok = (critic is None) or critic.get("grounded", False)
    if has_pair and code_sig and code_sig.get("separable") and critic_ok \
            and final in (AFFECTED, NOT_AFFECTED):
        return "static-analysis-verified"
    if final in (AFFECTED, NOT_AFFECTED):
        return "static-reasoned"
    return "under-investigation"


def _map_justification(final, pr, has_pair, code_sig):
    """Attach a CSAF/OpenVEX controlled-vocabulary justification to the verdict."""
    if final == NOT_AFFECTED:
        if pr["reachability"] == "no":
            return "vulnerable_code_cannot_be_controlled_by_adversary", "csaf-openvex"
        if has_pair and code_sig and code_sig.get("separable"):
            return "vulnerable_code_not_present", "csaf-openvex"
        return "vulnerable_code_cannot_be_controlled_by_adversary", "csaf-openvex"
    if final == AFFECTED:
        if pr["reachability"] == "yes":
            return "vulnerable_code_controllable_by_adversary", "extension"
        return "vulnerable_code_present", "extension"
    return None, None


def _record(f, exp, pr, route, final, justification, justification_vocabulary,
            tier, adjudication, securebert_signal=None, code_signal=None,
            static_assessment=None, critic=None):
    rec = {
        "cve": f["cve"], "component": f["component"], "version": f["version"],
        "av": f["av"], "kev": f["kev"], "sev": f["sev"], "epss": f["epss"],
        "exposure": exp, "reachability": pr["reachability"],
        "version_unconfirmed": pr["version_unconfirmed"],
        "route": route, "has_code_pair": bool(code_signal),
        "final_vex": final,
        "justification": justification,
        "justification_vocabulary": justification_vocabulary,
        "evidence_tier": tier,
        "adjudication": adjudication,
    }
    if securebert_signal is not None:
        rec["securebert_signal"] = securebert_signal
    if code_signal is not None:
        rec["code_signal"] = code_signal
    if static_assessment is not None:
        rec["static_assessment"] = {k: v for k, v in static_assessment.items()
                                    if k != "raw"}
    if critic is not None:
        rec["critic"] = {k: v for k, v in critic.items() if k != "raw"}
    return rec


def _summary(results):
    from collections import Counter
    c = Counter(r["final_vex"] for r in results)
    t = Counter(r["evidence_tier"] for r in results)
    return {"total": len(results), "by_vex": dict(c), "by_tier": dict(t),
            "code_pair_route": sum(1 for r in results if r.get("has_code_pair"))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--exposure", default=None,
                    help="isolated-cell | control-network | dmz-routable | remote-accessible")
    ap.add_argument("--no-sllm", action="store_true",
                    help="skip the sLLM static analyst; use the deterministic estimate only")
    a = ap.parse_args()
    try:
        run(a.sbom, exposure=a.exposure, use_sllm=not a.no_sllm)
    except Exception as e:
        import traceback
        emit(event="error", error=str(e), trace=traceback.format_exc()[-1500:])
        sys.exit(1)


if __name__ == "__main__":
    main()
