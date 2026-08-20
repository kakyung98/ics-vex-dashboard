#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Full-corpus STATIC VEX sweep over all findings (data/findings.csv).

Applies the redesigned static pipeline's decision to every CVE finding, with NO
PoC generation and NO execution. This is the corpus-scale counterpart of
vex_pipeline.py --no-sllm: the per-finding sLLM analyst is meant for interactive
SBOM subsets (a 7B analyst+critic pass over all ~13k findings would take many
hours), so the batch uses the deterministic static legs:

  presence + reachability gate  (CVSS AV x deployment exposure)
  -> SecureBERT context signal  (optional, --securebert; batched)
  -> deterministic adjudication (build_ground_truth.estimate)
  -> evidence tier              (static-reasoned / under-investigation)

Outputs:
  results/vex_batch.jsonl          one verdict per finding
  results/vex_batch_summary.json   distributions (by VEX / tier / reachability / CWE)

Run:
  python src/vex_batch.py                 # fast deterministic sweep (all findings)
  python src/vex_batch.py --securebert    # + live SecureBERT signal per finding
  python src/vex_batch.py --limit 500     # quick smoke test
"""
import os, sys, csv, json, argparse
from collections import Counter

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

FIND = os.path.join(BASE, "data", "findings.csv")
OUT = os.path.join(BASE, "results", "vex_batch.jsonl")
OUT_SUM = os.path.join(BASE, "results", "vex_batch_summary.json")

AFFECTED = "LIKELY_AFFECTED"
NOT_AFFECTED = "LIKELY_NOT_AFFECTED"
UNDER_INV = "UNDER_INVESTIGATION"


def tier_for(status, has_pair):
    if status in (AFFECTED, NOT_AFFECTED):
        # code-pair findings could reach static-analysis-verified once CodeBERT
        # confirms the fix is separable; the deterministic sweep stays conservative.
        return "static-reasoned"
    return "under-investigation"


def run(limit=None, use_securebert=False, progress_every=1000):
    import build_ground_truth as G

    code_cves = G.load_code_available()
    pairs = set()
    ce = json.load(open(os.path.join(BASE, "data", "code_evidence.json"), encoding="utf-8"))
    for k, v in ce.items():
        if isinstance(v, dict) and v.get("vuln_code") and v.get("patched_code"):
            pairs.add(k)

    sv = None
    if use_securebert:
        import vex_infer as VI
        sv = VI.SecureBertVex()

    rows = list(csv.DictReader(open(FIND, encoding="utf-8-sig")))
    if limit:
        rows = rows[:limit]
    total = len(rows)

    by_vex, by_tier, by_reach, by_cwe_vex = Counter(), Counter(), Counter(), {}
    # source-availability class drives which pipeline legs apply:
    #   code-available     -> code pair collected -> CodeBERT patch-diff eligible
    #   oss-attributed     -> OSS (tier A/C) but no code collected -> context+reach only
    #   vendor-proprietary -> tier E closed firmware -> context+reach only
    by_class_vex = {"code-available": Counter(), "oss-attributed": Counter(),
                    "vendor-proprietary": Counter()}
    by_class_n = Counter()
    n_pair = 0
    with open(OUT, "w", encoding="utf-8") as out:
        for i, r in enumerate(rows):
            device, vendor, product = r["device"], r["vendor"], r["product"]
            cve, cwe, tier = r["cve"], r["cwe"], r["tier"]
            av, sev = r["av"], r["severity"]
            av_source = r.get("av_source", "")
            kev = str(r.get("kev", "")).strip().lower() in ("1", "true", "yes")
            epss = None
            try:
                epss = float(r["epss"]) if r.get("epss") not in (None, "") else None
            except ValueError:
                epss = None

            exposure = G.exposure_for(device)
            reach = G.reachability(av, exposure)
            has_pair = cve in pairs
            if has_pair:
                n_pair += 1
            source_class = ("code-available" if has_pair
                            else "oss-attributed" if tier in ("A", "C")
                            else "vendor-proprietary")

            # --- presence + reachability gate (static, deterministic) ---
            if reach == "no":
                status = NOT_AFFECTED
                just = ("vulnerable_code_cannot_be_controlled_by_adversary")
                vocab = "csaf-openvex"
                basis = ("AV:P requires hands-on hardware access" if av == "P"
                         else "AV:%s unreachable at exposure '%s'" % (av, exposure))
                conf = 0.72
                route = "presence-reachability"
            else:
                status, just, vocab, basis, conf, reach = G.estimate(
                    av, exposure, av_source, tier, kev)
                route = "presence-reachability->deterministic-estimate"

            sb_signal = None
            if sv is not None:
                sents = G.render(device, vendor, product, cve, cwe, av, sev, epss, kev,
                                 exposure, has_pair, tier in ("A", "C"), None, None)
                pred = sv.predict(sents)
                sb_signal = {"label": pred["label"],
                             "probs": {k: round(v, 3) for k, v in pred["probs"].items()}}

            et = tier_for(status, has_pair)
            rec = {
                "cve": cve, "device": device, "vendor": vendor, "product": product,
                "cwe": cwe, "av": av, "sev": sev, "kev": kev, "epss": epss,
                "tier": tier, "source_class": source_class,
                "exposure": exposure, "exposure_synthetic": True,
                "reachability": reach, "has_code_pair": has_pair,
                "final_vex": status, "justification": just,
                "justification_vocabulary": vocab, "basis": basis,
                "estimate_confidence": conf, "evidence_tier": et, "route": route,
            }
            if sb_signal:
                rec["securebert_signal"] = sb_signal
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")

            by_vex[status] += 1
            by_tier[et] += 1
            by_reach[reach] += 1
            by_class_vex[source_class][status] += 1
            by_class_n[source_class] += 1
            if cwe:
                d = by_cwe_vex.setdefault(cwe, Counter())
                d[status] += 1

            if progress_every and (i + 1) % progress_every == 0:
                sys.stderr.write("  %d/%d\n" % (i + 1, total)); sys.stderr.flush()

    # CWE breakdown: keep the 20 most frequent, with their VEX split.
    cwe_top = sorted(by_cwe_vex.items(), key=lambda kv: -sum(kv[1].values()))[:20]
    summary = {
        "total_findings": total,
        "code_pair_findings": n_pair,
        "securebert": bool(use_securebert),
        "by_vex": dict(by_vex),
        "by_tier": dict(by_tier),
        "by_reachability": dict(by_reach),
        "by_source_class": {k: {"n": by_class_n[k], **dict(by_class_vex[k])}
                            for k in ("code-available", "oss-attributed",
                                      "vendor-proprietary")},
        "by_cwe_top20": {cwe: dict(c) for cwe, c in cwe_top},
        "note": ("Static analysis only (no PoC, no execution). Deterministic legs; "
                 "sLLM analyst is reserved for interactive SBOM subsets."),
    }
    json.dump(summary, open(OUT_SUM, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--securebert", action="store_true")
    a = ap.parse_args()
    s = run(limit=a.limit, use_securebert=a.securebert)
    print("== STATIC VEX BATCH ==")
    print("findings :", s["total_findings"], "| code pairs:", s["code_pair_findings"])
    print("by VEX   :", s["by_vex"])
    print("by tier  :", s["by_tier"])
    print("by reach :", s["by_reachability"])
    print("by source-class:")
    for k, c in s["by_source_class"].items():
        print("   %-20s n=%-6d %s" % (k, c["n"], {x: c[x] for x in c if x != "n"}))
    print("wrote    :", os.path.relpath(OUT, BASE), "+", os.path.relpath(OUT_SUM, BASE))


if __name__ == "__main__":
    main()
