#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gather the PoCs produced by verify_evidence together with the critic and verifier
verdicts.

Takes the PoC code out of each CVE's conversations/exploiter.json and writes
  results/pocs/<CVE>.py            a runnable script (provenance and verdict in the
                                   header comment)
plus an index of everything:
  results/pocs/INDEX.md            a table (code present, critic, verifier, tier)
  results/pocs/index.json          machine-readable
Read-only - safe to run while a batch is in progress.
"""
import csv
import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVID = os.path.join(BASE, "results", "verify_evidence")
OUT = os.path.join(BASE, "results", "pocs")
CSV = os.path.join(BASE, "results", "verify_full_summary.csv")


def load_json(p):
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return None


def outcome_map():
    m = {}
    if os.path.exists(CSV):
        for r in csv.DictReader(open(CSV, encoding="utf-8")):
            m[r["cve"]] = r.get("outcome", "")
    return m


def main():
    os.makedirs(OUT, exist_ok=True)
    outcomes = outcome_map()
    rows = []
    for cve in sorted(os.listdir(EVID)):
        conv = os.path.join(EVID, cve, "conversations")
        if not os.path.isdir(conv):
            continue
        expl = load_json(os.path.join(conv, "exploiter.json")) or {}
        crit = load_json(os.path.join(conv, "exploit_critic.json")) or {}
        veri = load_json(os.path.join(conv, "ctf_verifier.json")) or {}
        _runlog = os.path.join(EVID, cve, "run.log")
        _logtxt = open(_runlog, encoding="utf-8", errors="ignore").read() if os.path.exists(_runlog) else ""
        poc = expl.get("poc") or expl.get("exploit") or ""
        if isinstance(poc, (dict, list)):
            poc = json.dumps(poc, ensure_ascii=False, indent=2)
        poc = (poc or "").strip()
        crit_ok = str(crit.get("decision", crit.get("success", ""))).lower() in ("yes", "true", "accepted")
        crit_analysis = crit.get("analysis") or crit.get("reason") or ""
        # The Validator step (run.log) is the authority on the final verdict;
        # ctf_verifier.json is an intermediate agent artefact.
        import re as _re
        veri_ok = bool(_re.search(r"Results:\s*\{'success':\s*'True'", _logtxt)) and                   ("CVE reproduced" in _logtxt or "Flag found" in _logtxt)
        veri_reason = "CVE reproduced (execution-verified)" if veri_ok else                       (veri.get("reason","") or "not reproduced")
        tier = outcomes.get(cve, "")

        wrote = ""
        if poc:
            hdr = (
                "#!/usr/bin/env python3\n"
                "# ===== ICS-VEXForge extracted PoC =====\n"
                f"# CVE:      {cve}\n"
                f"# tier:     {tier}\n"
                f"# critic:   {'accepted' if crit_ok else 'not-accepted'}\n"
                f"# verifier: {'success' if veri_ok else 'NOT verified'}"
                f"{'' if veri_ok else '  (reason: ' + str(veri_reason) + ')'}\n"
                "# WARNING: LLM-generated, critic-accepted but NOT execution-verified.\n"
                "#          Run only in the isolated verification sandbox.\n"
                "# ======================================\n\n"
            )
            fp = os.path.join(OUT, f"{cve}.py")
            open(fp, "w", encoding="utf-8").write(hdr + poc + "\n")
            wrote = f"{cve}.py"

        rows.append({
            "cve": cve, "tier": tier, "has_poc": bool(poc),
            "poc_file": wrote, "critic_accepted": crit_ok,
            "verifier_success": veri_ok, "verifier_reason": veri_reason,
            "critic_analysis": crit_analysis[:500],
        })

    # the index
    json.dump(rows, open(os.path.join(OUT, "index.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    with_poc = [r for r in rows if r["has_poc"]]
    md = ["# Extracted PoCs", "",
          f"- evidence dirs scanned: **{len(rows)}**",
          f"- with a generated PoC: **{len(with_poc)}**",
          f"- critic-accepted: **{sum(r['critic_accepted'] for r in rows)}**",
          f"- execution-verified: **{sum(r['verifier_success'] for r in rows)}**",
          "",
          "| CVE | tier | PoC | critic | verifier |",
          "|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda x: (not x["has_poc"], x["cve"])):
        md.append(f"| {r['cve']} | {r['tier']} | "
                  f"{'✓ '+r['poc_file'] if r['has_poc'] else '—'} | "
                  f"{'accepted' if r['critic_accepted'] else '—'} | "
                  f"{'✓' if r['verifier_success'] else '✗'} |")
    open(os.path.join(OUT, "INDEX.md"), "w", encoding="utf-8").write("\n".join(md) + "\n")

    print(f"scanned {len(rows)} evidence dirs")
    print(f"  PoC extracted     : {len(with_poc)} -> results/pocs/*.py")
    print(f"  critic-accepted   : {sum(r['critic_accepted'] for r in rows)}")
    print(f"  execution-verified: {sum(r['verifier_success'] for r in rows)}")
    print(f"  index             : results/pocs/INDEX.md , index.json")


if __name__ == "__main__":
    main()
