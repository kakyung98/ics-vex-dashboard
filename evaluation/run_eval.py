#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""One command that evaluates certification test items #3 and #4 end to end.

    python evaluation/run_eval.py

It makes sure each item's evaluation dataset exists (building it with the right flags
if it does not), scores the system against it, checks the result against the figure on
record, and writes a self-contained HTML report with the charts.

**This module owns no scoring rules.** It calls `src/cert_eval`, which calls
`tools/eval_cpe_match_precision.score`, `tools/eval_vex_precision.score` and
`tools/eval_q34_agreement.score` - the same functions the CLI scripts and the web
console score through. A second implementation would be a second set of numbers, and
the entire value of a certification figure is that one number comes out of one place.
What this module adds is the wiring the other entry points leave to the operator:
pinned builder flags, a dataset-vs-manifest check, a reproduction check, and a report.

Outputs land in `evaluation/out/`:

    results.json   every scored record, in full
    report.html    the visual report - open it in a browser
    run.json       what ran, with the dataset state and timings

Item #3 takes roughly 8 minutes (it identifies products for ~14k components against
the full NVD CPE index), so `--reuse` is offered for when only the report is being
iterated on. The reuse path is clearly marked in the output, because a report that
silently showed a cached figure would be indistinguishable from one that measured it.
"""
import argparse
import datetime
import json
import os
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
for p in (os.path.join(BASE, "src"), os.path.join(BASE, "tools"), HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import datasets as DS            # noqa: E402  (path set above)
import report as REPORT          # noqa: E402

OUT = os.path.join(HERE, "out")

# Which variant of each item this runner scores, and where the previously recorded
# figure lives. The variant choice is not cosmetic:
#
#   #4 is scored PRE-GATE on purpose. With the patch gate live the same scope reads
#   0.9930, but the gate decides from the fix signature plus the NVD range - the same
#   two authorities the ground truth's patch_verified labels come from. Agreement on a
#   shared oracle is structural, not earned, so the gated figure is circular and the
#   scorer prints a !! CIRCULAR warning. The honest headline is the pre-gate one.
#
#   #3 is scored with the DEFAULT SUT (the string cascade with retrieval behind it).
#   The cascade alone is the ablation, not the system: it abstains on 6,633 of 14,173
#   components and every one of those answers was reachable in the index.
PLAN = {
    "3": {"variant": "ai", "reuse": "results/cpe_match_precision.json",
          "title": "Item #3 — SBOM → CVE identification"},
    "4": {"variant": "pregate", "reuse": "results/vex_precision_all.json",
          "title": "Item #4 — VEX affected-judgment"},
    "q34": {"variant": None, "reuse": "results/q34_agreement.json",
            "title": "Q3 / Q4 solver agreement"},
}

# Component axes: they measure a PART of an item rather than the item, so they carry
# no acceptance criterion and are never reported as a certification figure. They exist
# because each item's headline hides a learned component whose own error rate the
# headline does not reveal - #3's trained encoder and #4's CTI-extraction LLM. Both
# run in seconds (they read caches), so there is no reason to make them opt-in.
COMPONENTS = [
    {"key": "encoder", "module": "eval_encoder_contribution",
     "title": "Item #3's encoder — what does it contribute?",
     "of": "3"},
    {"key": "cti", "module": "eval_cti_localization",
     "title": "Item #4's LLM — does it name the function the fix edits?",
     "of": "4"},
]


def _echo(msg=""):
    """print() that survives a non-UTF-8 console (this one is cp949)."""
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    print(str(msg).encode(enc, "replace").decode(enc, "replace"), flush=True)


def _progress(label):
    """A progress callback for the long item - throttled, one line, overwritten."""
    state = {"t": 0.0}

    def cb(done, total, note=""):
        now = time.time()
        if now - state["t"] < 2.0 and done < total:
            return
        state["t"] = now
        pct = 100.0 * done / total if total else 0.0
        sys.stdout.write("\r    %s %6.1f%%  (%s/%s) %-28s"
                         % (label, pct, "{:,}".format(done), "{:,}".format(total),
                            str(note)[:28]))
        sys.stdout.flush()
        if done >= total:
            sys.stdout.write("\n")
    return cb


def _reference(cert, item, variant):
    """The figure on record for this item+variant, or None."""
    ref = (cert.ITEMS.get(item) or {}).get("reference")
    if ref is None:
        return None
    if isinstance(ref, dict) and variant in ref:
        return ref[variant]
    return ref if not isinstance(ref, dict) else None


def _reproduces(result, reference):
    """Did this run land on the recorded figure? None when there is nothing to check.

    Compared at 4 decimal places - the precision of the published figures. A tighter
    comparison would fail on float noise and teach the operator to ignore the check.
    """
    if reference is None:
        return None
    got = result.get("precision")
    if got is None:
        return None
    return abs(round(got, 4) - round(reference, 4)) < 5e-5


def run_item(item, cert, rebuild=False, reuse=False):
    """Prepare the dataset, score the item, and return a record for the report."""
    plan = PLAN[item]
    meta = dict(cert.ITEMS[item])
    meta["title"] = plan["title"]
    rec = {"item": item, "variant": plan["variant"], "meta": meta,
           "reference": None, "result": None, "reproduces": None,
           "seconds": None, "source": "measured", "error": None}

    _echo("\n== item #%s  (%s) ==" % (item, meta.get("name_en") or meta.get("name")))
    _echo("  SUT      : %s" % meta.get("sut"))
    _echo("  criterion: %s" % (
        ("precision >= %.2f" % meta["acceptance"]) if meta.get("acceptance") is not None
        else meta.get("acceptance_label")))

    try:
        ds = DS.ensure(item, rebuild=rebuild, echo=_echo)
        rec["dataset"] = ds
        _echo("  dataset  : %s  (%s records%s)"
              % (ds["gt"], "{:,}".format(ds["records"] or 0),
                 "" if ds["expected"] is None
                 else ", manifest says %s" % "{:,}".format(ds["expected"])))

        reuse_path = os.path.join(BASE, plan["reuse"])
        if reuse and os.path.isfile(reuse_path):
            rec["result"] = json.load(open(reuse_path, encoding="utf-8"))
            rec["source"] = "reused from %s" % plan["reuse"]
            _echo("  REUSED   : %s (not measured in this run)" % plan["reuse"])
        else:
            t0 = time.time()
            if item == "3":
                _echo("  running  : %s" % meta.get("runtime_hint"))
            scorer = cert._SCORERS[item]
            rec["result"] = scorer(DS._p(DS.DATASETS[item]["gt"]), plan["variant"],
                                   _progress("item #%s" % item))
            rec["seconds"] = round(time.time() - t0, 1)

        res = rec["result"]
        rec["reference"] = _reference(cert, item, plan["variant"])
        rec["reproduces"] = _reproduces(res, rec["reference"])

        if res.get("precision") is not None:
            acc = meta.get("acceptance")
            verdict = "n/a" if acc is None else ("PASS" if res["precision"] >= acc
                                                 else "FAIL")
            _echo("  RESULT   : precision = %.4f   TP=%s FP=%s   -> %s"
                  % (res["precision"], "{:,}".format(res.get("TP") or 0),
                     "{:,}".format(res.get("FP") or 0), verdict))
        else:
            pq = res.get("per_question") or {}
            for q, d in sorted(pq.items()):
                _echo("  RESULT   : %s contradictions=%s recall=%s -> %s"
                      % (q, d.get("contradictions"),
                         "%.4f" % d["recall"] if d.get("recall") is not None else "-",
                         "PASS" if d.get("contradictions") == 0 else "FAIL"))
        if rec["reproduces"] is False:
            _echo("  !! this run (%.4f) differs from the recorded figure (%.4f)"
                  % (res.get("precision") or -1, rec["reference"]))
        elif rec["reproduces"]:
            _echo("  reproduces the recorded figure (%.4f)" % rec["reference"])

    except DS.DatasetError as exc:
        rec["error"] = str(exc)
        _echo("  SKIPPED  : %s" % exc)
    except Exception as exc:                                  # noqa: BLE001
        rec["error"] = "%s: %s" % (type(exc).__name__, exc)
        _echo("  FAILED   : %s" % rec["error"])
        _echo(traceback.format_exc())
    return rec


def run_components(wanted_items):
    """Score the component axes belonging to the items that ran."""
    out = []
    for spec in COMPONENTS:
        if spec["of"] not in wanted_items:
            continue
        rec = {"key": spec["key"], "title": spec["title"], "of": spec["of"],
               "result": None, "error": None}
        _echo("\n== component axis: %s ==" % spec["title"])
        try:
            mod = __import__(spec["module"])
            rec["result"] = mod.score()
            res = rec["result"]
            if res.get("error"):
                rec["error"] = res["error"]
                _echo("  SKIPPED  : %s" % res["error"])
            elif spec["key"] == "cti":
                _echo("  scored %d CVEs  agreement %.4f (exact) / %.4f (file-level)"
                      % (res["scored"], res["agreement"],
                         res["file_level_agreement"]))
            else:
                m = res["retrieval_marginal"]
                _echo("  retrieval marginal: TP +%d / FP +%d over %d recovered "
                      "-> %.4f" % (m["TP_added"], m["FP_added"],
                                   m["components_recovered_from_abstention"],
                                   m["precision_on_what_it_recovered"]))
        except Exception as exc:                                   # noqa: BLE001
            rec["error"] = "%s: %s" % (type(exc).__name__, exc)
            _echo("  FAILED   : %s" % rec["error"])
        out.append(rec)
    return out


def _evidence_tiers():
    """The item #4 evidence-tier mix, for the report's ordinal bar.

    Read from results/vex_v2_summary.json, which is a committed roll-up of gitignored
    caches and so is the one artifact that can fall behind the pipeline. If it is
    missing the report simply omits the chart rather than inventing a distribution.
    """
    p = os.path.join(BASE, "results", "vex_v2_summary.json")
    if not os.path.isfile(p):
        return {}
    return json.load(open(p, encoding="utf-8")).get("evidence_tier") or {}


def main():
    ap = argparse.ArgumentParser(
        description="Evaluate certification test items #3 / #4 and write a report.")
    ap.add_argument("--items", default="3,4",
                    help="comma-separated: 3, 4, q34 (default 3,4)")
    ap.add_argument("--rebuild", action="store_true",
                    help="rebuild the ground truths before scoring (slow; the flags "
                         "are pinned in datasets.py)")
    ap.add_argument("--reuse", action="store_true",
                    help="reuse the committed result JSONs instead of measuring - for "
                         "iterating on the report. Marked as reused in the output.")
    ap.add_argument("--out", default=OUT, help="output directory")
    ap.add_argument("--render-only", action="store_true",
                    help="re-render the report from the last run's out/run.json, "
                         "measuring nothing. For iterating on the report after a "
                         "13-minute measured run - the figures are the ones that run "
                         "produced, not fresh ones.")
    a = ap.parse_args()

    if a.render_only:
        run_path = os.path.join(a.out, "run.json")
        if not os.path.isfile(run_path):
            ap.error("no %s to re-render from - run without --render-only first"
                     % run_path)
        run = json.load(open(run_path, encoding="utf-8"))
        html_path = os.path.join(a.out, "report.html")
        open(html_path, "w", encoding="utf-8").write(REPORT.render(run))
        _echo("re-rendered from %s (measured %s)" % (run_path, run.get("generated")))
        _echo("  report : %s" % html_path)
        return 0

    wanted = [x.strip() for x in a.items.split(",") if x.strip()]
    unknown = [x for x in wanted if x not in PLAN]
    if unknown:
        ap.error("unknown item(s): %s (choose from %s)"
                 % (", ".join(unknown), ", ".join(PLAN)))

    import cert_eval as cert

    os.makedirs(a.out, exist_ok=True)
    _echo("ICS-VEX certification evaluation")
    _echo("  repo   : %s" % BASE)
    _echo("  items  : %s" % ", ".join("#" + x for x in wanted))
    _echo("  mode   : %s" % ("REUSED result JSONs (not measured)" if a.reuse
                             else "measured in this run"))

    t0 = time.time()
    items = [run_item(x, cert, rebuild=a.rebuild, reuse=a.reuse) for x in wanted]
    components = run_components(wanted)
    run = {
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "seconds": round(time.time() - t0, 1),
        "measured": not a.reuse,
        "items": items,
        "datasets": [it["dataset"] for it in items if it.get("dataset")],
        "components": components,
        "evidence_tier": _evidence_tiers(),
    }

    _results = {it["item"]: it["result"] for it in items if it.get("result")}
    _results.update({c["key"]: c["result"] for c in components if c.get("result")})
    json.dump(_results,
              open(os.path.join(a.out, "results.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    json.dump(run, open(os.path.join(a.out, "run.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2, default=str)
    html_path = os.path.join(a.out, "report.html")
    open(html_path, "w", encoding="utf-8").write(REPORT.render(run))

    _echo("\n== summary ==")
    for it in items:
        res = it.get("result") or {}
        acc = (it["meta"] or {}).get("acceptance")
        if it.get("error"):
            line = "did not run"
        elif res.get("precision") is not None:
            line = "precision %.4f  (acceptance %s)  %s" % (
                res["precision"], "n/a" if acc is None else ">= %.2f" % acc,
                "PASS" if acc is not None and res["precision"] >= acc else
                ("FAIL" if acc is not None else ""))
        else:
            tot = sum((q or {}).get("contradictions", 0)
                      for q in (res.get("per_question") or {}).values())
            line = "contradictions %d  %s" % (tot, "PASS" if tot == 0 else "FAIL")
        _echo("  item #%-4s %s" % (it["item"], line))
    _echo("\n  results : %s" % os.path.join(a.out, "results.json"))
    _echo("  report  : %s" % html_path)
    _echo("  elapsed : %.1fs" % run["seconds"])

    failed = [it["item"] for it in items if it.get("error")]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
