#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run the certification test items (#3, #4) from the web app.

The point of the certification page is that a reviewer can hand the system the
evaluation dataset and watch it produce the figure that was certified. That only
means anything if the page scores through the SAME code the measurement was made
with, so this module owns no scoring rules at all: it calls
`tools/eval_cpe_match_precision.score` and `tools/eval_vex_precision.score`, and
everything here is about getting a dataset to them and a result back.

Two facts shape the design:

  * Item #3 takes ~8 minutes. It identifies products for ~14k components against
    an 18MB CPE index, so it cannot run inside a request. Jobs run on a thread and
    the page polls; `progress` is threaded through so the poll can say where it is.
  * A dataset may be the bundled one or an uploaded one. The bundled files carry a
    SHA-256, so "the dataset the figure was measured on" is checkable rather than
    asserted. An upload is scored exactly the same way and reported as `uploaded`,
    never silently compared against the recorded figure.
"""
import hashlib
import json
import os
import sys
import threading
import time
import traceback
import uuid

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "tools"))
UPLOADS = os.path.join(BASE, "data", "cert_uploads")

# Each item names the SUT entry point, the acceptance criterion from the test
# document, and the dataset the certified figure was measured on. `reference` is
# that figure, kept beside the item so the page can show measured-vs-now instead
# of asking the reader to remember what the number was supposed to be.
ITEMS = {
    "3": {
        "id": "3",
        "name": "SBOM-based public vulnerability identification precision",
        "name_en": "SBOM -> CVE identification precision",
        "metric": "precision = TP / (TP + FP)",
        "acceptance": 0.80,
        "sut": "src/cpe_match_ai (L0 NVD CPE index + L3 vendor guard + trained-encoder retrieval)",
        "dataset": {"gt": "data/cpe_match_eval.jsonl"},
        "record_unit": "records ((component, CVE) pairs)",
        "runtime_hint": "about 8 min (14,173 components x the full NVD CPE index)",
        # The retrieval-backed matcher is the default SUT: the string cascade
        # abstains on 6,633 of 14,173 components and every one of those answers
        # was reachable, so the cascade alone is the ablation, not the system.
        "variants": [
            {"key": "ai", "label": "string cascade + trained-encoder retrieval (default SUT)"},
            {"key": "string", "label": "string cascade only (ablation)"},
        ],
        "reference": {"ai": 0.949, "string": 0.9499},
    },
    "4": {
        "id": "4",
        "name": "VEX affected-judgment precision",
        "name_en": "VEX affected-judgment precision",
        "metric": "precision = TP / (TP + FP),  positive class = affected",
        "acceptance": 0.85,
        "sut": "tools/vex_judge_v2 (Q1 patch gate + Q2 presence, Q3/Q4 as tier)",
        "dataset": {"gt": "data/vex_gt_all.jsonl",
                    "sut": "data/vex_v2_pregate.json",
                    "sut_patched": "data/vex_v2_patched.json",
                    "sut_gated": "data/vex_v2.json"},
        "record_unit": "records ((CVE, build) pairs)",
        "runtime_hint": "instant (scores the verdict cache) - population = all 267 collected-source CVEs",
        # Three scopes, because one number cannot carry the whole claim. The
        # headline is the pre-gate vulnerable-build figure: it is the largest
        # scope whose ground truth does not share an oracle with the SUT.
        # An `independent` scope used to sit here, scoring only the GT's four
        # execution_verified labels. It was RETIRED: those labels came from an
        # execution-verification loop (results/exec_verification*.json, August
        # 2025) that the project replaced with the Q1-Q4 solver pipeline, so the
        # scope published a 0.6667 produced by a methodology the SUT no longer
        # uses, over 2 CVEs x 2 builds, with no path to growing it - the
        # collected corpus is overwhelmingly ICS firmware that cannot be built
        # and triggered. The four labels REMAIN in data/vex_gt_all.jsonl, because
        # execution is sound evidence and deleting correct labels would be worse;
        # what is gone is the claim that scoring them is an independent
        # evaluation. Independence is now carried by the Q3/Q4 axis below, whose
        # authorities (shipped public headers, NVD CVSS) are outside this
        # repository's own tooling.
        "variants": [
            {"key": "pregate", "label": "vulnerable build, patch gate OFF (headline, non-circular)"},
            {"key": "allbuilds", "label": "both builds, gate ON (carries a circularity warning)"},
        ],
        "reference": {"pregate": 0.9718, "allbuilds": 0.993},
    },
    "q34": {
        "id": "q34",
        "name": "Q3 reachability / Q4 controllability vs external authorities",
        "name_en": "Q3 reachability / Q4 controllability agreement",
        "metric": "contradictions == 0; recall reported, precision withheld (no negative class)",
        # No acceptance criterion exists for this: it is not one of the two
        # certification items. It is here because without it Joern and Z3
        # contribute 0 to every published figure - item #4 scores the `affected`
        # verdict, which vex_judge_v2 decides at Q2, while Q3/Q4 only set the
        # evidence tier and no answer key carried a tier.
        # Not a numeric precision threshold, so `acceptance` stays None and the
        # page renders `acceptance_label` instead. The bar is on contradictions
        # because the other candidates cannot carry one: precision has no negative
        # class to fail against, and a recall threshold is met outright by a system
        # that answers "yes" to everything. See tools/eval_q34_agreement.py.
        "acceptance": None,
        "acceptance_label": "criterion: contradictions = 0 (this repository's own; not a certification test item)",
        "sut": "tools/joern_reachability (Joern CPG) + tools/z3_controllability (Z3)",
        "dataset": {"gt": "data/vex_q34_gt.jsonl",
                    "reach": "data/reachability.json",
                    "ctrl": "data/controllability.json"},
        # 285 labels over a 267-CVE population: a CVE carries up to two labels,
        # one per question, and 249 of the 534 possible pairs are held out.
        "record_unit": "labels ((CVE, question) pairs over a 267-CVE population)",
        "runtime_hint": "instant (scores the verdict cache) - authorities = shipped public headers, NVD CVSS AV/UI",
        "variants": [{"key": "both", "label": "Q3 + Q4 (supplementary; criterion contradictions = 0)"}],
        # Recalls, not precisions: Q4's answer key has no negative class, so a
        # precision there is 1.0000 by construction. Q3's two misses are Joern
        # refuting `GENERAL_NAME_cmp` (CVE-2020-1971) and zlib's `inflate`
        # (CVE-2022-37434) - both declared in a shipped public header, which is
        # exactly the false negative the module docstring predicted.
        "reference": {"both": {"Q3_recall": 0.9655, "Q4_recall": 1.0,
                               "Q3_contradictions": 2, "Q4_contradictions": 0}},
    },
}

_JOBS = {}
_LOCK = threading.Lock()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _abs(rel):
    return rel if os.path.isabs(rel) else os.path.join(BASE, rel)


def dataset_info(item_id):
    """What the bundled dataset for this item is, with checkable identity."""
    it = ITEMS[item_id]
    out = {}
    for role, rel in it["dataset"].items():
        p = _abs(rel)
        if not os.path.isfile(p):
            out[role] = {"path": rel, "present": False}
            continue
        n = sum(1 for _ in open(p, encoding="utf-8")) if p.endswith(".jsonl") else None
        out[role] = {"path": rel, "present": True,
                     "bytes": os.path.getsize(p), "records": n,
                     "sha256": sha256(p)}
    return out


def items():
    """Item metadata plus the dataset identity, for the page to render."""
    out = []
    for k in sorted(ITEMS):
        it = dict(ITEMS[k])
        it["dataset_info"] = dataset_info(k)
        out.append(it)
    return out


def _score_item3(gt, variant, progress):
    import eval_cpe_match_precision as E3
    return E3.score(gt, matcher=variant, progress=progress)


def _score_item4(gt, variant, progress):
    import eval_vex_precision as E4
    d = ITEMS["4"]["dataset"]
    if variant == "pregate":
        return E4.score(gt, _abs(d["sut"]), None, build="vulnerable")
    if variant == "allbuilds":
        return E4.score(gt, _abs(d["sut_gated"]), _abs(d["sut_patched"]), build="all")
    raise ValueError("unknown variant for item #4: %r" % variant)


def _score_q34(gt, variant, progress):
    import eval_q34_agreement as EQ
    d = ITEMS["q34"]["dataset"]
    return EQ.score(gt, _abs(d["reach"]), _abs(d["ctrl"]))


_SCORERS = {"3": _score_item3, "4": _score_item4, "q34": _score_q34}


def _reproduces(res, ref, dataset):
    """Did this run land on the figure that was recorded? None when there is
    nothing to compare against.

    An uploaded dataset has no recorded figure, so the comparison is reported as
    not applicable rather than as a mismatch. The Q3/Q4 axis has no single
    precision - its reference is a dict of per-question recalls - so the check is
    'every recorded figure still holds', which is what keeps a solver change from
    moving these numbers unnoticed.
    """
    if dataset == "uploaded" or ref is None:
        return None
    if isinstance(ref, dict):
        for q in ("Q3", "Q4"):
            d = (res.get("per_question") or {}).get(q) or {}
            want = ref.get("%s_recall" % q)
            got = d.get("recall")
            if want is not None and (got is None or abs(got - want) > 1e-9):
                return False
            wc = ref.get("%s_contradictions" % q)
            if wc is not None and d.get("contradictions") != wc:
                return False
        return True
    return abs(res["precision"] - ref) < 1e-9


def _run(job_id, item_id, gt, variant):
    def progress(done, total, note):
        with _LOCK:
            j = _JOBS[job_id]
            j["progress"] = {"done": done, "total": total, "note": note}
            j["pct"] = round(100.0 * done / total, 1) if total else None

    try:
        res = _SCORERS[item_id](gt, variant, progress)
        ref = ITEMS[item_id]["reference"].get(variant)
        with _LOCK:
            j = _JOBS[job_id]
            j.update(state="done", result=res, finished=time.time(),
                     reference_precision=ref,
                     # A run on the bundled dataset must land on the certified
                     # figure; an uploaded dataset has no figure to match, so the
                     # comparison is reported as not applicable rather than as a
                     # mismatch.
                     reproduces=_reproduces(res, ref, j["dataset"]))
    except Exception:
        with _LOCK:
            _JOBS[job_id].update(state="error", error=traceback.format_exc(),
                                 finished=time.time())


def start(item_id, variant=None, gt_path=None, uploaded=False):
    item_id = str(item_id)
    if item_id not in ITEMS:
        raise ValueError("unknown test item: %r" % item_id)
    it = ITEMS[item_id]
    variant = variant or it["variants"][0]["key"]
    if variant not in {v["key"] for v in it["variants"]}:
        raise ValueError("unknown variant %r for item #%s" % (variant, item_id))
    gt = _abs(gt_path or it["dataset"]["gt"])
    if not os.path.isfile(gt):
        raise FileNotFoundError(gt)

    job_id = uuid.uuid4().hex[:12]
    with _LOCK:
        _JOBS[job_id] = {
            "job": job_id, "item": item_id, "variant": variant,
            "state": "running", "started": time.time(),
            "gt": os.path.relpath(gt, BASE) if gt.startswith(BASE) else gt,
            "gt_sha256": sha256(gt),
            "dataset": "uploaded" if uploaded else "bundled",
            "progress": None, "pct": None,
        }
    threading.Thread(target=_run, args=(job_id, item_id, gt, variant),
                     daemon=True).start()
    return _JOBS[job_id]


def job(job_id):
    with _LOCK:
        j = _JOBS.get(job_id)
        return dict(j) if j else None


def jobs():
    """Job summaries for the history table.

    The full result is dropped - item #3's carries 40 FP examples and every
    disclosure string, and the history only needs to say what ran and what it
    scored - but the precision is lifted out, because a history row without the
    number it produced is not a history of anything.
    """
    out = []
    with _LOCK:
        for j in sorted(_JOBS.values(), key=lambda x: -x["started"]):
            row = {k: v for k, v in j.items() if k != "result"}
            res = j.get("result") or {}
            row["precision"] = res.get("precision")
            row["passed"] = res.get("pass")
            out.append(row)
    return out


def save_upload(item_id, filename, data):
    """Store an uploaded dataset and return its path.

    Kept under data/cert_uploads/<item>/ and never written over a bundled file:
    an upload must not be able to change what the certified figure was measured
    against.
    """
    item_id = str(item_id)
    if item_id not in ITEMS:
        raise ValueError("unknown test item: %r" % item_id)
    safe = os.path.basename(filename or "uploaded.jsonl").replace("\\", "_")
    if not safe.endswith(".jsonl"):
        raise ValueError("dataset must be .jsonl in the ground-truth schema")
    d = os.path.join(UPLOADS, item_id)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "%s-%s" % (uuid.uuid4().hex[:8], safe))
    with open(p, "wb") as f:
        f.write(data)
    return p


def validate_gt(item_id, path):
    """Does this file look like the ground truth for that item?

    A dataset in the wrong schema would otherwise score 0 TP / 0 FP and read as a
    legitimate 0.0000 result, which is a worse failure than refusing the file.
    """
    required = {
        "3": {"component_id", "cve_id", "applicable"},
        "4": {"cve_id", "expected_status", "_build", "evidence_type"},
        "q34": {"cve_id", "question", "expected_verdict", "evidence_type"},
    }[str(item_id)]
    n = 0
    missing = None
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception as e:
            return {"ok": False, "records": n,
                    "error": "line %d is not JSON: %s" % (n + 1, e)}
        gap = required - set(r)
        if gap:
            missing = sorted(gap)
            break
        n += 1
        if n >= 200:
            break
    if missing:
        return {"ok": False, "records": n,
                "error": "record %d is missing %s" % (n + 1, missing),
                "required_fields": sorted(required)}
    if not n:
        return {"ok": False, "records": 0, "error": "no records"}
    return {"ok": True, "records_checked": n, "required_fields": sorted(required)}
