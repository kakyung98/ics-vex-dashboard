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
        "name": "SBOM 기반 공개 취약점 식별 정밀도",
        "name_en": "SBOM -> CVE identification precision",
        "metric": "precision = TP / (TP + FP)",
        "acceptance": 0.80,
        "sut": "src/cpe_match_ai (L0 NVD CPE index + L3 vendor guard + trained-encoder retrieval)",
        "dataset": {"gt": "data/cpe_match_eval.jsonl"},
        "runtime_hint": "약 8분 (14,173개 컴포넌트 × 전체 NVD CPE 인덱스)",
        # The retrieval-backed matcher is the default SUT: the string cascade
        # abstains on 6,633 of 14,173 components and every one of those answers
        # was reachable, so the cascade alone is the ablation, not the system.
        "variants": [
            {"key": "ai", "label": "문자열 캐스케이드 + 학습 인코더 검색 (기본 SUT)"},
            {"key": "string", "label": "문자열 캐스케이드만 (비교용 ablation)"},
        ],
        "reference": {"ai": 0.949, "string": 0.9499},
    },
    "4": {
        "id": "4",
        "name": "VEX 기반 식별된 취약점 영향 판단 정밀도",
        "name_en": "VEX affected-judgment precision",
        "metric": "precision = TP / (TP + FP),  positive class = affected",
        "acceptance": 0.85,
        "sut": "tools/vex_judge_v2 (Q0 patch gate + Q1 presence, Q2/Q3 as tier)",
        "dataset": {"gt": "data/vex_gt_all.jsonl",
                    "sut": "data/vex_v2_pregate.json",
                    "sut_patched": "data/vex_v2_patched.json",
                    "sut_gated": "data/vex_v2.json"},
        "runtime_hint": "즉시 (판정 캐시를 채점) · 모집단 = 소스 수집된 267 CVE 전수",
        # Three scopes, because one number cannot carry the whole claim. The
        # headline is the pre-gate vulnerable-build figure: it is the largest
        # scope whose ground truth does not share an oracle with the SUT.
        "variants": [
            {"key": "pregate", "label": "취약 빌드 · 패치게이트 OFF (주 지표, 비순환)"},
            {"key": "allbuilds", "label": "전체 빌드 · 게이트 ON (순환 경고 포함)"},
            {"key": "independent",
             "label": "실행검증 증거만 (오라클 비공유, n=4 — 합격기준 미달, 공시용)"},
        ],
        # Measured over the full collected-source population (267 CVEs, 80 GT
        # cases). `independent` is BELOW the acceptance criterion and is kept
        # here anyway: it is a disclosure scope, not the certification metric,
        # and hiding a scope because it reads badly is how a benchmark stops
        # meaning anything. Its single FP is CVE-2024-4340's patched build -
        # see the variant label.
        "reference": {"pregate": 0.9718, "allbuilds": 0.993,
                      "independent": 0.6667},
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
    if variant == "independent":
        return E4.score(gt, _abs(d["sut_gated"]), _abs(d["sut_patched"]),
                        build="all", independent=True)
    raise ValueError("unknown variant for item #4: %r" % variant)


def _run(job_id, item_id, gt, variant):
    def progress(done, total, note):
        with _LOCK:
            j = _JOBS[job_id]
            j["progress"] = {"done": done, "total": total, "note": note}
            j["pct"] = round(100.0 * done / total, 1) if total else None

    try:
        fn = _score_item3 if item_id == "3" else _score_item4
        res = fn(gt, variant, progress)
        ref = ITEMS[item_id]["reference"].get(variant)
        with _LOCK:
            j = _JOBS[job_id]
            j.update(state="done", result=res, finished=time.time(),
                     reference_precision=ref,
                     # A run on the bundled dataset must land on the certified
                     # figure; an uploaded dataset has no figure to match, so the
                     # comparison is reported as not applicable rather than as a
                     # mismatch.
                     reproduces=(None if j["dataset"] == "uploaded" or ref is None
                                 else abs(res["precision"] - ref) < 1e-9))
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
    required = ({"component_id", "cve_id", "applicable"} if str(item_id) == "3"
                else {"cve_id", "expected_status", "_build", "evidence_type"})
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
