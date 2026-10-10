#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Split the benchmark into one file per asset, so a case can be read whole.

The bundle ships item3 as three jsonl files of 41,868 / 14,173 / 23,049 lines. That
shape is right for a scorer and wrong for a person: checking what happened to one
Siemens advisory means grepping three files and stitching the hits together.

This writes one JSON per advisory that carries everything about it in reading order —
what went in, what the answer key says, and what was excluded with the reason:

    benchmark/item3/by_asset/icsa-24-235-03.json
      { asset_id, counts, input[], ground_truth[], excluded[] }

The jsonl files stay. They are what tools/eval_cpe_match_precision.py reads, and
splitting a scorer's input into 1,201 files would only slow it down; the per-asset
view is a second projection of the same records, not a replacement. `_index.json`
lists every asset with its counts so the directory is navigable without opening
1,201 files.

item4 is left alone: 58 cases over 54 CVEs is already small enough to read.

Usage:
  python tools/split_benchmark_by_asset.py
  python tools/split_benchmark_by_asset.py --clean   # remove the split, keep jsonl
"""
import argparse
import collections
import json
import os
import shutil

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ITEM3 = os.path.join(BASE, "benchmark", "item3")
OUT = os.path.join(ITEM3, "by_asset")


def read(path):
    rows = []
    if not os.path.isfile(path):
        return rows
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows


def asset_of(rec):
    """Every record type carries the advisory differently."""
    si = rec.get("_sut_input") or {}
    if si.get("asset_id"):
        return si["asset_id"]
    if rec.get("asset_id"):
        return rec["asset_id"]
    cid = str(rec.get("component_id") or rec.get("bom_ref") or "")
    # excluded.jsonl keeps the raw harvest record, whose asset is its own field
    return cid.split(":")[1].split("-")[0] if cid.startswith("variant:") else "_unassigned"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clean", action="store_true")
    a = ap.parse_args()

    if a.clean:
        if os.path.isdir(OUT):
            shutil.rmtree(OUT)
            print("removed", os.path.relpath(OUT, BASE))
        else:
            print("nothing to remove")
        return

    gt = read(os.path.join(ITEM3, "ground_truth.jsonl"))
    inp = read(os.path.join(ITEM3, "input.jsonl"))
    exc = read(os.path.join(ITEM3, "excluded.jsonl"))

    buckets = collections.defaultdict(lambda: {"input": [], "ground_truth": [],
                                               "excluded": []})
    for r in inp:
        buckets[r.get("asset_id") or "_unassigned"]["input"].append(r)
    for r in gt:
        buckets[asset_of(r)]["ground_truth"].append(r)
    for r in exc:
        buckets[asset_of(r)]["excluded"].append(r)

    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT, exist_ok=True)

    index = []
    for asset in sorted(buckets):
        b = buckets[asset]
        pos = sum(1 for r in b["ground_truth"] if r.get("applicable"))
        doc = {
            "asset_id": asset,
            "counts": {"input": len(b["input"]),
                       "ground_truth": len(b["ground_truth"]),
                       "applicable_true": pos,
                       "applicable_false": len(b["ground_truth"]) - pos,
                       "excluded": len(b["excluded"])},
            "input": b["input"],
            "ground_truth": b["ground_truth"],
            "excluded": b["excluded"],
        }
        json.dump(doc, open(os.path.join(OUT, "%s.json" % asset), "w",
                            encoding="utf-8"), ensure_ascii=False, indent=1)
        index.append({"asset_id": asset, **doc["counts"]})

    index.sort(key=lambda r: -r["ground_truth"])
    json.dump({"note": "one file per advisory; the jsonl files beside this directory "
                       "remain the scorer's input and this is a second projection of "
                       "the same records",
               "assets": len(index), "files": index},
              open(os.path.join(OUT, "_index.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    total_gt = sum(r["ground_truth"] for r in index)
    print("assets     : %d files" % len(index))
    print("records    : gt %d | input %d | excluded %d"
          % (total_gt, sum(r["input"] for r in index),
             sum(r["excluded"] for r in index)))
    print("largest    : %s" % ", ".join(
        "%s(%d)" % (r["asset_id"], r["ground_truth"]) for r in index[:3]))
    print("->", os.path.relpath(OUT, BASE))


if __name__ == "__main__":
    main()
