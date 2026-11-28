"""Verify the full-population evidence and staged workbooks before publication."""
import csv
import hashlib
import json
import os
import shutil
import sys
from collections import defaultdict
from itertools import zip_longest
from pathlib import Path

from openpyxl import load_workbook

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results/item4_source_condition_question_links"
DEST = ROOT / "data/자산유형별_엑셀"


def read(name):
    return json.loads((OUT / name).read_bytes())


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_population():
    data = read("condition_question_links.json")
    population = data["population"]
    sources = {}
    all_ids = set()
    corpus = OUT / "frozen_sources/cve_evidence.jsonl"
    if not corpus.is_file():
        corpus = ROOT / "benchmark/item4_evaluation/csaf_vex_v2/sources/cve_evidence.jsonl"
    with corpus.open(encoding="utf8") as stream:
        for line in stream:
            record = json.loads(line)["original"]
            all_ids.add(record["cve"])
            for source in record["sources"]:
                if source.get("text"):
                    sources[record["cve"] + "/" + source["id"]] = source["text"]
    assert len(all_ids) == 12418 and set(population) == all_ids
    cases = read("extracted_source_conditions.json")
    assert set(cases) == {k for p in population.values() for k in p["source_case_ids"]}
    intervals = defaultdict(list)
    for row in read("source_coverage.json"):
        if row.get("case_id"):
            assert row["case_id"] in cases and row["status"] == "본문 검토 완료"
            intervals[row["source"]].append((row["start"], row["end"]))
    assert set(intervals) == set(sources)
    for key, spans in intervals.items():
        end = 0
        for start, stop in sorted(spans):
            assert 0 <= start <= end and start < stop <= len(sources[key])
            end = max(end, stop)
        assert end == len(sources[key])
    units = data["units"]
    assert len({u["id"] for u in units}) == len(units)
    assert {u["id"] for u in units} == {i for p in population.values() for i in p["units"]}
    for unit in units:
        assert unit["deployment_status"] == "미확인"
        if not unit["verified"]:
            assert not unit["atoms"] and unit["mapping_status"] == "미확인"
            continue
        text = sources[unit["cve"] + "/" + unit["source_id"]]
        assert hashlib.sha256(text.encode()).hexdigest() == unit["source_sha256"]
        condition = unit["original_condition"]
        assert text[slice(*condition["source_span"])] == condition["source_quote"]
        for atom in unit["atoms"]:
            assert unit["source_grounding"] == "supported" and condition["necessity"] == "required"
            assert atom["verification"]["keep"] and atom["required"] in ("o", "x")
            assert text[slice(*atom["source_span"])] == atom["quote"]
    with (ROOT / "data/operator_asset_keys_clustered.csv").open(encoding="utf-8-sig", newline="") as f:
        catalog = list(csv.DictReader(f))
    bindings = {(r["asset_type_id"], r["key"]) for r in catalog}
    assert len(bindings) == 505
    assert bindings == {(r["asset_type_id"], q["key"]) for q in data["questions"] for r in q["rows"]}
    with (OUT / "population_ledger.csv").open(encoding="utf-8-sig", newline="") as f:
        ledger = list(csv.DictReader(f))
    assert len(ledger) == len(all_ids) and {r["CVE"] for r in ledger} == all_ids
    return bindings, dict(cves=len(all_ids), source_passages=len(sources), cases=len(cases),
                          conditions=len(units), questions=len(bindings))


def main(stage):
    bindings, report = verify_population()
    projections = read("workbook_type_rows.json")
    files = sorted(DEST.glob("A[0-9][0-9][0-9][0-9]_*.xlsx"))
    assert len(files) == len({f.name[:5] for f in files}) == 18
    hashes = {}
    missing = object()
    for file in files:
        hashes[file] = file_hash(file)
        before = load_workbook(file, read_only=True)
        after = load_workbook(stage / ("linked-" + file.name), read_only=True)
        try:
            for sheet in before.sheetnames:
                for a, b in zip_longest(before[sheet].values, after[sheet].values, fillvalue=missing):
                    assert a == b, (file.name, sheet)
            expected = {key for aid, key in bindings if aid == file.name[:5]}
            questions = list(after["질문별 연결 집계"].values)[3:]
            assert len(questions) == len(expected) and {r[0] for r in questions} == expected
            rows = after["악용 조건 연결"].iter_rows(min_row=4, values_only=True)
            expected_rows = projections[file.name[:5]]
            if expected_rows:
                for row, expected_row in zip_longest(rows, expected_rows):
                    assert row and expected_row and row[:10] == tuple(expected_row[:10])
            else:
                assert next(rows)[0] == "미확인" and next(rows, None) is None
        finally:
            before.close()
            after.close()
    # Preserve a verified copy even if Excel locks an original or the operator edits it.
    verified = OUT / "자산유형별_엑셀"
    verified.mkdir(exist_ok=True)
    pending = []
    for file in files:
        shutil.copy2(stage / ("linked-" + file.name), verified / file.name)
        if hashes[file] != file_hash(file):
            pending.append(file.name)
            continue
        staged = file.with_suffix(".xlsx.pending")
        try:
            shutil.copy2(verified / file.name, staged)
            os.replace(staged, file)
        except PermissionError:
            pending.append(file.name)
        finally:
            staged.unlink(missing_ok=True)
    report.update(verified_workbooks=18, original_files_pending=pending, verified_folder=str(verified))
    (OUT / "verification.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf8")
    print(json.dumps(report, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
