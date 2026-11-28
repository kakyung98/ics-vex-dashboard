"""Paired defensive V4 regression on frozen O/X worlds and historical model outputs."""

import argparse
import hashlib
import json
import sqlite3
import sys
import tarfile
import tempfile
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from copy import deepcopy
from pathlib import Path
from time import monotonic
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
DATA = "benchmark/item4_evaluation/extracted_ox_v3"
RESULT = "results/item4_extracted_ox_v3"
PRODUCER = "source_extraction_audit"
RUN = "item4-fixed-world-replay/1"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verified(name):
    row = FILES.execute("select payload from files where name=?", (name,)).fetchone()
    if not row:
        raise ValueError("Missing archive record: " + name)
    raw = row[0]
    if MANIFEST[name] != sha(raw):
        raise ValueError("Frozen file changed: " + name)
    return json.loads(raw)


def load_delivery(path):
    global DELIVERY, MANIFEST
    DELIVERY = Path(path)
    MANIFEST = json.loads((DELIVERY / "delivery_manifest.json").read_bytes())


def open_spool(path):
    global FILES
    FILES = sqlite3.connect(Path(path).as_uri() + "?mode=ro&immutable=1", uri=True)


def prepare_spool(path):
    # A single sequential archive pass avoids 80,000 seeks on the HDD.
    starts = (
        DATA + "/cves/",
        DATA + "/references/",
        RESULT + "/cves/",
        PRODUCER + "/raw/",
        PRODUCER + "/requests/",
        "results/mulval_cache/",
    )
    verification = json.loads(
        (ROOT / "results/item4_extracted_ox_v3_20261120/verification.json").read_bytes()
    )
    archive = DELIVERY / "delivery.tar.gz"
    h = hashlib.sha256()
    with archive.open("rb") as f:
        for block in iter(lambda: f.read(4194304), b""):
            h.update(block)
    if h.hexdigest() != verification["archive"]["sha256"]:
        raise ValueError("Frozen delivery archive differs from the verified release")
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute("CREATE TABLE files(name TEXT PRIMARY KEY,payload BLOB NOT NULL)")
    # Large compressed chunks repeatedly copy long decompressed tails for small
    # tar members in Python's streaming reader. Bound those copies here.
    with tarfile.open(archive, mode="r|gz", bufsize=16 * 1024) as t:
        for entry in t:
            if (
                entry.name.startswith(starts)
                or entry.name == DATA + "/population_ledger.json"
            ) and entry.isfile():
                payload = t.extractfile(entry).read()
                if sha(payload) != MANIFEST[entry.name]:
                    raise ValueError("Delivery manifest mismatch " + entry.name)
                conn.execute("INSERT INTO files VALUES (?,?)", (entry.name, payload))
    conn.commit()
    conn.close()
    open_spool(path)


def init_worker(path, spool):
    load_delivery(path)
    open_spool(spool)
    from src.item4.decision import mulval_attack_graphs as mulval

    # Exact byte-pinned prior MulVAL receipts only; never silently simulate a graph.
    def receipt(program):
        name = "results/mulval_cache/" + program["sha256"] + ".json"
        if name not in MANIFEST:
            raise RuntimeError("No frozen MulVAL receipt matches this program")
        value = verified(name)
        if value["program_sha256"] != program["sha256"] or value[
            "sha256"
        ] != mulval.digest({k: v for k, v in value.items() if k != "sha256"}):
            raise ValueError("Frozen MulVAL receipt is invalid")
        return value

    mulval.generate = receipt


def raw_index():
    rows = defaultdict(list)
    for name in MANIFEST:
        if not name.startswith(PRODUCER + "/raw/"):
            continue
        raw = verified(name)
        if raw.get("role") != "exploitation-prerequisites":
            continue
        request = verified(f"{PRODUCER}/requests/{raw['request_id']:07}.json")
        if any(
            request[k] != raw[k] for k in ("cve", "input_sha256", "role", "request_id")
        ):
            raise ValueError("Archived request/response mismatch")
        rows[raw["cve"]].append((raw["request_id"], name))
    return rows


def replay_extraction(cve, components, previous, responses):
    from src.item4.workflow import source_analysis_jobs as Q
    from src.item4.analysis import exploitation_prerequisites as V

    old = previous.get("prerequisite")
    audit = {
        "source_context": "unchanged",
        "v1_rows": 0,
        "v1_added_fields_complete": False,
    }

    def replay(record):
        if previous.get("source_kind") == "Product-scoped ICSA":
            old_record = {
                "cve": cve,
                "products": previous["advisory_context"]["products"],
                "sources": previous["sources"],
            }
        else:
            old_record = {
                "cve": cve,
                "products": [],
                "sources": previous.get("sources", record["sources"]),
            }
        if V.digest(old_record) != V.digest(record):
            audit["source_context"] = "changed"
        products = {p["key"]: p for p in record["products"]}
        if old:
            if old.get("source_record_sha256") != V.digest(old_record) or old[
                "sha256"
            ] != V.digest({k: v for k, v in old.items() if k != "sha256"}):
                raise ValueError("Archived extraction seal/source mismatch")
            # Draft references have been resolved already. Revalidate the unchanged
            # model draft against current source text and structured product scope.
            V.validate(old["draft"], record)
            artifact = dict(
                old,
                source_record_sha256=V.digest(record),
                replay_of_sha256=old["sha256"],
            )
            artifact["sha256"] = V.digest(
                {k: v for k, v in artifact.items() if k != "sha256"}
            )
            audit["method"] = "validated_archived_draft"
            return artifact
        transport = V.extraction_packet(old_record, legacy_v1=True)
        # The original v3 schema is byte-identical to today's schema with this
        # optional addition removed. Check against the archived original request.
        transport["schema"]["properties"].pop("uncertainty_details", None)
        fingerprint = Q.digest(transport)
        initial = [
            r
            for _, name in sorted(responses)
            if (r := verified(name))["input_sha256"] == fingerprint
        ]
        if len(initial) != 1:
            raise ValueError(
                "No unique original raw response matches frozen model input"
            )
        response = initial[0]
        if (
            response["generation"]["output_tokens"]
            >= response["generation"]["max_new_tokens"]
        ):
            raise ValueError("Archived model response hit output token limit")
        draft = V.L.parse_json(response["raw"])
        claims = draft.get("applicability_claims", [])
        audit["v1_rows"] = len(claims)
        audit["v1_added_fields_complete"] = bool(claims) and all(
            claim.get("product_key") in products
            and products[claim["product_key"]].get("status")
            == claim.get("source_status")
            and all(
                products[claim["product_key"]].get(k)
                for k in (
                    "source_file",
                    "status_pointer",
                    "product_pointer",
                    "document_sha256",
                )
            )
            for claim in claims
        )
        # Resolve evidence IDs via the ORIGINAL catalogue, then validate quotes
        # against the NEW record. Never manufacture missing model provenance.
        draft = V.enrich(V.resolve_references(draft, transport))
        V.validate(draft, record)
        artifact = {
            "version": V.VERSION,
            "draft": draft,
            "model": response["model"],
            "llm_used": True,
            "generation": response["generation"],
            "coverage_complete": False,
            "source_record_sha256": V.digest(record),
            "replay_of_request_id": response["request_id"],
            "independent_semantic_accuracy_verified": False,
        }
        artifact["sha256"] = V.digest(artifact)
        audit["method"] = "validated_initial_archived_response"
        return artifact

    with patch.object(V, "resolve", side_effect=replay):
        current = Q.extract_declared(cve, components)
    return current, audit


def score(args):
    from src.item4.assets import asset_observations as I
    from src.item4.workflow import source_analysis_jobs as Q
    from src.item4.decision import asset_vex_assessment as E
    from src.item4.evaluation.operator_observation_benchmark import source_bindings

    cve, responses = args
    previous = verified(f"{DATA}/cves/{cve}.json")
    baseline = verified(f"{RESULT}/cves/{cve}.json")
    refs = verified(f"{DATA}/references/{cve}.json")
    if (
        baseline["input_sha256"] != MANIFEST[f"{DATA}/cves/{cve}.json"]
        or baseline["reference_frozen_sha256"]
        != MANIFEST[f"{DATA}/references/{cve}.json"]
    ):
        raise ValueError("Baseline source seals differ")
    by_id = {r["id"]: r for r in baseline["predictions"]}
    if len(by_id) != len(previous["cases"]) or set(by_id) != {r["id"] for r in refs}:
        raise ValueError("Frozen case identifiers differ")
    job = deepcopy(previous["job"])
    components, _ = Q.inventory(job["input_bom"])
    old = job["conditions"][0]
    condition, audit = replay_extraction(cve, components, old, responses)

    def product_summary(extraction):
        context = extraction.get("advisory_context") or {}
        matches = context.get("matches", [])
        return {
            "recorded": "matches" in context,
            "rows": len(matches),
            "version_membership": dict(
                Counter(row["version_membership"] for row in matches)
            ),
            "matching_statuses": sorted(
                {
                    row.get("status", "not_recorded")
                    for row in matches
                    if row["version_membership"] == "true"
                }
            ),
        }

    audit["old_product"] = product_summary(old)
    audit["new_product"] = product_summary(condition)
    audit.update(
        cve=cve,
        old_status=old["status"],
        old_questions=len(job["questions"]),
        prior_v1="V1 claim does not match the original product status"
        in old.get("reason", ""),
        old_source_bound=bool(previous["generation"]["source_condition_bindings"]),
        new_status=condition["status"],
        new_reason=condition.get("reason", ""),
        new_source_product_claims=len(condition["advisory_context"]["matches"]),
    )
    job["conditions"] = [condition]
    I.prepare(job, Q.digest)
    bindings, _ = source_bindings(job["questions"], refs[0])
    audit.update(new_questions=len(job["questions"]), new_source_bound=bool(bindings))
    before = {q["id"]: q for q in previous["job"]["questions"]}
    shared = {q["id"] for q in job["questions"] if before.get(q["id"]) == q}
    audit["new_unattested_questions"] = len(job["questions"]) - len(shared)
    audit["unregistered_context_values"] = 0
    options = {
        q["id"]: {option["code"] for option in q["options"]}
        for q in job["context_questions"]
    }
    E.verify_source(condition)
    # An immutable CVE/product/source snapshot is shared by the frozen worlds.
    # Evaluate the exact same version binding/graph arguments only once per CVE.
    version = E.version_binding
    graph = E.G.build
    bound = {}
    graphs = {}

    def cached_binding(cve, component, result):
        key = Q.digest(component)
        if key not in bound:
            bound[key] = version(cve, component, result)
        return bound[key]

    def cached_graph(*args):
        key = E.digest(args)
        if key not in graphs:
            graphs[key] = graph(*args)
        return graphs[key]

    decisions = []
    with (
        patch.object(E, "verify_source", lambda result: None),
        patch.object(E, "version_binding", cached_binding),
        patch.object(E.G, "build", cached_graph),
    ):
        if len(job["assessment_cases"]) != 1:
            raise ValueError("Expected exactly one frozen assessment scope")
        prefix = job["assessment_cases"][0]["prefix"]
        for case in previous["cases"]:
            job["answers"] = {k: v for k, v in case["answers"].items() if k in shared}
            job["context_answers"] = {
                (prefix + k if k in ("deployment", "runtime") else k): v
                for k, v in case["context"].items()
            }
            for key, value in list(job["context_answers"].items()):
                if value not in options[key]:
                    job["context_answers"][key] = "unknown"
                    audit["unregistered_context_values"] += 1
            result = E.evaluate(job)["decisions"][0]
            decisions.append(
                {
                    "id": case["id"],
                    "cve": cve,
                    "old": by_id[case["id"]]["status"],
                    "new": result["status"],
                    "old_graph": by_id[case["id"]]["graph_generation_status"],
                    "graph": result["attack_graph"]["generation_status"],
                    "formula": result["prerequisite_status"],
                    "old_applicability": by_id[case["id"]]["product_applicability"],
                    "new_applicability": result["product_applicability"],
                }
            )
    labels = {r["id"]: r["actual_affected"] for r in refs}
    for row in decisions:
        row["candidate_label"] = labels[row["id"]]
    return audit, decisions


def dump(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def summarize_pairs(output):
    """Verify both ledgers by identity and report the product/evidence and graph strata."""
    report_path = output / "report.json"
    report = json.loads(report_path.read_bytes())
    for name, expected in report["ledgers"].items():
        if sha((output / name).read_bytes()) != expected:
            raise ValueError("Paired ledger checksum mismatch: " + name)

    product = {arm: Counter() for arm in ("old", "new")}
    audit_cves = set()
    v1 = set()
    methods = Counter()
    v1_methods = Counter()
    changed_products = set()
    with (output / "cve_audit.jsonl").open(encoding="utf-8") as audits:
        for line in audits:
            audit = json.loads(line)
            cve = audit["cve"]
            if cve in audit_cves:
                raise ValueError("Duplicate CVE: " + cve)
            audit_cves.add(cve)
            method = audit.get("method", "no_validated_model_output")
            methods[method] += 1
            if audit["prior_v1"]:
                v1.add(cve)
                v1_methods[method] += 1
            if audit["old_product"] != audit["new_product"]:
                changed_products.add(cve)
            for arm, counts in product.items():
                scope = audit[arm + "_product"]
                counts["cves_with_product_match"] += bool(scope["rows"])
                counts["matched_product_rows"] += scope["rows"]
                counts["cves_with_explicit_version_membership"] += bool(
                    scope["version_membership"].get("true")
                )
                counts["cves_with_conflicting_in_scope_statuses"] += (
                    len(scope["matching_statuses"]) > 1
                )
                counts.update(
                    {
                        "version_rows_" + k: v
                        for k, v in scope["version_membership"].items()
                    }
                )

    case_ids = set()
    case_cves = set()
    changed_cves = set()
    changed = Counter()
    graph = Counter()
    applicability = Counter()
    missing_graph = Counter()
    with (output / "paired_decisions.jsonl").open(encoding="utf-8") as decisions:
        for line in decisions:
            row = json.loads(line)
            if row["id"] in case_ids:
                raise ValueError("Duplicate paired case: " + row["id"])
            case_ids.add(row["id"])
            case_cves.add(row["cve"])
            graph[row["old_graph"] + " -> " + row["graph"]] += 1
            applicability[
                row["old_applicability"] + " -> " + row["new_applicability"]
            ] += 1
            if row["graph"] == "unavailable":
                missing_graph["prior_v1" if row["cve"] in v1 else "other"] += 1
            if row["old"] != row["new"]:
                changed["prior_v1" if row["cve"] in v1 else "other"] += 1
                changed_cves.add(row["cve"])
    if (
        case_cves != audit_cves
        or len(case_ids) != 97553
        or len(case_cves) != 12418
        or len(v1) != 3640
    ):
        raise ValueError("Expected one complete, unique paired population")
    report["replay_checks"] = {
        "unique_paired_cases": len(case_ids),
        "unique_paired_cves": len(case_cves),
        "unique_prior_v1": len(v1),
        "extraction_methods": methods,
        "prior_v1_methods": v1_methods,
        "product_version_coverage": product,
        "cves_changing_product_version_summary": len(changed_products),
        "graph_transitions": graph,
        "applicability_transitions": applicability,
        "changed_decision_cves": len(changed_cves),
        "changed_cases_by_prior_v1": changed,
        "unavailable_graph_cases_by_prior_v1": missing_graph,
    }
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--delivery", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--workers", type=int, default=4)
    a = p.parse_args()
    load_delivery(a.delivery)
    a.output.mkdir(parents=True, exist_ok=True)
    if any(a.output.iterdir()):
        raise FileExistsError("Choose an empty comparison output directory")
    with tempfile.TemporaryDirectory(prefix="icsvex-frozen-comparison-") as directory:
        spool = Path(directory) / "inputs.sqlite3"
        print(
            "Verifying frozen archive; preparing temporary read-only index", flush=True
        )
        prepare_spool(spool)
        try:
            run(a, spool)
        finally:
            FILES.close()


def run(a, spool):
    ids = sorted(verified(DATA + "/population_ledger.json")["cves"])
    assert len(set(ids)) == len(ids) == 12418
    start = monotonic()
    print("Verifying frozen raw response index", flush=True)
    index = raw_index()
    categories = defaultdict(Counter)
    stats = Counter()
    auditpath = a.output / "cve_audit.jsonl"
    decisionspath = a.output / "paired_decisions.jsonl"
    with (
        auditpath.open("x", encoding="utf-8") as audits,
        decisionspath.open("x", encoding="utf-8") as decisions,
        ProcessPoolExecutor(
            a.workers, initializer=init_worker, initargs=(a.delivery, spool)
        ) as pool,
    ):
        for i, (audit, rows) in enumerate(
            pool.map(score, ((c, index.get(c, [])) for c in ids), chunksize=12)
        ):
            audits.write(dump(audit) + "\n")
            for measure in ("old_status", "new_status", "source_context"):
                categories[measure][audit[measure]] += 1
            for k in (
                "old_questions",
                "new_questions",
                "new_unattested_questions",
                "unregistered_context_values",
            ):
                stats[k] += audit[k]
            for k in (
                "new_questions",
                "old_questions",
                "new_source_bound",
                "old_source_bound",
            ):
                stats["CVEs_with_" + k] += bool(audit[k])
            if audit["prior_v1"]:
                stats["prior_v1"] += 1
                stats["prior_v1_new_valid"] += audit["new_status"] == "extracted"
                stats["prior_v1_status_plus_four_provenance_fields_available"] += audit[
                    "v1_added_fields_complete"
                ]
                stats["prior_v1_with_questions"] += bool(audit["new_questions"])
                stats["prior_v1_with_bound_questions"] += audit["new_source_bound"]
                categories["prior_v1_new_reasons"][
                    audit["new_reason"] or "accepted"
                ] += 1
            for row in rows:
                decisions.write(dump(row) + "\n")
                categories["status_transition"][row["old"] + " -> " + row["new"]] += 1
                categories["new_graph"][row["graph"]] += 1
                categories["new_statuses"][row["new"]] += 1
                actual = row["candidate_label"]
                for arm in ("old", "new"):
                    pred = row[arm] == "affected"
                    counts = categories[arm + "_counts"]
                    counts["TP"] += pred and actual is True
                    counts["FP"] += pred and actual is False
                    counts["FN"] += not pred and actual is True
                    counts["unknown_positive"] += pred and actual is None
                stats["cases"] += 1
            if (i + 1) % 500 == 0:
                print(f"{i + 1}/{len(ids)} ({int(monotonic() - start)}s)", flush=True)
    assert stats["prior_v1"] == 3640 and stats["cases"] == 97553
    assert categories["old_counts"] == Counter(TP=0, FP=0, FN=3, unknown_positive=3)
    code = [
        "tools/item4/replay_item4_fixed_worlds.py",
        "src/item4/decision/asset_vex_assessment.py",
        "src/item4/workflow/source_analysis_jobs.py",
        "src/item4/assets/asset_observations.py",
        "src/item4/analysis/product_advisory_evidence.py",
        "src/item4/analysis/exploitation_prerequisites.py",
        "src/item4/decision/mulval_attack_graphs.py",
    ]
    summary = {
        "protocol": RUN,
        "completed_cves": len(ids),
        "counts": stats,
        "by": categories,
        "elapsed_seconds": monotonic() - start,
        "model_inputs_regenerated": False,
        "new_gpu_inference": False,
        "prior_classification_reused": True,
        "independent_expert_gold": False,
        "source_delivery": str(a.delivery),
        "source_manifest_sha256": sha(
            (a.delivery / "delivery_manifest.json").read_bytes()
        ),
        "code_sha256": {k: sha((ROOT / k).read_bytes()) for k in code},
        "ledgers": {f.name: sha(f.read_bytes()) for f in (auditpath, decisionspath)},
        "notes": [
            "Same frozen candidate labels and case IDs. Historical accepted drafts or the unique initial raw response were revalidated on current evidence; no new model/repair generations. Newly introduced questions have unknown answers.",
            "Original source identifiers/quotes are verified; only matching archived MulVAL receipts are used. Missing receipt yields the service unavailable-graph result. Previously recorded asset classifications are held fixed.",
            "Unjudged positives block the primary affected precision. A zero judged positive denominator is undefined.",
        ],
    }
    for arm in ("old", "new"):
        x = categories[arm + "_counts"]
        n = x["TP"] + x["FP"]
        summary[arm + "_precision"] = (
            x["TP"] / n if n and not x["unknown_positive"] else None
        )
    (a.output / "report.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    summarize_pairs(a.output)
    print("Comparison completed", len(ids), stats["cases"], flush=True)


if __name__ == "__main__":
    main()
