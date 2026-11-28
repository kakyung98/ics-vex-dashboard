# HISTORICAL: v3 random asset-question clusters; not the active CVSS operational evaluation.
"""Evaluate the v3 synthetic operator answers against the frozen source/question links."""
import argparse
import csv
import hashlib
import json
import sqlite3
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

from src.item4.evaluation.benchmark_rule_oracle import FACTS, route_facts
from jsonschema import Draft202012Validator
from tools.item4.rebuild_question_cluster_annotations import expand_answers, summaries

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "benchmark/item4_evaluation"
LINKS = ROOT / "results/item4_source_condition_question_links/condition_question_links.json"
OUTPUT = ROOT / "results/item4_synthetic_question_evaluation"
LABEL = {True: "true", False: "false", None: "unknown"}


def read(path, expected=None):
    raw = path.read_bytes()
    if expected and hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f"Input checksum changed: {path}")
    return json.loads(raw)


def condition_value(unit, aid, answers, definitions):
    original = unit["original_condition"]
    if not unit["verified"] or unit["source_grounding"] != "supported":
        return None, "source_unresolved"
    if original["necessity"] == "nonrequirement":
        return True, "explicit_nonrequirement"
    if original["necessity"] != "required":
        return None, "context_only"
    exact = [a for a in unit["atoms"] if a["verification"]["exact"]]
    if len(exact) != 1:
        return None, "incomplete_or_ambiguous_mapping"
    a = exact[0]
    q = definitions[a["qid"]]
    if not any(row["asset_type_id"] == aid for row in q["rows"]):
        return None, "different_question_profile"
    answer = answers[aid + ":" + q["key"]]
    if answer not in ("o", "x"):
        return None, "answer_unknown"
    return answer == a["required"], "synthetic_answer_matches_scope_assumption"


def expression_value(node, values):
    if "unknown" in node:
        return None
    if "constant" in node or "key" in node:
        return values.get(node.get("source_condition"))
    children = [expression_value(v, values) for v in node.get("args", [])]
    if not children:
        return None
    if node.get("op") == "and":
        return False if False in children else True if all(v is True for v in children) else None
    if node.get("op") == "or":
        return True if True in children else False if all(v is False for v in children) else None
    if node.get("op") == "not" and len(children) == 1:
        return None if children[0] is None else not children[0]
    raise ValueError("Invalid source expression")


def decide(binding, branches, declared_components, aid):
    if binding is None:
        return (*route_facts({"scope_confirmed": False}, None), "asset_component_runtime_unbound")
    facts = binding["facts"]
    Draft202012Validator(FACTS).validate(facts)
    if (binding.get("synthetic") is not True or not binding.get("scope_id") or
        not binding.get("evidence_refs") or binding.get("asset_type_id") != aid or
        binding.get("component_ref") not in declared_components):
        return (*route_facts({"scope_confirmed": False}, None), "binding_not_supported")
    # Only alternatives explicitly bound to this hypothetical component/scope
    # may contribute to its formula. Never OR unrelated publication scopes.
    refs = [tuple(ref) for ref in binding["alternative_scenarios"]]
    if any(ref not in branches for ref in refs):
        raise ValueError("Unknown source scenario in synthetic binding")
    values = [branches[ref] for ref in refs]
    formula = True if True in values else False if values and all(v is False for v in values) else None
    status, rule = route_facts(facts, formula)
    return status, rule, "explicit_synthetic_binding"


def run(data, links, output, bindings_path=None):
    manifest = read(data / "manifest.json")
    catalog = read(data / "catalog/question_clusters.json")
    if catalog["source_sha256"] != manifest["question_catalog_sha256"]:
        raise ValueError("Question catalogue changed")
    graph = read(links)
    definitions = {q["qid"]: q for q in graph["questions"]}
    binding = {(r["asset_type_id"], q["key"]): (q["scope"], q["yes"], q["no"])
               for q in definitions.values() for r in q["rows"]}
    assert binding == {(aid, q["key"]): (q["target_unit"], q["o_criterion"], q["x_criterion"])
                       for aid, profile in catalog["profiles"].items() for q in profile["questions"]}
    units = defaultdict(list)
    for u in graph["units"]:
        units[u["cve"]].append(u)
    bindings = {}
    for row in read(bindings_path) if bindings_path else []:
        key = (row["bom"], row["cve"], row["pattern"])
        if key in bindings:
            raise ValueError("Duplicate synthetic binding")
        bindings[key] = row
    output.mkdir(exist_ok=True, parents=True)
    with tempfile.TemporaryDirectory(dir=output) as tmp:
        tmp = Path(tmp)
        db = sqlite3.connect(tmp / "results.sqlite3")
        db.executescript("""
        create table bom(id text primary key, cves integer, patterns integer);
        create table declaration(bom text, cve text, pointer text, component_refs text);
        create table application(bom text, pattern text, primary key(bom,pattern));
        create table answer(pattern text, question text, value text, primary key(pattern,question));
        create table cluster(pattern text, cluster_id text, yes_count int, no_count int, unknown_count int);
        create table condition(pattern text, cve text, unit_id text, hypothetical_value text, reason text);
        create table scenario(pattern text,cve text,source_case text,scenario_id text,hypothetical_value text);
        create table decision(bom text,cve text,pattern text,vex_status text,rule text,reason text);
        """)
        patterns = {}
        hashes = {}
        for aid, profile in catalog["profiles"].items():
            path = data / "scenarios" / (aid + ".json")
            hashes[aid] = hashlib.sha256(path.read_bytes()).hexdigest()
            for s in read(path)["scenarios"]:
                pid = s["id"]
                assert pid not in patterns and s["inputs"]["asset_type_id"] == aid
                answers = expand_answers(profile, s["inputs"]["answer_assignment"])
                clusters = summaries(profile, answers)
                assert clusters == s["expected_question_results"]
                patterns[pid] = aid, answers
                db.executemany("insert into answer values(?,?,?)", [(pid,k,v) for k,v in answers.items()])
                db.executemany("insert into cluster values(?,?,?,?,?)",
                               [(pid,r["cluster_id"],r["o_count"],r["x_count"],r["unknown_count"]) for r in clusters])
        evaluated = {}
        distinct_cves = set()
        unlinked_cves = set()
        stats = Counter()
        for entry in read(data / "index.json")["entries"]:
            ann = read(data / entry["annotation_file"], entry["annotation_sha256"])
            bom = ann["id"]
            cves = ann["inventory"]["declared_cves"]
            assert len(set(cves)) == len(cves) == entry["cve_count"]
            distinct_cves.update(cves)
            selected = []
            for ref in ann["scenario_sets"]:
                aid = ref["asset_type_id"]
                assert ref["sha256"] == hashes[aid]
                profile = next(p for p in ann["inputs"]["question_profiles"] if p["asset_type_id"] == aid)
                ids = profile["scenario_ids"]
                assert len(set(ids)) == len(ids) == ref["count"]
                assert all(patterns[pid][0] == aid for pid in ids)
                selected.extend(ids)
            db.execute("insert into bom values(?,?,?)", (bom,len(cves),len(selected)))
            db.executemany("insert into application values(?,?)", [(bom,pid) for pid in selected])
            db.executemany("insert into declaration values(?,?,?,?)",
                [(bom,r["cve"],r["pointer"],json.dumps(r["component_refs"])) for r in ann["inventory"]["cve_declarations"]])
            ctx = ann["inputs"]["assessment_context"]
            if ctx["asset_ref"] or ctx["component_ref"] or ctx["running_version"] or ann["asset_classification"]["confirmed_asset_type_id"]:
                raise ValueError(f"{bom}: unexpected bound instance in v3 benchmark; inspect supplied evidence")
            # No scope-confirmed runtime instance is present in this dataset.
            # R0 has priority over every hypothetical formula result.
            decisions = []
            components = defaultdict(set)
            for declaration in ann["inventory"]["cve_declarations"]:
                components[declaration["cve"]].update(declaration["component_refs"])
            for cve in cves:
                if cve not in graph["population"]:
                    unlinked_cves.add(cve)
                for pid in selected or [None]:
                    if not pid:
                        status, rule, _ = decide(None, {}, set(), None)
                        decisions.append((bom,cve,None,status,rule,"unclassified_no_pattern"))
                        continue
                    aid, answers = patterns[pid]
                    if (pid,cve) not in evaluated:
                        branches = {}
                        values = {}
                        for u in units[cve]:
                            value, basis = condition_value(u, aid, answers, definitions)
                            values[u["id"]] = value
                            db.execute("insert into condition values(?,?,?,?,?)",(pid,cve,u["id"],LABEL[value],basis))
                        for s in graph["population"].get(cve,{}).get("question_scenarios",[]):
                            value = expression_value(s["expression"], values) if s["logic_status"] == "자동 추출 관계" else None
                            ref = (s["case_id"],s["id"])
                            # Duplicate local scenario IDs cannot prove which branch was bound.
                            branches[ref] = None if ref in branches else value
                            db.execute("insert into scenario values(?,?,?,?,?)",(pid,cve,*ref,LABEL[value]))
                        evaluated[pid,cve] = branches
                    binding = bindings.pop((bom,cve,pid), None)
                    decision = decide(binding, evaluated[pid,cve], components[cve], aid)
                    decisions.append((bom,cve,pid,*decision))
            db.executemany("insert into decision values(?,?,?,?,?,?)",decisions)
            stats["expected_decisions"] += len(cves)*max(1,len(selected))
        def count(table):
            return db.execute(f"select count(*) from {table}").fetchone()[0]
        def tally(table, col):
            return dict(db.execute(f"select {col},count(*) from {table} group by {col}"))
        counts = manifest["counts"]
        if bindings:
            raise ValueError("Synthetic binding has no matching BOM/CVE/pattern")
        assert count("bom")==counts["boms"] and count("application")==counts["synthetic_question_scenarios"]
        assert len(distinct_cves)==counts["unique_cves"] and len(patterns)==counts["shared_synthetic_patterns"]
        assert count("decision")==stats["expected_decisions"]
        report = dict(boms=count("bom"), patterns=len(patterns), applications=count("application"),
                      unique_cves=len(distinct_cves), cves_missing_from_extraction=len(unlinked_cves),
                      unique_pattern_cve_pairs=len(evaluated), hypothetical_conditions=tally("condition","hypothetical_value"),
                      hypothetical_scenarios=tally("scenario","hypothetical_value"), decisions=tally("decision","vex_status"),
                      no_pattern_decisions=db.execute("select count(*) from decision where pattern is null").fetchone()[0],
                      verified_cluster_gold=count("cluster"), independent_vex_gold=False,
                      links_sha256=hashlib.sha256(links.read_bytes()).hexdigest())
        db.execute("create index lookup_decision on decision(bom,cve)")
        db.execute("create index lookup_condition on condition(pattern,cve)")
        db.execute("create index lookup_scenario on scenario(pattern,cve)")
        with (tmp/"vex_decisions.csv").open("w",encoding="utf-8-sig",newline="") as f:
            writer=csv.writer(f)
            writer.writerow(["BOM","CVE","합성 패턴","잠정 VEX","판정 규칙","사유"])
            writer.writerows(db.execute("select * from decision order by bom,cve,pattern"))
        db.commit()
        assert db.execute("pragma integrity_check").fetchone()==("ok",)
        db.close()
        (tmp/"summary.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf8")
        for name in ["results.sqlite3","vex_decisions.csv","summary.json"]:
            (tmp/name).replace(output/name)
    print(json.dumps(report,ensure_ascii=False))


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data",type=Path,default=DATA)
    parser.add_argument("--links",type=Path,default=LINKS)
    parser.add_argument("--output",type=Path,default=OUTPUT)
    parser.add_argument("--bindings",type=Path,help="Optional explicit synthetic scope facts; use a separate output for controlled runs")
    args=parser.parse_args()
    if args.bindings and args.output.resolve() == OUTPUT.resolve():
        parser.error("Select a separate --output for synthetic binding controls")
    run(args.data,args.links,args.output,args.bindings)
