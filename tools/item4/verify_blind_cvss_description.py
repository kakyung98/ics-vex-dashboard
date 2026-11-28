"""Verify that the released comparison can be traced to both frozen source files."""
import hashlib
import json
from collections import Counter
from pathlib import Path
from functools import lru_cache
import re

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results/item4_blind_cvss_20261124"


@lru_cache(maxsize=96)
def advisory_scores(source):
    doc = json.loads((ROOT/source).read_bytes())
    return {(v.get("cve"), key, data["vectorString"], tuple(score.get("products", [])))
            for v in doc.get("vulnerabilities", [])
            for score in v.get("scores", [])
            for key,data in score.items() if isinstance(data,dict) and data.get("vectorString")}


def main():
    summary = json.loads((OUT/"summary.json").read_bytes())
    paths = [ROOT/name for name in summary["source_files"]]
    for path in paths:
        assert hashlib.sha256(path.read_bytes()).hexdigest() == summary["source_files"][str(path.relative_to(ROOT))]
    pop, text, ref = paths
    expected = {r["cve"] for r in json.loads(pop.read_bytes())}
    refs = {}
    for row in json.loads(ref.read_bytes()):
        groups = [[a for a in row["vectors"] if a["vector"].split("/")[0]=="CVSS:"+v]
                  for v in ("3.1","4.0","3.0")]
        refs[row["cve"]] = next((g for g in groups if g),[])
    seen = set()
    states = Counter()
    counts = Counter()
    versions = Counter()
    selected_counts = Counter()
    subjects = {}
    with text.open(encoding="utf8") as f:
        for line in f:
            r = json.loads(line)["original"]
            subjects[r["cve"]] = r["description"] or ""
    with (OUT/"records.jsonl").open(encoding="utf8") as f:
        for line in f:
            r = json.loads(line)
            c = r["cve"]
            assert c not in seen
            seen.add(c)
            desc = subjects[c]
            assert hashlib.sha256(desc.encode()).hexdigest() == r["description_sha256"]
            selected = refs[c][0]["vector"].split("/")[0][5:] if refs[c] else None
            selected_counts[selected or "none"]+=1
            assert r["selected_version"]==selected
            assert bool(r["h200_receipt"])==bool(selected and desc)
            if r["h200_receipt"]:
                receipt = json.loads((OUT/"h200_receipts"/r["h200_receipt"]).read_bytes())
                assert receipt["cvss_version"]==selected
                assert receipt["llm_used"] and receipt["model"]["revision"]==summary["revision"]
                assert receipt["model"]["provider"]=="nemotron_vllm_nvfp4_h200"
                assert str(r["receipt_document"]) in receipt["prediction"]
                offered=[(m.start(),m.end(),m.group()) for m in
                         re.finditer(r"\S[\s\S]*?(?:(?<=[.!?])(?=\s)|(?=\n)|\Z)",desc)
                         if not re.search(r"CVSS|(?:AV|AC|PR|UI|AT|Au):[A-Z]",m.group(),re.I)]
                claims=set(receipt["prediction"][str(r["receipt_document"])])
                allowed=r"(AV=[NALP]|AC=[LH]|PR=[NLH]|AT=[NP]|UI=[NPA])" if selected=="4.0" else r"(AV=[NALP]|AC=[LH]|PR=[NLH]|UI=[NR])"
                assert all(re.fullmatch(allowed+r"@[1-9][0-9]*",v) for v in claims)
                span_index={(a,b):i for i,(a,b,_) in enumerate(offered,1)}
                observed={f'{e["axis"]}={e["value"]}@{span_index[tuple(e["span"])]}' for e in r["readings"]}
                assert observed|set(r["rejected_citations"])==claims
                counts["cves_with_h200_receipt"]+=1
            counts["invalid_sentence_references"]+=len(r["rejected_citations"])
            for e in r["readings"]:
                start,end = e["span"]
                assert 0<=start<end<=len(desc) and desc[start:end]==e["quote"]
                counts["quote_spans_verified"]+=1
            assert [{k:a[k] for k in ("vector","source","score_key","products")} for a in r["assessments"]]==refs[c]
            for a in r["assessments"]:
                assert (c,a["score_key"],a["vector"],tuple(a["products"])) in advisory_scores(a["source"])
                counts["assessment_sources_verified"]+=1
                assert a["version"]==selected and set(a["metrics"])==({"AV","AC","PR","UI","AT"} if selected=="4.0" else {"AV","AC","PR","UI"})
                versions[a["version"]]+=1
                assert a["scope_status"]=="scope_unknown"
                vector = dict(p.split(":",1) for p in a["vector"].split("/"))
                for k,m in a["metrics"].items():
                    assert vector[k]==m["published"]
                    axis = k
                    evidence = [r["readings"][i] for i in m["evidence_indices"]]
                    assert all(e["axis"]==axis for e in evidence)
                    vals = {e["value"] for e in evidence}
                    blind = next(iter(vals)) if len(vals)==1 else "?"
                    if any(x.startswith(axis+"=") for x in r["rejected_citations"]):
                        blind="?"
                    assert blind==m["blind"]
                    state = "unknown" if blind=="?" else "same_value" if blind==vector[k] else "different_value"
                    assert state==m["comparison"]
                    states[state]+=1
    assert seen==expected and len(seen)==12418 and states==summary["metric_comparisons"]
    assert selected_counts==summary["selected_cves"]
    assert sum(versions.values())==summary["counts"]["assessments"]
    assert sum(states.values())==sum(n*(5 if v=="4.0" else 4) for v,n in versions.items())
    assert summary["version_priority"]==["3.1","4.0","3.0"]
    result = dict(unique_cves=len(seen),selected_cves=selected_counts, **counts, versions=versions, metric_comparisons=states,
                  controls_passed=sum(x["actual"]==x["expected"] for x in summary["controls"]),
                  control_count=len(summary["controls"]))
    (OUT/"verification.json").write_text(json.dumps(result,indent=2),encoding="utf8")
    print(result)


if __name__=="__main__":
    main()
