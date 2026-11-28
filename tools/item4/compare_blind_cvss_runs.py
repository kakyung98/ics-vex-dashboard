"""Compare two verified runs on identical CVEs, reference scores and source documents."""
import json
from collections import Counter, defaultdict
from itertools import zip_longest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results/item4_blind_cvss_20261124"
OLD = OUT / "before_evidence_policy"


def by_metric(record):
    return {m["metric_id"]: (a,k,m) for a in record["assessments"]
            for k,m in a["metrics"].items()}


def compare():
    old_summary = json.loads((OLD/"summary.json").read_bytes())
    new_summary = json.loads((OUT/"summary.json").read_bytes())
    verification = json.loads((OUT/"verification.json").read_bytes())
    assert new_summary["evidence_policy_versions"]==["3.0","3.1"]
    assert new_summary["source_files"]==old_summary["source_files"]
    assert verification["metric_comparisons"]==new_summary["metric_comparisons"]
    path=ROOT/"benchmark/item4_evaluation/csaf_vex_v2/sources/cve_evidence.jsonl"
    with path.open(encoding="utf8") as source:
        descriptions={r["cve"]:r["original"]["description"] for r in map(json.loads,source)}
    pilot=json.loads((OUT/"paired_evidence_policy_pilot.json").read_bytes())
    diagnostic={(r["cve"],r["axis"]):r["expected"] for r in pilot["revised"]["diagnostic_cases"]}
    checked={}
    transitions=defaultdict(Counter)
    before,after=Counter(),Counter()
    total=0
    temp=OUT/"disagreement_evidence.tmp"
    with (OLD/"records.jsonl").open(encoding="utf8") as old, (OUT/"records.jsonl").open(encoding="utf8") as new, temp.open("w",encoding="utf8") as diff:
        for x,y in zip_longest(map(json.loads,old),map(json.loads,new)):
            assert x and y and all(x[k]==y[k] for k in ["cve","selected_version","description_sha256"])
            total+=1
            old_metrics,new_metrics=by_metric(x),by_metric(y)
            assert old_metrics.keys()==new_metrics.keys()
            for identity,(a,k,m) in new_metrics.items():
                prev=old_metrics[identity][2]
                assert m["published"]==prev["published"]
                if (y["cve"],k) in diagnostic:
                    key=y["cve"]+"/"+k
                    item=dict(expected=diagnostic[y["cve"],k],before=prev["blind"],after=m["blind"])
                    assert checked.setdefault(key,item)==item
                start,end=prev["comparison"],m["comparison"]
                transitions[k][start+" -> "+end]+=1
                before[start]+=1
                after[end]+=1
                if end=="different_value":
                    evidence=[y["readings"][i] for i in m["evidence_indices"]]
                    description=descriptions[y["cve"]]
                    assert evidence and all(description[e["span"][0]:e["span"][1]]==e["quote"] for e in evidence)
                    row=dict(cve=y["cve"],metric=k,public_value=m["published"],read_value=m["blind"],
                             previous_read_value=prev["blind"],version=a["version"],source=a["source"],
                             origins=a["origins"],products=a["products"],description=description,citations=evidence,
                             published_values_for_cve=sorted({b["metrics"][k]["published"] for b in y["assessments"]}))
                    diff.write(json.dumps(row,ensure_ascii=False)+"\n")
    assert before==old_summary["metric_comparisons"] and after==new_summary["metric_comparisons"] and total==12418
    temp.replace(OUT/"disagreement_evidence.jsonl")
    overall=sum(transitions.values(),Counter())
    assert len(checked)==len(diagnostic)
    report=dict(diagnostic_cases=checked,population=total,compared_metrics=sum(after.values()),previous=before,current=after,
                transitions=overall,by_metric=transitions)
    (OUT/"evidence_policy_comparison.json").write_text(json.dumps(report,indent=2),encoding="utf8")
    print(json.dumps(report,indent=2))


if __name__=="__main__":
    compare()
