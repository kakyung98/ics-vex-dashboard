"""Paired H200 evaluation with predetermined sentence labels, without public scores."""
import json
from pathlib import Path
from tools.item4 import run_blind_cvss_description as audit

CASES={
    "AC":[
        ("A malformed document can cause the reader to stop responding.","?"),
        ("A remote party can affect availability through unspecified inputs.","?"),
        ("The report identifies a processing flaw but gives no details about reproducibility.","?"),
        ("A message to the service can cause data loss.","?"),
        ("Exploitation succeeds repeatably without special conditions.","L"),
        ("No circumstances beyond the attacker's control are needed and the outcome is repeatable.","L"),
        ("Successful exploitation depends on winning a timing race outside the attacker's control.","H"),
        ("Exploitation is possible only under exceptional circumstances beyond the attacker's control.","H")],
    "UI":[
        ("A remote party can cause a denial of service.","?"),
        ("The application fails while parsing an input file.","?"),
        ("An operator can view a project in the viewer.","?"),
        ("The attacker submits a request to the service.","?"),
        ("No interaction by any other user is needed for exploitation.","N"),
        ("Exploitation completes without participation from the victim or any other person.","N"),
        ("The vulnerability can be triggered only when the victim opens the document.","R"),
        ("Successful exploitation requires a separate operator to confirm the import.","R")],
    "PR":[
        ("Authenticated users may be affected; their required role is unspecified.","?"),
        ("The vulnerability can result in administrative privileges.","?"),
        ("Exploitation requires an existing administrator account.","H"),
        ("Ordinary user privileges suffice and are required for exploitation.","L")],
    "AV":[
        ("A remote attacker can provide a project file; the delivery mechanism is unspecified.","?"),
        ("The report lists a network adapter in the affected product.","?"),
        ("Successful exploitation requires physical contact with the device.","P"),
        ("Exploitation requires the attacker to be on the same adjacent network.","A")]}
def evaluate():
    report={}
    for policy in (False,True):
        out,gpu=audit.classify([q for rows in CASES.values() for q,_ in rows],"3.1",evidence_policy=policy)
        rows=[]
        for axis,cases in CASES.items():
            for q,expected in cases:
                values={x["value"] for x in out[q]["evidence"] if x["axis"]==axis}
                actual="?" if not values else "/".join(sorted(values))
                rows.append(dict(axis=axis,text=q,expected=expected,actual=actual,receipt=out[q]["receipt"]))
        report["revised" if policy else "baseline"]=dict(device=gpu,rows=rows,
            correct=sum(x["actual"]==x["expected"] for x in rows),
            unsupported=sum(x["expected"]=="?" and x["actual"]!="?" for x in rows),
            explicit_correct=sum(x["expected"]!="?" and x["actual"]==x["expected"] for x in rows))
    # Known diagnostic examples. Expected labels concern the description only.
    labels={"CVE-2016-2277":("AV","?"),"CVE-2010-3591":("AC","?"),
            "CVE-2015-7903":("PR","?"),"CVE-2011-4969":("UI","?"),
            "CVE-2021-0968":("UI","N"),"CVE-2022-30229":("PR","N")}
    documents={}
    with audit.TEXT.open(encoding="utf8") as f:
        for line in f:
            r=json.loads(line)["original"]
            if r["cve"] in labels:
                documents[r["cve"]]=r["description"]
    assert set(documents)==set(labels)
    for policy in (False,True):
        rows=[]
        for version,ids in [("3.0",list(labels)[:4]),("3.1",list(labels)[4:])]:
            result,_=audit.classify([documents[i] for i in ids],version,evidence_policy=policy)
            for i in ids:
                axis,expected=labels[i]
                response=result[documents[i]]
                vals={e["value"] for e in response["evidence"] if e["axis"]==axis}
                actual="/".join(sorted(vals)) if vals else "?"
                rows.append(dict(cve=i,axis=axis,expected=expected,actual=actual,receipt=response["receipt"]))
        report["revised" if policy else "baseline"]["diagnostic_cases"]=rows
    path=audit.OUT/"paired_evidence_policy_pilot.json"
    path.write_text(json.dumps(report,indent=2),encoding="utf8")
    for name,r in report.items(): print(name,{k:v for k,v in r.items() if k!="rows"})
if __name__=="__main__":
    evaluate()
