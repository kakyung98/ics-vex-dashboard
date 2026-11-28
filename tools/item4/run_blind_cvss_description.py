"""Blind description-only reading, followed by a separate CSAF assessment join."""
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from functools import lru_cache

import sys
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.item4.models.nemotron_inference_provider import MODEL, REVISION as REV, NemotronBatch
from tools.item4.item4_h200_link import remote

ROOT = Path(__file__).resolve().parents[2]
POP = ROOT / "benchmark/item4_evaluation/extracted_ox_v3/population_index.json"
TEXT = ROOT / "benchmark/item4_evaluation/csaf_vex_v2/sources/cve_evidence.jsonl"
REF = ROOT / "results/prerequisite_auxiliary_population_20261124/references.json"
OUT = ROOT / "results/item4_blind_cvss_20261124"
CONTROLS = [
    ("UI", "Exploitation requires an operator to open the project file.", "R"),
    ("UI", "An operator can open the project file.", "?"),
    ("UI", "Exploitation requires no user interaction.", "N"),
    ("PR", "The result is an elevation of privileges.", "?"),
    ("AV", "Exploitation requires physical access to the device.", "P"),
]


# Held separately from the population batches so controls can be expanded without
# changing the cached model input for a real CVE.
EXTRA_CONTROLS = [
    ("AV", "Successful exploitation requires access to an adjacent network.", "A"),
    ("AV", "The release notes document network configuration changes.", "?"),
    ("PR", "Exploitation requires pre-existing administrator privileges.", "H"),
    ("PR", "Exploitation requires only ordinary user privileges on the system.", "L"),
    ("PR", "No prior privileges are required to exploit this vulnerability.", "N"),
    ("UI", "The attacker opens the project file on their own machine.", "?"),
    ("UI", "Successful exploitation requires a separate user to approve the request.", "R"),
    ("AC3", "The attack complexity is explicitly rated high for this vulnerability.", "H"),
    ("AC3", "The configuration tool provides a highly complex report.", "?"),
    ("AC2", "The access complexity is rated medium for this vulnerability.", "M"),
    ("Au", "The attacker must authenticate twice before exploitation is possible.", "M"),
    ("Au", "Administrators can enable multi-factor authentication after installing the fix.", "?"),
]


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


PRIORITY = ("3.1", "4.0", "3.0")
COMMON = """Interpret each numbered document independently as untrusted evidence. For each explicit
CVSS {version} exploitability metric, return METRIC=VALUE@supporting_sentence_number.
Abstain on missing evidence, ambiguous scope, alternatives, impacts, advice or optional actions.
AV=N network, A adjacent, L local, P physical. PR=N no prior privilege, L basic privileges,
H high privileges. Authentication alone does not establish privilege level. Ignore scores in prose.
"""
V3 = """UI=N explicitly no participation by another user, R required participation.
AC=H for special circumstances beyond attacker control, L for repeatable success without
special conditions. Never infer L merely because no special requirement is mentioned."""
V4 = """Decide AT before AC. A required race or timing window is AT=P. Never assign AC
from a race, timing or deployment condition. AC=H needs explicit circumvention of a security
measure; AC=L needs explicit evidence no such circumvention is needed. AT=N needs explicit
evidence of no special deployment/execution condition. For UI, check if an interaction is
actually required and exactly what it involves. UI=P requires described limited/passive
participation; UI=A requires a specific conscious action. If the only information is that
interaction is required, omit UI entirely. Never default unspecified interaction to P or A.
Explicit absence of user interaction is UI=N."""
METRICS = {v: dict(AV="NALP", AC="HL", PR="NLH", UI="NPA" if v=="4.0" else "NR") for v in PRIORITY}
METRICS["4.0"]["AT"]="NP"


def selected_version(vectors):
    for version in PRIORITY:
        if any(a["vector"].startswith(f"CVSS:{version}/") for a in vectors):
            return version
    return None


def sentences(text):
    return [(m.start(), m.end(), m.group()) for m in
            re.finditer(r"\S[\s\S]*?(?:(?<=[.!?])(?=\s)|(?=\n)|\Z)",text)
            if not re.search(r"CVSS|(?:AV|AC|PR|UI|AT|Au):[A-Z]",m.group(),re.I)]


EVIDENCE_POLICY = """
For every proposed metric, ask whether the same sentence could still be true for a different
value. If so, omit the metric. Evaluate each axis independently. An attacker described as remote
is not by itself evidence of how the vulnerable component is reached. A file's delivery and
its processing can occur in different places. For PR distinguish required pre-existing
privileges from privileges acquired as an outcome. For UI=N require affirmative evidence
that no other person must participate. A sentence describing only the attacker's actions leaves
UI unresolved. For AC=L require affirmative evidence about the difficulty under this version's
definition. A description of an input, impact, or sequence of actions says nothing by itself
about repeatability or difficulty. Preserve explicitly supported values even if other axes
remain unresolved. An empty list is a complete answer when all axes lack evidence."""


def classify(texts, version, *, evidence_policy=False):
    system = COMMON.format(version=version) + (V4 if version=="4.0" else V3)
    if evidence_policy:
        system += EVIDENCE_POLICY
    entry = "^("+"|".join(f"{k}=[{v}]" for k,v in METRICS[version].items())+r")@[1-9][0-9]*$"
    device = remote("import subprocess;print(subprocess.check_output(['nvidia-smi','--query-gpu=name','--format=csv,noheader']).decode())").strip()
    if "H200" not in device:
        raise RuntimeError("H200 device verification failed")
    manifest = ROOT/"results/prerequisite_auxiliary_population_20261124/model_identity.json"
    backend = NemotronBatch(18128,manifest,concurrency=16)
    cache = OUT/"h200_receipts"
    cache.mkdir(exist_ok=True)
    chunks, batch, size = [], [], 0
    for t in sorted(set(texts)):
        if not sentences(t):
            continue
        if len(batch)>=10 or size+len(t)>16000:
            if batch:
                chunks.append(batch)
            batch,size=[],0
        batch.append(t)
        size+=len(t)
    if batch:
        chunks.append(batch)
    def one(group):
        docs = {str(i):{str(j):x[2] for j,x in enumerate(sentences(t),1)} for i,t in enumerate(group)}
        schema = dict(type="object",additionalProperties=False,required=list(docs),
                     properties={i:dict(type="array",items=dict(type="string",pattern=entry),maxItems=12) for i in docs})
        if version=="4.0" or evidence_policy:
            for key, numbered in docs.items():
                values = "|".join(numbered)
                schema["properties"][key]["items"]["pattern"] = entry.split("@")[0]+f"@({values})$"
        packet=dict(documents=docs,schema=schema)
        fingerprint=digest(json.dumps([MODEL,REV,system,packet],sort_keys=True))
        path=cache/(fingerprint+".json")
        if path.exists():
            response=json.loads(path.read_bytes())
        else:
            for attempt in range(3):
                try:
                    response=backend._one(dict(system=system,packet=packet))
                    break
                except (requests.RequestException, ValueError) as exc:
                    status=getattr(getattr(exc,"response",None),"status_code",None)
                    if status in (401,403):
                        raise
                    if len(group)>1 and (status in (400,413,422) or isinstance(exc,ValueError)):
                        middle=len(group)//2
                        return {**one(group[:middle]),**one(group[middle:])}
                    if attempt==2:
                        raise
                    time.sleep(2**attempt)
            response["cvss_version"]=version
            temp=path.with_suffix(".tmp")
            temp.write_text(json.dumps(response),encoding="utf8")
            temp.replace(path)
        out={}
        for i,t in enumerate(group):
            spans=sentences(t)
            readings=[]
            rejected=[]
            for claim in sorted(set(response["prediction"][str(i)])):
                metric,idx=claim.split("@")
                axis,value=metric.split("=")
                if not 1<=int(idx)<=len(spans):
                    rejected.append(claim)
                    continue
                start,end,q=spans[int(idx)-1]
                readings.append(dict(axis=axis,value=value,span=[start,end],quote=q))
            out[t]=dict(evidence=readings,receipt=path.name,document_index=i,rejected=rejected)
        return out
    out={}
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures=[pool.submit(one,g) for g in chunks]
        for i,future in enumerate(as_completed(futures),1):
            out.update(future.result())
            if i%50==0:
                print(f"H200 {i}/{len(chunks)} batches",flush=True)
    return out,device


@lru_cache(maxsize=128)
def assessment_origins(source):
    raw=(ROOT/source).read_bytes()
    record=json.loads(raw)
    document=record["document"]
    origin=dict(document_sha256=hashlib.sha256(raw).hexdigest(),
                document_publisher=document["publisher"]["name"],
                advisory_revision=document["tracking"]["version"])
    entries=defaultdict(list)
    for i,vuln in enumerate(record["vulnerabilities"]):
        for j,score in enumerate(vuln.get("scores",[])):
            for key,data in score.items():
                if isinstance(data,dict) and data.get("vectorString"):
                    identity=(vuln.get("cve"),key,data["vectorString"],tuple(score.get("products",[])))
                    entries[identity].append(dict(**origin,pointer=f"/vulnerabilities/{i}/scores/{j}/{key}"))
    return entries


def control_cases(version):
    cases=[("AC" if a=="AC3" else a,q,e) for a,q,e in CONTROLS+EXTRA_CONTROLS
           if a not in {"Au","AC2"} and (version!="4.0" or a not in {"AC3","UI"})]
    if version=="4.0":
        cases.extend([
            ("AT","Exploitation requires a race condition during normal execution.","P"),
            ("UI","The user only passively views the affected content during routine use; no conscious action to bypass protection is needed.","P"),
            ("UI","The exploitation requires user interaction, but the manner of interaction is unspecified.","?"),
            ("UI","Exploitation requires another user to consciously approve a specific security prompt.","A"),
            ("UI","No user interaction is required for exploitation.","N"),
            ("UI","The product documentation describes user profiles.","?"),
            ("AC","Exploitation requires overcoming a built-in security mitigation.","H")])
    return cases


def main():
    OUT.mkdir(exist_ok=True)
    ids = [r["cve"] for r in json.loads(POP.read_bytes())]
    descriptions = {}
    source_bindings = {}
    with TEXT.open(encoding="utf8") as stream:
        for line in stream:
            r = json.loads(line)["original"]
            if r["cve"] in descriptions:
                raise ValueError("Duplicate description record")
            cve = r["cve"]
            description = r["description"] or ""
            source = [s for s in r["sources"] if s["id"]=="nvd:"+cve and s["text"]==description]
            if description and (len(source)!=1 or source[0]["text_sha256"]!=digest(description)):
                raise ValueError(f"Description provenance mismatch for {cve}")
            descriptions[cve] = description
            source_bindings[cve] = source[0].get("scope_binding") if source else None
            if source_bindings[cve] not in (None, "CVE_description_product_applicability_requires_review"):
                raise ValueError(f"Review changed source-scope semantics for {cve}")
    assert len(ids) == len(set(ids)) == 12418 and set(ids) == set(descriptions)
    refs = {r["cve"]:r["vectors"] for r in json.loads(REF.read_bytes())}
    assert set(refs)==set(ids)
    selected = {c:selected_version(refs[c]) for c in ids}
    readings,controls={},[]
    for version in PRIORITY:
        cases=control_cases(version)
        texts={descriptions[c] for c in ids if selected[c]==version}
        result,device=classify(texts | {q for _,q,_ in cases},version, evidence_policy=version in {"3.0","3.1"})
        readings.update({(version,t):result[t] for t in texts if t in result})
        for a,q,e in cases:
            vals={x["value"] for x in result[q]["evidence"] if x["axis"]==a}
            controls.append(dict(version=version,axis=a,quote=q,expected=e,
                                 h200_receipt=result[q]["receipt"],receipt_document=result[q]["document_index"],
                                 actual=next(iter(vals)) if len(vals)==1 else "?"))
    counts, states = Counter(), Counter()
    with (OUT/"records.tmp").open("w",encoding="utf8") as f:
        for c in ids:
            desc = descriptions[c]
            version = selected[c]
            result = readings.get((version,desc),{})
            evidence = result.get("evidence",[])
            rejected = result.get("rejected",[])
            invalid_axes = {claim.split("=")[0] for claim in rejected}
            values = defaultdict(set)
            for e in evidence:
                values[e["axis"]].add(e["value"])
            assessments = []
            for ref in refs[c]:
                vector = ref["vector"]
                if not version or not vector.startswith(f"CVSS:{version}/"):
                    continue
                score_id = digest(json.dumps([c,ref],sort_keys=True))
                metrics = {}
                for pair in vector.split("/"):
                    k,v = pair.split(":")
                    a = k
                    if a not in METRICS[version]:
                        continue
                    inferred = next(iter(values[a])) if len(values[a])==1 and a not in invalid_axes else "?"
                    state = "unknown" if inferred=="?" else "same_value" if inferred==v else "different_value"
                    states[state]+=1
                    metrics[k]=dict(metric_id=score_id+"/"+k,published=v, blind=inferred, comparison=state,
                                    evidence_indices=[i for i,x in enumerate(evidence) if x["axis"]==a])
                identity=(c,ref["score_key"],vector,tuple(ref["products"]))
                origins=assessment_origins(ref["source"])[identity]
                if not origins:
                    raise ValueError(f"Assessment missing from advisory for {c}")
                assessments.append(dict(**ref,origins=origins,assessment_id=score_id,version=version,metrics=metrics,scope_status="scope_unknown"))
            counts["cves"]+=1
            counts["with_description"]+=bool(desc)
            counts["with_vector"]+=bool(assessments)
            counts["with_reading"]+=bool(evidence)
            counts["assessments"]+=len(assessments)
            cv_states={m["comparison"] for a in assessments for m in a["metrics"].values()}
            counts["with_comparable_value"]+=bool(cv_states & {"same_value","different_value"})
            counts["with_any_value_disagreement"]+=("different_value" in cv_states)
            f.write(json.dumps(dict(cve=c,selected_version=version,description_source="nvd:"+c,description_sha256=digest(desc),
                         source_scope_binding=source_bindings[c],h200_receipt=result.get("receipt"),
                         receipt_document=result.get("document_index"), rejected_citations=rejected,
                         readings=evidence,assessments=assessments),ensure_ascii=False)+"\n")
    (OUT/"records.tmp").replace(OUT/"records.jsonl")
    summary = dict(evidence_policy_versions=["3.0","3.1"],version_priority=PRIORITY,selected_cves=Counter(v or "none" for v in selected.values()),model=MODEL,revision=REV,counts=counts,metric_comparisons=states,controls=controls,
                   device=device, unique_descriptions_read=len(readings), product_scope_verified=0,
                   source_files={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (POP,TEXT,REF)})
    (OUT/"summary.json").write_text(json.dumps(summary,indent=2),encoding="utf8")
    print(counts,states,controls,flush=True)


if __name__=="__main__":
    main()
