"""Recheck source-to-question atoms and publish complete population ledgers."""
import csv
import hashlib
import json
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.item4.link_conditions_to_asset_questions import OUT, CHECK, OutputLimitError, call, digest
from src.item4.models.nemotron_inference_provider import NemotronBatch


def main():
    global OUT
    if len(sys.argv)>1:
        OUT=Path(sys.argv[1]).resolve()
        from tools.item4 import link_conditions_to_asset_questions as mapping_module
        mapping_module.CACHE=OUT/"question_review_cache"
        mapping_module.CACHE.mkdir(exist_ok=True)
    input_path=OUT/"linked_proposals.json" if (OUT/"linked_proposals.json").exists() else OUT/"proposals.json"
    data=json.loads(input_path.read_bytes())
    if data.get("source_full_population"):
        from tools.item4.build_cvss_question_condition_backbone import main as build_basic_conditions
        build_basic_conditions(OUT)
    if not data.get("source_full_population"):
        for line in (ROOT/"results/prerequisite_auxiliary_population_20261124/extractions.jsonl").open(encoding="utf8"):
            original=json.loads(line)
            extraction=original.get("prerequisite",{})
            pop=data["population"][original["cve"]]
            pop["original_unknowns"]=extraction.get("draft",{}).get("unknowns",[])
            pop["original_coverage_complete"]=extraction.get("coverage_complete",False)
    qs={q["qid"]:q for q in data["questions"]}
    backend=NemotronBatch(18128,ROOT/"results/prerequisite_auxiliary_population_20261124/model_identity.json",concurrency=16)
    checks={}
    for unit in data["units"]:
        for atom in unit["atoms"]:
            atom["check_id"]=digest([unit["text"],unit["statement"] if "original_condition" in unit else "",atom])
            pos=unit["text"].find(atom["quote"])
            context=unit["text"][max(0,pos-700):pos+len(atom["quote"])+700] if len(unit["text"])>1800 else unit["text"]
            checks.setdefault(atom["check_id"],dict(text=context,condition=unit["statement"] if "original_condition" in unit else "",
                              proposed=atom,question={k:v for k,v in qs[atom["qid"]].items() if k!="rows"}))
    verdicts={}
    inner=dict(type="object",properties=dict(keep={"type":"boolean"},exact={"type":"boolean"},reason_ko={"type":"string"},missing_ko={"type":"string"}),
               required=["keep","exact","reason_ko","missing_ko"],additionalProperties=False)
    def check(group):
        schema=dict(type="object",properties={str(i):inner for i in range(len(group))},required=[str(i) for i in range(len(group))],additionalProperties=False)
        try:
            answer=call(backend,CHECK,dict(cases={str(i):c for i,(_,c) in enumerate(group)},schema=schema))
        except OutputLimitError:
            if len(group)>1:
                mid = len(group)//2
                return check(group[:mid]) + check(group[mid:])
            verdicts[group[0][0]] = dict(keep=False, exact=False,
                reason_ko="2차 검토 출력 한도로 유효한 판정을 얻지 못함", missing_ko="미확인")
            return 1
        except Exception:
            if len(group)>1:
                return sum(check([item]) for item in group)
            raise
        for i,(ident,_) in enumerate(group):
            verdicts[ident]=answer[str(i)]
        return len(group)
    items=list(checks.items())
    n=0
    with ThreadPoolExecutor(max_workers=16) as pool:
        tasks=[pool.submit(check,items[i:i+6]) for i in range(0,len(items),6)]
        for t in as_completed(tasks):
            n+=t.result()
            if n%150==0:print("rechecked",n,"/",len(items),flush=True)
    # Original full passages remain in their source files. Publish compact exact excerpts.
    csv_rows=[]
    type_rows={f"A{i:04d}":[] for i in range(1,19)}
    for unit in data["units"]:
        unit["candidate_atoms"]=unit.pop("atoms")
        unit["atoms"]=[]
        for atom in unit["candidate_atoms"]:
            verdict=verdicts[atom["check_id"]]
            atom["verification"]=verdict
            if verdict["keep"]:
                atom["semantic_status"]="질문 의미 연결" if verdict["exact"] else "부분 연결·추가 확인"
                unit["atoms"].append(atom)
        unit["mapping_status"]=("질문 의미 연결" if any(a["verification"]["exact"] for a in unit["atoms"])
                                else "부분 연결·추가 확인" if unit["atoms"] else "미확인")
        if not unit["atoms"] and unit["candidate_atoms"]:
            rejection_reasons=[a["verification"]["reason_ko"]+" "+a["verification"]["missing_ko"] for a in unit["candidate_atoms"]]
            unit["why"]=" / ".join(rejection_reasons)
        unit["deployment_status"]="미확인"
        unit["remaining_conditions"]=unit["why"]
        for atom in unit["atoms"]:
            q=qs[atom["qid"]]
            snippet=atom["quote"]
            absolute_start=unit["source_span"][0]+unit["text"].index(snippet)
            atom["source_span"]=[absolute_start,absolute_start+len(snippet)]
            atom["source_sha256"]=unit["source_sha256"]
            atom["scoped_expression"]=q["key"]+"("+q["scope"]+")="+atom["required"]
            atom["type_candidates"]=[]
            for binding in q["rows"]:
                aid=binding["asset_type_id"]
                pop=data["population"][unit["cve"]]
                hint=aid in pop["asset_candidates"]
                # A reusable question definition is visible in every corresponding type.
                # Keep the distinct, unverified product/type applicability alongside it.
                atom["type_candidates"].append(dict(**binding,existing_asset_candidate=hint,applicability="미확인"))
                if not hint:
                    continue
                row=[unit["cve"],unit["id"],unit["kind"],unit["axis"],unit["statement"],q["key"],binding["cluster"],
                     atom["required"],atom["semantic_status"],atom["scoped_expression"],snippet,unit["source_url"],
                     unit["source_id"],str(atom["source_span"]),atom["verification"]["reason_ko"],
                     atom["verification"]["missing_ko"] or unit["why"],"미확인",
                     "기존 자산 유형 후보; 제품 범위 대조 필요" if hint else "질문 정의만 대응; 이 유형에 적용되는 제품인지 미확인"]
                type_rows[aid].append(row)
            csv_rows.append([unit["cve"],unit["id"],unit["kind"],unit["axis"],unit["statement"],q["qid"],q["key"],atom["required"],
                             atom["semantic_status"],snippet,unit["source_url"],unit["source_id"],str(atom["source_span"]),
                             atom["verification"]["reason_ko"],atom["verification"]["missing_ko"] or unit["why"],"미확인"])
        if not unit["atoms"]:
            csv_rows.append([unit["cve"],unit["id"],unit["kind"],unit["axis"],unit["statement"],"","","","미확인","",
                             unit["source_url"],unit["source_id"],str(unit["source_span"]),unit["why"],
                             "대응 질문 또는 원문 근거가 부족함","미확인"])
        match=re.search(r"\S+(?:\s+\S+){0,11}",unit["text"])
        source_quote=unit.get("original_condition",{}).get("source_quote","")
        if unit["atoms"]:
            unit["excerpt"]=unit["atoms"][0]["quote"]
        elif source_quote and source_quote in unit["text"] and unit["verified"]:
            unit["excerpt"]=source_quote
        else:
            unit["excerpt"]=match.group() if match and unit["verified"] else ""
        unit["excerpt_span"]=([unit["source_span"][0]+unit["text"].index(unit["excerpt"]),
                               unit["source_span"][0]+unit["text"].index(unit["excerpt"])+len(unit["excerpt"])]
                              if unit["excerpt"] else None)
        if not unit["atoms"]:
            csv_rows[-1][9]=unit["excerpt"]
            csv_rows[-1][12]=str(unit["excerpt_span"])
        unit["source_passage_sha256"]=hashlib.sha256(unit["text"].encode()).hexdigest()
        unit.pop("text")
    stats=Counter(u["mapping_status"] for u in data["units"])
    data["summary"]=dict(cves=len(data["population"]),units=len(data["units"]),questions=505,distinct_question_definitions=len(qs),
                          unit_status=dict(stats),projected_type_rows=sum(map(len,type_rows.values())),
                          caveat="자동 의미 연결 및 2차 모델 검토. 제품 범위와 배포 사실은 미확인. 확정하지 못한 원문 관계는 미확인으로 유지함.",
                          independent_semantic_accuracy_verified=False)
    data["summary"]["condition_roles"]=dict(Counter(u.get("original_condition",{}).get("necessity","unspecified") for u in data["units"]))
    data["summary"]["source_quotes_verified"]=sum(u["verified"] for u in data["units"])
    data["summary"]["source_condition_grounding"]=dict(Counter(u.get("source_grounding","unknown") for u in data["units"]))
    basic_path=OUT/"cvss_basic_conditions.json"
    if basic_path.exists():
        backbone=json.loads(basic_path.read_bytes())
        data["summary"]["cvss_basic_conditions"]=backbone["summary"]
        data["cvss_basic_conditions_file"]="cvss_basic_conditions.json"
        basic_by_cve={r["cve"]:r for r in backbone["population"]}
        formulas_by_cve={}
        for a in backbone["assessments"]:formulas_by_cve.setdefault(a["cve"],[]).append(a)
    else:
        basic_by_cve={};formulas_by_cve={}
    # Full population includes CVEs with no usable extracted unit.
    units_by_cve={}
    for u in data["units"]:units_by_cve.setdefault(u["cve"],[]).append(u)
    for cve,pop in data["population"].items():
        related=units_by_cve.get(cve,[])
        pop["mapping_status"]="질문 연결 있음" if any(u["atoms"] for u in related) else "미확인"
        pop["attack_vector_status"]="미확인"
        pop["cvss_basic_conditions"]=basic_by_cve.get(cve,{})
        pop["cvss_assessment_formulas"]=formulas_by_cve.get(cve,[])
        pop["formula"]="E_제품버전일치 AND E_원문시나리오조건충족 AND E_적용범위일치"
        by_condition={u["original_condition"].get("id",u["original_condition"].get("condition_id")):u for u in related if "original_condition" in u}
        def substitute(node):
            if not isinstance(node,dict):return dict(unknown="원문 논리식 미확인")
            if "condition" in node:
                u=by_condition.get(node["condition"])
                if u and u.get("original_condition",{}).get("necessity")=="nonrequirement" and u.get("verified") and u.get("source_grounding")=="supported":
                    return dict(constant=True,source_condition=node["condition"],reason="원문에서 해당 전제를 요구하지 않는다고 명시")
                matches=[a for a in u["atoms"] if a["verification"]["exact"]] if u else []
                if len(matches)==1:
                    a=matches[0]
                    return dict(key=qs[a["qid"]]["key"],question_id=a["qid"],required=a["required"],
                                source_condition=node["condition"],scope=qs[a["qid"]]["scope"],
                                allowed_question_asset_types=[r["asset_type_id"] for r in qs[a["qid"]]["rows"]])
                return dict(unknown=node["condition"],reason="조건 전체를 판정할 합성식 또는 단일한 대응 범위 미확인",
                            candidate_checks=[dict(question_id=a["qid"],key=qs[a["qid"]]["key"],required=a["required"],
                                                   scope=qs[a["qid"]]["scope"]) for a in u["atoms"]] if u else [])
            if node.get("op") in ("and","or","not") and isinstance(node.get("args"),list):
                return dict(op=node["op"],args=[substitute(n) for n in node["args"]])
            return dict(unknown="지원되는 원문 논리식 미확인")
        pop["question_scenarios"]=[dict(id=s.get("id"),case_id=s.get("case_id"),expression=substitute(s.get("expression")),
                                      source_id=s.get("source_id"),source_url=s.get("source_url"),source_quote=s.get("source_quote"),
                                      source_span=s.get("source_span"),evidence_valid=s.get("evidence_valid"),
                                      logic_status=s.get("logic_status","미확인"),candidate_expression=s.get("candidate_expression"),
                                      product_binding=s.get("product_binding","unresolved"))
                                    for s in pop["original_scenarios"]]
    (OUT/"condition_question_links.json").write_text(json.dumps(data,ensure_ascii=False),encoding="utf8")
    (OUT/"workbook_type_rows.json").write_text(json.dumps(type_rows,ensure_ascii=False),encoding="utf8")
    with (OUT/"condition_question_links.csv").open("w",encoding="utf-8-sig",newline="") as f:
        w=csv.writer(f);w.writerow(["CVE","추출_ID","종류","지표·조건","원래 조건","질문_ID","key","요구값","연결 상태","원문 인용","출처 URL","출처 ID","원문 위치","연결 근거","남은 조건","공격 벡터 판정","원문 조건 검토"])
        grounding_by_id={u["id"]:u.get("source_grounding","unknown") for u in data["units"]}
        for row in csv_rows:w.writerow(row+[grounding_by_id[row[1]]])
    with (OUT/"population_ledger.csv").open("w",encoding="utf-8-sig",newline="") as f:
        w=csv.writer(f);w.writerow(["CVE","CVSS 버전","CVSS 평가 수","CVSS 기본 지표 기록 수","원문 해석·조건 기록 수","원문 질문 연결 상태","공격 벡터 판정","자산 유형 후보"])
        for cve,pop in data["population"].items():
            basic=pop["cvss_basic_conditions"]
            w.writerow([cve,pop["cvss_version"],basic.get("assessment_count",0),basic.get("basic_condition_records",0),
                        len(pop["units"]),pop["mapping_status"],pop["attack_vector_status"]," · ".join(pop["asset_candidates"])])
    (OUT/"summary.json").write_text(json.dumps(data["summary"],ensure_ascii=False,indent=2),encoding="utf8")
    print(json.dumps(data["summary"],ensure_ascii=False),flush=True)


if __name__=="__main__":main()
