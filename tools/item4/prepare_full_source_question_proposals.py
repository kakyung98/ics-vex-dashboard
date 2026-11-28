"""Normalize full-source extractions for the shared second-pass correspondence audit."""
import hashlib
import csv
import json
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.item4.extract_source_conditions_for_question_links import OUT

CATEGORIES={"network_access":"네트워크 접근","adjacent_access":"인접 네트워크 접근","local_access":"로컬 접근",
            "physical_access":"물리적 접근","privilege":"기존 권한","authentication":"인증",
            "user_action":"사용자 동작","feature_setting":"기능·설정","input_processing":"입력 처리","deployment":"배포·실행 환경","other":"기타 조건"}
MISSING={"none":"","scope":"제품·계정·엔드포인트의 동일 범위 확인 필요","input_control":"공격자가 해당 입력을 제어·전달할 수 있는지 확인 필요",
         "feature":"대상 기능의 구체적 설정·상태를 추가 확인해야 함","privilege":"공격자가 가진 권한·인증 범위 확인 필요",
         "user_action":"원문이 요구하는 사용자 동작이 가능한지 확인 필요","return_path":"응답 경로·세션 성립 확인 필요",
         "relation":"조건 사이 AND/OR 관계를 원문으로 확인해야 함","unmapped":"이 조건을 직접 판정할 질문 미확인",
         "unspecified":"원문에서 구체적인 운영 조건 또는 논리 관계를 확정하지 못함"}
RELATIONS={"same_state":"질문이 확인하는 상태와 대응","partial_state":"질문이 필요한 상태의 일부만 확인",
           "partial_scope":"질문의 대상 범위와 조건 범위를 추가 대조해야 함","partial_route":"경로 확인은 접근 조건의 일부",
           "partial_policy":"통신 허용 확인은 접근 조건의 일부"}


def main():
    grouped={}
    for row in csv.DictReader((ROOT/"data/operator_asset_keys_clustered.csv").open(encoding="utf-8-sig",newline="")):
        sig=tuple(row[k] for k in ("key","확인대상단위","o_판정기준","x_판정기준"))
        if sig not in grouped:
            grouped[sig]=dict(qid="Q%03d"%(len(grouped)+1),key=row["key"],question=row["확인항목"],scope=row["확인대상단위"],
                              yes=row["o_판정기준"],no=row["x_판정기준"],rows=[])
        grouped[sig]["rows"].append(dict(asset_type_id=row["asset_type_id"],cluster=row["내부클러스터_ID"]))
    questions=list(grouped.values())
    population={}
    for line in (ROOT/"results/item4_blind_cvss_20261124/records.jsonl").open(encoding="utf8"):
        r=json.loads(line)
        assessments = []
        for assessment in r["assessments"]:
            metrics = {axis: {"metric_id": metric["metric_id"], "published": metric["published"]}
                       for axis, metric in assessment["metrics"].items()}
            assessments.append({**assessment, "metrics": metrics})
        population[r["cve"]]=dict(cve=r["cve"],cvss_version=r["selected_version"],assessments=assessments,
                                  asset_candidates=[],asset_binding="기존 후보 분류; 정확성 미검증",products=[])
    results=json.loads((OUT/"extracted_source_conditions.json").read_bytes())
    ledger=json.loads((OUT/"source_population.json").read_bytes())
    source_index=json.loads((OUT/"source_index.json").read_bytes())
    coverage_by_case={}
    for entry in json.loads((OUT/"source_coverage.json").read_bytes()):
        if entry.get("case_id"):coverage_by_case.setdefault(entry["case_id"],[]).append(entry)
    texts={}
    corpus = OUT/"frozen_sources/cve_evidence.jsonl"
    if not corpus.is_file():
        corpus = ROOT/"benchmark/item4_evaluation/csaf_vex_v2/sources/cve_evidence.jsonl"
    for line in corpus.open(encoding="utf8"):
        r=json.loads(line)["original"]
        population[r["cve"]]["asset_candidates"]=ledger[r["cve"]]["asset_candidates"]
        population[r["cve"]]["products"]=ledger[r["cve"]]["products"]
        population[r["cve"]]["identity_status"]=r.get("original_nvd_status")
        for s in r["sources"]:texts[r["cve"]+"/"+s["id"]]=s["text"]
    units=[]
    for cve,pop in population.items():
        pop["units"]=[];pop["original_scenarios"]=[]
        pop["original_unknowns"]=[];pop["original_coverage_complete"]=False
        cases=[(ident,results[ident]) for ident in ledger[cve]["case_ids"]]
        assert len(cases)==len(ledger[cve]["case_ids"])
        pop["source_case_ids"]=ledger[cve]["case_ids"]
        pop["source_pass_complete"]=all(r["complete"] for _,r in cases) if cases else False
        for ident,r in cases:
            unknown=MISSING.get(r["unknowns_ko"],r["unknowns_ko"])
            if unknown:pop["original_unknowns"].append(unknown)
            if r.get("recovery_status"):
                pop["original_unknowns"].append("모델 출력 한도로 본문을 분할 처리함; 구간 사이 조건 관계 또는 미추출 부분은 미확인")
            local_ids={}
            for atom in r["conditions"]:
                uid=ident+"/"+atom["id"];local_ids[atom["id"]]=uid
                source=atom.get("source_id","")
                initial_citation_status=atom["evidence_valid"]
                if not source and atom.get("source","").startswith("S"):
                    label=atom["source"][1:]
                    entries=coverage_by_case.get(ident,[])
                    if label.isdigit() and int(label)<len(entries):
                        entry=entries[int(label)]
                        source=entry["source"]
                        fragment=texts[source][entry["start"]:entry["end"]]
                        if atom["quote"] and atom["quote"] in fragment:
                            start=entry["start"]+fragment.index(atom["quote"])
                            atom["source_span"]=[start,start+len(atom["quote"])]
                            atom["evidence_valid"]=True
                source_meta=source_index.get(source,{})
                text=texts.get(source,"")
                if source_meta:
                    assert hashlib.sha256(text.encode()).hexdigest()==source_meta["text_sha256"],"Source text changed during extraction"
                mappings=atom["mappings"] if atom["evidence_valid"] and atom["necessity"]=="required" else []
                statement=CATEGORIES.get(atom["category"],atom["category"])+" · "+atom["quote"] if atom["statement_ko"]=="source_quote" else atom["statement_ko"]
                axis=atom.get("axis",atom["category"])
                axis_status="자동 분류"
                if axis=="AT" and pop["cvss_version"]!="4.0":
                    axis="OTHER";axis_status="선택 버전에 AT가 없어 관련 지표 미확인"
                if pop["cvss_version"] is None:axis_status="선택 가능한 CVSS 버전 없음; 지표 대응 미확인"
                kind={"required":"원문 재추출 필요 조건","contextual":"원문 맥락 정보","nonrequirement":"원문 비필요조건 명시"}[atom["necessity"]]
                units.append(dict(id=uid,cve=cve,kind=kind,axis=axis,axis_binding_status=axis_status,value=atom["necessity"],
                    statement=statement,text=text,source_id=source[len(cve)+1:] if source else "",
                    source_url=source_meta.get("url",""),source_span=[0,len(text)],source_sha256=hashlib.sha256(text.encode()).hexdigest(),
                    verified=atom["evidence_valid"],initial_citation_status=initial_citation_status,
                    proposal_kind="exact" if mappings and all(m["kind"]=="exact" for m in mappings) else "partial",
                    atoms=[dict(qid=m["qid"],required=m["required"],quote=atom["quote"],reason_ko=RELATIONS.get(m["reason_ko"],m["reason_ko"])) for m in mappings],
                    why=MISSING.get(atom["missing_ko"],atom["missing_ko"]) or unknown or ("원문 인용·대응 질문 미확인" if not mappings else ""),
                    original_condition=dict(id=uid,statement=statement,necessity=atom["necessity"],
                                            axis=atom.get("axis"),target=atom.get("target"),state=atom.get("state"),actor=atom.get("actor"),
                                            source_quote=atom["quote"],source_span=atom.get("source_span"),
                                            category=atom["category"],evidence_valid=atom["evidence_valid"]),
                    original_source_scope=source_meta.get("scope_binding","unresolved"),
                    source_subject_ambiguous=source_meta.get("subject_ambiguous",False),
                    source_product_keys=source_meta.get("product_keys",[])))
                pop["units"].append(uid)
            for s in r["scenarios"]:
                candidate=dict(op="and",args=[dict(condition=local_ids[c]) for c in s["conditions"] if c in local_ids])
                usable=bool(s["evidence_valid"] and r["complete"] and r["unknowns_ko"]=="none")
                pop["original_scenarios"].append(dict(id=ident+"/"+s["id"],product_binding="unresolved",
                    case_id=ident,source_id=s.get("source_id",""),source_quote=s["quote"],
                    source_span=s.get("source_span"),source_url=source_index.get(s.get("source_id",""),{}).get("url",""),
                    evidence_valid=s["evidence_valid"],logic_status="자동 추출 관계" if usable else "미확인",
                    candidate_expression=candidate,
                    expression=candidate if usable else dict(unknown="시나리오 원문 관계 또는 완전성 미확인")))
        if not pop["units"]:pop["original_unknowns"].append("원문 검토에서 인용 가능한 원자 조건을 확인하지 못함")
        pop["operational_extraction_status"]="본문 검토 완료" if cases else "사용 가능한 원문 없음"
    assert len(population)==12418
    data=dict(source_full_population=True,questions=questions,population=population,units=units)
    (OUT/"proposals.json").write_text(json.dumps(data,ensure_ascii=False),encoding="utf8")
    print("Full-source normalized",len(population),"CVEs",len(units),"condition records",flush=True)


if __name__=="__main__":main()
