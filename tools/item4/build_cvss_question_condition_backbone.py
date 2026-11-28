"""Keep every selected CVSS assessment and metric as a source-bound basic condition."""
import csv
import hashlib
import json
import sys
from functools import lru_cache
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/"results/item4_condition_question_links"
SPECS={v:f"https://www.first.org/cvss/v{v}/specification-document" for v in ("3.0","3.1","4.0")}
AV={"N":("네트워크를 통한 접근","source_route_present=o AND source_flow_permitted=o AND E_해당엔드포인트접근충족",["source_route_present","source_flow_permitted"]),
    "A":("인접 네트워크 접근","E_인접네트워크접근충족",[]),"L":("필요한 로컬 접근","E_로컬접근조건충족",[]),
    "P":("물리적 접근","E_물리적접근조건충족",[])}


@lru_cache(maxsize=64)
def document(source):
    path=ROOT/source.replace(chr(92),"/")
    raw=path.read_bytes()
    doc=json.loads(raw)
    return doc,hashlib.sha256(raw).hexdigest()


def condition(axis,value):
    if axis=="AV":
        label,expr,keys=AV[value]
        return label,expr,keys,"AV 정의를 실제 통신 경로의 운용 확인 항목으로 분해했다. 경로·허용만으로 서비스·입력 제어·반환 경로까지 확정할 수 없으므로 부분 연결이다."
    if axis=="PR":
        if value=="N":return "공격 전 사전 권한 요구 없음","TRUE",[],"PR:N은 사전 권한을 요구하지 않는 평가다. 익명 접근 설정 또는 MFA 비활성 값으로 치환할 근거는 미확인이다."
        return ("공격 전 높은 권한 필요" if value=="H" else "공격 전 낮은 권한 필요"),"E_공격자사전권한충족",[],"공격자가 가진 권한을 확인해야 한다. 서비스 실행 계정 권한이나 로컬 로그인 정책과의 직접 대응은 미확인이다."
    if axis=="UI":
        if value=="N":return "다른 사용자 동작 요구 없음","TRUE",[],"UI:N은 피해 사용자 동작을 추가 전제로 요구하지 않는 평가다. 애플리케이션 설정의 비활성 값으로 치환하지 않는다."
        return ("사용자 능동 참여 필요" if value=="A" else "사용자 수동 참여 필요" if value=="P" else "사용자 참여 필요"),"E_원문이요구하는사용자동작충족",[],"구체적인 사용자 동작과 파일·애플리케이션 범위가 필요하다. 일반 프로젝트 열기 기록과의 직접 대응은 미확인이다."
    if axis=="AC":
        if value=="L":return "AC 지표의 추가 복잡도 전제 없음","TRUE",[],"AC:L의 기본 평가를 보존한다. 원문에 기재된 기능·구성 등 다른 필요 조건은 별도로 확인해야 한다."
        return "높은 공격 복잡도에 해당하는 전제 필요","E_AC특수조건충족",[],"버전별 AC 정의에 해당하는 구체적인 필요 조건이 원문에서 식별돼야 한다."
    if axis=="AT":
        if value=="N":return "AT 배포·실행 전제 요구 없음","TRUE",[],"AT:N의 기본 평가를 보존하고 다른 지표와 원문 조건은 따로 확인한다."
        return "특정 배포·실행 전제 필요","E_AT배포실행조건충족",[],"AT:P에 해당하는 구체적인 배포·실행 조건과 관측 질문은 추가 확인이 필요하다."
    raise ValueError(axis)


def main(output=None):
    global OUT
    if output:OUT=Path(output)
    OUT.mkdir(parents=True, exist_ok=True)
    fresh_by_cve={}
    source_link=OUT/"linked_proposals.json"
    if source_link.exists():
        fresh=json.loads(source_link.read_bytes())
        if fresh.get("source_full_population"):
            for unit in fresh["units"]:fresh_by_cve.setdefault(unit["cve"],[]).append(unit)
    records=[json.loads(line) for line in (ROOT/"results/item4_blind_cvss_20261124/records.jsonl").open(encoding="utf8")]
    corpus = OUT/"frozen_sources/cve_evidence.jsonl"
    if not corpus.is_file():
        corpus = ROOT/"benchmark/item4_evaluation/csaf_vex_v2/sources/cve_evidence.jsonl"
    with corpus.open(encoding="utf8") as stream:
        originals = {row["cve"]: row for line in stream if (row := json.loads(line)["original"])}
    all_rows=[];types={f"A{i:04d}":[] for i in range(1,19)};ledger=[];assessments=[]
    for r in records:
        before=len(all_rows)
        for a in r["assessments"]:
            doc,sha=document(a["source"])
            origin=a["origins"][0];assert origin["document_sha256"]==sha
            pointer_parts=origin["pointer"].strip("/").split("/")
            assert doc["vulnerabilities"][int(pointer_parts[1])]["cve"]==r["cve"]
            obj=doc
            for part in pointer_parts:
                obj=obj[int(part)] if isinstance(obj,list) else obj[part]
            assert obj["vectorString"]==a["vector"]
            refs=doc["document"].get("references",[])
            url=next((v["url"] for v in refs if v.get("category")=="self" and "cisa.gov/" in v["url"]),None)
            url=url or next(v["url"] for v in refs if v.get("category")=="self")
            product_ids=set(a["products"]);advisory=Path(a["source"].replace(chr(92),"/")).stem
            product_records=[p for p in originals[r["cve"]].get("products",[]) if p.get("advisory_id")==advisory and p.get("source_product_id") in product_ids]
            candidates=sorted({aid for p in product_records for aid in p.get("asset_ids",[])})
            if not candidates:candidates=originals[r["cve"]].get("asset_ids",[])
            formula=[]
            for axis,m in a["metrics"].items():
                value=m["published"]
                label,expr,keys,why=condition(axis,value)
                quote=axis+":"+value
                assert quote in a["vector"]
                metric_id=a["assessment_id"]+"/"+axis
                formula.append("("+expr+")")
                detail_indices=m.get("evidence_indices",[])
                source_units=[u for u in fresh_by_cve.get(r["cve"],[]) if u["axis"]==axis and u["verified"]]
                row=dict(cve=r["cve"],assessment_id=a["assessment_id"],metric_id=metric_id,version=a["version"],axis=axis,value=value,
                    condition=label,expression=expr,question_keys=keys,link_status="부분 연결·추가 확인" if keys else "미확인",
                    reason=why,quote=quote,vector=a["vector"],source=a["source"],source_url=url,source_pointer=origin["pointer"]+"/vectorString",
                    source_sha256=sha,products=a["products"],product_names=[p["name"] for p in product_records],
                    asset_candidates=candidates,asset_binding_status="기존 자동분류 후보; 제품 유형 적용 미확인",specification_url=SPECS[a["version"]],
                    description_comparison="미확인" if source_link.exists() else m["comparison"],
                    source_condition_ids=[u["id"] for u in source_units],
                    description_reading_ids=[] if source_link.exists() else [r["cve"]+"/reading/"+str(i) for i in detail_indices],
                    description_support=("재추출 조건 있음; 지표·제품 범위 대조 미확인" if source_units else "구체적인 원문 근거 미확인")
                        if source_link.exists() else ("지표값 대조 기록 있음; 제품 범위 미확인" if detail_indices else "구체적인 원문 근거 미확인"),
                    deployment_status="미확인")
                all_rows.append(row)
                for aid in candidates:
                    if aid in types:types[aid].append(row)
            assessments.append(dict(cve=r["cve"],id=a["assessment_id"],source=a["source"],products=a["products"],
                expression="E_제품버전일치 AND E_평가적용범위일치 AND "+" AND ".join(formula)+" AND E_구체원문조건충족",status="미확인"))
        ledger.append(dict(cve=r["cve"],version=r["selected_version"],assessment_count=len(r["assessments"]),basic_condition_records=len(all_rows)-before,
                           source_detail_records=len(fresh_by_cve.get(r["cve"],[])) if source_link.exists() else len(r["readings"]),
                           status="미확인",reason="현장 값·제품 범위·구체 조건 확인 필요" if r["assessments"] else "선택할 CVSS 3.1/4.0/3.0 평가 없음"))
    assert len(records)==12418 and len(all_rows)==54648 and len(assessments)==13662
    payload=dict(summary=dict(cves=12418,assessments=len(assessments),basic_condition_records=len(all_rows),
        cves_with_selected_cvss=sum(bool(r["assessments"]) for r in records),cves_without_selected_cvss=sum(not r["assessments"] for r in records)),
        records=all_rows,assessments=assessments,population=ledger)
    (OUT/"cvss_basic_conditions.json").write_text(json.dumps(payload,ensure_ascii=False),encoding="utf8")
    (OUT/"cvss_type_basic_conditions.json").write_text(json.dumps(types,ensure_ascii=False),encoding="utf8")
    with (OUT/"cvss_basic_conditions.csv").open("w",encoding="utf-8-sig",newline="") as f:
        cols=["cve","assessment_id","version","axis","value","condition","expression","question_keys","link_status","reason","quote","source_url","source_pointer","products","description_support","deployment_status"]
        w=csv.writer(f);w.writerow(cols)
        for row in all_rows:w.writerow([" · ".join(row[k]) if isinstance(row[k],list) else row[k] for k in cols])
    (OUT/"cvss_backbone_summary.json").write_text(json.dumps(payload["summary"],ensure_ascii=False,indent=2),encoding="utf8")
    print(json.dumps(payload["summary"],ensure_ascii=False))


if __name__=="__main__":main(sys.argv[1] if len(sys.argv)>1 else None)
