"""Publish verified coverage and CVE-specific quotes to the existing #4 website."""
import json
from collections import defaultdict
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/"results/item4_blind_cvss_20261124"


def main():
    summary=json.loads((OUT/"summary.json").read_bytes())
    verified=json.loads((OUT/"verification.json").read_bytes())
    years=defaultdict(dict)
    empty_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    with (OUT/"records.jsonl").open(encoding="utf8") as stream:
        for line in stream:
            r=json.loads(line)
            c=r["cve"]
            evidence=[[e["axis"],e["value"],*e["span"],e["quote"]] for e in r["readings"]]
            scores=[dict(v=a["version"],s=Path(a["source"]).stem,p=a["products"],raw=a["vector"],publisher=a["origins"][0]["document_publisher"],
                         ptr=a["origins"][0]["pointer"],
                         m={k:[m["published"],m["blind"],m["comparison"]] for k,m in a["metrics"].items()})
                    for a in r["assessments"]]
            years[c.split("-")[1]][c]=dict(version=r["selected_version"],d=r["description_sha256"]!=empty_hash,e=evidence,a=scores)
    assert sum(map(len,years.values()))==verified["unique_cves"]==12418
    target=ROOT/"site/item4-cvss-data"
    target.mkdir(exist_ok=True)
    for year,rows in years.items():
        assert year.isdigit() and len(year)==4
        (target/(year+".js")).write_text("window.cvssYears ??= {}; window.cvssYears['"+year+"']="+
                                         json.dumps(rows,separators=(",",":"))+";\n",encoding="utf8")
    c=summary["counts"]
    states=summary["metric_comparisons"]
    text=(f'전체 {c["cves"]:,}건 중 description {c["with_description"]:,}건, 선택한 버전의 벡터 보유 CVE '
          f'{c["with_vector"]:,}건, 대상 버전 미보유 {c["cves"]-c["with_vector"]:,}건입니다. 지표별 값 일치 {states.get("same_value",0):,}건, '
          f'값 불일치 {states.get("different_value",0):,}건, 미확인 {states.get("unknown",0):,}건입니다.')
    coverage=summary["selected_cves"]
    text += " 선택 버전별 CVE는 " + ", ".join(
        f'{v} {coverage.get(v,0):,}건' for v in summary["version_priority"]) + "입니다."
    text += (f' 문장 대조 시험 {verified["control_count"]}개 중 {verified["controls_passed"]}개가 예상값과 일치했습니다.'
             ' 이 시험은 전체 CVE의 의미 정확도를 측정하지 않습니다.')
    (target/"summary.js").write_text("window.cvssSummary="+json.dumps(text)+";\nwindow.cvssAvailableYears="+
                                     json.dumps(sorted(years))+";\n",encoding="utf8")
    print(text)


if __name__=="__main__":
    main()
