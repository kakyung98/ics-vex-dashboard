"""Publish separate definition and type-placement decisions using a shared quotation register."""
import csv,gzip,json,re,sys
from collections import Counter,defaultdict
from pathlib import Path
from functools import lru_cache
from urllib.parse import urlparse,unquote
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from tools.item4.audit_asset_key_provenance import CACHE,ROOT,OUT,ROLES,MODEL,REVISION
def source_text(d):
    return json.loads((CACHE/(d+".json")).read_bytes())
@lru_cache(maxsize=40)
def pages(d):
    return dict(source_text(d)["pages"])
def anchor(ref):
    if not ref:return None
    e=dict(ref);t=pages(e["doc"])
    if e["location"]=="Document title":
        loc=next((k for k,v in t.items() if e["quote"] in v),None)
        if not loc:return None
        e["location"]=loc;e["start"]=t[loc].index(e["quote"]);e["end"]=e["start"]+len(e["quote"])
    assert t[e["location"]][e["start"]:e["end"]]==e["quote"]
    return e
def compact(ref,m):
    return {**ref,"quote":m.group(),"start":ref["start"]+m.start(),"end":ref["start"]+m.end()}
def main():
    cats=list(csv.DictReader(gzip.open(ROOT/"data/operator_asset_keys.csv.gz","rt",encoding="utf-8-sig")))
    reviews={(r["asset"],r["key"]):r for r in json.loads((CACHE/"adjudicated.json").read_bytes())}
    docs={x["id"]:x for x in json.loads((OUT/"reviewed_source_index.json").read_bytes())}
    assert len(cats)==len(reviews)==505
    keyclaims=defaultdict(list); assetclaims={}; catindex={}
    def signature(r):return tuple(r[k] for k in ("key","확인대상단위","o_판정기준","x_판정기준"))
    for i,r in enumerate(cats):
        aid,key=r["asset_type_id"],r["key"];catindex[aid,key]=i
        rev=reviews[aid,key];j=rev["judgement"];ev=rev["evidence"]
        mismatches={"project_import_enabled":"XDB 가져오기 절차만으로 프로젝트 가져오기의 활성 상태를 판정할 수 없다.",
                    "remote_parameter_write_enabled":"출력 채널 값 쓰기는 인터페이스의 원격 파라미터 쓰기 설정을 입증하지 않는다."}
        if ev["key"] and key in mismatches and any(s in ev["key"]["quote"] for s in ("XDB","output channels")):
            j["K"]=False;j["whyK"]=mismatches[key]
        if aid=="A0013" and key in ("remote_parameter_write_enabled","output_force_enabled"):
            j["A"]=False;j["whyA"]="제시된 출력 채널 쓰기 또는 I/O 확장 설명에서 원격 I/O 제품의 해당 기능을 특정하지 못했다."
        if key in {"source_route_present","source_flow_permitted"} and ev["key"]:
            j["K"]=False
            j["whyK"]="후보 원문은 한 장비의 경로 또는 정책을 설명하며 해당 흐름의 모든 경유 장비와 유효 설정에 대한 판정 기준까지 뒷받침하지 않는다."
        # Reuse definitions only when the entire operational predicate is identical.
        if j["K"] and (e:=anchor(ev["key"])):
            keyclaims[signature(r)].append((e,rev["asset"],i))
        if j["A"]:
            f,role=anchor(ev["feature"]),anchor(ev["role"])
            if not f or not role or f["doc"]!=role["doc"]:continue
            m=re.search(r"(?<![A-Za-z])(?:"+ROLES[int(aid[1:])-1]+r")(?![A-Za-z])",role["quote"],re.I)
            if not m:continue
            role=compact(role,m)
            assetclaims[i]=(f,role)
    # Reuse short excerpts via IDs and allocate scarce quotations to the widest
    # exact matches. A located source that still needs an excerpt is disclosed.
    def token(e):return (e["doc"],e["location"],e["start"],e["quote"])
    extra=list(docs.values())+json.loads((OUT/"sources_shared_key_search.json").read_bytes())+json.loads((OUT/"sources_manual_search.json").read_bytes())
    ids={x["sha256"]:x["id"] for x in docs.values()}
    notes={}
    curated=[
        ("usb_storage_enabled","620284ffcc818b22d066","allow write access for some USB devices","Microsoft Defender 문서는 이동식 저장장치별 USB 읽기 또는 쓰기를 허용하는 장치 제어 정책을 예시한다."),
        ("remote_update_enabled","81b0f298c558810fdd0d","configured to receive updates from an intranet update service","Windows Update는 내부 네트워크 업데이트 서비스에서 소프트웨어 업데이트를 받도록 설정할 수 있다."),
        ("wifi_enabled","101d9abe99adfd16605b","admin=]ENABLED|DISABLED","Windows netsh는 이름으로 지정한 인터페이스의 관리 상태를 설정하며 같은 문서에 Wi-Fi 인터페이스 예가 있다."),
        ("ethernet_cable_connected","118fd764260792715ffd","Connect ethernet cable from your computer to any port EXCEPT ether1","MikroTik 설치 지침은 이더넷 케이블의 물리적 포트 체결을 명시한다."),
        ("usb_device_connected","530434863d82910ee607","Plug the USB device into a different USB port","Microsoft는 물리적으로 USB 장치를 지정 포트에 꽂는 절차를 설명한다."),
        ("ssh_listener_enabled","29a2e0bdb6c32afe4547","Specifies the local addresses sshd(8) should listen on","OpenSSH의 ListenAddress는 SSH 서버가 수신하는 로컬 주소를 지정한다."),
        ("http_listener_enabled","84cde9a5a10b70cae4de","Listen directive tells the server to accept incoming requests","Apache HTTP Server의 Listen 설정으로 요청을 받을 포트와 주소를 지정한다."),
        ("https_listener_enabled","09c70f68a703ba1db005","SSLEnabled Use this attribute to enable SSL traffic on a connector.","Tomcat의 HTTP 커넥터는 SSLEnabled 설정으로 TLS 수신을 활성화한다."),
        ("anonymous_access_enabled","ec66ab78dd0f47fccd03","without prompting them for a user name or password","IIS의 익명 인증 설정은 이용자에게 계정명과 암호를 요구할지 결정한다."),
        ("serial_management_enabled","e05776ddd9e4693a32df","getty runs on the serial port so that you can login","Linux 직렬 콘솔 문서는 해당 포트에서 로그인을 받기 위한 서비스 구성을 설명한다."),
        ("telnet_listener_enabled","118fd764260792715ffd","/ip service disable telnet,ftp,www,api","MikroTik 문서는 Telnet을 개별적으로 끌 수 있는 수신 서비스로 열거한다."),
        ("snmp_listener_enabled","d339d15dc32f4cfe85a7","agent will bind to the specified port on all interfaces","Net-SNMP는 실행된 에이전트가 요청 수신 포트에 바인딩하는 동작을 명시한다."),
        ("local_interactive_login_enabled","cad3962285c7e3db53b7","which users can start an interactive session on the device","Windows의 Allow log on locally 정책은 이 장치에서 대화형 세션을 시작할 수 있는 계정을 정의한다."),
    ]
    def extra_ref(id,q,loc=None):
        d=next(x for x in extra if x["id"]==id)
        canon=ids.setdefault(d["sha256"],id)
        docs.setdefault(canon,d)
        for l,t in pages(canon).items():
            if q in t and (loc is None or l==loc):
                p=t.index(q)
                return dict(doc=canon,location=l,start=p,end=p+len(q),quote=q)
        raise ValueError(q)
    assetnotes={}
    for key,id,q,reason in curated:
        e=extra_ref(id,q)
        idx=next(i for i,r in enumerate(cats) if r["key"]==key)
        keyclaims[signature(cats[idx])].append((e,cats[idx]["asset_type_id"],idx))
        notes[token(e)]=reason
        if id=="118fd764260792715ffd":
            ridx=catindex["A0014",key]
            assetclaims[ridx]=(e,extra_ref(id,"MikroTik router"))
            assetnotes[ridx]="동일한 MikroTik 라우터 설치 문서에서 제품 유형과 해당 설정·연결 절차를 함께 확인했다."
    examples=[
        ("A0009","ethernet_cable_connected","e9e2684c9e9d6859bf4a",10,"Ethernet cable to the MGate’s 10/100M Ethernet port",4,"MGate 5119 Series of protocol gateways","MGate 5119 프로토콜 게이트웨이 설명서는 케이블을 연결할 이더넷 포트를 지정한다."),
        ("A0002","usb_device_connected","80f972932740fb0284b6",112,"Plug in a USB mouse to the terminal.",9,"human machine interface (HMI) application for the terminal","PanelView Plus 7의 HMI 단말에 USB 마우스를 꽂는 절차가 있다."),
        ("A0002","ethernet_cable_connected","80f972932740fb0284b6",39,"Secure the Ethernet cable",9,"human machine interface (HMI) application for the terminal","PanelView Plus 7 단말의 이더넷 커넥터에서 케이블을 고정하도록 지시한다."),
        ("A0003","ethernet_cable_connected","e1c71da847b4c69fe65d",15,"connection to an Ethernet network through any standard RJ45 Ethernet cable",1,"Micro820 Programmable Controllers","Micro820 프로그래머블 제어기 매뉴얼에서 RJ45 케이블을 사용하는 이더넷 연결을 명시한다."),
        ("A0004","http_listener_enabled","0d27ee23289bb489aa20",51,"enable the HTTP web server in SICAM A8000",97,"SICAM A8000 CP-8000/CP-802x / SICAM RTUs","SICAM RTU 보안 매뉴얼에서 A8000의 특정 CPU 모델에 대한 HTTP 서버 설정을 설명한다."),
        ("A0013","snmp_listener_enabled","425ab6d22f1e4b0976c9",51,"enable SNMP under SNMP Settings > SNMP Agent",6,"ioLogik E1200 industrial Ethernet remote I/O","ioLogik E1200 원격 I/O 매뉴얼에 SNMP 에이전트 활성화 설정이 있다."),
        ("A0015","telnet_listener_enabled","edabb6c144faa87613dd",13,"Disable or enable the Telnet Console",1,"Moxa Managed Ethernet Switch","Moxa 관리형 이더넷 스위치 매뉴얼에서 Telnet 콘솔 사용 여부를 설정한다."),
        ("A0018","ethernet_cable_connected","c69654817a613153aa6b",10,"you can use a standard straight-through Ethernet cable",9,"SNAP PAC R-series programmable automation controllers","SNAP PAC R 시리즈 PAC 설명서는 장비의 이더넷 인터페이스와 연결 케이블을 특정한다."),
    ]
    for aid,key,id,fp,f,rp,role,why in examples:
        idx=catindex[aid,key]
        assetclaims[idx]=(extra_ref(id,f,f"PDF p.{fp}"),extra_ref(id,role,f"PDF p.{rp}"))
        assetnotes[idx]=why
    (OUT/"reviewed_source_index.json").write_text(json.dumps(list(docs.values()),ensure_ascii=False,indent=1),encoding="utf8")
    proposals=defaultdict(list)
    for i,r in enumerate(cats):
        for e,_,_ in keyclaims[signature(r)]:proposals[(i,"K")].append((token(e),))
        if i in assetclaims:proposals[(i,"A")].append(tuple(map(token,assetclaims[i])))
    inverted=defaultdict(set)
    for target,opts in proposals.items():
        for option in opts:inverted[option].add(target)
    source_budget=defaultdict(dict);chosen={};used={}
    def cost(opt):
        add=defaultdict(set)
        for doc,loc,off,q in opt:
            if q not in source_budget[doc]:add[doc].add(q)
        return {doc:sum(len(x.split()) for x in quotes) for doc,quotes in add.items()}
    def room(opt):
        return all(sum(source_budget[d].values())+v<=25 for d,v in cost(opt).items())
    ordered=sorted(inverted,key=lambda opt:(opt[0] not in notes,-len(inverted[opt])/max(1,sum(cost(opt).values())),opt))
    for opt in ordered:
        targets=[x for x in inverted[opt] if x not in chosen]
        if not targets or not room(opt):continue
        for doc,loc,off,q in opt:source_budget[doc][q]=len(q.split())
        for target in targets:chosen[target]=opt
    register=[]
    def cite(t):
        if t not in used:
            doc,loc,off,q=t;d=docs[doc]
            assert pages(doc)[loc][off:off+len(q)]==q
            title=d["title"]
            if len(title)<9:title=unquote(urlparse(d["url"]).path.split("/")[-1]) or title
            url=d["url"];dest=url+("#page="+loc.split(".")[-1] if loc.startswith("PDF p.") else "")
            used[t]="Q%04d"%(len(register)+1)
            register.append(dict(id=used[t],source_id=doc,publisher_domain=urlparse(url).hostname,title=title,
                location=loc,quote=q,url=dest,normalized_span=[off,off+len(q)],sha256=d["sha256"]))
        return used[t]
    def scope_reason(i,r,axis):
        if (i,axis) in proposals and (i,axis) not in chosen:
            return "관련 문서 위치를 찾았으나 독립적으로 제시할 짧은 인용을 확정하지 못함."
        rev=reviews[r["asset_type_id"],r["key"]]
        if axis=="A" and rev["judgement"]["A"] and i not in assetclaims:
            return "제품 역할을 이 유형으로 특정할 원문 표현 또는 같은 문서의 기능 인용이 불충분함."
        if axis=="A" and not rev["evidence"]["role"]:return "이 유형의 제품이라는 근거와 해당 기능의 근거를 같은 제품 범위에서 함께 확인하지 못함."
        if axis=="K" and not rev["evidence"]["key"]:return "대상·방향·상태가 원본 key의 판정 기준에 대응하는 직접 인용을 확인하지 못함."
        return rev["judgement"].get("why"+axis) or ("원문 근거 미확인" if axis=="K" else "제품별 적용 근거 미확인")
    records=[]
    for i,r in enumerate(cats):
        aid,key=r["asset_type_id"],r["key"];rev=reviews[aid,key];k=chosen.get((i,"K"));a=chosen.get((i,"A"))
        origin=next((origin for e,_,origin in keyclaims[signature(r)] if k and token(e)==k[0]),None)
        kwhy=reviews[cats[origin]["asset_type_id"],key]["judgement"].get("whyK","") if k else scope_reason(i,r,"K")
        if k:kwhy=notes.get(k[0],kwhy)
        awhy=rev["judgement"].get("whyA","") if a else scope_reason(i,r,"A")
        if a:awhy=assetnotes.get(i,awhy)
        locations={}
        for ax,opt in (("K",k),("A",a)):
            if not opt and proposals.get((i,ax)):
                locations[ax]=[{"source_id":d,"location":l} for d,l,_,_ in proposals[(i,ax)][0]]
        records.append(dict(asset_type_id=aid,asset_name=r["자산유형"],key=key,question=r["확인항목"],scope=r["확인대상단위"],
                yes=r["o_판정기준"],no=r["x_판정기준"],site_evidence=r["확인자료"],mitre_type=r["MITRE_자산유형출처"],
                key_status="문헌 확인" if k else "미확인",key_reason=kwhy,key_quote=cite(k[0]) if k else None,
                assignment_status="제품 사례 확인" if a else "미확인",assignment_reason=awhy,
                feature_quote=cite(a[0]) if a else None,role_quote=cite(a[1]) if a else None,
                candidate_locations=locations,reviewed_sources=rev["reviewed_docs"],review_id=rev["review_id"]))
    assert len({(r["asset_type_id"],r["key"]) for r in records})==505
    counts=Counter((bool(r["key_quote"]),bool(r["role_quote"])) for r in records)
    summary=dict(rows=len(records),asset_types=len(set(r["asset_type_id"] for r in records)),keys=len(set(r["key"] for r in records)),
                 both=counts[True,True],key_only=counts[True,False],assignment_only=counts[False,True],neither=counts[False,False],
                 key_confirmed=sum(bool(r["key_quote"]) for r in records),assignment_confirmed=sum(bool(r["role_quote"]) for r in records),
                 unique_keys_with_evidence=len({r["key"] for r in records if r["key_quote"]}),sources_indexed=len(docs),
                 cited_sources=len({q["source_id"] for q in register}),quotes=len(register),
                 review_model=MODEL,revision=REVISION,review_date="2026-11-24")
    data=dict(summary=summary,records=records,quotations=register,
              sources=[{k:d.get(k) for k in ("id","title","url","sha256","format")} for d in docs.values()])
    (OUT/"asset_key_evidence.json").write_text(json.dumps(data,ensure_ascii=False,indent=1),encoding="utf8")
    print(json.dumps(summary,ensure_ascii=False))
if __name__=="__main__":main()
