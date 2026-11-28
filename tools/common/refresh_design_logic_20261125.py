"""Revise selected native HWP paragraphs, preserving document styles and objects."""
from pathlib import Path
import hashlib
import json
import shutil
import struct
import olefile
from tools.common.align_design_draft_to_template import read_stream, iter_records, pack_records, write_streams, para_text

ROOT = Path('C:/ICS-VEX')
OUT = ROOT / 'results/design_logic_refresh_20261125'
BACKUP = ROOT / 'docs/archive/design_logic_refresh_20261125'
TARGET = ROOT / '생성형 AI 모델 기반 VEX 자동 생성 시스템 설계서.hwp'

# Paragraph indices come from a complete native BodyText inventory, not PDF text.
REVISIONS = {
  42: '제품 식별은 I1 컴포넌트명 분석, I2 버전·모델 관측 구분, I3 CPE·PURL 원본 근거 확인으로 나눔. 필요한 역할만 조건부 호출하고 서버가 후보 자격과 충돌을 독립 검사함. I3의 후보 선택만으로 CVE 또는 운영 자산의 악용 가능성을 확정하지 않음.',
  54: 'V1 자산 맥락 식별: 제품·버전과 CVE 연결만으로 알 수 없는 자산의 기능과 역할을 ICSA 제품 근거로 식별함. 자산 유형 후보·분류 근거·자산 운영 정보 항목과 불확실성을 제공함. 같은 자산 유형이라는 이유로 악용 조건이나 자산 운영 정보를 공유하지 않음.',
  55: 'V2 악용 전제조건 구조화: 비정형 CVE·ICSA 원문에서 대상·경로·권한·설정 조건을 추출함. 제품 범위, 원문 인용, 필요성 및 AND·OR·NOT 관계를 구조화함. 원문에 없는 조건·충분성은 만들지 않고 미확인 사항을 보존함.',
  56: 'V3 자산 운영 정보·조건 연결: V1의 자산 운영 정보 항목과 V2의 조건을 연결해 운영자에게 확인할 질문을 구성함. 자산 목록·설정·접근 규칙·점검 기록에서 확인한 답변을 해당 컴포넌트·CVE·대상·평가 범위에 연결함. 누락·충돌·미확인은 unknown으로 남기며 운영자 진술과 독립 검증된 증거를 구분함.',
  57: 'V4 악용 가능성 평가·VEX 생성: 조건 논리와 자산 운영 정보 값을 결합해 명시적 정책으로 최종 상태를 결정함. 제품 VEX 상태와 배포 환경의 악용 가능성을 분리하고 결정 이유·사용 근거·미해결 사항을 기록함. 공급사 수정 근거와 실제 실행 버전이 확인되어야 fixed로 판단함.',
  58: 'V1~V4는 VEX 생성에 필요한 문제별 책임을 갖는 논리적 에이전트임. 각 역할이 독립 LLM 인스턴스 한 개와 일대일로 대응하지 않음. 현재 V3에는 자산 운영 정보 입력·연결 절차가, V4에는 결정론적 평가·출력 로직이 포함됨. 역할 분해만으로 정확도 향상을 입증하지 않음.',
  76: '운영 분석은 BOM 컴포넌트×CVE를 단위로 수행함. V1은 자산 맥락 부재, V2는 악용 조건의 비정형성, V3는 공개 조건과 자산 운영 정보의 단절, V4는 상태 결정과 근거 추적 문제를 담당함. 각 단계 산출물을 연결하여 정보 부족과 오류 발생 단계를 구분함.',
  88: 'F-04 자산 맥락 식별: V1은 제품별 권고문으로 자산 유형 후보와 분류 근거·불확실성을 기록하고, 운영자가 확인할 자산 속성의 범위를 정해야 함.',
  89: 'F-05 악용 전제조건 구조화: V2는 제품·경로별 조건과 필요성·논리 관계·원문 근거를 기록하고, 근거가 부족한 조건이나 관계를 미확인으로 보존해야 함.',
  90: 'F-06 자산 운영 정보·조건 연결: V3는 운영자에게 확인 가능한 질문을 제공하고, 답변과 근거를 해당 컴포넌트·조건·범위에 연결해야 함. 누락·충돌·미확인 값을 false로 바꾸지 않아야 함.',
  116: '제품 식별에는 I1 컴포넌트명, I2 버전·모델 관측, I3 CPE·PURL 근거 확인을 사용함. VEX 생성에는 V1 자산 맥락 식별, V2 악용 전제조건 구조화, V3 자산 운영 정보·조건 연결, V4 악용 가능성 평가·VEX 생성을 사용함. 식별과 운영환경 판단의 책임을 구분함.',
  133: 'V1은 자산 역할과 확인 속성의 범위를, V2는 제품·경로별 악용 전제조건을 제공함. V3는 자산 운영 정보를 조건과 평가 범위에 연결하고 V4는 상태 결정·근거 추적·VEX 출력을 담당함. extract·review·mapping·routing은 별도 평가의 모델 호출 역할이며 V1~V4와 구분함.',
  183: '2.3.7 V1의 자산 맥락 식별',
  185: 'V1은 제품·버전·CVE 식별만으로 부족한 자산의 기능과 자산 운영 정보를 보완함. 제품에 연결된 ICSA 근거로 18개 자산 유형 후보와 확인할 자산 운영 정보 항목을 정함. 권고문 전체의 분류를 다른 제품의 확정 분류로 승격하지 않음.',
  186: '산출물은 자산 유형 후보, 제품 연결 근거, 적용할 자산 운영 정보 항목과 분류 불확실성임. 자료가 부족하거나 후보가 충돌하면 미확정으로 남기고 사용자 확인을 받음.',
  188: '2.3.8 V2의 악용 전제조건 구조화',
  191: '원문에서 행위자·대상·상태·접근 경로·권한·기능 설정 및 조건의 필요성을 추출함. 제품·버전·시나리오 범위와 원문 인용을 보존함. 운영자가 확인하기 어려운 내부 조건과 충분성이 불명확한 진술은 미확인으로 남김.',
  193: '원문이 관계를 명시한 같은 제품·경로 범위에서만 AND·OR·NOT을 구성함. 필요조건 충족을 충분한 공격 경로로 확대하지 않음. 부정은 긍정 원자 사실과 NOT 연산으로 구분하고, 관계가 불명확하면 임의로 연결하지 않음.',
  196: '2.3.9 V3의 자산 운영 정보·조건 연결',
  200: 'V3는 V1의 자산 속성과 V2의 조건을 바탕으로 필요한 자산 운영 정보를 질문함. 조건과 질문의 대상·범위·요구값이 일치할 때만 연결하며, 해당 자산의 다른 서비스나 다른 컴포넌트 값을 대신 사용하지 않음.',
  205: '산출물은 운영자 답변과 출처, 조건별 true·false·unknown, 대상·범위 연결 및 누락·충돌 정보임. 현재 화면의 답변은 운영자 진술이며 독립적인 운영 기록 검증 완료로 표시하지 않음.',
  227: 'not_affected: 현재 단일 자산·구성과 연결된 컴포넌트의 미배포를 명시적으로 완전한 인벤토리로 확인했거나, 공급사 자료가 확인된 실제 실행 버전을 비영향으로 명시한 경우에 부여함.',
  229: '미설치 답변만으로는 비영향을 확정하지 않음. 인벤토리 범위가 partial·unknown이면 보류함. 알려진 경로 차단도 제품 전체 비영향의 근거가 아니며, 다른 경로 전체를 배제했다고 추정하지 않음.',
  230: '먼저 현재 단일 자산·구성, 컴포넌트 참조와 완전한 인벤토리의 부재 근거를 확인함. 실행 중인 제품은 정확 실행 버전·공급사 연결을 확인함. 수정·비영향의 직접 근거와 취약 경로 분석의 요건을 구분함.',
  257: 'VERTICES.CSV·ARCS.CSV의 노드·연결을 입력 규칙과 대조함. 취약 경로 판정에는 완료된 그래프가 필요하며 미완성은 보류함. 완전한 인벤토리의 미배포 또는 실행 빌드의 공급사 수정·비영향 직접 근거는 그래프 없이 별도 판단함.',
  283: '현재 단일 자산·구성과 명시적으로 완전한 인벤토리에서 해당 컴포넌트의 부재가 확인되면 not_affected임. 실행 중이면 BOM과 일치하는 구체적 실행 버전과 공급사 제품 연결을 확인하여 수정은 fixed, 명시적 비영향은 not_affected로 판단함.',
  293: '현재 범위의 완전한 인벤토리로 미배포 확인 또는 실제 실행 버전의 공급사 명시적 비영향 근거',
  353: '제품 식별 런타임은 data/identification_runtime.json의 precision_shared_14b_v1 설정과 지정 모델·어댑터를 사용함. I1·I2·I3는 역할별 입력·JSON 계약을 적용함. 조건 추출은 별도 역할 설정을 따르며 고정 기본 모델과 학습 파일의 해시·실제 호출 정보를 기록함.',
  374: '현재 조건 추출은 enabled=true, evaluation_passed=false 및 명시적 사용 승인에 따른 평가 게이트 예외를 기록함. 어댑터는 D:/ICS-VEX-support/models의 역할별 설정 경로를 따름. 활성화·학습 완료·평가 통과는 서로 다른 상태이며 실행 사실을 정확도 입증으로 표현하지 않음.',
  380: 'V1과 V2는 병렬로 자산 맥락과 악용 조건을 분석함. V3는 두 결과로 질문을 구성하고 자산 운영 정보를 해당 조건·대상·범위에 연결함. V4는 동일 입력 스냅샷에 명시적 결정 정책을 적용하고 근거·미해결 사항과 VEX를 생성함.',
  385: 'V1 자산 맥락 식별',
  388: 'V2 악용 전제조건 구조화',
  391: 'V3 자산 운영 정보·조건 연결',
  394: 'V4 악용 가능성 평가·VEX 생성',
  449: '공급사 근거로 vulnerable·fixed·unaffected·unknown을 구분함. 영향 범위 밖이라는 이유로 수정·비영향을 추정하지 않음. 실행 중이면 구체적 단일 버전과 BOM 일치를 확인함. 미배포는 현재 단일 범위·컴포넌트·명시적 완전 인벤토리를 별도로 확인함.',
  461: '현재 단일 자산·구성과 컴포넌트 연결. 경로 평가에는 운전 상태·출발점·자산 분류도 확인',
  462: '미배포·공급사 직접 근거와 취약 경로 평가의 요건을 구분',
  464: '미배포이면 명시적 인벤토리 완전성, 실행 중이면 정확 버전과 BOM 일치',
  465: '누락된 완전성·범위 또는 실행 버전 불일치는 보류',
  469: '5. 경로 분석',
  470: '취약 버전의 제품·조건 연결과 MulVAL 그래프 완료',
  471: '미배포·수정·명시적 비영향의 직접 판단에는 그래프 불필요',
  472: '현재 단일 범위와 컴포넌트가 확인되고 완전한 인벤토리가 미배포를 명시하면 not_affected임. 실행 제품·정확 버전이 공급사 기준에 연결되면 fixed 또는 not_affected임. 그 외 취약·원문 경로가 연결되고 운영 범위·분류·그래프가 유효하며 경로가 성립하면 affected임. 나머지는 보류함.',
  491: '공급사 수정 기준에 맞는 정확 실행 버전·배포·제품 연결이 확인되면 그래프 생성 없이 fixed로 판단함. 완전한 현재 인벤토리로 미배포가 확인될 때도 그래프는 불필요함. 자산 운영 정보 입력의 출처를 보존하며 독립 검증된 사실로 승격하지 않음.',
  512: 'OpenVEX는 취약점·제품 ID·상태·설명을 기록함. CycloneDX는 평가한 단일 컴포넌트와 범위가 일치하는 취약점 항목만 갱신함. 여러 대상을 포함하거나 버전 조건이 붙은 기존 선언은 보존하고 해당 컴포넌트의 결과를 별도 기록함. 상세 근거는 검토 보고서에 보관함.',
  517: '원문 조건은 조건 ID·source_refs로, 질문은 조건·컴포넌트·CVE·scope_id로 연결함. answers에는 조건 응답을, context_answers에는 범위·대상·배포·인벤토리 완전성·실행 버전을 기록함. 평가에는 입력 revision·해시와 당시 추출 어댑터·평가 상태를 보존함.',
  552: 'I2 이후 사전 재조회와 충돌 검사를 수행하되 I1 응답·순위 기록은 그대로 보존함. 새로 발견된 경쟁 후보는 재검증에 반영하며 원래 I1이 허용한 선택 범위를 임의 확장하지 않음. identification 범위의 CVE 연결은 운영 자산의 악용 가능성 판단과 구분함.',
}

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    BACKUP.mkdir(parents=True, exist_ok=True)
    original = BACKUP / TARGET.name
    if not original.exists():
        shutil.copy2(TARGET, original)
    draft = OUT / TARGET.name
    shutil.copy2(original, draft)
    inventory = []
    with olefile.OleFileIO(original) as ole:
        sections = sorted('/'.join(s) for s in ole.listdir() if s[0] == 'BodyText')
    streams = {}; changes = []; number = 0
    for section in sections:
        records = list(iter_records(read_stream(original, section)))
        for i, (tag, level, payload) in enumerate(records):
            if tag != 67: continue
            old = para_text(payload)
            new = REVISIONS.get(number)
            if old == '2026. 11. 20.': new = '2026. 11. 25.'
            inventory.append(dict(index=number, text=old))
            number += 1
            if new is None: continue
            # Selected paragraphs are plain editable text without embedded controls.
            raw = payload.decode('utf-16le')
            assert all(ord(c) >= 32 or c in '\r\n' for c in raw), (number-1, repr(raw))
            assert records[i-1][0] == 66, (number-1, 'missing paragraph header')
            head = bytearray(records[i-1][2])
            replacement = (new + '\r').encode('utf-16le')
            flags = struct.unpack_from('<I', head)[0] & 0x80000000
            struct.pack_into('<I', head, 0, flags | (len(replacement)//2))
            # Keep style identifiers, refresh run/line counts after replacing text.
            struct.pack_into('<H', head, 12, 1)
            struct.pack_into('<H', head, 16, 0)
            records[i-1] = (66, records[i-1][1], bytes(head))
            records[i] = (tag, level, replacement)
            j = i+1
            while j < len(records) and records[j][0] != 66:
                t,l,p = records[j]
                if t == 68: records[j] = (t,l,p[:8])
                elif t == 69: records[j] = (-1,l,b'')
                j += 1
            changes.append(dict(index=number-1, old=old, new=new))
        streams[section] = pack_records([r for r in records if r[0] != -1])
    assert len(changes) == len(REVISIONS)+1, len(changes)
    write_streams(draft, streams)
    # Refresh native preview; all rich content and embedded pictures remain intact.
    preview='\r\n'.join(next((c['new'] for c in changes if c['index']==r['index']),r['text']) for r in inventory)
    write_streams(draft, {'PrvText':preview.encode('utf-16le')}, compressed=False)
    with olefile.OleFileIO(original) as a, olefile.OleFileIO(draft) as b:
        unchanged=[s for s in a.listdir() if s[0] not in ('BodyText','PrvText')]
        assert all(a.openstream(s).read()==b.openstream(s).read() for s in unchanged)
    check=[]
    for s in sections:
        check.extend(para_text(p) for t,l,p in iter_records(read_stream(draft,s)) if t==67)
    assert len(check)==number
    for c in changes: assert check[c['index']]==c['new']
    manifest=dict(source=str(TARGET),backup=str(original),draft=str(draft),
        original_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
        revised_sha256=hashlib.sha256(draft.read_bytes()).hexdigest(),
        paragraphs=number,changes=changes,styles_and_objects_preserved=True,
        owning_sources=['src/item3/agents/evidence_review_agents.py',
          'src/item3/matching/identification_pipeline.py',
          'src/item4/decision/asset_vex_assessment.py',
          'src/item4/decision/inventory_evidence_policy.py',
          'src/item4/workflow/source_analysis_jobs.py',
          'data/prerequisite_adapter_roles.json','README.md'])
    (OUT/'changes.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in manifest.items() if k!='changes'},ensure_ascii=False,indent=2))

if __name__ == '__main__': main()
