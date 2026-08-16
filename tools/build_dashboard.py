#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""대시보드 HTML 생성: 평가 결과 뷰 + 대화형 SBOM->CVE 분석기 (KB 내장, self-contained)."""
import json, os, sys
sys.stdout.reconfigure(encoding="utf-8")
BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
R = os.path.join(BASE, "results")
KB = json.load(open(os.path.join(R, "cve_kb.json"), encoding="utf-8"))
EX = json.load(open(os.path.join(R, "example_sbom.json"), encoding="utf-8"))
DASH = json.load(open(os.path.join(R, "dashboard_data.json"), encoding="utf-8"))
TM = json.load(open(os.path.join(R, "two_model_metrics.json"), encoding="utf-8"))
CB = json.load(open(os.path.join(R, "codebert_metrics.json"), encoding="utf-8"))

# 대시보드 평가 데이터(요약)
o = DASH["overall"]
DATA = {
  "provenance": DASH["provenance"],
  "overall": {"macro_f1": round(o["macro_f1"],4), "ece": round(o["ece"],4),
              "under_rate": round(o["under_investigation_rate"],4),
              "wrong_na": o["wrong_not_affected_count"],
              "confusion_matrix": o["confusion_matrix"],
              "per_class": {k: {kk: round(vv,4) if isinstance(vv,float) else vv
                                for kk,vv in v.items()} for k,v in o["per_class"].items()}},
  "rationale": {"suff": round(DASH["rationale"]["sufficiency_drop"],4),
                "comp": round(DASH["rationale"]["comprehensiveness_drop"],4)},
  "baseline": round(DASH["baseline"],4),
  "perarm": DASH["perarm"], "labels": DASH["labels"],
  "runtime": DASH["runtime"], "device": DASH["device"],
  "two_model": {
      "codebert_standalone_acc": round(CB["accuracy_mean"], 3),
      "ref_match_perturbed": TM["A_reference_matching"]["perturbed_match_acc"],
      "ref_match_n": TM["A_reference_matching"]["n"],
      "bp_injected": TM["B_backport_detection"]["backport_injected"],
      "bp_caught": TM["B_backport_detection"]["backport_caught_by_codebert"],
      "ctx_acc": TM["B_backport_detection"]["context_only_acc"],
      "two_acc": TM["B_backport_detection"]["two_model_acc"],
      "ctx_fp": TM["B_backport_detection"]["context_only_backport_falsepos"],
      "two_fp": TM["B_backport_detection"]["two_model_backport_falsepos"],
      "code_cves": TM["A_reference_matching"]["n"] // 2,
      "unavail": TM["C_closed_code_routing"]["routed_to_under_investigation"],
      "total": TM["C_closed_code_routing"]["total_findings"],
  },
  "samples": [{"cve":"CVE-2012-4704","device":"CODESYS Gateway Server","status":"LIKELY_AFFECTED","conf":0.933,"oracle":"LIKELY_AFFECTED","rationale":["The weakness is driven through network messages accepted by an exposed interface.","The unit is reachable remotely, including through vendor remote-support tunnels."]},
              {"cve":"CVE-2012-4705","device":"CODESYS Gateway Server","status":"UNDER_INVESTIGATION","conf":0.946,"oracle":"UNDER_INVESTIGATION","rationale":["The prerequisites an attacker would need here are not established in the evidence.","The unit is reachable remotely, including through vendor remote-support tunnels."]},
              {"cve":"CVE-2019-9013","device":"CODESYS V3 Runtime","status":"LIKELY_NOT_AFFECTED","conf":0.944,"oracle":"LIKELY_NOT_AFFECTED","rationale":["The path opens only to an adjacent station on the same physical network.","The unit operates islanded, with no IP path in from plant or enterprise networks."]},
              {"cve":"CVE-2012-4708","device":"CODESYS Gateway Server","status":"LIKELY_AFFECTED","conf":0.933,"oracle":"UNDER_INVESTIGATION","rationale":["The weakness is driven through network messages accepted by an exposed interface.","The unit is reachable remotely, including through vendor remote-support tunnels."]}],
}

HTML = r"""<title>ICS-VEX Analyzer &amp; Panel</title>
<style>
  :root{
    --ground:#e9edf1;--surface:#ffffff;--surface-2:#f1f5f8;--raise:#fbfcfd;
    --ink:#111a20;--ink-2:#4b5a64;--ink-3:#7c8b95;--line:#d4dde4;
    --accent:#0c7c8a;--accent-2:#0a626d;
    --affected:#bd3b2c;--affected-bg:#f8e6e3;--safe:#1c8551;--safe-bg:#e2f2ea;
    --under:#b07d16;--under-bg:#f6ecd6;
    --shadow:0 1px 2px rgba(16,26,32,.06),0 6px 20px rgba(16,26,32,.05);
    --mono:ui-monospace,"Cascadia Code","JetBrains Mono",Consolas,monospace;
    --sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;
  }
  @media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
    --ground:#0b1116;--surface:#111a20;--surface-2:#16222a;--raise:#1a2831;
    --ink:#e6edf2;--ink-2:#93a3ad;--ink-3:#657580;--line:#25333c;
    --accent:#38ccd9;--accent-2:#2aa7b3;
    --affected:#e5675c;--affected-bg:#2a1613;--safe:#43be7c;--safe-bg:#0f2419;
    --under:#e0b24c;--under-bg:#271f0d;
    --shadow:0 1px 2px rgba(0,0,0,.3),0 8px 26px rgba(0,0,0,.35);
  }}
  :root[data-theme="dark"]{
    --ground:#0b1116;--surface:#111a20;--surface-2:#16222a;--raise:#1a2831;
    --ink:#e6edf2;--ink-2:#93a3ad;--ink-3:#657580;--line:#25333c;
    --accent:#38ccd9;--accent-2:#2aa7b3;
    --affected:#e5675c;--affected-bg:#2a1613;--safe:#43be7c;--safe-bg:#0f2419;
    --under:#e0b24c;--under-bg:#271f0d;
    --shadow:0 1px 2px rgba(0,0,0,.3),0 8px 26px rgba(0,0,0,.35);
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--ground);color:var(--ink);font-family:var(--sans);line-height:1.5;-webkit-font-smoothing:antialiased}
  .wrap{max-width:1120px;margin:0 auto;padding:32px 22px 64px}
  .eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--accent);font-weight:600}
  h1{font-size:clamp(26px,4vw,38px);line-height:1.08;margin:.28em 0 .1em;letter-spacing:-.02em;text-wrap:balance;font-weight:680}
  .sub{color:var(--ink-2);max-width:60ch;font-size:15px}
  .chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}
  .chip{font-family:var(--mono);font-size:12px;padding:5px 10px;border:1px solid var(--line);border-radius:6px;background:var(--surface);color:var(--ink-2);white-space:nowrap}
  .chip b{color:var(--ink);font-weight:600}.chip .dot{color:var(--accent)}
  .banner{display:flex;gap:12px;align-items:flex-start;background:var(--under-bg);border:1px solid color-mix(in srgb,var(--under) 40%,transparent);border-radius:10px;padding:14px 16px;margin:22px 0 8px;font-size:13.5px;color:var(--ink)}
  .banner .k{font-family:var(--mono);font-weight:700;color:var(--under);text-transform:uppercase;letter-spacing:.08em;font-size:11px;padding-top:2px;white-space:nowrap}
  section{margin-top:34px}
  .sec-h{display:flex;align-items:baseline;gap:12px;margin-bottom:14px;flex-wrap:wrap}
  .sec-h h2{font-size:16px;margin:0;letter-spacing:-.01em;font-weight:640}
  .sec-h .n{font-family:var(--mono);font-size:11px;color:var(--ink-3)}
  .card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:18px;box-shadow:var(--shadow)}
  .card h3{margin:0 0 3px;font-size:13.5px;font-weight:620}.card .hint{font-size:12px;color:var(--ink-3);margin:0 0 14px}
  /* analyzer */
  .analyzer{border:1px solid color-mix(in srgb,var(--accent) 35%,var(--line));box-shadow:0 0 0 1px color-mix(in srgb,var(--accent) 8%,transparent),var(--shadow)}
  .an-io{display:grid;grid-template-columns:1fr;gap:12px}
  .drop{border:1.5px dashed color-mix(in srgb,var(--accent) 40%,var(--line));border-radius:10px;padding:18px;text-align:center;background:var(--surface-2);cursor:pointer;transition:background .15s,border-color .15s}
  .drop:hover,.drop.over{background:color-mix(in srgb,var(--accent) 8%,var(--surface-2));border-color:var(--accent)}
  .drop .big{font-family:var(--mono);font-size:13px;color:var(--ink);font-weight:600}
  .drop .small{font-size:12px;color:var(--ink-3);margin-top:4px}
  textarea{width:100%;min-height:96px;background:var(--surface-2);color:var(--ink);border:1px solid var(--line);border-radius:9px;padding:11px;font-family:var(--mono);font-size:12px;resize:vertical}
  textarea:focus,select:focus,button:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
  .controls{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:4px}
  .controls .grp{display:flex;align-items:center;gap:7px;font-size:12.5px;color:var(--ink-2)}
  select{font-family:var(--mono);font-size:12.5px;padding:7px 9px;border-radius:8px;border:1px solid var(--line);background:var(--surface);color:var(--ink)}
  button{font-family:var(--sans);font-size:13px;font-weight:600;padding:9px 16px;border-radius:8px;border:1px solid transparent;cursor:pointer}
  .btn-primary{background:var(--accent);color:#fff}.btn-primary:hover{background:var(--accent-2)}
  .btn-ghost{background:var(--surface);color:var(--accent);border-color:color-mix(in srgb,var(--accent) 45%,var(--line))}
  .btn-ghost:hover{background:color-mix(in srgb,var(--accent) 8%,var(--surface))}
  .an-result{margin-top:18px}
  .an-summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:16px}
  .stile{background:var(--surface-2);border-radius:10px;padding:12px 14px;border:1px solid var(--line)}
  .stile .v{font-family:var(--mono);font-size:26px;font-weight:600;font-variant-numeric:tabular-nums;line-height:1}
  .stile .l{font-size:11.5px;color:var(--ink-2);margin-top:5px}
  .comp{border:1px solid var(--line);border-radius:11px;margin-bottom:11px;overflow:hidden}
  .comp .ch{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:11px 14px;background:var(--surface-2);flex-wrap:wrap}
  .comp .cn{font-family:var(--mono);font-size:13px;font-weight:600}
  .comp .cv{font-family:var(--mono);font-size:11.5px;color:var(--ink-3)}
  .comp .cc{font-family:var(--mono);font-size:11px;padding:3px 9px;border-radius:20px;font-weight:600}
  .cvelist{padding:4px 14px 12px}
  .cverow{display:grid;grid-template-columns:118px 1fr auto;gap:10px;align-items:center;padding:8px 0;border-top:1px solid var(--line);font-size:12.5px}
  .cverow:first-child{border-top:0}
  .cverow .id{font-family:var(--mono);font-weight:600}
  .cverow .tags{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
  .tag{font-family:var(--mono);font-size:10px;padding:2px 7px;border-radius:5px;background:var(--surface-2);color:var(--ink-2);border:1px solid var(--line)}
  .tag.sev-critical{background:var(--affected-bg);color:var(--affected);border-color:transparent}
  .tag.sev-high{background:color-mix(in srgb,var(--affected) 14%,transparent);color:var(--affected);border-color:transparent}
  .tag.kev{background:var(--affected);color:#fff;border-color:transparent}
  .pill{font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.02em;padding:4px 9px;border-radius:20px;white-space:nowrap;text-transform:uppercase}
  .pill.LIKELY_AFFECTED{background:var(--affected-bg);color:var(--affected)}
  .pill.LIKELY_NOT_AFFECTED{background:var(--safe-bg);color:var(--safe)}
  .pill.UNDER_INVESTIGATION{background:var(--under-bg);color:var(--under)}
  .empty{color:var(--ink-3);font-size:13px;text-align:center;padding:20px}
  .an-note{font-size:11.5px;color:var(--ink-3);margin-top:10px}
  /* kpi */
  .kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
  @media(max-width:720px){.kpis{grid-template-columns:repeat(2,1fr)}}
  .kpi{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px;box-shadow:var(--shadow);position:relative;overflow:hidden}
  .kpi .lab{font-size:11.5px;color:var(--ink-2);letter-spacing:.03em;text-transform:uppercase;font-weight:600}
  .kpi .val{font-family:var(--mono);font-size:34px;font-weight:600;letter-spacing:-.02em;margin-top:6px;font-variant-numeric:tabular-nums;line-height:1}
  .kpi .cap{font-size:12px;color:var(--ink-3);margin-top:6px}
  .kpi.safety{background:linear-gradient(180deg,var(--safe-bg),var(--surface))}
  .kpi.safety .val{color:var(--safe)}
  .kpi.safety::after{content:"";position:absolute;top:0;left:0;width:4px;height:100%;background:var(--safe)}
  .kpi .delta{color:var(--safe);font-family:var(--mono);font-size:12px}
  .grid2{display:grid;grid-template-columns:1.05fr .95fr;gap:18px}
  @media(max-width:860px){.grid2{grid-template-columns:1fr}}
  .cm{display:grid;grid-template-columns:auto repeat(3,1fr);gap:5px;font-family:var(--mono);font-variant-numeric:tabular-nums}
  .cm .h{font-size:10.5px;color:var(--ink-3);display:flex;align-items:center;justify-content:center;text-align:center;padding:2px}
  .cm .rh{font-size:10.5px;color:var(--ink-3);display:flex;align-items:center;justify-content:flex-end;padding-right:6px;text-align:right}
  .cm .cell{aspect-ratio:1.9/1;border-radius:7px;display:flex;flex-direction:column;align-items:center;justify-content:center;font-size:18px;font-weight:600;color:var(--ink);border:1px solid var(--line)}
  .cm .cell small{font-size:9px;color:var(--ink-3);font-weight:400;margin-top:1px}
  .cm .diag{outline:2px solid color-mix(in srgb,var(--accent) 55%,transparent);outline-offset:-2px}
  .cm .zero-safe{background:var(--safe-bg)!important;color:var(--safe);border-color:var(--safe)}
  .legend{display:flex;gap:14px;margin-top:12px;font-size:11.5px;color:var(--ink-2);flex-wrap:wrap}
  .legend span{display:flex;align-items:center;gap:6px}.sw{width:11px;height:11px;border-radius:3px;display:inline-block}
  .bars{display:flex;flex-direction:column;gap:13px}
  .bar-row{display:grid;grid-template-columns:140px 1fr;gap:10px;align-items:center}
  .bar-row .nm{font-size:12px;color:var(--ink-2)}
  .track{background:var(--surface-2);border-radius:5px;height:22px;overflow:hidden}
  .fill{height:100%;border-radius:5px;display:flex;align-items:center;justify-content:flex-end;padding-right:8px;font-family:var(--mono);font-size:11.5px;color:#fff;font-weight:600}
  .stat-line{display:flex;gap:6px;margin-top:3px}
  .stat-line .m{flex:1;text-align:center;font-family:var(--mono);font-size:11px;padding:5px 0;border-radius:5px;background:var(--surface-2);color:var(--ink-2)}
  .stat-line .m b{color:var(--ink);font-weight:600;display:block;font-size:13px}
  .rmet{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .rmet .box{background:var(--surface-2);border-radius:9px;padding:13px}
  .rmet .box .v{font-family:var(--mono);font-size:26px;font-weight:600}
  .rmet .box .l{font-size:11.5px;color:var(--ink-2);margin-top:3px}.rmet .box .d{font-size:11px;color:var(--ink-3);margin-top:6px}
  .samples{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  @media(max-width:760px){.samples{grid-template-columns:1fr}}
  .svex{border:1px solid var(--line);border-radius:11px;padding:14px 15px;background:var(--surface)}
  .svex .top{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:9px}
  .cve{font-family:var(--mono);font-size:13px;font-weight:600}
  .svex .dev{font-family:var(--mono);font-size:11px;color:var(--ink-3);margin-bottom:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .rats{display:flex;flex-direction:column;gap:6px}
  .rat{display:flex;gap:8px;font-size:12.5px;color:var(--ink-2);line-height:1.4}
  .rat .eid{font-family:var(--mono);font-size:10px;color:var(--accent);padding-top:2px;flex-shrink:0}
  .svex .meta{display:flex;justify-content:space-between;margin-top:11px;padding-top:10px;border-top:1px solid var(--line);font-family:var(--mono);font-size:11px;color:var(--ink-3)}
  .svex .meta b{color:var(--ink-2)}.match{color:var(--safe)}.miss{color:var(--under)}
  .ychart{display:flex;align-items:flex-end;gap:3px;height:120px;margin-top:6px}
  .ycol{flex:1;height:100%;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;gap:5px;min-width:0}
  .ycol .b{width:100%;background:var(--accent);border-radius:3px 3px 0 0;opacity:.85}
  .ycol:hover .b{opacity:1}
  .ycol .y{font-family:var(--mono);font-size:8.5px;color:var(--ink-3)}
  footer{margin-top:40px;padding-top:20px;border-top:1px solid var(--line);font-size:12px;color:var(--ink-3)}
  .pipe{font-family:var(--mono);color:var(--ink-2);font-size:11.5px;display:flex;flex-wrap:wrap;gap:6px;align-items:center}
  .pipe .s{color:var(--accent)}
</style>

<div class="wrap">
  <header>
    <div class="eyebrow">Explainable ICS VEX &middot; SecureBERT / CodeBERT</div>
    <h1>SBOM 취약점 분석기 &amp; 평가 계기판</h1>
    <p class="sub">CycloneDX SBOM을 올리면 컴포넌트를 CVE와 대조해 배치맥락 기반 VEX 판정을 즉시 산출한다.
      아래에는 이 판정 시스템의 실측 평가 결과를 함께 싣는다.</p>
    <div class="chips" id="chips"></div>
  </header>

  <div class="banner">
    <span class="k">Note</span>
    <span>분석기는 <b>내장 CVE 지식베이스</b>(주요 OSS 42종·303 CVE, 실측 CVSS/KEV/EPSS)로 브라우저 안에서만 동작한다.
      평가 수치는 규칙 오라클 기반 <b>silver GT</b> 위에서 측정된 값으로, 실세계 정확도가 아니라 파이프라인·학습가능성 검증이다.</span>
  </div>

  <section>
    <div class="sec-h"><h2>SBOM &rarr; CVE &rarr; VEX 분석기</h2><span class="n">CycloneDX 1.x &middot; 브라우저 내 처리</span></div>
    <div class="card analyzer">
      <div class="an-io">
        <div class="drop" id="drop">
          <div class="big">SBOM 파일을 여기에 드롭하거나 클릭해 선택</div>
          <div class="small">CycloneDX JSON (.json) &middot; 파일은 업로드되지 않고 브라우저에서만 처리됩니다</div>
          <input type="file" id="file" accept=".json,application/json" hidden>
        </div>
        <textarea id="paste" placeholder="또는 CycloneDX JSON을 여기에 붙여넣기…"></textarea>
        <div class="controls">
          <button class="btn-primary" id="analyze">분석</button>
          <button class="btn-ghost" id="loadex">예시 SBOM 불러오기</button>
          <div class="grp">배치 노출도
            <select id="exposure">
              <option value="isolated-cell">격리 셀 (air-gap)</option>
              <option value="control-network" selected>제어망</option>
              <option value="dmz-routable">DMZ 라우팅</option>
              <option value="remote-accessible">원격 접근</option>
            </select>
          </div>
        </div>
      </div>
      <div class="an-result" id="anres"><div class="empty">SBOM을 입력하면 컴포넌트별 CVE와 VEX 판정이 여기에 표시됩니다.</div></div>
      <div class="an-note">VEX 판정: CVE의 Attack Vector와 선택한 배치 노출도로 도달성을 계산 →
        도달 가능+취약버전 = <b>영향 가능</b>, 도달 불가 = <b>비영향</b>, 조건부 = <b>조사 필요</b>.
        버전이 취약 범위 밖이면 CVE 미탐(예: zlib 1.2.13).</div>
    </div>
  </section>

  <section>
    <div class="sec-h"><h2>시스템 평가 결과</h2><span class="n">SecureBERT &middot; test n=2,117 &middot; device-disjoint</span></div>
    <div class="kpis" id="kpis"></div>
  </section>

  <section>
    <div class="grid2">
      <div class="card">
        <h3>Confusion Matrix</h3>
        <p class="hint">행 = 정답, 열 = 예측. 대각선(정답) 강조, 안전 임계 셀(영향→비영향) 초록.</p>
        <div class="cm" id="cm"></div>
        <div class="legend">
          <span><i class="sw" style="background:var(--safe)"></i>영향→비영향 오판 = 0</span>
          <span><i class="sw" style="background:color-mix(in srgb,var(--accent) 30%,transparent)"></i>대각선</span>
        </div>
      </div>
      <div class="card">
        <h3>클래스별 P / R / F1</h3><p class="hint">각 VEX 상태의 정밀도·재현율·F1.</p>
        <div class="bars" id="perclass"></div>
      </div>
    </div>
  </section>

  <section>
    <div class="grid2">
      <div class="card">
        <h3>Arm별 성능</h3><p class="hint">OSS-arm(동적 재현) vs 벤더맥락-arm(폐쇄). Macro F1.</p>
        <div class="bars" id="perarm"></div>
        <div class="legend"><span>두 arm 모두 영향→비영향 오판 0건</span></div>
      </div>
      <div class="card">
        <h3>근거(Rationale) 충실도</h3><p class="hint">선택 근거가 실제 예측 원인인지 입력 제거로 검증.</p>
        <div class="rmet" id="rmet"></div>
      </div>
    </div>
  </section>

  <section>
    <div class="sec-h"><h2>2-모델 결합 (SecureBERT + CodeBERT)</h2><span class="n">맥락 leg + 코드 leg</span></div>
    <div class="grid2">
      <div class="card">
        <h3>CodeBERT 코드 leg — 정직한 두 얼굴</h3>
        <p class="hint">추상적 취약성 판단은 실패, 레퍼런스 매칭은 작동.</p>
        <div class="rmet" id="tm_code"></div>
      </div>
      <div class="card">
        <h3>백포트 오탐 탐지</h3>
        <p class="hint">버전은 취약하나 코드가 패치된 케이스를 CodeBERT가 바로잡음.</p>
        <div id="tm_bp"></div>
      </div>
    </div>
    <div class="banner" style="margin-top:16px;background:var(--surface-2);border-color:var(--line)">
      <span class="k" style="color:var(--accent)">한계</span>
      <span id="tm_note"></span>
    </div>
  </section>

  <section>
    <div class="sec-h"><h2>설명가능 VEX 출력</h2><span class="n">각 판정에 근거 문장 부착</span></div>
    <div class="samples" id="samples"></div>
  </section>

  <section>
    <div class="card">
      <h3>데이터 출처 &middot; CISA ICS 어드바이저리 (2010–2026)</h3>
      <p class="hint">연도별 CVE 보유 어드바이저리 수. 전량 실데이터 크롤.</p>
      <div class="ychart" id="ychart"></div>
    </div>
  </section>

  <footer>
    <div class="pipe" id="pipe"></div>
    <p style="margin-top:12px">모델: SecureBERT 문장-어텐션 멀티태스크 + 보수적 Decision Engine.
      학습·평가 <span id="rt"></span> on <span id="dev"></span>.</p>
  </footer>
</div>

<script>
const D = __DATA__;
const KB = __KB__;
const EXAMPLE = __EXAMPLE__;
const LAB={LIKELY_AFFECTED:"영향 가능",LIKELY_NOT_AFFECTED:"비영향",UNDER_INVESTIGATION:"조사 필요"};
const SC={LIKELY_AFFECTED:"var(--affected)",LIKELY_NOT_AFFECTED:"var(--safe)",UNDER_INVESTIGATION:"var(--under)"};
const $=(s)=>document.querySelector(s);

/* ---------- 분석기: KB 인덱스 ---------- */
const IDX=new Map();
function key(){return Array.from(arguments).join("||").toLowerCase();}
for(const c of KB.components){
  for(const [ver,cl] of Object.entries(c.versions)){
    IDX.set(key("purl",c.purl,ver),{comp:c,cves:cl});
    IDX.set(key("cpe",c.cpe_vendor,c.cpe_product,ver),{comp:c,cves:cl});
    IDX.set(key("name",c.name,ver),{comp:c,cves:cl});
  }
}
function parsePurl(p){if(!p||p.indexOf("@")<0)return null;const i=p.lastIndexOf("@");return[p.slice(0,i),p.slice(i+1)];}
function parseCpe(c){const m=/^cpe:2\.3:[aoh]:([^:]+):([^:]+):([^:]+):/.exec(c||"");return m?[m[1],m[2],m[3]]:null;}
function lookup(comp){
  const v=comp.version||"";
  if(comp.purl){const pk=parsePurl(comp.purl);if(pk){const h=IDX.get(key("purl",pk[0],pk[1]));if(h)return h;}}
  if(comp.cpe){const ck=parseCpe(comp.cpe);if(ck){const h=IDX.get(key("cpe",ck[0],ck[1],ck[2]));if(h)return h;}}
  if(comp.name){const h=IDX.get(key("name",comp.name,v));if(h)return h;}
  return null;
}
/* 도달성 + VEX (오라클과 동일 규칙) */
const EXPT={"isolated-cell":0,"control-network":1,"dmz-routable":2,"remote-accessible":3};
function reach(av,exp){const t=EXPT[exp];
  if(av==="N")return t===0?"no":(t===1?"cond":"yes");
  if(av==="A")return t===0?"no":(t<=2?"cond":"yes");
  if(av==="L")return "cond"; if(av==="P")return "no"; return "cond";}
const AVW={N:"네트워크",A:"인접망",L:"로컬",P:"물리"};
function vex(cve,exp){
  const r=reach(cve.av,exp);
  if(r==="no")return {s:"LIKELY_NOT_AFFECTED",why:(cve.av==="P"?"물리 접근 필요":"도달 경로 없음")+" · "+exp};
  if(r==="yes")return {s:"LIKELY_AFFECTED",why:AVW[cve.av]+" 공격면 · "+exp+(cve.kev?" · 야생 악용":"")};
  return {s:"UNDER_INVESTIGATION",why:"도달성 조건부("+(AVW[cve.av]||"?")+") · "+exp};
}
function analyze(sbom,exp){
  let comps=[];
  if(sbom.components)comps=comps.concat(sbom.components);
  if(sbom.metadata&&sbom.metadata.component)comps.push(sbom.metadata.component);
  const rows=[]; let total=0,aff=0,kev=0,crit=0;
  for(const c of comps){
    const h=lookup(c); if(!h)continue;
    const cves=h.cves.map(cv=>{const vx=vex(cv,exp);total++;if(vx.s==="LIKELY_AFFECTED")aff++;
      if(cv.kev)kev++;if(cv.sev==="critical")crit++;return {...cv,vex:vx};});
    if(cves.length)rows.push({name:c.name||h.comp.name,version:c.version||"",cves});
  }
  return {rows,total,aff,kev,crit,scanned:comps.length};
}
function sevRank(s){return {critical:0,high:1,medium:2,low:3,unknown:4}[s]||4;}
function render(res,exp){
  const el=$("#anres");
  if(!res.rows.length){el.innerHTML='<div class="empty">스캔한 '+res.scanned+'개 컴포넌트에서 알려진 CVE를 찾지 못했습니다. (내장 KB는 주요 OSS 42종 대상)</div>';return;}
  let h='<div class="an-summary">'
    +tile(res.total,"매칭 CVE")+tile(res.aff,"영향 가능",res.aff?"var(--affected)":"")
    +tile(res.crit,"Critical",res.crit?"var(--affected)":"")+tile(res.kev,"KEV 악용",res.kev?"var(--affected)":"")
    +tile(res.rows.length,"취약 컴포넌트")+'</div>';
  for(const r of res.rows.sort((a,b)=>Math.min(...a.cves.map(x=>sevRank(x.sev)))-Math.min(...b.cves.map(x=>sevRank(x.sev))))){
    const worst=r.cves.some(x=>x.vex.s==="LIKELY_AFFECTED");
    h+='<div class="comp"><div class="ch"><div><span class="cn">'+esc(r.name)+'</span> <span class="cv">'+esc(r.version)+'</span></div>'
      +'<span class="cc pill '+(worst?"LIKELY_AFFECTED":"UNDER_INVESTIGATION")+'">'+r.cves.length+' CVE</span></div><div class="cvelist">';
    for(const cv of r.cves.sort((a,b)=>sevRank(a.sev)-sevRank(b.sev))){
      h+='<div class="cverow"><span class="id">'+cv.id+'</span><span class="tags">'
        +'<span class="tag sev-'+cv.sev+'">'+cv.sev+'</span>'
        +(cv.kev?'<span class="tag kev">KEV</span>':'')
        +(cv.epss!=null?'<span class="tag">EPSS '+cv.epss.toFixed(2)+'</span>':'')
        +(cv.av?'<span class="tag">AV:'+cv.av+'</span>':'')
        +'<span style="color:var(--ink-3);font-size:11px">'+esc(cv.vex.why)+'</span></span>'
        +'<span class="pill '+cv.vex.s+'">'+LAB[cv.vex.s]+'</span></div>';
    }
    h+='</div></div>';
  }
  el.innerHTML=h;
}
function tile(v,l,col){return '<div class="stile"><div class="v"'+(col?' style="color:'+col+'"':'')+'>'+v+'</div><div class="l">'+l+'</div></div>';}
function esc(s){return String(s).replace(/[&<>]/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[m]));}
function run(){
  const raw=$("#paste").value.trim(); if(!raw){$("#anres").innerHTML='<div class="empty">SBOM JSON을 붙여넣거나 파일을 선택하세요.</div>';return;}
  let sbom; try{sbom=JSON.parse(raw);}catch(e){$("#anres").innerHTML='<div class="empty">JSON 파싱 오류: '+esc(e.message)+'</div>';return;}
  render(analyze(sbom,$("#exposure").value),$("#exposure").value);
}
$("#analyze").addEventListener("click",run);
$("#exposure").addEventListener("change",()=>{if($("#paste").value.trim())run();});
$("#loadex").addEventListener("click",()=>{$("#paste").value=JSON.stringify(EXAMPLE,null,1);run();});
const drop=$("#drop"),file=$("#file");
drop.addEventListener("click",()=>file.click());
file.addEventListener("change",e=>{const f=e.target.files[0];if(!f)return;const rd=new FileReader();rd.onload=()=>{$("#paste").value=rd.result;run();};rd.readAsText(f);});
["dragover","dragenter"].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add("over");}));
["dragleave","drop"].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove("over");}));
drop.addEventListener("drop",e=>{const f=e.dataTransfer.files[0];if(!f)return;const rd=new FileReader();rd.onload=()=>{$("#paste").value=rd.result;run();};rd.readAsText(f);});

/* ---------- 평가 결과 렌더 ---------- */
const p=D.provenance;
$("#chips").innerHTML=[["CISA 어드바이저리",p.advisories.toLocaleString()],["고유 CVE",p.cves.toLocaleString()],
  ["장비 SBOM",p.devices.toLocaleString()],["Findings",p.findings.toLocaleString()],
  ["OSS-arm",p.oss.toLocaleString()],["벤더맥락-arm",p.vendor.toLocaleString()],["KEV 실악용",p.kev]]
  .map(([k,v])=>'<span class="chip"><span class="dot">&#9679;</span> '+k+' <b>'+v+'</b></span>').join("");
const o=D.overall;
$("#kpis").innerHTML=
  '<div class="kpi"><div class="lab">Macro F1</div><div class="val">'+o.macro_f1.toFixed(3)+'</div>'
  +'<div class="cap">baseline 대비 <span class="delta">+'+(o.macro_f1-D.baseline).toFixed(3)+'</span> (TF-IDF '+D.baseline.toFixed(3)+')</div></div>'
  +'<div class="kpi safety"><div class="lab">영향&rarr;비영향 오판</div><div class="val">'+o.wrong_na+'</div>'
  +'<div class="cap">ICS 안전 핵심 지표 · 가장 위험한 오류 0건</div></div>'
  +'<div class="kpi"><div class="lab">Calibration ECE</div><div class="val">'+o.ece.toFixed(3)+'</div><div class="cap">낮을수록 보정 우수</div></div>'
  +'<div class="kpi"><div class="lab">조사 필요 전환율</div><div class="val">'+(o.under_rate*100).toFixed(0)+'<span style="font-size:18px">%</span></div><div class="cap">불확실 시 보수적 보류</div></div>';
const cm=o.confusion_matrix,L=D.labels,mx=Math.max(...cm.flat());
let cmh='<div class="h"></div>'+L.map(l=>'<div class="h">'+LAB[l]+'<br>예측</div>').join("");
cm.forEach((row,i)=>{cmh+='<div class="rh">'+LAB[L[i]]+' · 정답</div>';
  row.forEach((v,j)=>{const diag=i===j,zs=(i===0&&j===1),inten=v/mx;
    const bg=diag?'color-mix(in srgb,var(--accent) '+(8+inten*30)+'%,var(--surface))':'color-mix(in srgb,var(--ink-3) '+(inten*22)+'%,var(--surface))';
    cmh+='<div class="cell'+(diag?' diag':'')+(zs?' zero-safe':'')+'" style="background:'+(zs?'':bg)+'">'+v+(zs?'<small>안전</small>':'')+'</div>';});});
$("#cm").innerHTML=cmh;
$("#perclass").innerHTML=L.map(l=>{const c=o.per_class[l];
  return '<div><div class="bar-row" style="grid-template-columns:1fr"><div class="nm"><i class="sw" style="background:'+SC[l]+'"></i> <b style="color:var(--ink)">'+LAB[l]+'</b> <span style="color:var(--ink-3);font-family:var(--mono);font-size:11px">n='+c.support+'</span></div></div>'
    +'<div class="stat-line"><div class="m"><b>'+c.precision.toFixed(3)+'</b>Precision</div><div class="m"><b>'+c.recall.toFixed(3)+'</b>Recall</div><div class="m"><b>'+c.f1.toFixed(3)+'</b>F1</div></div></div>';}).join("");
const arms=[["OSS-arm (동적)",D.perarm.oss,"var(--accent)"],["벤더맥락-arm (폐쇄)",D.perarm.vendor,"var(--accent-2)"]];
$("#perarm").innerHTML=arms.map(a=>'<div class="bar-row"><div class="nm">'+a[0]+'<br><span style="color:var(--ink-3);font-family:var(--mono);font-size:10px">n='+a[1][1]+'</span></div>'
  +'<div class="track"><div class="fill" style="width:'+(a[1][0]*100)+'%;background:'+a[2]+'">'+a[1][0].toFixed(3)+'</div></div></div>').join("");
const r=D.rationale;
$("#rmet").innerHTML='<div class="box"><div class="v" style="color:var(--safe)">'+r.comp.toFixed(3)+'</div><div class="l">Comprehensiveness &uarr;</div><div class="d">근거 제거 시 확신 급락 → 인과적</div></div>'
  +'<div class="box"><div class="v" style="color:var(--accent)">'+r.suff.toFixed(3)+'</div><div class="l">Sufficiency drop &darr;</div><div class="d">근거만으로 예측 유지 → 충분</div></div>';
$("#samples").innerHTML=D.samples.map(s=>{const m=s.status===s.oracle;
  return '<div class="svex"><div class="top"><span class="cve">'+s.cve+'</span><span class="pill '+s.status+'">'+LAB[s.status]+'</span></div><div class="dev">'+s.device+'</div>'
    +'<div class="rats">'+s.rationale.map((t,i)=>'<div class="rat"><span class="eid">CVE-'+(i+2)+'</span><span>'+esc(t)+'</span></div>').join("")+'</div>'
    +'<div class="meta"><span>confidence <b>'+s.conf.toFixed(2)+'</b></span><span class="'+(m?"match":"miss")+'">oracle '+(m?"&#10003; 일치":"&#8800; 불일치")+' · '+LAB[s.oracle]+'</span></div></div>';}).join("");
// two-model
const T=D.two_model;
$("#tm_code").innerHTML='<div class="box"><div class="v" style="color:var(--affected)">'+T.codebert_standalone_acc.toFixed(2)+'</div><div class="l">추상적 취약성 분류</div><div class="d">미학습 CVE, 무작위 0.50 = 실패 (정직히 보고)</div></div>'
  +'<div class="box"><div class="v" style="color:var(--safe)">'+T.ref_match_perturbed.toFixed(2)+'</div><div class="l">레퍼런스 매칭 (변형)</div><div class="d">변형된 배포코드→올바른 레퍼런스. n='+T.ref_match_n+'</div></div>';
$("#tm_bp").innerHTML=
  '<div class="an-summary" style="grid-template-columns:1fr 1fr">'
  +'<div class="stile"><div class="v">'+T.bp_caught+'/'+T.bp_injected+'</div><div class="l">CodeBERT가 잡은 백포트</div></div>'
  +'<div class="stile"><div class="v" style="color:var(--safe)">'+T.ctx_fp+'&rarr;'+T.two_fp+'</div><div class="l">백포트 오탐 감소</div></div></div>'
  +'<div class="bars"><div class="bar-row"><div class="nm">맥락 단독</div><div class="track"><div class="fill" style="width:'+(T.ctx_acc*100)+'%;background:var(--under)">'+T.ctx_acc.toFixed(3)+'</div></div></div>'
  +'<div class="bar-row"><div class="nm">+CodeBERT</div><div class="track"><div class="fill" style="width:'+(T.two_acc*100)+'%;background:var(--safe)">'+T.two_acc.toFixed(3)+'</div></div></div></div>';
$("#tm_note").innerHTML='실제 코드는 OSS '+T.code_cves+' CVE에서만 확보됨 → 엄격한 "코드 없으면 조사필요" 규칙은 findings의 '
  +Math.round(100*T.unavail/T.total)+'%('+T.unavail.toLocaleString()+'/'+T.total.toLocaleString()+')를 조사필요로 만듦. '
  +'따라서 실제 시스템은 <b>하이브리드</b>: 코드 있으면 CodeBERT 확정(백포트 제거), 없으면 SecureBERT 맥락 판정.';
const yrs=D.provenance.years,ymax=Math.max(...Object.values(yrs));
$("#ychart").innerHTML=Object.entries(yrs).map(([y,v])=>'<div class="ycol" title="'+y+': '+v+'"><div class="b" style="height:'+Math.max(3,v/ymax*92)+'px"></div><div class="y">'+y.slice(2)+'</div></div>').join("");
$("#pipe").innerHTML=["CISA 크롤","악용신호(KEV·EPSS)","역방향 SBOM","Ground Truth","SecureBERT 학습·평가"].map(s=>'<span>'+s+'</span>').join('<span class="s">&rarr;</span>');
$("#rt").textContent=D.runtime+"s";$("#dev").textContent=D.device.toUpperCase();
</script>
"""

out = (HTML.replace("__DATA__", json.dumps(DATA, ensure_ascii=False))
           .replace("__KB__", json.dumps(KB, ensure_ascii=False, separators=(",", ":")))
           .replace("__EXAMPLE__", json.dumps(EX, ensure_ascii=False)))
open(os.path.join(R, "dashboard.html"), "w", encoding="utf-8").write(out)
print("dashboard.html written:", round(len(out)/1024, 1), "KB")
