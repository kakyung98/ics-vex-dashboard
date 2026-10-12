# -*- coding: utf-8 -*-
"""The certification page (/cert.html) — run test items #3 and #4 in the browser.

Markup and client script only; every number on the page comes from /api/cert/*,
which scores through tools/eval_*.score. Nothing here computes a metric, because a
figure computed in the page would be a second implementation of the measurement.

Two things the page must make legible rather than hide:

  * Item #3 runs for minutes. The Run button starts a job and the page polls
    /api/cert/job/<id>, showing component progress, so a long run looks like work
    rather than a hang.
  * Item #4's figure depends on the scope. The three scopes are offered as an
    explicit choice with the circularity disclosure attached to the result, not as
    one headline number the reader has to take on trust.
"""

CERT_PAGE = """
<h1 style="margin:0 0 6px">인증시험 성능지표 평가</h1>
<p class="hint" style="margin:0 0 18px">
시험항목 <b>#3 (SBOM 기반 공개 취약점 식별 정밀도)</b> 과
<b>#4 (VEX 기반 식별된 취약점 영향 판단 정밀도)</b> 를 이 화면에서 직접 실행합니다.
평가 데이터셋은 번들된 정답셋을 쓰거나, 동일 스키마의 <code>.jsonl</code> 을 업로드할 수 있습니다.
채점은 CLI 측정 도구와 <b>같은 함수</b>(<code>tools/eval_cpe_match_precision.score</code>,
<code>tools/eval_vex_precision.score</code>)를 호출하므로, 이 화면의 수치는 측정된 수치와
정의상 같습니다 — 번들 데이터셋으로 실행하면 기록된 값과 일치하는지도 함께 표시됩니다.
</p>

<div id="certItems"></div>

<div class="card" style="margin-top:18px">
  <h3 style="margin:0 0 8px">실행 이력</h3>
  <div id="certJobs" class="hint">아직 실행한 평가가 없습니다.</div>
</div>

<style>
.cert-item{border:1px solid var(--bd,#2b3a2b);border-radius:8px;padding:14px 16px;margin-bottom:14px}
.cert-head{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
.cert-badge{font-weight:700;font-size:12px;padding:2px 8px;border-radius:10px;background:#1f3d26;color:#8ce99a}
.cert-grid{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;margin:10px 0;font-size:13px}
.cert-grid dt{color:#9aa}
.cert-ds{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#9aa;
         word-break:break-all;margin:6px 0 0}
.cert-run{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:10px}
.cert-res{margin-top:12px;border-top:1px solid #2b3a2b;padding-top:10px;display:none}
.cert-prec{font-size:28px;font-weight:800;letter-spacing:-.5px}
.cert-pass{color:#51cf66}.cert-fail{color:#ff6b6b}
.cert-warn{background:#3d2f1f;border-left:3px solid #f59f00;padding:8px 10px;
           margin-top:10px;font-size:12px;border-radius:0 4px 4px 0}
.cert-ok{background:#1f3d26;border-left:3px solid #51cf66;padding:8px 10px;
         margin-top:10px;font-size:12px;border-radius:0 4px 4px 0}
.cert-bar{height:6px;background:#223;border-radius:3px;overflow:hidden;margin-top:8px}
.cert-bar>i{display:block;height:100%;background:#51cf66;width:0;transition:width .4s}
.cert-kv{display:flex;gap:18px;flex-wrap:wrap;margin-top:8px;font-size:13px}
.cert-kv b{font-variant-numeric:tabular-nums}
table.cert-fp{width:100%;border-collapse:collapse;font-size:12px;margin-top:10px}
table.cert-fp th,table.cert-fp td{border-bottom:1px solid #2b3a2b;padding:4px 6px;text-align:left}
</style>

<script>
const CERT = {};

function fmtBytes(n){
  if(n==null) return '—';
  if(n > 1048576) return (n/1048576).toFixed(1)+' MB';
  if(n > 1024) return (n/1024).toFixed(0)+' KB';
  return n+' B';
}

function dsRows(info){
  return Object.entries(info).map(([role,d])=>
    '<div class="cert-ds">'+role+': <b>'+d.path+'</b> '+
    (d.present ? '· '+(d.records!=null ? d.records.toLocaleString()+' records · ' : '')+
                 fmtBytes(d.bytes)+' · sha256 '+d.sha256.slice(0,16)+'…'
               : '<span style="color:#ff6b6b">없음</span>')+
    '</div>').join('');
}

function itemCard(it){
  const vs = it.variants.map(v=>'<option value="'+v.key+'">'+v.label+'</option>').join('');
  return '<div class="cert-item" id="item'+it.id+'">'+
    '<div class="cert-head"><span class="cert-badge">시험항목 #'+it.id+'</span>'+
      '<b style="font-size:16px">'+it.name+'</b>'+
      '<span class="hint">합격기준 정밀도 ≥ '+(it.acceptance*100).toFixed(0)+'%</span></div>'+
    '<dl class="cert-grid">'+
      '<dt>지표</dt><dd><code>'+it.metric+'</code></dd>'+
      '<dt>SUT</dt><dd><code>'+it.sut+'</code></dd>'+
      '<dt>소요</dt><dd>'+it.runtime_hint+'</dd>'+
    '</dl>'+
    dsRows(it.dataset_info)+
    '<div class="cert-run">'+
      '<select id="var'+it.id+'">'+vs+'</select>'+
      '<button class="btn" onclick="certRun(\\''+it.id+'\\')">번들 데이터셋으로 평가</button>'+
      '<label class="hint" style="cursor:pointer">'+
        '<input type="file" id="up'+it.id+'" accept=".jsonl" style="display:none" '+
        'onchange="certUpload(\\''+it.id+'\\',this)"> '+
        '<span class="btn" onclick="document.getElementById(\\'up'+it.id+'\\').click()">'+
        '데이터셋 업로드…</span></label>'+
      '<span id="st'+it.id+'" class="hint"></span>'+
    '</div>'+
    '<div class="cert-bar" id="bar'+it.id+'" style="display:none"><i></i></div>'+
    '<div class="cert-res" id="res'+it.id+'"></div>'+
  '</div>';
}

async function certLoad(){
  const r = await fetch('/api/cert/items'); const items = await r.json();
  document.getElementById('certItems').innerHTML = items.map(itemCard).join('');
  items.forEach(it=>CERT[it.id]=it);
  certJobs();
}

async function certRun(id, gt){
  const variant = document.getElementById('var'+id).value;
  const st = document.getElementById('st'+id);
  st.textContent = '실행 중…';
  const body = {item:id, variant:variant};
  if(gt) body.gt_path = gt;
  const r = await fetch('/api/cert/run', {method:'POST',
      headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  const j = await r.json();
  if(!r.ok){ st.textContent = '오류: '+(j.detail||'실행 실패'); return; }
  certPoll(id, j.job);
}

async function certUpload(id, inp){
  const f = inp.files[0]; if(!f) return;
  const st = document.getElementById('st'+id);
  st.textContent = '업로드 중… ('+fmtBytes(f.size)+')';
  const fd = new FormData(); fd.append('file', f); fd.append('item', id);
  const r = await fetch('/api/cert/upload', {method:'POST', body:fd});
  const j = await r.json();
  if(!r.ok || !j.valid || !j.valid.ok){
    st.textContent = '거부: '+((j.valid&&j.valid.error)||j.detail||'스키마 불일치');
    return;
  }
  st.textContent = '업로드 완료 ('+j.valid.records_checked+'행 검증) · 평가 시작';
  certRun(id, j.path);
}

function certPoll(id, job){
  const st = document.getElementById('st'+id);
  const bar = document.getElementById('bar'+id);
  const tick = async ()=>{
    const r = await fetch('/api/cert/job/'+job); const j = await r.json();
    if(j.state === 'running'){
      bar.style.display='block';
      if(j.pct!=null){
        bar.firstChild.style.width = j.pct+'%';
        st.textContent = '실행 중… '+j.pct+'% ('+j.progress.done.toLocaleString()+
                         ' / '+j.progress.total.toLocaleString()+')';
      } else { st.textContent = '실행 중…'; }
      setTimeout(tick, 1500); return;
    }
    bar.style.display='none';
    if(j.state === 'error'){
      st.textContent = '오류';
      document.getElementById('res'+id).style.display='block';
      document.getElementById('res'+id).innerHTML =
        '<pre style="color:#ff6b6b;font-size:11px;white-space:pre-wrap">'+j.error+'</pre>';
      certJobs(); return;
    }
    st.textContent = '완료 ('+((j.finished-j.started)).toFixed(1)+'초)';
    certShow(id, j); certJobs();
  };
  tick();
}

function certShow(id, j){
  const res = j.result, box = document.getElementById('res'+id);
  const pct = (res.precision*100).toFixed(2);
  const cls = res.pass ? 'cert-pass' : 'cert-fail';
  let h = '<div class="cert-prec '+cls+'">'+pct+'% '+
          '<span style="font-size:13px;font-weight:600">'+
          (res.pass ? 'PASS' : 'FAIL')+' · '+res.acceptance_criterion+'</span></div>';

  h += '<div class="cert-kv"><span>TP <b>'+res.TP+'</b></span><span>FP <b>'+res.FP+'</b></span>';
  if(res.TN!=null) h += '<span>TN <b>'+res.TN+'</b></span><span>FN <b>'+res.FN+'</b></span>';
  if(res.scored!=null) h += '<span>채점 <b>'+res.scored.toLocaleString()+'</b></span>';
  if(res.recall!=null) h += '<span class="hint">recall '+(res.recall*100).toFixed(2)+'% (비평가)</span>';
  h += '</div>';

  // Did this run land on the figure that was certified? Only meaningful for the
  // bundled dataset; an upload has nothing to be compared against.
  if(j.reproduces === true){
    h += '<div class="cert-ok">✔ 기록된 측정값 '+(j.reference_precision*100).toFixed(2)+
         '% 와 일치합니다 (번들 데이터셋 · sha256 '+j.gt_sha256.slice(0,16)+'…).</div>';
  } else if(j.reproduces === false){
    h += '<div class="cert-warn">⚠ 기록된 측정값 '+(j.reference_precision*100).toFixed(2)+
         '% 와 다릅니다. 데이터셋 또는 판정 캐시가 갱신되었는지 확인하십시오.</div>';
  } else if(j.dataset === 'uploaded'){
    h += '<div class="cert-warn">업로드된 데이터셋입니다. 기록된 인증 측정값과의 '+
         '대조 대상이 아니므로 위 수치는 이 데이터셋에 대한 결과입니다.</div>';
  }

  if(res.labelled_share_pct!=null){
    h += '<div class="cert-warn">라벨된 예측 비율 '+res.labelled_share_pct+'% — '+
         '정답셋이 열거하지 않는 CVE '+res.unlabelled_predictions.toLocaleString()+
         '건과 기관 간 등록주체 불일치 '+res.unadjudicable_predictions.toLocaleString()+
         '건은 채점에서 제외되었습니다. 위 수치는 라벨된 구간에 대한 값입니다.</div>';
  }
  if(res.circularity_warning){
    h += '<div class="cert-warn">⚠ 순환성: '+res.circularity_warning+'</div>';
  }
  if(res.per_build && Object.keys(res.per_build).length>1){
    h += '<div class="cert-kv">'+Object.entries(res.per_build).map(([b,c])=>
      '<span>'+b+' <b>TP '+(c.TP||0)+' / FP '+(c.FP||0)+' / TN '+(c.TN||0)+
      ' / FN '+(c.FN||0)+'</b></span>').join('')+'</div>';
  }

  const fps = res.fp_examples || res.fp_cases || [];
  if(fps.length){
    h += '<details style="margin-top:10px"><summary class="hint">오탐(FP) '+
         fps.length+'건 보기</summary><table class="cert-fp"><tr>'+
         Object.keys(fps[0]).map(k=>'<th>'+k+'</th>').join('')+'</tr>'+
         fps.slice(0,40).map(r=>'<tr>'+Object.values(r).map(v=>
           '<td>'+String(v==null?'':v).slice(0,80)+'</td>').join('')+'</tr>').join('')+
         '</table></details>';
  }
  h += '<details style="margin-top:8px"><summary class="hint">결과 JSON</summary>'+
       '<pre style="font-size:11px;white-space:pre-wrap;max-height:320px;overflow:auto">'+
       JSON.stringify(res,null,1).replace(/</g,'&lt;')+'</pre></details>';
  box.innerHTML = h; box.style.display='block';
}

async function certJobs(){
  const r = await fetch('/api/cert/jobs'); const js = await r.json();
  const el = document.getElementById('certJobs');
  if(!js.length){ el.innerHTML='아직 실행한 평가가 없습니다.'; return; }
  el.innerHTML = '<table class="cert-fp"><tr><th>시각</th><th>항목</th><th>범위</th>'+
    '<th>데이터셋</th><th>상태</th><th>정밀도</th><th>재현</th></tr>'+
    js.map(j=>'<tr><td>'+new Date(j.started*1000).toLocaleTimeString()+'</td>'+
      '<td>#'+j.item+'</td><td>'+j.variant+'</td><td>'+j.dataset+'</td>'+
      '<td>'+j.state+'</td>'+
      '<td>'+(j.precision!=null ? (j.precision*100).toFixed(2)+'%' : '—')+
      (j.passed===true?' <span class="cert-pass">PASS</span>':
       j.passed===false?' <span class="cert-fail">FAIL</span>':'')+'</td>'+
      '<td>'+(j.reproduces===true?'✔':j.reproduces===false?'⚠':'—')+'</td></tr>').join('')+
    '</table>';
}

if(document.getElementById('certItems')) certLoad();
</script>
"""

# ---------------------------------------------------------------------------
# The static (GitHub Pages) variant.
#
# /cert.html above RUNS the measurement: it posts a job, polls it, and scores
# through tools/eval_*.score. None of that exists on Pages, which serves files
# and nothing else. Baking the interactive page would ship a Run button that
# silently does nothing, which is worse than not shipping it - a reviewer would
# conclude the measurement is broken rather than that the host cannot run it.
#
# So the static variant shows the same figures, read out of the result JSONs at
# BUILD time, and says plainly where the run happens. Same numbers, no dead
# controls.
# ---------------------------------------------------------------------------

def _row(res, label, note=""):
    if not res:
        return ("<tr><td>%s</td><td colspan=\"4\" class=\"hint\">결과 파일 없음"
                "</td></tr>" % label)
    pct = "%.2f%%" % (res["precision"] * 100)
    cls = "cert-pass" if res.get("pass") else "cert-fail"
    verdict = "PASS" if res.get("pass") else "FAIL"
    counts = "TP %d / FP %d" % (res["TP"], res["FP"])
    if res.get("TN") is not None:
        counts += " / TN %d / FN %d" % (res["TN"], res["FN"])
    return ("<tr><td>%s</td><td><b class=\"%s\">%s</b></td><td>%s</td>"
            "<td>%s</td><td class=\"hint\">%s</td></tr>"
            % (label, cls, pct, verdict, counts, note))


def cert_static_page(results):
    """Markup for the baked page. `results` maps a key to a loaded result dict."""
    i3 = results.get("item3")
    i3ai = results.get("item3_ai")
    i4 = results.get("item4")
    i4a = results.get("item4_allbuilds")
    i4i = results.get("item4_independent")

    def pop(res, key, default="—"):
        return res.get(key, default) if res else default

    return """
<h1 style="margin:0 0 6px">인증시험 성능지표 평가</h1>
<p class="hint" style="margin:0 0 18px">
시험항목 <b>#3 (SBOM 기반 공개 취약점 식별 정밀도)</b> 와
<b>#4 (VEX 기반 식별된 취약점 영향 판단 정밀도)</b> 의 측정 결과입니다.
아래 수치는 이 사이트를 빌드할 때 <code>results/*.json</code> 에서 읽어온 것으로,
적어 둔 값이 아니라 측정 산출물 그 자체입니다.
</p>

<div class="cert-warn" style="margin:0 0 18px">
이 페이지는 <b>정적 사본</b>입니다. 평가를 직접 실행하는 화면
(데이터셋 업로드 · 재실행 · 진행률)은 백엔드가 필요하므로 로컬 서버에서만 동작합니다:
<code>python src/api_server.py</code> 후 <code>/cert.html</code>.
</div>

<div class="cert-item">
  <div class="cert-head"><span class="cert-badge">시험항목 #3</span>
    <b style="font-size:16px">SBOM 기반 공개 취약점 식별 정밀도</b>
    <span class="hint">합격기준 정밀도 ≥ 80%</span></div>
  <dl class="cert-grid">
    <dt>지표</dt><dd><code>precision = TP / (TP + FP)</code></dd>
    <dt>SUT</dt><dd><code>{i3sut}</code></dd>
    <dt>정답셋</dt><dd><code>{i3gt}</code> · {i3labels} 라벨</dd>
  </dl>
  <table class="cert-fp">
    <tr><th>구성</th><th>정밀도</th><th>판정</th><th>집계</th><th>비고</th></tr>
    {i3rows}
  </table>
  <div class="cert-warn">라벨된 예측 비율 <b>{i3share}%</b> — 정답셋이 열거하지 않는 CVE와
  기관 간 등록주체 불일치 건은 채점에서 제외되었습니다. 위 수치는 라벨된 구간에 대한 값입니다.</div>
</div>

<div class="cert-item">
  <div class="cert-head"><span class="cert-badge">시험항목 #4</span>
    <b style="font-size:16px">VEX 기반 식별된 취약점 영향 판단 정밀도</b>
    <span class="hint">합격기준 정밀도 ≥ 85%</span></div>
  <dl class="cert-grid">
    <dt>지표</dt><dd><code>precision = TP / (TP + FP)</code>, positive = affected</dd>
    <dt>SUT</dt><dd><code>tools/vex_judge_v2</code> (Q0 패치게이트 + Q1 존재성, Q2/Q3는 증거등급)</dd>
    <dt>모집단</dt><dd>소스를 수집한 전체 CVE · 정답 케이스 {i4cases}건</dd>
  </dl>
  <table class="cert-fp">
    <tr><th>범위</th><th>정밀도</th><th>판정</th><th>집계</th><th>비고</th></tr>
    {i4rows}
  </table>
  <div class="cert-warn">
  <b>범위를 함께 읽어야 합니다.</b> 게이트를 켠 전수 측정은 패치게이트가 정답셋과
  같은 권위(수정 시그니처 + NVD 범위)를 읽으므로 <b>순환</b>입니다. 인용 가능한 주 지표는
  게이트를 끈 취약빌드 측정입니다. 실행검증 전용 범위는 오라클을 공유하지 않는 유일한
  범위지만 표본이 매우 작아 합격기준에 미달하며, 숨기지 않고 공시합니다.
  </div>
</div>

<p class="hint" style="margin-top:18px">
평가 데이터셋과 산출물은 저장소의 <code>benchmark/</code> 에 번들되어 있습니다
(정답셋 · 입력 · SUT 출력 · 채점 결과, 각 파일의 SHA-256 포함).
</p>
""".format(
        i3sut=pop(i3, "sut"),
        i3gt=pop(i3, "ground_truth"),
        i3labels="{:,}".format(i3["gt_labels"]) if i3 else "—",
        i3share=pop(i3, "labelled_share_pct"),
        i3rows=(_row(i3, "문자열 캐스케이드 (기본 SUT)")
                + _row(i3ai, "+ 학습 인코더 검색",
                       "문자열 경로가 포기한 컴포넌트에만 적용")),
        i4cases=pop(i4, "gt_cases_total"),
        i4rows=(_row(i4, "취약 빌드 · 패치게이트 OFF",
                     "주 지표 — 오라클 비공유 중 최대 범위")
                + _row(i4a, "전체 빌드 · 게이트 ON",
                       "not_affected를 실제로 시험하는 유일한 범위 · 순환")
                + _row(i4i, "실행검증 증거만",
                       "오라클 완전 비공유 · 표본이 작음")),
    )
