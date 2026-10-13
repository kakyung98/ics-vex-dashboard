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
<h1 style="margin:0 0 6px">Certification performance metrics</h1>
<p class="hint" style="margin:0 0 18px">
Run test item <b>#3 (SBOM-based public vulnerability identification precision)</b> and
<b>#4 (VEX affected-judgment precision)</b> directly from this page, against the bundled
ground truth or a <code>.jsonl</code> you upload in the same schema.
Scoring calls the <b>same functions</b> the CLI measurement tools do
(<code>tools/eval_cpe_match_precision.score</code>, <code>tools/eval_vex_precision.score</code>),
so these figures are identical to the measured ones by construction &mdash; and a run on the
bundled dataset also reports whether it landed on the recorded figure.
</p>

<div id="certItems"></div>

<div class="card" style="margin-top:18px">
  <h3 style="margin:0 0 8px">Run history</h3>
  <div id="certJobs" class="hint">Nothing has been run yet.</div>
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

function dsRows(info, unit){
  // Each item counts a DIFFERENT thing per row - (component, CVE) for #3,
  // (CVE, build) for #4, (CVE, question) for the Q3/Q4 axis - so a bare
  // "285 records" invites reading it as a CVE count. The unit is named.
  return Object.entries(info).map(([role,d])=>
    '<div class="cert-ds">'+role+': <b>'+d.path+'</b> '+
    (d.present ? '· '+(d.records!=null
                       ? d.records.toLocaleString()+(unit ? ' '+unit : ' records')+' · ' : '')+
                 fmtBytes(d.bytes)+' · sha256 '+d.sha256.slice(0,16)+'…'
               : '<span style="color:#ff6b6b">missing</span>')+
    '</div>').join('');
}

function itemCard(it){
  const vs = it.variants.map(v=>'<option value="'+v.key+'">'+v.label+'</option>').join('');
  return '<div class="cert-item" id="item'+it.id+'">'+
    '<div class="cert-head"><span class="cert-badge">'+
      (it.acceptance==null ? 'SUPPLEMENTARY' : 'Test item #'+it.id)+'</span>'+
      '<b style="font-size:16px">'+it.name+'</b>'+
      '<span class="hint">'+(it.acceptance==null
        ? (it.acceptance_label || 'not a certification test item; no acceptance criterion')
        : 'acceptance: precision &ge; '+(it.acceptance*100).toFixed(0)+'%')+'</span></div>'+
    '<dl class="cert-grid">'+
      '<dt>Metric</dt><dd><code>'+it.metric+'</code></dd>'+
      '<dt>SUT</dt><dd><code>'+it.sut+'</code></dd>'+
      '<dt>Runtime</dt><dd>'+it.runtime_hint+'</dd>'+
    '</dl>'+
    dsRows(it.dataset_info, it.record_unit)+
    '<div class="cert-run">'+
      '<select id="var'+it.id+'">'+vs+'</select>'+
      '<button class="btn" onclick="certRun(\\''+it.id+'\\')">Evaluate on the bundled dataset</button>'+
      '<label class="hint" style="cursor:pointer">'+
        '<input type="file" id="up'+it.id+'" accept=".jsonl" style="display:none" '+
        'onchange="certUpload(\\''+it.id+'\\',this)"> '+
        '<span class="btn" onclick="document.getElementById(\\'up'+it.id+'\\').click()">'+
        'Upload a dataset&hellip;</span></label>'+
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
  st.textContent = 'running…';
  const body = {item:id, variant:variant};
  if(gt) body.gt_path = gt;
  const r = await fetch('/api/cert/run', {method:'POST',
      headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  const j = await r.json();
  if(!r.ok){ st.textContent = 'error: '+(j.detail||'run failed'); return; }
  certPoll(id, j.job);
}

async function certUpload(id, inp){
  const f = inp.files[0]; if(!f) return;
  const st = document.getElementById('st'+id);
  st.textContent = 'uploading… ('+fmtBytes(f.size)+')';
  const fd = new FormData(); fd.append('file', f); fd.append('item', id);
  const r = await fetch('/api/cert/upload', {method:'POST', body:fd});
  const j = await r.json();
  if(!r.ok || !j.valid || !j.valid.ok){
    st.textContent = 'rejected: '+((j.valid&&j.valid.error)||j.detail||'schema mismatch');
    return;
  }
  st.textContent = 'uploaded ('+j.valid.records_checked+' rows validated) - starting';
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
        st.textContent = 'running… '+j.pct+'% ('+j.progress.done.toLocaleString()+
                         ' / '+j.progress.total.toLocaleString()+')';
      } else { st.textContent = 'running…'; }
      setTimeout(tick, 1500); return;
    }
    bar.style.display='none';
    if(j.state === 'error'){
      st.textContent = 'error';
      document.getElementById('res'+id).style.display='block';
      document.getElementById('res'+id).innerHTML =
        '<pre style="color:#ff6b6b;font-size:11px;white-space:pre-wrap">'+j.error+'</pre>';
      certJobs(); return;
    }
    st.textContent = 'done ('+((j.finished-j.started)).toFixed(1)+'s)';
    certShow(id, j); certJobs();
  };
  tick();
}

function certShowQ34(res, box, j){
  const NAME = {Q3:'Q3 reachability (Joern)', Q4:'Q4 controllability (Z3)'};
  let h = '<div class="cert-warn" style="margin:0 0 12px">'+
    '<b>The criterion is contradictions = 0.</b> Recall cannot carry one &mdash; '+
    'the answer key has no negative class, so <b>a system that analyses nothing and '+
    'answers positive to everything scores 100% recall</b>. The harm this pipeline can take '+
    'is one-directional (an over-positive solver clears nothing and is safe; <b>an over-refuting solver produces false clearances</b>), so the bar is placed there: '+
    'the solver must never assert the negative on a case an outside authority asserts as positive. '+
    'This is not a certification test item, and the criterion is this repository&rsquo;s own.</div>'+
    '<div class="cert-warn" style="margin:0 0 12px">'+
    '<b>Supplementary disclosure.</b> Item #4&rsquo;s precision is about the <code>affected</code> verdict, and '+
    'that verdict is decided at Q2 (presence) &mdash; Q3/Q4 only set the evidence tier, and no answer key carried a tier, so '+
    'their contribution to every published figure was <b>0</b>. This is the axis on which '+
    'those two engines become measurable, with authorities outside the repository (shipped public headers, NVD CVSS AV/UI).</div>';
  ['Q3','Q4'].forEach(function(q){
    const d = res.per_question[q]; if(!d) return;
    const vcls = d.pass ? 'cert-pass' : 'cert-fail';
    h += '<div style="margin:0 0 14px"><b>'+NAME[q]+'</b> '+
      '<span class="'+vcls+'" style="font-weight:700">'+(d.pass?'PASS':'FAIL')+'</span> '+
      '<span class="hint">'+d.contradictions+' contradictions &middot; criterion 0</span>'+
      '<div class="cert-kv"><span>TP <b>'+d.TP+'</b></span><span>FP <b>'+d.FP+'</b></span>'+
      '<span>FN <b>'+d.FN+'</b></span><span>TN <b>'+d.TN+'</b></span>'+
      '<span>labels <b>'+d.labels+'</b></span>'+
      '<span>abstained <b>'+d.abstained+'</b> ('+(d.abstention_pct||0)+'%)</span></div>'+
      '<div class="cert-kv"><span>precision <b>'+
        (d.precision!=null ? (d.precision*100).toFixed(2)+'%' : '—')+'</b></span>'+
      '<span>recall <b>'+(d.recall!=null ? (d.recall*100).toFixed(2)+'%' : '—')+'</b></span></div>'+
      (d.precision_null_reason ? '<p class="hint" style="margin:6px 2px 0">no precision &mdash; '+
        d.precision_null_reason+'</p>' : '')+
      (d.disagreements && d.disagreements.length
        ? '<details style="margin-top:6px"><summary class="hint">see '+
          d.disagreements.length+' disagreements</summary><pre class="mono" style="white-space:pre-wrap">'+
          d.disagreements.map(function(w){return w.cve+'  authority='+w.expected+
            '  SUT='+w.sut+'\\n   '+(w.sut_detail||'');}).join('\\n')+'</pre></details>'
        : '')+
      '</div>';
  });
  // The reproduction check for this axis compares the recorded RECALLS, since it
  // has no single precision to compare.
  const ref = j.reference_precision || {};
  if(j.reproduces === true){
    h += '<div class="cert-ok">✔ matches the recorded recalls, Q3 '+
         (ref.Q3_recall*100).toFixed(2)+'% / Q4 '+(ref.Q4_recall*100).toFixed(2)+
         '% (sha256 '+j.gt_sha256.slice(0,16)+'…).</div>';
  } else if(j.reproduces === false){
    h += '<div class="cert-warn">⚠ differs from the recorded recalls. '+
         'Check whether the ground truth or the engine '+
         'verdicts were '+
         'regenerated.</div>';
  }
  box.innerHTML = h;
}

function certShow(id, j){
  const res = j.result, box = document.getElementById('res'+id);
  // The Q3/Q4 axis has no single precision and no PASS/FAIL - Q4's answer key has
  // no negative class, so a precision there would be 1.0000 by construction. It
  // renders per question instead of pretending to one headline number.
  if(res.per_question){ certShowQ34(res, box, j); return; }
  const pct = (res.precision*100).toFixed(2);
  const cls = res.pass ? 'cert-pass' : 'cert-fail';
  let h = '<div class="cert-prec '+cls+'">'+pct+'% '+
          '<span style="font-size:13px;font-weight:600">'+
          (res.pass ? 'PASS' : 'FAIL')+' · '+res.acceptance_criterion+'</span></div>';

  h += '<div class="cert-kv"><span>TP <b>'+res.TP+'</b></span><span>FP <b>'+res.FP+'</b></span>';
  if(res.TN!=null) h += '<span>TN <b>'+res.TN+'</b></span><span>FN <b>'+res.FN+'</b></span>';
  if(res.scored!=null) h += '<span>scored <b>'+res.scored.toLocaleString()+'</b></span>';
  if(res.recall!=null) h += '<span class="hint">recall '+(res.recall*100).toFixed(2)+'% (not graded)</span>';
  h += '</div>';

  // Did this run land on the figure that was certified? Only meaningful for the
  // bundled dataset; an upload has nothing to be compared against.
  if(j.reproduces === true){
    h += '<div class="cert-ok">✔ matches the recorded figure '+(j.reference_precision*100).toFixed(2)+
         '% (bundled dataset, sha256 '+j.gt_sha256.slice(0,16)+'…).</div>';
  } else if(j.reproduces === false){
    h += '<div class="cert-warn">⚠ differs from the recorded figure '+(j.reference_precision*100).toFixed(2)+
         '%. Check whether the dataset or the verdict cache was regenerated.</div>';
  } else if(j.dataset === 'uploaded'){
    h += '<div class="cert-warn">This is an uploaded dataset. It is not compared against the recorded certification '+
         'figure, so the numbers above describe this dataset only.</div>';
  }

  if(res.labelled_share_pct!=null){
    h += '<div class="cert-warn">only '+res.labelled_share_pct+'% of predictions carry a label &mdash; '+
         ''+res.unlabelled_predictions.toLocaleString()+
         ' are CVEs the ground truth does not enumerate, and '+res.unadjudicable_predictions.toLocaleString()+
         ' are unadjudicable because the two authorities disagree about what the CVE is filed against. Both are excluded from scoring, so the figures above describe the labelled slice.</div>';
  }
  if(res.circularity_warning){
    h += '<div class="cert-warn">⚠ circularity: '+res.circularity_warning+'</div>';
  }
  if(res.per_build && Object.keys(res.per_build).length>1){
    h += '<div class="cert-kv">'+Object.entries(res.per_build).map(([b,c])=>
      '<span>'+b+' <b>TP '+(c.TP||0)+' / FP '+(c.FP||0)+' / TN '+(c.TN||0)+
      ' / FN '+(c.FN||0)+'</b></span>').join('')+'</div>';
  }

  const fps = res.fp_examples || res.fp_cases || [];
  if(fps.length){
    h += '<details style="margin-top:10px"><summary class="hint">see '+
         fps.length+' false positives</summary><table class="cert-fp"><tr>'+
         Object.keys(fps[0]).map(k=>'<th>'+k+'</th>').join('')+'</tr>'+
         fps.slice(0,40).map(r=>'<tr>'+Object.values(r).map(v=>
           '<td>'+String(v==null?'':v).slice(0,80)+'</td>').join('')+'</tr>').join('')+
         '</table></details>';
  }
  h += '<details style="margin-top:8px"><summary class="hint">result JSON</summary>'+
       '<pre style="font-size:11px;white-space:pre-wrap;max-height:320px;overflow:auto">'+
       JSON.stringify(res,null,1).replace(/</g,'&lt;')+'</pre></details>';
  box.innerHTML = h; box.style.display='block';
}

async function certJobs(){
  const r = await fetch('/api/cert/jobs'); const js = await r.json();
  const el = document.getElementById('certJobs');
  if(!js.length){ el.innerHTML='Nothing has been run yet.'; return; }
  el.innerHTML = '<table class="cert-fp"><tr><th>time</th><th>item</th><th>scope</th>'+
    '<th>dataset</th><th>state</th><th>precision</th><th>reproduces</th></tr>'+
    // Fixed locale: toLocaleTimeString() follows the BROWSER, so the one Korean
    // string left on this page came from the viewer rather than from the source.
    js.map(j=>'<tr><td>'+new Date(j.started*1000).toLocaleTimeString('en-GB',{hour12:false})+'</td>'+
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
