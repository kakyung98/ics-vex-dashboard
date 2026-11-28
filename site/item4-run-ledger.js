// Historical evaluation ledger UI; not loaded by the active CVSS Operational VEX page.
(() => {
  'use strict';
  const el = id => document.getElementById(id);
  const panel = el('evaluation-runs');
  if (!panel) return;
  const base = '/api/item4/evaluation-runs';
  const select = el('evaluation-run-select');
  const status = el('evaluation-status');
  const record = el('evaluation-record');
  const form = el('evaluation-start');
  const report = el('evaluation-report');
  const candidates = el('evaluation-candidates');
  const requested = new URLSearchParams(location.search).get('run_id');
  let timer, revision = 0, active;
  let runList = [];

  function textNode(tag, value) {
    const node = document.createElement(tag);
    node.textContent = value ?? 'Not recorded';
    return node;
  }

  async function request(path, options) {
    const response = await fetch(base + path, options);
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw Error(typeof body.detail === 'string' ? body.detail : 'Evaluation service returned HTTP ' + response.status);
    }
    return response;
  }

  const fieldRecordNames = {
    asset_scope: '자산과 구성 범위', deployment_inventory: '설치·배포 재고',
    inventory_completeness: '재고 완전성', running_build: '실행 버전·빌드',
    configuration_state: '운영 설정', change_history: '변경 이력', supplier_scope: '공급사 적용 범위'
  };

  const statusNames = {affected: '영향 있음', not_affected: '미영향', fixed: '수정됨', under_investigation: '조사 보류'};

  function statusPair(a, b) {
    return 'A ' + statusNames[a] + ' / B ' + statusNames[b];
  }

  function reportLink(runId, label, caseId) {
    const link = textNode('a', label);
    link.href = base + '/' + encodeURIComponent(runId) + '/agent-review/report.ko.html' +
      (caseId ? '#' + encodeURIComponent(caseId) : '');
    return link;
  }

  const priorGroups = [
    ['prior_not_affected', '이전 A·B 모두 미영향'],
    ['prior_disagreement', '이전 A·B 불일치']
  ];

  function appendTransitionTables(section, row, entries) {
    const policy = row.policy_rereview;
    for (const [group, title] of priorGroups) {
      const subset = entries.filter(item => item.prior_groups.includes(group));
      if (subset.length !== policy[group + '_count']) throw Error('transition counts differ');
      const table = document.createElement('table');
      table.createCaption().textContent = title + ' · ' + subset.length + '건';
      const headers = table.createTHead().insertRow();
      for (const label of ['사례 ID', 'CVE', '이전 판정', '정책 재검토 판정']) {
        const heading = textNode('th', label);
        heading.scope = 'col';
        headers.append(heading);
      }
      const body = table.createTBody();
      for (const item of subset) {
        const line = body.insertRow();
        line.insertCell().textContent = item.review_id;
        line.insertCell().textContent = item.cve;
        const prior = item.previous_statuses;
        line.insertCell().append(reportLink(policy.previous_run_id,
          statusPair(prior.reviewer_a, prior.reviewer_b), item.review_id));
        line.insertCell().append(reportLink(row.run_id,
          statusPair(item.reviewer_a.status, item.reviewer_b.status), item.review_id));
      }
      section.append(table);
    }
  }

  function agentCaseList(row, path) {
    const panel = document.createElement('details');
    panel.append(textNode('summary', row.policy_rereview ? '사례별 이전·재검토 판정과 현장 근거 요청 보기' :
      '사례별 일치·불일치 및 현장 근거 요청 보기'));
    const body = document.createElement('div');
    panel.append(body);
    let loading = false, loaded = false;
    panel.addEventListener('toggle', async () => {
      if (!panel.open || loaded || loading) return;
      loading = true;
      body.textContent = '사례별 검토 기록을 불러오는 중입니다.';
      try {
        const response = await fetch(path + 'comparisons.jsonl', {cache: 'no-store'});
        if (!response.ok) throw Error('comparison data unavailable');
        const content = (await response.text()).trim();
        const entries = content.split(/\r?\n/).map(line => JSON.parse(line));
        const groups = new Map([[false, []], [true, []]]);
        for (const item of entries) groups.get(item.agreement).push(item);
        if (entries.length !== row.agent_review.agent_reviewed_scenarios ||
            groups.get(false).length !== row.agent_review.disagreements) throw Error('comparison counts differ');
        const section = document.createDocumentFragment();
        if (row.policy_rereview) appendTransitionTables(section, row, entries);
        for (const [agrees, cases] of groups) {
          section.append(textNode('h4', (agrees ? '일치 ' : '불일치 ') + cases.length + '건'));
          for (const item of cases) {
            const casePanel = document.createElement('details');
            const a = item.reviewer_a, b = item.reviewer_b;
            casePanel.append(textNode('summary', item.review_id + ' · ' + item.cve + ' · ' + statusPair(a.status, b.status)));
            const facts = document.createElement('dl');
            for (const [name, rating] of [['A', a], ['B', b]]) {
              facts.append(textNode('dt', name + ' 판단 사유'), textNode('dd', rating.rationale),
                textNode('dt', name + ' 인용 근거'), textNode('dd', rating.evidence_ids.join(', ')),
                textNode('dt', name + ' 추가 근거 요청'), textNode('dd', rating.needed_records));
            }
            casePanel.append(facts);
            section.append(casePanel);
          }
        }
        body.replaceChildren(section);
        loaded = true;
      } catch {
        body.textContent = '사례 기록을 확인할 수 없습니다. 목록을 닫았다가 다시 열어 주세요.';
      } finally {
        loading = false;
      }
    });
    return panel;
  }

  function policyReviewDetails(row, fields) {
    const policy = row.policy_rereview;
    const previous = document.createElement('dd');
    previous.append(reportLink(policy.previous_run_id, policy.previous_run_id));
    fields.append(textNode('dt', '정책 재검토와 비교한 이전 실행'), previous);
    for (const [group, title] of priorGroups) {
      const distribution = document.createElement('dd');
      const list = document.createElement('ul');
      for (const [pair, count] of Object.entries(policy[group + '_pairs'])) {
        const [a, b] = pair.split(' / ');
        list.append(textNode('li', statusPair(a, b) + ' · ' + count + '건'));
      }
      distribution.append(list);
      fields.append(textNode('dt', title + ' ' + policy[group + '_count'] + '건의 재검토 판정'), distribution);
    }
    fields.append(textNode('dt', '이전 불일치 중 재검토에서 일치한 사례'),
      textNode('dd', policy.prior_disagreements_now_agree + '건'),
      textNode('dt', '미배포 근거 판정 정책 위반'), textNode('dd', policy.absence_policy_violations + '건'));
  }

  function agentReviewDetails(row, fields) {
    const review = row.agent_review;
    const counts = [
      ['두 에이전트가 모두 검토한 시나리오', review.agent_reviewed_scenarios, '건'],
      ['A·B 개별 판정', review.agent_ratings, '개'],
      ['A·B 판정 일치', review.agreements, '건'], ['A·B 판정 불일치', review.disagreements, '건'],
      ['사람이 검토한 시나리오', row.expert_reviewed_count, '건'],
      ['확인된 현장 운영 기록', review.verified_field_records, '건']
    ];
    for (const [label, value, unit] of counts) {
      fields.append(textNode('dt', label), textNode('dd', value.toLocaleString('ko-KR') + unit));
    }
    if (row.policy_rereview) policyReviewDetails(row, fields);
    const needs = document.createElement('ul');
    const countsByType = Object.entries(review.field_record_type_counts).sort(([a, n], [b, m]) => m - n || a.localeCompare(b));
    for (const [type, count] of countsByType) {
      needs.append(textNode('li', (fieldRecordNames[type] || type) + ' · ' + count + '건'));
    }
    const list = document.createElement('dd');
    list.append(needs);
    fields.append(textNode('dt', '추가 요청 자료별 사례 수 (A·B 중복 제거)'), list);
    const links = document.createElement('ul');
    const path = base + '/' + encodeURIComponent(row.run_id) + '/agent-review/';
    for (const [name, label] of [
      ['report.ko.html', row.policy_rereview ? '정책 적용 A·B 재검토 보고서' : '에이전트 독립 검토 보고서'],
      ['comparisons.jsonl', '사례별 판정 비교·추가 근거 요청'],
      ['reviewer_a.json', '에이전트 A 최초 판정'], ['reviewer_b.json', '에이전트 B 최초 판정'],
      ['ballot_receipts.json', '최초 판정 파일 지문'], ['report.json', '비교 집계 JSON']
    ]) {
      const line = document.createElement('li');
      const link = textNode('a', label);
      link.href = path + name;
      line.append(link);
      links.append(line);
    }
    const artifacts = document.createElement('dd');
    artifacts.append(agentCaseList(row, path), links);
    fields.append(textNode('dt', '에이전트 검토 기록'), artifacts);
  }

  function adjudicationDetails(row) {
    const review = row.adjudication;
    const section = document.createElement('section');
    section.append(textNode('h3', review.cve + ' · 불일치 1건 근거 재판정'));
    const fields = document.createElement('dl');
    const previous = document.createElement('dd');
    const pair = review.previous_statuses;
    previous.append(reportLink(review.previous_run_id, statusPair(pair.reviewer_a, pair.reviewer_b), review.review_id));
    fields.append(textNode('dt', '사례 ID'), textNode('dd', review.review_id),
      textNode('dt', '새 VEX 판정'), textNode('dd', statusNames[review.status] + ' (' + review.status + ')'),
      textNode('dt', '정책 재검토 당시 A·B 판정'), previous,
      textNode('dt', '실행 중인 Spectrum Power 릴리스'), textNode('dd', review.running_release_verified ? '현장 확인' : '현장 미확인'),
      textNode('dt', 'Web Office Portal 설치 여부'), textNode('dd', review.portal_installation_verified ? '현장 확인' : '현장 미확인'),
      textNode('dt', '확인된 현장 운영 기록'), textNode('dd', review.verified_field_records + '건'),
      textNode('dt', 'AI 에이전트가 재판정한 사례'), textNode('dd', '1건'),
      textNode('dt', '사람이 검토한 시나리오'), textNode('dd', review.human_reviewed_scenarios + '건'));
    const path = base + '/' + encodeURIComponent(row.run_id) + '/evidence-adjudication/';
    const list = document.createElement('ul');
    for (const [label, url] of [
      ['근거 재판정 보고서', path + 'report.ko.html'], ['공급사 권고문 원문', review.supplier_advisory],
      ['공급사 제품·버전 근거', path + 'supplier_evidence.json'], ['현장 기록 대조 내역', path + 'field_audit.json'],
      ['사례 판정 JSON', path + 'decision.json'], ['출처 확인 기록', path + 'source_receipt.json'],
      ['재판정 보고서 JSON', path + 'report.json']
    ]) {
      const item = document.createElement('li');
      const link = textNode('a', label);
      link.href = url;
      item.append(link);
      list.append(item);
    }
    section.append(fields, list);
    return section;
  }

  function appendFollowUps(fields, previousId) {
    const matches = runList.filter(run => run.generation_method === 'scenario_evidence_adjudication' &&
      run.status === 'completed' && run.adjudication?.previous_run_id === previousId);
    for (const run of matches) {
      const review = run.adjudication;
      const entry = document.createElement('dd');
      const link = textNode('a', review.cve + ' · ' + review.review_id + ' · ' + statusNames[review.status]);
      link.href = '?run_id=' + encodeURIComponent(run.run_id) + '#evaluation-runs';
      entry.append(link);
      fields.append(textNode('dt', '불일치 사례의 후속 근거 재판정'), entry);
    }
  }

  function display(row) {
    const fields = document.createElement('dl');
    const progress = (row.completed ?? 'Not recorded') + ' / ' + (row.total ?? 'Not recorded');
    const origin = row.generation_method === 'scenario_moe_explicit_inventory_review' ? 'Candidates after inventory review' :
      row.candidate_origin === 'frozen_reference' ? 'Frozen candidate answers' : 'Generated candidate answers';
    const common = [
      ['Run ID', row.run_id], ['Status', row.status], ['Method', row.generation_method],
      ['Scenarios processed', progress], ['System predictions', row.prediction_count]
    ];
    if (!row.agent_review && !row.adjudication) common.push([origin, row.candidate_count], ['Independently reviewed scenarios', row.expert_reviewed_count]);
    if (row.adjudication) common.push(['생성된 후보', row.candidate_count]);
    for (const [label, value] of common) fields.append(textNode('dt', label), textNode('dd', value));
    if (row.policy_rereview) appendFollowUps(fields, row.run_id);
    if (row.agent_review) agentReviewDetails(row, fields);
    if (row.inventory_review) {
      const previous = row.inventory_review.prior_not_affected_review;
      const absence = row.inventory_review.absence_evidence_review;
      for (const [label, count] of [
        ['재검증한 기존 미영향 후보', previous.reviewed], ['조사 보류로 바뀐 기존 미영향 후보', previous.changed_to_under_investigation],
        ['미영향을 유지한 후보', previous.retained], ['완전한 재고 범위를 명시한 미배포 사례', absence.explicit_complete],
        ['기존 보류 중 교차검토에서 재고 완전성 사유로 바뀐 사례', absence.prior_crosscheck_holds_replaced],
      ]) fields.append(textNode('dt', label), textNode('dd', count.toLocaleString('ko-KR') + '건'));
    }
    if (row.error) fields.append(textNode('dt', 'Run error'), textNode('dd', row.error));
    const summary = row.result || row.progress;
    if (summary) {
      const decisions = {affected: 0, not_affected: 0, fixed: 0, under_investigation: 0, ...summary.candidate_statuses};
      for (const [label, counts] of [['Generation outcomes', summary.generation_statuses], ['Candidate decisions', decisions]]) {
        const totals = Object.entries(counts).map(([name, count]) => name + ' (' + count + ')');
        fields.append(textNode('dt', label), textNode('dd', totals.join(', ') || '0'));
      }
      if (summary.hold_reasons) {
        for (const [label, counts] of [
          ['Reasons for under investigation', summary.hold_reasons],
          ['Supplier evidence details for held scenarios', summary.product_hold_reasons],
          ['Errors in incomplete scenario generation', summary.generation_failure_reasons],
        ]) {
          const values = Object.entries(counts).sort(([a, n], [b, m]) => m - n || a.localeCompare(b));
          const entry = document.createElement('dd');
          if (values.length) {
            const list = document.createElement('ul');
            for (const [reason, count] of values) list.append(textNode('li', reason + ' (' + count + ')'));
            entry.append(list);
          } else entry.textContent = '0';
          fields.append(textNode('dt', label), entry);
        }
        fields.append(textNode('dt', 'Counting method'), textNode('dd',
          'Each scenario counts once per applicable reason. A scenario can have several reasons.'));
      }
    }
    const hashes = document.createElement('details');
    hashes.className = 'evaluation-fingerprints';
    hashes.open = Boolean(record.querySelector('details.evaluation-fingerprints')?.open);
    hashes.append(textNode('summary', 'Code, model and data fingerprints'));
    const groups = [['Code', row.code_hashes], ['Model files', row.model_hashes], ['Data', row.data_hashes]];
    if (row.result) groups.push(['Output', {'candidates.jsonl': row.result.candidates_sha256}]);
    for (const [label, values] of groups) {
      hashes.append(textNode('h3', label));
      const entries = Object.entries(values);
      if (!entries.length) hashes.append(textNode('p', 'Not recorded'));
      const list = document.createElement('ul');
      for (const [name, hash] of entries) {
        const item = textNode('li', name + ' ');
        item.append(textNode('code', hash));
        list.append(item);
      }
      hashes.append(list);
    }
    record.replaceChildren(fields, hashes);
    if (row.adjudication) record.prepend(adjudicationDetails(row));
    if (row.population_comparison) {
      const comparison = row.population_comparison;
      const section = document.createElement('section');
      section.append(textNode('h3', '합성 BOM 전수 MoE 재실행 비교'),
        textNode('p', '기존 실행 ' + comparison.previous_run_id + ' · 상태 변경 ' +
          comparison.status_changed + '건 · 보류 사유 변경 ' + comparison.reasons_changed + '건'));
      const path = base + '/' + encodeURIComponent(row.run_id) + '/population-review/';
      for (const [file, label] of [
        ['population-report.ko.html', '전수 재실행 한국어 보고서'],
        ['population-report.json', '상태·보류 사유·변경 집계 JSON'],
        ['changes.jsonl', '시나리오별 변경 내역']
      ]) {
        const line = document.createElement('p');
        const link = textNode('a', label);
        link.href = path + file;
        line.append(link);
        section.append(line);
      }
      record.prepend(section);
    }
    active = row;
    report.hidden = false;
    const generatesCandidates = ['scenario_moe_local_llm', 'scenario_moe_h200_llm'].includes(row.generation_method);
    candidates.hidden = !generatesCandidates || !row.completed || row.status === 'running';
    candidates.textContent = row.candidate_count ? 'Download scenario candidates' : 'Download scenario traces';
    status.textContent = '';
  }

  async function checkCandidateFile(row, ticket) {
    let probe;
    try {
      probe = await fetch(base + '/' + encodeURIComponent(row.run_id) + '/candidates', {
        method: 'HEAD', cache: 'no-store'
      });
    } catch {
      // A temporary connection failure leaves the ledger and run report available.
    }
    if (revision !== ticket || active !== row || !panel.open) return;
    if (probe?.status === 200) {
      candidates.hidden = false;
    } else if (probe?.status === 404 || probe?.status === 405) {
      const note = textNode('p', 'Open the candidate file in the project folder. ');
      note.append(textNode('code', 'results/item4_scenario_moe/' + row.run_id + '/candidates.jsonl'));
      record.append(note);
    } else {
      status.textContent = 'The candidate file could not be verified. Refresh to try again.';
    }
  }

  async function showInventoryReport(row, ticket) {
    const name = 'report.ko.html';
    const path = base + '/' + encodeURIComponent(row.run_id) + '/inventory-review/' + name;
    let response;
    try {
      response = await fetch(path, {method: 'HEAD', cache: 'no-store'});
    } catch {
      // The public ledger snapshot can still be downloaded when the report is unavailable.
    }
    if (revision !== ticket || active !== row || !panel.open) return;
    const note = document.createElement('p');
    if (response?.status === 200) {
      const link = textNode('a', '재고 완전성 재검증 보고서 열기');
      link.href = path;
      link.hreflang = 'ko';
      note.append(link);
    } else if (response?.status === 404 || response?.status === 405) {
      note.append('재고 완전성 재검증 보고서 파일 ', textNode('code', 'results/item4_scenario_moe/' + row.run_id + '/' + name));
    } else {
      note.textContent = '재고 완전성 재검증 보고서를 확인할 수 없습니다. 새로 고침해 다시 확인하세요.';
    }
    record.append(note);
  }

  async function refresh(reloadList, preferred) {
    const ticket = ++revision;
    clearTimeout(timer);
    if (!panel.open) return;
    status.textContent = 'Loading evaluation records…';
    report.hidden = candidates.hidden = true;
    active = null;
    try {
      if (reloadList) {
        const {runs} = await (await request('')).json();
        if (ticket !== revision) return;
        runList = runs;
        const previous = preferred || select.value || requested;
        select.replaceChildren(...runs.map(r => {
          const option = textNode('option', r.run_id + ' · ' + r.status);
          option.value = r.run_id;
          return option;
        }));
        select.disabled = !runs.length;
        if (runs.some(r => r.run_id === previous)) select.value = previous;
        if (!runs.length) {
          record.replaceChildren();
          status.textContent = 'No evaluation runs have been recorded.';
          return;
        }
      }
      const row = await (await request('/' + encodeURIComponent(select.value))).json();
      if (ticket !== revision || !panel.open) return;
      display(row);
      if (row.generation_method === 'scenario_moe_explicit_inventory_review' && row.status === 'completed') {
        await Promise.all([checkCandidateFile(row, ticket), showInventoryReport(row, ticket)]);
      } else if (row.generation_method === 'scenario_moe_supplier_review_pilot' && row.completed && row.status !== 'running') {
        await checkCandidateFile(row, ticket);
      }
      if (row.status === 'running') timer = setTimeout(() => refresh(true, row.run_id), 2500);
    } catch (err) {
      if (ticket === revision) {
        record.replaceChildren();
        status.textContent = err.message;
      }
    }
  }

  async function download(kind, suffix) {
    if (!active) return;
    const id = active.run_id;
    if (kind === 'candidates') {
      // Let the browser stream the full population directly to disk.
      const link = document.createElement('a');
      link.href = base + '/' + encodeURIComponent(id) + '/candidates';
      link.download = id + suffix;
      link.click();
      return;
    }
    try {
      const response = await request('/' + encodeURIComponent(id) + '/' + kind);
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement('a');
      link.href = url;
      link.download = id + suffix;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) { status.textContent = err.message; }
  }

  panel.addEventListener('toggle', () => refresh(true));
  select.addEventListener('change', () => refresh(false));
  el('evaluation-refresh').addEventListener('click', () => refresh(true));
  report.addEventListener('click', () => download('report', '-run-report.json'));
  candidates.addEventListener('click', () => download('candidates', '-candidates.jsonl'));
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const button = form.querySelector('button');
    button.disabled = true;
    clearTimeout(timer);
    ++revision;
    try {
      const cve = el('evaluation-cve').value.trim().toUpperCase();
      const fullPopulation = el('evaluation-cohort').value === 'all';
      const response = await request(fullPopulation ? '/selection' : '/v1-sample', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(fullPopulation ? {cves: [cve]} : {cve})
      });
      const run = await response.json();
      await refresh(true, run.run_id);
    } catch (err) { status.textContent = err.message; }
    finally { button.disabled = false; }
  });
  if (requested || location.hash === '#evaluation-runs') panel.open = true;
})();
