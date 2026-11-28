"""Join two independently submitted AI ballots against the sealed #4 review packet."""
import argparse
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
import json
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.evaluation import scenario_evaluation_runner as runs
from src.item4.evaluation.synthetic_vex_benchmark import kappa
from tools.item4 import build_item4_blind_sample as packets
from tools.item4.render_item4_scenario_run_ko import CSS, table


VERSION = 'item4-blind-agent-comparison/1'
BALLOT = 'item4-independent-agent-ballot/1'
SLOTS = ('reviewer_a', 'reviewer_b')
STATES = {'affected':'영향 있음', 'not_affected':'미영향', 'fixed':'수정됨', 'under_investigation':'조사 보류'}
FIELDS = {'asset_scope':'자산·설정 범위', 'deployment_inventory':'배포·설치 재고',
          'inventory_completeness':'재고 수집의 완전성', 'running_build':'실행 버전·빌드',
          'configuration_state':'설정·운영 상태', 'change_history':'변경·패치 이력',
          'supplier_scope':'공급사 적용 범위 문서'}
FILES = ('report.ko.html','report.json','comparisons.jsonl','reviewer_a.json','reviewer_b.json','ballot_receipts.json')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return sha256(raw).hexdigest()


def encoded(item):
    return (json.dumps(item, ensure_ascii=False, indent=2, allow_nan=False)+'\n').encode('utf-8')


def unique_keys(pairs):
    value = {}
    for key,item in pairs:
        require(key not in value, 'Duplicate JSON key: ' + key)
        value[key] = item
    return value


def load_ballot(raw, slot, packet, cards):
    ballot = json.loads(raw, object_pairs_hook=unique_keys)
    require(isinstance(ballot,dict) and set(ballot) == {'schema_version','packet_id','reviewer_kind','reviewer_slot','ratings'}
            and ballot['schema_version'] == BALLOT and ballot['packet_id'] == packet
            and ballot['reviewer_kind'] == 'ai_agent' and ballot['reviewer_slot'] == slot,
            'Ballot scope, kind, or slot differs: ' + slot)
    require(isinstance(ballot['ratings'],list) and len(ballot['ratings']) == len(cards), 'Incomplete ballot: ' + slot)
    ratings = {}
    for row in ballot['ratings']:
        require(isinstance(row,dict) and set(row) == {'review_id','status','evidence_ids','rationale','needed_records','field_record_types'},
                'Unexpected rating format in ' + slot)
        identifier = row['review_id']
        require(identifier in cards and identifier not in ratings and row['status'] in STATES,
                f'Unknown case/status or duplicate in {slot}: {identifier}')
        citations, fields = row['evidence_ids'], row['field_record_types']
        available = {e['evidence_id'] for e in cards[identifier]['evidence']}
        require(isinstance(citations,list) and citations and len(citations) == len(set(citations))
                and set(citations) <= available, f'Unknown, repeated or missing exhibit: {slot}/{identifier}')
        require(isinstance(fields,list) and len(fields) == len(set(fields)) and set(fields) <= FIELDS.keys()
                and set(fields)-{'supplier_scope'}, f'A concrete field evidence type is required: {slot}/{identifier}')
        require(all(isinstance(row[k],str) and row[k].strip() for k in ('rationale','needed_records')),
                f'Incomplete rationale or evidence request: {slot}/{identifier}')
        ratings[identifier] = row
    require(ratings.keys() == cards.keys(), 'Different ballot population: ' + slot)
    return ratings


def get_sample(directory, *, full_verify=False):
    packets.verify(directory, rerun=full_verify)
    folder = directory/'coordinator'
    manifest = json.loads((folder/'manifest.json').read_bytes())
    cards = {r['review_id']:r for r in packets.read_rows(folder/'neutral_evidence.jsonl')}
    key = packets.read_rows(folder/'selection_key.jsonl')
    require(manifest['sample_scenarios'] == len(cards) == len(key) == 95
            and manifest['verified_field_records_attached'] == 0
            and manifest['completed_human_reviews_at_preparation'] == 0,
            'The source packet differs from the announced review.')
    return manifest, cards, key


def compare(sample, cards, key, ratings):
    rows = []
    by_stratum = {}
    field_counts = Counter()
    for origin in key:
        rid = origin['review_id']
        a,b = (ratings[slot][rid] for slot in SLOTS)
        agreed = a['status'] == b['status']
        requested = [f for f in FIELDS if f in a['field_record_types'] or f in b['field_record_types']]
        shared = [f for f in requested if f in a['field_record_types'] and f in b['field_record_types']]
        field_counts.update(requested)
        group = by_stratum.setdefault(origin['stratum'], dict(agreements=0, disagreements=0))
        group['agreements' if agreed else 'disagreements'] += 1
        cited = set(a['evidence_ids']) | set(b['evidence_ids'])
        refs = [dict(evidence_id=e['evidence_id'], title=e['title'], kind=e['kind'], source=e['source'])
                for e in cards[rid]['evidence'] if e['evidence_id'] in cited]
        rows.append(dict(review_id=rid,cve=origin['cve'],source_scenario_id=origin['source_scenario_id'],
                         source_candidate_status=origin['candidate_status'],source_stratum=origin['stratum'],
                         agreement=agreed,reviewer_a=a,reviewer_b=b,field_record_types=requested,
                         shared_field_record_types=shared,cited_evidence=refs))
    agreement = kappa([(r['reviewer_a']['status'],r['reviewer_b']['status']) for r in rows])
    matches = sum(row['agreement'] for row in rows)
    agent_review = dict(packet_id=sample['packet_id'], source_run_id=sample['source_run_id'],
                        agent_reviewed_scenarios=len(rows), agent_ratings=2*len(rows), agreements=matches,
                        disagreements=len(rows)-matches, human_reviewed_scenarios=0, verified_field_records=0,
                        field_record_type_counts={f:field_counts[f] for f in FIELDS}, status_pairs=agreement['confusion'])
    different_requests = [r['review_id'] for r in rows if r['field_record_types'] != r['shared_field_record_types']]
    return rows, dict(agent_review=agent_review,agreement_statistics=agreement,source_strata=by_stratum,
                      different_requested_type_ids=different_requests,
                      agreed_with_different_requests=sum(r['agreement'] and r['field_record_types'] != r['shared_field_record_types'] for r in rows),
                      affected_candidate_review_ids=[r['review_id'] for r in rows if r['source_candidate_status']=='affected'],
                      agreement_ids=[r['review_id'] for r in rows if r['agreement']],
                      disagreement_ids=[r['review_id'] for r in rows if not r['agreement']])


def receipt(sample, sample_sha, submissions, pins, times):
    return dict(packet_id=sample['packet_id'], source_packet_manifest_sha256=sample_sha,
                submitted_before_comparison=True, independence='Two separate agent contexts, one blinded form per reviewer; no peer ballot or coordinator answer supplied.',
                reviewer_kind='ai_agent', human_ballots=0,
                ballots={s:dict(reviewer_slot=s, input_form_sha256=sample['files'][s+'/index.html'],
                                agent_attested_sha256=pins[s], stored_sha256=sha(submissions[s]),
                                reviewed_rows=sample['sample_scenarios'], file_saved_utc=times[s])
                         for s in SLOTS})


def make_outputs(sample, cards, key, submissions, pins, witness):
    # Check both reported commitments before parsing either ballot or joining the pair.
    require(set(submissions) == set(pins) == set(SLOTS) and
            all(re.fullmatch('[a-f0-9]{64}',pins[s]) and sha(submissions[s]) == pins[s] for s in SLOTS),
            'Ballots differ from the two hashes reported by the agents.')
    by_slot = {s:load_ballot(submissions[s],s,sample['packet_id'],cards) for s in SLOTS}
    rows, summary = compare(sample,cards,key,by_slot)
    code = {p.name:runs.file_sha(p) for p in (
        Path(__file__), ROOT/'src/item4/evaluation/synthetic_vex_benchmark.py', ROOT/'src/item4/evaluation/agent_review_records.py',
        ROOT/'tools/item4/build_item4_blind_sample.py', ROOT/'tools/item4/render_item4_scenario_run_ko.py')}
    identity = [VERSION,sample['packet_id'],witness['source_packet_manifest_sha256'],pins,code]
    rid = 'agent-review-' + sha(packets.json_bytes(identity))[:20]
    report = dict(version=VERSION,run_id=rid,generation_method='scenario_blind_agent_review',
                  source_run_id=sample['source_run_id'],sample_packet_id=sample['packet_id'],
                  sample_scenarios=len(rows),unique_cves=sample['sample_cves'],case_scope='frozen_synthetic_scenario',
                  reviewer_kind='ai_agent',independent_human_review_count=0,field_records_attached=0,
                  human_adjudicated_disagreements=0,source_population=sample['population_scenarios'],
                  ballots_sha256=pins,code_hashes=code,**summary)
    return rid, report, {
        'reviewer_a.json':submissions['reviewer_a'],'reviewer_b.json':submissions['reviewer_b'],
        'comparisons.jsonl':b''.join(packets.json_bytes(row)+b'\n' for row in rows),
        'ballot_receipts.json':encoded(witness),'report.json':encoded(report),'report.ko.html':render(report,rows).encode('utf-8')}


def render(report, rows):
    info = report['agent_review']
    stats = report['agreement_statistics']
    def number(value):
        return '산출 불가' if value is None else f'{value:.3f}'
    def field_labels(codes):
        return ', '.join(FIELDS[x] for x in codes)
    def cite(exhibit):
        source = exhibit['source']
        locator = source.get('pointer') or source.get('status_pointer') or ''
        origin = ' · '.join(x for x in (source.get('file'),locator) if x)
        url = source.get('url','')
        link = f' · <a href="{escape(url, quote=True)}">공개 권고문</a>' if url.startswith('https://') else ''
        return (f'<li><code>{escape(exhibit["evidence_id"])}</code> {escape(exhibit["title"])} '
                f'<small>{escape(origin)}</small>{link}</li>')
    def case_details(row):
        rid = escape(row['review_id'])
        statuses = ' / '.join(STATES[row[s]['status']] for s in SLOTS)
        body = [f'<details class="case" id="{rid}"><summary><code>{rid}</code> · {escape(row["cve"])} · {statuses}</summary>',
                f'<p>표본 추출 집단 · {escape(packets.STRATA[row["source_stratum"]])}</p><div class="pair">']
        for s,letter in zip(SLOTS,'AB'):
            ballot = row[s]
            body.extend([f'<section><h4>에이전트 {letter} · {STATES[ballot["status"]]}</h4>',
                         f'<p>{escape(ballot["rationale"])}</p>',
                         f'<p><strong>인용 근거</strong> {escape(", ".join(ballot["evidence_ids"]))}</p>',
                         f'<p><strong>추가 요청</strong> {escape(ballot["needed_records"])}</p></section>'])
        body.append(f'</div><p>이 사례에 요청된 자료 · {escape(field_labels(row["field_record_types"]))}</p>')
        body.append('<ul class="refs">'+''.join(cite(e) for e in row['cited_evidence'])+'</ul></details>')
        return ''.join(body)
    extra_css = """
.metrics{display:flex;flex-wrap:wrap;gap:1.2rem;margin:1.2rem 0}.metrics span{display:grid}
.metrics b{font-size:1.55rem;color:#154e49}.case{border-top:1px solid #cdd8d5;padding:.6rem 0;overflow-wrap:anywhere}
.case summary{cursor:pointer;font-weight:600}.pair{display:grid;grid-template-columns:1fr 1fr;gap:1.2rem}.pair h4{margin:.6rem 0}
.pair p{line-height:1.55}.refs{font-size:.88rem}.scroll{overflow-x:auto}.meta-links a,nav a{display:inline-block;margin:.3rem 1rem .3rem 0}
@media(max-width:650px){.pair{grid-template-columns:1fr}.metrics{gap:.8rem}.scroll th,.scroll td{white-space:normal}h1{font-size:1.65rem}}
"""
    out = ['<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
           '<title>#4 A/B 에이전트 독립 검토</title><style>'+CSS+extra_css+'</style></head><body><main>',
           '<h1>#4 A/B 에이전트 독립 검토</h1>',
           f'<p>에이전트 A와 B가 같은 {report["unique_cves"]}개 CVE의 합성 시나리오 {len(rows)}건을 각자 검토했습니다. '
           '각자의 양식에는 원래 후보 상태, 표본 추출 사유, 상대방 답을 제공하지 않았습니다. '
           '각자가 제출한 원본 파일의 SHA-256을 고정한 뒤 같은 시나리오 ID로 결과를 대조했습니다.</p>',
           '<div class="metrics">'+''.join(f'<span><b>{n}건</b>{label}</span>' for label,n in (
               ('상태 일치',info['agreements']),('상태 불일치',info['disagreements']),('AI 개별 판정',info['agent_ratings']),
               ('사람 검토 시나리오',info['human_reviewed_scenarios']),('첨부된 현장 원기록',info['verified_field_records'])))+'</div>',
           '<nav><a href="#different">불일치 사례</a><a href="#same">일치 사례</a><a href="#field">필요한 자료</a></nav>',
           f'<p>두 AI가 같은 상태를 선택한 비율은 <strong>{100*stats["observed_agreement"]:.1f}%</strong>입니다. '
           f'네 상태 기준 비가중 Cohen의 κ는 {number(stats["kappa"])}입니다. κ는 두 분포에서 우연 일치 확률이 1이면 산출할 수 없습니다. '
           '이 값은 층별 표본에서 두 에이전트가 어느 정도 일치했는지 나타냅니다. '
           '사람의 독립 판정과 실제 현장 관측을 이용한 정확도는 미측정입니다. '
           f'상태 일치 {info["agreements"]}건 중 {report["agreed_with_different_requests"]}건에서 두 에이전트가 요청한 자료 유형이 달랐습니다.</p>',
           '<h2>판정 교차표</h2><div class="scroll">']
    matrix = info['status_pairs']
    out.append(table(['A ＼ B',*STATES.values()],[(label,*(matrix.get(s,{}).get(t,0) for t in STATES)) for s,label in STATES.items()])+'</div>')
    out.append('<h2>표본 집단별 결과</h2>'+table(['표본 추출 집단','일치','불일치'],[
        (title,report['source_strata'][s]['agreements'],report['source_strata'][s]['disagreements']) for s,title in packets.STRATA.items()]))
    out.append('<h2>원래 영향 후보 1건</h2>')
    positive = next(r for r in rows if r['source_candidate_status']=='affected')
    out.append(f'<p>{escape(positive["cve"])} · <code>{escape(positive["review_id"])}</code>. '
               f'A는 {STATES[positive["reviewer_a"]["status"]]}, B는 {STATES[positive["reviewer_b"]["status"]]}로 판단했습니다. '
               f'<a href="#{escape(positive["review_id"])}">두 의견과 요청한 자료 보기</a></p>')
    out.append('<h2 id="field">추가로 필요한 근거</h2><p>각 유형을 A나 B 중 한 명 이상이 요청한 시나리오 수입니다. '
               '한 사례에서 여러 유형을 요청할 수 있습니다. 공급사 적용 범위는 별도의 문서 요청입니다.</p>')
    out.append(table(['자료 유형','시나리오 수'],[(label,info['field_record_type_counts'][f]) for f,label in FIELDS.items()]))
    for value, section, label in [(False,'different','불일치'),(True,'same','일치')]:
        subset = [row for row in rows if row['agreement'] == value]
        out.append(f'<h2 id="{section}">{label} 사례 {len(subset)}건</h2>')
        out.extend(case_details(r) for r in subset)
    out.append('<h2>검토 출처와 다운로드</h2><p>기존 전수본의 후보와 추출 집단은 두 AI의 원본 제출 후 진행자 대조표로 연결했습니다. '
               '각 사례의 현장 요청은 추가로 수집할 자료입니다. 현장에 적용할 때는 자산·시점·빌드가 일치하는 원기록을 확인해야 합니다. '
               '이 실행에서 새 전수 후보, 시스템 예측, 사람 확정 판정은 각각 0건입니다.</p>')
    out.append('<p class="meta-links">'+''.join(f'<a href="{name}">{label}</a>' for name,label in (
        ('comparisons.jsonl','사례별 대조표 JSONL'),('report.json','집계 JSON'),('reviewer_a.json','A 원본 판정'),
        ('reviewer_b.json','B 원본 판정'),('ballot_receipts.json','제출 해시 기록')) )+'</p>')
    out.append(f'<p>실행 ID <code>{escape(report["run_id"])}</code><br>검토 자료 <code>{escape(report["sample_packet_id"])}</code></p></main></body></html>')
    return '\n'.join(out)


def publish(packet_dir, paths, pins):
    sample, cards, key = get_sample(packet_dir)
    raw = {s:paths[s].read_bytes() for s in SLOTS}
    require(all(sha(raw[s]) == pins[s] for s in SLOTS), 'External ballot locks do not match the original files.')
    times = {s:datetime.fromtimestamp(paths[s].stat().st_mtime,timezone.utc).isoformat() for s in SLOTS}
    sample_sha = runs.file_sha(packet_dir/'coordinator/manifest.json')
    witness = receipt(sample,sample_sha,raw,pins,times)
    rid,report,contents = make_outputs(sample,cards,key,raw,pins,witness)
    destination = runs.OUTPUT/rid
    # The ledger can point to a review only after every complete artifact has been installed.
    with tempfile.TemporaryDirectory(prefix='.blind-agent-review-',dir=runs.OUTPUT) as tmp:
        stage = Path(tmp)/rid
        stage.mkdir()
        for name, data in contents.items():
            (stage/name).write_bytes(data)
        try:
            stage.rename(destination)
        except OSError:
            if not destination.is_dir() or any((destination/name).read_bytes() != contents[name] for name in FILES):
                raise
    publish_ledger(destination, packet_dir, report)
    return destination


def publish_ledger(directory, packet_dir, report):
    from src.item4.evaluation.agent_review_records import publish_agent_review
    hashes = {name:runs.file_sha(directory/name) for name in FILES}
    hashes['source_packet_manifest'] = runs.file_sha(packet_dir/'coordinator/manifest.json')
    hashes['source_candidates'] = json.loads((packet_dir/'coordinator/manifest.json').read_bytes())['source_candidates_sha256']
    return publish_agent_review(report['run_id'],total=report['sample_scenarios'], code_hashes=report['code_hashes'],
                                data_hashes=hashes, agent_review=report['agent_review'])


def verify(directory, packet_dir):
    sample,cards,key = get_sample(packet_dir)
    witness = json.loads((directory/'ballot_receipts.json').read_bytes())
    require(witness['source_packet_manifest_sha256'] == runs.file_sha(packet_dir/'coordinator/manifest.json'),
            'The original review packet manifest differs.')
    raw = {s:(directory/(s+'.json')).read_bytes() for s in SLOTS}
    pins = {s:witness['ballots'][s]['agent_attested_sha256'] for s in SLOTS}
    times = {s:witness['ballots'][s]['file_saved_utc'] for s in SLOTS}
    for stamp in times.values():
        require(datetime.fromisoformat(stamp).utcoffset() is not None, 'Invalid ballot file timestamp.')
    require(witness == receipt(sample,witness['source_packet_manifest_sha256'],raw,pins,times), 'Ballot receipt differs.')
    rid,report,files = make_outputs(sample,cards,key,raw,pins,witness)
    entry = runs.ledger.get_run(rid)
    require(rid==directory.name and directory.resolve() == (runs.OUTPUT/rid).resolve() and entry['status']=='completed'
            and entry['agent_review']==report['agent_review'] and entry['expert_reviewed_count']==0
            and entry['candidate_count']==entry['prediction_count']==0 and entry['completed']==entry['total']==len(cards)
            and all((directory/name).read_bytes() == content and sha(content) == entry['data_hashes'][name]
                    for name,content in files.items()), 'Stored totals, case rows, report or ledger hashes differ.')
    return report['agent_review']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet-dir',type=Path,default=packets.DEFAULT_OUTPUT)
    cmd = parser.add_subparsers(dest='action',required=True)
    new = cmd.add_parser('publish')
    for slot in SLOTS:
        new.add_argument('--'+slot.replace('_','-'),type=Path,required=True)
        new.add_argument('--'+slot.replace('_','-')+'-sha256',required=True)
    cmd.add_parser('verify').add_argument('directory',type=Path)
    args = parser.parse_args()
    if args.action == 'publish':
        result = publish(args.packet_dir,{s:getattr(args,s) for s in SLOTS},{s:getattr(args,s+'_sha256') for s in SLOTS})
        print(result)
    else:
        print(json.dumps(verify(args.directory.resolve(),args.packet_dir),indent=2,ensure_ascii=False))
