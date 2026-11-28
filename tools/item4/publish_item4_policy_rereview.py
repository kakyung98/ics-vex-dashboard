"""Seal and compare two blinded policy-v2 ballots after both reviewers commit their originals."""
import argparse
from collections import Counter
from datetime import datetime, timezone
from html import escape
import json
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.evaluation import scenario_evaluation_runner as runs
from src.item4.evaluation.blind_inventory_review import inspect_absence
from tools.item4 import publish_item4_blind_agent_review as first
from tools.item4.render_item4_scenario_run_ko import CSS, table


PREVIOUS = 'agent-review-793506d5daba1562502d'
POLICY_PACKET = ROOT/'results/item4_policy_blind_packet_20261122'
VERSION = 'item4-policy-blind-rereview/2'
SLOTS, STATES = first.SLOTS, first.STATES
require = first.require
BASE_LABELS = {'deployment_absence':'미배포', 'supplier_status':'공급사 상태', 'version_range':'버전 범위',
               'other':'기타 운영·제품 근거', 'insufficient_evidence':'근거 부족'}


def check_locks(ballots, pins):
    require(set(ballots) == set(pins) == set(SLOTS)
            and all(re.fullmatch('[a-f0-9]{64}', pins[s]) and first.sha(ballots[s]) == pins[s] for s in SLOTS),
            'Both agent-attested ballot hashes must match before comparison.')


def pair_lock(pins, *, create=False):
    """Record both attestations without reading a ballot. Keep this receipt stable over file copies."""
    require(set(pins)==set(SLOTS) and all(re.fullmatch('[0-9a-f]{64}',x) for x in pins.values()),
            'Two agent-attested SHA-256 digests are required.')
    manifest = (POLICY_PACKET/'manifest.json').read_bytes()
    expected = dict(packet_id=json.loads(manifest)['packet_id'], policy_packet_sha256=first.sha(manifest),
                    agent_attested_sha256=pins)
    root = ROOT/'results/item4_policy_review_commitments_20261122'
    name = root/(first.sha(first.packets.json_bytes(expected))+'.json')
    if create:
        root.mkdir(parents=True,exist_ok=True)
        record = dict(expected,coordinator_sealed_utc=datetime.now(timezone.utc).isoformat())
        with tempfile.TemporaryDirectory(dir=root) as staging:
            stage = Path(staging)/'commitment.json'
            stage.write_bytes(first.encoded(record))
            try:
                os.link(stage,name)
            except FileExistsError:
                pass
    lock = json.loads(name.read_bytes())
    require(set(lock)==set(expected)|{'coordinator_sealed_utc'} and all(lock[k]==v for k,v in expected.items())
            and datetime.fromisoformat(lock['coordinator_sealed_utc']).utcoffset() is not None,
            'Paired attestation scope or recorded timestamp differs.')
    return lock

def ratings_for(raw, slot, packet_id, cards):
    ballot = json.loads(raw, object_pairs_hook=first.unique_keys)
    require(isinstance(ballot, dict) and ballot.get('schema_version') == 'item4-independent-agent-ballot/2'
            and isinstance(ballot.get('ratings'), list), 'Expected policy-aware ballot/2.')
    extras = {'decision_basis','inventory_evidence_ids'}
    projected = []
    for rating in ballot['ratings']:
        require(isinstance(rating, dict) and extras <= rating.keys(), 'Missing policy evidence fields.')
        projected.append({k:v for k,v in rating.items() if k not in extras})
    # Validate identity, cardinality, sources, rationale and requests with the first review's contract.
    first.load_ballot(first.encoded(dict(ballot, schema_version=first.BALLOT, ratings=projected)), slot, packet_id, cards)
    result = {r['review_id']:r for r in ballot['ratings']}
    for case_id,rating in result.items():
        try:
            inspect_absence(cards[case_id], rating)
        except ValueError as exc:
            raise ValueError(f'{slot}/{case_id}: {exc}') from exc
    return result


def sources():
    from tools.item4 import build_item4_policy_blind_packet as forms
    forms.verify(POLICY_PACKET)
    packet = json.loads((POLICY_PACKET/'manifest.json').read_bytes())
    sample,cards,key = first.get_sample(first.packets.DEFAULT_OUTPUT)
    old_dir = runs.OUTPUT/PREVIOUS
    first.verify(old_dir,first.packets.DEFAULT_OUTPUT)
    previous = runs.ledger.get_run(PREVIOUS)
    require(sample['packet_id'] == packet['source_packet_id'] == previous['agent_review']['packet_id'],
            'The source packet and previous run must match.')
    old_rows = {r['review_id']:r for r in first.packets.read_rows(old_dir/'comparisons.jsonl')}
    require(old_rows.keys() == cards.keys() and all(old_rows[k['review_id']]['source_scenario_id'] == k['source_scenario_id']
            and old_rows[k['review_id']]['cve'] == k['cve'] for k in key), 'The two runs have different source cases.')
    return packet, dict(sample,packet_id=packet['packet_id']), cards, key, old_rows, previous


def transitions(rows, old_rows, cards):
    groups = {'prior_not_affected':Counter(), 'prior_disagreement':Counter()}
    changed = newly_disagreed = resolved = 0
    for row in rows:
        rid = row['review_id']
        old = old_rows[rid]
        previous = {s:old[s]['status'] for s in SLOTS}
        row['previous_statuses'] = previous
        row['prior_groups'] = []
        before, after = tuple(previous.values()), tuple(row[s]['status'] for s in SLOTS)
        changed += before != after
        newly_disagreed += old['agreement'] and not row['agreement']
        if before == ('not_affected','not_affected'):
            row['prior_groups'].append('prior_not_affected')
        if not old['agreement']:
            row['prior_groups'].append('prior_disagreement')
            resolved += row['agreement']
        for group in row['prior_groups']:
            groups[group][' / '.join(after)] += 1
        # ratings_for has validated both submissions. The underlying observation is common to both.
        row['inventory_observation'] = inspect_absence(cards[rid], row['reviewer_a'])
    info = dict(previous_run_id=PREVIOUS, prior_not_affected_count=sum(groups['prior_not_affected'].values()),
                prior_not_affected_pairs=dict(groups['prior_not_affected']),
                prior_disagreement_count=sum(groups['prior_disagreement'].values()),
                prior_disagreement_pairs=dict(groups['prior_disagreement']), prior_disagreements_now_agree=resolved,
                absence_policy_violations=0)
    return info, dict(ordered_pairs_changed=changed, newly_disagreed=newly_disagreed,
                      observed_absent=sum(r['inventory_observation']['deployment']=='not_deployed' for r in rows),
                      observed_absent_explicit_complete=sum(r['inventory_observation']['deployment']=='not_deployed'
                          and r['inventory_observation']['coverage_explicit_complete'] for r in rows))


def status_pair(statuses):
    return ' / '.join(STATES[s] for s in statuses)


def render(report, rows):
    info, policy = report['agent_review'], report['policy_rereview']
    stats, delta = report['agreement_statistics'],report['rereview_counts']
    previous_url = 'http://127.0.0.1:8100/api/item4/evaluation-runs/'+PREVIOUS+'/agent-review/report.ko.html'
    def link(row, label):
        return f'<a href="#{escape(row["review_id"])}">{escape(label)}</a>'
    def focused(group):
        return table(['사례 · CVE','이전 A / B','재검토 A / B'], [
            (link(r, r['review_id']+' · '+r['cve']), status_pair(r['previous_statuses'].values()),
             status_pair(r[s]['status'] for s in SLOTS)) for r in rows if group in r['prior_groups']])
    def distribution(pairs):
        return ', '.join(f'{status_pair(pair.split(" / "))} {count}건' for pair,count in sorted(pairs.items()))
    def details(r):
        e = escape
        rid = e(r['review_id'])
        out = [f'<details class="case" id="{rid}"><summary>{rid} · {e(r["cve"])} · {status_pair(r[s]["status"] for s in SLOTS)}</summary>',
               f'<p>이전 A / B · <a href="{previous_url}#{rid}">{status_pair(r["previous_statuses"].values())}</a>　'
               f'원래 추출 집단 · {e(first.packets.STRATA[r["source_stratum"]])}</p>']
        obs = r['inventory_observation']
        if obs['deployment'] == 'not_deployed':
            out.append('<p><strong>미배포 관측의 재고 완전성</strong> · '
                       +e(str(obs['inventory_coverage'] or '명시되지 않음'))+' · '+e(obs['operator_evidence_id'])+'</p>')
        for s, name in zip(SLOTS, 'AB'):
            b = r[s]
            out += [f'<h4>{name} · {STATES[b["status"]]} · {BASE_LABELS[b["decision_basis"]]}</h4>',
                    f'<p>{e(b["rationale"])}</p><p><strong>추가 요청</strong>　{e(b["needed_records"])}</p>',
                    f'<p><small>판정 근거 {e(", ".join(b["evidence_ids"]))}　·　재고 관련 인용 {e(", ".join(b["inventory_evidence_ids"]) or "없음")}</small></p>']
        out.append('<ul>')
        for ref in r['cited_evidence']:
            src = ref['source']
            url = src.get('url','')
            doc = f' · <a href="{e(url, quote=True)}">공개 권고문</a>' if url.startswith('https://') else ''
            location = ' '.join(filter(None,[src.get('file'),src.get('pointer') or src.get('status_pointer')]))
            out.append(f'<li>{e(ref["evidence_id"])} · {e(ref["title"])} <small>{e(location)}</small>{doc}</li>')
        return ''.join(out)+'</ul></details>'
    def cases(match):
        return ''.join(details(r) for r in rows if r['agreement']==match)
    title = '#4 재고 완전성 기준을 적용한 A/B 독립 재검토'
    style = 'details{border-top:1px solid #cad6d6;padding:.65rem 0;overflow-wrap:anywhere}summary{cursor:pointer;font-weight:600}details p{margin:.35rem 0}small{color:#38535b}nav a{display:inline-block;margin:.2rem 1rem .2rem 0}.scroll{overflow:auto}'
    pos = next(r for r in rows if r['source_candidate_status']=='affected')
    other_changes = [r for r in rows if not r['prior_groups']
                     and any(r['previous_statuses'][s]!=r[s]['status'] for s in SLOTS)]
    kappa = stats['kappa']
    html = ['<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
            '<title>'+title+'</title><style>'+CSS+style+'</style></head><body><main><h1>'+title+'</h1>',
            f'<p>같은 {report["unique_cves"]}개 CVE의 합성 시나리오 {len(rows)}건을 새로운 두 AI가 독립 검토했습니다. 기존 결과, 추출 집단, 상대 판정은 양식에서 숨겼습니다. 각 원본의 SHA-256을 고정한 뒤 사례 ID로 대조했습니다.</p>',
            '<p>미배포를 미영향으로 판정하려면 동일한 운영 관측에 완전한 재고 범위가 명시되고, 현재 단일 자산과 대상 구성요소가 인용 근거에 연결돼야 합니다. 재고 완전성이 미확정이면 조사 보류입니다.</p>',
            f'<p><strong>일치 {info["agreements"]}건 · 불일치 {info["disagreements"]}건 · AI 개별 판정 {info["agent_ratings"]}건</strong><br>사람 검토 {info["human_reviewed_scenarios"]}건 · 확인된 현장 원기록 {info["verified_field_records"]}건</p>',
            '<nav><a href="#prior-absence">기존 미영향 사례</a><a href="#prior-split">기존 불일치 사례</a><a href="#different">현재 불일치</a><a href="#same">현재 일치</a><a href="#records">추가 자료</a></nav>',
            f'<h2 id="prior-absence">기존 미영향 일치 {policy["prior_not_affected_count"]}건</h2>',
            f'<p><strong>새 A / B 판정　{distribution(policy["prior_not_affected_pairs"])}</strong></p>',
            f'<p>전체 표본의 미배포 관측 {delta["observed_absent"]}건 중 재고 완전성이 명시된 사례는 {delta["observed_absent_explicit_complete"]}건입니다. 제출된 두 판정 원본의 미배포 정책 위반은 {policy["absence_policy_violations"]}건입니다. 현장 확인에는 해당 시점과 자산의 재고 수집 범위, 수집 예외·누락, 구성요소 조회 결과가 필요합니다.</p>',
            '<div class="scroll">'+focused('prior_not_affected')+'</div>',
            f'<h2 id="prior-split">기존 불일치 {policy["prior_disagreement_count"]}건</h2><p>이 중 재검토에서 일치한 사례는 {policy["prior_disagreements_now_agree"]}건입니다. 각 사례를 선택하면 새 A/B의 판단 이유와 요청 기록을 확인할 수 있습니다.</p>',
            '<div class="scroll">'+focused('prior_disagreement')+'</div>',
            f'<h2>전체 표본의 변화</h2><p>이전 A/B 순서쌍과 달라진 사례 {delta["ordered_pairs_changed"]}건, 이전에 일치했다가 새로 갈린 사례 {delta["newly_disagreed"]}건입니다. 미배포 이외의 사례도 두 AI가 처음부터 다시 읽었으므로 이 변화에는 검토자 간 해석 차이가 포함됩니다.</p>',
            '<p>위 두 집단 밖에서 판정이 달라진 사례　'+(', '.join(
                link(r,r['cve'])+' ('+status_pair(r['previous_statuses'].values())+' → '+status_pair(r[s]['status'] for s in SLOTS)+')'
                for r in other_changes) or '없음')+'</p>',
            f'<p>기존 전수본의 유일한 영향 후보 {link(pos,pos["cve"])} · 재검토 A / B {status_pair(pos[s]["status"] for s in SLOTS)}.</p>',
            f'<p>재검토의 에이전트 간 일치율 {stats["observed_agreement"]:.1%} · 비가중 Cohen의 κ '+(f'{kappa:.3f}' if kappa is not None else '산출 불가')+'. 사람 검토 또는 실제 현장 관측을 기준으로 한 정확도는 미측정입니다.</p>',
            table(['A ＼ B',*STATES.values()],[(l,*(info['status_pairs'].get(s,{}).get(t,0) for t in STATES)) for s,l in STATES.items()]),
            '<h2 id="records">추가로 필요한 근거</h2><p>유형별로 A 또는 B가 요청한 고유 시나리오 수입니다. 한 사례가 여러 유형에 포함될 수 있습니다.</p>',
            table(['자료 유형','사례 수'],[(label,info['field_record_type_counts'][k]) for k,label in first.FIELDS.items()]),
            '<h2 id="different">재검토 불일치 '+str(info['disagreements'])+'건</h2>'+cases(False),
            '<h2 id="same">재검토 일치 '+str(info['agreements'])+'건</h2>'+cases(True),
            '<h2>원본 및 다운로드</h2><nav>'+''.join(f'<a href="{p}">{label}</a>' for p,label in [
                ('comparisons.jsonl','95건 이전·현재 대조표'),('report.json','집계 JSON'),('reviewer_a.json','A 판정 원본'),
                ('reviewer_b.json','B 판정 원본'),('ballot_receipts.json','제출 지문'),(previous_url,'이전 A/B 보고서')])+'</nav>',
            f'<p>실행 ID <code>{escape(report["run_id"])}</code></p></main></body></html>']
    return '\n'.join(html)


def artifacts(ballots, pins, lock):
    check_locks(ballots, pins)
    packet,sample,cards,key,old_rows,previous = sources()
    ratings = {s:ratings_for(ballots[s],s,packet['packet_id'],cards) for s in SLOTS}
    rows, summary = first.compare(sample,cards,key,ratings)
    policy, counts = transitions(rows,old_rows,cards)
    require(policy['prior_not_affected_count'] == 19 and policy['prior_disagreement_count'] == 2,
            'The previous 19-case and 2-case cohorts differ from the sealed run.')
    input_hashes = dict(source_packet_manifest=packet['source_manifest_sha256'],
                        policy_packet_manifest=runs.file_sha(POLICY_PACKET/'manifest.json'),
                        neutral_evidence=packet['neutral_evidence_sha256'],
                        source_candidates=sample['source_candidates_sha256'],
                        previous_comparisons=previous['data_hashes']['comparisons.jsonl'],
                        previous_report=previous['data_hashes']['report.json'])
    code_files = ('tools/item4/build_item4_policy_blind_packet.py','tools/item4/publish_item4_policy_rereview.py',
                  'tools/item4/publish_item4_blind_agent_review.py','tools/item4/build_item4_blind_sample.py',
                  'tools/item4/render_item4_scenario_run_ko.py','src/item4/evaluation/blind_inventory_review.py','src/item4/decision/inventory_evidence_policy.py',
                  'src/item4/analysis/product_advisory_evidence.py','src/item4/evaluation/synthetic_vex_benchmark.py',
                  'src/item4/evaluation/policy_review_records.py','src/item4/evaluation/agent_review_records.py')
    code = {Path(p).name:runs.file_sha(ROOT/p) for p in code_files}
    input_hashes['paired_attestation'] = first.sha(first.encoded(lock))
    identity = first.packets.json_bytes([VERSION, packet['packet_id'], PREVIOUS, input_hashes, pins, code])
    rid = 'policy-review-'+first.sha(identity)[:20]
    report = dict(version=VERSION,run_id=rid,generation_method='scenario_blind_agent_review',
                  source_run_id=sample['source_run_id'], policy_packet_id=packet['packet_id'],
                  source_packet_id=packet['source_packet_id'],unique_cves=sample['sample_cves'],
                  sample_scenarios=len(rows),case_scope='frozen_synthetic_scenario',source_population=sample['population_scenarios'],
                  case_matching='review_id, original scenario ID and CVE', input_hashes=input_hashes,
                  ballots_sha256=pins,code_hashes=code,policy_rereview=policy,rereview_counts=counts,**summary)
    witness = dict(packet_id=packet['packet_id'], source_packet_id=packet['source_packet_id'],
                   previous_run_id=PREVIOUS, policy_packet_sha256=input_hashes['policy_packet_manifest'],
                   independence='Coordinator recorded separate fresh reviewer contexts. Each received only its own neutral form and returned a hash before the coordinator compared either ballot.',
                   paired_attestation=lock,
                   reviewer_kind='ai_agent',human_ballots=0,submitted_before_comparison=True,
                   ballots={s:dict(reviewer_slot=s, reviewed_rows=len(rows), agent_attested_sha256=pins[s],
                                   stored_sha256=first.sha(ballots[s]),
                                   input_form_sha256=packet['files'][s+'/form.json']) for s in SLOTS})
    files = {'report.ko.html':render(report,rows).encode('utf-8'),'report.json':first.encoded(report),
             'comparisons.jsonl':b''.join(first.packets.json_bytes(row)+b'\n' for row in rows),
             'ballot_receipts.json':first.encoded(witness), **{s+'.json':ballots[s] for s in SLOTS}}
    return report,files


def publish(paths, pins):
    from src.item4.evaluation.policy_review_records import publish_policy_review
    lock = pair_lock(pins)
    ballots = {s:paths[s].read_bytes() for s in SLOTS}
    report,files = artifacts(ballots,pins,lock)
    rid = report['run_id']
    directory = runs.OUTPUT/rid
    with tempfile.TemporaryDirectory(prefix='.item4-policy-rereview-',dir=runs.OUTPUT) as tmp:
        stage = Path(tmp)/rid
        stage.mkdir()
        for name,data in files.items():
            (stage/name).write_bytes(data)
        try:
            stage.rename(directory)
        except OSError:
            if not directory.is_dir() or any((directory/name).read_bytes()!=v for name,v in files.items()):
                raise
    publish_policy_review(rid,total=report['sample_scenarios'],code_hashes=report['code_hashes'],
                          data_hashes={**report['input_hashes'],**{k:first.sha(v) for k,v in files.items()}},
                          agent_review=report['agent_review'],policy_rereview=report['policy_rereview'])
    return directory


def verify(directory):
    directory = directory.resolve()
    require(directory.parent == runs.OUTPUT.resolve(), 'The artifact folder must belong to the ledger.')
    witness = json.loads((directory/'ballot_receipts.json').read_bytes())
    ballots = {s:(directory/(s+'.json')).read_bytes() for s in SLOTS}
    pins = {s:witness['ballots'][s]['agent_attested_sha256'] for s in SLOTS}
    lock = pair_lock(pins)
    require(witness['paired_attestation']==lock,'The artifact differs from the pre-comparison lock.')
    report,files = artifacts(ballots,pins,lock)
    entry = runs.ledger.get_run(directory.name)
    require(entry['status']=='completed' and directory.name==report['run_id']
            and all(entry[k]==report[k] for k in ('agent_review','policy_rereview','code_hashes'))
            and entry['completed']==entry['total']==report['sample_scenarios']
            and entry['expert_reviewed_count']==entry['prediction_count']==entry['candidate_count']==0
            and entry['data_hashes']=={**report['input_hashes'],**{k:first.sha(v) for k,v in files.items()}}
            and all((directory/n).read_bytes()==v for n,v in files.items()),
            'The ledger receipt and reconstructed review must agree on inputs, reports, ballots and counts.')
    return {k:report[k] for k in ('run_id','policy_rereview','rereview_counts','agent_review')}


if __name__ == '__main__':
    cli = argparse.ArgumentParser(description=__doc__)
    actions = cli.add_subparsers(dest='action',required=True)
    new = actions.add_parser('publish')
    lock_cmd = actions.add_parser('lock',help='Record the two reported SHA-256 digests before reading either ballot.')
    for slot in SLOTS:
        opt = '--'+slot.replace('_','-')
        new.add_argument(opt,type=Path,required=True)
        new.add_argument(opt+'-sha256',required=True)
        lock_cmd.add_argument(opt+'-sha256',required=True)
    actions.add_parser('verify').add_argument('directory',type=Path)
    args = cli.parse_args()
    if args.action=='lock':
        print(json.dumps(pair_lock({s:getattr(args,s+'_sha256') for s in SLOTS},create=True),indent=2))
    elif args.action=='publish':
        print(publish({s:getattr(args,s) for s in SLOTS},{s:getattr(args,s+'_sha256') for s in SLOTS}))
    else:
        print(json.dumps(verify(args.directory),ensure_ascii=False,indent=2))
