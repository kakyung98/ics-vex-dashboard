"""Freeze current V2/V3 reference labels, retaining assistant-only provenance.

This does not create independent expert gold or actual exploitability labels.
"""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from datetime import datetime,timezone
import json
from src.item4.analysis import exploitation_prerequisites as V
from src.item4.decision.condition_logic_evaluation import leaves


def main():
    original=ROOT/'results/operator_vep_adapter_v2/real_dataset'
    out=ROOT/'benchmark/item4_evaluation/current_reference_v1';out.mkdir(exist_ok=True)
    train=[json.loads(l) for l in (original/'train.jsonl').read_text(encoding='utf-8').splitlines() if l.strip()]
    test=[json.loads(l) for l in (original/'test.jsonl').read_text(encoding='utf-8').splitlines() if l.strip()]
    training_groups={r['source_group'] for r in train if r.get('source_group')}
    training_texts={V.digest([s['text'] for s in r['packet']['sources']]) for r in train if not r['synthetic']}
    labels=[];queue=[]
    for row in test:
        if row.get('source_group') in training_groups:raise ValueError('Held-out source group overlaps adapter training')
        record={k:row['packet'][k] for k in ('cve','sources','products')}
        if not row['synthetic'] and V.digest([s['text'] for s in record['sources']]) in training_texts:raise ValueError('Real test source text overlaps adapter training')
        draft=V.resolve_references(row['target'],row['packet'])
        V.validate(draft,record)
        used=set().union(*(leaves(s['expression']) for s in draft['scenarios']))
        questions=[dict(condition_id=p['id'],positive_fact=p['statement'],
            should_ask=p['id'] in used and p.get('necessity','required') in {'required','alternative'},
            observable_from=p['observation']['record_type'],target=p['target'],
            source_refs=p['source_refs'],operational_quote=p['operational_quote'],
            polarity='yes_true_no_false_unknown_preserved',
            requirements=['Preserve the same actor, target, qualifiers and scope.',
                'Do not infer reachability from ACL alone or actual actions from procedures alone.',
                'Do not invent a setting or turn an implementation defect into a question.']) for p in draft['prerequisites']]
        label=dict(id=row['id'],cve=record['cve'],synthetic=row['synthetic'],family=row['family'],
            split='synthetic_boundary' if row['synthetic'] else 'adapter_training_source_disjoint_test',source_group=row.get('source_group') or V.digest(record['sources']),
            record=record,source_record_sha256=V.digest(record),draft=draft,
            v3_question_labels=questions,actual_exploitable=None,
            annotation_method='assistant_source_review_migrated_from_frozen_test_labels',
            origin_annotation_method=row.get('annotation_method','synthetic_curriculum_target'),review_method='assistant_reference',
            independent_gold=False,expert_review_status='pending',expert_reviewer=None,
            completeness='partial' if any(not q['should_ask'] for q in questions) or draft['unknowns'] else 'source_bounded',
            origin=dict(file=str((original/'test.jsonl').relative_to(ROOT)),id=row['id']))
        labels.append(label)
        if not row['synthetic']:queue.append(dict(id=row['id'],cve=record['cve'],source_record_sha256=label['source_record_sha256'],
            candidate_label=label,review_status='pending',reviewer=None,
            required_review=['Exact source support and omissions','AND/OR/NOT and same-actor constraints',
                'Operator answerability and insufficient-record handling','Product, component and assessment scope'],
            actual_exploitable=None))
    def save(name,rows):
        raw=''.join(json.dumps(r,ensure_ascii=False,separators=(',',':'))+'\n' for r in rows)
        (out/name).write_bytes(raw.encode('utf-8'))
        import hashlib
        return hashlib.sha256(raw.encode()).hexdigest()
    digest=save('labels.jsonl',labels);queue_digest=save('expert_review_queue.jsonl',queue)
    training_issues=[]
    for row in train:
        record={k:row['packet'][k] for k in ('cve','sources','products')}
        try:V.validate(V.resolve_references(row['target'],row['packet']),record)
        except ValueError as exc:
            training_issues.append(dict(id=row['id'],cve=record['cve'],source_record_sha256=V.digest(record),
                record=record,current_validation_error=str(exc),
                disposition='requires_semantic_review_original_training_label_unchanged',independent_review=False))
    issue_digest=save('legacy_training_label_issues.jsonl',training_issues)
    manifest=dict(version='item4-current-reference/1',created_at=datetime.now(timezone.utc).isoformat(),
        label_count=len(labels),real_descriptions=sum(not r['synthetic'] for r in labels),
        synthetic_cases=sum(r['synthetic'] for r in labels),
        v2_condition_labels=sum(len(r['draft']['prerequisites']) for r in labels),
        v3_candidate_question_labels=sum(len(r['v3_question_labels']) for r in labels),
        v3_askable_question_labels=sum(q['should_ask'] for r in labels for q in r['v3_question_labels']),
        real_source_groups_disjoint_from_adapter_training=True,real_source_texts_disjoint_from_adapter_training=True,independent_expert_labels=0,
        actual_exploitability_labels=0,review_method='assistant_reference',
        labels_sha256=digest,review_queue_sha256=queue_digest,operator_policy=V.OP.POLICY,
        legacy_training_label_issues=len(training_issues),legacy_training_issues_sha256=issue_digest,
        input_snapshot_sha256=V.digest(test),
        limitations=['Migrated and source-reviewed assistant labels, not new independent expert adjudication.',
            'The 18 real cases are held out from the recorded adapter training source groups; not guaranteed unseen during all project development or model pretraining.',
            'Partial source descriptions and explicit unknowns remain; no closed-world exploitability label.',
            'V3 labels describe semantic requirements, not one exact wording; field answerability requires operator review.'])
    (out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(manifest,ensure_ascii=False))


if __name__=='__main__':main()
